//! RunBundle implementation - contains the actual orchestration logic.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::application::run_bundle::{RunBundleRequest, RunResult};
use crate::domain::manifest;
use crate::harness::registry::HarnessRegistry;
use crate::harness::traits::PrepareRuntimeRequest;
use crate::security::crypto;
use crate::security::integrity;
use crate::security::secrets::SecretsBundle;
use crate::security::signing;

/// Use case: run an agent from a bundle.
pub fn execute(request: RunBundleRequest) -> Result<RunResult> {
    // ── 1. Resolve bundle directory ────────────────────────────────
    let bundle_dir = request.bundle_path;

    if !bundle_dir.is_dir() {
        bail!(
            "not a directory: {}\n  hint: pass a path to a bundle directory, or '.' for the current directory",
            bundle_dir.display()
        );
    }

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "no manifest.yaml found in {}\n  hint: this doesn't look like an agentpacknest bundle — run `pn init` to create one",
            bundle_dir.display()
        );
    }

    // ── 2. Load and validate manifest ──────────────────────────────
    let m = manifest::load(&manifest_path).context("failed to load manifest")?;

    println!("Bundle:   {}", m.bundle.name);
    println!("Harness:  {} v{}", m.harness.name, m.harness.version);

    // ── 3. Check bundle freshness ──────────────────────────────────
    check_stale_bundle(&m, request.max_age_secs)?;

    // ── 4. Verify integrity and signature BEFORE execution ──────────
    // This is a security checkpoint: tampered bundles must not execute by default.
    // `--allow-unverified` bypasses ONLY trust verification (checksum/signature),
    // never structural validity — the manifest was already parsed and validated
    // above, and schema/format failures abort before this point.
    verify_bundle_integrity_and_signature(&bundle_dir, &m, request.allow_unverified)?;

    println!();

    // ── 5. Validate runtime compatibility ───────────────────────────
    // The manifest may require a minimum agentpacknest version to read it.
    check_compatibility(&m)?;

    // ── 6. Resolve the harness and prepare the runtime ──────────────
    // The harness owns its runtime prerequisites (Pi requires Node.js >= 20)
    // and the final launch specification. `--allow-unverified` must NOT bypass
    // runtime compatibility — it is structural, not trust.
    let registry = HarnessRegistry::with_defaults();
    let harness = registry.by_name(&m.harness.name)?;
    let prepared = harness.prepare_runtime(PrepareRuntimeRequest {
        bundle_root: bundle_dir.clone(),
        launch: m.launch.clone(),
    })?;

    // ── 7. Decrypt secrets (in memory only) ────────────────────────
    let secrets = if m.security.secrets_encrypted {
        let enc_path = bundle_dir.join("secrets/keys.enc");
        if !enc_path.is_file() {
            bail!(
                "manifest says secrets are encrypted but secrets/keys.enc is missing\n  hint: re-run `pn pack --with-secrets` to regenerate the encrypted file"
            );
        }

        let pass = match request.passphrase {
            Some(p) => p,
            None => crypto::prompt_passphrase("Passphrase")?,
        };

        let bundle = SecretsBundle::load_decrypted(&enc_path, &pass)
            .context("failed to decrypt secrets — wrong passphrase?")?;

        println!("Secrets:  ✓ decrypted ({} keys)", bundle.len());
        Some(bundle)
    } else {
        println!("Secrets:  none encrypted");
        None
    };

    // ── 8. Prepare working directory ───────────────────────────────
    let run_workdir = match request.workdir {
        Some(w) => PathBuf::from(w),
        None => {
            let wd = bundle_dir.join(prepared.working_directory.as_deref().unwrap_or("."));
            // A manifest-provided working directory must stay inside the bundle.
            // This is a structural check: `--allow-unverified` cannot override it.
            ensure_inside_bundle(&bundle_dir, &wd)?;
            wd
        }
    };

    if !run_workdir.is_dir() {
        bail!(
            "working directory does not exist: {}\n  hint: check the --workdir flag or launch.working_directory in manifest.yaml",
            run_workdir.display()
        );
    }

    // ── 9. Build environment ───────────────────────────────────────
    let env_vars = build_env(&bundle_dir, &m, secrets.as_ref());

    // ── 10. Resolve command ────────────────────────────────────────
    // The harness returned the final command/args (launch spec resolution
    // already happened in prepare_runtime).
    let cmd_name = &prepared.command;
    let mut cmd_args: Vec<&str> = prepared.args.iter().map(|s| s.as_str()).collect();
    cmd_args.extend(request.args.iter().map(|s| s.as_str()));

    // ── 11. Dry run or execute ─────────────────────────────────────
    println!();
    println!("Working dir: {}", run_workdir.display());
    println!("Command:     {} {}", cmd_name, cmd_args.join(" "));

    if !env_vars.is_empty() {
        println!("Env vars:    {} set", env_vars.len());
        for key in env_vars.keys() {
            println!("             {}", key);
        }
    }

    if request.dry_run {
        println!();
        println!("(dry run — not executing)");
        return Ok(RunResult {
            exit_code: 0,
            dry_run: true,
        });
    }

    println!();
    println!("Starting agent...");
    println!();

    // Run the command with our env vars injected
    let exit_code = run_command(cmd_name, &cmd_args, &run_workdir, &env_vars)?;

    // ── 12. Cleanup ────────────────────────────────────────────────
    // Secrets only existed in memory — they're dropped here.
    // env_vars is dropped too.
    // No cleanup needed since we never wrote secrets to disk.

    if exit_code == 0 {
        println!();
        println!("Agent finished successfully.");
    } else {
        println!();
        println!("Agent exited with code {}.", exit_code);
    }

    Ok(RunResult {
        exit_code,
        dry_run: false,
    })
}

// ---------------------------------------------------------------------------
// Bundle integrity and signature verification
// ---------------------------------------------------------------------------

/// Verify bundle integrity (checksum) and signature.
///
/// This is a security checkpoint: tampered bundles must not execute by default.
/// If `allow_unverified` is true, skip the signature check with a warning.
fn verify_bundle_integrity_and_signature(
    bundle_dir: &Path,
    m: &manifest::Manifest,
    allow_unverified: bool,
) -> Result<()> {
    // ── Check checksum ───────────────────────────────────────────────
    if let Some(ref expected) = m.integrity.checksum {
        match integrity::verify_checksum(bundle_dir, expected) {
            Ok(true) => {
                println!("Checksum: ✓ verified");
            }
            Ok(false) => {
                if allow_unverified {
                    eprintln!(
                        "⚠ WARNING: --allow-unverified specified — checksum verification skipped"
                    );
                    eprintln!("  the bundle may have been tampered with");
                    eprintln!("  do not run bundles from untrusted sources");
                } else {
                    bail!(
                        "checksum mismatch: bundle has been modified\n  expected: {}...{}\n  got: (computed mismatch)",
                        &expected[..16],
                        &expected[expected.len()-16..]
                    );
                }
            }
            Err(e) => {
                if allow_unverified {
                    eprintln!(
                        "⚠ WARNING: --allow-unverified specified — checksum verification error: {}",
                        e
                    );
                    eprintln!("  the bundle may have been tampered with");
                    eprintln!("  do not run bundles from untrusted sources");
                } else {
                    bail!("checksum verification failed: {}", e);
                }
            }
        }
    } else {
        if allow_unverified {
            eprintln!("⚠ WARNING: --allow-unverified specified — no checksum in manifest");
        } else {
            bail!(
                "missing checksum: bundle integrity cannot be verified\n  use `pn pack` to generate a checksum\n  or `pn run --allow-unverified` to override (not recommended)"
            );
        }
    }

    // ── Check signature ──────────────────────────────────────────────
    let sig_path = bundle_dir.join("manifest.sig");
    let pubkey_path = bundle_dir.join("signing/public.key");

    if sig_path.is_file() && pubkey_path.is_file() {
        // Verify over the canonical manifest representation (recomputed from
        // the parsed manifest) using the public key bundled with the bundle.
        let signature_verified =
            signing::verify_manifest_with_bundled_pubkey(m, &sig_path, &pubkey_path);

        match signature_verified {
            Ok(true) => println!("Signature: ✓ verified"),
            Ok(false) => {
                if allow_unverified {
                    eprintln!(
                        "⚠ WARNING: --allow-unverified specified — signature verification failed"
                    );
                    eprintln!("  the bundle may have been tampered with");
                    eprintln!("  do not run bundles from untrusted sources");
                } else {
                    bail!(
                        "invalid manifest signature — the bundle may have been tampered with\n\
                         do not run bundles from untrusted sources\n\
                         use `pn run --allow-unverified <bundle>` to override (not recommended)"
                    );
                }
            }
            Err(e) => {
                if allow_unverified {
                    eprintln!("⚠ WARNING: --allow-unverified specified — signature verification error: {}", e);
                } else {
                    bail!("signature verification failed: {}", e);
                }
            }
        }
    } else if sig_path.is_file() && !pubkey_path.is_file() {
        // Has signature but no public key
        if allow_unverified {
            eprintln!("⚠ WARNING: --allow-unverified specified — missing signing/public.key");
        } else {
            bail!(
                "missing signing/public.key: signature cannot be verified\n  the bundle was signed but public key is missing\n\
                 use `pn run --allow-unverified <bundle>` to override (not recommended)"
            );
        }
    } else {
        // No signature file
        if allow_unverified {
            eprintln!("⚠ WARNING: --allow-unverified specified — no manifest signature found");
            eprintln!("  do not run bundles from untrusted sources");
        } else {
            bail!(
                "missing manifest signature — unverified bundle\n\
                 do not run bundles without a valid signature\n\
                 use `pn run --allow-unverified <bundle>` to override (not recommended)"
            );
        }
    }

    Ok(())
}

/// Ensure a manifest-derived path stays inside the bundle directory.
///
/// This is a structural safety check (path traversal), NOT a trust check:
/// `--allow-unverified` must never allow a manifest to redirect execution
/// outside the bundle. Uses canonicalized paths so `..` and symlinks resolve.
fn ensure_inside_bundle(bundle_dir: &Path, candidate: &Path) -> Result<()> {
    let root = fs::canonicalize(bundle_dir)
        .with_context(|| format!("failed to resolve bundle path: {}", bundle_dir.display()))?;
    let resolved = fs::canonicalize(candidate).with_context(|| {
        format!(
            "failed to resolve working directory: {}",
            candidate.display()
        )
    })?;

    if !resolved.starts_with(&root) {
        bail!(
            "launch.working_directory escapes the bundle: {} (resolved to {})",
            candidate.display(),
            resolved.display()
        );
    }
    Ok(())
}

/// Enforce `compatibility.min_agentpacknest_version` from the manifest.
///
/// Refuses to run when the bundle requires a newer agentpacknest than the
/// running binary. Structural — `--allow-unverified` cannot override it.
fn check_compatibility(m: &manifest::Manifest) -> Result<()> {
    let Some(required) = m.min_agentpacknest_version() else {
        return Ok(());
    };

    let current = env!("CARGO_PKG_VERSION");
    if version_lt(current, required) {
        bail!(
            "this bundle requires agentpacknest >= {required}, but you are running {current}\n\
             hint: upgrade pn to read this bundle",
        );
    }
    Ok(())
}

/// True when `a` < `b` for dotted numeric versions (MAJOR.MINOR[.PATCH]).
fn version_lt(a: &str, b: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    }
    let pa = parts(a);
    let pb = parts(b);
    for i in 0..pa.len().max(pb.len()) {
        let va = pa.get(i).copied().unwrap_or(0);
        let vb = pb.get(i).copied().unwrap_or(0);
        if va != vb {
            return va < vb;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Stale bundle detection
// ---------------------------------------------------------------------------

/// Check if the bundle is stale compared to current time.
/// Warns (does not block) when the bundle is older than `max_age_secs`
/// (the default of 7 days is resolved in the command layer).
fn check_stale_bundle(m: &manifest::Manifest, max_age_secs: u64) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Some(age_secs) = stale_age_secs(m, now_secs, max_age_secs) {
        if let Some(ref origin) = m.origin {
            println!(
                "⚠ WARNING: this bundle was packed {} ago on '{}'",
                format_age(age_secs),
                origin.origin_machine
            );
            println!("  hint: the local harness may have changed since then.");
            println!("  run `pn diff` to compare, or `pn pack` to refresh.");
            println!();
        }
    }
    Ok(())
}

/// The bundle's age in seconds when it is older than `max_age_secs`;
/// `None` when it is fresh enough, or when no origin timestamp is present
/// or parseable.
fn stale_age_secs(m: &manifest::Manifest, now_secs: u64, max_age_secs: u64) -> Option<u64> {
    let origin = m.origin.as_ref()?;
    let pack_secs = parse_iso8601_secs(&origin.packed_at).ok()?;
    let age_secs = now_secs.saturating_sub(pack_secs);
    (age_secs > max_age_secs).then_some(age_secs)
}

/// Human-friendly age for the staleness warning message.
fn format_age(age_secs: u64) -> String {
    if age_secs >= 86_400 {
        format!("{} days", age_secs / 86_400)
    } else if age_secs >= 3_600 {
        format!("{} hours", age_secs / 3_600)
    } else {
        format!("{} minutes", (age_secs / 60).max(1))
    }
}

/// Parse ISO 8601 timestamp to seconds since epoch.
fn parse_iso8601_secs(ts: &str) -> Result<u64> {
    // Simple parser for "2025-01-15T12:34:56Z" format
    let parts: Vec<&str> = ts.trim_end_matches('Z').split(['T', '-', ':']).collect();
    if parts.len() != 6 {
        bail!("invalid timestamp format: {}", ts);
    }
    let year: u64 = parts[0].parse().context("bad year")?;
    let month: u64 = parts[1].parse().context("bad month")?;
    let day: u64 = parts[2].parse().context("bad day")?;
    let hour: u64 = parts[3].parse().context("bad hour")?;
    let minute: u64 = parts[4].parse().context("bad minute")?;
    let second: u64 = parts[5].parse().context("bad second")?;

    // Days since epoch (simplified — ignores leap seconds)
    let mut total_days = 0u64;
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        total_days += month_days[m as usize];
        if m == 2 && is_leap_year(year) {
            total_days += 1;
        }
    }
    total_days += day - 1;

    let secs = total_days * 86400 + hour * 3600 + minute * 60 + second;
    Ok(secs)
}

fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

// ---------------------------------------------------------------------------
// Environment setup
// ---------------------------------------------------------------------------

/// Build environment variables for the agent process.
///
/// - Sets `AGENTPACKNEST_BUNDLE` to the bundle path
/// - Sets `AGENTPACKNEST_HARNESS` to the harness name
/// - Injects decrypted secrets as individual env vars
fn build_env(
    bundle_dir: &Path,
    m: &manifest::Manifest,
    secrets: Option<&SecretsBundle>,
) -> HashMap<String, String> {
    let mut env = HashMap::new();

    // Core agentpacknest vars
    env.insert(
        "AGENTPACKNEST_BUNDLE".to_string(),
        bundle_dir.to_string_lossy().into_owned(),
    );
    env.insert("AGENTPACKNEST_HARNESS".to_string(), m.harness.name.clone());

    // Agent-specific dirs
    let agent_dir = bundle_dir.join("agent");
    env.insert(
        "AGENTPACKNEST_CONFIG".to_string(),
        agent_dir.join("config").to_string_lossy().into_owned(),
    );
    env.insert(
        "AGENTPACKNEST_MEMORY".to_string(),
        agent_dir.join("memory").to_string_lossy().into_owned(),
    );
    env.insert(
        "AGENTPACKNEST_PACKAGES".to_string(),
        agent_dir.join("packages").to_string_lossy().into_owned(),
    );

    // Inject secrets
    if let Some(sec) = secrets {
        for (key, value) in sec.iter() {
            env.insert(key.to_string(), value.to_string());
        }
    }

    env
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

/// Execute a command with given args, working directory, and env vars.
/// Returns the exit code.
fn run_command(
    cmd: &str,
    args: &[&str],
    workdir: &Path,
    env_vars: &HashMap<String, String>,
) -> Result<i32> {
    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(workdir);

    // Clear inherited env and set only our vars
    // This minimizes environment pollution
    command.env_clear();

    // Inherit essential system vars
    // Unix: PATH, HOME, USER, SHELL, LANG, etc.
    // Windows: SystemRoot, COMSPEC, PATHEXT, TEMP, etc.
    let inherit_keys = if cfg!(target_os = "windows") {
        &[
            "PATH",
            "HOME",
            "USER",
            "SystemRoot",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
        ] as &[&str]
    } else {
        &["PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TMPDIR"] as &[&str]
    };
    for key in inherit_keys {
        if let Ok(val) = env::var(key) {
            command.env(key, val);
        }
    }

    // Add our vars
    for (key, value) in env_vars {
        command.env(key, value);
    }

    let status = command
        .status()
        .with_context(|| format!("failed to execute: {}", cmd))?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_run_request_construction() {
        let request = RunBundleRequest {
            bundle_path: PathBuf::from("/tmp/bundle"),
            passphrase: Some("test".to_string()),
            workdir: None,
            dry_run: true,
            allow_unverified: false,
            max_age_secs: crate::application::run_bundle::DEFAULT_MAX_AGE_SECS,
            args: vec![],
        };
        assert!(request.dry_run);
        assert!(!request.allow_unverified);
    }

    // ── Staleness threshold ───────────────────────────────────────

    /// Build a manifest whose origin is packed at a fixed past date.
    fn manifest_packed_at(iso: &str) -> manifest::Manifest {
        let mut m = manifest::default_pi("stale-test", "0.1.0");
        m.origin = Some(manifest::OriginMeta {
            origin_machine: "old-machine".to_string(),
            packed_at: iso.to_string(),
            source_state_hash: None,
        });
        m
    }

    #[test]
    fn stale_beyond_threshold_reported() {
        // Packed 245 days before the (fixed) reference clock.
        let now = parse_iso8601_secs("2026-09-03T00:00:00Z").unwrap();
        let m = manifest_packed_at("2026-01-01T00:00:00Z");
        let age = now - parse_iso8601_secs("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(age, 245 * 86_400);

        // Stale beyond the default 7 days.
        assert_eq!(stale_age_secs(&m, now, 7 * 86_400), Some(245 * 86_400));
        // Not stale when the threshold is raised past the age.
        assert_eq!(stale_age_secs(&m, now, 400 * 86_400), None);
        // Exactly at the threshold is not stale (strictly older than).
        assert_eq!(stale_age_secs(&m, now, 245 * 86_400), None);
    }

    #[test]
    fn no_origin_never_stale() {
        let now = parse_iso8601_secs("2026-09-03T00:00:00Z").unwrap();
        let m = manifest::default_pi("no-origin", "0.1.0");
        assert_eq!(stale_age_secs(&m, now, 86_400), None);
    }

    #[test]
    fn humanized_age_uses_largest_unit() {
        assert_eq!(format_age(245 * 86_400), "245 days");
        assert_eq!(format_age(12 * 3_600), "12 hours");
        assert_eq!(format_age(30 * 60), "30 minutes");
    }
}

//! PackBundle — orchestrate packing a bundle from a harness installation.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::domain::manifest;
use crate::harness::pi::detect::PiInstallation;
use crate::harness::types::HarnessAdapter;
use crate::infrastructure::ignore::IgnorePatterns;
use crate::security::crypto;
use crate::security::integrity;
use crate::security::secrets::SecretsBundle;
use crate::security::signing;

#[derive(Debug)]
pub struct PackBundleRequest {
    pub bundle_path: PathBuf,
    pub harness_path: Option<PathBuf>,
    pub with_config: bool,
    pub with_memory: bool,
    pub with_skills: bool,
    pub with_secrets: bool,
    pub force: bool,
}

#[derive(Debug)]
pub struct PackBundleResult {
    pub manifest: manifest::Manifest,
    pub checksum: String,
}

/// Orchestrate: discover → stage → encrypt → integrity → manifest → sign → validate
pub fn execute(request: PackBundleRequest) -> Result<PackBundleResult> {
    // ── 1. Resolve bundle directory ────────────────────────────────
    let bundle_dir = &request.bundle_path;

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "not a valid agentpacknest bundle: no manifest.yaml in {}\n  hint: run `pn init` first",
            bundle_dir.display()
        );
    }

    // ── 2. Load and validate manifest ──────────────────────────────
    let mut m = manifest::load(&manifest_path).context("failed to load manifest")?;

    if m.harness.name != "pi" {
        bail!(
            "unsupported harness in manifest: `{}`\n  only 'pi' is supported in pn v0.1\n  hint: this bundle was created for a different harness",
            m.harness.name
        );
    }

    println!("Bundle:     {}", m.bundle.name);
    println!("Harness:    pi v{}", m.harness.version);

    // ── 3. Detect Pi installation ──────────────────────────────────
    let pi =
        PiInstallation::detect(request.harness_path).context("failed to detect Pi installation")?;

    println!("Pi source:  {}", pi.root().display());
    println!();

    // ── 4. Load ignore patterns ────────────────────────────────────
    let ignore = IgnorePatterns::load(pi.root());
    if !ignore.is_empty() {
        println!(
            "Ignore:     {} pattern(s) from .agentpacknestignore",
            ignore.len()
        );
        println!();
    }

    // ── 5. Copy files ──────────────────────────────────────────────
    if request.with_config {
        // Config source is the Pi agent root: copy loose config files only.
        // Component directories (sessions, skills, ...) and secret sources
        // (auth.json, .env files) are excluded — they are handled by their
        // own pack flags and must never appear as plaintext in the payload.
        copy_dir_recursive(
            &pi.config_path(),
            &bundle_dir.join("agent/config"),
            request.force,
            "config",
            &ignore,
            &[
                // component directories (packed via their own flags)
                "sessions",
                "skills",
                "themes",
                "extensions",
                "packages",
                "prompts",
                "npm",
                "git",
                "secrets",
                // secret-source files — must only ever exist encrypted
                "auth.json",
                "secrets.json",
                ".env",
                "env",
            ],
        )?;
    }

    if request.with_memory {
        copy_dir_recursive(
            &pi.memory_path(),
            &bundle_dir.join("agent/memory"),
            request.force,
            "memory",
            &ignore,
            &[],
        )?;
    }

    if request.with_skills {
        copy_packages(&pi, bundle_dir, request.force, &ignore)?;
    }

    if request.with_secrets {
        copy_secrets_encrypted(&pi, bundle_dir, request.force)?;
    }

    // ── 6. Update manifest contents ────────────────────────────────
    m.contents.config = request.with_config;
    m.contents.memory = request.with_memory;
    m.contents.skills = request.with_skills;
    m.contents.secrets = request.with_secrets;

    if request.with_skills {
        m.packages = scan_packages(&pi);
    }

    if request.with_secrets {
        m.security.secrets_encrypted = true;
        m.security.encryption = Some(crypto::CRYPTO_FORMAT_IDENTIFIER.to_string());
    }

    // ── 7. Compute integrity checksum ──────────────────────────────
    let checksum = integrity::compute_bundle_checksum(bundle_dir)?;
    m.integrity.checksum = Some(checksum.clone());
    m.integrity.format_version = integrity::INTEGRITY_FORMAT_VERSION;

    // Ensure crypto format version is set
    if m.crypto.is_none() {
        m.crypto = Some(manifest::CryptoMeta {
            format_version: crypto::CRYPTO_FORMAT_VERSION,
        });
    } else if let Some(ref mut crypto_meta) = m.crypto {
        crypto_meta.format_version = crypto::CRYPTO_FORMAT_VERSION;
    }

    // Ensure compatibility is set
    if m.compatibility.is_none() {
        m.compatibility = Some(manifest::Compatibility {
            min_agentpacknest_version: "0.1.0".to_string(),
        });
    }

    // Set origin metadata
    m.origin = Some(manifest::OriginMeta {
        origin_machine: manifest::hostname(),
        packed_at: manifest::now_iso8601(),
        source_state_hash: None, // TODO: compute source state hash
    });

    // ── 8. Save manifest ───────────────────────────────────────────
    manifest::save(&manifest_path, &m).context("failed to save updated manifest")?;

    println!();
    println!("  ✓ manifest.yaml updated (checksum: {})", &checksum[..16]);

    // ── 9. Sign the manifest ───────────────────────────────────────
    let signature = signing::sign_canonical_manifest(&m)
        .context("failed to sign manifest — is your keypair set up?")?;

    let sig_path = bundle_dir.join("manifest.sig");
    signing::save_signature(&sig_path, &signature).context("failed to save signature")?;

    // Save public key for portable verification
    signing::save_public_key(bundle_dir).context("failed to save public key")?;

    println!("  ✓ manifest signed");

    // ── 10. Validate the completed bundle ──────────────────────────
    // Re-verify checksum
    let reverify = integrity::verify_checksum(bundle_dir, &checksum)
        .context("post-pack integrity verification failed")?;
    if !reverify {
        bail!("post-pack integrity check failed — bundle may be corrupted");
    }

    // Re-verify signature
    let sig_reverify = signing::verify_manifest_with_bundled_pubkey(
        &m,
        &sig_path,
        &bundle_dir.join("signing/public.key"),
    )
    .context("post-pack signature verification failed")?;
    if !sig_reverify {
        bail!("post-pack signature check failed — bundle may be corrupted");
    }

    println!("  ✓ bundle validated");

    // ── Summary ────────────────────────────────────────────────────
    println!();
    println!("Pack complete!");
    println!(
        "  Contents:  config={}  memory={}  skills={}  secrets={}",
        flag(request.with_config),
        flag(request.with_memory),
        flag(request.with_skills),
        flag(request.with_secrets)
    );
    println!("  Bundle:    {}/", bundle_dir.display());
    println!();

    Ok(PackBundleResult {
        manifest: m,
        checksum,
    })
}

// ---------------------------------------------------------------------------
// Copy helpers (moved from commands/pack.rs)
// ---------------------------------------------------------------------------

/// Copy a directory tree recursively. Skips if source doesn't exist.
/// Files matching ignore patterns are skipped.
fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
    force: bool,
    label: &str,
    ignore: &IgnorePatterns,
    excluded_names: &[&str],
) -> Result<()> {
    if !src.is_dir() {
        println!("  ⚠ {} not found in Pi installation, skipping", label);
        return Ok(());
    }

    if dst.exists() && !force {
        bail!(
            "destination already exists: {}\n  use --force to overwrite",
            dst.display()
        );
    }

    let mut count = 0u64;
    let mut skipped = 0u64;
    let walker = walkdir::WalkDir::new(src)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok());
    for entry in walker {
        // Reject symlinks — could point outside bundle
        if entry.file_type().is_symlink() {
            bail!(
                "symlink not allowed in bundle: {}\n  hint: remove the symlink from the source",
                entry.path().display()
            );
        }

        let rel = entry.path().strip_prefix(src).unwrap();
        let rel_str = rel.to_string_lossy();

        // Exclude source directories and secret files from plaintext copies
        if is_excluded(&rel_str, excluded_names) {
            skipped += 1;
            continue;
        }

        // Check ignore patterns
        if !ignore.is_empty() && ignore.is_ignored(&rel_str) {
            skipped += 1;
            continue;
        }

        let target = dst.join(rel);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
            count += 1;
        }
    }

    if skipped > 0 {
        println!(
            "  ✓ {} copied ({} files, {} excluded/ignored)",
            label, count, skipped
        );
    } else {
        println!("  ✓ {} copied ({} files)", label, count);
    }
    Ok(())
}

/// True when any path segment is in `excluded_names`, or the file is a
/// secret-source file (`*.env`, `.env`, `env`, auth-style JSON).
fn is_excluded(rel: &str, excluded_names: &[&str]) -> bool {
    let segments: Vec<&str> = rel.split('/').collect();
    let filename = segments.last().copied().unwrap_or("");

    // Directory segment match (excluding the file itself is handled below)
    if segments.len() > 1 {
        for seg in &segments[..segments.len() - 1] {
            if excluded_names.contains(seg) {
                return true;
            }
        }
    }

    if excluded_names.contains(&filename) {
        return true;
    }

    // .env style files, regardless of exact name
    filename == ".env"
        || filename == "env"
        || filename.ends_with(".env")
        || filename == "auth.json"
        || filename == "secrets.json"
}

/// Copy packages (extensions, skills, themes) from Pi into bundle.
/// Files matching ignore patterns are skipped.
fn copy_packages(
    pi: &PiInstallation,
    bundle_dir: &Path,
    force: bool,
    ignore: &IgnorePatterns,
) -> Result<()> {
    let src = pi.packages_path();
    if !src.is_dir() {
        println!("  ⚠ packages/ not found in Pi installation, skipping");
        return Ok(());
    }

    let dst_base = bundle_dir.join("agent/packages");
    let mut total = 0u64;

    for sub in &["extensions", "skills", "themes"] {
        let sub_src = src.join(sub);
        let sub_dst = dst_base.join(sub);

        if sub_src.is_dir() {
            if sub_dst.exists() && !force {
                bail!(
                    "destination already exists: {}\n  use --force to overwrite",
                    sub_dst.display()
                );
            }

            let walker = walkdir::WalkDir::new(&sub_src)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok());
            for entry in walker {
                // Reject symlinks
                if entry.file_type().is_symlink() {
                    bail!("symlink not allowed in bundle: {}", entry.path().display());
                }

                let rel = entry.path().strip_prefix(&sub_src).unwrap();
                let rel_str = rel.to_string_lossy();

                // Secret-source files must never be copied as plaintext
                if is_excluded(&rel_str, &["auth.json", "secrets.json", ".env", "env"]) {
                    continue;
                }

                // Check ignore patterns
                if !ignore.is_empty() && ignore.is_ignored(&rel_str) {
                    continue;
                }

                let target = sub_dst.join(rel);
                if entry.file_type().is_dir() {
                    fs::create_dir_all(&target)?;
                } else {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::copy(entry.path(), &target)?;
                    total += 1;
                }
            }
        }
    }

    println!("  ✓ packages copied ({} files)", total);
    Ok(())
}

/// Scan Pi packages and return manifest entries.
fn scan_packages(pi: &PiInstallation) -> manifest::Packages {
    let src = pi.packages_path();
    let mut ext = Vec::new();
    let mut skills = Vec::new();
    let mut themes = Vec::new();

    for (sub, list) in [
        ("extensions", &mut ext),
        ("skills", &mut skills),
        ("themes", &mut themes),
    ] {
        let dir = src.join(sub);
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        list.push(manifest::PackageEntry {
                            name,
                            version: "0.0.0".to_string(),
                            source: None,
                            path: None,
                        });
                    }
                }
            }
        }
    }

    manifest::Packages {
        extensions: ext,
        skills,
        themes,
    }
}

/// Collect secrets from the Pi installation and write them encrypted to keys.enc.
///
/// Secret sources (scanned in order):
/// 1. `secrets/` directory — each file becomes key=filename, value=content
/// 2. `.env` / `*.env` files — parsed as key=value lines
///
/// **No plaintext is written to disk.**
fn copy_secrets_encrypted(pi: &PiInstallation, bundle_dir: &Path, force: bool) -> Result<()> {
    let secrets_dst = bundle_dir.join("secrets/keys.enc");

    if secrets_dst.exists() && !force {
        bail!("secrets/keys.enc already exists\n  use --force to overwrite");
    }

    // ── Collect secrets ────────────────────────────────────────────
    let mut bundle = SecretsBundle::new();

    // 1. Pi auth.json (API keys / credentials) — one secret per JSON key
    bundle.scan_auth_json(&pi.auth_path())?;

    // 2. Scan secrets/ directory for key files
    bundle.scan_secret_files(&pi.root().join("secrets"))?;

    // 3. Scan .env files at root and in config/
    bundle.scan_env_files(pi.root())?;
    bundle.scan_env_files(&pi.root().join("config"))?;

    if bundle.is_empty() {
        println!("  ⚠ no secrets found in Pi installation, skipping");
        return Ok(());
    }

    println!(
        "  Found {} secret(s): {}",
        bundle.len(),
        bundle.keys().join(", ")
    );

    // ── Prompt for passphrase ──────────────────────────────────────
    let passphrase = crypto::prompt_passphrase_confirm()?;

    // ── Encrypt and write ──────────────────────────────────────────
    if let Some(parent) = secrets_dst.parent() {
        fs::create_dir_all(parent)?;
    }

    bundle
        .save_encrypted(&secrets_dst, &passphrase)
        .context("failed to encrypt and save secrets")?;

    let file_size = fs::metadata(&secrets_dst).map(|m| m.len()).unwrap_or(0);

    println!(
        "  ✓ secrets encrypted → secrets/keys.enc ({} bytes)",
        file_size
    );
    Ok(())
}

fn flag(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Ensure a signing keypair exists (create it on first use).
    fn ensure_keypair() {
        if signing::load_verifying_key().is_err() {
            // Ignore "already exists" races between parallel tests.
            let _ = signing::generate_keypair();
        }
    }

    /// Build a fake Pi agent directory.
    fn fake_pi(dir: &Path) {
        fs::create_dir_all(dir.join("sessions")).unwrap();
        fs::create_dir_all(dir.join("packages/skills/coding")).unwrap();
        fs::create_dir_all(dir.join("extensions")).unwrap();
        fs::write(dir.join("settings.json"), "{\"version\": \"0.5.0\"}").unwrap();
        fs::write(
            dir.join("auth.json"),
            "{\"anthropicApiKey\": \"sk-super-secret-value\"}",
        )
        .unwrap();
        fs::write(dir.join("sessions/2025-01-15.jsonl"), "{}").unwrap();
        fs::write(
            dir.join("packages/skills/coding/prompt.md"),
            "# coding skill",
        )
        .unwrap();
    }

    /// Initialize an empty bundle directory with a default manifest.
    fn init_bundle(dir: &Path, name: &str) {
        let m = manifest::default_pi(name, "0.5.0");
        let manifest_path = dir.join("manifest.yaml");
        manifest::save(&manifest_path, &m).unwrap();
    }

    fn run_pack(bundle: &Path, pi: &Path, flags: Vec<(&str, bool)>) -> PackBundleResult {
        ensure_keypair();
        let request = PackBundleRequest {
            bundle_path: bundle.to_path_buf(),
            harness_path: Some(pi.to_path_buf()),
            with_config: flags.iter().any(|(f, _)| *f == "config"),
            with_memory: flags.iter().any(|(f, _)| *f == "memory"),
            with_skills: flags.iter().any(|(f, _)| *f == "skills"),
            with_secrets: flags.iter().any(|(f, _)| *f == "secrets"),
            force: true,
        };
        execute(request).unwrap()
    }

    fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(dir) {
            let entry = entry.unwrap();
            if entry.file_type().is_file() {
                out.push(entry.path().to_path_buf());
            }
        }
        out
    }

    #[test]
    fn pack_config_excludes_secret_sources() {
        let pi_dir = TempDir::new().unwrap();
        fake_pi(pi_dir.path());
        let bundle_dir = TempDir::new().unwrap();
        init_bundle(bundle_dir.path(), "cfg-agent");

        run_pack(bundle_dir.path(), pi_dir.path(), vec![("config", true)]);

        // Loose config file copied
        assert!(bundle_dir
            .path()
            .join("agent/config/settings.json")
            .is_file());

        // Secret sources must NOT exist anywhere in the bundle as plaintext
        for f in files_under(bundle_dir.path()) {
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            assert_ne!(
                name,
                "auth.json",
                "auth.json leaked into bundle: {}",
                f.display()
            );
            assert!(
                !name.ends_with(".env"),
                "env file leaked into bundle: {}",
                f.display()
            );
        }

        // Component directories are not nested inside config/
        assert!(!bundle_dir.path().join("agent/config/sessions").exists());
        assert!(!bundle_dir.path().join("agent/config/packages").exists());

        // And the secret VALUE never appears in any packed file
        let contents: String = files_under(bundle_dir.path())
            .iter()
            .map(|f| fs::read_to_string(f).unwrap_or_default())
            .collect();
        assert!(
            !contents.contains("sk-super-secret-value"),
            "plaintext secret value leaked into bundle payload"
        );
    }

    #[test]
    fn pack_with_skills_copies_packages_only() {
        let pi_dir = TempDir::new().unwrap();
        fake_pi(pi_dir.path());
        let bundle_dir = TempDir::new().unwrap();
        init_bundle(bundle_dir.path(), "skill-agent");

        run_pack(bundle_dir.path(), pi_dir.path(), vec![("skills", true)]);

        assert!(bundle_dir
            .path()
            .join("agent/packages/skills/coding/prompt.md")
            .is_file());
        assert!(!bundle_dir.path().join("agent/config").exists());
        assert!(!bundle_dir.path().join("agent/packages/auth.json").exists());
    }

    #[test]
    fn pack_sets_formats_and_signs_valid_bundle() {
        let pi_dir = TempDir::new().unwrap();
        fake_pi(pi_dir.path());
        let bundle_dir = TempDir::new().unwrap();
        init_bundle(bundle_dir.path(), "sign-agent");

        let result = run_pack(
            bundle_dir.path(),
            pi_dir.path(),
            vec![("config", true), ("skills", true)],
        );

        // Format versions are recorded in the manifest
        assert_eq!(result.manifest.integrity.format_version, 1);
        assert_eq!(
            result.manifest.crypto.as_ref().unwrap().format_version,
            crypto::CRYPTO_FORMAT_VERSION
        );
        assert_eq!(
            result.manifest.integrity.checksum.as_deref(),
            Some(result.checksum.as_str())
        );

        // Integrity verifies
        assert!(integrity::verify_checksum(bundle_dir.path(), &result.checksum).unwrap());

        // Signature verifies with the bundled public key (portable)
        let sig_path = bundle_dir.path().join("manifest.sig");
        let pubkey_path = bundle_dir.path().join("signing/public.key");
        assert!(sig_path.is_file());
        assert!(pubkey_path.is_file());
        let manifest = manifest::load(&bundle_dir.path().join("manifest.yaml")).unwrap();
        let verified =
            signing::verify_manifest_with_bundled_pubkey(&manifest, &sig_path, &pubkey_path)
                .unwrap();
        assert!(verified);
    }
}

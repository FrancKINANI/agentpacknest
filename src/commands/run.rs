use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process;

use crate::core::manifest;
use crate::security::crypto;
use crate::security::secrets::SecretsBundle;

/// Execute `hh run`.
pub fn execute(
    bundle_path: Option<String>,
    passphrase: Option<String>,
    workdir: Option<String>,
    dry_run: bool,
    args: Vec<String>,
) -> Result<()> {
    // ── 1. Resolve bundle directory ────────────────────────────────
    let bundle_dir = match bundle_path {
        Some(p) => PathBuf::from(&p),
        None => env::current_dir().context("failed to get current directory")?,
    };

    if !bundle_dir.is_dir() {
        bail!(
            "not a directory: {}\n  hint: pass a path to a bundle directory, or '.' for the current directory",
            bundle_dir.display()
        );
    }

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "no manifest.yaml found in {}\n  hint: this doesn't look like an hitchhike bundle — run `hh init` to create one",
            bundle_dir.display()
        );
    }

    // ── 2. Load and validate manifest ──────────────────────────────
    let m = manifest::load(&manifest_path)
        .context("failed to load manifest")?;

    println!("Bundle:   {}", m.bundle.name);
    println!("Harness:  {} v{}", m.harness.name, m.harness.version);

    // ── 3. Check integrity ─────────────────────────────────────────
    if let Some(ref expected) = m.integrity.checksum {
        match verify_checksum(&bundle_dir, expected) {
            Ok(true) => println!("Checksum: ✓ verified"),
            Ok(false) => {
                println!("⚠ WARNING: checksum mismatch!");
                println!("  expected: {}", &expected[..16]);
                println!("  (continuing anyway — this is a warning, not a blocker)");
            }
            Err(e) => println!("⚠ WARNING: could not verify checksum: {}", e),
        }
    } else {
        println!("Checksum: (not set)");
    }

    // ── 4. Check runtime requirements ──────────────────────────────
    if m.harness.name == "pi" {
        check_node_version(20)?;
    }

    // ── 5. Decrypt secrets (in memory only) ────────────────────────
    let secrets = if m.security.secrets_encrypted {
        let enc_path = bundle_dir.join("secrets/keys.enc");
        if !enc_path.is_file() {
            bail!(
                "manifest says secrets are encrypted but secrets/keys.enc is missing\n  hint: re-run `hh pack --with-secrets` to regenerate the encrypted file"
            );
        }

        let pass = match passphrase {
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

    // ── 6. Prepare working directory ───────────────────────────────
    let run_workdir = match workdir {
        Some(w) => PathBuf::from(w),
        None => bundle_dir
            .join(m.launch.working_directory.as_deref().unwrap_or(".")),
    };

    if !run_workdir.is_dir() {
        bail!(
            "working directory does not exist: {}\n  hint: check the --workdir flag or launch.working_directory in manifest.yaml",
            run_workdir.display()
        );
    }

    // ── 7. Build environment ───────────────────────────────────────
    let env_vars = build_env(&bundle_dir, &m, secrets.as_ref());

    // ── 8. Resolve command ─────────────────────────────────────────
    let command_parts: Vec<&str> = m.launch.command.split_whitespace().collect();
    if command_parts.is_empty() {
        bail!("launch.command is empty in manifest");
    }

    let cmd_name = command_parts[0];
    let mut cmd_args: Vec<&str> = command_parts[1..].iter().copied().collect();
    cmd_args.extend(args.iter().map(|s| s.as_str()));

    // ── 9. Dry run or execute ──────────────────────────────────────
    println!();
    println!("Working dir: {}", run_workdir.display());
    println!("Command:     {} {}", cmd_name, cmd_args.join(" "));

    if !env_vars.is_empty() {
        println!("Env vars:    {} set", env_vars.len());
        for key in env_vars.keys() {
            println!("             {}", key);
        }
    }

    if dry_run {
        println!();
        println!("(dry run — not executing)");
        return Ok(());
    }

    println!();
    println!("Starting agent...");
    println!();

    // Run the command with our env vars injected
    let exit_code = run_command(cmd_name, &cmd_args, &run_workdir, &env_vars)?;

    // ── 10. Cleanup ────────────────────────────────────────────────
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

    process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

/// Verify the bundle checksum against manifest.
fn verify_checksum(bundle_dir: &Path, expected: &str) -> Result<bool> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut files: Vec<_> = walkdir::WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            !(name == "keys.enc")
        })
        .collect();
    files.sort_by_key(|e| e.path().to_path_buf());

    for entry in &files {
        if let Ok(content) = std::fs::read(entry.path()) {
            let rel = entry.path().strip_prefix(bundle_dir).unwrap();
            hasher.update(rel.to_string_lossy().as_bytes());
            hasher.update(&content);
        }
    }

    let computed = hex::encode(hasher.finalize());
    Ok(computed == expected)
}

// ---------------------------------------------------------------------------
// Runtime checks
// ---------------------------------------------------------------------------

/// Check that a command is available and meets a minimum major version.
/// For now only `node >= 20` is checked (Pi harness).
fn check_node_version(min_major: u32) -> Result<()> {
    let output = process::Command::new("node")
        .arg("--version")
        .output()
        .context(
            "Node.js is not installed or not in PATH\n  \
             Pi requires Node.js >= 20\n  \
             install: https://nodejs.org/ or use `nvm install 20`",
        )?;

    if !output.status.success() {
        bail!(
            "failed to run `node --version`\n  \
             Pi requires Node.js >= 20\n  \
             install: https://nodejs.org/"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_str = stdout.trim().trim_start_matches('v');

    let parts: Vec<&str> = version_str.split('.').collect();
    let major: u32 = parts.first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if major < min_major {
        bail!(
            "Node.js v{} detected, but Pi requires >= v{}.0\n  \
             upgrade: https://nodejs.org/ or `nvm install {}`",
            version_str, min_major, min_major
        );
    }

    println!("Node.js:   v{} ✓", version_str);
    Ok(())
}

// ---------------------------------------------------------------------------
// Environment setup
// ---------------------------------------------------------------------------

/// Build environment variables for the agent process.
///
/// - Sets `HITCHHIKE_BUNDLE` to the bundle path
/// - Sets `HITCHHIKE_HARNESS` to the harness name
/// - Injects decrypted secrets as individual env vars
fn build_env(
    bundle_dir: &Path,
    m: &manifest::Manifest,
    secrets: Option<&SecretsBundle>,
) -> HashMap<String, String> {
    let mut env = HashMap::new();

    // Core hitchhike vars
    env.insert(
        "HITCHHIKE_BUNDLE".to_string(),
        bundle_dir.to_string_lossy().into_owned(),
    );
    env.insert(
        "HITCHHIKE_HARNESS".to_string(),
        m.harness.name.clone(),
    );

    // Agent-specific dirs
    let agent_dir = bundle_dir.join("agent");
    env.insert(
        "HITCHHIKE_CONFIG".to_string(),
        agent_dir.join("config").to_string_lossy().into_owned(),
    );
    env.insert(
        "HITCHHIKE_MEMORY".to_string(),
        agent_dir.join("memory").to_string_lossy().into_owned(),
    );
    env.insert(
        "HITCHHIKE_PACKAGES".to_string(),
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
    let mut command = process::Command::new(cmd);
    command.args(args);
    command.current_dir(workdir);

    // Clear inherited env and set only our vars
    // This minimizes environment pollution
    command.env_clear();

    // Inherit essential system vars
    // Unix: PATH, HOME, USER, SHELL, LANG, etc.
    // Windows: SystemRoot, COMSPEC, PATHEXT, TEMP, etc.
    let inherit_keys = if cfg!(target_os = "windows") {
        &["PATH", "HOME", "USER", "SystemRoot", "COMSPEC", "PATHEXT", "TEMP", "TMP"] as &[&str]
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

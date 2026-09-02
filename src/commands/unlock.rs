use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;

use crate::core::manifest;
use crate::security::crypto;
use crate::security::secrets::SecretsBundle;

/// Execute `pn unlock`.
pub fn execute(bundle_path: Option<String>, show: bool, env_mode: bool) -> Result<()> {
    // ── 1. Resolve bundle directory ────────────────────────────────
    let bundle_dir = match bundle_path {
        Some(p) => PathBuf::from(p),
        None => env::current_dir().context("failed to get current directory")?,
    };

    if !bundle_dir.is_dir() {
        bail!(
            "not a directory: {}\n  hint: pass a path to a bundle directory",
            bundle_dir.display()
        );
    }

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "no manifest.yaml found in {}\n  hint: this doesn't look like an agentpacknest bundle",
            bundle_dir.display()
        );
    }

    // ── 2. Load manifest ───────────────────────────────────────────
    let m = manifest::load(&manifest_path).context("failed to load manifest")?;

    println!("Bundle:   {}", m.bundle.name);
    println!("Harness:  {} v{}", m.harness.name, m.harness.version);

    // ── 3. Check for encrypted secrets ─────────────────────────────
    if !m.security.secrets_encrypted {
        println!();
        println!("No encrypted secrets in this bundle.");
        println!("hint: use `pn pack --with-secrets` to add encrypted secrets.");
        return Ok(());
    }

    let enc_path = bundle_dir.join("secrets/keys.enc");
    if !enc_path.is_file() {
        bail!(
            "manifest says secrets are encrypted but secrets/keys.enc is missing\n  hint: re-run `pn pack --with-secrets` to regenerate"
        );
    }

    // ── 4. Decrypt ─────────────────────────────────────────────────
    let passphrase = crypto::prompt_passphrase("Passphrase")?;

    let secrets = SecretsBundle::load_decrypted(&enc_path, &passphrase)
        .context("decryption failed — wrong passphrase?")?;

    println!();
    println!("Decrypted {} secret(s):", secrets.len());
    println!();

    // ── 5. Display ─────────────────────────────────────────────────
    if env_mode {
        for line in secrets.display_env() {
            println!("{}", line);
        }
    } else if show {
        println!("  ⚠ Showing full secret values");
        println!();
        for line in secrets.display_full() {
            println!("{}", line);
        }
    } else {
        println!("  (values masked — use --show to reveal)");
        println!();
        for line in secrets.display_masked() {
            println!("{}", line);
        }
    }

    // ── 6. Cleanup ─────────────────────────────────────────────────
    // `secrets` is dropped here — in-memory only, never persisted.
    println!();
    println!("Secrets cleared from memory.");
    Ok(())
}

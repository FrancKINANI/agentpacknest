use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::core::manifest;
use crate::security::crypto;
use crate::security::secrets::SecretsBundle;

/// Execute `pn rekey`.
pub fn execute(bundle_path: Option<String>) -> Result<()> {
    // ── 1. Resolve bundle ──────────────────────────────────────────
    let bundle_dir = match bundle_path {
        Some(p) => PathBuf::from(&p),
        None => std::env::current_dir().context("failed to get current directory")?,
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
            "no manifest.yaml found in {}\n  hint: this doesn't look like a agentpacknest bundle",
            bundle_dir.display()
        );
    }

    // ── 2. Load manifest ──────────────────────────────────────────
    let m = manifest::load(&manifest_path).context("failed to load manifest")?;

    if !m.security.secrets_encrypted {
        bail!(
            "no encrypted secrets in this bundle\n  hint: rekey only works on bundles packed with --with-secrets"
        );
    }

    // ── 3. Check keys.enc exists ──────────────────────────────────
    let enc_path = bundle_dir.join("secrets/keys.enc");
    if !enc_path.is_file() {
        bail!(
            "secrets/keys.enc is missing\n  hint: re-run `pn pack --with-secrets` to regenerate the encrypted file"
        );
    }

    println!("Bundle:   {}", m.bundle.name);
    println!("Harness:  {} v{}", m.harness.name, m.harness.version);
    println!();

    // ── 4. Prompt for old passphrase ───────────────────────────────
    let old_pass = crypto::prompt_passphrase("Current passphrase")?;

    // ── 5. Decrypt with old passphrase (verify it works) ──────────
    print!("  Decrypting with current passphrase...");
    let bundle = SecretsBundle::load_decrypted(&enc_path, &old_pass)
        .context("decryption failed — wrong passphrase?")?;
    println!(" ✓ ({} keys)", bundle.len());

    // ── 6. Prompt for new passphrase ───────────────────────────────
    println!();
    let new_pass = crypto::prompt_passphrase_confirm()?;

    if old_pass == new_pass {
        bail!("new passphrase is the same as the old one");
    }

    // ── 7. Re-encrypt with new passphrase ──────────────────────────
    print!("  Re-encrypting with new passphrase...");
    SecretsBundle::rekey(&enc_path, &old_pass, &new_pass)
        .context("failed to re-encrypt secrets")?;
    println!(" ✓");

    // ── 8. Verify the new passphrase works ─────────────────────────
    print!("  Verifying new passphrase...");
    let _verify = SecretsBundle::load_decrypted(&enc_path, &new_pass)
        .context("verification failed — something went wrong during rekey")?;
    println!(" ✓");

    // ── Summary ────────────────────────────────────────────────────
    println!();
    println!("Passphrase rotated successfully!");
    println!("  Bundle:  {}", bundle_dir.display());
    println!("  Keys:    {} secrets re-encrypted", bundle.len());
    println!();

    Ok(())
}

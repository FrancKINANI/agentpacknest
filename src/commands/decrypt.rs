//! `pn decrypt` command — decrypt an archive produced by
//! `pn pack --archive --encrypt-archive`.
//!
//! The encrypted archive is a full `.tar.gz` wrapped in the same versioned
//! AES-256-GCM + Argon2id envelope used for `secrets/keys.enc`
//! (`crypto::encrypt_secrets`, crypto format v1). Decrypting restores the
//! plain `.tar.gz`, which the recipient can then extract with `tar`.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::security::crypto;

/// Execute `pn decrypt <file.enc>`.
pub fn execute(file: String) -> Result<()> {
    // ── 1. Resolve input ──────────────────────────────────────────
    let input = PathBuf::from(&file);

    if !input.is_file() {
        bail!(
            "not a file: {}\n  hint: pass the path to an encrypted archive (.tar.gz.enc)",
            file
        );
    }

    let file_name = input
        .file_name()
        .and_then(|n| n.to_str())
        .context("archive filename is not valid UTF-8")?;
    let Some(stem) = file_name.strip_suffix(".enc") else {
        bail!(
            "expected a '.enc' archive, got '{}'\n  \
             hint: pn decrypt only decrypts files produced by `pn pack --archive --encrypt-archive`",
            file
        );
    };

    // Output sits next to the input, with the `.enc` suffix removed.
    let output = input.with_file_name(stem);
    if output.exists() {
        bail!(
            "output already exists: {}\n  hint: move the existing file or decrypt into a different directory",
            output.display()
        );
    }

    // ── 2. Prompt for passphrase ───────────────────────────────────
    let passphrase = crypto::prompt_passphrase("Passphrase")?;

    // ── 3. Decrypt (same versioned envelope as secrets/keys.enc) ───
    let mut encrypted =
        fs::read(&input).with_context(|| format!("failed to read archive: {}", input.display()))?;
    let mut plaintext = crypto::decrypt_secrets(&passphrase, &encrypted)
        .context("decryption failed — wrong passphrase or corrupted archive")?;

    // ── 4. Write the decrypted .tar.gz ─────────────────────────────
    fs::write(&output, &plaintext)
        .with_context(|| format!("failed to write decrypted archive: {}", output.display()))?;

    let size = fs::metadata(&output)
        .map(|m| m.len() as f64 / 1024.0)
        .unwrap_or(0.0);
    println!("Archive:  {}", input.display());
    println!("  ✓ decrypted → {} ({:.1} KB)", output.display(), size);
    println!(
        "  next: tar xzf {}",
        output.file_name().unwrap_or_default().to_string_lossy()
    );

    // ── 5. Cleanup ─────────────────────────────────────────────────
    // The plaintext archive and the encrypted bytes only ever existed in
    // memory; zeroize them before dropping.
    plaintext.zeroize();
    encrypted.zeroize();

    Ok(())
}

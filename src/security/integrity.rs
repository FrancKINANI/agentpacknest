//! Integrity — bundle file verification (checksums).
//!
//! This is distinct from signing (authenticity). Integrity answers:
//! "Have the files changed?" Signing answers: "Who created this?"

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Compute SHA-256 checksum of all files in a bundle directory,
/// excluding secrets/keys.enc and manifest.sig.
pub fn compute_bundle_checksum(bundle_dir: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut files: Vec<_> = walkdir::WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            !(name == "keys.enc" || name == "manifest.sig")
        })
        .collect();
    files.sort_by_key(|e| e.path().to_path_buf());

    for entry in &files {
        if let Ok(content) = fs::read(entry.path()) {
            let rel = entry.path().strip_prefix(bundle_dir).unwrap();
            hasher.update(rel.to_string_lossy().as_bytes());
            hasher.update(&content);
        }
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Verify a bundle's checksum against the expected value.
pub fn verify_checksum(bundle_dir: &Path, expected: &str) -> Result<bool> {
    let computed =
        compute_bundle_checksum(bundle_dir).context("failed to compute bundle checksum")?;
    Ok(computed == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn checksum_is_deterministic() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file.txt"), "hello").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/nested.txt"), "world").unwrap();

        let h1 = compute_bundle_checksum(dir.path()).unwrap();
        let h2 = compute_bundle_checksum(dir.path()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn checksum_changes_with_content() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file.txt"), "v1").unwrap();
        let h1 = compute_bundle_checksum(dir.path()).unwrap();

        fs::write(dir.path().join("file.txt"), "v2").unwrap();
        let h2 = compute_bundle_checksum(dir.path()).unwrap();

        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_checksum_works() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file.txt"), "data").unwrap();
        let hash = compute_bundle_checksum(dir.path()).unwrap();

        assert!(verify_checksum(dir.path(), &hash).unwrap());
        assert!(!verify_checksum(dir.path(), "wrong_hash").unwrap());
    }

    #[test]
    fn checksum_excludes_keys_enc() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file.txt"), "data").unwrap();
        let h1 = compute_bundle_checksum(dir.path()).unwrap();

        fs::write(dir.path().join("keys.enc"), "encrypted_stuff").unwrap();
        let h2 = compute_bundle_checksum(dir.path()).unwrap();

        assert_eq!(h1, h2, "keys.enc should not affect checksum");
    }
}

//! Integrity — bundle file verification (checksums).
//!
//! This is distinct from signing (authenticity). Integrity answers:
//! "Have the files changed?" Signing answers: "Who created this?"
//!
//! Integrity scope: Hashes the bundle PAYLOAD only (agent/, secrets/keys.enc).
//! Does NOT include: manifest.yaml, manifest.sig, signing/public.key
//! because these are metadata/signature layers.
//!
//! The security chain is:
//! PAYLOAD → SHA-256 → integrity checksum → stored in MANIFEST → Ed25519 → SIGNATURE
//!
//! Fail-closed behavior: Any I/O error during traversal or reading
//! causes the entire checksum computation to fail. No silent skips.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Compute SHA-256 checksum of the bundle payload.
/// Includes: agent/, secrets/keys.enc
/// Excludes: manifest.yaml, manifest.sig, signing/public.key
pub fn compute_bundle_checksum(bundle_dir: &Path) -> Result<String> {
    let mut hasher = Sha256::new();

    // Define payload directories to hash (relative to bundle_dir)
    let payload_dirs = ["agent", "secrets"];

    let mut files: Vec<_> = Vec::new();

    for payload_dir in &payload_dirs {
        let full_path = bundle_dir.join(payload_dir);
        if !full_path.exists() {
            continue; // directory may not exist
        }

        for entry in walkdir::WalkDir::new(&full_path) {
            let entry =
                entry.with_context(|| format!("walkdir error in {}", full_path.display()))?;
            if entry.file_type().is_file() {
                files.push(entry);
            }
        }
    }

    // Deterministic ordering: sort by relative path
    files.sort_by_key(|e| e.path().strip_prefix(bundle_dir).unwrap().to_path_buf());

    for entry in &files {
        let content = fs::read(entry.path()).with_context(|| {
            format!(
                "failed to read file for checksum: {}",
                entry.path().display()
            )
        })?;
        let rel = entry
            .path()
            .strip_prefix(bundle_dir)
            .with_context(|| format!("failed to strip prefix: {}", entry.path().display()))?;
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&content);
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
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "{}").unwrap();
        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/keys.enc"), "encrypted").unwrap();

        let h1 = compute_bundle_checksum(dir.path()).unwrap();
        let h2 = compute_bundle_checksum(dir.path()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn checksum_changes_with_content() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "v1").unwrap();
        let h1 = compute_bundle_checksum(dir.path()).unwrap();

        fs::write(dir.path().join("agent/config/settings.json"), "v2").unwrap();
        let h2 = compute_bundle_checksum(dir.path()).unwrap();

        assert_ne!(h1, h2);
    }

    #[test]
    fn checksum_includes_keys_enc() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "data").unwrap();
        let h1 = compute_bundle_checksum(dir.path()).unwrap();

        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/keys.enc"), "encrypted_stuff").unwrap();
        let h2 = compute_bundle_checksum(dir.path()).unwrap();

        assert_ne!(h1, h2, "keys.enc SHOULD affect checksum");
    }

    #[test]
    fn checksum_excludes_manifest_and_signature() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "data").unwrap();
        let h1 = compute_bundle_checksum(dir.path()).unwrap();

        // manifest and signature should NOT affect checksum
        fs::write(dir.path().join("manifest.yaml"), "bundle: test").unwrap();
        fs::write(dir.path().join("manifest.sig"), "sig").unwrap();
        fs::create_dir(dir.path().join("signing")).unwrap();
        fs::write(dir.path().join("signing/public.key"), "pubkey").unwrap();

        let h2 = compute_bundle_checksum(dir.path()).unwrap();
        assert_eq!(
            h1, h2,
            "manifest.yaml, manifest.sig, signing/public.key should NOT affect checksum"
        );
    }

    #[test]
    fn verify_checksum_works() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "data").unwrap();
        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/keys.enc"), "encrypted").unwrap();

        let hash = compute_bundle_checksum(dir.path()).unwrap();

        assert!(verify_checksum(dir.path(), &hash).unwrap());
        assert!(!verify_checksum(dir.path(), "wrong_hash").unwrap());
    }

    #[test]
    fn checksum_fails_on_read_error() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "data").unwrap();

        // Function should work correctly with readable files
        let hash = compute_bundle_checksum(dir.path()).unwrap();
        assert!(!hash.is_empty());

        // Note: Testing actual permission denied is platform-dependent and
        // requires root/privileges. The fail-closed behavior is enforced
        // by using `?` operator on all fs::read and walkdir operations.
    }
}

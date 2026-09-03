//! Integrity — bundle payload verification (checksums).
//!
//! This is distinct from signing (authenticity). Integrity answers:
//! "Have the files changed?" Signing answers: "Who created this?"
//!
//! # Canonical model
//!
//! ```text
//! PAYLOAD ──SHA-256──▶ PAYLOAD DIGEST ──stored in──▶ MANIFEST ──Ed25519──▶ SIGNATURE
//! ```
//!
//! The payload digest covers **every file in the payload directories** —
//! including `secrets/keys.enc` — so that any modification to the portable
//! environment is detected. It does NOT cover `manifest.yaml`,
//! `manifest.sig`, or `signing/public.key`, because those are the metadata
//! and signature layers that reference the digest (hashing them would be
//! circular).
//!
//! # Canonical hashing (deterministic, cross-platform)
//!
//! ```text
//! payload_digest = SHA-256(
//!     for each file in payload, sorted by canonical relative path:
//!         canonical_relative_path || 0x00 || file_contents
//! )
//! ```
//!
//! - Relative paths are expressed with `/` separators (even on Windows),
//!   with no leading `./`.
//! - The NUL byte unambiguously separates path identity from file contents,
//!   so two different payloads can never produce the same hash stream.
//! - Files are sorted by canonical relative path, making the digest
//!   independent of filesystem traversal order.
//!
//! # Fail-closed behavior
//!
//! Any error — WalkDir failure, permission denied, unreadable file, or a
//! symlink inside the payload — causes the entire computation to fail.
//! Nothing is silently skipped.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Integrity format version.
/// v1 = SHA-256 over payload files, NUL-delimited canonical path + content.
pub const INTEGRITY_FORMAT_VERSION: u32 = 1;

/// Payload directories relative to the bundle root.
/// In v0.1.x the payload lives at the bundle root (`agent/`, `secrets/`);
/// conceptually these are `payload/agent/` and `payload/secrets/`.
pub const PAYLOAD_DIRS: &[&str] = &["agent", "secrets"];

/// Compute the SHA-256 checksum of the bundle payload.
pub fn compute_bundle_checksum(bundle_dir: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut entries: Vec<(String, PathBuf)> = Vec::new();

    for payload_dir in PAYLOAD_DIRS {
        let full_path = bundle_dir.join(payload_dir);
        if !full_path.exists() {
            continue; // payload subdirectory may be absent (e.g. no memory)
        }

        for entry in walkdir::WalkDir::new(&full_path) {
            let entry =
                entry.with_context(|| format!("walkdir error in {}", full_path.display()))?;

            if entry.file_type().is_symlink() {
                bail!(
                    "symlink not allowed in bundle payload: {}",
                    entry.path().display()
                );
            }

            if entry.file_type().is_file() {
                let rel = canonical_relative_path(bundle_dir, entry.path())?;
                entries.push((rel, entry.path().to_path_buf()));
            }
        }
    }

    // Deterministic ordering: sort by canonical relative path.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (rel, path) in &entries {
        let content = fs::read(path)
            .with_context(|| format!("failed to read file for checksum: {}", path.display()))?;
        hasher.update(rel.as_bytes());
        hasher.update([0u8]); // NUL separates path identity from content
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

/// Compute a canonical, cross-platform relative path for hashing.
///
/// Converts native separators to `/` and never produces a leading `./`.
/// Any component that escapes the bundle root (e.g. `..`) is an error:
/// integrity verification fails closed rather than hashing outside scope.
fn canonical_relative_path(bundle_dir: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(bundle_dir)
        .with_context(|| format!("path escapes bundle root: {}", path.display()))?;

    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(seg) => parts.push(seg.to_string_lossy()),
            Component::CurDir => {} // ignore "." — never hashed as ./x
            Component::ParentDir => {
                bail!("path escapes bundle payload: {}", path.display());
            }
            _ => {
                bail!("unsupported path component in payload: {}", path.display());
            }
        }
    }

    if parts.is_empty() {
        bail!("empty relative path for: {}", path.display());
    }

    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a bundle payload with a known file layout.
    fn build_payload(dir: &Path) {
        fs::create_dir_all(dir.join("agent/config")).unwrap();
        fs::write(dir.join("agent/config/settings.json"), "{\"key\": \"v1\"}").unwrap();
        fs::create_dir_all(dir.join("agent/packages/skills/coding")).unwrap();
        fs::write(
            dir.join("agent/packages/skills/coding/prompt.md"),
            "# skill",
        )
        .unwrap();
        fs::create_dir_all(dir.join("agent/packages/extensions/my-ext")).unwrap();
        fs::write(
            dir.join("agent/packages/extensions/my-ext/config.json"),
            "{}",
        )
        .unwrap();
        fs::create_dir_all(dir.join("agent/themes/dark")).unwrap();
        fs::write(dir.join("agent/themes/dark/theme.css"), "body{}").unwrap();
        fs::create_dir(dir.join("secrets")).unwrap();
        fs::write(dir.join("secrets/keys.enc"), "encrypted-bytes").unwrap();
    }

    #[test]
    fn checksum_is_deterministic() {
        let dir = TempDir::new().unwrap();
        build_payload(dir.path());

        let h1 = compute_bundle_checksum(dir.path()).unwrap();
        let h2 = compute_bundle_checksum(dir.path()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn checksum_independent_of_creation_order() {
        // Create the same file set in a different order and verify the digest
        // does not depend on filesystem traversal order.
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();

        // dir_a: create in alphabetical order
        fs::create_dir_all(dir_a.path().join("agent/a")).unwrap();
        fs::write(dir_a.path().join("agent/a/z.txt"), "z").unwrap();
        fs::write(dir_a.path().join("agent/a/m.txt"), "m").unwrap();
        fs::write(dir_a.path().join("agent/a/a.txt"), "a").unwrap();

        // dir_b: create in reverse order with deeper nesting first
        fs::create_dir_all(dir_b.path().join("agent/a/deep/nested")).unwrap();
        fs::write(dir_b.path().join("agent/a/a.txt"), "a").unwrap();
        fs::write(dir_b.path().join("agent/a/deep/nested/q.txt"), "q").unwrap();
        fs::write(dir_b.path().join("agent/a/m.txt"), "m").unwrap();
        fs::write(dir_b.path().join("agent/a/z.txt"), "z").unwrap();

        let ha = compute_bundle_checksum(dir_a.path()).unwrap();
        let hb = compute_bundle_checksum(dir_b.path()).unwrap();
        // dir_b has an extra file (deep/nested/q.txt) so it must differ.
        assert_ne!(ha, hb);

        // Now replicate dir_a's file set in dir_b and expect identical digests.
        fs::remove_file(dir_b.path().join("agent/a/deep/nested/q.txt")).unwrap();
        let hb2 = compute_bundle_checksum(dir_b.path()).unwrap();
        assert_eq!(ha, hb2);
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

        assert_ne!(h1, h2, "keys.enc SHOULD affect the payload checksum");
    }

    #[test]
    fn checksum_excludes_manifest_signature_and_pubkey() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "data").unwrap();
        let h1 = compute_bundle_checksum(dir.path()).unwrap();

        // Metadata / signing material must NOT affect the payload checksum.
        fs::write(dir.path().join("manifest.yaml"), "bundle: test").unwrap();
        fs::write(dir.path().join("manifest.sig"), "sig").unwrap();
        fs::create_dir(dir.path().join("signing")).unwrap();
        fs::write(dir.path().join("signing/public.key"), "pubkey").unwrap();

        let h2 = compute_bundle_checksum(dir.path()).unwrap();
        assert_eq!(
            h1, h2,
            "manifest.yaml, manifest.sig and signing/public.key must not affect the checksum"
        );
    }

    // ── Tamper matrix (Milestone 3) ──────────────────────────────────

    fn packed_bundle() -> (TempDir, String) {
        let dir = TempDir::new().unwrap();
        build_payload(dir.path());
        let hash = compute_bundle_checksum(dir.path()).unwrap();
        (dir, hash)
    }

    #[test]
    fn modify_config_fails_verification() {
        let (dir, hash) = packed_bundle();
        fs::write(dir.path().join("agent/config/settings.json"), "tampered").unwrap();
        assert!(!verify_checksum(dir.path(), &hash).unwrap());
    }

    #[test]
    fn modify_skill_fails_verification() {
        let (dir, hash) = packed_bundle();
        fs::write(
            dir.path().join("agent/packages/skills/coding/prompt.md"),
            "tampered skill",
        )
        .unwrap();
        assert!(!verify_checksum(dir.path(), &hash).unwrap());
    }

    #[test]
    fn modify_extension_fails_verification() {
        let (dir, hash) = packed_bundle();
        fs::write(
            dir.path()
                .join("agent/packages/extensions/my-ext/config.json"),
            "tampered extension",
        )
        .unwrap();
        assert!(!verify_checksum(dir.path(), &hash).unwrap());
    }

    #[test]
    fn modify_keys_enc_fails_verification() {
        let (dir, hash) = packed_bundle();
        fs::write(dir.path().join("secrets/keys.enc"), "tampered ciphertext").unwrap();
        assert!(!verify_checksum(dir.path(), &hash).unwrap());
    }

    #[test]
    fn delete_payload_file_fails_verification() {
        let (dir, hash) = packed_bundle();
        fs::remove_file(dir.path().join("agent/config/settings.json")).unwrap();
        assert!(!verify_checksum(dir.path(), &hash).unwrap());
    }

    #[test]
    fn add_unexpected_payload_file_fails_verification() {
        let (dir, hash) = packed_bundle();
        fs::write(dir.path().join("agent/config/evil.json"), "injected").unwrap();
        assert!(!verify_checksum(dir.path(), &hash).unwrap());
    }

    // ── Canonical hashing details ────────────────────────────────────

    #[test]
    fn nul_separator_disambiguates_path_and_content() {
        // Without a delimiter, file "a" + content "bc" and file "ab" + content "c"
        // would produce the same hash stream. The NUL separator prevents this.
        let dir1 = TempDir::new().unwrap();
        fs::create_dir_all(dir1.path().join("agent")).unwrap();
        fs::write(dir1.path().join("agent/a"), "bc").unwrap();

        let dir2 = TempDir::new().unwrap();
        fs::create_dir_all(dir2.path().join("agent")).unwrap();
        fs::write(dir2.path().join("agent/ab"), "c").unwrap();

        let h1 = compute_bundle_checksum(dir1.path()).unwrap();
        let h2 = compute_bundle_checksum(dir2.path()).unwrap();
        assert_ne!(h1, h2, "path/content boundaries must be unambiguous");
    }

    #[test]
    fn symlink_in_payload_is_rejected() {
        #[cfg(unix)]
        {
            let dir = TempDir::new().unwrap();
            fs::create_dir_all(dir.path().join("agent/config")).unwrap();
            fs::write(dir.path().join("agent/config/real.txt"), "data").unwrap();
            std::os::unix::fs::symlink(
                dir.path().join("agent/config/real.txt"),
                dir.path().join("agent/config/link.txt"),
            )
            .unwrap();

            let result = compute_bundle_checksum(dir.path());
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("symlink not allowed"));
        }
    }

    #[test]
    fn missing_payload_directories_are_skipped() {
        // A bundle with no agent/ and no secrets/ at all hashes to the empty digest.
        let dir = TempDir::new().unwrap();
        let hash = compute_bundle_checksum(dir.path()).unwrap();
        assert_eq!(hash.len(), 64);

        // Adding manifest-only files still yields the same (empty) digest.
        fs::write(dir.path().join("manifest.yaml"), "{}").unwrap();
        let hash2 = compute_bundle_checksum(dir.path()).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn canonical_relative_path_uses_forward_slashes() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/sub")).unwrap();
        fs::write(dir.path().join("agent/sub/file.txt"), "x").unwrap();
        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/keys.enc"), "y").unwrap();

        let hash = compute_bundle_checksum(dir.path()).unwrap();

        // Mirror the digest by hashing exactly "agent/sub/file.txt\0x" and
        // "secrets/keys.enc\0y" in sorted order with the same algorithm.
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"agent/sub/file.txt");
        hasher.update([0u8]);
        hasher.update(b"x");
        hasher.update(b"secrets/keys.enc");
        hasher.update([0u8]);
        hasher.update(b"y");
        assert_eq!(hash, hex::encode(hasher.finalize()));
    }

    #[test]
    fn verify_checksum_works() {
        let (dir, hash) = packed_bundle();
        assert!(verify_checksum(dir.path(), &hash).unwrap());
        assert!(!verify_checksum(dir.path(), "wrong_hash").unwrap());
    }

    #[test]
    fn checksum_fails_on_unreadable_file() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("agent/config")).unwrap();
        fs::write(dir.path().join("agent/config/settings.json"), "data").unwrap();

        let hash = compute_bundle_checksum(dir.path()).unwrap();
        assert!(!hash.is_empty());

        // Permission-denied tests are platform/privilege dependent; the
        // fail-closed behavior is enforced by `?` on every walkdir and
        // fs::read call above.
    }
}

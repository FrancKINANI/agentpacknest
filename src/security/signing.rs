//! Bundle signing with ed25519.
//!
//! Each user has a keypair stored at `~/.config/agentpacknest/keypair`.
//! - `pn pack` signs the canonical manifest JSON bytes with the private key.
//! - `pn info` and `pn run` verify the signature using the bundled public key.
//!
//! The signature is stored as `manifest.sig` alongside the bundle.
//! The public key is stored as `signing/public.key` for portable verification.
//!
//! This is NOT a security boundary — it's a tamper-evident seal.
//!
//! IMPORTANT: A valid signature proves control of the private key
//! corresponding to the public key used for verification — it does NOT prove
//! the signer's real-world identity or that the signer is trustworthy.
//! Trusting a key is a SEPARATE problem. This implementation does NOT provide
//! a PKI, certificate authority, or trust network.

use anyhow::{bail, Context, Result};
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fs;
use std::path::{Path, PathBuf};

/// Directory where agentpacknest stores its config (keypair, etc.).
fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .context("could not determine config directory")?;
    Ok(base.join("agentpacknest"))
}

/// Path to the signing keypair file.
fn keypair_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("keypair"))
}

/// Generate a new signing keypair and save it to disk.
/// Returns the verifying (public) key bytes.
pub fn generate_keypair() -> Result<[u8; 32]> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create config dir: {}", dir.display()))?;

    let path = keypair_path()?;
    if path.is_file() {
        bail!(
            "keypair already exists at {}\n  hint: delete it first to generate a new one",
            path.display()
        );
    }

    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Save as 32-byte seed
    let seed = signing_key.to_bytes();
    fs::write(&path, seed)
        .with_context(|| format!("failed to write keypair: {}", path.display()))?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(verifying_key.to_bytes())
}

/// Load the signing keypair from disk.
fn load_signing_key() -> Result<SigningKey> {
    let path = keypair_path()?;
    let seed = fs::read(&path).with_context(|| {
        format!(
            "failed to read keypair: {}\n  hint: run `pn init` to generate one",
            path.display()
        )
    })?;

    if seed.len() != 32 {
        bail!(
            "invalid keypair file: expected 32 bytes, got {}",
            seed.len()
        );
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&bytes))
}

/// Load the verifying (public) key from disk.
pub fn load_verifying_key() -> Result<VerifyingKey> {
    let signing_key = load_signing_key()?;
    Ok(signing_key.verifying_key())
}

/// Get the public key bytes for embedding in bundle.
pub fn get_public_key_bytes() -> Result<[u8; 32]> {
    let vk = load_verifying_key()?;
    Ok(vk.to_bytes())
}

/// Sign canonical manifest JSON bytes with the user's keypair.
/// This is the primary signing method for v0.1.1+.
pub fn sign_canonical_manifest(manifest: &crate::domain::manifest::Manifest) -> Result<Vec<u8>> {
    let canonical_bytes = manifest.canonical_json()?;
    let signing_key = load_signing_key()?;
    let signature = signing_key.sign(&canonical_bytes);
    Ok(signature.to_bytes().to_vec())
}

/// Sign arbitrary bytes with the user's keypair (legacy/compat).
pub fn sign(data: &[u8]) -> Result<Vec<u8>> {
    let signing_key = load_signing_key()?;
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a signature against data and a public key.
pub fn verify(data: &[u8], signature_bytes: &[u8], public_key_bytes: &[u8]) -> Result<bool> {
    if public_key_bytes.len() != 32 {
        bail!(
            "invalid public key: expected 32 bytes, got {}",
            public_key_bytes.len()
        );
    }
    if signature_bytes.len() != 64 {
        bail!(
            "invalid signature: expected 64 bytes, got {}",
            signature_bytes.len()
        );
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(public_key_bytes);
    let public_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_bytes);

    match public_key.verify(data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify manifest signature using the bundled public key.
/// This is the primary verification method for v0.1.1+.
pub fn verify_manifest_with_bundled_pubkey(
    manifest: &crate::domain::manifest::Manifest,
    sig_path: &Path,
    pubkey_path: &Path,
) -> Result<bool> {
    let canonical_bytes = manifest.canonical_json()?;
    let sig_bytes = fs::read(sig_path)
        .with_context(|| format!("failed to read signature: {}", sig_path.display()))?;
    let pubkey_bytes = fs::read(pubkey_path)
        .with_context(|| format!("failed to read public key: {}", pubkey_path.display()))?;

    verify(&canonical_bytes, &sig_bytes, &pubkey_bytes)
}

/// Save a signature to a file in the bundle.
pub fn save_signature(path: &Path, sig: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, sig)
        .with_context(|| format!("failed to write signature: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }

    Ok(())
}

/// Load a signature from a file.
pub fn load_signature(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read signature: {}", path.display()))
}

/// Save the public key to the bundle's signing/ directory.
pub fn save_public_key(bundle_dir: &Path) -> Result<()> {
    let pubkey = get_public_key_bytes()?;
    let pubkey_path = bundle_dir.join("signing/public.key");

    if let Some(parent) = pubkey_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let display_path = pubkey_path.display().to_string();
    fs::write(&pubkey_path, pubkey)
        .with_context(|| format!("failed to write public key: {}", display_path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pubkey_path, fs::Permissions::from_mode(0o644))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Ensure a keypair exists for tests. If one already exists, this is a no-op.
    fn ensure_keypair() {
        let path = keypair_path().unwrap();
        if !path.is_file() {
            generate_keypair().expect("failed to generate test keypair");
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        ensure_keypair();
        let data = b"hello, world";

        let sig = sign(data).unwrap();
        let vk = load_verifying_key().unwrap();

        assert!(verify(data, &sig, &vk.to_bytes()).unwrap());
    }

    #[test]
    fn wrong_data_fails_verification() {
        ensure_keypair();
        let data = b"hello, world";
        let wrong = b"wrong data";

        let sig = sign(data).unwrap();
        let vk = load_verifying_key().unwrap();

        assert!(!verify(wrong, &sig, &vk.to_bytes()).unwrap());
    }

    #[test]
    fn save_and_load_signature() {
        ensure_keypair();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sig.bin");

        let sig = sign(b"test").unwrap();
        save_signature(&path, &sig).unwrap();

        let loaded = load_signature(&path).unwrap();
        assert_eq!(sig, loaded);
    }

    #[test]
    fn keypair_persistence() {
        ensure_keypair();
        let vk = load_verifying_key().unwrap();
        assert_eq!(vk.to_bytes().len(), 32);
    }

    #[test]
    fn save_public_key_works() {
        ensure_keypair();
        let dir = TempDir::new().unwrap();
        save_public_key(dir.path()).unwrap();

        let pubkey_path = dir.path().join("signing/public.key");
        assert!(pubkey_path.is_file());

        let pubkey = fs::read(&pubkey_path).unwrap();
        assert_eq!(pubkey.len(), 32);

        // Verify it matches the loaded verifying key
        let vk = load_verifying_key().unwrap();
        assert_eq!(pubkey, vk.to_bytes());
    }

    /// Build a signed bundle context: sign `manifest` with the real keypair
    /// and lay out manifest.sig + signing/public.key under `dir`.
    fn sign_into_bundle(dir: &Path, manifest: &crate::domain::manifest::Manifest) {
        let sig = sign_canonical_manifest(manifest).unwrap();
        let sig_path = dir.join("manifest.sig");
        let pubkey_path = dir.join("signing/public.key");
        fs::create_dir_all(pubkey_path.parent().unwrap()).unwrap();
        save_signature(&sig_path, &sig).unwrap();
        save_public_key(dir).unwrap();
    }

    #[test]
    fn canonical_json_signing_roundtrip() {
        ensure_keypair();

        // Create a minimal manifest
        let manifest = crate::domain::manifest::default_pi("test-agent", "0.1.0");

        // Sign using canonical JSON
        let sig = sign_canonical_manifest(&manifest).unwrap();

        // Save signature and public key to temp dir
        let dir = TempDir::new().unwrap();
        let sig_path = dir.path().join("manifest.sig");
        let pubkey_path = dir.path().join("signing/public.key");
        fs::create_dir_all(pubkey_path.parent().unwrap()).unwrap();

        save_signature(&sig_path, &sig).unwrap();
        save_public_key(dir.path()).unwrap();

        // Verify using bundled public key
        let verified =
            verify_manifest_with_bundled_pubkey(&manifest, &sig_path, &pubkey_path).unwrap();
        assert!(verified);
    }

    // ── Portable verification (Milestone 4) ───────────────────────────
    //
    // Signing context A produces a bundle; a fresh verification context B
    // verifies it using ONLY the public key that traveled with the bundle.
    // B never needs Machine A's private key.

    #[test]
    fn portable_verification_uses_only_bundled_pubkey() {
        ensure_keypair();

        // Context A: sign a manifest and write bundle artifacts.
        let mut manifest = crate::domain::manifest::default_pi("portable-agent", "0.1.0");
        manifest.bundle.id = "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string();
        manifest.bundle.created_at = "2025-01-15T12:00:00Z".to_string();

        let dir_a = TempDir::new().unwrap();
        sign_into_bundle(dir_a.path(), &manifest);

        // Context B: a fresh machine with no access to the private key.
        // Verification must succeed using the bundled artifacts alone.
        let sig_path = dir_a.path().join("manifest.sig");
        let pubkey_path = dir_a.path().join("signing/public.key");
        let verified = verify_manifest_with_bundled_pubkey(&manifest, &sig_path, &pubkey_path);
        assert!(verified.unwrap());
    }

    // ── Signature attack matrix (Milestone 6) ─────────────────────────

    fn attack_bundle() -> (TempDir, crate::domain::manifest::Manifest) {
        ensure_keypair();
        let mut manifest = crate::domain::manifest::default_pi("attack-agent", "0.1.0");
        manifest.bundle.id = "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string();
        manifest.bundle.created_at = "2025-01-15T12:00:00Z".to_string();
        let dir = TempDir::new().unwrap();
        sign_into_bundle(dir.path(), &manifest);
        (dir, manifest)
    }

    #[test]
    fn attack_valid_manifest_and_signature_succeeds() {
        let (dir, manifest) = attack_bundle();
        let verified = verify_manifest_with_bundled_pubkey(
            &manifest,
            &dir.path().join("manifest.sig"),
            &dir.path().join("signing/public.key"),
        )
        .unwrap();
        assert!(verified);
    }

    #[test]
    fn attack_modified_manifest_fails() {
        let (dir, manifest) = attack_bundle();
        let mut tampered = manifest.clone();
        tampered.bundle.name = "evil-agent".to_string();

        let verified = verify_manifest_with_bundled_pubkey(
            &tampered,
            &dir.path().join("manifest.sig"),
            &dir.path().join("signing/public.key"),
        )
        .unwrap();
        assert!(!verified, "modified manifest must fail verification");
    }

    #[test]
    fn attack_modified_signature_fails() {
        let (dir, manifest) = attack_bundle();
        let sig_path = dir.path().join("manifest.sig");
        let mut sig = fs::read(&sig_path).unwrap();
        sig[0] ^= 0xff; // flip a byte in the signature
        fs::write(&sig_path, &sig).unwrap();

        let verified = verify_manifest_with_bundled_pubkey(
            &manifest,
            &sig_path,
            &dir.path().join("signing/public.key"),
        )
        .unwrap();
        assert!(!verified, "corrupted signature must fail verification");
    }

    #[test]
    fn attack_missing_signature_errors() {
        let (dir, manifest) = attack_bundle();
        fs::remove_file(dir.path().join("manifest.sig")).unwrap();

        let result = verify_manifest_with_bundled_pubkey(
            &manifest,
            &dir.path().join("manifest.sig"),
            &dir.path().join("signing/public.key"),
        );
        assert!(result.is_err(), "missing signature file must error cleanly");
    }

    #[test]
    fn attack_malformed_signature_errors() {
        let (dir, manifest) = attack_bundle();
        let sig_path = dir.path().join("manifest.sig");
        fs::write(&sig_path, b"too-short").unwrap();

        let result = verify_manifest_with_bundled_pubkey(
            &manifest,
            &sig_path,
            &dir.path().join("signing/public.key"),
        );
        let err = result.expect_err("wrong-length signature must error, not verify");
        assert!(err.to_string().contains("invalid signature"));
    }

    #[test]
    fn attack_missing_public_key_errors() {
        let (dir, manifest) = attack_bundle();
        fs::remove_file(dir.path().join("signing/public.key")).unwrap();

        let result = verify_manifest_with_bundled_pubkey(
            &manifest,
            &dir.path().join("manifest.sig"),
            &dir.path().join("signing/public.key"),
        );
        assert!(result.is_err(), "missing public key must error cleanly");
    }

    #[test]
    fn attack_malformed_public_key_errors() {
        let (dir, manifest) = attack_bundle();
        let pubkey_path = dir.path().join("signing/public.key");
        fs::write(&pubkey_path, b"not-a-key").unwrap();

        let result = verify_manifest_with_bundled_pubkey(
            &manifest,
            &dir.path().join("manifest.sig"),
            &pubkey_path,
        );
        let err = result.expect_err("wrong-length public key must error, not verify");
        assert!(err.to_string().contains("invalid public key"));
    }

    #[test]
    fn attack_replaced_public_key_fails() {
        let (dir, manifest) = attack_bundle();

        // Replace the bundled public key with a DIFFERENT valid key
        // (as if an attacker swapped keys), keeping the original signature.
        let mut rng = rand::thread_rng();
        let attacker = SigningKey::generate(&mut rng);
        let pubkey_path = dir.path().join("signing/public.key");
        fs::write(&pubkey_path, attacker.verifying_key().to_bytes()).unwrap();

        let verified = verify_manifest_with_bundled_pubkey(
            &manifest,
            &dir.path().join("manifest.sig"),
            &pubkey_path,
        )
        .unwrap();
        assert!(
            !verified,
            "signature signed by the original key must not verify under a replaced key"
        );
    }
}

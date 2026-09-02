use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{bail, Result};
use argon2::Argon2;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

// ── Constants ────────────────────────────────────────────────────────────────

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

// ── Public API ───────────────────────────────────────────────────────────────

/// Encrypt arbitrary bytes with a passphrase.
///
/// Output format: `[16B salt][12B nonce][ciphertext + 16B GCM tag]`
/// The caller should write the result to disk; no plaintext is ever persisted.
pub fn encrypt_secrets(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        bail!("passphrase cannot be empty");
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("cipher init failed: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("aes-gcm encryption failed: {}", e))?;

    // Zeroize the derived key before returning
    key.zeroize();

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt bytes that were produced by [`encrypt_secrets`].
///
/// Returns the original plaintext or an error if the passphrase is wrong
/// or the data is corrupted.
pub fn decrypt_secrets(passphrase: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
    let min_len = SALT_LEN + NONCE_LEN + 1;
    if encrypted.len() < min_len {
        bail!(
            "encrypted data too short: {} bytes (minimum {})",
            encrypted.len(),
            min_len
        );
    }

    let salt = &encrypted[..SALT_LEN];
    let nonce_bytes = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];

    let mut key = derive_key(passphrase.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("cipher init failed: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let result = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong passphrase or corrupted data"));

    // Zeroize the derived key before returning
    key.zeroize();

    result
}

/// Prompt the user for a passphrase (masked terminal input, no echo).
pub fn prompt_passphrase(label: &str) -> Result<String> {
    let pass = rpassword::prompt_password(format!("{}: ", label))
        .map_err(|e| anyhow::anyhow!("failed to read passphrase: {}", e))?;
    if pass.is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(pass)
}

/// Prompt twice and confirm the two inputs match.
pub fn prompt_passphrase_confirm() -> Result<String> {
    let a = prompt_passphrase("Enter passphrase")?;
    let b = prompt_passphrase("Confirm passphrase")?;
    if a != b {
        bail!("passphrases do not match");
    }
    Ok(a)
}

// ── Internals ────────────────────────────────────────────────────────────────

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {}", e))?;
    // Note: key is zeroized by the caller after use
    Ok(key)
}

// ── KEK/DEK Envelope ────────────────────────────────────────────────────────
//
// For passphrase rotation (pn rekey), we use a two-layer scheme:
//   KEK (key encryption key) = derived from passphrase
//   DEK (data encryption key) = random 32 bytes
//
// File format: [16B salt][12B nonce_kek][encrypted_dek + 16B tag][12B nonce_dek][encrypted_data + 16B tag]
// The DEK is encrypted by the KEK; the data is encrypted by the DEK.
// Changing passphrase = re-encrypt DEK with new KEK, data untouched.

/// Generate a random DEK (data encryption key).
#[allow(dead_code)]
pub fn generate_dek() -> Result<[u8; KEY_LEN]> {
    let mut dek = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut dek);
    Ok(dek)
}

/// Encrypt data using a DEK directly (no passphrase involved).
#[allow(dead_code)]
pub fn encrypt_with_dek(dek: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| anyhow::anyhow!("cipher init failed: {}", e))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("aes-gcm encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data using a DEK directly.
#[allow(dead_code)]
pub fn decrypt_with_dek(dek: &[u8; KEY_LEN], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_LEN + 1 {
        bail!("encrypted data too short");
    }
    let nonce_bytes = &encrypted[..NONCE_LEN];
    let ciphertext = &encrypted[NONCE_LEN..];

    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| anyhow::anyhow!("cipher init failed: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong key or corrupted data"))
}

/// Encrypt a DEK with a passphrase (wraps the DEK in a KEK envelope).
#[allow(dead_code)]
pub fn wrap_dek(passphrase: &str, dek: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_key(passphrase.as_bytes(), &salt)?;
    let encrypted_dek = encrypt_with_dek(&kek, dek)?;
    let mut kek_ref = kek;
    kek_ref.zeroize();

    let mut out = Vec::with_capacity(SALT_LEN + encrypted_dek.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&encrypted_dek);
    Ok(out)
}

/// Unwrap a DEK from a KEK envelope using a passphrase.
#[allow(dead_code)]
pub fn unwrap_dek(passphrase: &str, wrapped: &[u8]) -> Result<[u8; KEY_LEN]> {
    if wrapped.len() < SALT_LEN + NONCE_LEN + 1 {
        bail!("wrapped DEK too short");
    }
    let salt = &wrapped[..SALT_LEN];
    let encrypted_dek = &wrapped[SALT_LEN..];
    let kek = derive_key(passphrase.as_bytes(), salt)?;
    let dek_bytes = decrypt_with_dek(&kek, encrypted_dek)?;
    let mut kek_ref = kek;
    kek_ref.zeroize();

    if dek_bytes.len() != KEY_LEN {
        bail!("invalid DEK length after decryption: {}", dek_bytes.len());
    }
    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&dek_bytes);
    Ok(dek)
}

/// Create a full KEK/DEK envelope: encrypt data with a random DEK, then wrap the DEK.
/// Returns: [wrapped_dek][encrypted_data]
#[allow(dead_code)]
pub fn encrypt_envelope(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let dek = generate_dek()?;
    let encrypted_data = encrypt_with_dek(&dek, plaintext)?;
    let wrapped_dek = wrap_dek(passphrase, &dek)?;
    let mut dek_ref = dek;
    dek_ref.zeroize();

    let mut out = Vec::with_capacity(wrapped_dek.len() + encrypted_data.len());
    out.extend_from_slice(&wrapped_dek);
    out.extend_from_slice(&encrypted_data);
    Ok(out)
}

/// Decrypt a full KEK/DEK envelope.
#[allow(dead_code)]
pub fn decrypt_envelope(passphrase: &str, envelope: &[u8]) -> Result<Vec<u8>> {
    // The wrapped DEK is: 16B salt + 12B nonce + 32B plaintext + 16B tag = 76 bytes
    let wrapped_len = SALT_LEN + NONCE_LEN + KEY_LEN + 16;
    if envelope.len() < wrapped_len + 1 {
        bail!("envelope too short");
    }
    let wrapped_dek = &envelope[..wrapped_len];
    let encrypted_data = &envelope[wrapped_len..];

    let dek = unwrap_dek(passphrase, wrapped_dek)?;
    let plaintext = decrypt_with_dek(&dek, encrypted_data)?;
    Ok(plaintext)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello, secret world!";
        let pass = "my-strong-passphrase";

        let enc = encrypt_secrets(pass, data).unwrap();
        assert_ne!(&enc[..], data);

        let dec = decrypt_secrets(pass, &enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let enc = encrypt_secrets("correct", b"secret").unwrap();
        assert!(decrypt_secrets("wrong", &enc).is_err());
    }

    #[test]
    fn truncated_data_rejected() {
        assert!(decrypt_secrets("pass", &[0u8; 5]).is_err());
    }

    #[test]
    fn empty_passphrase_rejected() {
        assert!(encrypt_secrets("", b"data").is_err());
    }

    #[test]
    fn nondeterministic() {
        let data = b"same data";
        let pass = "same-pass";

        let enc1 = encrypt_secrets(pass, data).unwrap();
        let enc2 = encrypt_secrets(pass, data).unwrap();
        // Random salt + nonce -> different ciphertext
        assert_ne!(enc1, enc2);
        // But both decrypt correctly
        assert_eq!(decrypt_secrets(pass, &enc1).unwrap(), data);
        assert_eq!(decrypt_secrets(pass, &enc2).unwrap(), data);
    }

    #[test]
    fn large_payload() {
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let enc = encrypt_secrets("big-data-pass", &data).unwrap();
        let dec = decrypt_secrets("big-data-pass", &enc).unwrap();
        assert_eq!(dec, data);
    }

    // ── KEK/DEK envelope tests ────────────────────────────────────

    #[test]
    fn envelope_roundtrip() {
        let data = b"hello, envelope world!";
        let pass = "strong-passphrase";
        let envelope = encrypt_envelope(pass, data).unwrap();
        let decrypted = decrypt_envelope(pass, &envelope).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn envelope_wrong_passphrase() {
        let envelope = encrypt_envelope("correct", b"secret").unwrap();
        assert!(decrypt_envelope("wrong", &envelope).is_err());
    }

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek("passphrase", &dek).unwrap();
        let unwrapped = unwrap_dek("passphrase", &wrapped).unwrap();
        assert_eq!(dek, unwrapped);
    }

    #[test]
    fn wrap_unwrap_wrong_passphrase() {
        let dek = generate_dek().unwrap();
        let wrapped = wrap_dek("correct", &dek).unwrap();
        assert!(unwrap_dek("wrong", &wrapped).is_err());
    }

    #[test]
    fn envelope_nondeterministic() {
        let data = b"same data";
        let pass = "same-pass";
        let env1 = encrypt_envelope(pass, data).unwrap();
        let env2 = encrypt_envelope(pass, data).unwrap();
        assert_ne!(env1, env2);
        assert_eq!(decrypt_envelope(pass, &env1).unwrap(), data);
        assert_eq!(decrypt_envelope(pass, &env2).unwrap(), data);
    }
}

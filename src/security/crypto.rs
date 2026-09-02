use anyhow::{bail, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
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
        .map_err(|_| anyhow::anyhow!(
            "decryption failed — wrong passphrase or corrupted data"
        ));

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
        // Random salt + nonce → different ciphertext
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
}

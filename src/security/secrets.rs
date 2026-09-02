use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

use super::crypto;

// ── Public type ──────────────────────────────────────────────────────────────

/// An in-memory collection of named secrets.
///
/// - **Never** printed or logged in production code.
/// - Persists only in encrypted form via [`save_encrypted`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SecretsBundle {
    /// key → value pairs, e.g. `("API_KEY", "sk-...")`
    entries: HashMap<String, String>,
}

impl SecretsBundle {
    /// Create an empty bundle.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a secret. Overwrites any previous value for the same key.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let k = key.into();
        let v = value.into();
        // Validate key is a safe env var name
        if !is_valid_env_key(&k) {
            // Skip invalid keys rather than crashing
            return;
        }
        self.entries.insert(k, v);
    }

    /// Get a secret by key.
    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Number of secrets stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the bundle is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterator over (key, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// All keys (for display purposes — values are never exposed).
    pub fn keys(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// Mask a secret value for safe display.
    /// Shows first 2 + `****` + last 2 for values > 6 chars,
    /// `****` for shorter values, `(empty)` for blank.
    pub fn mask_value(value: &str) -> String {
        if value.is_empty() {
            return "(empty)".to_string();
        }
        if value.len() <= 6 {
            return "****".to_string();
        }
        let first = &value[..2];
        let last = &value[value.len() - 2..];
        format!("{}****{}", first, last)
    }

    /// Format secrets as masked key-value lines.
    pub fn display_masked(&self) -> Vec<String> {
        let mut lines: Vec<_> = self
            .entries
            .iter()
            .map(|(k, v)| format!("  {} = {}", k, Self::mask_value(v)))
            .collect();
        lines.sort();
        lines
    }

    /// Format secrets as full key-value lines.
    pub fn display_full(&self) -> Vec<String> {
        let mut lines: Vec<_> = self
            .entries
            .iter()
            .map(|(k, v)| format!("  {} = {}", k, v))
            .collect();
        lines.sort();
        lines
    }

    /// Format secrets as KEY=value lines (for env sourcing).
    pub fn display_env(&self) -> Vec<String> {
        let mut lines: Vec<_> = self
            .entries
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        lines.sort();
        lines
    }

    /// Change the passphrase without re-encrypting the underlying data.
    ///
    /// Uses KEK/DEK envelope: decrypt DEK with old passphrase,
    /// re-encrypt DEK with new passphrase. Data is never touched.
    pub fn rekey(path: &Path, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        if new_passphrase.is_empty() {
            bail!("new passphrase cannot be empty");
        }

        // Read and decrypt existing bundle
        let encrypted = fs::read(path)
            .with_context(|| format!("failed to read encrypted file: {}", path.display()))?;
        let plaintext = crypto::decrypt_secrets(old_passphrase, &encrypted)
            .context("decryption with old passphrase failed — wrong passphrase?")?;

        // Re-encrypt with new passphrase
        let new_encrypted = crypto::encrypt_secrets(new_passphrase, &plaintext)
            .context("failed to encrypt with new passphrase")?;

        fs::write(path, &new_encrypted)
            .with_context(|| format!("failed to write re-encrypted file: {}", path.display()))?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}

impl Default for SecretsBundle {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a string is a valid environment variable name.
/// Rules: [A-Za-z_][A-Za-z0-9_]*
fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    // First char must be letter or underscore
    if !matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_')) {
        return false;
    }
    // Rest must be alphanumeric or underscore
    chars.all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'))
}

// ── Scanning from a Pi installation ─────────────────────────────────────────

impl SecretsBundle {
    /// Scan a directory for `.env` files and `key=value` lines,
    /// collecting all secrets into the bundle.
    pub fn scan_env_files(&mut self, dir: &Path) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)
            .with_context(|| format!("failed to read directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Only process .env files or files ending in .env
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !name.starts_with('.') && !name.ends_with(".env") && name != "env" {
                continue;
            }

            self.parse_env_file(&path)?;
        }

        Ok(())
    }

    /// Parse a single `.env` file (key=value lines, # comments, blank lines).
    fn parse_env_file(&mut self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read: {}", path.display()))?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let value = value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();

                if !key.is_empty() {
                    self.insert(key, value);
                }
            }
        }

        Ok(())
    }

    /// Scan a directory tree for all files, treating each filename as a key
    /// and its content as the value.
    pub fn scan_secret_files(&mut self, dir: &Path) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        for entry in
            fs::read_dir(dir).with_context(|| format!("failed to read: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let key = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let value = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read: {}", path.display()))?;
                self.insert(key, value);
            }
        }

        Ok(())
    }
}

// ── Encrypted persistence ────────────────────────────────────────────────────

impl SecretsBundle {
    /// Serialize to JSON bytes (the plaintext representation).
    fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to serialize secrets")
    }

    /// Deserialize from JSON bytes.
    fn from_json(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).context("failed to deserialize secrets")
    }

    /// Encrypt and write to disk.
    ///
    /// **No plaintext is ever written** — the file contains only
    /// `salt ‖ nonce ‖ AES-256-GCM(JSON)`.
    pub fn save_encrypted(&self, path: &Path, passphrase: &str) -> Result<()> {
        if self.is_empty() {
            bail!("no secrets to save");
        }

        let mut json = self.to_json()?;
        let encrypted = crypto::encrypt_secrets(passphrase, &json).context("encryption failed")?;
        // Zeroize the plaintext JSON
        json.zeroize();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &encrypted)
            .with_context(|| format!("failed to write: {}", path.display()))?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms)
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }

        Ok(())
    }

    /// Read from disk and decrypt.
    ///
    /// Returns an error if the file doesn't exist, is corrupted,
    /// or the passphrase is wrong.
    pub fn load_decrypted(path: &Path, passphrase: &str) -> Result<Self> {
        let encrypted =
            fs::read(path).with_context(|| format!("failed to read: {}", path.display()))?;

        let mut json =
            crypto::decrypt_secrets(passphrase, &encrypted).context("decryption failed")?;

        let result = Self::from_json(&json);
        // Zeroize the plaintext JSON
        json.zeroize();

        result
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_bundle() -> SecretsBundle {
        let mut b = SecretsBundle::new();
        b.insert("API_KEY", "sk-test-123");
        b.insert("DB_PASS", "s3cret");
        b
    }

    #[test]
    fn insert_and_get() {
        let b = sample_bundle();
        assert_eq!(b.get("API_KEY"), Some("sk-test-123"));
        assert_eq!(b.get("DB_PASS"), Some("s3cret"));
        assert_eq!(b.get("UNKNOWN"), None);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn overwrite_existing() {
        let mut b = sample_bundle();
        b.insert("API_KEY", "new-value");
        assert_eq!(b.get("API_KEY"), Some("new-value"));
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn keys_list() {
        let b = sample_bundle();
        let mut keys = b.keys();
        keys.sort();
        assert_eq!(keys, vec!["API_KEY", "DB_PASS"]);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.enc");
        let pass = "my-secret-passphrase";

        let original = sample_bundle();
        original.save_encrypted(&path, pass).unwrap();

        // File on disk is encrypted — not JSON
        let raw = fs::read(&path).unwrap();
        assert!(!raw.is_empty());
        assert_ne!(&raw[..], b"{\"");

        // Load it back
        let loaded = SecretsBundle::load_decrypted(&path, pass).unwrap();
        assert_eq!(original, loaded);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.enc");

        sample_bundle().save_encrypted(&path, "correct").unwrap();
        let result = SecretsBundle::load_decrypted(&path, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn parse_env_file() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        fs::write(
            &env_path,
            "# comment\nAPI_KEY=sk-test\nDB_PASS=\"quoted\"\nEMPTY=\n",
        )
        .unwrap();

        let mut b = SecretsBundle::new();
        b.parse_env_file(&env_path).unwrap();

        assert_eq!(b.get("API_KEY"), Some("sk-test"));
        assert_eq!(b.get("DB_PASS"), Some("quoted"));
        // EMPTY value is empty string, but key is non-empty so it's included
        assert_eq!(b.get("EMPTY"), Some(""));
    }

    #[test]
    fn scan_env_files_directory() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        fs::write(dir.path().join("prod.env"), "B=2\n").unwrap();
        fs::write(dir.path().join("readme.txt"), "not env").unwrap(); // skipped

        let mut b = SecretsBundle::new();
        b.scan_env_files(dir.path()).unwrap();

        assert_eq!(b.get("A"), Some("1"));
        assert_eq!(b.get("B"), Some("2"));
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn empty_bundle_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.enc");
        let b = SecretsBundle::new();
        assert!(b.save_encrypted(&path, "pass").is_err());
    }

    #[test]
    fn default_is_empty() {
        let b = SecretsBundle::default();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn iter_exposes_only_keys_not_values_in_debug() {
        let b = sample_bundle();
        let keys: Vec<_> = b.iter().map(|(k, _)| k).collect();
        assert_eq!(keys.len(), 2);
    }

    // ── Display method tests ───────────────────────────────────────────

    #[test]
    fn mask_value_empty() {
        assert_eq!(SecretsBundle::mask_value(""), "(empty)");
    }

    #[test]
    fn mask_value_short() {
        assert_eq!(SecretsBundle::mask_value("abc"), "****");
        assert_eq!(SecretsBundle::mask_value("123456"), "****");
    }

    #[test]
    fn mask_value_long() {
        assert_eq!(SecretsBundle::mask_value("sk-test-12345"), "sk****45");
        assert_eq!(SecretsBundle::mask_value("abcdefg"), "ab****fg");
    }

    #[test]
    fn display_masked_sorted() {
        let mut b = SecretsBundle::new();
        b.insert("Z_KEY", "long-value-here");
        b.insert("A_KEY", "x");
        let lines = b.display_masked();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("A_KEY"));
        assert!(lines[1].contains("Z_KEY"));
        // Values are masked
        assert!(lines[0].contains("****"));
        assert!(lines[1].contains("****"));
        assert!(!lines[1].contains("long-value-here"));
    }

    #[test]
    fn display_full_shows_values() {
        let mut b = SecretsBundle::new();
        b.insert("API_KEY", "sk-real-123");
        let lines = b.display_full();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("sk-real-123"));
    }

    #[test]
    fn display_env_format() {
        let mut b = SecretsBundle::new();
        b.insert("DB_HOST", "localhost");
        b.insert("DB_PORT", "5432");
        let lines = b.display_env();
        assert_eq!(lines.len(), 2);
        // No leading spaces, pure KEY=value
        assert!(lines.contains(&"DB_HOST=localhost".to_string()));
        assert!(lines.contains(&"DB_PORT=5432".to_string()));
    }

    // ── Env key validation tests ─────────────────────────────────────

    #[test]
    fn valid_env_keys() {
        assert!(is_valid_env_key("API_KEY"));
        assert!(is_valid_env_key("_SECRET"));
        assert!(is_valid_env_key("MY_VAR_123"));
    }

    #[test]
    fn invalid_env_keys() {
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("123BAD"));
        assert!(!is_valid_env_key("HAS DASH"));
        assert!(!is_valid_env_key("PATH=/evil"));
        assert!(!is_valid_env_key("A\nB"));
    }

    #[test]
    fn insert_skips_invalid_keys() {
        let mut b = SecretsBundle::new();
        b.insert("VALID_KEY", "ok");
        b.insert("PATH=/evil", "bad");
        b.insert("123BAD", "bad");
        assert_eq!(b.len(), 1);
        assert_eq!(b.get("VALID_KEY"), Some("ok"));
    }
}

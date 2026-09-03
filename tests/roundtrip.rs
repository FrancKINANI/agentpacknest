//! Integration tests for the full agentpacknest round-trip.
//!
//! These tests exercise the full lifecycle: init → pack → info → diff.
//! They use a fake Pi installation fixture to avoid requiring a real Pi install.

use std::path::PathBuf;

/// Get the path to the fake Pi fixture.
fn fixture_pi() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-pi/agent")
}

/// Create a temporary directory for test output.
fn temp_bundle() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("failed to create temp dir")
}

// ---------------------------------------------------------------------------
// Test: manifest round-trip (create → save → load → validate)
// ---------------------------------------------------------------------------

#[test]
fn manifest_roundtrip() {
    let manifest = agentpacknest::domain::manifest::default_pi("test-agent", "0.84.4");

    // Validate
    manifest.validate().expect("manifest should be valid");

    // Serialize to YAML
    let yaml = serde_yaml::to_string(&manifest).expect("should serialize");
    assert!(yaml.contains("schema_version:"));
    assert!(yaml.contains("agentpacknest_version:"));
    assert!(yaml.contains("bundle_version: 1"));
    assert!(yaml.contains("platform:"));
    assert!(yaml.contains("os:"));
    assert!(yaml.contains("arch:"));

    // Deserialize back
    let loaded: agentpacknest::domain::manifest::Manifest =
        serde_yaml::from_str(&yaml).expect("should deserialize");
    loaded.validate().expect("loaded manifest should be valid");

    // Key fields preserved
    assert_eq!(loaded.bundle.name, "test-agent");
    assert_eq!(loaded.harness.name, "pi");
    assert_eq!(loaded.harness.version, "0.84.4");
    assert_eq!(loaded.bundle_version, 1);
    assert!(loaded.platform.is_some());
    assert!(loaded.agentpacknest_version.is_some());
}

// ---------------------------------------------------------------------------
// Test: default manifest creation
// ---------------------------------------------------------------------------

#[test]
fn default_pi_manifest_is_valid() {
    let m = agentpacknest::domain::manifest::default_pi("my-agent", "0.84.4");
    assert!(m.validate().is_ok());
    assert_eq!(m.schema_version, "0.2");
    assert!(!m.bundle.id.is_empty());
    assert!(m.platform.is_some());
    assert!(!m.contents.config); // defaults to false
    assert!(!m.contents.secrets);
}

// ---------------------------------------------------------------------------
// Test: schema version backward compatibility
// ---------------------------------------------------------------------------

#[test]
fn schema_v01_is_accepted() {
    let mut m = agentpacknest::domain::manifest::default_pi("test", "0.1.0");
    m.schema_version = "0.1".to_string();
    assert!(m.validate().is_ok(), "schema 0.1 should be accepted");
}

#[test]
fn schema_v99_is_rejected() {
    let mut m = agentpacknest::domain::manifest::default_pi("test", "0.1.0");
    m.schema_version = "9.9".to_string();
    assert!(m.validate().is_err(), "schema 9.9 should be rejected");
}

// ---------------------------------------------------------------------------
// Test: crypto round-trip
// ---------------------------------------------------------------------------

#[test]
fn crypto_roundtrip() {
    use agentpacknest::security::crypto;

    let data = b"secret agent data";
    let pass = "test-passphrase-123";

    let encrypted = crypto::encrypt_secrets(pass, data).expect("encrypt should work");
    assert_ne!(&encrypted[..], data);

    let decrypted = crypto::decrypt_secrets(pass, &encrypted).expect("decrypt should work");
    assert_eq!(decrypted, data);

    // Wrong passphrase fails
    assert!(crypto::decrypt_secrets("wrong", &encrypted).is_err());
}

#[test]
fn kek_dek_envelope_roundtrip() {
    use agentpacknest::security::crypto;

    let data = b"envelope test data";
    let pass = "envelope-passphrase";

    let envelope = crypto::encrypt_envelope(pass, data).expect("encrypt_envelope should work");
    let decrypted =
        crypto::decrypt_envelope(pass, &envelope).expect("decrypt_envelope should work");
    assert_eq!(decrypted, data);

    // Wrong passphrase fails
    assert!(crypto::decrypt_envelope("wrong", &envelope).is_err());
}

// ---------------------------------------------------------------------------
// Test: secrets bundle round-trip
// ---------------------------------------------------------------------------

#[test]
fn secrets_bundle_save_load_roundtrip() {
    use agentpacknest::security::secrets::SecretsBundle;

    let dir = temp_bundle();
    let enc_path = dir.path().join("keys.enc");

    let mut bundle = SecretsBundle::new();
    bundle.insert("API_KEY".to_string(), "sk-test-12345".to_string());
    bundle.insert(
        "DB_URL".to_string(),
        "postgres://localhost/mydb".to_string(),
    );

    let pass = "secrets-passphrase";
    bundle
        .save_encrypted(&enc_path, pass)
        .expect("save should work");

    assert!(enc_path.exists(), "encrypted file should exist");

    // Load and verify
    let loaded = SecretsBundle::load_decrypted(&enc_path, pass).expect("load should work");
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.get("API_KEY"), Some("sk-test-12345"));
    assert_eq!(loaded.get("DB_URL"), Some("postgres://localhost/mydb"));
}

// ---------------------------------------------------------------------------
// Test: ignore patterns
// ---------------------------------------------------------------------------

#[test]
fn ignore_patterns_filter_files() {
    use agentpacknest::infrastructure::ignore::IgnorePatterns;

    let patterns = IgnorePatterns::parse("*.log\nsecrets.env\ncache\n");
    assert!(!patterns.is_empty());
    assert_eq!(patterns.len(), 3);

    assert!(patterns.is_ignored("debug.log"));
    assert!(patterns.is_ignored("logs/debug.log"));
    assert!(patterns.is_ignored("secrets.env"));
    assert!(patterns.is_ignored("my/cache/file.txt"));
    assert!(!patterns.is_ignored("config.json"));
    assert!(!patterns.is_ignored("agent/settings.json"));
}

// ---------------------------------------------------------------------------
// Test: platform detection
// ---------------------------------------------------------------------------

#[test]
fn platform_detection() {
    let plat = agentpacknest::domain::manifest::PlatformMeta::detect();
    assert!(!plat.os.is_empty());
    assert!(!plat.arch.is_empty());

    // Should match current OS
    assert_eq!(plat.os, std::env::consts::OS);
    assert_eq!(plat.arch, std::env::consts::ARCH);
}

// ---------------------------------------------------------------------------
// Test: fixture Pi installation is detectable
// ---------------------------------------------------------------------------

#[test]
fn fixture_pi_is_valid() {
    let pi_path = fixture_pi();
    assert!(pi_path.is_dir(), "fixture Pi dir should exist");
    assert!(
        pi_path.join("settings.json").exists(),
        "settings.json should exist"
    );
    assert!(pi_path.join("sessions").is_dir(), "sessions/ should exist");
}

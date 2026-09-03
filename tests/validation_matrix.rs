//! Schema validation failure matrix (Milestone 11).
//!
//! Every negative case here must fail explicitly and cleanly — never panic,
//! never silently reinterpret an unsupported format, never expose secrets.
//!
//! Two groups:
//! - Raw YAML strings: parsing failures, wrong field types, missing fields.
//! - Struct mutation: version failures and semantic validation failures,
//!   exercised through the same load() path a real command uses.

use std::fs;
use std::path::Path;

use agentpacknest::domain::manifest::{self, Manifest};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write YAML to a temp file and load it through the real `manifest::load` path.
fn load_str(yaml: &str) -> anyhow::Result<Manifest> {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("manifest.yaml");
    fs::write(&path, yaml).expect("write manifest");
    manifest::load(&path)
}

/// A known-valid manifest serialized to YAML, used as the base for raw edits.
fn valid_yaml() -> String {
    let m = manifest::default_pi("matrix-agent", "0.1.0");
    serde_yaml::to_string(&m).expect("serialize")
}

/// Replace the value of a top-level YAML key, regardless of quoting style.
/// `key` is given without a colon (e.g. "schema_version").
fn replace_top_level_value(yaml: &str, key: &str, new_value: &str) -> String {
    let mut replaced = false;
    let out: String = yaml
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if !replaced && trimmed.starts_with(key) && trimmed[key.len()..].starts_with(':') {
                replaced = true;
                format!("{}: {}", key, new_value)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(replaced, "key '{}' not found in YAML", key);
    format!("{}\n", out)
}

/// Remove a top-level YAML block whose key line starts with `key_prefix`
/// (the key line plus all indented lines that follow it).
fn remove_top_level(yaml: &str, key_prefix: &str) -> String {
    let lines: Vec<&str> = yaml.lines().collect();
    let mut out: Vec<&str> = Vec::new();
    let mut skipping = false;
    for line in lines {
        let trimmed = line.trim_start();
        if !skipping && trimmed.starts_with(key_prefix) {
            skipping = true;
            continue;
        }
        if skipping {
            // Top-level keys are not indented; nested keys are.
            let indented = line.starts_with(' ') || line.starts_with('\t');
            if !indented && !line.is_empty() {
                skipping = false;
                out.push(line);
                continue;
            }
            continue;
        }
        out.push(line);
    }
    format!("{}\n", out.join("\n"))
}

// ---------------------------------------------------------------------------
// Parsing failures
// ---------------------------------------------------------------------------

#[test]
fn empty_manifest_fails() {
    let err = load_str("").unwrap_err();
    assert!(err.to_string().contains("failed to parse manifest"));
}

#[test]
fn invalid_yaml_fails() {
    let err = load_str("{{{{ not yaml at all").unwrap_err();
    assert!(err.to_string().contains("failed to parse manifest"));
}

#[test]
fn truncated_yaml_fails() {
    let yaml = valid_yaml();
    let truncated = &yaml[..yaml.len() / 2];
    let result = load_str(truncated);
    assert!(
        result.is_err(),
        "truncated manifest must fail to parse, not be silently accepted"
    );
}

#[test]
fn wrong_field_type_fails() {
    let yaml = replace_top_level_value(&valid_yaml(), "schema_version", "[1, 2]");
    let result = load_str(&yaml);
    assert!(
        result.is_err(),
        "wrong-typed schema_version must fail to parse. yaml was:\n{yaml}"
    );
}

#[test]
fn wrong_integrity_field_type_fails() {
    // Insert `checksum: 12345` into the integrity block. The digest is an
    // Option<String> — a numeric value must fail to parse.
    let yaml = valid_yaml().replace("algorithm: sha256", "algorithm: sha256\n  checksum: 12345");
    let result = load_str(&yaml);
    assert!(
        result.is_err(),
        "numeric integrity checksum must fail to parse as a string"
    );
}

// ---------------------------------------------------------------------------
// Required fields
// ---------------------------------------------------------------------------

#[test]
fn missing_schema_version_fails() {
    let yaml = remove_top_level(&valid_yaml(), "schema_version:");
    let result = load_str(&yaml);
    assert!(result.is_err(), "missing schema_version must fail");
}

#[test]
fn missing_harness_fails() {
    let yaml = remove_top_level(&valid_yaml(), "harness:");
    let result = load_str(&yaml);
    assert!(result.is_err(), "missing harness must fail");
}

#[test]
fn missing_integrity_fails() {
    let yaml = remove_top_level(&valid_yaml(), "integrity:");
    let result = load_str(&yaml);
    assert!(result.is_err(), "missing integrity must fail");
}

#[test]
fn missing_runtime_fails() {
    let yaml = remove_top_level(&valid_yaml(), "runtime:");
    let result = load_str(&yaml);
    assert!(result.is_err(), "missing runtime must fail");
}

#[test]
fn missing_launch_command_fails() {
    let yaml = remove_top_level(&valid_yaml(), "launch:");
    let result = load_str(&yaml);
    assert!(result.is_err(), "missing launch must fail");
}

#[test]
fn missing_bundle_version_defaults_to_v1() {
    // bundle_version is optional for backward compatibility with bundles
    // created before the field existed; absence is interpreted as v1.
    let yaml = remove_top_level(&valid_yaml(), "bundle_version: 1");
    let m = load_str(&yaml).expect("bundle_version should default to 1");
    assert_eq!(m.bundle_version, 1);
    m.validate().expect("defaulted manifest must validate");
}

// ---------------------------------------------------------------------------
// Version failures — explicit, never silent
// ---------------------------------------------------------------------------

#[test]
fn unsupported_future_schema_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.schema_version = "9.9".to_string();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("unsupported schema_version"));
}

#[test]
fn unsupported_old_schema_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.schema_version = "0.0".to_string();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("unsupported schema_version"));
}

#[test]
fn legacy_schema_01_is_accepted() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.schema_version = "0.1".to_string();
    save_load(&m).expect("schema 0.1 must remain readable");
}

#[test]
fn unsupported_bundle_format_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.bundle_version = 2;
    let err = save_load(&m).unwrap_err();
    assert!(err
        .to_string()
        .contains("unsupported bundle format version: 2"));
}

#[test]
fn unsupported_integrity_format_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.integrity.format_version = 2;
    let err = save_load(&m).unwrap_err();
    assert!(err
        .to_string()
        .contains("unsupported integrity format version: 2"));
}

#[test]
fn unsupported_crypto_format_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.crypto = Some(manifest::CryptoMeta { format_version: 2 });
    let err = save_load(&m).unwrap_err();
    assert!(err
        .to_string()
        .contains("unsupported crypto format version: 2"));
}

#[test]
fn unsupported_integrity_algorithm_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.integrity.algorithm = "md5".to_string();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("unknown integrity algorithm"));
}

// ---------------------------------------------------------------------------
// Semantic validation
// ---------------------------------------------------------------------------

#[test]
fn empty_harness_name_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.harness.name = String::new();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("harness.name is empty"));
}

#[test]
fn unknown_harness_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.harness.name = "docker".to_string();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("unknown harness"));
}

#[test]
fn invalid_uuid_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.bundle.id = "not-a-uuid".to_string();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("does not look like a valid UUID"));
}

#[test]
fn invalid_timestamp_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.bundle.created_at = "yesterday".to_string();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("not valid ISO 8601"));
}

#[test]
fn empty_created_by_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.bundle.created_by = String::new();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("bundle.created_by is empty"));
}

#[test]
fn invalid_integrity_digest_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.integrity.checksum = Some("zz-not-a-digest".to_string());
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("invalid integrity digest"));
}

#[test]
fn empty_runtime_command_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.launch.command = String::new();
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("launch.command is empty"));
}

#[test]
fn empty_launch_arg_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.launch.args.push(String::new());
    let err = save_load(&m).unwrap_err();
    assert!(err
        .to_string()
        .contains("launch.args contains an empty argument"));
}

#[test]
fn absolute_working_directory_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.launch.working_directory = Some("/tmp/outside".to_string());
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("must be relative"));
}

#[test]
fn escaping_working_directory_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.launch.working_directory = Some("../..".to_string());
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("must stay inside the bundle"));
}

#[test]
fn invalid_compatibility_version_fails() {
    let mut m = manifest::default_pi("matrix-agent", "0.1.0");
    m.compatibility = Some(manifest::Compatibility {
        min_agentpacknest_version: "banana".to_string(),
    });
    let err = save_load(&m).unwrap_err();
    assert!(err.to_string().contains("invalid compatibility"));
}

// ---------------------------------------------------------------------------
// Positive control
// ---------------------------------------------------------------------------

#[test]
fn valid_manifest_passes() {
    let m = manifest::default_pi("matrix-agent", "0.1.0");
    save_load(&m).expect("valid manifest must load");
}

/// Round-trip a struct through YAML on disk and through `manifest::load`,
/// which is the exact path every command uses.
fn save_load(m: &Manifest) -> anyhow::Result<Manifest> {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path: &Path = dir.path();
    let manifest_path = path.join("manifest.yaml");
    fs::write(&manifest_path, serde_yaml::to_string(m).expect("serialize")).expect("write");
    manifest::load(&manifest_path)
}

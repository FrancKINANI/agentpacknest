use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Current schema version supported by this implementation.
const SCHEMA_VERSION: &str = "0.2";

/// The version of agentpacknest that created this manifest.
const AGENTPACKNEST_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Root manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub schema_version: String,
    /// Version of agentpacknest that created this bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agentpacknest_version: Option<String>,
    /// Monotonically increasing bundle format version.
    #[serde(default = "default_bundle_version")]
    pub bundle_version: u32,
    pub bundle: BundleMeta,
    pub harness: HarnessMeta,
    /// Platform where this bundle was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<PlatformMeta>,
    pub contents: Contents,
    pub packages: Packages,
    pub runtime: Runtime,
    pub launch: Launch,
    pub security: Security,
    pub integrity: Integrity,
    /// Snapshot provenance — populated by `pn pack`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginMeta>,
}

fn default_bundle_version() -> u32 {
    1
}

// ---------------------------------------------------------------------------
// Bundle metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleMeta {
    pub name: String,
    pub id: String,
    pub created_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Harness metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HarnessMeta {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

// ---------------------------------------------------------------------------
// Contents
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contents {
    #[serde(default)]
    pub config: bool,
    #[serde(default)]
    pub memory: bool,
    #[serde(default)]
    pub skills: bool,
    #[serde(default)]
    pub secrets: bool,
}

// ---------------------------------------------------------------------------
// Packages (extensions, skills, themes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Packages {
    #[serde(default)]
    pub extensions: Vec<PackageEntry>,
    #[serde(default)]
    pub skills: Vec<PackageEntry>,
    #[serde(default)]
    pub themes: Vec<PackageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

// ---------------------------------------------------------------------------
// Runtime requirements
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Runtime {
    pub required: Vec<RuntimeRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRequirement {
    pub name: String,
    pub min_version: String,
}

// ---------------------------------------------------------------------------
// Launch configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Launch {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Security {
    #[serde(default)]
    pub secrets_encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
}

// ---------------------------------------------------------------------------
// Integrity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Integrity {
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

// ---------------------------------------------------------------------------
// Platform metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlatformMeta {
    pub os: String,
    pub arch: String,
}

impl PlatformMeta {
    pub fn detect() -> Self {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        Self { os, arch }
    }
}

// ---------------------------------------------------------------------------
// Origin / snapshot metadata
// ---------------------------------------------------------------------------

/// Provenance metadata — records where and when a bundle was packed,
/// plus a hash of the source harness state at pack time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OriginMeta {
    /// Hostname of the machine where `pn pack` was run.
    pub origin_machine: String,
    /// ISO 8601 timestamp of when `pn pack` was run.
    pub packed_at: String,
    /// SHA-256 hash of the harness source state at pack time.
    /// Used by `pn diff` to detect drift.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_state_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Validation error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ValidationError {
    #[error("unsupported schema_version: expected {SCHEMA_VERSION}, got {0}")]
    UnsupportedVersion(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Load a manifest from a YAML file on disk.
pub fn load(path: &Path) -> Result<Manifest> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest: {}", path.display()))?;

    let manifest: Manifest = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse manifest: {}", path.display()))?;

    manifest.validate()?;

    Ok(manifest)
}

/// Save a manifest to a YAML file on disk.
pub fn save(path: &Path, manifest: &Manifest) -> Result<()> {
    let yaml = serde_yaml::to_string(manifest).context("failed to serialize manifest")?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }

    fs::write(path, yaml)
        .with_context(|| format!("failed to write manifest: {}", path.display()))?;

    Ok(())
}

/// Create a default manifest pre-configured for the "pi" harness.
pub fn default_pi(name: &str, harness_version: &str) -> Manifest {
    Manifest {
        schema_version: SCHEMA_VERSION.to_string(),
        agentpacknest_version: Some(AGENTPACKNEST_VERSION.to_string()),
        bundle_version: 1,
        bundle: BundleMeta {
            name: name.to_string(),
            id: uuid_v4(),
            created_at: now_iso8601(),
            created_by: whoami(),
            description: Some("Agent bundle for harness pi".to_string()),
        },
        harness: HarnessMeta {
            name: "pi".to_string(),
            version: harness_version.to_string(),
            source: None,
        },
        platform: Some(PlatformMeta::detect()),
        contents: Contents {
            config: false,
            memory: false,
            skills: false,
            secrets: false,
        },
        packages: Packages {
            extensions: vec![],
            skills: vec![],
            themes: vec![],
        },
        runtime: Runtime {
            required: vec![RuntimeRequirement {
                name: "pi-runtime".to_string(),
                min_version: "0.1.0".to_string(),
            }],
        },
        launch: Launch {
            command: "pn run .".to_string(),
            working_directory: Some(".".to_string()),
        },
        security: Security {
            secrets_encrypted: false,
            encryption: None,
        },
        integrity: Integrity {
            algorithm: "sha256".to_string(),
            checksum: None,
        },
        origin: None,
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl Manifest {
    /// Validate the manifest for structural correctness.
    pub fn validate(&self) -> Result<()> {
        // Schema version check — accept 0.1 (legacy) and 0.2 (current)
        if self.schema_version != "0.1" && self.schema_version != SCHEMA_VERSION {
            bail!(
                "unsupported schema_version: expected '0.1' or '{}', got '{}'\n  hint: this bundle was created with a different version of pn",
                SCHEMA_VERSION, self.schema_version
            );
        }

        // Critical fields presence
        if self.bundle.name.is_empty() {
            bail!("bundle.name is empty — give your agent a name");
        }
        if self.bundle.id.is_empty() {
            bail!("bundle.id is empty — this field is required");
        }
        if self.harness.name.is_empty() {
            bail!("harness.name is empty — specify which harness this bundle uses");
        }
        if self.harness.version.is_empty() {
            bail!("harness.version is empty — specify the harness version");
        }
        if self.launch.command.is_empty() {
            bail!("launch.command is empty — specify how to start the agent");
        }
        if self.integrity.algorithm.is_empty() {
            bail!("integrity.algorithm is empty");
        }

        // Harness name validation
        let known_harnesses = ["pi"];
        if !known_harnesses.contains(&self.harness.name.as_str()) {
            bail!(
                "unknown harness '{}'\n  supported harnesses: {}\n  hint: only 'pi' is supported in pn v0.1",
                self.harness.name,
                known_harnesses.join(", ")
            );
        }

        // UUID format check (basic — 36 chars with hyphens)
        if self.bundle.id.len() != 36 || self.bundle.id.chars().filter(|c| *c == '-').count() != 4 {
            bail!(
                "bundle.id '{}' does not look like a valid UUID\n  expected format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx",
                self.bundle.id
            );
        }

        // Created-at format check (must contain T and end with Z)
        if !self.bundle.created_at.contains('T') || !self.bundle.created_at.ends_with('Z') {
            bail!(
                "bundle.created_at '{}' is not valid ISO 8601\n  expected format: 2025-01-15T12:34:56Z",
                self.bundle.created_at
            );
        }

        // Integrity algorithm check
        let known_algos = ["sha256"];
        if !known_algos.contains(&self.integrity.algorithm.as_str()) {
            bail!(
                "unknown integrity algorithm '{}'\n  supported: {}",
                self.integrity.algorithm,
                known_algos.join(", ")
            );
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        // Set version nibble to 4
        (bytes[6] & 0x0f) | 0x40, bytes[7],
        // Set variant bits
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn now_iso8601() -> String {
    // Simple ISO 8601 without pulling in chrono
    // Format: 2025-01-15T12:34:56Z
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert to broken-down time (UTC)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 to Y-M-D (simplified leap year calc)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[allow(dead_code)]
fn hostname() -> String {
    #[cfg(unix)]
    {
        if let Ok(name) = std::process::Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        {
            if !name.is_empty() {
                return name;
            }
        }
    }
    whoami()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_manifest() -> Manifest {
        Manifest {
            schema_version: SCHEMA_VERSION.to_string(),
            agentpacknest_version: Some("0.1.0".to_string()),
            bundle_version: 1,
            bundle: BundleMeta {
                name: "test-agent".to_string(),
                id: "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                created_at: "2025-01-15T12:00:00Z".to_string(),
                created_by: "tester".to_string(),
                description: Some("A test agent".to_string()),
            },
            harness: HarnessMeta {
                name: "pi".to_string(),
                version: "0.1.0".to_string(),
                source: Some("https://example.com".to_string()),
            },
            platform: Some(PlatformMeta {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
            }),
            contents: Contents {
                config: true,
                memory: true,
                skills: true,
                secrets: false,
            },
            packages: Packages {
                extensions: vec![PackageEntry {
                    name: "ext-a".to_string(),
                    version: "1.0.0".to_string(),
                    source: None,
                    path: None,
                }],
                skills: vec![],
                themes: vec![],
            },
            runtime: Runtime {
                required: vec![RuntimeRequirement {
                    name: "pi-runtime".to_string(),
                    min_version: "0.1.0".to_string(),
                }],
            },
            launch: Launch {
                command: "pn run .".to_string(),
                working_directory: Some(".".to_string()),
            },
            security: Security {
                secrets_encrypted: false,
                encryption: None,
            },
            integrity: Integrity {
                algorithm: "sha256".to_string(),
                checksum: None,
            },
            origin: None,
        }
    }

    #[test]
    fn test_roundtrip_yaml() {
        let manifest = sample_manifest();
        let yaml = serde_yaml::to_string(&manifest).unwrap();
        let parsed: Manifest = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn test_save_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.yaml");

        let manifest = sample_manifest();
        save(&path, &manifest).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(manifest, loaded);
    }

    #[test]
    fn test_load_missing_file() {
        let result = load(Path::new("/nonexistent/agent.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_invalid_yaml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.yaml");
        fs::write(&path, "{{{{not yaml").unwrap();

        let result = load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_bad_version() {
        let mut manifest = sample_manifest();
        manifest.schema_version = "9.9".to_string();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported schema_version"));
    }

    #[test]
    fn test_validation_missing_name() {
        let mut manifest = sample_manifest();
        manifest.bundle.name = String::new();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("bundle.name is empty"));
    }

    #[test]
    fn test_validation_missing_launch_command() {
        let mut manifest = sample_manifest();
        manifest.launch.command = String::new();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("launch.command is empty"));
    }

    #[test]
    fn test_validation_unknown_harness() {
        let mut manifest = sample_manifest();
        manifest.harness.name = "docker".to_string();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown harness 'docker'"));
    }

    #[test]
    fn test_validation_bad_uuid() {
        let mut manifest = sample_manifest();
        manifest.bundle.id = "not-a-uuid".to_string();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not look like a valid UUID"));
    }

    #[test]
    fn test_validation_bad_created_at() {
        let mut manifest = sample_manifest();
        manifest.bundle.created_at = "yesterday".to_string();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not valid ISO 8601"));
    }

    #[test]
    fn test_validation_bad_algorithm() {
        let mut manifest = sample_manifest();
        manifest.integrity.algorithm = "md5".to_string();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown integrity algorithm 'md5'"));
    }

    #[test]
    fn test_validation_empty_harness_version() {
        let mut manifest = sample_manifest();
        manifest.harness.version = String::new();

        let result = manifest.validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("harness.version is empty"));
    }

    #[test]
    fn test_default_pi() {
        let manifest = default_pi("my-pi-agent", "0.3.1");

        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.bundle.name, "my-pi-agent");
        assert_eq!(manifest.harness.name, "pi");
        assert_eq!(manifest.harness.version, "0.3.1");
        assert!(!manifest.bundle.id.is_empty());
        assert!(!manifest.bundle.created_at.is_empty());
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_optional_fields_omit_when_none() {
        let manifest = sample_manifest();
        let yaml = serde_yaml::to_string(&manifest).unwrap();

        // source, description, working_directory, encryption, checksum
        // should be present in this sample
        assert!(yaml.contains("source:"));
        assert!(yaml.contains("description:"));
    }

    #[test]
    fn test_optional_fields_absent_when_none() {
        let mut manifest = sample_manifest();
        manifest.bundle.description = None;
        manifest.harness.source = None;
        manifest.launch.working_directory = None;
        manifest.security.encryption = None;
        manifest.integrity.checksum = None;

        let yaml = serde_yaml::to_string(&manifest).unwrap();
        assert!(!yaml.contains("description:"));
        assert!(!yaml.contains("source:"));
        assert!(!yaml.contains("working_directory:"));
        assert!(!yaml.contains("encryption:"));
        assert!(!yaml.contains("checksum:"));
    }

    #[test]
    fn test_empty_packages_serializes_empty_lists() {
        let manifest = sample_manifest();
        let yaml = serde_yaml::to_string(&manifest).unwrap();

        // Empty vecs should still appear as empty lists
        assert!(yaml.contains("skills: []\n") || yaml.contains("skills: []"));
    }
}

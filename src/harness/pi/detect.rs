use anyhow::{bail, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::harness::types::HarnessAdapter;

/// Detected Pi installation on disk.
#[derive(Debug)]
pub struct PiInstallation {
    root: PathBuf,
    version: String,
}

const PI_ENV_VAR: &str = "PI_HOME";

impl HarnessAdapter for PiInstallation {
    fn name(&self) -> &str {
        "pi"
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn detect(path: Option<PathBuf>) -> Result<Self> {
        let root = resolve_root(path)?;
        Self::validate(&root)?;
        let version = Self::read_version(&root);
        Ok(Self { root, version })
    }

    fn is_valid_install(path: &Path) -> bool {
        if !path.is_dir() {
            return false;
        }

        // A valid Pi install must have at least `config/` and `packages/`
        let has_config = path.join("config").is_dir();
        let has_packages = path.join("packages").is_dir();

        has_config && has_packages
    }

    fn read_version(path: &Path) -> String {
        // Try VERSION file first
        let version_file = path.join("VERSION");
        if let Ok(content) = fs::read_to_string(&version_file) {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }

        // Try version.txt
        let version_txt = path.join("version.txt");
        if let Ok(content) = fs::read_to_string(&version_txt) {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }

        // Try reading from a TOML manifest at root
        let manifest_path = path.join("pi.toml");
        if let Ok(content) = fs::read_to_string(&manifest_path) {
            // Simple line scan — avoids pulling in toml dep for this
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("version") {
                    if let Some(val) = trimmed.split_once('=') {
                        let v = val.1.trim().trim_matches('"').trim_matches('\'');
                        if !v.is_empty() {
                            return v.to_string();
                        }
                    }
                }
            }
        }

        "unknown".to_string()
    }
}

impl PiInstallation {
    /// Validate that a path looks like a real Pi installation.
    /// Returns an error with a clear message if not.
    fn validate(path: &Path) -> Result<()> {
        if !path.is_dir() {
            bail!("path does not exist or is not a directory: {}", path.display());
        }

        if !Self::is_valid_install(path) {
            // Give a more specific hint about what's missing
            let mut missing = Vec::new();
            if !path.join("config").is_dir() {
                missing.push("config/");
            }
            if !path.join("packages").is_dir() {
                missing.push("packages/");
            }
            bail!(
                "not a valid Pi installation at {}\n  missing: {}",
                path.display(),
                missing.join(", ")
            );
        }

        Ok(())
    }
}

/// Resolve the Pi root directory from the given inputs.
fn resolve_root(path: Option<PathBuf>) -> Result<PathBuf> {
    // 1. Explicit path
    if let Some(p) = path {
        return Ok(p);
    }

    // 2. Environment variable
    if let Ok(val) = env::var(PI_ENV_VAR) {
        let p = PathBuf::from(&val);
        if p.is_dir() {
            return Ok(p);
        }
    }

    // 3. Default: ~/.pi
    if let Some(home) = dirs::home_dir() {
        let p = home.join(".pi");
        if p.is_dir() {
            return Ok(p);
        }
    }

    bail!(
        "could not find Pi installation\n  tried: PI_HOME env var, ~/.pi\n  hint: pass the path explicitly with `--path`"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_pi_install(dir: &Path) {
        fs::create_dir_all(dir.join("config")).unwrap();
        fs::create_dir_all(dir.join("packages")).unwrap();
        fs::write(dir.join("VERSION"), "0.3.1\n").unwrap();
    }

    #[test]
    fn test_is_valid_install() {
        let dir = TempDir::new().unwrap();
        assert!(!PiInstallation::is_valid_install(dir.path()));

        setup_pi_install(dir.path());
        assert!(PiInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn test_read_version_from_file() {
        let dir = TempDir::new().unwrap();
        setup_pi_install(dir.path());

        assert_eq!(PiInstallation::read_version(dir.path()), "0.3.1");
    }

    #[test]
    fn test_read_version_missing() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("config")).unwrap();
        fs::create_dir_all(dir.path().join("packages")).unwrap();

        assert_eq!(PiInstallation::read_version(dir.path()), "unknown");
    }

    #[test]
    fn test_read_version_from_toml() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("config")).unwrap();
        fs::create_dir_all(dir.path().join("packages")).unwrap();
        fs::write(dir.path().join("pi.toml"), "[meta]\nversion = \"1.2.3\"\n").unwrap();

        assert_eq!(PiInstallation::read_version(dir.path()), "1.2.3");
    }

    #[test]
    fn test_detect_explicit_path() {
        let dir = TempDir::new().unwrap();
        setup_pi_install(dir.path());

        let pi = PiInstallation::detect(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(pi.name(), "pi");
        assert_eq!(pi.version(), "0.3.1");
        assert_eq!(pi.root(), dir.path());
    }

    #[test]
    fn test_detect_invalid_path_errors() {
        // Path exists as a dir but is not a valid Pi install
        let dir = TempDir::new().unwrap();
        let result = PiInstallation::detect(Some(dir.path().to_path_buf()));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not a valid Pi installation"));
    }

    #[test]
    fn test_detect_missing_dirs_errors() {
        let dir = TempDir::new().unwrap();
        // Only config, no packages
        fs::create_dir_all(dir.path().join("config")).unwrap();

        let result = PiInstallation::detect(Some(dir.path().to_path_buf()));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing: packages/"));
    }

    #[test]
    fn test_detect_with_env_var() {
        let dir = TempDir::new().unwrap();
        setup_pi_install(dir.path());

        env::set_var(PI_ENV_VAR, dir.path().to_str().unwrap());
        let pi = PiInstallation::detect(None).unwrap();
        assert_eq!(pi.version(), "0.3.1");
        env::remove_var(PI_ENV_VAR);
    }

    #[test]
    fn test_detect_nothing_found() {
        // An empty dir is not a valid install, and PI_HOME is unset
        // so detect(None) should fail regardless of ~/.pi
        let dir = TempDir::new().unwrap();
        let result = PiInstallation::detect(Some(dir.path().to_path_buf()));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not a valid Pi installation"));
    }

    #[test]
    fn test_paths_are_correct() {
        let dir = TempDir::new().unwrap();
        setup_pi_install(dir.path());

        let pi = PiInstallation::detect(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(pi.config_path(), dir.path().join("config"));
        assert_eq!(pi.packages_path(), dir.path().join("packages"));
        assert_eq!(pi.memory_path(), dir.path().join("memory"));
        assert_eq!(pi.skills_path(), dir.path().join("skills"));
        assert_eq!(pi.themes_path(), dir.path().join("themes"));
    }
}

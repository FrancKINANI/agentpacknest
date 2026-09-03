use anyhow::{bail, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::harness::types::HarnessAdapter;

/// Detected Pi installation on disk.
///
/// Real directory layout (typical):
///
///   ~/.pi/agent/
///     settings.json        # config
///     auth.json            # secrets (API keys, OAuth)
///     models-store.json
///     sessions/            # memory / history (.jsonl)
///     extensions/
///     skills/
///     prompts/
///     themes/
///     npm/
///     git/
///     packages/
#[derive(Debug)]
pub struct PiInstallation {
    /// The resolved agent directory (e.g. `~/.pi/agent`).
    agent_dir: PathBuf,
    /// The resolved version string.
    version: String,
}

// ── Environment variable names ───────────────────────────────────────────────

/// Primary: explicit override for the agent directory.
const PI_CODING_AGENT_DIR: &str = "PI_CODING_AGENT_DIR";
/// Legacy fallback (will be used with a deprecation warning).
const PI_HOME: &str = "PI_HOME";

// ── HarnessAdapter implementation ────────────────────────────────────────────

impl HarnessAdapter for PiInstallation {
    fn name(&self) -> &str {
        "pi"
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn root(&self) -> &Path {
        &self.agent_dir
    }

    /// Override default config path — Pi uses `settings.json` at root.
    fn config_path(&self) -> PathBuf {
        self.agent_dir.clone()
    }

    /// Override: Pi stores sessions in `sessions/`.
    fn memory_path(&self) -> PathBuf {
        self.agent_dir.join("sessions")
    }

    /// Override: Pi has `skills/` at root.
    fn skills_path(&self) -> PathBuf {
        self.agent_dir.join("skills")
    }

    /// Override: Pi has `themes/` at root.
    fn themes_path(&self) -> PathBuf {
        self.agent_dir.join("themes")
    }

    /// Override: Pi has `extensions/` at root.
    fn extensions_path(&self) -> PathBuf {
        self.agent_dir.join("extensions")
    }

    /// Override: Pi has `packages/` at root.
    fn packages_path(&self) -> PathBuf {
        self.agent_dir.join("packages")
    }

    fn detect(path: Option<PathBuf>) -> Result<Self> {
        let (agent_dir, is_legacy) = resolve_agent_dir(path)?;
        Self::validate(&agent_dir)?;
        let version = Self::read_version(&agent_dir);

        if is_legacy {
            eprintln!(
                "⚠ WARNING: using legacy Pi path: {}\n  \
                 recommended: migrate to PI_CODING_AGENT_DIR or ~/.pi/agent",
                agent_dir.display()
            );
        }

        Ok(Self { agent_dir, version })
    }

    fn is_valid_install(path: &Path) -> bool {
        if !path.is_dir() {
            return false;
        }

        // Must have at least one config file
        let has_settings = path.join("settings.json").is_file();
        let has_auth = path.join("auth.json").is_file();

        if !has_settings && !has_auth {
            return false;
        }

        // And at least one of the key directories
        let has_sessions = path.join("sessions").is_dir();
        let has_extensions = path.join("extensions").is_dir();
        let has_skills = path.join("skills").is_dir();
        let has_packages = path.join("packages").is_dir();

        has_sessions || has_extensions || has_skills || has_packages
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

        // Try reading version from settings.json
        // Checks for "version", then "lastChangelogVersion" as fallback
        if let Ok(content) = fs::read_to_string(path.join("settings.json")) {
            for line in content.lines() {
                let trimmed = line.trim();
                // Try "version" field first
                if trimmed.contains("\"version\"") {
                    if let Some(val) = trimmed.split_once(':') {
                        let v = val.1.trim().trim_matches(',').trim_matches('"');
                        if !v.is_empty() && v != "null" {
                            return v.to_string();
                        }
                    }
                }
            }
            // Fallback: lastChangelogVersion
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.contains("\"lastChangelogVersion\"") {
                    if let Some(val) = trimmed.split_once(':') {
                        let v = val.1.trim().trim_matches(',').trim_matches('"');
                        if !v.is_empty() && v != "null" {
                            return v.to_string();
                        }
                    }
                }
            }
        }

        "unknown".to_string()
    }
}

// ── Pi-specific methods ──────────────────────────────────────────────────────

#[allow(dead_code)]
impl PiInstallation {
    /// Path to `auth.json` (API keys, OAuth tokens).
    pub fn auth_path(&self) -> PathBuf {
        self.agent_dir.join("auth.json")
    }

    /// Path to `settings.json`.
    pub fn settings_path(&self) -> PathBuf {
        self.agent_dir.join("settings.json")
    }

    /// Path to `sessions/` directory.
    pub fn sessions_path(&self) -> PathBuf {
        self.agent_dir.join("sessions")
    }

    /// Path to `prompts/` directory.
    pub fn prompts_path(&self) -> PathBuf {
        self.agent_dir.join("prompts")
    }

    /// Validate that a path looks like a real Pi agent directory.
    fn validate(path: &Path) -> Result<()> {
        if !path.is_dir() {
            bail!(
                "path does not exist or is not a directory: {}",
                path.display()
            );
        }

        if !Self::is_valid_install(path) {
            let mut hints = Vec::new();
            if !path.join("settings.json").is_file() && !path.join("auth.json").is_file() {
                hints.push("no settings.json or auth.json found");
            }
            if !path.join("sessions").is_dir()
                && !path.join("extensions").is_dir()
                && !path.join("skills").is_dir()
                && !path.join("packages").is_dir()
            {
                hints.push("no sessions/, extensions/, skills/, or packages/ directory");
            }

            bail!(
                "not a valid Pi agent directory: {}\n  {}",
                path.display(),
                hints.join("\n  ")
            );
        }

        Ok(())
    }
}

// ── Path resolution ──────────────────────────────────────────────────────────

/// Resolve the Pi agent directory from the given inputs.
///
/// Resolution order:
/// 1. Explicit `--path` argument
/// 2. `PI_CODING_AGENT_DIR` env var (canonical)
/// 3. `~/.pi/agent/` (standard location)
/// 4. `PI_HOME` env var or `~/.pi/` (legacy, with warning)
///
/// Returns `(path, is_legacy)`.
fn resolve_agent_dir(path: Option<PathBuf>) -> Result<(PathBuf, bool)> {
    // 1. Explicit path
    if let Some(p) = path {
        return Ok((p, false));
    }

    // 2. PI_CODING_AGENT_DIR (canonical)
    if let Ok(val) = env::var(PI_CODING_AGENT_DIR) {
        let p = PathBuf::from(&val);
        if p.is_dir() {
            return Ok((p, false));
        }
    }

    // 3. ~/.pi/agent/ (standard)
    if let Some(home) = dirs::home_dir() {
        let p = home.join(".pi").join("agent");
        if p.is_dir() {
            return Ok((p, false));
        }
    }

    // 4. Legacy: PI_HOME or ~/.pi/ (with warning)
    if let Ok(val) = env::var(PI_HOME) {
        let p = PathBuf::from(&val);
        if p.is_dir() {
            return Ok((p, true));
        }
    }

    if let Some(home) = dirs::home_dir() {
        let p = home.join(".pi");
        if p.is_dir() {
            return Ok((p, true));
        }
    }

    bail!(
        "could not find Pi installation\n  \
         tried:\n    \
           1. PI_CODING_AGENT_DIR env var\n    \
           2. ~/.pi/agent/\n    \
           3. PI_HOME env var\n    \
           4. ~/.pi/\n  \
         hint: pass the path explicitly with `--path`"
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a minimal valid Pi agent directory.
    fn setup_agent_dir(dir: &Path) {
        fs::write(dir.join("settings.json"), "{}").unwrap();
        fs::create_dir_all(dir.join("sessions")).unwrap();
    }

    /// Create a full Pi agent directory.
    #[allow(dead_code)]
    fn setup_full_agent_dir(dir: &Path) {
        fs::write(dir.join("settings.json"), "{}").unwrap();
        fs::write(dir.join("auth.json"), "{}").unwrap();
        fs::create_dir_all(dir.join("sessions")).unwrap();
        fs::create_dir_all(dir.join("extensions")).unwrap();
        fs::create_dir_all(dir.join("skills")).unwrap();
        fs::create_dir_all(dir.join("themes")).unwrap();
        fs::create_dir_all(dir.join("packages")).unwrap();
    }

    // ── is_valid_install ────────────────────────────────────────────

    #[test]
    fn valid_install_with_settings_and_sessions() {
        let dir = TempDir::new().unwrap();
        setup_agent_dir(dir.path());
        assert!(PiInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn valid_install_with_auth_only() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("auth.json"), "{}").unwrap();
        fs::create_dir_all(dir.path().join("extensions")).unwrap();
        assert!(PiInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn invalid_empty_dir() {
        let dir = TempDir::new().unwrap();
        assert!(!PiInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn invalid_settings_but_no_dirs() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("settings.json"), "{}").unwrap();
        assert!(!PiInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn invalid_dirs_but_no_config() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("sessions")).unwrap();
        assert!(!PiInstallation::is_valid_install(dir.path()));
    }

    // ── detect with explicit path ───────────────────────────────────

    #[test]
    fn detect_explicit_path() {
        let dir = TempDir::new().unwrap();
        setup_agent_dir(dir.path());

        let pi = PiInstallation::detect(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(pi.name(), "pi");
        assert_eq!(pi.root(), dir.path());
    }

    #[test]
    fn detect_invalid_path_errors() {
        let dir = TempDir::new().unwrap();
        let result = PiInstallation::detect(Some(dir.path().to_path_buf()));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not a valid Pi agent directory"));
    }

    #[test]
    fn detect_nonexistent_path_errors() {
        let result = PiInstallation::detect(Some(PathBuf::from("/nonexistent")));
        assert!(result.is_err());
    }

    // ── detect with env vars ────────────────────────────────────────

    #[test]
    fn detect_with_coding_agent_dir() {
        let dir = TempDir::new().unwrap();
        setup_agent_dir(dir.path());

        env::set_var(PI_CODING_AGENT_DIR, dir.path().to_str().unwrap());
        let pi = PiInstallation::detect(None).unwrap();
        assert_eq!(pi.root(), dir.path());
        env::remove_var(PI_CODING_AGENT_DIR);
    }

    // ── read_version ────────────────────────────────────────────────

    #[test]
    fn read_version_from_file() {
        let dir = TempDir::new().unwrap();
        setup_agent_dir(dir.path());
        fs::write(dir.path().join("VERSION"), "0.5.0\n").unwrap();

        assert_eq!(PiInstallation::read_version(dir.path()), "0.5.0");
    }

    #[test]
    fn read_version_from_settings() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("settings.json"),
            "{\n  \"version\": \"1.2.3\"\n}",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("sessions")).unwrap();

        assert_eq!(PiInstallation::read_version(dir.path()), "1.2.3");
    }

    #[test]
    fn read_version_unknown() {
        let dir = TempDir::new().unwrap();
        setup_agent_dir(dir.path());
        assert_eq!(PiInstallation::read_version(dir.path()), "unknown");
    }

    // ── Pi-specific paths ───────────────────────────────────────────

    #[test]
    fn pi_paths_are_correct() {
        let dir = TempDir::new().unwrap();
        setup_agent_dir(dir.path());

        let pi = PiInstallation::detect(Some(dir.path().to_path_buf())).unwrap();

        // Config is the agent dir itself (settings.json is there)
        assert_eq!(pi.config_path(), dir.path());
        // Sessions = memory
        assert_eq!(pi.memory_path(), dir.path().join("sessions"));
        // Other paths
        assert_eq!(pi.packages_path(), dir.path().join("packages"));
        assert_eq!(pi.skills_path(), dir.path().join("skills"));
        assert_eq!(pi.themes_path(), dir.path().join("themes"));
        assert_eq!(pi.extensions_path(), dir.path().join("extensions"));
        // Pi-specific
        assert_eq!(pi.auth_path(), dir.path().join("auth.json"));
        assert_eq!(pi.settings_path(), dir.path().join("settings.json"));
        assert_eq!(pi.sessions_path(), dir.path().join("sessions"));
        assert_eq!(pi.prompts_path(), dir.path().join("prompts"));
    }

    // ── validate ────────────────────────────────────────────────────

    #[test]
    fn validate_error_messages() {
        let dir = TempDir::new().unwrap();
        let result = PiInstallation::validate(dir.path());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not a valid Pi agent directory"));
        assert!(msg.contains("settings.json"));
    }

    // ── real installation ───────────────────────────────────────────

    #[test]
    fn detect_real_pi_if_exists() {
        // This test only runs if ~/.pi/agent exists on the machine
        if let Some(home) = dirs::home_dir() {
            let agent_dir = home.join(".pi").join("agent");
            if agent_dir.is_dir() {
                let pi = PiInstallation::detect(None).unwrap();
                assert_eq!(pi.name(), "pi");
                assert!(pi.root().exists());
            }
        }
    }
}

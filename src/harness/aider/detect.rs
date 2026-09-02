//! Aider harness detection.
//!
//! Aider (https://aider.chat) is a command-line coding agent that works
//! differently from Pi:
//!
//! - **No central install dir**: Aider is a pip package, not a local agent dir.
//! - **Per-project config**: `.aider.conf.yml` at project root or `~/.aider.conf.yml`.
//! - **Secrets via env**: API keys via `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.
//! - **Conversation history**: `.aider.chat.history.md` per project.
//!
//! # What to detect
//!
//! 1. Check that `aider` is on PATH (`which aider` or `aider --version`)
//! 2. Read version from `aider --version` output
//! 3. Detect config file: `~/.aider.conf.yml` or project-level `.aider.conf.yml`
//! 4. Detect `.env` file for API keys
//! 5. Detect `.aider/` cache directory
//!
//! # Key differences from Pi
//!
//! | Aspect        | Pi                              | Aider                              |
//! |---------------|---------------------------------|------------------------------------|
//! | Install       | `~/.pi/agent/` dir              | `pip install aider` (no local dir) |
//! | Config        | `settings.json` in agent dir    | `.aider.conf.yml` (YAML)           |
//! | Secrets       | `auth.json`                     | Env vars / `.env` file             |
//! | History       | `sessions/` dir                 | `.aider.chat.history.md` per repo  |
//! | Skills        | `skills/` dir                   | None (conventions via markdown)    |
//! | Extensions    | `extensions/` dir               | None                               |
//! | Themes        | `themes/` dir                   | None                               |
//! | Run command   | `pi`                            | `aider`                            |

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::process;

use crate::harness::types::HarnessAdapter;

/// Detected Aider installation.
///
/// Unlike Pi, Aider doesn't have a central agent directory.
/// Instead, it's a CLI tool with per-project configuration.
#[derive(Debug)]
pub struct AiderInstallation {
    /// Path to the aider binary (detected via `which`).
    binary: PathBuf,
    /// Version string from `aider --version`.
    version: String,
    /// Project directory (where `.aider.conf.yml` lives).
    project_dir: PathBuf,
}

impl HarnessAdapter for AiderInstallation {
    fn name(&self) -> &str {
        "aider"
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn root(&self) -> &Path {
        &self.project_dir
    }

    /// Aider config is a single YAML file, not a directory.
    fn config_path(&self) -> PathBuf {
        self.project_dir.clone()
    }

    /// Aider's config file: `.aider.conf.yml`.
    fn config_file(&self) -> PathBuf {
        // Check project root first, then home dir
        let project_config = self.project_dir.join(".aider.conf.yml");
        if project_config.is_file() {
            return project_config;
        }

        if let Some(home) = dirs::home_dir() {
            let home_config = home.join(".aider.conf.yml");
            if home_config.is_file() {
                return home_config;
            }
        }

        // Return default (may not exist)
        self.project_dir.join(".aider.conf.yml")
    }

    /// Aider doesn't have a packages directory.
    fn packages_path(&self) -> PathBuf {
        self.project_dir.join(".aider")
    }

    /// Aider history: `.aider.chat.history.md` per project.
    fn memory_path(&self) -> PathBuf {
        self.project_dir.join(".aider.chat.history.md")
    }

    /// Aider doesn't have skills — uses CONVENTIONS.md instead.
    fn skills_path(&self) -> PathBuf {
        self.project_dir.join("CONVENTIONS.md")
    }

    /// Aider doesn't have extensions.
    fn extensions_path(&self) -> PathBuf {
        self.project_dir.join(".aider")
    }

    /// Aider doesn't have themes.
    fn themes_path(&self) -> PathBuf {
        self.project_dir.join(".aider")
    }

    /// Secrets: `.env` file or env vars.
    fn secrets_path(&self) -> PathBuf {
        // Check for .env in project dir
        let dot_env = self.project_dir.join(".env");
        if dot_env.is_file() {
            return dot_env;
        }
        // Fall back to home dir
        dirs::home_dir()
            .map(|h| h.join(".env"))
            .unwrap_or_else(|| PathBuf::from(".env"))
    }

    fn detect(path: Option<PathBuf>) -> Result<Self> {
        // 1. Find aider binary
        let binary = find_aider_binary()?;

        // 2. Get version
        let version = get_aider_version(&binary)?;

        // 3. Resolve project directory
        let project_dir = path.unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        });

        Ok(Self {
            binary,
            version,
            project_dir,
        })
    }

    fn is_valid_install(path: &Path) -> bool {
        // For Aider, "valid install" means:
        // 1. aider binary exists on PATH
        // 2. The project dir has .aider.conf.yml or .env
        let has_config = path.join(".aider.conf.yml").is_file();
        let has_env = path.join(".env").is_file();
        let has_aider_dir = path.join(".aider").is_dir();

        has_config || has_env || has_aider_dir
    }

    fn read_version(path: &Path) -> String {
        // Aider version comes from the binary, not a file
        // Try reading from .aider/version if it exists
        let version_file = path.join(".aider").join("version");
        if let Ok(content) = std::fs::read_to_string(&version_file) {
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        "unknown".to_string()
    }
}

impl AiderInstallation {
    /// Path to the aider binary.
    pub fn binary_path(&self) -> &Path {
        &self.binary
    }

    /// Path to the `.aider/` cache directory.
    pub fn cache_dir(&self) -> PathBuf {
        self.project_dir.join(".aider")
    }

    /// Path to `.aider.chat.history.md`.
    pub fn chat_history_path(&self) -> PathBuf {
        self.project_dir.join(".aider.chat.history.md")
    }

    /// Path to `CONVENTIONS.md` (Aider's equivalent of skills).
    pub fn conventions_path(&self) -> PathBuf {
        self.project_dir.join("CONVENTIONS.md")
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Find the aider binary on PATH.
fn find_aider_binary() -> Result<PathBuf> {
    let output = process::Command::new("which")
        .arg("aider")
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `which aider`: {}", e))?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    bail!(
        "aider is not installed or not in PATH\n  \
         install: pip install aider-chat\n  \
         docs: https://aider.chat/docs/install.html"
    )
}

/// Get the aider version from `aider --version`.
fn get_aider_version(binary: &Path) -> Result<String> {
    let output = process::Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `aider --version`: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = stdout.trim().to_string();
        if !version.is_empty() {
            return Ok(version);
        }
    }

    Ok("unknown".to_string())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn is_valid_with_config_yml() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".aider.conf.yml"), "model: gpt-4\n").unwrap();
        assert!(AiderInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn is_valid_with_env_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "OPENAI_API_KEY=sk-...\n").unwrap();
        assert!(AiderInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn is_valid_with_aider_dir() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".aider")).unwrap();
        assert!(AiderInstallation::is_valid_install(dir.path()));
    }

    #[test]
    fn is_invalid_empty() {
        let dir = TempDir::new().unwrap();
        assert!(!AiderInstallation::is_valid_install(dir.path()));
    }

    // detect() tests require aider installed — skip in CI
}

//! AiderHarness — adapter for the Aider coding agent.
//!
//! Aider is a Python-based coding agent. Unlike Pi, it doesn't have
//! a global installation directory — it operates per-project.

use super::super::super::domain::harness::HarnessId;
use super::super::traits::{DetectionResult, Harness};
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Aider harness adapter.
pub struct AiderHarness;

impl AiderHarness {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AiderHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness for AiderHarness {
    fn id(&self) -> HarnessId {
        HarnessId::Aider
    }

    fn name(&self) -> &str {
        "aider"
    }

    fn detect(&self, explicit_path: Option<&Path>) -> Result<DetectionResult> {
        // 1. Find the aider binary
        let binary = find_aider_binary()?;

        // 2. Get version
        let version = get_aider_version(&binary)?;

        // 3. Resolve project directory
        let root = match explicit_path {
            Some(p) if p.is_dir() => p.to_path_buf(),
            Some(p) => bail!("path is not a directory: {}", p.display()),
            None => std::env::current_dir()
                .map_err(|e| anyhow::anyhow!("failed to get current directory: {}", e))?,
        };

        Ok(DetectionResult {
            harness_id: HarnessId::Aider,
            root,
            version,
        })
    }

    fn is_valid_install(&self, path: &Path) -> bool {
        // Aider is valid if there's a config file or .env in the project
        path.join(".aider.conf.yml").is_file()
            || path.join(".env").is_file()
            || path.join(".aider").is_dir()
    }

    fn config_path(&self, root: &Path) -> PathBuf {
        root.to_path_buf() // .aider.conf.yml is in project root
    }

    fn memory_path(&self, root: &Path) -> PathBuf {
        root.to_path_buf() // chat history is per-repo
    }

    fn packages_path(&self, root: &Path) -> PathBuf {
        root.to_path_buf() // CONVENTIONS.md is in project root
    }

    fn secrets_path(&self, root: &Path) -> PathBuf {
        root.to_path_buf() // .env is in project root
    }

    fn launch_command(&self) -> &str {
        "aider"
    }
}

/// Find the aider binary via `which`.
fn find_aider_binary() -> Result<PathBuf> {
    let output = Command::new("which")
        .arg("aider")
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `which aider`: {}", e))?;

    if !output.status.success() {
        bail!(
            "aider not found in PATH\n  \
             install: pip install aider-chat\n  \
             docs: https://aider.chat/docs/install.html"
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}

/// Get the aider version from `aider --version`.
fn get_aider_version(binary: &Path) -> Result<String> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `aider --version`: {}", e))?;

    if !output.status.success() {
        return Ok("unknown".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = stdout.trim().to_string();
    Ok(if version.is_empty() {
        "unknown".to_string()
    } else {
        version
    })
}

//! AiderHarness — detection scaffold for the Aider coding agent.
//!
//! Aider is a Python-based coding agent. Unlike Pi, it doesn't have a global
//! installation directory — it operates per-project.
//!
//! **Status (v0.2): detection-only.** Aider is not yet wired end-to-end
//! through `init`/`pack`/`run`. `discover()` and `prepare_runtime()` are
//! intentionally unsupported until a real Aider environment can be validated
//! against the portable-environment contract.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::domain::harness::HarnessId;
use crate::harness::traits::{
    DetectionResult, Harness, HarnessContext, PortableEnvironment, PrepareRuntimeRequest,
    PreparedRuntime,
};

/// Aider harness adapter (detection scaffold).
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
    fn identity(&self) -> HarnessId {
        HarnessId::Aider
    }

    fn detect(&self, context: &HarnessContext) -> Result<DetectionResult> {
        // 1. Find the aider binary
        let binary = find_aider_binary()?;

        // 2. Get version
        let version = get_aider_version(&binary)?;

        // 3. Resolve project directory
        let root = match context.explicit_path.as_deref() {
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

    fn discover(&self, _context: &HarnessContext) -> Result<PortableEnvironment> {
        bail!(
            "aider harness is a detection-only scaffold in v0.2\n  \
             portable-environment discovery for aider is not implemented yet"
        )
    }

    fn prepare_runtime(&self, _request: PrepareRuntimeRequest) -> Result<PreparedRuntime> {
        bail!(
            "aider harness is a detection-only scaffold in v0.2\n  \
             runtime preparation for aider is not implemented yet"
        )
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

//! PiHarness — formalized adapter for the Pi agent runtime.
//!
//! Wraps the existing PiInstallation detection logic behind
//! the Harness trait interface.

use super::super::super::domain::harness::HarnessId;
use super::super::traits::{DetectionResult, Harness};
use super::super::types::HarnessAdapter;
use super::detect::PiInstallation;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Pi harness adapter.
pub struct PiHarness;

impl PiHarness {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PiHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness for PiHarness {
    fn id(&self) -> HarnessId {
        HarnessId::Pi
    }

    fn name(&self) -> &str {
        "pi"
    }

    fn detect(&self, explicit_path: Option<&Path>) -> Result<DetectionResult> {
        let pi = PiInstallation::detect(explicit_path.map(PathBuf::from))?;
        Ok(DetectionResult {
            harness_id: HarnessId::Pi,
            root: pi.root().to_path_buf(),
            version: pi.version().to_string(),
        })
    }

    fn is_valid_install(&self, path: &Path) -> bool {
        PiInstallation::is_valid_install(path)
    }

    fn config_path(&self, root: &Path) -> PathBuf {
        // Pi stores settings.json at the agent dir root
        root.to_path_buf()
    }

    fn memory_path(&self, root: &Path) -> PathBuf {
        root.join("sessions")
    }

    fn packages_path(&self, root: &Path) -> PathBuf {
        root.join("packages")
    }

    fn secrets_path(&self, root: &Path) -> PathBuf {
        root.to_path_buf() // auth.json is at root
    }

    fn launch_command(&self) -> &str {
        "pi"
    }
}

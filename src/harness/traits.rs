//! Harness trait — the abstraction that makes agentpacknest multi-harness.
//!
//! Each harness implementation knows how to interact with one specific
//! agent runtime (Pi, Aider, etc.). The core never knows about
//! harness-specific filesystem details.

use super::super::domain::harness::HarnessId;
use anyhow::Result;
use std::path::Path;

/// Detection result from a harness.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// The harness that was detected.
    pub harness_id: HarnessId,
    /// Path to the harness installation.
    pub root: std::path::PathBuf,
    /// Detected version string.
    pub version: String,
}

/// What a harness knows about itself.
pub trait Harness: Send + Sync {
    /// The unique identifier for this harness.
    fn id(&self) -> HarnessId;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Detect an installation of this harness.
    ///
    /// Resolution order:
    /// 1. Explicit path (if provided)
    /// 2. Environment variable
    /// 3. Default path
    fn detect(&self, explicit_path: Option<&Path>) -> Result<DetectionResult>;

    /// Check if a path looks like a valid installation.
    fn is_valid_install(&self, path: &Path) -> bool;

    /// Path to the configuration directory/file.
    fn config_path(&self, root: &Path) -> std::path::PathBuf;

    /// Path to the memory/sessions directory.
    fn memory_path(&self, root: &Path) -> std::path::PathBuf;

    /// Path to the packages directory.
    fn packages_path(&self, root: &Path) -> std::path::PathBuf;

    /// Path to the secrets file.
    fn secrets_path(&self, root: &Path) -> std::path::PathBuf;

    /// The launch command for this harness.
    fn launch_command(&self) -> &str;
}

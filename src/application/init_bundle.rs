//! InitBundle — create a new bundle from a harness installation.
//!
//! This is a thin orchestration layer. The actual bundle creation
//! logic lives in the harness adapters and infrastructure layer.

use crate::domain::harness::HarnessId;
use anyhow::Result;
use std::path::PathBuf;

/// Request to initialize a new bundle.
pub struct InitBundleRequest {
    pub harness: HarnessId,
    pub name: String,
    pub output_dir: PathBuf,
    pub source_path: Option<PathBuf>,
}

/// Result of bundle initialization.
pub struct InitBundleResult {
    pub bundle_path: PathBuf,
    pub harness_version: String,
}

/// Use case: initialize a new agent bundle.
pub fn execute(
    _app: &crate::application::Application,
    request: InitBundleRequest,
) -> Result<InitBundleResult> {
    // Delegate to the existing init command logic
    crate::commands::init::execute(
        request.harness.to_string(),
        request
            .source_path
            .map(|p| p.to_string_lossy().into_owned()),
        Some(request.name),
        Some(request.output_dir.to_string_lossy().into_owned()),
    )?;

    // For now, return the expected path
    // A full implementation would return the actual result from init
    Ok(InitBundleResult {
        bundle_path: request.output_dir,
        harness_version: "detected".to_string(),
    })
}

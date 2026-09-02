//! PackBundle — copy agent components into a bundle.
//!
//! Orchestrates: harness detection → component discovery → copy → encrypt → sign.

use anyhow::Result;
use std::path::PathBuf;

/// Request to pack a bundle.
pub struct PackBundleRequest {
    pub bundle_path: PathBuf,
    pub source_path: Option<PathBuf>,
    pub with_config: bool,
    pub with_memory: bool,
    pub with_skills: bool,
    pub with_secrets: bool,
    pub all: bool,
    pub archive: bool,
    pub encrypt_archive: bool,
    pub force: bool,
}

/// Use case: pack components into an existing bundle.
pub fn execute(_app: &crate::application::Application, request: PackBundleRequest) -> Result<()> {
    crate::commands::pack::execute(
        Some(request.bundle_path.to_string_lossy().into_owned()),
        request
            .source_path
            .map(|p| p.to_string_lossy().into_owned()),
        request.with_config,
        request.with_memory,
        request.with_skills,
        request.with_secrets,
        request.all,
        request.archive,
        request.encrypt_archive,
        request.force,
    )
}

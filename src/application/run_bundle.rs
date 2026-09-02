//! RunBundle — launch an agent from a bundle.
//!
//! Orchestrates: load manifest → verify integrity → decrypt secrets → build env → spawn.

use anyhow::Result;
use std::path::PathBuf;

/// Request to run a bundle.
pub struct RunBundleRequest {
    pub bundle_path: PathBuf,
    pub passphrase: Option<String>,
    pub workdir: Option<String>,
    pub dry_run: bool,
    pub args: Vec<String>,
}

/// Use case: run an agent from a bundle.
pub fn execute(_app: &crate::application::Application, request: RunBundleRequest) -> Result<()> {
    crate::commands::run::execute(
        Some(request.bundle_path.to_string_lossy().into_owned()),
        request.passphrase,
        request.workdir,
        request.dry_run,
        request.args,
    )
}

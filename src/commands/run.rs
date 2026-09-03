//! `pn run` command - thin CLI wrapper.

use crate::application::run_bundle::{RunBundleRequest, RunResult};
use anyhow::Result;
use std::path::PathBuf;

/// Execute `pn run` - thin wrapper that converts CLI args to application request.
pub fn execute(
    bundle_path: Option<String>,
    passphrase: Option<String>,
    workdir: Option<String>,
    dry_run: bool,
    allow_unverified: bool,
    args: Vec<String>,
) -> Result<RunResult> {
    let request = RunBundleRequest {
        bundle_path: bundle_path
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().expect("failed to get current directory")),
        passphrase,
        workdir,
        dry_run,
        allow_unverified,
        args,
    };

    crate::application::run_bundle::execute(request)
}

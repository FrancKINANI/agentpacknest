//! RunBundle — launch an agent from a bundle.
//!
//! Orchestrates: load manifest → verify integrity → verify signature → decrypt secrets → build env → spawn.

use anyhow::Result;
use std::path::PathBuf;

/// Request to run a bundle.
pub struct RunBundleRequest {
    pub bundle_path: PathBuf,
    pub passphrase: Option<String>,
    pub workdir: Option<String>,
    pub dry_run: bool,
    pub allow_unverified: bool,
    pub args: Vec<String>,
}

/// Result of a run operation.
pub struct RunResult {
    pub exit_code: i32,
    pub dry_run: bool,
}

/// Use case: run an agent from a bundle.
pub fn execute(request: RunBundleRequest) -> Result<RunResult> {
    crate::application::run_bundle_impl::execute(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_run_request_construction() {
        let request = RunBundleRequest {
            bundle_path: PathBuf::from("/tmp/bundle"),
            passphrase: Some("test".to_string()),
            workdir: None,
            dry_run: true,
            allow_unverified: false,
            args: vec![],
        };
        assert!(request.dry_run);
        assert!(!request.allow_unverified);
    }
}

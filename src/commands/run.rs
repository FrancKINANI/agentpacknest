//! `pn run` command - thin CLI wrapper.

use crate::application::run_bundle::{RunBundleRequest, RunResult, DEFAULT_MAX_AGE_SECS};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

/// Environment variable that sets the default freshness threshold.
pub(crate) const MAX_AGE_ENV: &str = "AGENTPACKNEST_MAX_AGE";

/// Execute `pn run` - thin wrapper that converts CLI args to application request.
pub fn execute(
    bundle_path: Option<String>,
    passphrase: Option<String>,
    workdir: Option<String>,
    dry_run: bool,
    allow_unverified: bool,
    args: Vec<String>,
    max_age: Option<String>,
) -> Result<RunResult> {
    let env_value = std::env::var(MAX_AGE_ENV).ok();
    let max_age_secs = resolve_max_age_secs(max_age.as_deref(), env_value.as_deref())?;

    let request = RunBundleRequest {
        bundle_path: bundle_path
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().expect("failed to get current directory")),
        passphrase,
        workdir,
        dry_run,
        allow_unverified,
        args,
        max_age_secs,
    };

    crate::application::run_bundle::execute(request)
}

/// Resolve the freshness threshold in seconds. Precedence: the `--max-age`
/// flag wins, then the `AGENTPACKNEST_MAX_AGE` environment variable, then
/// the default of 7 days. An empty environment value counts as unset.
pub(crate) fn resolve_max_age_secs(flag: Option<&str>, env_value: Option<&str>) -> Result<u64> {
    if let Some(value) = flag {
        return parse_duration_secs(value)
            .with_context(|| format!("invalid --max-age value '{value}'"));
    }
    if let Some(value) = env_value.filter(|v| !v.trim().is_empty()) {
        return parse_duration_secs(value)
            .with_context(|| format!("invalid {MAX_AGE_ENV} value '{value}'"));
    }
    Ok(DEFAULT_MAX_AGE_SECS)
}

/// Parse a freshness duration into seconds.
///
/// Accepts `Nd` (days), `Nh` (hours), `Nw` (weeks), or a bare number of
/// days (`30`). Zero and unparseable values are rejected.
pub(crate) fn parse_duration_secs(input: &str) -> Result<u64> {
    let raw = input.trim();
    if raw.is_empty() {
        bail!("duration cannot be empty");
    }

    let (digits, multiplier) = if let Some(d) = raw.strip_suffix('d') {
        (d, 86_400u64)
    } else if let Some(h) = raw.strip_suffix('h') {
        (h, 3_600)
    } else if let Some(w) = raw.strip_suffix('w') {
        (w, 604_800)
    } else {
        (raw, 86_400)
    };

    let n: u64 = digits.trim().parse().with_context(|| {
        format!("expected a duration like 7d, 24h, 2w, or a bare number of days, got '{input}'")
    })?;
    if n == 0 {
        bail!("duration must be greater than zero: '{input}'");
    }

    n.checked_mul(multiplier).context("duration is too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_days_hours_weeks_and_bare_days() {
        assert_eq!(parse_duration_secs("7d").unwrap(), 7 * 86_400);
        assert_eq!(parse_duration_secs("24h").unwrap(), 86_400);
        assert_eq!(parse_duration_secs("2w").unwrap(), 14 * 86_400);
        assert_eq!(parse_duration_secs("30").unwrap(), 30 * 86_400);
        assert_eq!(parse_duration_secs(" 5d ").unwrap(), 5 * 86_400);
    }

    #[test]
    fn rejects_invalid_durations() {
        for bad in ["", "0", "0d", "-1", "abc", "1.5d", "7m", "7years"] {
            assert!(
                parse_duration_secs(bad).is_err(),
                "'{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn flag_wins_over_env() {
        assert_eq!(
            resolve_max_age_secs(Some("30d"), Some("7d")).unwrap(),
            30 * 86_400,
            "--max-age must win over AGENTPACKNEST_MAX_AGE"
        );
    }

    #[test]
    fn env_used_when_no_flag() {
        assert_eq!(resolve_max_age_secs(None, Some("24h")).unwrap(), 86_400);
    }

    #[test]
    fn empty_env_counts_as_unset() {
        assert_eq!(
            resolve_max_age_secs(None, Some("  ")).unwrap(),
            DEFAULT_MAX_AGE_SECS
        );
    }

    #[test]
    fn default_when_nothing_configured() {
        assert_eq!(
            resolve_max_age_secs(None, None).unwrap(),
            DEFAULT_MAX_AGE_SECS
        );
        assert_eq!(DEFAULT_MAX_AGE_SECS, 7 * 86_400);
    }

    #[test]
    fn invalid_flag_and_env_rejected() {
        assert!(resolve_max_age_secs(Some("bogus"), None).is_err());
        assert!(resolve_max_age_secs(None, Some("bogus")).is_err());
        assert!(resolve_max_age_secs(Some("bogus"), Some("7d")).is_err());
    }
}

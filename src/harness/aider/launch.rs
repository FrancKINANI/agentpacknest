#![allow(dead_code)]
//! Aider launch configuration.
//!
//! # How Aider is launched
//!
//! ```bash
//! # Basic launch
//! aider
//!
//! # With specific model
//! aider --model gpt-4
//!
//! # With files
//! aider file1.py file2.py
//!
//! # Non-interactive (for agentpacknest)
//! aider --yes --message "fix the bug" --file src/main.py
//! ```
//!
//! # Environment variables needed
//!
//! Aider reads these env vars at runtime:
//! - `OPENAI_API_KEY` — OpenAI API key
//! - `ANTHROPIC_API_KEY` — Anthropic API key
//! - `GITHUB_TOKEN` — GitHub token (for GitHub Copilot)
//! - `GEMINI_API_KEY` — Google Gemini API key
//! - `OPENROUTER_API_KEY` — OpenRouter API key
//!
//! These are typically set via `.env` file or shell environment.
//! agentpacknest should decrypt secrets and inject them as env vars.
//!
//! # Key differences from Pi
//!
//! - Pi: launches via `pi` command, uses its own runtime
//! - Aider: launches via `aider` command, is a standalone CLI tool
//!
//! - Pi: needs Node.js >= 20
//! - Aider: needs Python >= 3.8, pip-installed
//!
//! - Pi: env cleared + agentpacknest vars injected
//! - Aider: env cleared + API key vars injected (from .env or encrypted secrets)

use std::path::Path;

/// Build the command line for launching Aider.
///
/// This is a stub — the actual implementation will parse `.aider.conf.yml`
/// and merge with bundle settings.
pub fn build_launch_command(config_file: &Path) -> String {
    // TODO: Parse .aider.conf.yml and build command
    // For now, return the basic command
    let mut cmd = String::from("aider");

    // If config file exists, reference it
    if config_file.is_file() {
        cmd.push_str(&format!(" --config {}", config_file.display()));
    }

    cmd
}

/// Build environment variables for Aider.
///
/// Returns the list of env var names that should be injected.
pub fn required_env_vars() -> Vec<&'static str> {
    vec![
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn build_command_basic() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join(".aider.conf.yml");
        let cmd = build_launch_command(&config);
        assert_eq!(cmd, "aider");
    }

    #[test]
    fn build_command_with_config() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join(".aider.conf.yml");
        std::fs::write(&config, "model: gpt-4\n").unwrap();

        let cmd = build_launch_command(&config);
        assert!(cmd.starts_with("aider"));
        assert!(cmd.contains("--config"));
    }

    #[test]
    fn required_env_vars_list() {
        let vars = required_env_vars();
        assert!(vars.contains(&"OPENAI_API_KEY"));
        assert!(vars.contains(&"ANTHROPIC_API_KEY"));
    }
}

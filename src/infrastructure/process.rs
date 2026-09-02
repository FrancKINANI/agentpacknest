//! Process execution — spawning agent processes with isolated environments.
//!
//! This module handles:
//! - Building clean environments (env_clear + selective inheritance)
//! - Injecting agent variables and secrets
//! - Spawning the child process
//! - Capturing exit status

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::Command;

/// An isolated runtime environment for executing an agent.
#[derive(Debug, Default)]
pub struct RuntimeEnvironment {
    variables: HashMap<String, String>,
}

impl RuntimeEnvironment {
    /// Create a clean environment (no inherited variables).
    pub fn clean() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    /// Allow essential system variables to pass through.
    pub fn allow_system_defaults(&mut self) {
        let keys = if cfg!(target_os = "windows") {
            &[
                "PATH",
                "HOME",
                "USER",
                "SystemRoot",
                "COMSPEC",
                "PATHEXT",
                "TEMP",
                "TMP",
            ] as &[&str]
        } else {
            &["PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TMPDIR"] as &[&str]
        };

        for key in keys {
            if let Ok(val) = env::var(key) {
                self.variables.insert(key.to_string(), val);
            }
        }
    }

    /// Inject a variable into the environment.
    pub fn inject(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.variables.insert(key.into(), value.into());
    }

    /// Inject multiple variables.
    pub fn inject_all(&mut self, vars: HashMap<String, String>) {
        self.variables.extend(vars);
    }

    /// Get the number of variables.
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Check if the environment is empty.
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// Get the variable keys (for display).
    pub fn keys(&self) -> Vec<&str> {
        self.variables.keys().map(|s| s.as_str()).collect()
    }
}

/// Execute a command with an isolated runtime environment.
///
/// Returns the exit code of the child process.
pub fn run_with_environment(
    cmd: &str,
    args: &[&str],
    workdir: &Path,
    env: &RuntimeEnvironment,
) -> Result<i32> {
    let mut command = Command::new(cmd);
    command.args(args);
    command.current_dir(workdir);

    // Clear inherited env
    command.env_clear();

    // Inject our variables
    for (key, value) in &env.variables {
        command.env(key, value);
    }

    let status = command
        .status()
        .with_context(|| format!("failed to execute: {}", cmd))?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_environment_is_empty() {
        let env = RuntimeEnvironment::clean();
        assert!(env.is_empty());
        assert_eq!(env.len(), 0);
    }

    #[test]
    fn inject_variables() {
        let mut env = RuntimeEnvironment::clean();
        env.inject("MY_VAR", "hello");
        env.inject("OTHER", "world");
        assert_eq!(env.len(), 2);
        assert!(env.keys().contains(&"MY_VAR"));
        assert!(env.keys().contains(&"OTHER"));
    }

    #[test]
    fn run_simple_command() {
        let env = RuntimeEnvironment::clean();
        let code = run_with_environment("echo", &["hello"], Path::new("."), &env).unwrap();
        assert_eq!(code, 0);
    }
}

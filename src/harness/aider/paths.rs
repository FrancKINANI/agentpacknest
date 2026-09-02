//! Aider path resolution.
//!
//! Aider's file layout per project:
//!
//! ```text
//! project-root/
//! ├── .aider.conf.yml       # YAML config (model, edit format, etc.)
//! ├── .env                   # API keys (OPENAI_API_KEY, etc.)
//! ├── .aider.chat.history.md # Chat history (auto-generated)
//! ├── .aider.input.history   # Input history (auto-generated)
//! ├── .aider/                # Cache dir (repo map, lock files)
//! │   └── cache/
//! ├── CONVENTIONS.md         # Coding conventions (optional)
//! └── ... source files
//! ```
//!
//! Global config (checked after project-level):
//!
//! ```text
//! ~/.aider.conf.yml         # Global aider settings
//! ```
//!
//! # Key differences from Pi
//!
//! - Pi: config is `settings.json` (JSON) in a central agent dir
//! - Aider: config is `.aider.conf.yml` (YAML) per project
//!
//! - Pi: secrets in `auth.json` (JSON, encrypted by hitchhike)
//! - Aider: secrets in `.env` (plaintext) or env vars
//!
//! - Pi: history in `sessions/` dir (structured .jsonl)
//! - Aider: history in `.aider.chat.history.md` (markdown)

use std::path::PathBuf;

/// Resolve all Aider-related paths for a given project directory.
pub struct AiderPaths {
    pub project_dir: PathBuf,
}

impl AiderPaths {
    pub fn new(project_dir: PathBuf) -> Self {
        Self { project_dir }
    }

    /// `.aider.conf.yml` — main config file.
    pub fn config_file(&self) -> PathBuf {
        self.project_dir.join(".aider.conf.yml")
    }

    /// `.env` — API keys and secrets.
    pub fn env_file(&self) -> PathBuf {
        self.project_dir.join(".env")
    }

    /// `.aider/` — cache directory.
    pub fn cache_dir(&self) -> PathBuf {
        self.project_dir.join(".aider")
    }

    /// `.aider.chat.history.md` — conversation history.
    pub fn chat_history(&self) -> PathBuf {
        self.project_dir.join(".aider.chat.history.md")
    }

    /// `.aider.input.history` — input history.
    pub fn input_history(&self) -> PathBuf {
        self.project_dir.join(".aider.input.history")
    }

    /// `CONVENTIONS.md` — coding conventions (Aider's "skills").
    pub fn conventions(&self) -> PathBuf {
        self.project_dir.join("CONVENTIONS.md")
    }

    /// Check which paths actually exist on disk.
    pub fn exists(&self) -> AiderPathStatus {
        AiderPathStatus {
            config_file: self.config_file().is_file(),
            env_file: self.env_file().is_file(),
            cache_dir: self.cache_dir().is_dir(),
            chat_history: self.chat_history().is_file(),
            conventions: self.conventions().is_file(),
        }
    }
}

/// Status of which Aider paths exist.
#[derive(Debug)]
pub struct AiderPathStatus {
    pub config_file: bool,
    pub env_file: bool,
    pub cache_dir: bool,
    pub chat_history: bool,
    pub conventions: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn paths_point_to_correct_locations() {
        let dir = TempDir::new().unwrap();
        let paths = AiderPaths::new(dir.path().to_path_buf());

        assert_eq!(paths.config_file(), dir.path().join(".aider.conf.yml"));
        assert_eq!(paths.env_file(), dir.path().join(".env"));
        assert_eq!(paths.cache_dir(), dir.path().join(".aider"));
        assert_eq!(paths.chat_history(), dir.path().join(".aider.chat.history.md"));
        assert_eq!(paths.conventions(), dir.path().join("CONVENTIONS.md"));
    }

    #[test]
    fn status_detects_existing_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".aider.conf.yml"), "model: gpt-4\n").unwrap();
        std::fs::write(dir.path().join(".env"), "KEY=val\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".aider")).unwrap();

        let paths = AiderPaths::new(dir.path().to_path_buf());
        let status = paths.exists();

        assert!(status.config_file);
        assert!(status.env_file);
        assert!(status.cache_dir);
        assert!(!status.chat_history);
        assert!(!status.conventions);
    }
}

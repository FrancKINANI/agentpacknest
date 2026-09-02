use anyhow::Result;
use std::path::{Path, PathBuf};

/// Abstraction over different agent runtime environments.
///
/// Each harness (pi, desktop, etc.) implements this trait to provide
/// a uniform interface for detecting, configuring, and interacting
/// with an installation.
pub trait HarnessAdapter {
    /// The human-readable name of this harness (e.g. "pi", "desktop").
    fn name(&self) -> &str;

    /// The detected version string, or "unknown" if unreadable.
    fn version(&self) -> &str;

    /// Root directory of the detected installation.
    fn root(&self) -> &Path;

    /// Path to the configuration directory.
    fn config_path(&self) -> PathBuf {
        self.root().join("config")
    }

    /// Path to the packages directory.
    fn packages_path(&self) -> PathBuf {
        self.root().join("packages")
    }

    /// Path to the memory directory.
    fn memory_path(&self) -> PathBuf {
        self.root().join("memory")
    }

    /// Path to the skills directory.
    fn skills_path(&self) -> PathBuf {
        self.root().join("skills")
    }

    /// Path to the themes directory.
    fn themes_path(&self) -> PathBuf {
        self.root().join("themes")
    }

    /// Path to the extensions directory.
    fn extensions_path(&self) -> PathBuf {
        self.root().join("extensions")
    }

    /// Detect an installation.
    ///
    /// Resolution order:
    /// 1. Use `path` if provided and valid
    /// 2. Fall back to harness-specific env var (e.g. `PI_HOME`)
    /// 3. Fall back to a default location (e.g. `~/.pi`)
    fn detect(path: Option<PathBuf>) -> Result<Self>
    where
        Self: Sized;

    /// Verify that a directory looks like a valid installation of this harness.
    fn is_valid_install(path: &Path) -> bool;

    /// Try to read the version from the installation.
    fn read_version(path: &Path) -> String;
}

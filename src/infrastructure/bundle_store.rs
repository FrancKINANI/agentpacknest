//! BundleRepository — abstraction for bundle storage.
//!
//! A BundleRepository knows how to load, save, and verify bundles.
//! The default implementation uses the filesystem, but this can be
//! extended to support archives, remote registries, etc.

use crate::domain::manifest::Manifest;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Trait for bundle storage operations.
pub trait BundleRepository: Send + Sync {
    /// Check if a bundle exists at the given path.
    fn exists(&self, path: &Path) -> bool;

    /// Load a manifest from a bundle directory.
    fn load_manifest(&self, bundle_path: &Path) -> Result<Manifest>;

    /// Save a manifest to a bundle directory.
    fn save_manifest(&self, bundle_path: &Path, manifest: &Manifest) -> Result<()>;

    /// Get the path to the signature file for a bundle.
    fn signature_path(&self, bundle_path: &Path) -> PathBuf {
        bundle_path.join("manifest.sig")
    }

    /// Get the path to the encrypted secrets file.
    fn secrets_path(&self, bundle_path: &Path) -> PathBuf {
        bundle_path.join("secrets/keys.enc")
    }
}

/// Filesystem-based bundle repository.
pub struct FilesystemBundleRepository;

impl BundleRepository for FilesystemBundleRepository {
    fn exists(&self, path: &Path) -> bool {
        path.is_dir() && path.join("manifest.yaml").is_file()
    }

    fn load_manifest(&self, bundle_path: &Path) -> Result<Manifest> {
        let manifest_path = bundle_path.join("manifest.yaml");
        crate::domain::manifest::load(&manifest_path)
            .with_context(|| format!("failed to load manifest from {}", bundle_path.display()))
    }

    fn save_manifest(&self, bundle_path: &Path, manifest: &Manifest) -> Result<()> {
        let manifest_path = bundle_path.join("manifest.yaml");
        crate::domain::manifest::save(&manifest_path, manifest)
            .with_context(|| format!("failed to save manifest to {}", bundle_path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn filesystem_repository_exists() {
        let dir = TempDir::new().unwrap();
        let repo = FilesystemBundleRepository;

        assert!(!repo.exists(dir.path()));

        // Create a manifest
        std::fs::write(dir.path().join("manifest.yaml"), "test").unwrap();
        assert!(repo.exists(dir.path()));
    }

    #[test]
    fn filesystem_repository_save_load_manifest() {
        let dir = TempDir::new().unwrap();
        let repo = FilesystemBundleRepository;

        let manifest = crate::domain::manifest::default_pi("test", "1.0");
        repo.save_manifest(dir.path(), &manifest).unwrap();

        let loaded = repo.load_manifest(dir.path()).unwrap();
        assert_eq!(loaded.bundle.name, "test");
        assert_eq!(loaded.harness.version, "1.0");
    }
}

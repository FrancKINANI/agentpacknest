//! Bundle — the central concept of agentpacknest.
//!
//! A Bundle represents a portable, reproducible agent environment.
//! It is the aggregate root that ties together manifest, components,
//! and provenance.

use super::component::{ComponentKind, ComponentState};
use super::harness::HarnessId;
use std::path::PathBuf;

/// A portable agent environment bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Filesystem path to the bundle root directory.
    pub root: PathBuf,
    /// Harness this bundle targets.
    pub harness: HarnessId,
    /// Bundle name (human-readable).
    pub name: String,
    /// Components packed into this bundle.
    pub components: Vec<ComponentState>,
}

impl Bundle {
    /// Create a new Bundle reference from a directory path.
    ///
    /// Does not validate or load — use `Bundle::load()` for that.
    pub fn new(root: PathBuf, name: String, harness: HarnessId) -> Self {
        Self {
            root,
            harness,
            name,
            components: Vec::new(),
        }
    }

    /// Path to the manifest file.
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.yaml")
    }

    /// Path to the signature file.
    pub fn signature_path(&self) -> PathBuf {
        self.root.join("manifest.sig")
    }

    /// Path to the encrypted secrets file.
    pub fn secrets_path(&self) -> PathBuf {
        self.root.join("secrets/keys.enc")
    }

    /// Check if the bundle directory exists and contains a manifest.
    pub fn exists(&self) -> bool {
        self.root.is_dir() && self.manifest_path().is_file()
    }

    /// Get the state of a specific component.
    pub fn component(&self, kind: ComponentKind) -> Option<&ComponentState> {
        self.components.iter().find(|c| c.kind == kind)
    }

    /// Check if a specific component is packed.
    pub fn has_component(&self, kind: ComponentKind) -> bool {
        self.component(kind).is_some_and(|c| c.packed)
    }

    /// Count of packed components.
    pub fn packed_count(&self) -> usize {
        self.components.iter().filter(|c| c.packed).count()
    }

    /// Total component count.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }
}

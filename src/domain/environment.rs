//! AgentEnvironment — the discovered state of an agent installation.
//!
//! A harness discovers an AgentEnvironment from a local installation.
//! The application layer then converts this into a Bundle for packing.

use super::component::{ComponentKind, ComponentState};
use super::harness::HarnessId;
use std::path::PathBuf;

/// The discovered state of an agent installation.
///
/// This is what a Harness discovers via `detect()` + path scanning.
/// It represents the agent's environment in a harness-agnostic way.
#[derive(Debug, Clone)]
pub struct AgentEnvironment {
    /// Which harness this environment belongs to.
    pub harness: HarnessId,
    /// Root path of the harness installation.
    pub root: PathBuf,
    /// Detected version of the harness.
    pub version: String,
    /// Components found in this environment.
    pub components: Vec<ComponentState>,
}

impl AgentEnvironment {
    /// Create a new empty environment for a given harness.
    pub fn new(harness: HarnessId, root: PathBuf, version: String) -> Self {
        let components = ComponentKind::all()
            .iter()
            .map(|&kind| ComponentState::new(kind))
            .collect();
        Self {
            harness,
            root,
            version,
            components,
        }
    }

    /// Mark a component as packed with a file count.
    pub fn mark_packed(&mut self, kind: ComponentKind, file_count: u64) {
        if let Some(comp) = self.components.iter_mut().find(|c| c.kind == kind) {
            *comp = ComponentState::packed(kind, file_count);
        }
    }

    /// Check if a component is packed.
    pub fn has_component(&self, kind: ComponentKind) -> bool {
        self.components.iter().any(|c| c.kind == kind && c.packed)
    }

    /// Count of packed components.
    pub fn packed_count(&self) -> usize {
        self.components.iter().filter(|c| c.packed).count()
    }

    /// Total number of files across all packed components.
    pub fn total_files(&self) -> u64 {
        self.components.iter().map(|c| c.file_count).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_environment_has_all_components_unpacked() {
        let env = AgentEnvironment::new(HarnessId::Pi, PathBuf::from("/tmp/test"), "0.84.4".into());
        assert_eq!(env.components.len(), 6);
        assert_eq!(env.packed_count(), 0);
    }

    #[test]
    fn mark_packed_tracks_files() {
        let mut env = AgentEnvironment::new(HarnessId::Pi, PathBuf::from("/tmp"), "1.0".into());
        env.mark_packed(ComponentKind::Config, 5);
        env.mark_packed(ComponentKind::Skills, 3);
        assert!(env.has_component(ComponentKind::Config));
        assert!(env.has_component(ComponentKind::Skills));
        assert!(!env.has_component(ComponentKind::Memory));
        assert_eq!(env.packed_count(), 2);
        assert_eq!(env.total_files(), 8);
    }
}

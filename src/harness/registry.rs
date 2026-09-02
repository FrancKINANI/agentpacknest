//! HarnessRegistry — central registry for harness adapters.
//!
//! The registry maps HarnessId → Harness adapter. The core uses
//! the registry to resolve which adapter to use for a given harness name.

use super::super::domain::harness::HarnessId;
use super::traits::{DetectionResult, Harness};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

/// Central registry of harness adapters.
pub struct HarnessRegistry {
    harnesses: HashMap<HarnessId, Box<dyn Harness>>,
}

impl HarnessRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            harnesses: HashMap::new(),
        }
    }

    /// Create a registry with all built-in harnesses pre-registered.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        // Pi is fully supported
        registry.register(Box::new(super::pi::PiHarness::new()));
        // Aider is scaffolded (detection only)
        registry.register(Box::new(super::aider::AiderHarness::new()));
        registry
    }

    /// Register a harness adapter.
    pub fn register(&mut self, harness: Box<dyn Harness>) {
        self.harnesses.insert(harness.id(), harness);
    }

    /// Get a harness adapter by ID.
    pub fn get(&self, id: HarnessId) -> Result<&dyn Harness> {
        self.harnesses.get(&id).map(|h| h.as_ref()).ok_or_else(|| {
            let supported: Vec<_> = self.supported_ids().iter().map(|h| h.to_string()).collect();
            anyhow::anyhow!(
                "harness '{}' not registered — available: {}",
                id,
                supported.join(", ")
            )
        })
    }

    /// Detect a harness installation.
    pub fn detect(&self, id: HarnessId, explicit_path: Option<&Path>) -> Result<DetectionResult> {
        let harness = self.get(id)?;
        harness.detect(explicit_path)
    }

    /// List all registered harness IDs.
    pub fn supported_ids(&self) -> Vec<HarnessId> {
        self.harnesses.keys().copied().collect()
    }
}

impl Default for HarnessRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_pi_and_aider() {
        let registry = HarnessRegistry::with_defaults();
        let ids = registry.supported_ids();
        assert!(ids.contains(&HarnessId::Pi));
        assert!(ids.contains(&HarnessId::Aider));
    }

    #[test]
    fn get_registered_harness() {
        let registry = HarnessRegistry::with_defaults();
        assert!(registry.get(HarnessId::Pi).is_ok());
    }

    #[test]
    fn get_unregistered_harness_fails() {
        let registry = HarnessRegistry::with_defaults();
        // Manually remove Pi
        let mut registry = registry;
        registry.harnesses.remove(&HarnessId::Pi);
        assert!(registry.get(HarnessId::Pi).is_err());
    }
}

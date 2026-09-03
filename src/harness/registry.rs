//! HarnessRegistry — central registry for harness adapters.
//!
//! The registry maps HarnessId → Harness adapter. Application-layer code
//! resolves a harness by name through the registry, so Pi-specific knowledge
//! never leaks into `application`, `commands`, `domain`, or `security`.

use crate::domain::harness::HarnessId;
use crate::harness::traits::{
    DetectionResult, Harness, HarnessContext, PortableEnvironment, PrepareRuntimeRequest,
    PreparedRuntime,
};
use anyhow::Result;
use std::collections::HashMap;

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
        // Pi is fully supported.
        registry.register(Box::new(super::pi::PiHarness::new()));
        // Aider is scaffolded (detection only).
        registry.register(Box::new(super::aider::AiderHarness::new()));
        registry
    }

    /// Register a harness adapter.
    pub fn register(&mut self, harness: Box<dyn Harness>) {
        self.harnesses.insert(harness.identity(), harness);
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

    /// Resolve a harness by name (e.g. "pi"), returning a clean error listing
    /// registered harnesses when the name is unknown.
    pub fn by_name(&self, name: &str) -> Result<&dyn Harness> {
        let id = HarnessId::from_name(name).ok_or_else(|| {
            let supported: Vec<_> = self.supported_ids().iter().map(|h| h.to_string()).collect();
            anyhow::anyhow!(
                "unsupported harness '{}'\n  supported: {}\n  hint: only 'pi' is fully supported in pn v0.2",
                name,
                supported.join(", ")
            )
        })?;
        self.get(id)
    }

    /// Detect an installation of the harness with the given ID.
    pub fn detect(&self, id: HarnessId, context: &HarnessContext) -> Result<DetectionResult> {
        self.get(id)?.detect(context)
    }

    /// Discover the portable environment of the harness with the given ID.
    pub fn discover(&self, id: HarnessId, context: &HarnessContext) -> Result<PortableEnvironment> {
        self.get(id)?.discover(context)
    }

    /// Prepare the runtime of the harness with the given ID.
    pub fn prepare_runtime(
        &self,
        id: HarnessId,
        request: PrepareRuntimeRequest,
    ) -> Result<PreparedRuntime> {
        self.get(id)?.prepare_runtime(request)
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
    use crate::harness::traits::HarnessContext;
    use std::path::PathBuf;

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

    #[test]
    fn by_name_resolves_pi() {
        let registry = HarnessRegistry::with_defaults();
        let harness = registry.by_name("pi").unwrap();
        assert_eq!(harness.identity(), HarnessId::Pi);
    }

    #[test]
    fn by_name_rejects_unknown() {
        let registry = HarnessRegistry::with_defaults();
        assert!(registry.by_name("codex").is_err());
    }

    #[test]
    fn detect_pi_with_explicit_path() {
        // Build a minimal fake Pi install in a temp dir.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();
        std::fs::create_dir_all(dir.path().join("sessions")).unwrap();

        let registry = HarnessRegistry::with_defaults();
        let ctx = HarnessContext::new(Some(PathBuf::from(dir.path())));
        let detected = registry.detect(HarnessId::Pi, &ctx).unwrap();
        assert_eq!(detected.harness_id, HarnessId::Pi);
        assert_eq!(detected.root, dir.path());
    }

    #[test]
    fn discover_pi_fails_without_installation() {
        let registry = HarnessRegistry::with_defaults();
        let ctx = HarnessContext::new(Some(PathBuf::from("/nonexistent")));
        assert!(registry.discover(HarnessId::Pi, &ctx).is_err());
    }
}

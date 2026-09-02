//! Domain layer — what the system IS.
//!
//! Contains the core types that represent agent environments and bundles.
//! This layer has no knowledge of CLI, filesystem, or crypto implementations.

pub mod bundle;
pub mod component;
pub mod environment;
pub mod error;
pub mod harness;
pub mod manifest;

pub use bundle::Bundle;
pub use component::{ComponentKind, ComponentState};
pub use environment::AgentEnvironment;
pub use error::DomainError;
pub use harness::HarnessId;
pub use manifest::Manifest;

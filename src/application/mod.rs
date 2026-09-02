//! Application layer — what the system DOES.
//!
//! Each module represents a use case. The application layer orchestrates
//! domain types, harness adapters, and infrastructure services.
//! It contains no business logic itself — that lives in domain/.

pub mod init_bundle;
pub mod pack_bundle;
pub mod run_bundle;

/// Shared application context.
pub struct Application {
    pub harnesses: crate::harness::HarnessRegistry,
}

impl Application {
    /// Build the application with default harnesses registered.
    pub fn build() -> Self {
        Self {
            harnesses: crate::harness::HarnessRegistry::with_defaults(),
        }
    }
}

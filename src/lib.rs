//! agentpacknest — Package coding agents into portable, reproducible bundles.
//!
//! Architecture:
//! - `domain` — what the system IS (Bundle, Manifest, Component, HarnessId)
//! - `application` — what the system DOES (use cases)
//! - `harness` — agent-specific adapters (Pi, Aider)
//! - `security` — crypto, secrets, signing, integrity
//! - `infrastructure` — filesystem, process execution, archives
//! - `cli` — command-line interface (thin dispatch layer)

pub mod application;
pub mod cli;
pub mod commands;
pub mod domain;
pub mod harness;
pub mod infrastructure;
pub mod security;

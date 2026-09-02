//! agentpacknest — Package coding agents into portable, reproducible bundles.
//!
//! Architecture:
//! - `domain` — what the system IS (Bundle, Component, HarnessId)
//! - `application` — what the system DOES (use cases)
//! - `harness` — agent-specific adapters (Pi, Aider)
//! - `security` — crypto, secrets, signing
//! - `infrastructure` — filesystem, process execution
//! - `cli` — command-line interface (thin dispatch layer)

pub mod cli;
pub mod commands;
pub mod core;
pub mod domain;
pub mod harness;
pub mod infrastructure;
pub mod security;
pub mod utils;

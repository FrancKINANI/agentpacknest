//! Structured domain errors.
//!
//! These represent business-logic failures that can occur in the domain layer.
//! They use `thiserror` for structured variants. The application layer
//! converts these to `anyhow::Error` at the boundary.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    // ── Manifest ──────────────────────────────────────────────────────
    #[error("manifest not found at {path}")]
    ManifestNotFound { path: String },

    #[error("unsupported schema version: expected {expected}, got {got}")]
    UnsupportedSchemaVersion { expected: String, got: String },

    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    // ── Bundle ────────────────────────────────────────────────────────
    #[error("not a valid bundle directory: {path}")]
    InvalidBundle { path: String },

    #[error("bundle already exists at {path}")]
    BundleAlreadyExists { path: String },

    #[error("component '{component}' not packed in bundle")]
    ComponentNotPacked { component: String },

    // ── Harness ───────────────────────────────────────────────────────
    #[error("unsupported harness: '{name}' — supported: {supported}")]
    UnsupportedHarness { name: String, supported: String },

    #[error("harness not found: {name}")]
    HarnessNotFound { name: String },

    // ── Integrity ─────────────────────────────────────────────────────
    #[error("checksum mismatch: expected {expected}, got {got}")]
    ChecksumMismatch { expected: String, got: String },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("signature verification failed: {reason}")]
    SignatureVerificationFailed { reason: String },

    // ── Secrets ───────────────────────────────────────────────────────
    #[error("decryption failed — wrong passphrase or corrupted data")]
    DecryptionFailed,

    #[error("passphrase cannot be empty")]
    EmptyPassphrase,

    #[error("passphrases do not match")]
    PassphraseMismatch,

    // ── Runtime ───────────────────────────────────────────────────────
    #[error("runtime '{name}' not found — {install_hint}")]
    RuntimeMissing { name: String, install_hint: String },

    #[error("runtime '{name}' version {got} below minimum {min}")]
    RuntimeVersionTooOld {
        name: String,
        got: String,
        min: String,
    },
}

//! Harness contract (v0.2) — the single abstraction between AgentPackNest
//! Core and agent runtimes.
//!
//! Core principle: **harnesses describe their environments.**
//!
//! The AgentPackNest Core owns:
//! - bundle construction, filesystem copying into the bundle
//! - manifest construction
//! - secret encryption/decryption
//! - integrity calculation, signature creation/verification
//! - structural validation, security policy
//! - process spawning and secret injection
//!
//! A harness owns:
//! - identifying itself
//! - detecting its installation/environment ([`Harness::detect`])
//! - discovering which resources constitute its portable environment
//!   ([`Harness::discover`])
//! - describing how its runtime should be prepared ([`Harness::prepare_runtime`])
//!
//! A harness MUST NOT sign bundles, calculate integrity, encrypt/decrypt
//! secrets, or own security policy. [`PrepareRuntimeRequest`] never carries
//! decrypted secrets.

use crate::domain::harness::HarnessId;
use crate::domain::manifest::{Launch, RuntimeRequirement};
use anyhow::Result;
use std::path::PathBuf;

/// Read-only inputs provided by the caller for a harness operation.
///
/// - `explicit_path` is the optional `--path` override.
/// - Environment variables and the home directory are readable by the
///   harness (read-only) during detection — this is how Pi resolves
///   `PI_CODING_AGENT_DIR` / `PI_HOME` / `~/.pi/agent`.
#[derive(Debug, Clone, Default)]
pub struct HarnessContext {
    pub explicit_path: Option<PathBuf>,
}

impl HarnessContext {
    pub fn new(explicit_path: Option<PathBuf>) -> Self {
        Self { explicit_path }
    }
}

/// Result of detecting an installation of a harness.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub harness_id: HarnessId,
    /// Path to the detected installation (root of the portable environment).
    pub root: PathBuf,
    /// Detected harness version string.
    pub version: String,
}

/// The kinds of portable resources a harness can describe.
///
/// - `Config` — loose configuration (Pi: agent root minus component dirs).
/// - `Memory` — session history / memory (Pi: `sessions/`).
/// - `Extensions` / `Skills` / `Themes` — package sub-directories.
/// - `SecretSource` — credential sources that must be **encrypted**, never
///   copied as plaintext. Packing is handled by Core via [`SecretFormat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableKind {
    Config,
    Memory,
    Extensions,
    Skills,
    Themes,
    SecretSource,
}

/// How a [`PortableKind::SecretSource`] component's content should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFormat {
    /// A single JSON credentials file whose top-level string fields are
    /// secrets (Pi: `auth.json`).
    AuthJsonFile,
    /// A directory of `.env`-style files (`key=value` lines).
    DotEnvDir,
    /// A directory where each file is a secret keyed by filename.
    KeyFileDir,
}

/// One portable resource discovered by a harness.
///
/// The harness describes *what* is portable and *where it should land*;
/// the Core performs the actual copy and encryption.
#[derive(Debug, Clone)]
pub struct PortableComponent {
    pub kind: PortableKind,
    /// Absolute source path in the installation (file or directory).
    pub source: PathBuf,
    /// Bundle-relative destination, e.g. `agent/config`.
    /// For [`PortableKind::SecretSource`] this is the encrypted blob
    /// location (`secrets/keys.enc`) — the Core encrypts, never copies.
    pub destination: PathBuf,
    /// When `false`, a missing source is skipped (possibly with a notice);
    /// when `true`, a missing source is an error.
    pub required: bool,
    /// Relative names to exclude when copying this component's directory
    /// tree (harness vocabulary — e.g. Pi's non-portable root names).
    pub excludes: Vec<String>,
    /// Present iff `kind == PortableKind::SecretSource`.
    pub secret_format: Option<SecretFormat>,
}

impl PortableComponent {
    pub fn dir(
        kind: PortableKind,
        source: PathBuf,
        destination: &str,
        required: bool,
        excludes: &[&str],
    ) -> Self {
        Self {
            kind,
            source,
            destination: PathBuf::from(destination),
            required,
            excludes: excludes.iter().map(|s| s.to_string()).collect(),
            secret_format: None,
        }
    }

    pub fn secret_source(source: PathBuf, format: SecretFormat) -> Self {
        Self {
            kind: PortableKind::SecretSource,
            source,
            destination: PathBuf::from("secrets/keys.enc"),
            required: false,
            excludes: Vec::new(),
            secret_format: Some(format),
        }
    }
}

/// The portable environment discovered by a harness.
#[derive(Debug, Clone)]
pub struct PortableEnvironment {
    /// Detected harness version.
    pub version: String,
    /// Root of the source installation (where `.agentpacknestignore` lives).
    pub source_root: PathBuf,
    /// The portable components that make up this environment.
    pub components: Vec<PortableComponent>,
    /// The launch specification for this environment (command, args,
    /// working directory).
    pub launch: Launch,
    /// Runtime prerequisites genuinely required by this environment
    /// (Pi requires Node.js >= 20). Enforced via [`Harness::prepare_runtime`].
    pub runtime_requirements: Vec<RuntimeRequirement>,
}

/// Input for [`Harness::prepare_runtime`]. Never carries secrets.
#[derive(Debug, Clone)]
pub struct PrepareRuntimeRequest {
    pub bundle_root: PathBuf,
    /// The manifest's structured launch specification.
    pub launch: Launch,
}

/// The fully-prepared launch returned by [`Harness::prepare_runtime`].
#[derive(Debug, Clone)]
pub struct PreparedRuntime {
    pub command: String,
    pub args: Vec<String>,
    /// Bundle-relative working directory. `None` means the bundle root.
    pub working_directory: Option<String>,
}

/// The harness abstraction.
pub trait Harness: Send + Sync {
    /// The unique identity of this harness (e.g. Pi).
    fn identity(&self) -> HarnessId;

    /// Detect an installation of this harness.
    fn detect(&self, context: &HarnessContext) -> Result<DetectionResult>;

    /// Discover the portable environment of a detected installation.
    fn discover(&self, context: &HarnessContext) -> Result<PortableEnvironment>;

    /// Prepare the runtime for execution against a bundle. This is where a
    /// harness verifies its runtime prerequisites (Pi: Node.js >= 20) and
    /// returns the final command/args/working-directory.
    fn prepare_runtime(&self, request: PrepareRuntimeRequest) -> Result<PreparedRuntime>;
}

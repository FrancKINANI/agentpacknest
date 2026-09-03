//! PiHarness — the Pi agent runtime behind the v0.2 Harness contract.
//!
//! All Pi-layout knowledge lives here (or in [`PiInstallation`] detection):
//! which directories are portable components, where packages live, which
//! files are secret sources, what the runtime needs (Node.js >= 20) and how
//! `pn run` should launch Pi. The application/domain/security layers never
//! hardcode Pi paths or the Pi runtime requirement.

use anyhow::{bail, Context, Result};
use std::process::Command;

use crate::domain::harness::HarnessId;
use crate::domain::manifest::{Launch, RuntimeRequirement};
use crate::harness::traits::{
    DetectionResult, Harness, HarnessContext, PortableComponent, PortableEnvironment, PortableKind,
    PrepareRuntimeRequest, PreparedRuntime, SecretFormat,
};

use super::detect::PiInstallation;

/// Pi harness adapter.
pub struct PiHarness;

impl PiHarness {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PiHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness for PiHarness {
    fn identity(&self) -> HarnessId {
        HarnessId::Pi
    }

    fn detect(&self, context: &HarnessContext) -> Result<DetectionResult> {
        let pi = PiInstallation::detect(context.explicit_path.clone())
            .context("failed to detect Pi installation")?;
        Ok(DetectionResult {
            harness_id: HarnessId::Pi,
            root: pi.root().to_path_buf(),
            version: pi.version().to_string(),
        })
    }

    fn discover(&self, context: &HarnessContext) -> Result<PortableEnvironment> {
        let pi = PiInstallation::detect(context.explicit_path.clone())
            .context("failed to detect Pi installation")?;
        let root = pi.root().to_path_buf();

        let mut components = vec![
            // Loose config files at the agent root (settings.json, ...).
            // Component directories are excluded — they are handled by their
            // own components and must not be nested inside agent/config.
            PortableComponent::dir(
                PortableKind::Config,
                root.clone(),
                "agent/config",
                true,
                &[
                    "sessions",
                    "skills",
                    "themes",
                    "extensions",
                    "packages",
                    "prompts",
                    "npm",
                    "git",
                    "secrets",
                ],
            ),
            // Session history = memory.
            PortableComponent::dir(
                PortableKind::Memory,
                root.join("sessions"),
                "agent/memory",
                false,
                &[],
            ),
            // Packages: each kind is a sub-directory of `packages/`.
            PortableComponent::dir(
                PortableKind::Extensions,
                root.join("packages").join("extensions"),
                "agent/packages/extensions",
                false,
                &[],
            ),
            PortableComponent::dir(
                PortableKind::Skills,
                root.join("packages").join("skills"),
                "agent/packages/skills",
                false,
                &[],
            ),
            PortableComponent::dir(
                PortableKind::Themes,
                root.join("packages").join("themes"),
                "agent/packages/themes",
                false,
                &[],
            ),
            // Secret sources — Core encrypts these into secrets/keys.enc;
            // they are never copied as plaintext. Scan order matters for
            // duplicate keys (later sources win), matching pack v0.1.x.
            PortableComponent::secret_source(root.join("auth.json"), SecretFormat::AuthJsonFile),
            PortableComponent::secret_source(root.join("secrets"), SecretFormat::KeyFileDir),
            PortableComponent::secret_source(root.clone(), SecretFormat::DotEnvDir),
            PortableComponent::secret_source(root.join("config"), SecretFormat::DotEnvDir),
        ];

        // Secret sources are optional: missing files/dirs are skipped by the
        // scanners, so a bare installation still packs cleanly.
        for c in &mut components {
            if c.kind == PortableKind::SecretSource {
                c.required = false;
            }
        }

        let version = pi.version().to_string();

        Ok(PortableEnvironment {
            version: version.clone(),
            source_root: root,
            components,
            launch: Launch {
                command: "pi".to_string(),
                args: vec!["--agent-dir".to_string(), "agent".to_string()],
                working_directory: Some(".".to_string()),
            },
            // Pi runs on Node.js >= 20; enforced in prepare_runtime.
            runtime_requirements: vec![RuntimeRequirement {
                name: "node".to_string(),
                min_version: "20".to_string(),
            }],
        })
    }

    fn prepare_runtime(&self, request: PrepareRuntimeRequest) -> Result<PreparedRuntime> {
        // Pi requires Node.js >= 20 to run. This is a harness-owned runtime
        // requirement: `--allow-unverified` must NOT bypass it (runtime
        // compatibility is structural, not trust).
        check_node_version(20)?;

        let (command, args) = resolve_launch(&request.launch.command, &request.launch.args)?;

        Ok(PreparedRuntime {
            command,
            args,
            working_directory: request.launch.working_directory.clone(),
        })
    }
}

/// Resolve a manifest launch spec into a structurally separated
/// `(executable, args)` pair — never a shell-parsed command line.
///
/// Canonical (current) manifests carry a bare executable in
/// `launch.command` and a structured `launch.args` vector; those boundaries
/// are preserved exactly, including arguments that contain spaces.
///
/// Legacy (schema 0.1) manifests predate `launch.args` and may embed
/// arguments in the command string. That representation is lossy — it
/// cannot express quoted arguments — so it is handled by an explicit,
/// isolated tokenizer that refuses to guess when the string cannot be
/// interpreted faithfully. No shell semantics (quoting, escapes) are ever
/// applied.
fn resolve_launch(command: &str, args: &[String]) -> Result<(String, Vec<String>)> {
    // Whitespace separates the executable from any embedded (legacy) args.
    // This tokenization is purely structural — no shell semantics (quoting,
    // escapes) are ever applied.
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // ── Canonical: structured args present ─────────────────────────
    if !args.is_empty() {
        if tokens.len() > 1 {
            bail!(
                "launch.command contains embedded arguments while launch.args is also set:\n  \
                 command: '{}'\n  \
                 hint: put the executable in launch.command and its arguments in launch.args\n  \
                 (re-run `pn pack` or edit manifest.yaml)",
                command
            );
        }
        let executable = tokens.first().map(|s| s.to_string()).unwrap_or_default();
        // The structured argument vector is preserved exactly — including
        // arguments that contain spaces.
        return Ok((executable, args.to_vec()));
    }

    // ── No structured args ─────────────────────────────────────────
    match tokens.len() {
        0 => bail!(
            "launch.command contains no executable: '{}'\n  hint: set launch.command in manifest.yaml",
            command
        ),
        // Bare executable.
        1 => Ok((tokens[0].to_string(), Vec::new())),
        // Legacy (schema 0.1): args embedded in the command string. This
        // form cannot express quoted arguments — failing clearly beats
        // silently mis-splitting them.
        _ => {
            for token in &tokens {
                if token.contains('"') || token.contains('\'') {
                    bail!(
                        "cannot safely interpret legacy launch.command containing quoted argument '{}':\n  \
                         the legacy (schema 0.1) command string cannot express argument boundaries\n  \
                         hint: re-run `pn pack` to write structured launch.args, or edit manifest.yaml",
                        token
                    );
                }
            }
            Ok((
                tokens[0].to_string(),
                tokens[1..].iter().map(|s| s.to_string()).collect(),
            ))
        }
    }
}

/// Check that a command is available and meets a minimum major version.
/// For Pi this is `node >= 20`.
fn check_node_version(min_major: u32) -> Result<()> {
    let output = Command::new("node").arg("--version").output().context(
        "Node.js is not installed or not in PATH\n  \
             Pi requires Node.js >= 20\n  \
             install: https://nodejs.org/ or use `nvm install 20`",
    )?;

    if !output.status.success() {
        bail!(
            "failed to run `node --version`\n  \
             Pi requires Node.js >= 20\n  \
             install: https://nodejs.org/"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_str = stdout.trim().trim_start_matches('v');

    let parts: Vec<&str> = version_str.split('.').collect();
    let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);

    if major < min_major {
        bail!(
            "Node.js v{} detected, but Pi requires >= v{}.0\n  \
             upgrade: https://nodejs.org/ or `nvm install {}`",
            version_str,
            min_major,
            min_major
        );
    }

    println!("Node.js:   v{} ✓", version_str);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Create a full fake Pi agent directory.
    fn setup_full_agent_dir(dir: &Path) {
        fs::write(dir.join("settings.json"), "{}").unwrap();
        fs::write(dir.join("auth.json"), r#"{"anthropicApiKey":"sk-test"}"#).unwrap();
        fs::create_dir_all(dir.join("sessions")).unwrap();
        fs::create_dir_all(dir.join("packages/extensions/ext-a")).unwrap();
        fs::create_dir_all(dir.join("packages/skills/coding")).unwrap();
        fs::create_dir_all(dir.join("packages/themes/dark")).unwrap();
    }

    fn context_for(dir: &Path) -> HarnessContext {
        HarnessContext::new(Some(dir.to_path_buf()))
    }

    #[test]
    fn discover_describes_pi_environment() {
        let dir = TempDir::new().unwrap();
        setup_full_agent_dir(dir.path());

        let harness = PiHarness::new();
        let env = harness.discover(&context_for(dir.path())).unwrap();

        assert_eq!(env.version, "unknown"); // no VERSION file in fixture
        assert_eq!(env.source_root, dir.path());
        assert_eq!(env.launch.command, "pi");

        // Components cover config, memory, the three package kinds, and the
        // Pi secret sources — with correct bundle destinations.
        let kinds: Vec<PortableKind> = env.components.iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&PortableKind::Config));
        assert!(kinds.contains(&PortableKind::Memory));
        assert!(kinds.contains(&PortableKind::Extensions));
        assert!(kinds.contains(&PortableKind::Skills));
        assert!(kinds.contains(&PortableKind::Themes));

        let config = env
            .components
            .iter()
            .find(|c| c.kind == PortableKind::Config)
            .unwrap();
        assert_eq!(config.destination, PathBuf::from("agent/config"));
        assert!(config.excludes.contains(&"sessions".to_string()));

        let skills = env
            .components
            .iter()
            .find(|c| c.kind == PortableKind::Skills)
            .unwrap();
        assert_eq!(skills.source, dir.path().join("packages/skills"));
        assert_eq!(skills.destination, PathBuf::from("agent/packages/skills"));

        let secrets: Vec<_> = env
            .components
            .iter()
            .filter(|c| c.kind == PortableKind::SecretSource)
            .collect();
        assert_eq!(secrets.len(), 4);
        // auth.json is a single-file JSON credential source.
        assert_eq!(secrets[0].secret_format, Some(SecretFormat::AuthJsonFile));
        assert_eq!(secrets[0].source, dir.path().join("auth.json"));
        // All secret sources target the encrypted blob.
        assert!(secrets
            .iter()
            .all(|c| c.destination.as_os_str() == "secrets/keys.enc"));

        // Pi genuinely requires Node >= 20.
        assert_eq!(env.runtime_requirements.len(), 1);
        assert_eq!(env.runtime_requirements[0].name, "node");
    }

    #[test]
    fn discover_fails_on_invalid_path() {
        let harness = PiHarness::new();
        let ctx = HarnessContext::new(Some(PathBuf::from("/nonexistent")));
        assert!(harness.discover(&ctx).is_err());
    }

    // ── resolve_launch: structured args are preserved exactly ──────

    #[test]
    fn structured_args_preserved_exactly() {
        let args = vec![
            "--agent-dir".to_string(),
            "agent".to_string(),
            "--name".to_string(),
            "hello world".to_string(),
        ];
        let (command, out_args) = resolve_launch("pi", &args).unwrap();
        assert_eq!(command, "pi");
        // Argument boundaries must survive unchanged — including the space
        // inside "hello world" (still one argument).
        assert_eq!(out_args, args);
    }

    #[test]
    fn args_with_spaces_remain_one_argument() {
        let args = vec!["--message".to_string(), "two words here".to_string()];
        let (_, out_args) = resolve_launch("pi", &args).unwrap();
        assert_eq!(out_args.len(), 2);
        assert_eq!(out_args[1], "two words here");
    }

    #[test]
    fn bare_executable_without_args() {
        let (command, args) = resolve_launch("pi", &[]).unwrap();
        assert_eq!(command, "pi");
        assert!(args.is_empty());
    }

    #[test]
    fn structured_args_with_embedded_command_rejected() {
        let err = resolve_launch("pi --agent-dir agent", &["--agent-dir".to_string()])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("launch.command contains embedded arguments"),
            "{}",
            err
        );
    }

    // ── resolve_launch: isolated legacy (schema 0.1) tokenization ──

    #[test]
    fn legacy_clean_tokens_split_into_executable_and_args() {
        let (command, args) = resolve_launch("pi --agent-dir agent", &[]).unwrap();
        assert_eq!(command, "pi");
        assert_eq!(args, vec!["--agent-dir".to_string(), "agent".to_string()]);
    }

    #[test]
    fn legacy_quoted_argument_fails_clearly() {
        let err = resolve_launch("pi --name \"hello world\"", &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot safely interpret") && err.contains("re-run `pn pack`"),
            "legacy quotes must fail clearly, got: {}",
            err
        );
    }

    #[test]
    fn legacy_whitespace_only_command_fails_clearly() {
        let err = resolve_launch("   ", &[]).unwrap_err().to_string();
        assert!(err.contains("no executable"), "{}", err);
    }

    use std::path::Path;
    use std::path::PathBuf;
}

//! PackBundle — orchestrate packing a bundle from a harness installation.
//!
//! The application layer owns the *pack sequence*; the harness owns the
//! *vocabulary*. Pi-specific knowledge (which dirs are components, where
//! packages live, what the secret sources are) comes from
//! [`PortableEnvironment`] returned by the harness — never hardcoded here.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::domain::manifest;
use crate::harness::registry::HarnessRegistry;
use crate::harness::traits::{
    HarnessContext, PortableComponent, PortableEnvironment, PortableKind, SecretFormat,
};
use crate::infrastructure::ignore::IgnorePatterns;
use crate::security::crypto;
use crate::security::integrity;
use crate::security::secrets::SecretsBundle;
use crate::security::signing;

#[derive(Debug)]
pub struct PackBundleRequest {
    pub bundle_path: PathBuf,
    pub harness_path: Option<PathBuf>,
    pub with_config: bool,
    pub with_memory: bool,
    pub with_skills: bool,
    pub with_secrets: bool,
    pub force: bool,
}

#[derive(Debug)]
pub struct PackBundleResult {
    pub manifest: manifest::Manifest,
    pub checksum: String,
}

/// Orchestrate: discover → stage → encrypt → integrity → manifest → sign → validate
pub fn execute(request: PackBundleRequest) -> Result<PackBundleResult> {
    // ── 1. Resolve bundle directory ────────────────────────────────
    let bundle_dir = &request.bundle_path;

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "not a valid agentpacknest bundle: no manifest.yaml in {}\n  hint: run `pn init` first",
            bundle_dir.display()
        );
    }

    // ── 2. Load and validate manifest ──────────────────────────────
    let mut m = manifest::load(&manifest_path).context("failed to load manifest")?;

    // ── 3. Resolve the harness from the manifest via the registry ──
    let registry = HarnessRegistry::with_defaults();
    let harness = registry.by_name(&m.harness.name)?;

    let context = HarnessContext::new(request.harness_path.clone());

    println!("Bundle:     {}", m.bundle.name);
    println!("Harness:    {} v{}", m.harness.name, m.harness.version);

    // ── 4. Discover the portable environment ──────────────────────
    let env = harness
        .discover(&context)
        .context("failed to discover harness environment")?;

    println!("Source:     {}", env.source_root.display());
    println!();

    // ── 4b. Validate every declared destination ────────────────────
    // Core safety policy: destinations are bundle-relative paths that must
    // stay inside the bundle. Absolute paths and parent traversal (`..`)
    // are rejected before anything is copied — a misbehaving harness can
    // describe resources, but it can never direct the copy outside the
    // bundle root.
    for component in &env.components {
        validate_component_destination(&component.destination)?;
    }

    // ── 5. Load ignore patterns ────────────────────────────────────
    let ignore = IgnorePatterns::load(&env.source_root);
    if !ignore.is_empty() {
        println!(
            "Ignore:     {} pattern(s) from .agentpacknestignore",
            ignore.len()
        );
        println!();
    }

    // ── 6. Copy components selected by flags ───────────────────────
    let mut secrets_written = false;

    if request.with_config {
        copy_kind(
            &env,
            PortableKind::Config,
            bundle_dir,
            request.force,
            &ignore,
        )?;
    }
    if request.with_memory {
        copy_kind(
            &env,
            PortableKind::Memory,
            bundle_dir,
            request.force,
            &ignore,
        )?;
    }
    if request.with_skills {
        for kind in [
            PortableKind::Extensions,
            PortableKind::Skills,
            PortableKind::Themes,
        ] {
            copy_kind(&env, kind, bundle_dir, request.force, &ignore)?;
        }
    }
    if request.with_secrets {
        secrets_written = pack_secrets(&env, bundle_dir, request.force)?;
    }

    // ── 7. Update manifest contents ────────────────────────────────
    m.contents.config = request.with_config;
    m.contents.memory = request.with_memory;
    m.contents.skills = request.with_skills;
    m.contents.secrets = request.with_secrets;

    if request.with_skills {
        m.packages = scan_packages_from_bundle(bundle_dir);
    }

    if secrets_written {
        m.security.secrets_encrypted = true;
        m.security.encryption = Some(crypto::CRYPTO_FORMAT_IDENTIFIER.to_string());
    }

    // ── 8. Compute integrity checksum ──────────────────────────────
    let checksum = integrity::compute_bundle_checksum(bundle_dir)?;
    m.integrity.checksum = Some(checksum.clone());
    m.integrity.format_version = integrity::INTEGRITY_FORMAT_VERSION;

    // Ensure crypto format version is set
    if m.crypto.is_none() {
        m.crypto = Some(manifest::CryptoMeta {
            format_version: crypto::CRYPTO_FORMAT_VERSION,
        });
    } else if let Some(ref mut crypto_meta) = m.crypto {
        crypto_meta.format_version = crypto::CRYPTO_FORMAT_VERSION;
    }

    // Ensure compatibility is set
    if m.compatibility.is_none() {
        m.compatibility = Some(manifest::Compatibility {
            min_agentpacknest_version: "0.1.0".to_string(),
        });
    }

    // Set origin metadata
    m.origin = Some(manifest::OriginMeta {
        origin_machine: manifest::hostname(),
        packed_at: manifest::now_iso8601(),
        source_state_hash: None, // TODO: compute source state hash
    });

    // ── 9. Save manifest ───────────────────────────────────────────
    manifest::save(&manifest_path, &m).context("failed to save updated manifest")?;

    println!();
    println!("  ✓ manifest.yaml updated (checksum: {})", &checksum[..16]);

    // ── 10. Sign the manifest ──────────────────────────────────────
    let signature = signing::sign_canonical_manifest(&m)
        .context("failed to sign manifest — is your keypair set up?")?;

    let sig_path = bundle_dir.join("manifest.sig");
    signing::save_signature(&sig_path, &signature).context("failed to save signature")?;

    // Save public key for portable verification
    signing::save_public_key(bundle_dir).context("failed to save public key")?;

    println!("  ✓ manifest signed");

    // ── 11. Validate the completed bundle ──────────────────────────
    // Re-verify checksum
    let reverify = integrity::verify_checksum(bundle_dir, &checksum)
        .context("post-pack integrity verification failed")?;
    if !reverify {
        bail!("post-pack integrity check failed — bundle may be corrupted");
    }

    // Re-verify signature
    let sig_reverify = signing::verify_manifest_with_bundled_pubkey(
        &m,
        &sig_path,
        &bundle_dir.join("signing/public.key"),
    )
    .context("post-pack signature verification failed")?;
    if !sig_reverify {
        bail!("post-pack signature check failed — bundle may be corrupted");
    }

    println!("  ✓ bundle validated");

    // ── Summary ────────────────────────────────────────────────────
    println!();
    println!("Pack complete!");
    println!(
        "  Contents:  config={}  memory={}  skills={}  secrets={}",
        flag(request.with_config),
        flag(request.with_memory),
        flag(request.with_skills),
        flag(request.with_secrets)
    );
    println!("  Bundle:    {}/", bundle_dir.display());
    println!();

    Ok(PackBundleResult {
        manifest: m,
        checksum,
    })
}

// ---------------------------------------------------------------------------
// Component-driven copy
// ---------------------------------------------------------------------------

/// Copy every component of the given kind that the harness discovered.
fn copy_kind(
    env: &PortableEnvironment,
    kind: PortableKind,
    bundle_dir: &Path,
    force: bool,
    ignore: &IgnorePatterns,
) -> Result<()> {
    for component in env.components.iter().filter(|c| c.kind == kind) {
        copy_component(component, bundle_dir, force, ignore)?;
    }
    Ok(())
}

/// Copy a single portable directory component into the bundle.
///
/// Core policy (independent of the harness):
/// - Secret-source files (`auth.json`, `secrets.json`, `.env`, `env`, `*.env`)
///   are NEVER copied as plaintext — the harness declares them separately and
///   Core encrypts them instead.
/// - Symlinks are rejected (they could point outside the source tree).
/// - Ignore patterns from `.agentpacknestignore` are respected.
///
/// Harness vocabulary (comes from `component.excludes`):
/// - non-portable sub-directory names inside the component's tree.
fn copy_component(
    component: &PortableComponent,
    bundle_dir: &Path,
    force: bool,
    ignore: &IgnorePatterns,
) -> Result<()> {
    let src = &component.source;
    if !src.is_dir() {
        if component.required {
            bail!(
                "required component '{}' is missing: {}\n  hint: check the harness installation",
                component.destination.display(),
                src.display()
            );
        }
        println!(
            "  ⚠ {} not found in harness installation, skipping",
            component.destination.display()
        );
        return Ok(());
    }

    let dst = bundle_dir.join(&component.destination);
    if dst.exists() && !force {
        bail!(
            "destination already exists: {}\n  use --force to overwrite",
            dst.display()
        );
    }

    let mut count = 0u64;
    let mut skipped = 0u64;
    let walker = walkdir::WalkDir::new(src)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok());
    for entry in walker {
        // Reject symlinks — could point outside bundle
        if entry.file_type().is_symlink() {
            bail!(
                "symlink not allowed in bundle: {}\n  hint: remove the symlink from the source",
                entry.path().display()
            );
        }

        let rel = entry.path().strip_prefix(src).unwrap();
        let rel_str = rel.to_string_lossy();

        // Skip any path segment that is a non-portable (excluded) name.
        // Directory components whose dir-name appears deeper in the tree are
        // also excluded — the walker is not pruned, so nested files under an
        // excluded dir are individually skipped.
        if is_excluded_path(&rel_str, &component.excludes) {
            skipped += 1;
            continue;
        }

        // Check ignore patterns
        if !ignore.is_empty() && ignore.is_ignored(&rel_str) {
            skipped += 1;
            continue;
        }

        let target = dst.join(rel);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
            count += 1;
        }
    }

    if skipped > 0 {
        println!(
            "  ✓ {} copied ({} files, {} excluded/ignored)",
            component.destination.display(),
            count,
            skipped
        );
    } else {
        println!(
            "  ✓ {} copied ({} files)",
            component.destination.display(),
            count
        );
    }
    Ok(())
}

/// True when any segment of the relative path is an excluded name, or the
/// path's final name is a secret-source file that must never be copied as
/// plaintext (Core security policy: `auth.json`, `secrets.json`, `.env`,
/// `env`, `*.env`).
fn is_excluded_path(rel: &str, excluded: &[String]) -> bool {
    let segments: Vec<&str> = rel.split('/').collect();
    let filename = segments.last().copied().unwrap_or("");

    // Excluded component names match any segment (dir or file name).
    if segments.iter().any(|seg| excluded.iter().any(|e| e == seg)) {
        return true;
    }

    // Secret-source file names are excluded at the file level only.
    is_secret_source_file(filename)
}

/// Validate a harness-declared bundle destination before anything is copied.
///
/// Core policy: destinations are bundle-relative paths inside the bundle.
/// Rejected: empty paths, absolute paths (including Windows prefixes like
/// `C:`), root paths, and any `..` (parent traversal) segment.
fn validate_component_destination(dest: &Path) -> Result<()> {
    use std::path::Component;

    if dest.as_os_str().is_empty() {
        bail!("component destination is empty — harness bug");
    }
    if dest.is_absolute() {
        bail!(
            "component destination must be bundle-relative, got absolute path '{}'\n  \
             hint: this is a harness bug — report it",
            dest.display()
        );
    }
    for component in dest.components() {
        match component {
            Component::ParentDir => bail!(
                "component destination escapes the bundle (contains '..'): '{}'\n  \
                 hint: this is a harness bug — report it",
                dest.display()
            ),
            Component::Prefix(_) | Component::RootDir => bail!(
                "component destination must be bundle-relative, got '{}'\n  \
                 hint: this is a harness bug — report it",
                dest.display()
            ),
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    Ok(())
}

/// True when a filename is a secret-source file that must never be copied
/// as plaintext. This is Core policy, applied to every plaintext copy.
fn is_secret_source_file(filename: &str) -> bool {
    filename == ".env"
        || filename == "env"
        || filename.ends_with(".env")
        || filename == "auth.json"
        || filename == "secrets.json"
}

#[cfg(test)]
mod exclusion_tests {
    use super::*;

    #[test]
    fn excluded_dir_names_match_any_segment() {
        let excluded = vec!["sessions".to_string(), "packages".to_string()];
        assert!(is_excluded_path("sessions", &excluded));
        assert!(is_excluded_path("sessions/2025-01-15.jsonl", &excluded));
        assert!(is_excluded_path("deep/nested/packages/x", &excluded));
        assert!(!is_excluded_path("settings.json", &excluded));
        assert!(!is_excluded_path("skills/coding/prompt.md", &excluded));
    }

    #[test]
    fn secret_source_files_always_excluded() {
        let excluded: Vec<String> = Vec::new();
        assert!(is_excluded_path("auth.json", &excluded));
        assert!(is_excluded_path(".env", &excluded));
        assert!(is_excluded_path("prod.env", &excluded));
        assert!(is_excluded_path("nested/secrets.json", &excluded));
        assert!(!is_excluded_path("settings.json", &excluded));
        assert!(!is_excluded_path("prompt.md", &excluded));
    }
}

// ---------------------------------------------------------------------------
// Secrets (Core-owned encryption of harness-declared SecretSource components)
// ---------------------------------------------------------------------------

/// Collect secrets from every [`PortableKind::SecretSource`] component the
/// harness described, encrypt them, and write them to `secrets/keys.enc`.
///
/// Returns `true` when an encrypted file was actually written.
fn pack_secrets(env: &PortableEnvironment, bundle_dir: &Path, force: bool) -> Result<bool> {
    let secrets_dst = bundle_dir.join("secrets/keys.enc");

    if secrets_dst.exists() && !force {
        bail!("secrets/keys.enc already exists\n  use --force to overwrite");
    }

    // ── Collect secrets ────────────────────────────────────────────
    let mut bundle = SecretsBundle::new();

    for component in env
        .components
        .iter()
        .filter(|c| c.kind == PortableKind::SecretSource)
    {
        let format = component
            .secret_format
            .expect("SecretSource component without a SecretFormat — harness bug");
        match format {
            SecretFormat::AuthJsonFile => {
                bundle.scan_auth_json(&component.source)?;
            }
            SecretFormat::DotEnvDir => {
                bundle.scan_env_files(&component.source)?;
            }
            SecretFormat::KeyFileDir => {
                bundle.scan_secret_files(&component.source)?;
            }
        }
    }

    if bundle.is_empty() {
        println!("  ⚠ no secrets found in harness installation, skipping");
        return Ok(false);
    }

    println!(
        "  Found {} secret(s): {}",
        bundle.len(),
        bundle.keys().join(", ")
    );

    // ── Prompt for passphrase ──────────────────────────────────────
    let passphrase = crypto::prompt_passphrase_confirm()?;

    // ── Encrypt and write ──────────────────────────────────────────
    if let Some(parent) = secrets_dst.parent() {
        fs::create_dir_all(parent)?;
    }

    bundle
        .save_encrypted(&secrets_dst, &passphrase)
        .context("failed to encrypt and save secrets")?;

    let file_size = fs::metadata(&secrets_dst).map(|m| m.len()).unwrap_or(0);

    println!(
        "  ✓ secrets encrypted → secrets/keys.enc ({} bytes)",
        file_size
    );
    Ok(true)
}

// ---------------------------------------------------------------------------
// Manifest package listing (Core reads back what was copied)
// ---------------------------------------------------------------------------

/// Build the manifest `packages` section from what actually landed in the
/// bundle under `agent/packages/{extensions,skills,themes}`.
fn scan_packages_from_bundle(bundle_dir: &Path) -> manifest::Packages {
    let base = bundle_dir.join("agent/packages");
    let read = |sub: &str| -> Vec<manifest::PackageEntry> {
        let dir = base.join(sub);
        let mut entries = Vec::new();
        if let Ok(rd) = fs::read_dir(&dir) {
            for entry in rd.filter_map(|e| e.ok()) {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    entries.push(manifest::PackageEntry {
                        name: entry.file_name().to_string_lossy().into_owned(),
                        version: "0.0.0".to_string(),
                        source: None,
                        path: None,
                    });
                }
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    };

    manifest::Packages {
        extensions: read("extensions"),
        skills: read("skills"),
        themes: read("themes"),
    }
}

fn flag(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Ensure a signing keypair exists (create it on first use).
    fn ensure_keypair() {
        if signing::load_verifying_key().is_err() {
            // Ignore "already exists" races between parallel tests.
            let _ = signing::generate_keypair();
        }
    }

    /// Build a fake Pi agent directory matching the harness layout.
    fn fake_pi(dir: &Path) {
        fs::create_dir_all(dir.join("sessions")).unwrap();
        fs::create_dir_all(dir.join("packages/skills/coding")).unwrap();
        fs::create_dir_all(dir.join("extensions")).unwrap();
        fs::write(dir.join("settings.json"), "{\"version\": \"0.5.0\"}").unwrap();
        fs::write(
            dir.join("auth.json"),
            "{\"anthropicApiKey\": \"sk-super-secret-value\"}",
        )
        .unwrap();
        fs::write(dir.join("sessions/2025-01-15.jsonl"), "{}").unwrap();
        fs::write(
            dir.join("packages/skills/coding/prompt.md"),
            "# coding skill",
        )
        .unwrap();
    }

    /// Initialize an empty bundle directory with a default manifest.
    fn init_bundle(dir: &Path, name: &str) {
        let m = manifest::default_pi(name, "0.5.0");
        let manifest_path = dir.join("manifest.yaml");
        manifest::save(&manifest_path, &m).unwrap();
    }

    fn run_pack(bundle: &Path, pi: &Path, flags: Vec<(&str, bool)>) -> PackBundleResult {
        ensure_keypair();
        let request = PackBundleRequest {
            bundle_path: bundle.to_path_buf(),
            harness_path: Some(pi.to_path_buf()),
            with_config: flags.iter().any(|(f, _)| *f == "config"),
            with_memory: flags.iter().any(|(f, _)| *f == "memory"),
            with_skills: flags.iter().any(|(f, _)| *f == "skills"),
            with_secrets: flags.iter().any(|(f, _)| *f == "secrets"),
            force: true,
        };
        execute(request).unwrap()
    }

    fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for entry in walkdir::WalkDir::new(dir) {
            let entry = entry.unwrap();
            if entry.file_type().is_file() {
                out.push(entry.path().to_path_buf());
            }
        }
        out
    }

    #[test]
    fn pack_config_excludes_secret_sources() {
        let pi_dir = TempDir::new().unwrap();
        fake_pi(pi_dir.path());
        let bundle_dir = TempDir::new().unwrap();
        init_bundle(bundle_dir.path(), "cfg-agent");

        run_pack(bundle_dir.path(), pi_dir.path(), vec![("config", true)]);

        // Loose config file copied
        assert!(bundle_dir
            .path()
            .join("agent/config/settings.json")
            .is_file());

        // Secret sources must NOT exist anywhere in the bundle as plaintext
        for f in files_under(bundle_dir.path()) {
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            assert_ne!(
                name,
                "auth.json",
                "auth.json leaked into bundle: {}",
                f.display()
            );
            assert!(
                !name.ends_with(".env"),
                "env file leaked into bundle: {}",
                f.display()
            );
        }

        // Component directories are not nested inside config/
        assert!(!bundle_dir.path().join("agent/config/sessions").exists());
        assert!(!bundle_dir.path().join("agent/config/packages").exists());

        // And the secret VALUE never appears in any packed file
        let contents: String = files_under(bundle_dir.path())
            .iter()
            .map(|f| fs::read_to_string(f).unwrap_or_default())
            .collect();
        assert!(
            !contents.contains("sk-super-secret-value"),
            "plaintext secret value leaked into bundle payload"
        );
    }

    #[test]
    fn pack_with_skills_copies_packages_only() {
        let pi_dir = TempDir::new().unwrap();
        fake_pi(pi_dir.path());
        let bundle_dir = TempDir::new().unwrap();
        init_bundle(bundle_dir.path(), "skill-agent");

        run_pack(bundle_dir.path(), pi_dir.path(), vec![("skills", true)]);

        assert!(bundle_dir
            .path()
            .join("agent/packages/skills/coding/prompt.md")
            .is_file());
        assert!(!bundle_dir.path().join("agent/config").exists());
        assert!(!bundle_dir.path().join("agent/packages/auth.json").exists());
    }

    #[test]
    fn destination_validation_rejects_absolute_paths() {
        // On Unix a leading `/` is absolute; on Windows a drive prefix is.
        let bad_paths: Vec<&str> = {
            #[cfg(windows)]
            {
                vec!["/etc/passwd", "/agent/config", "C:\\evil"]
            }
            #[cfg(not(windows))]
            {
                vec!["/etc/passwd", "/agent/config"]
            }
        };
        for bad in bad_paths {
            let err = validate_component_destination(Path::new(bad))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("must be bundle-relative"),
                "{} should be rejected as absolute: {}",
                bad,
                err
            );
        }
    }

    #[test]
    fn destination_validation_rejects_parent_traversal() {
        for bad in ["../escape", "agent/../../outside", "a/../.."] {
            let err = validate_component_destination(Path::new(bad))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("escapes the bundle"),
                "{} should be rejected as traversal: {}",
                bad,
                err
            );
        }
    }

    #[test]
    fn destination_validation_rejects_empty() {
        let err = validate_component_destination(Path::new(""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("destination is empty"), "{}", err);
    }

    #[test]
    fn destination_validation_accepts_bundle_relative_paths() {
        for good in [
            "agent/config",
            "agent/memory",
            "agent/packages/skills",
            "secrets/keys.enc",
        ] {
            assert!(
                validate_component_destination(Path::new(good)).is_ok(),
                "{} should be accepted",
                good
            );
        }
    }

    #[test]
    fn discovered_pi_components_have_valid_destinations() {
        // Every destination the Pi harness declares must pass Core validation.
        let pi_dir = TempDir::new().unwrap();
        fake_pi(pi_dir.path());

        let registry = HarnessRegistry::with_defaults();
        let ctx = HarnessContext::new(Some(pi_dir.path().to_path_buf()));
        let env = registry
            .discover(crate::domain::harness::HarnessId::Pi, &ctx)
            .unwrap();

        assert!(!env.components.is_empty());
        for component in &env.components {
            validate_component_destination(&component.destination).unwrap_or_else(|e| {
                panic!(
                    "invalid destination {}: {}",
                    component.destination.display(),
                    e
                )
            });
        }
    }

    #[test]
    fn pack_sets_formats_and_signs_valid_bundle() {
        let pi_dir = TempDir::new().unwrap();
        fake_pi(pi_dir.path());
        let bundle_dir = TempDir::new().unwrap();
        init_bundle(bundle_dir.path(), "sign-agent");

        let result = run_pack(
            bundle_dir.path(),
            pi_dir.path(),
            vec![("config", true), ("skills", true)],
        );

        // Format versions are recorded in the manifest
        assert_eq!(result.manifest.integrity.format_version, 1);
        assert_eq!(
            result.manifest.crypto.as_ref().unwrap().format_version,
            crypto::CRYPTO_FORMAT_VERSION
        );
        assert_eq!(
            result.manifest.integrity.checksum.as_deref(),
            Some(result.checksum.as_str())
        );

        // Integrity verifies
        assert!(integrity::verify_checksum(bundle_dir.path(), &result.checksum).unwrap());

        // Signature verifies with the bundled public key (portable)
        let sig_path = bundle_dir.path().join("manifest.sig");
        let pubkey_path = bundle_dir.path().join("signing/public.key");
        assert!(sig_path.is_file());
        assert!(pubkey_path.is_file());
        let manifest = manifest::load(&bundle_dir.path().join("manifest.yaml")).unwrap();
        let verified =
            signing::verify_manifest_with_bundled_pubkey(&manifest, &sig_path, &pubkey_path)
                .unwrap();
        assert!(verified);
    }
}

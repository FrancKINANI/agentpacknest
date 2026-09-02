use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::manifest;
use crate::harness::pi::detect::PiInstallation;
use crate::harness::types::HarnessAdapter;
use crate::security::crypto;
use crate::security::signing;

/// Execute `hh pack`.
pub fn execute(
    bundle_path: Option<String>,
    pi_path: Option<String>,
    with_config: bool,
    with_memory: bool,
    with_skills: bool,
    with_secrets: bool,
    all: bool,
    archive: bool,
    force: bool,
) -> Result<()> {
    // ── Resolve flags (--all expands) ──────────────────────────────
    let do_config = all || with_config;
    let do_memory = all || with_memory;
    let do_skills = all || with_skills;
    let do_secrets = all || with_secrets;

    if !do_config && !do_memory && !do_skills && !do_secrets && !archive {
        bail!(
            "nothing to pack — no content flags specified\n  hint: use --all to include everything, or pick one or more of:\n    --with-config   configuration files\n    --with-memory   session history\n    --with-skills   extensions, skills, themes\n    --with-secrets  encrypted secrets"
        );
    }

    // ── 1. Resolve bundle directory ────────────────────────────────
    let bundle_dir = match bundle_path {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir().context("failed to get current directory")?,
    };

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "not a valid hitchhike bundle: no manifest.yaml in {}\n  hint: run `hh init` first",
            bundle_dir.display()
        );
    }

    // ── 2. Load and validate manifest ──────────────────────────────
    let mut m = manifest::load(&manifest_path)
        .context("failed to load manifest")?;

    if m.harness.name != "pi" {
        bail!(
            "unsupported harness in manifest: `{}`\n  only 'pi' is supported in hh v0.1\n  hint: this bundle was created for a different harness",
            m.harness.name
        );
    }

    println!("Bundle:     {}", m.bundle.name);
    println!("Harness:    pi v{}", m.harness.version);

    // ── 3. Detect Pi installation ──────────────────────────────────
    let pi_detect_path = pi_path.as_ref().map(PathBuf::from);
    let pi = PiInstallation::detect(pi_detect_path)
        .context("failed to detect Pi installation")?;

    println!("Pi source:  {}", pi.root().display());
    println!();

    // ── 4. Copy files ──────────────────────────────────────────────
    if do_config {
        copy_dir_recursive(
            &pi.config_path(),
            &bundle_dir.join("agent/config"),
            force,
            "config",
        )?;
    }

    if do_memory {
        copy_dir_recursive(
            &pi.memory_path(),
            &bundle_dir.join("agent/memory"),
            force,
            "memory",
        )?;
    }

    if do_skills {
        copy_packages(&pi, &bundle_dir, force)?;
    }

    if do_secrets {
        copy_secrets_encrypted(&pi, &bundle_dir, force)?;
    }

    // ── 5. Update manifest ─────────────────────────────────────────
    m.contents.config = do_config;
    m.contents.memory = do_memory;
    m.contents.skills = do_skills;
    m.contents.secrets = do_secrets;

    if do_skills {
        m.packages = scan_packages(&pi);
    }

    if do_secrets {
        m.security.secrets_encrypted = true;
        m.security.encryption = Some("aes-256-gcm/argon2".to_string());
    }

    // Compute integrity checksum (sha256 of all bundle files except secrets/)
    let checksum = compute_bundle_checksum(&bundle_dir)?;
    m.integrity.checksum = Some(checksum.clone());

    manifest::save(&manifest_path, &m)
        .context("failed to save updated manifest")?;

    println!();
    println!("  ✓ manifest.yaml updated (checksum: {})", &checksum[..16]);

    // ── 6. Sign the manifest ───────────────────────────────────────
    match sign_manifest(&m, &bundle_dir) {
        Ok(()) => println!("  ✓ manifest signed"),
        Err(e) => println!("  ⚠ signing skipped: {}", e),
    }

    // ── 7. Archive ─────────────────────────────────────────────────
    if archive {
        create_archive(&bundle_dir)?;
    }

    // ── Summary ────────────────────────────────────────────────────
    println!();
    println!("Pack complete!");
    println!("  Contents:  config={}  memory={}  skills={}  secrets={}",
        flag(do_config), flag(do_memory), flag(do_skills), flag(do_secrets));
    println!("  Bundle:    {}/", bundle_dir.display());
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Copy helpers
// ---------------------------------------------------------------------------

/// Copy a directory tree recursively. Skips if source doesn't exist.
fn copy_dir_recursive(src: &Path, dst: &Path, force: bool, label: &str) -> Result<()> {
    if !src.is_dir() {
        println!("  ⚠ {} not found in Pi installation, skipping", label);
        return Ok(());
    }

    if dst.exists() && !force {
        bail!(
            "destination already exists: {}\n  use --force to overwrite",
            dst.display()
        );
    }

    let mut count = 0u64;
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

    println!("  ✓ {} copied ({} files)", label, count);
    Ok(())
}

/// Copy packages (extensions, skills, themes) from Pi into bundle.
fn copy_packages(pi: &PiInstallation, bundle_dir: &Path, force: bool) -> Result<()> {
    let src = pi.packages_path();
    if !src.is_dir() {
        println!("  ⚠ packages/ not found in Pi installation, skipping");
        return Ok(());
    }

    let dst_base = bundle_dir.join("agent/packages");
    let mut total = 0u64;

    for sub in &["extensions", "skills", "themes"] {
        let sub_src = src.join(sub);
        let sub_dst = dst_base.join(sub);

        if sub_src.is_dir() {
            if sub_dst.exists() && !force {
                bail!(
                    "destination already exists: {}\n  use --force to overwrite",
                    sub_dst.display()
                );
            }

            let walker = walkdir::WalkDir::new(&sub_src)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok());
            for entry in walker {
                // Reject symlinks
                if entry.file_type().is_symlink() {
                    bail!(
                        "symlink not allowed in bundle: {}",
                        entry.path().display()
                    );
                }

                let rel = entry.path().strip_prefix(&sub_src).unwrap();
                let target = sub_dst.join(rel);
                if entry.file_type().is_dir() {
                    fs::create_dir_all(&target)?;
                } else {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::copy(entry.path(), &target)?;
                    total += 1;
                }
            }
        }
    }

    println!("  ✓ packages copied ({} files)", total);
    Ok(())
}

/// Scan Pi packages and return manifest entries.
fn scan_packages(pi: &PiInstallation) -> manifest::Packages {
    let src = pi.packages_path();
    let mut ext = Vec::new();
    let mut skills = Vec::new();
    let mut themes = Vec::new();

    for (sub, list) in [
        ("extensions", &mut ext),
        ("skills", &mut skills),
        ("themes", &mut themes),
    ] {
        let dir = src.join(sub);
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        list.push(manifest::PackageEntry {
                            name,
                            version: "0.0.0".to_string(),
                            source: None,
                            path: None,
                        });
                    }
                }
            }
        }
    }

    manifest::Packages {
        extensions: ext,
        skills,
        themes,
    }
}

/// Collect secrets from the Pi installation and write them encrypted to keys.enc.
///
/// Secret sources (scanned in order):
/// 1. `secrets/` directory — each file becomes key=filename, value=content
/// 2. `.env` / `*.env` files — parsed as key=value lines
///
/// **No plaintext is written to disk.**
fn copy_secrets_encrypted(pi: &PiInstallation, bundle_dir: &Path, force: bool) -> Result<()> {
    use crate::security::secrets::SecretsBundle;

    let secrets_dst = bundle_dir.join("secrets/keys.enc");

    if secrets_dst.exists() && !force {
        bail!(
            "secrets/keys.enc already exists\n  use --force to overwrite"
        );
    }

    // ── Collect secrets ────────────────────────────────────────────
    let mut bundle = SecretsBundle::new();

    // 1. Scan secrets/ directory for key files
    bundle.scan_secret_files(&pi.root().join("secrets"))?;

    // 2. Scan .env files at root and in config/
    bundle.scan_env_files(pi.root())?;
    bundle.scan_env_files(&pi.root().join("config"))?;

    if bundle.is_empty() {
        println!("  ⚠ no secrets found in Pi installation, skipping");
        return Ok(());
    }

    println!("  Found {} secret(s): {}", bundle.len(), bundle.keys().join(", "));

    // ── Prompt for passphrase ──────────────────────────────────────
    let passphrase = crypto::prompt_passphrase_confirm()?;

    // ── Encrypt and write ──────────────────────────────────────────
    if let Some(parent) = secrets_dst.parent() {
        fs::create_dir_all(parent)?;
    }

    bundle.save_encrypted(&secrets_dst, &passphrase)
        .context("failed to encrypt and save secrets")?;

    let file_size = fs::metadata(&secrets_dst)
        .map(|m| m.len())
        .unwrap_or(0);

    println!("  ✓ secrets encrypted → secrets/keys.enc ({} bytes)", file_size);
    Ok(())
}

/// Compute SHA-256 checksum of all files in the bundle, excluding secrets/keys.enc.
fn compute_bundle_checksum(bundle_dir: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut files: Vec<_> = walkdir::WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            // Exclude the encrypted secrets file from checksum
            let name = e.file_name().to_string_lossy();
            !(name == "keys.enc")
        })
        .collect();
    files.sort_by_key(|e| e.path().to_path_buf());

    for entry in &files {
        if let Ok(content) = fs::read(entry.path()) {
            let rel = entry.path().strip_prefix(bundle_dir).unwrap();
            hasher.update(rel.to_string_lossy().as_bytes());
            hasher.update(&content);
        }
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Create a .tar.gz archive of the bundle directory.
fn create_archive(bundle_dir: &Path) -> Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    let archive_name = format!("{}.tar.gz", bundle_dir.file_name()
        .unwrap_or_default()
        .to_string_lossy());
    let archive_path = bundle_dir.parent()
        .unwrap_or(Path::new("."))
        .join(&archive_name);

    println!();
    println!("Creating archive: {}", archive_path.display());

    let file = fs::File::create(&archive_path)
        .with_context(|| format!("failed to create archive: {}", archive_path.display()))?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(enc);

    tar.append_dir_all(
        bundle_dir.file_name().unwrap_or_default(),
        bundle_dir,
    )
    .context("failed to add files to archive")?;

    tar.finish().context("failed to finalize archive")?;

    let size = fs::metadata(&archive_path)
        .map(|m| m.len() as f64 / 1024.0)
        .unwrap_or(0.0);
    println!("  ✓ archive created ({:.1} KB)", size);

    Ok(())
}

/// Sign the manifest and save signature to bundle.
fn sign_manifest(m: &manifest::Manifest, bundle_dir: &Path) -> Result<()> {
    let manifest_yaml = serde_yaml::to_string(m)
        .context("failed to serialize manifest for signing")?;

    let signature = signing::sign(manifest_yaml.as_bytes())
        .context("failed to sign manifest — is your keypair set up?")?;

    // Save signature next to manifest in the bundle root
    // (not a secret — it's a tamper-evident seal)
    let sig_path = bundle_dir.join("manifest.sig");
    signing::save_signature(&sig_path, &signature)
        .context("failed to save signature")?;

    Ok(())
}

fn flag(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

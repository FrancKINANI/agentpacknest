//! PackBundle — orchestrate packing a bundle from a harness installation.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::domain::manifest;
use crate::harness::pi::detect::PiInstallation;
use crate::harness::types::HarnessAdapter;
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

    if m.harness.name != "pi" {
        bail!(
            "unsupported harness in manifest: `{}`\n  only 'pi' is supported in pn v0.1\n  hint: this bundle was created for a different harness",
            m.harness.name
        );
    }

    println!("Bundle:     {}", m.bundle.name);
    println!("Harness:    pi v{}", m.harness.version);

    // ── 3. Detect Pi installation ──────────────────────────────────
    let pi =
        PiInstallation::detect(request.harness_path).context("failed to detect Pi installation")?;

    println!("Pi source:  {}", pi.root().display());
    println!();

    // ── 4. Load ignore patterns ────────────────────────────────────
    let ignore = IgnorePatterns::load(pi.root());
    if !ignore.is_empty() {
        println!(
            "Ignore:     {} pattern(s) from .agentpacknestignore",
            ignore.len()
        );
        println!();
    }

    // ── 5. Copy files ──────────────────────────────────────────────
    if request.with_config {
        copy_dir_recursive(
            &pi.config_path(),
            &bundle_dir.join("agent/config"),
            request.force,
            "config",
            &ignore,
        )?;
    }

    if request.with_memory {
        copy_dir_recursive(
            &pi.memory_path(),
            &bundle_dir.join("agent/memory"),
            request.force,
            "memory",
            &ignore,
        )?;
    }

    if request.with_skills {
        copy_packages(&pi, bundle_dir, request.force, &ignore)?;
    }

    if request.with_secrets {
        copy_secrets_encrypted(&pi, bundle_dir, request.force)?;
    }

    // ── 6. Update manifest contents ────────────────────────────────
    m.contents.config = request.with_config;
    m.contents.memory = request.with_memory;
    m.contents.skills = request.with_skills;
    m.contents.secrets = request.with_secrets;

    if request.with_skills {
        m.packages = scan_packages(&pi);
    }

    if request.with_secrets {
        m.security.secrets_encrypted = true;
        m.security.encryption = Some(crypto::CRYPTO_FORMAT_IDENTIFIER.to_string());
        m.security.format_version = crypto::CRYPTO_FORMAT_VERSION;
    }

    // ── 7. Compute integrity checksum ──────────────────────────────
    let checksum = integrity::compute_bundle_checksum(bundle_dir)?;
    m.integrity.checksum = Some(checksum.clone());
    m.integrity.format_version = 1;

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
        origin_machine: hostname(),
        packed_at: now_iso8601(),
        source_state_hash: None, // TODO: compute source state hash
    });

    // ── 8. Save manifest ───────────────────────────────────────────
    manifest::save(&manifest_path, &m).context("failed to save updated manifest")?;

    println!();
    println!("  ✓ manifest.yaml updated (checksum: {})", &checksum[..16]);

    // ── 9. Sign the manifest ───────────────────────────────────────
    let signature = signing::sign_canonical_manifest(&m)
        .context("failed to sign manifest — is your keypair set up?")?;

    let sig_path = bundle_dir.join("manifest.sig");
    signing::save_signature(&sig_path, &signature).context("failed to save signature")?;

    // Save public key for portable verification
    signing::save_public_key(bundle_dir).context("failed to save public key")?;

    println!("  ✓ manifest signed");

    // ── 10. Validate the completed bundle ──────────────────────────
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
// Copy helpers (moved from commands/pack.rs)
// ---------------------------------------------------------------------------

/// Copy a directory tree recursively. Skips if source doesn't exist.
/// Files matching ignore patterns are skipped.
fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
    force: bool,
    label: &str,
    ignore: &IgnorePatterns,
) -> Result<()> {
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
            "  ✓ {} copied ({} files, {} ignored)",
            label, count, skipped
        );
    } else {
        println!("  ✓ {} copied ({} files)", label, count);
    }
    Ok(())
}

/// Copy packages (extensions, skills, themes) from Pi into bundle.
/// Files matching ignore patterns are skipped.
fn copy_packages(
    pi: &PiInstallation,
    bundle_dir: &Path,
    force: bool,
    ignore: &IgnorePatterns,
) -> Result<()> {
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
                    bail!("symlink not allowed in bundle: {}", entry.path().display());
                }

                let rel = entry.path().strip_prefix(&sub_src).unwrap();
                let rel_str = rel.to_string_lossy();

                // Check ignore patterns
                if !ignore.is_empty() && ignore.is_ignored(&rel_str) {
                    continue;
                }

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
    let secrets_dst = bundle_dir.join("secrets/keys.enc");

    if secrets_dst.exists() && !force {
        bail!("secrets/keys.enc already exists\n  use --force to overwrite");
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
    Ok(())
}

/// Create a .tar.gz archive of the bundle directory.
/// If `encrypt` is true, the archive is encrypted with AES-256-GCM.
#[allow(dead_code)]
fn create_archive(bundle_dir: &Path, encrypt: bool) -> Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    let ext = if encrypt { ".tar.gz.enc" } else { ".tar.gz" };
    let archive_name = format!(
        "{}{}",
        bundle_dir.file_name().unwrap_or_default().to_string_lossy(),
        ext
    );
    let archive_path = bundle_dir
        .parent()
        .unwrap_or(Path::new("."))
        .join(&archive_name);

    println!();
    println!("Creating archive: {}", archive_path.display());

    // Build the .tar.gz in memory first
    let mut tar_gz_buf = Vec::new();
    {
        let enc = GzEncoder::new(&mut tar_gz_buf, Compression::default());
        let mut tar = Builder::new(enc);
        tar.append_dir_all(bundle_dir.file_name().unwrap_or_default(), bundle_dir)
            .context("failed to add files to archive")?;
        tar.finish().context("failed to finalize archive")?;
    }

    if encrypt {
        // Prompt for passphrase and encrypt the entire archive
        let passphrase = crypto::prompt_passphrase_confirm()?;
        let mut encrypted = crypto::encrypt_secrets(&passphrase, &tar_gz_buf)
            .context("failed to encrypt archive")?;
        fs::write(&archive_path, &encrypted).with_context(|| {
            format!(
                "failed to write encrypted archive: {}",
                archive_path.display()
            )
        })?;
        zeroize_buffer(&mut tar_gz_buf);
        zeroize_buffer(&mut encrypted);
    } else {
        fs::write(&archive_path, &tar_gz_buf)
            .with_context(|| format!("failed to write archive: {}", archive_path.display()))?;
    }

    let size = fs::metadata(&archive_path)
        .map(|m| m.len() as f64 / 1024.0)
        .unwrap_or(0.0);
    println!(
        "  ✓ archive created ({:.1} KB){}",
        size,
        if encrypt { " (encrypted)" } else { "" }
    );

    Ok(())
}

/// Zeroize a buffer to prevent secrets from lingering in memory.
#[allow(dead_code)]
fn zeroize_buffer(buf: &mut Vec<u8>) {
    use zeroize::Zeroize;
    buf.zeroize();
    buf.clear();
}

fn flag(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

// ---------------------------------------------------------------------------
// Helpers (duplicated from manifest.rs for now)
// ---------------------------------------------------------------------------

fn hostname() -> String {
    #[cfg(unix)]
    {
        if let Ok(name) = std::process::Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        {
            if !name.is_empty() {
                return name;
            }
        }
    }
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

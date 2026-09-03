use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::application::pack_bundle::{execute as pack_bundle_execute, PackBundleRequest};
use crate::security::crypto;

/// Execute `pn pack`.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    bundle_path: Option<String>,
    pi_path: Option<String>,
    with_config: bool,
    with_memory: bool,
    with_skills: bool,
    with_secrets: bool,
    all: bool,
    archive: bool,
    encrypt_archive: bool,
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

    if encrypt_archive && !archive {
        bail!("--encrypt-archive requires --archive");
    }

    // ── Resolve bundle path early for archive ──────────────────────
    let bundle_path = bundle_path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("failed to get current directory"));

    // ── Construct request ──────────────────────────────────────────
    let request = PackBundleRequest {
        bundle_path: bundle_path.clone(),
        harness_path: pi_path.map(PathBuf::from),
        with_config: do_config,
        with_memory: do_memory,
        with_skills: do_skills,
        with_secrets: do_secrets,
        force,
    };

    // ── Delegate to application layer ──────────────────────────────
    let _result = pack_bundle_execute(request)?;

    // ── Archive (still handled at command layer for now) ───────────
    if archive {
        create_archive(&bundle_path, encrypt_archive)?;
    }

    Ok(())
}

/// Create a .tar.gz archive of the bundle directory.
/// If `encrypt` is true, the archive is encrypted with AES-256-GCM.
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
fn zeroize_buffer(buf: &mut Vec<u8>) {
    use zeroize::Zeroize;
    buf.zeroize();
    buf.clear();
}

use std::fs;
use std::path::Path;

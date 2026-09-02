use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::core::manifest;
use crate::security::signing;

/// Verify the manifest signature against the bundle's manifest.sig.
fn verify_signature(
    manifest_path: &Path,
    sig_path: &Path,
) -> Result<bool> {
    let manifest_bytes = std::fs::read(manifest_path)
        .context("failed to read manifest for verification")?;
    let sig_bytes = signing::load_signature(sig_path)
        .context("failed to load signature")?;
    let vk = signing::load_verifying_key()
        .context("failed to load verifying key")?;

    signing::verify(&manifest_bytes, &sig_bytes, &vk.to_bytes())
        .context("signature verification failed")
}

pub fn execute(bundle: String) -> Result<()> {
    let bundle_dir = Path::new(&bundle);

    if !bundle_dir.is_dir() {
        bail!(
            "not a directory: {}\n  hint: pass a path to a bundle directory",
            bundle
        );
    }

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "no manifest.yaml found in {}\n  hint: this doesn't look like an hitchhike bundle",
            bundle
        );
    }

    let m = manifest::load(&manifest_path)
        .context("failed to load manifest")?;

    // ── Header ──────────────────────────────────────────────────────
    println!();
    println!("  Bundle Information");
    println!("  {}", "─".repeat(44));

    // ── Bundle ──────────────────────────────────────────────────────
    println!("  Name         {}", m.bundle.name);
    println!("  ID           {}", m.bundle.id);
    println!("  Created      {}", m.bundle.created_at);
    println!("  Author       {}", m.bundle.created_by);
    if let Some(ref desc) = m.bundle.description {
        println!("  Description  {}", desc);
    }

    // ── Harness ─────────────────────────────────────────────────────
    println!();
    println!("  Harness");
    println!("  {}", "─".repeat(44));
    println!("  Name         {} v{}", m.harness.name, m.harness.version);
    if let Some(ref src) = m.harness.source {
        println!("  Source       {}", src);
    }

    // ── Contents ────────────────────────────────────────────────────
    println!();
    println!("  Contents");
    println!("  {}", "─".repeat(44));
    println!(
        "  config={}  memory={}  skills={}  secrets={}",
        flag(m.contents.config),
        flag(m.contents.memory),
        flag(m.contents.skills),
        flag(m.contents.secrets),
    );

    // ── Packages ────────────────────────────────────────────────────
    let ext_count = m.packages.extensions.len();
    let skill_count = m.packages.skills.len();
    let theme_count = m.packages.themes.len();

    println!();
    println!("  Packages");
    println!("  {}", "─".repeat(44));
    println!(
        "  extensions={}  skills={}  themes={}",
        ext_count, skill_count, theme_count
    );

    if ext_count + skill_count + theme_count > 0 {
        print_package_list("  ext", &m.packages.extensions);
        print_package_list("  skill", &m.packages.skills);
        print_package_list("  theme", &m.packages.themes);
    }

    // ── Runtime ─────────────────────────────────────────────────────
    println!();
    println!("  Runtime");
    println!("  {}", "─".repeat(44));
    if m.runtime.required.is_empty() {
        println!("  (none)");
    } else {
        for req in &m.runtime.required {
            println!("  {} >= {}", req.name, req.min_version);
        }
    }

    // ── Integrity ───────────────────────────────────────────────────
    println!();
    println!("  Integrity");
    println!("  {}", "─".repeat(44));
    println!("  Algorithm    {}", m.integrity.algorithm);
    match &m.integrity.checksum {
        Some(hash) => println!("  Checksum     {}", hash),
        None => println!("  Checksum     (not computed)"),
    }

    // ── Launch ──────────────────────────────────────────────────────
    println!();
    println!("  Launch");
    println!("  {}", "─".repeat(44));
    println!("  Command      {}", m.launch.command);
    if let Some(ref wd) = m.launch.working_directory {
        println!("  Work dir     {}", wd);
    }

    // ── Signature ───────────────────────────────────────────────────
    println!();
    println!("  Signature");
    println!("  {}", "─".repeat(44));
    let sig_path = bundle_dir.join("manifest.sig");
    if sig_path.is_file() {
        match verify_signature(&manifest_path, &sig_path) {
            Ok(true) => println!("  Status       ✓ valid signature"),
            Ok(false) => println!("  Status       ✗ INVALID signature — bundle may be tampered"),
            Err(e) => println!("  Status       ⚠ verification failed: {}", e),
        }
    } else {
        println!("  Status       (unsigned — no manifest.sig found)");
    }

    println!();
    Ok(())
}

fn flag(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

fn print_package_list(label: &str, entries: &[manifest::PackageEntry]) {
    for e in entries {
        let mut line = format!("  {} {}", label, e.name);
        line.push_str(&format!(" v{}", e.version));
        if let Some(ref s) = e.source {
            line.push_str(&format!(" ({})", s));
        }
        if let Some(ref p) = e.path {
            line.push_str(&format!(" [{}]", p));
        }
        println!("{}", line);
    }
}

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::domain::manifest;
use crate::security::signing;

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
            "no manifest.yaml found in {}\n  hint: this doesn't look like an agentpacknest bundle",
            bundle
        );
    }

    let m = manifest::load(&manifest_path).context("failed to load manifest")?;

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
    if let Some(ref ver) = m.agentpacknest_version {
        println!("  Packed by    agentpacknest v{}", ver);
    }
    println!("  Bundle fmt   v{}", m.bundle_version);

    // ── Platform ────────────────────────────────────────────────────
    if let Some(ref plat) = m.platform {
        println!();
        println!("  Platform");
        println!("  {}", "─".repeat(44));
        println!("  OS           {}", plat.os);
        println!("  Arch         {}", plat.arch);
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
    println!("  Components");
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
    println!("  Format       v{}", m.integrity.format_version);
    match &m.integrity.checksum {
        Some(hash) => println!("  Checksum     {}", hash),
        None => println!("  Checksum     (not computed)"),
    }

    // ── Signature ───────────────────────────────────────────────────
    println!();
    println!("  Signature");
    println!("  {}", "─".repeat(44));
    let sig_path = bundle_dir.join("manifest.sig");
    let pubkey_path = bundle_dir.join("signing/public.key");

    if sig_path.is_file() && pubkey_path.is_file() {
        // Portable verification: recompute the canonical manifest
        // representation from the parsed manifest and verify it against
        // the bundled public key. No local keypair is involved.
        match signing::verify_manifest_with_bundled_pubkey(&m, &sig_path, &pubkey_path) {
            Ok(true) => {
                println!("  Status       ✓ valid signature (verified with bundled public key)")
            }
            Ok(false) => println!("  Status       ✗ INVALID signature — bundle may be tampered"),
            Err(e) => println!("  Status       ⚠ verification failed: {}", e),
        }
    } else if sig_path.is_file() {
        println!("  Status       ⚠ public key missing (signing/public.key not found)");
    } else {
        println!("  Status       (unsigned — no manifest.sig found)");
    }

    // ── Security ───────────────────────────────────────────────────
    println!();
    println!("  Security");
    println!("  {}", "─".repeat(44));
    println!("  Secrets enc  {}", flag(m.security.secrets_encrypted));
    if let Some(ref enc) = m.security.encryption {
        println!("  Encryption   {}", enc);
    }
    match m.crypto {
        Some(ref c) => println!("  Crypto fmt   v{}", c.format_version),
        None => println!("  Crypto fmt   (unspecified)"),
    }

    // ── Launch ──────────────────────────────────────────────────────
    println!();
    println!("  Launch");
    println!("  {}", "─".repeat(44));
    println!("  Command      {}", m.launch.command);
    if !m.launch.args.is_empty() {
        println!("  Args         {}", m.launch.args.join(" "));
    }
    if let Some(ref wd) = m.launch.working_directory {
        println!("  Work dir     {}", wd);
    }

    // ── Reproducibility Report ──────────────────────────────────────
    println!();
    println!("  Reproducibility");
    println!("  {}", "─".repeat(44));
    let (score, warnings) = compute_reproducibility(&m, bundle_dir);
    println!("  Score        {}%", score);
    if warnings.is_empty() {
        println!("  Warnings     (none)");
    } else {
        for w in &warnings {
            println!("  ⚠ {}", w);
        }
    }

    println!();
    Ok(())
}

/// Compute a reproducibility score (0-100) and list warnings.
///
/// Factors:
/// - Has config: +15
/// - Has skills: +15
/// - Has memory: +10
/// - Has secrets encrypted: +15
/// - Has integrity checksum: +10
/// - Has signature: +10
/// - Has platform info: +5
/// - Has origin/provenance: +5
/// - Has runtime requirements: +5
/// - Has packages: +5
/// - No warnings penalty: up to +5
fn compute_reproducibility(m: &manifest::Manifest, bundle_dir: &Path) -> (u32, Vec<String>) {
    let mut score = 0u32;
    let mut warnings = Vec::new();

    // Components
    if m.contents.config {
        score += 15;
    } else {
        warnings.push("no config packed — bundle may not be self-contained".to_string());
    }
    if m.contents.skills {
        score += 15;
    } else {
        warnings.push("no skills packed — agent capabilities may differ".to_string());
    }
    if m.contents.memory {
        score += 10;
    } else {
        warnings.push("no memory packed — session history lost".to_string());
    }
    if m.contents.secrets && m.security.secrets_encrypted {
        score += 15;
    } else if m.contents.secrets {
        score += 5;
        warnings.push("secrets present but not encrypted".to_string());
    } else {
        warnings.push("no secrets packed — API keys may be missing".to_string());
    }

    // Integrity
    if m.integrity.checksum.is_some() {
        score += 10;
    } else {
        warnings.push("no checksum — bundle integrity unverified".to_string());
    }

    // Signature
    let sig_path = bundle_dir.join("manifest.sig");
    if sig_path.is_file() {
        score += 10;
    } else {
        warnings.push("unsigned bundle — authenticity unverified".to_string());
    }

    // Platform
    if m.platform.is_some() {
        score += 5;
    } else {
        warnings.push("no platform info — cross-platform compatibility unknown".to_string());
    }

    // Origin
    if m.origin.is_some() {
        score += 5;
    }

    // Runtime
    if !m.runtime.required.is_empty() {
        score += 5;
    } else {
        warnings.push("no runtime requirements specified".to_string());
    }

    // Packages
    let pkg_count = m.packages.extensions.len() + m.packages.skills.len() + m.packages.themes.len();
    if pkg_count > 0 {
        score += 5;
    }

    // Cap at 100
    score = score.min(100);

    (score, warnings)
}

fn flag(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
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

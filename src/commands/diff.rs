use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::manifest;

/// Execute `hh diff`.
pub fn execute(bundle_path: Option<String>, path: Option<String>) -> Result<()> {
    // ── 1. Resolve bundle ──────────────────────────────────────────
    let bundle_dir = match bundle_path {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir().context("failed to get current directory")?,
    };

    let manifest_path = bundle_dir.join("manifest.yaml");
    if !manifest_path.is_file() {
        bail!(
            "no manifest.yaml found in {}\n  hint: not a valid hitchhike bundle",
            bundle_dir.display()
        );
    }

    let m = manifest::load(&manifest_path)
        .context("failed to load manifest")?;

    println!("Bundle:   {}", m.bundle.name);
    println!("Packed:   {}", m.origin.as_ref().map_or("(unknown)", |o| &o.packed_at));
    println!("Machine:  {}", m.origin.as_ref().map_or("(unknown)", |o| &o.origin_machine));
    println!();

    // ── 2. Resolve harness source ──────────────────────────────────
    let harness_path = match path {
        Some(p) => PathBuf::from(p),
        None => resolve_harness_path(&m.harness.name)?,
    };

    if !harness_path.is_dir() {
        bail!(
            "harness directory not found: {}\n  hint: pass --path to specify the harness location",
            harness_path.display()
        );
    }

    println!("Harness:  {} ({})", m.harness.name, harness_path.display());
    println!();

    // ── 3. Compare files ───────────────────────────────────────────
    let bundle_files = collect_bundle_files(&bundle_dir)?;
    let harness_files = collect_harness_files(&harness_path)?;

    // Map relative paths
    let bundle_rels: BTreeSet<String> = bundle_files
        .iter()
        .filter_map(|p| p.strip_prefix(&bundle_dir).ok())
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| s != "manifest.yaml" && !s.starts_with("secrets/"))
        .collect();

    let harness_rels: BTreeSet<String> = harness_files
        .iter()
        .filter_map(|p| p.strip_prefix(&harness_path).ok())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let in_both: Vec<&String> = bundle_rels.iter().filter(|b| harness_rels.contains(*b)).collect();
    let only_in_bundle: Vec<&String> = bundle_rels.iter().filter(|b| !harness_rels.contains(*b)).collect();
    let only_in_harness: Vec<&String> = harness_rels.iter().filter(|h| !bundle_rels.contains(*h)).collect();

    let mut changed = Vec::new();
    for rel in &in_both {
        // Find the full paths and compare content
        let bundle_file = bundle_files.iter().find(|p| {
            p.strip_prefix(&bundle_dir).ok().map(|r| r.to_string_lossy().into_owned()).as_deref() == Some(rel.as_str())
        });
        let harness_file = harness_files.iter().find(|p| {
            p.strip_prefix(&harness_path).ok().map(|r| r.to_string_lossy().into_owned()).as_deref() == Some(rel.as_str())
        });

        if let (Some(bf), Some(hf)) = (bundle_file, harness_file) {
            let b_content = fs::read(bf).unwrap_or_default();
            let h_content = fs::read(hf).unwrap_or_default();
            if b_content != h_content {
                changed.push(rel.clone());
            }
        }
    }

    // ── 4. Print results ───────────────────────────────────────────
    if changed.is_empty() && only_in_bundle.is_empty() && only_in_harness.is_empty() {
        println!("✓ Bundle is in sync with the local harness.");
        return Ok(());
    }

    let mut has_diff = false;

    if !changed.is_empty() {
        has_diff = true;
        println!("  {} Modified files:", "≠".to_string());
        for f in &changed {
            println!("    {}", f);
        }
        println!();
    }

    if !only_in_bundle.is_empty() {
        has_diff = true;
        println!("  {} Only in bundle (removed from harness):", "−".to_string());
        for f in &only_in_bundle {
            println!("    {}", f);
        }
        println!();
    }

    if !only_in_harness.is_empty() {
        has_diff = true;
        println!("  {} Only in harness (not packed):", "+".to_string());
        for f in &only_in_harness {
            println!("    {}", f);
        }
        println!();
    }

    if has_diff {
        println!("Bundle and local harness have diverged.");
        println!("hint: re-run `hh pack` to update the bundle, or use `--force` to ignore.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_harness_path(harness_name: &str) -> Result<PathBuf> {
    match harness_name {
        "pi" => {
            // Check PI_CODING_AGENT_DIR, then ~/.pi/agent, then PI_HOME, then ~/.pi
            if let Ok(val) = std::env::var("PI_CODING_AGENT_DIR") {
                let p = PathBuf::from(&val);
                if p.is_dir() { return Ok(p); }
            }
            if let Some(home) = dirs::home_dir() {
                let p = home.join(".pi").join("agent");
                if p.is_dir() { return Ok(p); }
            }
            if let Ok(val) = std::env::var("PI_HOME") {
                let p = PathBuf::from(&val);
                if p.is_dir() { return Ok(p); }
            }
            if let Some(home) = dirs::home_dir() {
                let p = home.join(".pi");
                if p.is_dir() { return Ok(p); }
            }
            bail!("could not find Pi installation\n  hint: pass --path explicitly")
        }
        _ => bail!("unsupported harness for auto-detection: {}", harness_name),
    }
}

fn collect_bundle_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

fn collect_harness_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

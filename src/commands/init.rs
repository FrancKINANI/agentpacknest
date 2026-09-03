use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::domain::harness::HarnessId;
use crate::domain::manifest;
use crate::harness::registry::HarnessRegistry;
use crate::harness::traits::HarnessContext;

pub fn execute(
    harness: String,
    path: Option<String>,
    name: Option<String>,
    output: Option<String>,
) -> Result<()> {
    // ── 1. Validate harness ────────────────────────────────────────
    let id = HarnessId::from_name(&harness)
        .ok_or_else(|| anyhow::anyhow!("unsupported harness: `{}`", harness))?;

    if !id.is_fully_supported() {
        bail!(
            "unsupported harness: `{}`\n  supported harnesses: pi\n  hint: only 'pi' is available in pn v0.2",
            harness
        );
    }

    // ── 2. Detect the harness installation ─────────────────────────
    let registry = HarnessRegistry::with_defaults();
    let adapter = registry
        .get(id)
        .context("failed to resolve harness adapter")?;
    let context = HarnessContext::new(path.map(PathBuf::from));
    let detected = adapter
        .detect(&context)
        .context("failed to detect harness installation")?;

    println!("Detected {} v{}", id, detected.version);

    // ── 3. Resolve output directory ────────────────────────────────
    let agent_name = name.unwrap_or_else(|| "my-agent".to_string());
    let out_dir = match output {
        Some(o) => PathBuf::from(o),
        None => PathBuf::from(&agent_name),
    };

    if out_dir.exists() {
        bail!(
            "output directory already exists: {}\n  hint: remove it with `rm -rf {}` or use --output to choose another path",
            out_dir.display(),
            out_dir.display()
        );
    }

    // ── 4. Create directory structure ──────────────────────────────
    let dirs = [
        "agent/config",
        "agent/memory",
        "agent/packages/extensions",
        "agent/packages/skills",
        "agent/packages/themes",
        "agent/workspace",
        "secrets",
    ];

    for dir in &dirs {
        fs::create_dir_all(out_dir.join(dir)).with_context(|| {
            format!(
                "failed to create directory: {}/{}\n",
                out_dir.display(),
                dir
            )
        })?;
    }

    println!("Created bundle structure in {}/", out_dir.display());

    // ── 5. Generate manifest.yaml ──────────────────────────────────
    let mut m = manifest::default_pi(&agent_name, &detected.version);

    // Fill in the runtime requirement with detected version
    if let Some(req) = m.runtime.required.first_mut() {
        req.min_version = detected.version.clone();
    }

    let manifest_path = out_dir.join("manifest.yaml");
    manifest::save(&manifest_path, &m).context("failed to write manifest.yaml")?;

    println!("Wrote manifest.yaml");

    // ── 6. Summary ─────────────────────────────────────────────────
    println!();
    println!("Bundle '{}' initialized successfully!", agent_name);
    println!("  Harness:    {} v{}", id, detected.version);
    println!("  Output:     {}/", out_dir.display());
    println!();
    println!("Next steps:");
    println!("  cd {}", out_dir.display());
    println!("  pn info .");
    println!();

    Ok(())
}

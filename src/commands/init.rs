use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::domain::manifest;
use crate::harness::pi::detect::PiInstallation;
use crate::harness::types::HarnessAdapter;

pub fn execute(
    harness: String,
    path: Option<String>,
    name: Option<String>,
    output: Option<String>,
) -> Result<()> {
    // ── 1. Validate harness ────────────────────────────────────────
    if harness != "pi" {
        bail!(
            "unsupported harness: `{}`\n  supported harnesses: pi\n  hint: only 'pi' is available in pn v0.1",
            harness
        );
    }

    // ── 2. Detect Pi installation ──────────────────────────────────
    let pi_path = path.map(PathBuf::from);
    let pi = PiInstallation::detect(pi_path).context("failed to detect Pi installation")?;

    println!("Detected Pi v{}", pi.version());

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
            format!("failed to create directory: {}/{}", out_dir.display(), dir)
        })?;
    }

    println!("Created bundle structure in {}/", out_dir.display());

    // ── 5. Create launch placeholder ───────────────────────────────
    let launch_content = format!(
        "#!/usr/bin/env bash\n# Launch script for {}\n# Edit this file to define how the agent starts.\n\necho \"Agent '{}' is starting...\"\n",
        agent_name, agent_name
    );
    fs::write(out_dir.join("launch"), &launch_content)
        .context("failed to write launch placeholder")?;

    // ── 6. Generate manifest.yaml ──────────────────────────────────
    let mut m = manifest::default_pi(&agent_name, pi.version());

    // Fill in the runtime requirement with detected version
    if let Some(req) = m.runtime.required.first_mut() {
        req.min_version = pi.version().to_string();
    }

    let manifest_path = out_dir.join("manifest.yaml");
    manifest::save(&manifest_path, &m).context("failed to write manifest.yaml")?;

    println!("Wrote manifest.yaml");

    // ── 7. Summary ─────────────────────────────────────────────────
    println!();
    println!("Bundle '{}' initialized successfully!", agent_name);
    println!("  Harness:    pi v{}", pi.version());
    println!("  Output:     {}/", out_dir.display());
    println!();
    println!("Next steps:");
    println!("  cd {}", out_dir.display());
    println!("  pn info .");
    println!();

    Ok(())
}

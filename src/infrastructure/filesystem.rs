//! Filesystem operations — copy, walk, permissions.
//!
//! These are the low-level file operations used by the application layer.
//! They handle symlinks, permissions, and cross-platform concerns.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// Copy a directory tree recursively.
///
/// - Skips if source doesn't exist (returns Ok with count 0)
/// - Rejects symlinks (security)
/// - Respects ignore patterns
/// - Returns the number of files copied
pub fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
    force: bool,
    label: &str,
    ignore: Option<&crate::infrastructure::ignore::IgnorePatterns>,
) -> Result<u64> {
    if !src.is_dir() {
        return Ok(0);
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
        if entry.file_type().is_symlink() {
            bail!(
                "symlink not allowed in bundle: {}\n  hint: remove the symlink from the source",
                entry.path().display()
            );
        }

        let rel = entry.path().strip_prefix(src).unwrap();
        let rel_str = rel.to_string_lossy();

        if let Some(patterns) = ignore {
            if !patterns.is_empty() && patterns.is_ignored(&rel_str) {
                skipped += 1;
                continue;
            }
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

    Ok(count)
}

/// Set restrictive permissions on a file (Unix only).
///
/// On Windows, this is a no-op.
pub fn set_restrictive_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    let _ = path; // suppress unused warning on non-Unix
    Ok(())
}

/// Ensure a directory exists, creating it if necessary.
pub fn ensure_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create directory: {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn copy_dir_basic() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().join("sub");

        fs::write(src.path().join("file.txt"), "hello").unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/nested.txt"), "world").unwrap();

        let count = copy_dir_recursive(src.path(), &dst_path, false, "test", None).unwrap();
        assert_eq!(count, 2);
        assert!(dst_path.join("file.txt").exists());
        assert!(dst_path.join("sub/nested.txt").exists());
    }

    #[test]
    fn copy_dir_rejects_symlink() {
        let src = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", src.path().join("evil.link")).unwrap();
            let result =
                copy_dir_recursive(src.path(), &dst.path().join("out"), false, "test", None);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("symlink"));
        }
    }

    #[test]
    fn set_restrictive_permissions_works() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("secret.enc");
        fs::write(&file, "data").unwrap();

        set_restrictive_permissions(&file).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = fs::metadata(&file).unwrap().permissions();
            assert_eq!(perm.mode() & 0o777, 0o600);
        }
    }
}

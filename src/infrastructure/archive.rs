//! Archive — create and extract .tar.gz bundles.

use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::path::Path;
use tar::Builder;

/// Create a .tar.gz archive of a directory.
pub fn create_tar_gz(source_dir: &Path, output_path: &Path) -> Result<u64> {
    let file = fs::File::create(output_path)
        .with_context(|| format!("failed to create archive: {}", output_path.display()))?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(enc);

    tar.append_dir_all(source_dir.file_name().unwrap_or_default(), source_dir)
        .context("failed to add files to archive")?;

    tar.finish().context("failed to finalize archive")?;

    let size = fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);

    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn create_archive_basic() {
        let source = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();

        fs::write(source.path().join("file.txt"), "hello").unwrap();
        fs::create_dir(source.path().join("sub")).unwrap();
        fs::write(source.path().join("sub/nested.txt"), "world").unwrap();

        let archive_path = output.path().join("test.tar.gz");
        let size = create_tar_gz(source.path(), &archive_path).unwrap();

        assert!(archive_path.exists());
        assert!(size > 0);
    }
}

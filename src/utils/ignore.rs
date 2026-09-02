//! `.hitchhikeignore` file support.
//!
//! Reads a `.hitchhikeignore` file (same syntax as `.gitignore`) and provides
//! a method to check if a relative path should be excluded from packing.
//!
//! Patterns are matched against the relative path within the source directory.
//! Comments (lines starting with `#`) and empty lines are ignored.

use std::fs;
use std::path::Path;

/// A set of ignore patterns parsed from a `.hitchhikeignore` file.
#[derive(Debug, Clone, Default)]
pub struct IgnorePatterns {
    patterns: Vec<String>,
}

impl IgnorePatterns {
    /// Load patterns from a `.hitchhikeignore` file.
    /// Returns an empty pattern set if the file doesn't exist.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(".hitchhikeignore");
        if !path.is_file() {
            return Self::default();
        }
        Self::from_file(&path)
    }

    /// Parse patterns from a specific file path.
    pub fn from_file(path: &Path) -> Self {
        let content = fs::read_to_string(path).unwrap_or_default();
        Self::from_str(&content)
    }

    /// Parse patterns from a string.
    pub fn from_str(content: &str) -> Self {
        let patterns = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect();
        Self { patterns }
    }

    /// Check if a relative path should be ignored.
    ///
    /// Matching rules (simplified gitignore):
    /// - Exact filename match: `secrets.env` ignores `secrets.env` anywhere in the tree
    /// - Glob: `*.log` ignores any file ending in `.log`
    /// - Prefix: `/tmp` ignores paths starting with `tmp`
    /// - Directory name: `cache` ignores any path segment named `cache`
    pub fn is_ignored(&self, rel_path: &str) -> bool {
        let path = rel_path.trim_start_matches('/');
        let filename = path.rsplit('/').next().unwrap_or(path);

        for pattern in &self.patterns {
            let pat = pattern.trim_end_matches('/');

            // Exact filename match
            if pat == filename {
                return true;
            }

            // Glob: *.ext
            if let Some(suffix) = pat.strip_prefix("*.") {
                if filename.ends_with(suffix) && filename.len() > suffix.len() + 1 {
                    return true;
                }
            }

            // Prefix match for patterns like /tmp (ignore leading /)
            // Only match at path boundaries: /tmp matches /tmp/foo but not /tmpfoo
            if !pat.starts_with('*') && !pat.contains('*') {
                let pat_clean = pat.trim_start_matches('/');
                if path == pat_clean || path.starts_with(&format!("{}/", pat_clean)) {
                    return true;
                }
            }

            // Contains match: any path segment matches a bare name
            if !pat.contains('/') && !pat.contains('*') {
                if path.split('/').any(|seg| seg == pat) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if patterns are empty (no ignore rules).
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Number of patterns.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_matches_nothing() {
        let p = IgnorePatterns::default();
        assert!(!p.is_ignored("anything.txt"));
    }

    #[test]
    fn exact_filename_match() {
        let p = IgnorePatterns::from_str("secrets.env\n");
        assert!(p.is_ignored("secrets.env"));
        assert!(p.is_ignored("dir/secrets.env"));
        assert!(!p.is_ignored("secrets.env.bak"));
    }

    #[test]
    fn glob_match() {
        let p = IgnorePatterns::from_str("*.log\n*.tmp\n");
        assert!(p.is_ignored("debug.log"));
        assert!(p.is_ignored("logs/debug.log"));
        assert!(p.is_ignored("file.tmp"));
        assert!(!p.is_ignored("debug.log.bak"));
    }

    #[test]
    fn directory_pattern() {
        let p = IgnorePatterns::from_str("cache\n");
        assert!(p.is_ignored("cache/some-file"));
        assert!(p.is_ignored("my/cache/dir/file"));
        assert!(!p.is_ignored("cache_file"));
    }

    #[test]
    fn prefix_match() {
        let p = IgnorePatterns::from_str("/tmp\n");
        assert!(p.is_ignored("tmp/file"));
        assert!(p.is_ignored("tmp/deep/file"));
        assert!(!p.is_ignored("not-tmp/file"));
    }

    #[test]
    fn comments_and_blank_lines() {
        let p = IgnorePatterns::from_str("# comment\n\n*.log\n  \n# another\n");
        assert_eq!(p.len(), 1);
        assert!(p.is_ignored("test.log"));
    }

    #[test]
    fn from_file_nonexistent() {
        let p = IgnorePatterns::load(Path::new("/nonexistent/path"));
        assert!(p.is_empty());
    }
}

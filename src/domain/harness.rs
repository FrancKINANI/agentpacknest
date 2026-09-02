//! Harness identification — which agent runtime a bundle targets.

use std::fmt;

/// Identifier for a supported agent harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessId {
    Pi,
    Aider,
    // Future: Codex, ClaudeCode, OpenCode
}

impl HarnessId {
    /// Parse a harness name string into a HarnessId.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "pi" => Some(HarnessId::Pi),
            "aider" => Some(HarnessId::Aider),
            _ => None,
        }
    }

    /// All supported harnesses.
    pub fn all() -> &'static [HarnessId] {
        &[HarnessId::Pi, HarnessId::Aider]
    }

    /// Check if this harness is fully supported (not just scaffolded).
    pub fn is_fully_supported(&self) -> bool {
        matches!(self, HarnessId::Pi)
    }
}

impl fmt::Display for HarnessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HarnessId::Pi => write!(f, "pi"),
            HarnessId::Aider => write!(f, "aider"),
        }
    }
}

impl std::str::FromStr for HarnessId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HarnessId::from_name(s).ok_or_else(|| {
            let supported: Vec<_> = HarnessId::all().iter().map(|h| h.to_string()).collect();
            format!(
                "unknown harness '{}'\n  supported: {}",
                s,
                supported.join(", ")
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pi() {
        assert_eq!("pi".parse::<HarnessId>().unwrap(), HarnessId::Pi);
    }

    #[test]
    fn parse_aider() {
        assert_eq!("aider".parse::<HarnessId>().unwrap(), HarnessId::Aider);
    }

    #[test]
    fn parse_unknown_fails() {
        assert!("docker".parse::<HarnessId>().is_err());
    }

    #[test]
    fn case_insensitive() {
        assert_eq!("PI".parse::<HarnessId>().unwrap(), HarnessId::Pi);
        assert_eq!("Aider".parse::<HarnessId>().unwrap(), HarnessId::Aider);
    }

    #[test]
    fn pi_is_fully_supported() {
        assert!(HarnessId::Pi.is_fully_supported());
    }

    #[test]
    fn aider_is_not_fully_supported() {
        assert!(!HarnessId::Aider.is_fully_supported());
    }
}

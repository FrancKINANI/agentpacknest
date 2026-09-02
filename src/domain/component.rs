//! Component — the parts that make up an agent environment.
//!
//! Each component represents a category of agent assets that can be
//! independently packed, verified, and transferred.

use std::fmt;

/// The kind of component in an agent environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentKind {
    Config,
    Memory,
    Skills,
    Extensions,
    Themes,
    Secrets,
}

impl ComponentKind {
    /// All component kinds in canonical order.
    pub fn all() -> &'static [ComponentKind] {
        &[
            ComponentKind::Config,
            ComponentKind::Memory,
            ComponentKind::Skills,
            ComponentKind::Extensions,
            ComponentKind::Themes,
            ComponentKind::Secrets,
        ]
    }

    /// Directory name for this component in the bundle.
    pub fn dir_name(&self) -> &'static str {
        match self {
            ComponentKind::Config => "config",
            ComponentKind::Memory => "memory",
            ComponentKind::Skills => "skills",
            ComponentKind::Extensions => "extensions",
            ComponentKind::Themes => "themes",
            ComponentKind::Secrets => "secrets",
        }
    }
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComponentKind::Config => write!(f, "config"),
            ComponentKind::Memory => write!(f, "memory"),
            ComponentKind::Skills => write!(f, "skills"),
            ComponentKind::Extensions => write!(f, "extensions"),
            ComponentKind::Themes => write!(f, "themes"),
            ComponentKind::Secrets => write!(f, "secrets"),
        }
    }
}

/// State of a component in a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentState {
    /// What kind of component this is.
    pub kind: ComponentKind,
    /// Whether this component has been packed into the bundle.
    pub packed: bool,
    /// Number of files in this component.
    pub file_count: u64,
}

impl ComponentState {
    pub fn new(kind: ComponentKind) -> Self {
        Self {
            kind,
            packed: false,
            file_count: 0,
        }
    }

    pub fn packed(kind: ComponentKind, file_count: u64) -> Self {
        Self {
            kind,
            packed: true,
            file_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_kind_all_has_six() {
        assert_eq!(ComponentKind::all().len(), 6);
    }

    #[test]
    fn component_kind_dir_names() {
        assert_eq!(ComponentKind::Config.dir_name(), "config");
        assert_eq!(ComponentKind::Secrets.dir_name(), "secrets");
    }

    #[test]
    fn component_state_defaults_unpacked() {
        let c = ComponentState::new(ComponentKind::Config);
        assert!(!c.packed);
        assert_eq!(c.file_count, 0);
    }

    #[test]
    fn component_state_packed() {
        let c = ComponentState::packed(ComponentKind::Memory, 42);
        assert!(c.packed);
        assert_eq!(c.file_count, 42);
    }
}

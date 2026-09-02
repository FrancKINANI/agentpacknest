//! Infrastructure layer — filesystem, process execution, archives.
//!
//! This layer provides the low-level operations that the application
//! layer uses. It has no knowledge of domain concepts.

pub mod filesystem;
pub mod process;

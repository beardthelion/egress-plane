//! Dependency-source support: parsers for package metadata, lockfiles,
//! and version comparison. Everything here works on bytes; path reads
//! stay in `discover` (KTD24).

pub mod inventory;
pub mod locator;
pub mod lockfile;
pub mod metadata;
pub mod verify;
pub mod version;

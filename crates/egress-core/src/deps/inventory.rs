//! The inventory record one named root produces for each installed
//! package instance (KTD4, KTD24): name, installed version, locator,
//! the import names later resolution maps, and the metadata the gates
//! need. No findings live here; scanning is U8.

use crate::model::DependencyRootKind;

/// One installed package instance in a named root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Report language of the package's source.
    pub package: String,
    /// Locator chain per KTD4 (version-free; `#<n>` joins at selection
    /// time, never here).
    pub locator: String,
    /// Installed version as read from metadata; emitted, never hashed.
    pub version: String,
    /// Relative path of the instance directory inside the root, for
    /// scoped discovery. Never an absolute path.
    pub rel: Vec<u8>,
    /// Top-level import names the instance provides (Python: from
    /// `RECORD` or `top_level.txt`; npm/cargo: the package name).
    pub imports: Vec<String>,
    /// Python: the normalized distribution name from `METADATA`
    /// (`pyyaml` for a `yaml` import); other kinds: None.
    pub distribution: Option<String>,
    /// Declared file hashes the verification gates compare (Python
    /// `RECORD`, Cargo `.cargo-checksum.json`). Path -> hash string.
    pub record: Vec<(Vec<u8>, String)>,
    /// `.crate` package checksum (vendor dirs) when present.
    pub package_checksum: Option<String>,
    /// Instance flags the report carries (unsupported layout reasons,
    /// name escapes, modified markers are set by later gates).
    pub flags: InstanceFlags,
}

/// Per-instance flags inventory and the gates attach.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstanceFlags {
    /// The instance's metadata could not be read within budget or
    /// parsed; resolution keeps it with reason unsupported layout
    /// rather than failing the root.
    pub unsupported: Option<String>,
    /// The instance's directory or package name is not UTF-8 or holds
    /// an escapable character; emitted names are the escaped form
    /// (KTD24).
    pub escaped_name: bool,
    /// A registry root holds this name+version under more than one
    /// index directory (KTD6).
    pub duplicate_index: bool,
    /// npm `.pnpm` or archive-only yarn layout: the root is detected
    /// but not supported this version.
    pub store_layout: bool,
}

/// A file in a root's import root that runs without an import
/// (KTD16): `.pth` with an `import` line, `sitecustomize.py`, and
/// `usercustomize.py`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoRunFile {
    /// File name relative to the root (the import root's child).
    pub file: String,
    /// The trigger kind.
    pub trigger: crate::model::AutoRunTrigger,
    /// Installing distribution, or `unattributed`.
    pub distribution: String,
}

/// The inventory of one named root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub kind: DependencyRootKind,
    pub instances: Vec<Instance>,
    /// Auto-run files found in the import root (Python roots only).
    pub auto_runs: Vec<AutoRunFile>,
    /// True when the listing hit the `inventory_entries` budget; every
    /// instance of this root is then flagged budget-exhausted by the
    /// caller (U8 consumes the flag).
    pub entries_exceeded: bool,
}

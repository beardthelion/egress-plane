//! Inside probe that enumerates an environment's egress and escape surface.
//!
//! The probe runs as an ordinary process inside the target environment and
//! reports every way code there could send data out or gain reach it should
//! not have, plus an explicit list of what it could not see. It reads local
//! state only in passive mode: finite sets (mounts, sockets, listeners, open
//! descriptors, environment variable names, capabilities, routes, resolvers,
//! devices) are enumerated completely and every member is classified by
//! declared rules or listed as unclassified. Anything unreadable is an
//! explicit unknown and makes the run incomplete.
//!
//! All filesystem reads go through one reader abstraction so the snapshot
//! corpus can replay any environment from `tree/` + `manifest.toml` +
//! `facts.toml` (KTD4). The snapshot entry point exists only under the
//! `snapshot` feature, which the shipped binary never enables.

#[cfg(feature = "snapshot")]
pub mod snapshot {
    //! Snapshot replay entry point for the corpus harness.
    //!
    //! Compiled only with `--features snapshot`; the release build cannot
    //! replay a fixture tree.

    use std::path::Path;

    use egress_core::model::ToolError;

    /// One call the snapshot reader performed, in call order.
    ///
    /// The corpus harness asserts two things on this log for every case
    /// (KTD13): no content read touches a credential or socket signal path
    /// (metadata and listing calls only, R17/KTD31), and no call of any kind
    /// touches a path under a no-touch filesystem (KTD26/R31).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ReadLogEntry {
        pub kind: ReadCall,
        /// Resolved path inside the case root: `/`-separated, no leading
        /// slash, allowlisted hops already applied.
        pub path: String,
    }

    /// Reader call kinds the read log records.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ReadCall {
        /// File contents.
        Read,
        /// Directory listing.
        List,
        /// File metadata (`lstat`-style).
        Metadata,
        /// Access check.
        Access,
        /// Symlink target.
        Readlink,
    }

    /// Rendered output of one snapshot run plus its read log.
    #[derive(Debug, Clone)]
    pub struct ScanOutput {
        /// The JSON report, exactly as stdout would carry it.
        pub json: String,
        /// The text report.
        pub text: String,
        /// Every call the snapshot reader performed, in order.
        pub read_log: Vec<ReadLogEntry>,
    }

    /// Runs the probe over one snapshot corpus case directory (one holding
    /// `tree/`, `facts.toml`, and an optional `manifest.toml`).
    ///
    /// U1 stub: every case fails as a tool error and sits in
    /// `fixtures/probe/pending.toml` until the reader and enumerators land.
    pub fn scan_case(_case_dir: &Path) -> Result<ScanOutput, ToolError> {
        Err(ToolError::Internal("snapshot probing is not implemented"))
    }
}

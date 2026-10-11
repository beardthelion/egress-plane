//! Per-file install-hash verification (KTD8): the URL-safe base64
//! encoder for `RECORD` hashes, the per-file comparison, and the gate
//! that maps (root kind, lock state, locked version, installed
//! version, hashes present) onto a strength or an unscanned reason.

use sha2::Digest;

use crate::model::{DependencyRootKind, UnscannedReason, VerificationStrength};

/// SHA-256 in the `RECORD` encoding: URL-safe base64, no padding.
pub fn sha256_b64u(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(43);
    for chunk in digest.chunks(3) {
        let n = match chunk.len() {
            3 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32,
            2 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8),
            1 => (chunk[0] as u32) << 16,
            _ => 0,
        };
        let width = if chunk.len() == 3 { 4 } else { chunk.len() + 1 };
        for i in (0..4).rev().take(width) {
            out.push(ALPHA[(n >> (i * 6)) as usize & 0x3f] as char);
        }
    }
    out
}

/// The result of comparing an instance's files against its install
/// record (KTD8): whether the record was complete and which mark the
/// comparison sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCheck {
    /// Every listed file read and matched; the strength can then be
    /// checksum-verified.
    pub complete: bool,
    /// The modified mark: a listed hash differs, a listed file is
    /// missing or unreadable, or a file under the instance is absent
    /// from the record.
    pub modified: bool,
}

/// Compare `files` (`rel` path -> bytes read through discovery code)
/// against the install `record`. Files under `__pycache__/` never mark
/// the package modified. A `record` path escaping the instance
/// (`../x`) is ignored.
pub fn compare_files(files: &[(Vec<u8>, Vec<u8>)], record: &[(Vec<u8>, String)]) -> FileCheck {
    let mut complete = !record.is_empty();
    let mut modified = false;
    let mut listed: Vec<&[u8]> = Vec::new();
    for (path, want) in record {
        if path.starts_with(b"../") || path.starts_with(b"/") {
            continue;
        }
        listed.push(path);
        match files.iter().find(|(p, _)| p == path) {
            Some((_, bytes)) => {
                if sha256_b64u(bytes) != *want {
                    modified = true;
                    complete = false;
                }
            }
            None => {
                modified = true;
                complete = false;
            }
        }
    }
    // A file under the package that no record lists marks modified,
    // `__pycache__/` excepted.
    for (path, _) in files {
        if path.starts_with(b"__pycache__/") || path.starts_with(b"../") || path.starts_with(b"/") {
            continue;
        }
        if !listed.contains(&path.as_slice()) {
            modified = true;
        }
    }
    FileCheck { complete, modified }
}

/// The gate of the verification diagram (U5 approach 3): given the
/// root kind, whether a supported lockfile governs, the locked
/// version when it does, and whether per-file hashes exist, emit the
/// strength or the unscanned reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// Scan with this strength; the modified mark comes from
    /// [`compare_files`] when hashes exist.
    Scan(VerificationStrength),
    /// Keep unscanned with this reason.
    Unscanned(UnscannedReason),
}

/// `locked` is the version a supported governing lockfile lists for
/// the name (after ecosystem normalization already applied); `None`
/// means no supported lockfile governs, or it does not lock the name.
/// `hashes` is whether the instance carries a per-file install record.
pub fn gate(
    kind: DependencyRootKind,
    lock: LockState,
    version_matches: Option<bool>,
    hashes: bool,
) -> Gate {
    use DependencyRootKind::*;
    match kind {
        CargoRegistry | CargoGit => match lock {
            LockState::Absent | LockState::Unsupported => {
                Gate::Unscanned(UnscannedReason::UnlockedSharedCache)
            }
            LockState::Unreadable => Gate::Unscanned(UnscannedReason::LockfileUnreadable),
            LockState::Governing => {
                if version_matches == Some(true) {
                    Gate::Scan(VerificationStrength::VersionMatched)
                } else {
                    Gate::Unscanned(UnscannedReason::VersionMismatch)
                }
            }
        },
        Npm | Python | CargoVendor => match lock {
            LockState::Unreadable => Gate::Unscanned(UnscannedReason::LockfileUnreadable),
            LockState::Absent | LockState::Unsupported => {
                Gate::Scan(VerificationStrength::Unlocked)
            }
            LockState::Governing => {
                if version_matches != Some(true) {
                    Gate::Unscanned(UnscannedReason::VersionMismatch)
                } else if hashes {
                    Gate::Scan(VerificationStrength::ChecksumVerified)
                } else {
                    Gate::Scan(VerificationStrength::VersionMatched)
                }
            }
        },
    }
}

/// The state of the governing lockfile for one instance's ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No lockfile of this ecosystem sits in an ancestor directory of
    /// the importer.
    Absent,
    /// A lockfile exists but its format version is not supported; it
    /// is treated as absent (KTD7, the support matrix's middle column).
    Unsupported,
    /// A supported lockfile failed to parse, carries an unknown
    /// version, or exceeded `lockfile_bytes`; the section lists a
    /// diagnostic and every governed package stays unscanned.
    Unreadable,
    /// A supported lockfile parsed and governs.
    Governing,
}

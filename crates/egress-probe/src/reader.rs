//! The one reader abstraction every probe input goes through (KTD4).
//!
//! Enumerators, signals, and attribute sources never touch the filesystem
//! directly. They call a [`Reader`], which resolves the allowlisted
//! one-hop symlink policy (KTD11), applies the kernel-filesystem checks
//! (KTD24), enforces the no-touch gate once the mount table is known
//! (KTD26), resolves symlinked credential and socket signal paths for
//! metadata only (KTD31), refuses content reads under credential signal
//! paths, and records every performed call in a read log for the corpus
//! harness (KTD13). The same trait is implemented by the live reader over
//! a real root and by the snapshot reader over a case's `tree/` and
//! manifest overlay; tests supply their own implementation.
//!
//! Every call returns a typed outcome: `Ok` or a [`Denial`] naming why the
//! call produced nothing, so an enumerator can map it to an absent
//! signature or to one unknown reason of the closed vocabulary (KTD3).
//! `ENOENT` is the only errno that reads as absent; `EMFILE` and `ENFILE`
//! read as a descriptor limit, never as "not present" (KTD9).

use std::path::Path;

pub use egress_core::discover::open::NodeType;
use egress_core::discover::open::{AccessCheck, NodeStat, ReadFail, RootDir};
use egress_core::model::ToolError;

use crate::facts::{Fact, Facts, Platform};
use crate::integrity;

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

/// One call the reader performed, in call order (KTD13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadLogEntry {
    pub kind: ReadCall,
    /// The resolved in-root path: `/`-separated, no leading slash,
    /// allowlisted hops already applied.
    pub path: String,
}

/// Why a reader call produced no result. Each variant maps to an absent
/// signature or one unknown reason of the closed vocabulary (KTD3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// `ENOENT` at the target: the source's declared absent signature
    /// decides whether this is complete-empty or an unknown.
    Absent,
    /// Any other errno, preserved.
    Unreadable(i32),
    /// `EMFILE` or `ENFILE`: descriptor exhaustion must never read as
    /// "not present" (KTD9).
    DescriptorLimit,
    /// The final component exists but is not a regular file, or a walk
    /// component was not a directory.
    NotRegular,
    /// The file exceeds the read bound.
    TooLarge,
    /// The symlink policy refused the path (KTD11, KTD31).
    LinkPolicy,
    /// A handle under `proc/` or `sys/` reported the wrong filesystem
    /// (KTD24).
    FsTypeMismatch,
    /// `proc/self` did not resolve to the probe's pid (KTD24).
    ProcSelfMismatch,
    /// A path component sits on a network or FUSE filesystem the passive
    /// probe never touches (KTD26).
    NotTouched,
    /// The mount table is unknown or not yet enumerated, so the gate
    /// cannot decide (KTD26).
    DependsOnUnknown,
}

/// Metadata for one in-root path: raw type, mode, owner, size, and the
/// device pair for character and block nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub kind: NodeType,
    /// Raw `st_mode` bits (type plus permissions).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// `(major, minor)` for character and block nodes.
    pub device: Option<(u32, u32)>,
}

/// Which access bits a caller asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessMask {
    pub read: bool,
    pub write: bool,
}

impl AccessMask {
    pub const READ: Self = Self {
        read: true,
        write: false,
    };
    pub const WRITE: Self = Self {
        read: false,
        write: true,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
    };
}

/// The result of an access check on a real object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessResult {
    /// Every requested bit is permitted.
    Granted,
    /// The check ran and was refused.
    Refused,
}

/// One entry of the mount table the no-touch gate consults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Mount point as in-root components.
    pub point: Vec<Vec<u8>>,
    pub fstype: String,
}

impl Mount {
    pub fn new(point: &str, fstype: &str) -> Mount {
        Mount {
            point: point
                .split('/')
                .filter(|c| !c.is_empty())
                .map(|c| c.as_bytes().to_vec())
                .collect(),
            fstype: fstype.to_string(),
        }
    }

    pub fn from_bytes(point: &[u8], fstype: &str) -> Mount {
        Mount {
            point: point
                .split(|b| *b == b'/')
                .filter(|c| !c.is_empty())
                .map(|c| c.to_vec())
                .collect(),
            fstype: fstype.to_string(),
        }
    }
}

/// The reader interface every probe source uses. Implementations: the live
/// reader ([`SharedReader`] over [`FsBackend`]) and, behind the `snapshot`
/// feature, the snapshot reader. Tests supply their own.
pub trait Reader {
    /// Bounded content read.
    fn read(&mut self, path: &[u8], limit: u64) -> Result<Vec<u8>, Denial>;
    /// Directory listing with per-entry metadata.
    fn list(&mut self, path: &[u8]) -> Result<Vec<(Vec<u8>, Meta)>, Denial>;
    /// `lstat` of a path.
    fn metadata(&mut self, path: &[u8]) -> Result<Meta, Denial>;
    /// Access check that never follows a swapped-in final symlink.
    fn access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial>;
    /// Target bytes of a symlink.
    fn readlink(&mut self, path: &[u8]) -> Result<Vec<u8>, Denial>;
    /// Metadata of a credential-path or socket signal path, resolving a
    /// symlink chain metadata-only per KTD31.
    fn signal_metadata(&mut self, path: &[u8]) -> Result<Meta, Denial>;
    /// Access of a signal path under the same KTD31 chain resolution.
    fn signal_access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial>;
    /// The fact set this run consumes.
    fn facts(&self) -> &Facts;
    /// Every call performed so far, in order (KTD13).
    fn read_log(&self) -> &[ReadLogEntry];
    /// Arms the no-touch gate with the enumerated mount table (KTD26).
    fn arm_mounts(&mut self, mounts: Vec<Mount>);
    /// Arms the gate in its mounts-unknown form: `proc/` and `sys/`
    /// proceed under the kernel checks and everything else is refused.
    fn mounts_unknown(&mut self);
    /// Whether the `proc/self` hop was accepted through the ancestor pid
    /// namespace `NSpid` check (KTD24); reported as a layer attribute.
    fn accepted_ancestor_pidns(&self) -> bool;
}

// ---------------------------------------------------------------------------
// The policy tables: allowlisted hops, no-touch filesystems, and the
// metadata-only credential prefixes (KTD11, KTD26).
// ---------------------------------------------------------------------------

/// Whether an allowlisted link is a directory prefix (`proc/self`,
/// `var/run`) or a file valid only as the path's final component
/// (`etc/resolv.conf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HopKind {
    Dir,
    File,
}

/// The permitted normalized targets of an allowlisted link.
#[derive(Debug, Clone)]
pub(crate) enum HopTargets {
    /// `proc/self`: exactly `proc/<n>`, checked against the probe's pid or
    /// the ancestor `NSpid` chain (KTD24).
    ProcSelf,
    Exact(Vec<Vec<Vec<u8>>>),
}

#[derive(Debug, Clone)]
pub(crate) struct HopLink {
    pub path: Vec<Vec<u8>>,
    pub kind: HopKind,
    pub targets: HopTargets,
}

fn comps(parts: &[&str]) -> Vec<Vec<u8>> {
    parts.iter().map(|p| p.as_bytes().to_vec()).collect()
}

/// The fixed reader policy for one platform (KTD11, KTD26, KTD31).
#[derive(Debug, Clone)]
pub(crate) struct Policy {
    pub platform: Platform,
    pub hop_links: Vec<HopLink>,
    /// Filesystem types never touched; `fuse.` prefixes match too.
    pub no_touch_fstypes: Vec<String>,
    /// Resolved path prefixes whose contents are never read (R17).
    pub credential_dirs: Vec<Vec<Vec<u8>>>,
    /// macOS home-relative socket suffixes matched lexically as
    /// `Users/<one component>/<suffix>` (KTD31).
    pub home_socket_suffixes: Vec<Vec<Vec<u8>>>,
}

impl Policy {
    pub fn for_platform(platform: Platform) -> Policy {
        match platform {
            Platform::Linux => Policy::linux(),
            Platform::Macos => Policy::macos(),
        }
    }

    pub fn linux() -> Policy {
        Policy {
            platform: Platform::Linux,
            hop_links: vec![
                HopLink {
                    path: comps(&["proc", "self"]),
                    kind: HopKind::Dir,
                    targets: HopTargets::ProcSelf,
                },
                HopLink {
                    path: comps(&["proc", "net"]),
                    kind: HopKind::Dir,
                    targets: HopTargets::Exact(vec![comps(&["proc", "self", "net"])]),
                },
                HopLink {
                    path: comps(&["etc", "resolv.conf"]),
                    kind: HopKind::File,
                    targets: HopTargets::Exact(vec![
                        comps(&["run", "systemd", "resolve", "stub-resolv.conf"]),
                        comps(&["run", "systemd", "resolve", "resolv.conf"]),
                        comps(&["run", "resolvconf", "resolv.conf"]),
                        comps(&["run", "NetworkManager", "resolv.conf"]),
                        comps(&["etc", "resolvconf", "run", "resolv.conf"]),
                    ]),
                },
                HopLink {
                    path: comps(&["var", "run"]),
                    kind: HopKind::Dir,
                    targets: HopTargets::Exact(vec![comps(&["run"])]),
                },
                HopLink {
                    path: comps(&["sys", "class", "dmi", "id"]),
                    kind: HopKind::Dir,
                    targets: HopTargets::Exact(vec![comps(&[
                        "sys", "devices", "virtual", "dmi", "id",
                    ])]),
                },
            ],
            no_touch_fstypes: [
                "nfs",
                "nfs4",
                "cifs",
                "smb3",
                "smbfs",
                "ceph",
                "glusterfs",
                "lustre",
                "afs",
                "autofs",
                "fuse",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            credential_dirs: vec![
                comps(&["run", "secrets"]),
                comps(&["var", "run", "secrets"]),
            ],
            home_socket_suffixes: Vec::new(),
        }
    }

    pub fn macos() -> Policy {
        Policy {
            platform: Platform::Macos,
            hop_links: vec![
                HopLink {
                    path: comps(&["etc"]),
                    kind: HopKind::Dir,
                    targets: HopTargets::Exact(vec![comps(&["private", "etc"])]),
                },
                HopLink {
                    path: comps(&["var"]),
                    kind: HopKind::Dir,
                    targets: HopTargets::Exact(vec![comps(&["private", "var"])]),
                },
                HopLink {
                    path: comps(&["tmp"]),
                    kind: HopKind::Dir,
                    targets: HopTargets::Exact(vec![comps(&["private", "tmp"])]),
                },
                HopLink {
                    path: comps(&["private", "etc", "resolv.conf"]),
                    kind: HopKind::File,
                    targets: HopTargets::Exact(vec![comps(&[
                        "private",
                        "var",
                        "run",
                        "resolv.conf",
                    ])]),
                },
            ],
            no_touch_fstypes: [
                "smbfs", "nfs", "afpfs", "webdav", "osxfuse", "macfuse", "autofs",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            credential_dirs: vec![
                comps(&["run", "secrets"]),
                comps(&["var", "run", "secrets"]),
            ],
            home_socket_suffixes: vec![
                comps(&[".docker", "run", "docker.sock"]),
                comps(&[".colima", "default", "docker.sock"]),
                comps(&[".rd", "docker.sock"]),
                comps(&[".orbstack", "run", "docker.sock"]),
                comps(&[
                    ".local",
                    "share",
                    "containers",
                    "podman",
                    "machine",
                    "podman.sock",
                ]),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Backends: raw calls on an already-resolved path plus the filesystem type
// each opened handle reported.
// ---------------------------------------------------------------------------

/// A backend failure; the reader maps each onto a [`Denial`]. An
/// implementation seam, not part of the reader contract.
#[doc(hidden)]
#[derive(Debug)]
pub enum Fail {
    /// A raw errno.
    Errno(i32),
    /// The final component is not a regular file; carries its type.
    NotRegular(NodeType),
    /// The final component of an access check is a symlink.
    IsSymlink,
    TooLarge,
}

/// The raw-call seam a [`SharedReader`] drives: an implementation detail
/// behind [`LiveReader`] and the snapshot reader, not part of the reader
/// contract.
#[doc(hidden)]
pub trait Backend {
    fn metadata(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Meta, Fail>;
    fn read(&mut self, path: &[u8], limit: u64, fs: &mut Vec<String>) -> Result<Vec<u8>, Fail>;
    fn list(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Vec<(Vec<u8>, Meta)>, Fail>;
    fn access(
        &mut self,
        path: &[u8],
        mask: AccessMask,
        fs: &mut Vec<String>,
    ) -> Result<AccessResult, Fail>;
    fn readlink(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Vec<u8>, Fail>;
    /// The mount table, for backends that report filesystem types from it
    /// (the snapshot overlay).
    fn set_mounts(&mut self, _mounts: &[Mount]) {}
    /// Whether a resolved path sits under a virtual no-touch overlay node
    /// (the manifest `fs` overrides; KTD12). Always false on a real root.
    fn overlay_no_touch(&self, _path: &[u8]) -> bool {
        false
    }
}

fn meta_of(st: NodeStat) -> Meta {
    Meta {
        kind: st.kind,
        mode: st.mode,
        uid: st.uid,
        gid: st.gid,
        size: st.size,
        device: match st.kind {
            NodeType::Char | NodeType::Block => Some((dev_major(st.rdev), dev_minor(st.rdev))),
            _ => None,
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn dev_major(rdev: u64) -> u32 {
    libc::major(rdev)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn dev_minor(rdev: u64) -> u32 {
    libc::minor(rdev)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn dev_major(rdev: u64) -> u32 {
    // BSD dev_t layout.
    ((rdev >> 24) & 0xff) as u32
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn dev_minor(rdev: u64) -> u32 {
    (rdev & 0xff_ff_ff) as u32
}

fn errno(e: std::io::Error) -> Fail {
    Fail::Errno(e.raw_os_error().unwrap_or(0))
}

/// The backend over a real [`RootDir`]: live reads and the snapshot
/// reader's underlying `tree/` calls.
pub struct FsBackend {
    root: RootDir,
}

impl FsBackend {
    pub fn new(root: RootDir) -> FsBackend {
        FsBackend { root }
    }
}

impl Backend for FsBackend {
    fn metadata(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Meta, Fail> {
        self.root.lstat_full(path, fs).map(meta_of).map_err(errno)
    }

    fn read(&mut self, path: &[u8], limit: u64, fs: &mut Vec<String>) -> Result<Vec<u8>, Fail> {
        self.root
            .read_file_errno(path, limit, fs)
            .map_err(|f| match f {
                ReadFail::NotRegular(kind) => Fail::NotRegular(kind),
                ReadFail::TooLarge => Fail::TooLarge,
                ReadFail::Errno(e) => Fail::Errno(e),
            })
    }

    fn list(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Vec<(Vec<u8>, Meta)>, Fail> {
        self.root
            .list_dir_full(path, fs)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|(name, st)| (name, meta_of(st)))
                    .collect()
            })
            .map_err(errno)
    }

    fn access(
        &mut self,
        path: &[u8],
        mask: AccessMask,
        fs: &mut Vec<String>,
    ) -> Result<AccessResult, Fail> {
        match self.root.access_nofollow(path, mask.read, mask.write, fs) {
            Ok(AccessCheck::Granted) => Ok(AccessResult::Granted),
            Ok(AccessCheck::Refused) => Ok(AccessResult::Refused),
            Ok(AccessCheck::Symlink) => Err(Fail::IsSymlink),
            Err(e) => Err(errno(e)),
        }
    }

    fn readlink(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Vec<u8>, Fail> {
        self.root.readlink_observed(path, fs).map_err(errno)
    }
}

// ---------------------------------------------------------------------------
// The shared reader machinery over a backend: the gate, the hop resolver,
// the kernel-filesystem check, the KTD31 chain, and the read log.
// ---------------------------------------------------------------------------

/// The mount-table gate state (KTD26).
#[derive(Debug)]
enum GateState {
    /// The mount table has not been enumerated yet. Only the mountinfo
    /// read itself is allowed through, which arms the gate.
    Unarmed,
    /// The mount table is known; every path component is checked against
    /// the containing mount's filesystem type.
    Armed { mounts: Vec<Mount> },
    /// Mount enumeration failed: `proc/` and `sys/` proceed under the
    /// kernel checks and every other call is refused.
    Unknown,
}

fn initial_gate(facts: &Facts) -> GateState {
    match facts.platform {
        Some(Platform::Macos) => match facts.mounts.as_ref().and_then(Fact::read) {
            Some(entries) => GateState::Armed {
                mounts: entries
                    .iter()
                    .map(|m| Mount::from_bytes(&m.path, &m.fstype))
                    .collect(),
            },
            None => GateState::Unknown,
        },
        _ => GateState::Unarmed,
    }
}

/// Splits a root-relative path into components and rejects anything a
/// caller must not construct (empty components, `.`, `..`).
fn split_path(path: &[u8]) -> Result<Vec<Vec<u8>>, Denial> {
    let parts: Vec<Vec<u8>> = path.split(|b| *b == b'/').map(<[u8]>::to_vec).collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return Err(Denial::Unreadable(libc::EINVAL));
    }
    Ok(parts)
}

/// Joins resolved components for the backend call and the read log.
fn join_path(comps: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    out
}

fn has_prefix(path: &[Vec<u8>], prefix: &[Vec<u8>]) -> bool {
    path.len() >= prefix.len() && &path[..prefix.len()] == prefix
}

/// Normalizes link text against the link's parent directory: `..` and `.`
/// are resolved lexically, an absolute target is re-rooted inside the root,
/// and a `..` that climbs past the root is refused (KTD11).
fn normalize_target(parent: &[Vec<u8>], text: &[u8]) -> Result<Vec<Vec<u8>>, Denial> {
    let mut out: Vec<Vec<u8>> = if text.first() == Some(&b'/') {
        Vec::new()
    } else {
        parent.to_vec()
    };
    for part in text.split(|b| *b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                if out.pop().is_none() {
                    return Err(Denial::LinkPolicy);
                }
            }
            c => out.push(c.to_vec()),
        }
    }
    Ok(out)
}

/// The containing mount of a resolved path prefix: the longest mount point
/// that is a component prefix.
fn containing_mount<'a>(mounts: &'a [Mount], comps: &[Vec<u8>]) -> Option<&'a str> {
    mounts
        .iter()
        .filter(|m| has_prefix(comps, &m.point))
        .max_by_key(|m| m.point.len())
        .map(|m| m.fstype.as_str())
}

/// Whether a filesystem type is one the passive probe never touches:
/// network filesystems, autofs, and any `fuse.` flavor (KTD26).
fn is_no_touch(policy: &Policy, fstype: &str) -> bool {
    policy.no_touch_fstypes.iter().any(|t| t == fstype) || fstype.starts_with("fuse.")
}

fn denial_of(fail: Fail) -> Denial {
    match fail {
        Fail::Errno(e) => match e {
            libc::ENOENT => Denial::Absent,
            libc::EMFILE | libc::ENFILE => Denial::DescriptorLimit,
            libc::ELOOP | libc::EMLINK => Denial::LinkPolicy,
            e => Denial::Unreadable(e),
        },
        Fail::NotRegular(NodeType::Symlink) | Fail::IsSymlink => Denial::LinkPolicy,
        Fail::NotRegular(_) => Denial::NotRegular,
        Fail::TooLarge => Denial::TooLarge,
    }
}

/// The reader over one backend: every call resolves allowlisted hops,
/// passes the mount-table gate and the kernel-filesystem checks, and lands
/// in the read log. `B` is [`FsBackend`] live or the snapshot backend.
pub struct SharedReader<B> {
    backend: B,
    policy: Policy,
    facts: Facts,
    log: Vec<ReadLogEntry>,
    gate: GateState,
    /// The cached `proc/self` verdict: `Ok(pid)` when the link names the
    /// probe's own pid (or the accepted ancestor chain), else the denial
    /// every `proc/self` read returns (KTD24).
    proc_self: Option<Result<u64, Denial>>,
    ancestor_pidns: bool,
}

impl<B: Backend> SharedReader<B> {
    pub fn new(backend: B, facts: Facts) -> SharedReader<B> {
        let policy = Policy::for_platform(facts.platform.unwrap_or(Platform::Linux));
        let gate = initial_gate(&facts);
        SharedReader {
            backend,
            policy,
            facts,
            log: Vec::new(),
            gate,
            proc_self: None,
            ancestor_pidns: false,
        }
    }

    /// The gate for one resolved call (KTD26): the mount-table state
    /// decides which paths may proceed at all, then the manifest overlay's
    /// no-touch nodes refuse anything left (KTD12).
    fn gate_check(&self, comps: &[Vec<u8>], path: &[u8]) -> Result<(), Denial> {
        match &self.gate {
            GateState::Unarmed => match comps.first().map(Vec::as_slice) {
                Some(b"proc") => {}
                _ => return Err(Denial::DependsOnUnknown),
            },
            GateState::Unknown => match comps.first().map(Vec::as_slice) {
                Some(b"proc") | Some(b"sys") => {}
                _ => return Err(Denial::DependsOnUnknown),
            },
            GateState::Armed { mounts } => {
                for i in 1..=comps.len() {
                    if let Some(fs) = containing_mount(mounts, &comps[..i])
                        && is_no_touch(&self.policy, fs)
                    {
                        return Err(Denial::NotTouched);
                    }
                }
            }
        }
        if self.backend.overlay_no_touch(path) {
            return Err(Denial::NotTouched);
        }
        Ok(())
    }

    /// Performs one backend call: gates it, runs it, records it, then
    /// applies the kernel-filesystem check to the handles it opened
    /// (KTD24). The log holds only performed calls.
    fn perform<T>(
        &mut self,
        kind: ReadCall,
        comps: &[Vec<u8>],
        op: impl FnOnce(&mut B, &[u8], &mut Vec<String>) -> Result<T, Fail>,
    ) -> Result<T, Denial> {
        let path = join_path(comps);
        self.gate_check(comps, &path)?;
        let mut fs = Vec::new();
        let result = op(&mut self.backend, &path, &mut fs);
        self.log.push(ReadLogEntry {
            kind,
            path: String::from_utf8_lossy(&path).into_owned(),
        });
        if let Some(expected) = integrity::expected_fs(&comps[0])
            && !integrity::fs_matches(&fs, expected)
        {
            return Err(Denial::FsTypeMismatch);
        }
        match result {
            Ok(v) => Ok(v),
            // `openat` reports ENOTDIR for a mid-walk symlink as well as a
            // real non-directory component, so the failing component's type
            // decides between link-policy and not-regular.
            Err(Fail::Errno(libc::ENOTDIR)) => Err(self.notdir_denial(comps)),
            Err(f) => Err(denial_of(f)),
        }
    }

    /// Distinguishes a mid-path symlink (link-policy) from a mid-path
    /// non-directory (not-regular) after an ENOTDIR failure.
    fn notdir_denial(&mut self, comps: &[Vec<u8>]) -> Denial {
        for i in 1..=comps.len() {
            match self.internal_metadata(&comps[..i]) {
                Ok(st) if st.kind == NodeType::Symlink => return Denial::LinkPolicy,
                Ok(st) if st.kind != NodeType::Dir => return Denial::NotRegular,
                Ok(_) => {}
                Err(d) => return d,
            }
        }
        Denial::NotRegular
    }

    fn internal_readlink(&mut self, comps: &[Vec<u8>]) -> Result<Vec<u8>, Denial> {
        self.perform(ReadCall::Readlink, comps, |b, p, fs| b.readlink(p, fs))
    }

    fn internal_metadata(&mut self, comps: &[Vec<u8>]) -> Result<Meta, Denial> {
        self.perform(ReadCall::Metadata, comps, |b, p, fs| b.metadata(p, fs))
    }

    fn internal_read(&mut self, comps: &[Vec<u8>], limit: u64) -> Result<Vec<u8>, Denial> {
        self.perform(ReadCall::Read, comps, move |b, p, fs| b.read(p, limit, fs))
    }

    /// Resolves the allowlisted one-hop links in a path (KTD11). Each
    /// allowlisted link is taken at most once per call, its normalized
    /// target must be one of the declared set (or the `proc/<n>` shape for
    /// `proc/self`), must not name a credential prefix, and must not sit on
    /// a no-touch filesystem. A file-kind hop (`etc/resolv.conf`) also
    /// verifies the resolved target is a regular file, which makes a
    /// second hop, a device, or a FIFO at the target a policy violation.
    fn resolve(&mut self, mut comps: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, Denial> {
        let mut file_hop = false;
        let mut hops = 0usize;
        'outer: loop {
            for i in (1..=comps.len()).rev() {
                let Some(entry) =
                    self.policy.hop_links.iter().find(|e| {
                        e.path == comps[..i] && (e.kind == HopKind::Dir || i == comps.len())
                    })
                else {
                    continue;
                };
                let entry = entry.clone();
                match self.internal_readlink(&comps[..i]) {
                    Ok(text) => {
                        let target = normalize_target(&comps[..i - 1], &text)?;
                        self.check_hop_target(&entry, &target)?;
                        let mut next = target;
                        next.extend_from_slice(&comps[i..]);
                        comps = next;
                        file_hop = entry.kind == HopKind::File;
                        hops += 1;
                        if hops > 16 {
                            return Err(Denial::LinkPolicy);
                        }
                        continue 'outer;
                    }
                    // Not a symlink: the component is ordinary, keep
                    // scanning shorter prefixes.
                    Err(Denial::Unreadable(e)) if e == libc::EINVAL => continue,
                    Err(d) => return Err(d),
                }
            }
            break;
        }
        if file_hop {
            let st = self.internal_metadata(&comps)?;
            if st.kind != NodeType::File {
                return Err(Denial::LinkPolicy);
            }
        }
        Ok(comps)
    }

    /// The target checks of KTD11: the declared target set (or the
    /// `proc/self` pid check), the credential prefixes, and the no-touch
    /// mounts.
    fn check_hop_target(&mut self, entry: &HopLink, target: &[Vec<u8>]) -> Result<(), Denial> {
        match &entry.targets {
            HopTargets::ProcSelf => {
                self.proc_self_target(target)?;
            }
            HopTargets::Exact(set) => {
                if !set.iter().any(|t| t == target) {
                    return Err(Denial::LinkPolicy);
                }
            }
        }
        if self.under_credential_dir(target) {
            return Err(Denial::LinkPolicy);
        }
        if let GateState::Armed { mounts } = &self.gate {
            for i in 1..=target.len() {
                if let Some(fs) = containing_mount(mounts, &target[..i])
                    && is_no_touch(&self.policy, fs)
                {
                    return Err(Denial::LinkPolicy);
                }
            }
        }
        Ok(())
    }

    /// Whether a resolved path sits under a credential prefix (contents
    /// are never read; R17).
    fn under_credential_dir(&self, comps: &[Vec<u8>]) -> bool {
        self.policy
            .credential_dirs
            .iter()
            .any(|d| has_prefix(comps, d))
    }

    /// The `proc/self` verdict, computed once and reused for every
    /// `proc/self` read of the run (KTD24).
    fn proc_self_target(&mut self, target: &[Vec<u8>]) -> Result<u64, Denial> {
        if let Some(r) = &self.proc_self {
            return *r;
        }
        let result = self.check_proc_self_target(target);
        self.proc_self = Some(result);
        result
    }

    fn check_proc_self_target(&mut self, target: &[Vec<u8>]) -> Result<u64, Denial> {
        // The permitted shape is proc/<n>; anything else is a policy
        // violation, not a pid mismatch.
        if target.len() != 2
            || target[0] != b"proc"
            || target[1].is_empty()
            || !target[1].iter().all(u8::is_ascii_digit)
        {
            return Err(Denial::LinkPolicy);
        }
        let Ok(n) = String::from_utf8_lossy(&target[1]).parse::<u64>() else {
            return Err(Denial::LinkPolicy);
        };
        let Some(pid) = self.facts.pid() else {
            return Err(Denial::ProcSelfMismatch);
        };
        if n == pid {
            return Ok(n);
        }
        // An ancestor pid namespace shows the probe under a different
        // outer pid; accept it only through the NSpid check (KTD24).
        let status = self.internal_read(
            &[b"proc".to_vec(), target[1].clone(), b"status".to_vec()],
            1 << 20,
        );
        let Ok(status) = status else {
            return Err(Denial::ProcSelfMismatch);
        };
        if integrity::nspid_accepts(&status, n, pid) {
            self.ancestor_pidns = true;
            Ok(n)
        } else {
            Err(Denial::ProcSelfMismatch)
        }
    }

    /// The public call path: mountinfo is the only call allowed before the
    /// mount table is armed; everything else waits for the gate.
    fn call<T>(
        &mut self,
        kind: ReadCall,
        path: &[u8],
        op: impl FnOnce(&mut B, &[u8], &mut Vec<String>) -> Result<T, Fail>,
    ) -> Result<T, Denial> {
        let comps = split_path(path)?;
        if let GateState::Unarmed = self.gate {
            let mountinfo = kind == ReadCall::Read
                && comps == [b"proc".to_vec(), b"self".to_vec(), b"mountinfo".to_vec()];
            if !mountinfo {
                return Err(Denial::DependsOnUnknown);
            }
        }
        let resolved = self.resolve(comps)?;
        if resolved.is_empty() {
            return Err(Denial::LinkPolicy);
        }
        if kind == ReadCall::Read && self.under_credential_dir(&resolved) {
            return Err(Denial::LinkPolicy);
        }
        self.perform(kind, &resolved, op)
    }

    /// Resolves a signal path's symlink chain metadata-only (KTD31): the
    /// allowlisted hops run first and do not count, then up to two more
    /// hops resolve, each target must lie under the signal path's parent
    /// directory or match a declared macOS home-socket suffix, and every
    /// hop is gated like any call. The result is the resolved path for a
    /// metadata or access call, never a content read.
    fn signal_chain(&mut self, path: &[u8]) -> Result<Vec<Vec<u8>>, Denial> {
        let comps = split_path(path)?;
        let mut resolved = self.resolve(comps)?;
        if resolved.is_empty() {
            return Err(Denial::LinkPolicy);
        }
        let parent = resolved[..resolved.len() - 1].to_vec();
        let mut hops = 0usize;
        loop {
            let mut linked = false;
            for i in 0..resolved.len() {
                let prefix = resolved[..=i].to_vec();
                if self.internal_metadata(&prefix)?.kind != NodeType::Symlink {
                    continue;
                }
                let text = self.internal_readlink(&prefix)?;
                let target = normalize_target(&prefix[..i], &text)?;
                if !(has_prefix(&target, &parent) || self.is_home_socket(&target)) {
                    return Err(Denial::LinkPolicy);
                }
                hops += 1;
                if hops > 2 {
                    return Err(Denial::LinkPolicy);
                }
                let mut next = target;
                next.extend_from_slice(&resolved[i + 1..]);
                resolved = next;
                linked = true;
                break;
            }
            if !linked {
                return Ok(resolved);
            }
        }
    }

    /// Whether a hop target matches a declared macOS home-relative socket
    /// suffix as `Users/<one component>/<suffix>` (KTD31).
    fn is_home_socket(&self, comps: &[Vec<u8>]) -> bool {
        self.policy.platform == Platform::Macos
            && comps.len() > 2
            && comps[0] == b"Users"
            && self
                .policy
                .home_socket_suffixes
                .iter()
                .any(|s| comps[2..] == s[..])
    }
}

impl<B: Backend> Reader for SharedReader<B> {
    fn read(&mut self, path: &[u8], limit: u64) -> Result<Vec<u8>, Denial> {
        self.call(ReadCall::Read, path, move |b, p, fs| b.read(p, limit, fs))
    }

    fn list(&mut self, path: &[u8]) -> Result<Vec<(Vec<u8>, Meta)>, Denial> {
        self.call(ReadCall::List, path, |b, p, fs| b.list(p, fs))
    }

    fn metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        self.call(ReadCall::Metadata, path, |b, p, fs| b.metadata(p, fs))
    }

    fn access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial> {
        self.call(ReadCall::Access, path, move |b, p, fs| {
            b.access(p, mask, fs)
        })
    }

    fn readlink(&mut self, path: &[u8]) -> Result<Vec<u8>, Denial> {
        self.call(ReadCall::Readlink, path, |b, p, fs| b.readlink(p, fs))
    }

    fn signal_metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        let resolved = self.signal_chain(path)?;
        self.perform(ReadCall::Metadata, &resolved, |b, p, fs| b.metadata(p, fs))
    }

    fn signal_access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial> {
        let resolved = self.signal_chain(path)?;
        self.perform(ReadCall::Access, &resolved, move |b, p, fs| {
            b.access(p, mask, fs)
        })
    }

    fn facts(&self) -> &Facts {
        &self.facts
    }

    fn read_log(&self) -> &[ReadLogEntry] {
        &self.log
    }

    fn arm_mounts(&mut self, mounts: Vec<Mount>) {
        self.backend.set_mounts(&mounts);
        self.gate = GateState::Armed { mounts };
    }

    fn mounts_unknown(&mut self) {
        self.gate = GateState::Unknown;
    }

    fn accepted_ancestor_pidns(&self) -> bool {
        self.ancestor_pidns
    }
}

/// The live reader: the shared machinery over a [`RootDir`] opened on the
/// host's real root.
pub type LiveReader = SharedReader<FsBackend>;

impl SharedReader<FsBackend> {
    /// Opens the live reader on `/` with a host fact set (the pid and the
    /// platform fields drive the `proc/self` check and the policy).
    pub fn live(facts: Facts) -> Result<Self, ToolError> {
        let root = RootDir::open(Path::new("/"))?;
        Ok(Self::new(FsBackend::new(root), facts))
    }
}

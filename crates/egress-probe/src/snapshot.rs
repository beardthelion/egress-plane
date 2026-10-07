//! Snapshot replay: the same probing pipeline as live, driven by a case
//! directory instead of the host (KTD4). Everything in this module is
//! behind the `snapshot` cargo feature so the released binary cannot
//! replay a snapshot.
//!
//! A case is a `tree/` directory of real files and links (the snapshot
//! root), a `facts.toml` with the normalized fact set, and an optional
//! `manifest.toml` overlay describing virtual nodes the filesystem cannot
//! hold: sockets, FIFOs, device nodes, `meta` nodes that override metadata
//! or the reported filesystem of an existing tree node, and `error` nodes
//! that force an errno on calls that reach them (KTD12).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use egress_core::discover::open::{NodeType, RootDir};
use egress_core::model::ToolError;
use serde::Deserialize;

use crate::facts;
use crate::reader::{
    AccessMask, AccessResult, Backend, Fail, FsBackend, Meta, Mount, SharedReader,
};
pub use crate::reader::{ReadCall, ReadLogEntry};

/// Rendered output of one snapshot run plus its read log.
#[derive(Debug)]
pub struct ScanOutput {
    /// The JSON report, exactly as stdout would carry it.
    pub json: String,
    /// The text report.
    pub text: String,
    /// Every call the snapshot reader performed, in order.
    pub read_log: Vec<ReadLogEntry>,
}

/// Runs a snapshot scan of a case directory: not implemented until the
/// scan pipeline unit. The harness compiles against this signature.
pub fn scan_case(_case_dir: &Path) -> Result<ScanOutput, ToolError> {
    Err(ToolError::Internal("snapshot probing is not implemented"))
}

// ---------------------------------------------------------------------------
// manifest.toml
// ---------------------------------------------------------------------------

/// One node of the manifest overlay (KTD12).
#[derive(Debug, Clone)]
pub struct ManifestNode {
    /// The in-root path as components.
    pub path: Vec<Vec<u8>>,
    pub kind: ManifestKind,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub access: Option<NodeAccess>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    /// The filesystem name calls under this node report (KTD12). `local`
    /// means "report whatever the real `tree/` mount is".
    pub fs: Option<String>,
    /// The errno an `error` node forces.
    pub errno: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    Socket,
    Fifo,
    Char,
    Block,
    /// An existing tree node whose metadata or reported filesystem is
    /// overridden.
    Meta,
    /// A node whose calls fail with `errno`.
    Error,
}

impl ManifestKind {
    /// Whether the node is a virtual object (not `meta`, not `error`).
    fn is_virtual(self) -> bool {
        matches!(self, Self::Socket | Self::Fifo | Self::Char | Self::Block)
    }
}

/// The declared access a manifest node returns for an access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAccess {
    None,
    Read,
    Write,
}

/// The parsed manifest: nodes keyed by joined path bytes, plus the parent
/// index a listing merge needs.
#[derive(Debug, Default)]
pub struct Manifest {
    nodes: BTreeMap<Vec<u8>, ManifestNode>,
    /// Joined parent path -> names of virtual child nodes.
    virtual_children: BTreeMap<Vec<u8>, Vec<Vec<u8>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(default)]
    node: Vec<RawNode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    access: Option<String>,
    major: Option<u32>,
    minor: Option<u32>,
    fs: Option<String>,
    errno: Option<String>,
}

fn errno_of(name: &str) -> Option<i32> {
    Some(match name {
        "EACCES" => libc::EACCES,
        "EPERM" => libc::EPERM,
        "ENOENT" => libc::ENOENT,
        "EMFILE" => libc::EMFILE,
        "ENFILE" => libc::ENFILE,
        "ELOOP" => libc::ELOOP,
        "ENOTDIR" => libc::ENOTDIR,
        "EINVAL" => libc::EINVAL,
        _ => return None,
    })
}

fn split_components(path: &str) -> Result<Vec<Vec<u8>>, String> {
    let parts: Vec<Vec<u8>> = path.split('/').map(|p| p.as_bytes().to_vec()).collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return Err(format!(
            "manifest node path {path:?} has an invalid component"
        ));
    }
    Ok(parts)
}

fn join(comps: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    out
}

impl Manifest {
    /// Parses manifest text (the corpus harness also validates the file on
    /// its own).
    pub fn parse(text: &str) -> Result<Manifest, String> {
        let raw: RawManifest =
            toml::from_str(text).map_err(|e| format!("malformed manifest.toml: {e}"))?;
        let mut manifest = Manifest::default();
        for n in raw.node {
            let path = split_components(&n.path)?;
            let kind = match n.kind.as_str() {
                "socket" => ManifestKind::Socket,
                "fifo" => ManifestKind::Fifo,
                "char" => ManifestKind::Char,
                "block" => ManifestKind::Block,
                "meta" => ManifestKind::Meta,
                "error" => ManifestKind::Error,
                other => {
                    return Err(format!(
                        "malformed manifest.toml: unknown node type {other:?}"
                    ));
                }
            };
            let access = match n.access.as_deref() {
                None => None,
                Some("none") => Some(NodeAccess::None),
                Some("read") => Some(NodeAccess::Read),
                Some("write") => Some(NodeAccess::Write),
                Some(other) => {
                    return Err(format!("malformed manifest.toml: unknown access {other:?}"));
                }
            };
            let errno =
                match n.errno.as_deref() {
                    None => None,
                    Some(name) => Some(errno_of(name).ok_or_else(|| {
                        format!("malformed manifest.toml: unknown errno {name:?}")
                    })?),
                };
            let node = ManifestNode {
                path: path.clone(),
                kind,
                mode: n.mode,
                uid: n.uid,
                gid: n.gid,
                access,
                major: n.major,
                minor: n.minor,
                fs: n.fs,
                errno,
            };
            if node.kind.is_virtual() {
                manifest
                    .virtual_children
                    .entry(join(&path[..path.len() - 1]))
                    .or_default()
                    .push(path.last().unwrap().clone());
            }
            manifest.nodes.insert(join(&path), node);
        }
        Ok(manifest)
    }

    /// Loads `manifest.toml` when present; an absent file is an empty
    /// overlay.
    pub fn load(path: &Path) -> Result<Manifest, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Manifest::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Manifest::default()),
            Err(e) => Err(format!("manifest.toml: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// The snapshot backend: the manifest overlay applied before the real tree.
// ---------------------------------------------------------------------------

/// The snapshot backend: manifest nodes overlay a [`RootDir`] opened on a
/// case's `tree/` (KTD12). Calls on a virtual node synthesize their
/// result; calls reaching an `error` node fail with its errno; everything
/// else goes to the real tree, and the filesystem each handle reports is
/// the overlay's name (manifest `fs` override, then `proc`/`sysfs`
/// defaults, then the mount table, then the real filesystem).
pub struct SnapshotBackend {
    fs: FsBackend,
    manifest: Manifest,
    mounts: Vec<Mount>,
}

impl SnapshotBackend {
    pub fn new(root: RootDir, manifest: Manifest) -> SnapshotBackend {
        SnapshotBackend {
            fs: FsBackend::new(root),
            manifest,
            mounts: Vec::new(),
        }
    }

    fn node_at(&self, comps: &[Vec<u8>]) -> Option<&ManifestNode> {
        self.manifest.nodes.get(&join(comps))
    }

    /// The errno of the first `error` node on the path, if any.
    fn error_at(&self, comps: &[Vec<u8>]) -> Option<i32> {
        for i in 1..=comps.len() {
            if let Some(n) = self.node_at(&comps[..i])
                && n.kind == ManifestKind::Error
            {
                return Some(n.errno.unwrap_or(0));
            }
        }
        None
    }

    /// The manifest `fs` override covering a component prefix: the deepest
    /// ancestor-or-self node that declares one.
    fn fs_override(&self, comps: &[Vec<u8>]) -> Option<&str> {
        for d in (1..=comps.len()).rev() {
            if let Some(n) = self.node_at(&comps[..d])
                && n.fs.is_some()
            {
                return n.fs.as_deref();
            }
        }
        None
    }

    /// The filesystem name one opened handle reports (KTD12): the manifest
    /// override (`local` falls through to the real filesystem), then the
    /// `proc`/`sysfs` defaults, then the containing mount's type, then the
    /// real handle's type.
    fn reported_fs(&self, prefix: &[Vec<u8>], real: Option<&str>) -> String {
        if let Some(name) = self.fs_override(prefix) {
            if name == "local" {
                return real.unwrap_or("local").to_string();
            }
            return name.to_string();
        }
        match prefix.first().map(Vec::as_slice) {
            Some(b"proc") => "proc".to_string(),
            Some(b"sys") => "sysfs".to_string(),
            _ => self
                .mounts
                .iter()
                .filter(|m| m.point.len() <= prefix.len() && m.point[..] == prefix[..m.point.len()])
                .max_by_key(|m| m.point.len())
                .map(|m| m.fstype.clone())
                .or_else(|| real.map(str::to_string))
                .unwrap_or_else(|| "local".to_string()),
        }
    }

    /// Fills the `fs` report for a call: one name per handle the walk
    /// conceptually opened (`handles` entries; `real` holds whatever the
    /// underlying RootDir actually reported).
    fn finish_fs(&self, comps: &[Vec<u8>], handles: usize, real: &[String], fs: &mut Vec<String>) {
        for i in 0..handles {
            let prefix = &comps[..(i + 1).min(comps.len())];
            fs.push(self.reported_fs(prefix, real.get(i).map(String::as_str)));
        }
    }

    /// Synthesized metadata for a virtual node.
    fn synth_meta(node: &ManifestNode) -> Meta {
        let kind = match node.kind {
            ManifestKind::Socket => NodeType::Socket,
            ManifestKind::Fifo => NodeType::Fifo,
            ManifestKind::Char => NodeType::Char,
            ManifestKind::Block => NodeType::Block,
            _ => NodeType::Other,
        };
        Meta {
            kind,
            mode: node.mode.unwrap_or(0),
            uid: node.uid.unwrap_or(0),
            gid: node.gid.unwrap_or(0),
            size: 0,
            device: match node.kind {
                ManifestKind::Char | ManifestKind::Block => {
                    Some((node.major.unwrap_or(0), node.minor.unwrap_or(0)))
                }
                _ => None,
            },
        }
    }

    /// The access result a node declaration gives, or `None` when the
    /// node does not declare one.
    fn declared_access(node: &ManifestNode, mask: AccessMask) -> Option<AccessResult> {
        match node.access {
            Some(NodeAccess::None) => Some(AccessResult::Refused),
            Some(NodeAccess::Read) => Some(if mask.write {
                AccessResult::Refused
            } else {
                AccessResult::Granted
            }),
            Some(NodeAccess::Write) => Some(AccessResult::Granted),
            None => match node.kind {
                k if k.is_virtual() => Some(AccessResult::Granted),
                _ => None,
            },
        }
    }

    /// Applies a `meta` node's mode/uid/gid overrides to real metadata.
    fn apply_overlays(node: &ManifestNode, st: &mut Meta) {
        if let Some(mode) = node.mode {
            st.mode = (st.mode & !0o7777) | mode;
        }
        if let Some(uid) = node.uid {
            st.uid = uid;
        }
        if let Some(gid) = node.gid {
            st.gid = gid;
        }
    }

    fn path_comps(path: &[u8]) -> Vec<Vec<u8>> {
        path.split(|b| *b == b'/').map(<[u8]>::to_vec).collect()
    }
}

impl Backend for SnapshotBackend {
    fn metadata(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Meta, Fail> {
        let comps = Self::path_comps(path);
        if let Some(e) = self.error_at(&comps) {
            self.finish_fs(&comps, comps.len().saturating_sub(1), &[], fs);
            return Err(Fail::Errno(e));
        }
        let node = self.node_at(&comps).cloned();
        if let Some(node) = &node
            && node.kind.is_virtual()
        {
            self.finish_fs(&comps, comps.len().saturating_sub(1), &[], fs);
            return Ok(Self::synth_meta(node));
        }
        let mut real = Vec::new();
        let st = self.fs.metadata(path, &mut real);
        self.finish_fs(&comps, comps.len().saturating_sub(1), &real, fs);
        let mut meta = st?;
        if let Some(node) = &node
            && node.kind == ManifestKind::Meta
        {
            Self::apply_overlays(node, &mut meta);
        }
        Ok(meta)
    }

    fn read(&mut self, path: &[u8], limit: u64, fs: &mut Vec<String>) -> Result<Vec<u8>, Fail> {
        let comps = Self::path_comps(path);
        if let Some(e) = self.error_at(&comps) {
            self.finish_fs(&comps, comps.len(), &[], fs);
            return Err(Fail::Errno(e));
        }
        if let Some(node) = self.node_at(&comps)
            && node.kind.is_virtual()
        {
            self.finish_fs(&comps, comps.len(), &[], fs);
            return Err(Fail::NotRegular(Self::synth_meta(node).kind));
        }
        let mut real = Vec::new();
        let result = self.fs.read(path, limit, &mut real);
        self.finish_fs(&comps, comps.len(), &real, fs);
        result
    }

    fn list(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Vec<(Vec<u8>, Meta)>, Fail> {
        let comps = Self::path_comps(path);
        if let Some(e) = self.error_at(&comps) {
            self.finish_fs(&comps, comps.len(), &[], fs);
            return Err(Fail::Errno(e));
        }
        if let Some(node) = self.node_at(&comps)
            && node.kind.is_virtual()
        {
            self.finish_fs(&comps, comps.len(), &[], fs);
            return Err(Fail::NotRegular(Self::synth_meta(node).kind));
        }
        let mut real = Vec::new();
        let result = self.fs.list(path, &mut real);
        self.finish_fs(&comps, comps.len(), &real, fs);
        let mut entries = result?;
        // Apply `meta` overrides to real children and merge virtual ones.
        for (name, st) in &mut entries {
            let mut child = comps.clone();
            child.push(name.clone());
            if let Some(node) = self.node_at(&child)
                && node.kind == ManifestKind::Meta
            {
                Self::apply_overlays(node, st);
            }
        }
        if let Some(virtuals) = self.manifest.virtual_children.get(path) {
            for name in virtuals {
                if entries.iter().any(|(n, _)| n == name) {
                    continue;
                }
                let mut child = comps.clone();
                child.push(name.clone());
                if let Some(node) = self.node_at(&child) {
                    entries.push((name.clone(), Self::synth_meta(node)));
                }
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Ok(entries)
    }

    fn access(
        &mut self,
        path: &[u8],
        mask: AccessMask,
        fs: &mut Vec<String>,
    ) -> Result<AccessResult, Fail> {
        let comps = Self::path_comps(path);
        if let Some(e) = self.error_at(&comps) {
            self.finish_fs(&comps, comps.len().saturating_sub(1), &[], fs);
            return Err(Fail::Errno(e));
        }
        if let Some(node) = self.node_at(&comps)
            && let Some(result) = Self::declared_access(node, mask)
        {
            self.finish_fs(&comps, comps.len().saturating_sub(1), &[], fs);
            return Ok(result);
        }
        let mut real = Vec::new();
        let result = self.fs.access(path, mask, &mut real);
        self.finish_fs(&comps, comps.len().saturating_sub(1), &real, fs);
        result
    }

    fn readlink(&mut self, path: &[u8], fs: &mut Vec<String>) -> Result<Vec<u8>, Fail> {
        let comps = Self::path_comps(path);
        if let Some(e) = self.error_at(&comps) {
            self.finish_fs(&comps, comps.len().saturating_sub(1), &[], fs);
            return Err(Fail::Errno(e));
        }
        if let Some(node) = self.node_at(&comps)
            && node.kind.is_virtual()
        {
            self.finish_fs(&comps, comps.len().saturating_sub(1), &[], fs);
            return Err(Fail::Errno(libc::EINVAL));
        }
        let mut real = Vec::new();
        let result = self.fs.readlink(path, &mut real);
        self.finish_fs(&comps, comps.len().saturating_sub(1), &real, fs);
        result
    }

    fn set_mounts(&mut self, mounts: &[Mount]) {
        self.mounts = mounts.to_vec();
    }

    fn overlay_no_touch(&self, path: &[u8]) -> bool {
        let comps = Self::path_comps(path);
        for i in 1..=comps.len() {
            if let Some(n) = self.node_at(&comps[..i])
                && let Some(fs) = n.fs.as_deref()
                && is_no_touch_snapshot(fs)
            {
                return true;
            }
        }
        false
    }
}

/// `is_no_touch` needs a policy; the snapshot overlay uses the Linux
/// no-touch vocabulary (cases are platform-fixture sets on the host they
/// run on).
fn is_no_touch_snapshot(fstype: &str) -> bool {
    const TYPES: &[&str] = &[
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
        "afpfs",
        "webdav",
        "osxfuse",
        "macfuse",
    ];
    TYPES.contains(&fstype) || fstype.starts_with("fuse.")
}

// ---------------------------------------------------------------------------
// SnapshotReader: the shared reader over the snapshot backend.
// ---------------------------------------------------------------------------

/// The snapshot reader: [`SharedReader`] machinery over the manifest
/// overlay and the case's `tree/`. Compiles only behind `snapshot`.
pub type SnapshotReader = SharedReader<SnapshotBackend>;

impl SharedReader<SnapshotBackend> {
    /// Opens a snapshot reader on a case directory: `tree/` is the root,
    /// `facts.toml` is required, `manifest.toml` is optional.
    pub fn open(case_dir: &Path) -> Result<SnapshotReader, String> {
        let facts_text = std::fs::read_to_string(case_dir.join("facts.toml"))
            .map_err(|e| format!("facts.toml: {e}"))?;
        let facts = facts::parse_facts(&facts_text)?;
        let manifest = Manifest::load(&case_dir.join("manifest.toml"))?;
        let tree: PathBuf = case_dir.join("tree");
        let root = RootDir::open(&tree).map_err(|e| format!("tree/: {e}"))?;
        Ok(SharedReader::new(
            SnapshotBackend::new(root, manifest),
            facts,
        ))
    }
}

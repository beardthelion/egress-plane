//! Universe enumeration: every declared finite set enumerates completely
//! or reports one unknown reason, never a partial set (KTD3).
//!
//! One enumerator per universe-table row runs under
//! [`egress_core::discover::guard`], applies the source's absent, masked,
//! and implausibly-empty signatures, and honors the KTD18 budgets. The
//! reader supplies the hop policy, the kernel-filesystem checks, and the
//! no-touch gate; a [`Denial`] maps to exactly one unknown reason here.
//! `linux.mounts` (or `macos.mounts`) runs first and arms the gate; when
//! it fails every gated source degrades to `depends-on-unknown` (KTD26).

mod devices;
pub mod linux;
mod resolvers;
mod socket_files;

use std::collections::BTreeMap;

use egress_core::discover::guard;

use crate::data::Budgets;
use crate::facts::{EnvName, Fact, FdEntry};
use crate::model::{
    AttrValue, Member, MemberClass, MemberField, MemberValue, Universe, UniverseState, Unknown,
    UnknownReason,
};
use crate::reader::{Denial, Mount, NodeType, Reader};

/// What one source produced: every member, the declared absent signature,
/// or one unknown reason (KTD3).
pub enum Outcome {
    Enumerated(Vec<Member>),
    Absent,
    Unknown(UnknownReason),
}

impl Outcome {
    fn into_universe(self, id: &str) -> Universe {
        let (state, members) = match self {
            Self::Enumerated(m) => (UniverseState::Enumerated, m),
            Self::Absent => (UniverseState::Absent, Vec::new()),
            Self::Unknown(r) => (UniverseState::Unknown(r), Vec::new()),
        };
        Universe {
            id: id.to_string(),
            state,
            members,
        }
    }
}

/// The result of the enumeration stage for one run: per-source states,
/// the confinement attributes the attribute sources produced (R12), the
/// identity fields later stages need, and the home-directory verdict
/// home-relative signals resolve against (KTD15).
pub struct Scan {
    /// Every declared universe in declared order, including
    /// not-applicable entries for the other platform (R24).
    pub universes: Vec<Universe>,
    /// One unknown per universe, attribute source, or attribute-producing
    /// signal that could not be read.
    pub unknowns: Vec<Unknown>,
    /// Confinement attributes for the innermost layer (R12, KTD16).
    pub attributes: BTreeMap<String, AttrValue>,
    /// Attribute-source ids that do not exist on this platform (R24).
    pub not_applicable: Vec<String>,
    /// The effective uid and gid, when the platform exposes them to the
    /// probe (Linux: `proc/self/status`; macOS: the identity fact).
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    /// The account's home directory from `etc/passwd` (KTD15), or the
    /// reason home-relative signals are unknown.
    pub home: Result<Vec<u8>, UnknownReason>,
    /// `TracerPid` at the start of the run (the KTD25 first read).
    pub tracer_pid: Option<u64>,
    /// Whether the `proc/self` hop passed through the accepted ancestor
    /// pid namespace (KTD24); a layer attribute when set.
    pub ancestor_pidns: bool,
}

// ---------------------------------------------------------------------------
// Denial and fact mapping.
// ---------------------------------------------------------------------------

/// Maps a reader denial to the one unknown reason it names (KTD3).
/// `Absent` has no generic meaning: callers apply their source's absent
/// signature, or `proc-not-mounted` for `proc/` sources.
pub(crate) fn denial_reason(d: Denial) -> UnknownReason {
    match d {
        Denial::Absent | Denial::Unreadable(_) | Denial::NotRegular => UnknownReason::Unreadable,
        Denial::DescriptorLimit => UnknownReason::DescriptorLimit,
        Denial::TooLarge => UnknownReason::BudgetExceeded,
        Denial::LinkPolicy => UnknownReason::LinkPolicy,
        Denial::FsTypeMismatch => UnknownReason::FsTypeMismatch,
        Denial::ProcSelfMismatch => UnknownReason::ProcSelfMismatch,
        Denial::NotTouched => UnknownReason::NetworkFilesystemNotTouched,
        Denial::DependsOnUnknown => UnknownReason::DependsOnUnknown,
    }
}

/// The denial mapping for a `proc/` source: a missing file under a missing
/// proc filesystem is `proc-not-mounted`, not a read failure.
pub(crate) fn proc_denial(d: Denial) -> UnknownReason {
    match d {
        Denial::Absent => UnknownReason::ProcNotMounted,
        d => denial_reason(d),
    }
}

/// The unknown reason a non-`read` fact state names (KTD8, KTD17).
pub fn fact_reason<T>(f: &Fact<T>) -> UnknownReason {
    match f {
        Fact::Read(_) => UnknownReason::InternalFailure,
        Fact::Unreadable | Fact::NotBuilt | Fact::Disabled => UnknownReason::Unreadable,
        Fact::UnsupportedLayout => UnknownReason::UnsupportedLayout,
        Fact::FsTypeMismatch => UnknownReason::FsTypeMismatch,
        Fact::ProcSelfMismatch => UnknownReason::ProcSelfMismatch,
    }
}

// ---------------------------------------------------------------------------
// Guards and budgets.
// ---------------------------------------------------------------------------

/// Runs one source enumerator under the panic guard: a panic is an
/// `internal-failure` unknown, never a lost run (KTD3).
pub(crate) fn run<T>(f: impl FnOnce() -> Result<T, UnknownReason>) -> Result<T, UnknownReason> {
    guard(f).unwrap_or(Err(UnknownReason::InternalFailure))
}

/// The per-universe budgets (KTD18): member count, and every member
/// string within the per-string limit.
pub(crate) fn check_members(members: &[Member], budgets: &Budgets) -> Result<(), UnknownReason> {
    if members.len() as u64 > budgets.members_per_universe {
        return Err(UnknownReason::BudgetExceeded);
    }
    let over = budgets.bytes_per_member_string;
    for m in members {
        for f in &m.fields {
            if let MemberValue::Text(b) = &f.value
                && b.len() as u64 > over
            {
                return Err(UnknownReason::BudgetExceeded);
            }
        }
    }
    Ok(())
}

/// The masked signature for a header-bearing proc table: each declared
/// prefix must appear in the matching line (a zero-byte file fails the
/// first check). A header-only file passes and enumerates empty.
pub(crate) fn masked(bytes: &[u8], prefixes: &[String]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let mut lines = bytes.split(|b| *b == b'\n');
    for p in prefixes {
        match lines.next() {
            Some(l) if l.windows(p.len()).any(|w| w == p.as_bytes()) => {}
            _ => return true,
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Member field builders.
// ---------------------------------------------------------------------------

pub(crate) fn tfield(name: &str, value: &str, identity: bool) -> MemberField {
    MemberField {
        name: name.to_string(),
        value: MemberValue::Text(value.as_bytes().to_vec()),
        identity,
    }
}

pub(crate) fn bfield(name: &str, value: &[u8], identity: bool) -> MemberField {
    MemberField {
        name: name.to_string(),
        value: MemberValue::Text(value.to_vec()),
        identity,
    }
}

pub(crate) fn ifield(name: &str, value: u64) -> MemberField {
    MemberField {
        name: name.to_string(),
        value: MemberValue::Int(value),
        identity: false,
    }
}

pub(crate) fn flagfield(name: &str, value: bool, identity: bool) -> MemberField {
    MemberField {
        name: name.to_string(),
        value: MemberValue::Bool(value),
        identity,
    }
}

pub(crate) fn member(fields: Vec<MemberField>, display: String) -> Member {
    Member {
        id: String::new(),
        fields,
        display,
        class: MemberClass::Unclassified,
        rules: Vec::new(),
        ordinal: 0,
    }
}

pub(crate) fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ---------------------------------------------------------------------------
// Fact-fed member builders shared by the linux and macos enumerators.
// ---------------------------------------------------------------------------

/// One `linux.fds` or `macos.fds` member per inventory entry (R28): the
/// probe's standard streams, its own handles, and every inherited
/// descriptor, labeled, none excluded (KTD8).
pub fn fd_members(entries: &[FdEntry]) -> Vec<Member> {
    entries
        .iter()
        .map(|e| {
            let label = match e.fd {
                0 => "stdin",
                1 => "stdout",
                2 => "stderr",
                _ if e.probe_own => "probe-own",
                _ => "inherited",
            };
            let (kind, path, anon, inode) = fd_target(&e.target);
            member(
                vec![
                    tfield("label", label, true),
                    tfield("kind", kind, true),
                    bfield("path", &path, true),
                    tfield("anon-name", &anon, true),
                    ifield("fd", e.fd),
                    ifield("inode", inode),
                ],
                format!("fd {}: {}", e.fd, e.target),
            )
        })
        .collect()
}

/// The target of one descriptor link: `socket:[i]`, `pipe:[i]`,
/// `anon_inode:<name>`, or a filesystem path. Returns
/// `(kind, path, anon_name, inode)`.
fn fd_target(target: &str) -> (&'static str, Vec<u8>, String, u64) {
    if let Some(inner) = bracketed(target, "socket:") {
        return ("socket", Vec::new(), String::new(), inner);
    }
    if let Some(inner) = bracketed(target, "pipe:") {
        return ("pipe", Vec::new(), String::new(), inner);
    }
    if let Some(name) = target.strip_prefix("anon_inode:") {
        return ("anon", Vec::new(), name.to_string(), 0);
    }
    if target.starts_with('/') {
        return ("path", target.as_bytes().to_vec(), String::new(), 0);
    }
    ("other", Vec::new(), String::new(), 0)
}

fn bracketed(target: &str, prefix: &str) -> Option<u64> {
    let rest = target.strip_prefix(prefix)?;
    let inner = rest.strip_prefix('[')?.strip_suffix(']')?;
    inner.parse().ok()
}

/// One `env-names` member per environment name (R26): raw bytes here,
/// redacted before identity and output in finalize (KTD14); the
/// `redacted` field records whether the name itself matched a
/// token-prefix class. An entry with no `=` separator is the fixed
/// placeholder `<no-separator>`; its bytes never exist.
pub fn env_members(names: &[EnvName]) -> Vec<Member> {
    names
        .iter()
        .map(|n| {
            let bytes = match n {
                EnvName::Name(b) => b.clone(),
                EnvName::NoSeparator => b"<no-separator>".to_vec(),
            };
            let redacted = crate::identity::redact_bytes(&bytes) != bytes;
            member(
                vec![
                    bfield("name", &bytes, true),
                    flagfield("redacted", redacted, false),
                ],
                lossy(&bytes),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Address helpers for the proc network tables.
// ---------------------------------------------------------------------------

/// Parses a hex field of a proc IPv4 table (`0100007F` = 127.0.0.1):
/// the address is printed little-endian.
pub(crate) fn ipv4_from_proc(hex: &str) -> Option<std::net::Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(std::net::Ipv4Addr::from(n.to_le_bytes()))
}

/// Parses a 32-hex proc IPv6 socket-table address: each 4-byte group is
/// printed byte-reversed (`::1` appears as `...01000000`).
pub(crate) fn ipv6_from_proc(hex: &str) -> Option<std::net::Ipv6Addr> {
    let mut bytes = hex_bytes(hex)?;
    for group in bytes.chunks_exact_mut(4) {
        group.reverse();
    }
    Some(std::net::Ipv6Addr::from(bytes))
}

/// Parses a 32-hex `proc/net/ipv6_route` address, printed in plain
/// network order.
pub(crate) fn ipv6_from_route(hex: &str) -> Option<std::net::Ipv6Addr> {
    Some(std::net::Ipv6Addr::from(hex_bytes(hex)?))
}

fn hex_bytes(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The mount layout shared by socket-files and devices (KTD30).
// ---------------------------------------------------------------------------

/// Mount-point findings one pass of `lstat` produced: non-canonical
/// directory mount points listed at depth 1 (KTD30) and mount points
/// that are themselves socket files, with their metadata.
pub(crate) struct MountLayout {
    pub dir_mounts: Vec<Vec<u8>>,
    pub socket_points: Vec<(Vec<u8>, crate::reader::Meta)>,
}

/// `lstat` of every mount point from the mount table: directory mounts
/// outside the canonical set are depth-1 listing candidates, sockets are
/// socket-files members, and a call the gate refuses fails the source
/// (KTD26, KTD30).
pub(crate) fn mount_layout<R: Reader>(
    r: &mut R,
    mounts: &[Mount],
) -> Result<MountLayout, UnknownReason> {
    let mut layout = MountLayout {
        dir_mounts: Vec::new(),
        socket_points: Vec::new(),
    };
    for m in mounts {
        if m.point.is_empty() {
            continue; // the root mount is canonical by definition
        }
        let path = join(m.point.as_slice());
        match r.metadata(&path) {
            Ok(meta) => match meta.kind {
                NodeType::Dir => {
                    if !canonical_mount(&m.point) {
                        layout.dir_mounts.push(path);
                    }
                }
                NodeType::Socket => layout.socket_points.push((path, meta)),
                _ => {}
            },
            Err(Denial::Absent) => {}
            Err(d) => return Err(denial_reason(d)),
        }
    }
    Ok(layout)
}

/// The canonical mount points KTD30 never lists: `/`, `/proc` and
/// anything under it, `/sys` and anything under it, `/dev`, `/dev/shm`,
/// `/run`, `/tmp`, and `/var/run`.
fn canonical_mount(point: &[Vec<u8>]) -> bool {
    match point.first().map(Vec::as_slice) {
        None => true,
        Some(b"proc") | Some(b"sys") => true,
        _ => {
            point == [b"dev"]
                || point == [b"dev", b"shm"]
                || point == [b"run"]
                || point == [b"tmp"]
                || point == [b"var", b"run"]
        }
    }
}

/// Joins in-root path components into call bytes (no leading slash).
pub(crate) fn join(comps: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    out
}

/// The display and identity form of an in-root path: leading slash.
pub(crate) fn abs(comps: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![b'/'];
    out.extend_from_slice(&join(comps));
    out
}

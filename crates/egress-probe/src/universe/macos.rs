//! The macOS universe enumerators, attribute sources, and record
//! parsers (U7).
//!
//! `macos.mounts` arms the no-touch gate from the mounts fact (KTD26);
//! sockets, listeners, routes, interfaces, descriptors, and environment
//! names come from the normalized facts the live adapters collect
//! (KTD4); socket files, devices, and resolver files are reader-backed
//! like the Linux sources. Home-relative signals resolve to
//! `no-account-home`: v1 performs no account lookup (KTD15).
//!
//! The `pcblist_n`, `NET_RT_DUMP`, and `proc_pidfdinfo` record layouts
//! decode as pure functions over byte buffers: a truncated or
//! foreign-layout buffer yields [`LayoutError`], which the live
//! adapters map to `unsupported-layout` instead of a short member set
//! (KTD17). The parsers run on every platform so snapshot replay and
//! unit tests exercise them without a macOS host.

use std::collections::BTreeMap;

pub use super::Scan;
use super::{
    Outcome, bfield, check_members, denial_reason, env_members, fact_reason, fd_members, flagfield,
    ifield, join, lossy, member, resolvers, run, tfield,
};
use crate::data::{Budgets, Data};
use crate::facts::{
    Fact, IdentityFact, InterfaceFact, ListenerFact, MountFact, RouteFact, UnixSocketFact,
};
use crate::model::{AttrValue, Member, Universe, UniverseState, Unknown, UnknownReason};
use crate::reader::{AccessMask, AccessResult, Denial, Meta, Mount, NodeType, Reader};

/// Runs every macOS source through the reader and returns the
/// per-source states, attributes, identity fields, and the fixed
/// `no-account-home` verdict (KTD3, KTD15, R12).
pub fn enumerate<R: Reader>(r: &mut R, data: &Data) -> Scan {
    let budgets = &data.budgets;
    let mut outcomes: BTreeMap<&str, Outcome> = BTreeMap::new();
    let mut unknowns: Vec<Unknown> = Vec::new();
    let mut attributes: BTreeMap<String, AttrValue> = BTreeMap::new();
    let mut euid = None;
    let mut egid = None;
    let u = |id: &str| -> &crate::data::Universe {
        data.universes
            .iter()
            .find(|u| u.id == id)
            .unwrap_or_else(|| panic!("declared universe {id}"))
    };

    // 1. Mounts: the fact arms the gate; when it fails every gated
    //    source degrades to depends-on-unknown (KTD26).
    let mut mount_table: Vec<Mount> = Vec::new();
    let mounts_out = run(|| mounts(r, u("macos.mounts"), budgets));
    match mounts_out {
        Ok((members, table)) => {
            mount_table = table;
            r.arm_mounts(mount_table.clone());
            outcomes.insert("macos.mounts", Outcome::Enumerated(members));
        }
        Err(reason) => {
            r.mounts_unknown();
            outcomes.insert("macos.mounts", Outcome::Unknown(reason));
        }
    }

    // 2. The numeric identity: euid and egid for the privilege fields
    //    and for signal substitution (KTD15 applies to home only).
    match run(|| identity(r)) {
        Ok((attrs, id)) => {
            attributes.extend(attrs);
            euid = Some(id.euid);
            egid = Some(id.egid);
        }
        Err(reason) => unknowns.push(unknown("macos.attr.identity", reason)),
    }

    // 3. Universes in declared order.
    let no_touch = |fs: &str| data.no_touch_fstype("macos", fs);
    let sock = run(|| socket_files(r, &mount_table, budgets, &no_touch));
    outcomes.insert("macos.socket-files", sock.unwrap_or_else(Outcome::Unknown));

    outcomes.insert(
        "macos.unix-sockets",
        outcome(run(|| unix_sockets(r, budgets))),
    );
    outcomes.insert("macos.listeners", outcome(run(|| listeners(r, budgets))));
    outcomes.insert(
        "macos.fds",
        outcome(run(|| fds(r, u("macos.fds"), budgets))),
    );
    outcomes.insert("macos.env-names", outcome(run(|| env_names(r))));
    outcomes.insert("macos.routes", outcome(run(|| routes(r, budgets))));
    let resolv = run(|| resolvers(r, budgets));
    outcomes.insert("macos.resolvers", resolv.unwrap_or_else(Outcome::Unknown));
    outcomes.insert("macos.interfaces", outcome(run(|| interfaces(r, budgets))));
    outcomes.insert(
        "macos.devices",
        outcome(run(|| devices(r, u("macos.devices"), budgets))),
    );

    // 4. The remaining attribute sources (R12).
    match run(|| sandbox_check_attr(r)) {
        Ok(attr) => {
            attributes.insert("sandbox_check".to_string(), attr);
        }
        Err(reason) => unknowns.push(unknown("macos.attr.sandbox-check", reason)),
    }
    match run(|| hv_vmm_attr(r)) {
        Ok(attr) => {
            attributes.insert("hv_vmm_present".to_string(), attr);
        }
        Err(reason) => unknowns.push(unknown("macos.attr.hv-vmm", reason)),
    }
    match run(|| traced_attr(r)) {
        Ok(attr) => {
            attributes.insert("traced".to_string(), attr);
        }
        Err(reason) => unknowns.push(unknown("macos.attr.traced", reason)),
    }

    // Assemble: every declared universe in order, Linux entries not
    // applicable (R24).
    let mut universes = Vec::new();
    for u in &data.universes {
        if u.platform == "macos" {
            let out = outcomes.remove(u.id.as_str()).unwrap_or(Outcome::Absent);
            if let Outcome::Unknown(reason) = out {
                unknowns.push(unknown(&u.id, reason));
            }
            universes.push(out.into_universe(&u.id));
        } else {
            universes.push(Universe {
                id: u.id.clone(),
                state: UniverseState::NotApplicable,
                members: Vec::new(),
            });
        }
    }
    for (id, out) in outcomes {
        if let Outcome::Unknown(reason) = out {
            unknowns.push(unknown(id, reason));
        }
    }
    let not_applicable = data
        .not_applicable
        .iter()
        .filter(|n| n.platform == "macos")
        .map(|n| n.id.clone())
        .collect();

    Scan {
        universes,
        unknowns,
        attributes,
        not_applicable,
        euid,
        egid,
        home: Err(UnknownReason::NoAccountHome),
        tracer_pid: None,
        ancestor_pidns: false,
    }
}

fn outcome(m: Result<Vec<Member>, UnknownReason>) -> Outcome {
    match m {
        Ok(members) => Outcome::Enumerated(members),
        Err(reason) => Outcome::Unknown(reason),
    }
}

fn unknown(source: &str, reason: UnknownReason) -> Unknown {
    Unknown {
        id: String::new(),
        source: source.to_string(),
        reason,
    }
}

// ---------------------------------------------------------------------------
// macos.mounts: the getfsstat fact.
// ---------------------------------------------------------------------------

fn mounts(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<(Vec<Member>, Vec<Mount>), UnknownReason> {
    match r.facts().mounts.clone() {
        Some(Fact::Read(entries)) => {
            if (entries.len() as u64) < u.min_members {
                return Err(UnknownReason::ImplausiblyEmpty);
            }
            let members: Vec<Member> = entries.iter().map(mount_member).collect();
            check_members(&members, budgets)?;
            let table = entries
                .iter()
                .map(|m| Mount::from_bytes(&m.path, &m.fstype))
                .collect();
            Ok((members, table))
        }
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

fn mount_member(m: &MountFact) -> Member {
    member(
        vec![
            bfield("mount-point", &m.path, true),
            tfield("fstype", &m.fstype, true),
            tfield("mount-source", m.source.as_deref().unwrap_or(""), false),
            flagfield("writable", !m.readonly.unwrap_or(true), false),
        ],
        lossy(&m.path),
    )
}

// ---------------------------------------------------------------------------
// macos.socket-files: mount-point lstat and the fixed depth-1 listings.
// ---------------------------------------------------------------------------

/// `lstat` of every non-directory mount point that is a socket, plus the
/// depth-1 listings of `private/var/run` and `private/tmp`. A mount on
/// a never-touched filesystem is not stat'd at all (KTD26); a mount
/// point whose lstat fails contributes nothing. Both listing
/// directories missing is the declared absent signature.
fn socket_files<R: Reader>(
    r: &mut R,
    mounts: &[Mount],
    budgets: &Budgets,
    no_touch: &dyn Fn(&str) -> bool,
) -> Result<Outcome, UnknownReason> {
    let mut found: BTreeMap<Vec<u8>, Meta> = BTreeMap::new();
    for m in mounts {
        if m.point.is_empty() || no_touch(&m.fstype) {
            continue;
        }
        let path = join(&m.point);
        if let Ok(meta) = r.metadata(&path)
            && meta.kind == NodeType::Socket
        {
            found.entry(path).or_insert(meta);
        }
    }

    let mut missing = 0usize;
    for dir in [&b"private/var/run"[..], &b"private/tmp"[..]] {
        match r.list(dir) {
            Ok(entries) => {
                if entries.len() as u64 > budgets.entries_per_listing {
                    return Err(UnknownReason::BudgetExceeded);
                }
                for (name, meta) in entries {
                    if meta.kind != NodeType::Socket {
                        continue;
                    }
                    let mut path = dir.to_vec();
                    path.push(b'/');
                    path.extend_from_slice(&name);
                    found.entry(path).or_insert(meta);
                }
            }
            Err(Denial::Absent) => missing += 1,
            Err(d) => return Err(denial_reason(d)),
        }
    }
    if missing == 2 {
        return Ok(Outcome::Absent);
    }

    let mut members = Vec::new();
    for (path, meta) in found {
        let writable = access_writable(r, &path)?;
        members.push(socket_member(&path, meta, writable));
    }
    check_members(&members, budgets)?;
    Ok(Outcome::Enumerated(members))
}

fn access_writable(r: &mut impl Reader, path: &[u8]) -> Result<bool, UnknownReason> {
    match r.access(path, AccessMask::WRITE) {
        Ok(AccessResult::Granted) => Ok(true),
        Ok(AccessResult::Refused) | Err(Denial::Absent) => Ok(false),
        Err(d) => Err(denial_reason(d)),
    }
}

fn socket_member(path: &[u8], meta: Meta, writable: bool) -> Member {
    let mut abs = vec![b'/'];
    abs.extend_from_slice(path);
    member(
        vec![
            bfield("path", &abs, true),
            ifield("mode", meta.mode as u64),
            ifield("uid", meta.uid as u64),
            ifield("gid", meta.gid as u64),
            flagfield("writable", writable, false),
        ],
        lossy(&abs),
    )
}

// ---------------------------------------------------------------------------
// Fact-fed universes.
// ---------------------------------------------------------------------------

fn unix_sockets(r: &mut impl Reader, budgets: &Budgets) -> Result<Vec<Member>, UnknownReason> {
    match r.facts().unix_sockets.clone() {
        Some(Fact::Read(entries)) => {
            let members = unix_socket_members(&entries);
            check_members(&members, budgets)?;
            Ok(members)
        }
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

/// One member per named `pcblist_n` unix socket; unnamed sockets fold
/// into one member per socket type (universe table).
fn unix_socket_members(entries: &[UnixSocketFact]) -> Vec<Member> {
    let mut members = Vec::new();
    let mut unnamed: BTreeMap<(String, bool), u64> = BTreeMap::new();
    for s in entries {
        let Some(path) = &s.path else {
            *unnamed.entry((s.kind.clone(), s.listening)).or_default() += 1;
            continue;
        };
        if path.is_empty() {
            *unnamed.entry((s.kind.clone(), s.listening)).or_default() += 1;
            continue;
        }
        members.push(member(
            vec![
                bfield("path", path, true),
                tfield("socket-type", &s.kind, true),
                flagfield("listening", s.listening, true),
                ifield("unnamed-count", 0),
            ],
            lossy(path),
        ));
    }
    for ((kind, listening), count) in unnamed {
        members.push(member(
            vec![
                bfield("path", b"", true),
                tfield("socket-type", &kind, true),
                flagfield("listening", listening, true),
                ifield("unnamed-count", count),
            ],
            format!("<unnamed {kind}>"),
        ));
    }
    members
}

fn listeners(r: &mut impl Reader, budgets: &Budgets) -> Result<Vec<Member>, UnknownReason> {
    match r.facts().listeners.clone() {
        Some(Fact::Read(entries)) => {
            let members: Vec<Member> = entries.iter().map(listener_member).collect();
            check_members(&members, budgets)?;
            Ok(members)
        }
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

fn listener_member(l: &ListenerFact) -> Member {
    let display = if l.protocol.ends_with('6') {
        format!("{} [{}]:{}", l.protocol, l.address, l.port)
    } else {
        format!("{} {}:{}", l.protocol, l.address, l.port)
    };
    member(
        vec![
            tfield("protocol", &l.protocol, true),
            tfield("local-address", &l.address, true),
            ifield("port", l.port as u64),
        ],
        display,
    )
}

fn fds(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    match r.facts().fds.clone() {
        Fact::Read(entries) => {
            if entries.len() < u.min_members as usize {
                return Err(UnknownReason::ImplausiblyEmpty);
            }
            let members = fd_members(&entries);
            check_members(&members, budgets)?;
            Ok(members)
        }
        other => Err(fact_reason(&other)),
    }
}

fn env_names(r: &mut impl Reader) -> Result<Vec<Member>, UnknownReason> {
    match r.facts().env_names.clone() {
        Fact::Read(names) => Ok(env_members(&names)),
        other => Err(fact_reason(&other)),
    }
}

fn routes(r: &mut impl Reader, budgets: &Budgets) -> Result<Vec<Member>, UnknownReason> {
    match r.facts().routes.clone() {
        Some(Fact::Read(entries)) => {
            let members: Vec<Member> = entries.iter().map(route_member).collect();
            check_members(&members, budgets)?;
            Ok(members)
        }
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

fn route_member(rt: &RouteFact) -> Member {
    let gateway = rt.gateway.as_deref().unwrap_or("0.0.0.0");
    let iface = rt.interface.as_deref().unwrap_or("");
    let mut display = rt.destination.clone();
    if let Some(g) = &rt.gateway {
        display.push_str(&format!(" via {g}"));
    }
    if let Some(i) = &rt.interface {
        display.push_str(&format!(" dev {i}"));
    }
    member(
        vec![
            tfield("family", &rt.family, true),
            tfield("destination-prefix", &rt.destination, true),
            tfield("gateway", gateway, true),
            tfield("interface", iface, true),
        ],
        display,
    )
}

fn interfaces(r: &mut impl Reader, budgets: &Budgets) -> Result<Vec<Member>, UnknownReason> {
    match r.facts().interfaces.clone() {
        Some(Fact::Read(entries)) => {
            let members: Vec<Member> = entries.iter().map(interface_member).collect();
            check_members(&members, budgets)?;
            Ok(members)
        }
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

fn interface_member(i: &InterfaceFact) -> Member {
    member(
        vec![
            tfield("name", &i.name, true),
            tfield("families", &i.families.join(","), false),
        ],
        i.name.clone(),
    )
}

// ---------------------------------------------------------------------------
// macos.resolvers: the stub file plus every `private/etc/resolver/` file.
// ---------------------------------------------------------------------------

/// The stub `private/etc/resolv.conf` (through the declared hop) plus
/// every file in `private/etc/resolver/`; both missing is the declared
/// absent signature. The resolver file name joins each member's
/// identity.
fn resolvers<R: Reader>(r: &mut R, budgets: &Budgets) -> Result<Outcome, UnknownReason> {
    let mut members = Vec::new();
    let mut missing = 0usize;
    match r.read(b"private/etc/resolv.conf", budgets.bytes_per_file) {
        Ok(bytes) => resolvers::parse_members(&bytes, Some(b"resolv.conf"), &mut members)?,
        Err(Denial::Absent) => missing += 1,
        Err(d) => return Err(denial_reason(d)),
    }
    match r.list(b"private/etc/resolver") {
        Ok(entries) => {
            if entries.len() as u64 > budgets.entries_per_listing {
                return Err(UnknownReason::BudgetExceeded);
            }
            for (name, meta) in entries {
                if !matches!(meta.kind, NodeType::File | NodeType::Symlink) {
                    continue;
                }
                let mut path = b"private/etc/resolver/".to_vec();
                path.extend_from_slice(&name);
                match r.read(&path, budgets.bytes_per_file) {
                    Ok(bytes) => resolvers::parse_members(&bytes, Some(&name), &mut members)?,
                    Err(Denial::Absent) => {}
                    Err(d) => return Err(denial_reason(d)),
                }
            }
        }
        Err(Denial::Absent) => missing += 1,
        Err(d) => return Err(denial_reason(d)),
    }
    if missing == 2 {
        return Ok(Outcome::Absent);
    }
    check_members(&members, budgets)?;
    Ok(Outcome::Enumerated(members))
}

// ---------------------------------------------------------------------------
// macos.devices: the depth-1 `dev` listing, char and block nodes only.
// ---------------------------------------------------------------------------

fn devices<R: Reader>(
    r: &mut R,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let entries = match r.list(b"dev") {
        Ok(e) => e,
        Err(d) => return Err(denial_reason(d)),
    };
    if entries.len() as u64 > budgets.entries_per_listing {
        return Err(UnknownReason::BudgetExceeded);
    }
    let mut metas = Vec::new();
    for (name, meta) in entries {
        if !matches!(meta.kind, NodeType::Char | NodeType::Block) {
            continue;
        }
        let mut path = b"dev/".to_vec();
        path.extend_from_slice(&name);
        metas.push((path, meta));
    }
    if metas.len() < u.min_members as usize {
        return Err(UnknownReason::ImplausiblyEmpty);
    }
    let mut members = Vec::new();
    for (path, meta) in metas {
        let accessible = access_rw(r, &path)?;
        members.push(device_member(&path, meta, accessible));
    }
    check_members(&members, budgets)?;
    Ok(members)
}

fn access_rw(r: &mut impl Reader, path: &[u8]) -> Result<bool, UnknownReason> {
    let mut yes = false;
    for mask in [AccessMask::READ, AccessMask::WRITE] {
        match r.access(path, mask) {
            Ok(AccessResult::Granted) => yes = true,
            Ok(AccessResult::Refused) | Err(Denial::Absent) => {}
            Err(d) => return Err(denial_reason(d)),
        }
    }
    Ok(yes)
}

fn device_member(path: &[u8], meta: Meta, accessible: bool) -> Member {
    let node = match meta.kind {
        NodeType::Char => "char",
        NodeType::Block => "block",
        _ => "other",
    };
    let device = meta
        .device
        .map(|(major, minor)| format!("{major}:{minor}"))
        .unwrap_or_default();
    let mut abs = vec![b'/'];
    abs.extend_from_slice(path);
    member(
        vec![
            bfield("path", &abs, true),
            tfield("node-type", node, true),
            ifield("mode", meta.mode as u64),
            ifield("uid", meta.uid as u64),
            ifield("gid", meta.gid as u64),
            tfield("device", &device, false),
            flagfield("accessible", accessible, false),
        ],
        lossy(&abs),
    )
}

// ---------------------------------------------------------------------------
// The attribute sources (R12): facts only, no filesystem calls.
// ---------------------------------------------------------------------------

fn identity(
    r: &mut impl Reader,
) -> Result<(BTreeMap<String, AttrValue>, IdentityFact), UnknownReason> {
    match r.facts().identity.clone() {
        Some(Fact::Read(id)) => Ok((
            BTreeMap::from([
                ("euid".to_string(), AttrValue::Int(id.euid as i64)),
                ("egid".to_string(), AttrValue::Int(id.egid as i64)),
            ]),
            id,
        )),
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

fn sandbox_check_attr(r: &mut impl Reader) -> Result<AttrValue, UnknownReason> {
    match r.facts().sandbox_check.clone() {
        Some(Fact::Read(v)) => Ok(AttrValue::Int(v)),
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

fn hv_vmm_attr(r: &mut impl Reader) -> Result<AttrValue, UnknownReason> {
    match r.facts().hv_vmm_present.clone() {
        Some(Fact::Read(v)) => Ok(AttrValue::Bool(v)),
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

fn traced_attr(r: &mut impl Reader) -> Result<AttrValue, UnknownReason> {
    match r.facts().traced.clone() {
        Some(Fact::Read(v)) => Ok(AttrValue::Bool(v)),
        Some(other) => Err(fact_reason(&other)),
        None => Err(UnknownReason::Unreadable),
    }
}

// ---------------------------------------------------------------------------
// Record parsers (KTD17): pure byte-buffer decoders for the live
// adapters. A buffer that cannot be walked with confidence is a
// LayoutError; nothing is emitted partially.
// ---------------------------------------------------------------------------

/// The closed failure of the macOS record parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// The buffer ends inside a record.
    Truncated,
    /// Lengths, kinds, or families do not match the declared layout.
    Unsupported,
}

// The `xinpgen`/`xunpgen` framing: a 24-byte header and, when records
// exist, a 24-byte trailer.
const XINPGEN_LEN: usize = 24;
// `x*gen` kinds for the typed sub-structures of a pcb record.
const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;
const XSO_TCPCB: u32 = 0x020;
const XSO_UNPCB: u32 = 0x200;
// Field offsets inside the pack(4) `_n` structures (xnu socketvar.h,
// in_pcb.h, unpcb.h, tcp_var.h).
const XINPCB_FPORT: usize = 16;
const XINPCB_LPORT: usize = 18;
const XINPCB_VFLAG: usize = 44;
const XINPCB_FADDR: usize = 48;
const XINPCB_LADDR: usize = 64;
const XINPCB_MIN: usize = 104;
const XSOCKET_TYPE: usize = 16;
const XSOCKET_OPTIONS: usize = 20;
const XSOCKET_MIN: usize = 28;
const XTCPCB_STATE: usize = 36;
const XTCPCB_MIN: usize = 40;
const XUNPCB_ADDR: usize = 76;
const XUNPCB_ADDR_MAX: usize = 106; // sockaddr_un: 2 header + 104 path
const XUNPCB_MIN: usize = XUNPCB_ADDR + 2;

const INP_IPV4: u8 = 0x1;
const INP_IPV6: u8 = 0x2;
const TCPS_LISTEN: i32 = 1;
const SOCK_STREAM: i16 = 1;
const SOCK_DGRAM: i16 = 2;
const SOCK_SEQPACKET: i16 = 5;
const SO_ACCEPTCONN: u32 = 0x0002;

const AF_UNIX: u8 = 1;
const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
const AF_INET6: u8 = 30;

// rt_msghdr: the fixed 92-byte header, then rtm_addrs sockaddrs at
// 4-byte strides (xnu route.h, rtsock.c ROUNDUP32).
const RT_MSGHDR_LEN: usize = 92;
const RTM_VERSION: u8 = 5;
const RTM_GET: u8 = 0x4;
const RTF_HOST: i32 = 0x4;
const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
const RTAX_IFP: usize = 4;

fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn le_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn le_i16(b: &[u8], off: usize) -> i16 {
    i16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
fn be_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(b[off..off + 2].try_into().unwrap())
}
fn roundup8(n: usize) -> usize {
    (n + 7) & !7
}

/// One pcblist record: its typed sub-structures in write order, each as
/// `(kind, bytes)` where `bytes` includes the 8-byte length/kind head.
struct PcbRecord<'a>(Vec<(u32, &'a [u8])>);

impl<'a> PcbRecord<'a> {
    fn get(&self, kind: u32) -> Option<&'a [u8]> {
        self.0.iter().find(|(k, _)| *k == kind).map(|(_, b)| *b)
    }
}

/// Walks a `pcblist_n` buffer into records. The kernel writes a 24-byte
/// `xinpgen`/`xunpgen` header, back-to-back records each starting with
/// the pcb sub-structure (`XSO_INPCB` or `XSO_UNPCB`), and a 24-byte
/// trailer when any record exists (xnu `get_pcblist_n`,
/// `unp_pcblist_n`). A record-less buffer is the header alone.
fn pcb_records(buf: &[u8]) -> Result<Vec<PcbRecord<'_>>, LayoutError> {
    if buf.len() < XINPGEN_LEN {
        return Err(LayoutError::Truncated);
    }
    if le_u32(buf, 0) as usize != XINPGEN_LEN {
        return Err(LayoutError::Unsupported);
    }
    let mut records = Vec::new();
    let mut cur: Vec<(u32, &[u8])> = Vec::new();
    let mut trailer = false;
    let mut pos = XINPGEN_LEN;
    while pos < buf.len() {
        if buf.len() - pos < 8 {
            return Err(LayoutError::Truncated);
        }
        let len = le_u32(buf, pos) as usize;
        let kind = le_u32(buf, pos + 4);
        if len == XINPGEN_LEN {
            if pos + XINPGEN_LEN != buf.len() {
                return Err(LayoutError::Unsupported);
            }
            trailer = true;
            break;
        }
        if len < 8 {
            return Err(LayoutError::Unsupported);
        }
        if pos + len > buf.len() {
            return Err(LayoutError::Truncated);
        }
        if matches!(kind, XSO_INPCB | XSO_UNPCB) && !cur.is_empty() {
            records.push(PcbRecord(std::mem::take(&mut cur)));
        }
        cur.push((kind, &buf[pos..pos + len]));
        pos += roundup8(len);
    }
    if !cur.is_empty() {
        records.push(PcbRecord(cur));
    }
    if !records.is_empty() && !trailer {
        return Err(LayoutError::Truncated);
    }
    Ok(records)
}

/// `net.inet.tcp.pcblist_n` or `net.inet.udp.pcblist_n` records into
/// listener facts: TCP listeners (`t_state == TCPS_LISTEN`) and UDP
/// pcbs with an unspecified remote, both families (`inp_vflag`).
pub fn pcblist_inet(buf: &[u8], proto: &str) -> Result<Vec<ListenerFact>, LayoutError> {
    if proto != "tcp" && proto != "udp" {
        return Err(LayoutError::Unsupported);
    }
    let mut out = Vec::new();
    for rec in pcb_records(buf)? {
        let Some(inpcb) = rec.get(XSO_INPCB) else {
            return Err(LayoutError::Unsupported);
        };
        if inpcb.len() < XINPCB_MIN {
            return Err(LayoutError::Unsupported);
        }
        let fport = be_u16(inpcb, XINPCB_FPORT);
        let lport = be_u16(inpcb, XINPCB_LPORT);
        let vflag = inpcb[XINPCB_VFLAG];
        let faddr = &inpcb[XINPCB_FADDR..XINPCB_FADDR + 16];
        let laddr = &inpcb[XINPCB_LADDR..XINPCB_LADDR + 16];
        if proto == "tcp" {
            let Some(xt) = rec.get(XSO_TCPCB) else {
                return Err(LayoutError::Unsupported);
            };
            if xt.len() < XTCPCB_MIN {
                return Err(LayoutError::Unsupported);
            }
            if le_i32(xt, XTCPCB_STATE) != TCPS_LISTEN {
                continue;
            }
        } else if !(fport == 0 && faddr.iter().all(|b| *b == 0)) {
            continue;
        }
        let (protocol, address) = if vflag & INP_IPV6 != 0 {
            let a: [u8; 16] = laddr.try_into().unwrap();
            (format!("{proto}6"), std::net::Ipv6Addr::from(a).to_string())
        } else if vflag & INP_IPV4 != 0 {
            let a: [u8; 4] = laddr[12..16].try_into().unwrap();
            (proto.to_string(), std::net::Ipv4Addr::from(a).to_string())
        } else {
            return Err(LayoutError::Unsupported);
        };
        out.push(ListenerFact {
            protocol,
            address,
            port: lport,
        });
    }
    Ok(out)
}

/// `net.local.stream.pcblist_n` or `net.local.dgram.pcblist_n` records
/// into unix socket facts: the bound `sockaddr_un` (empty when
/// unbound), the socket type, and the listen flag from `so_options`.
pub fn pcblist_unix(buf: &[u8]) -> Result<Vec<UnixSocketFact>, LayoutError> {
    let mut out = Vec::new();
    for rec in pcb_records(buf)? {
        let Some(unpcb) = rec.get(XSO_UNPCB) else {
            return Err(LayoutError::Unsupported);
        };
        if unpcb.len() < XUNPCB_MIN {
            return Err(LayoutError::Unsupported);
        }
        let sun_len = unpcb[XUNPCB_ADDR] as usize;
        let sun_family = unpcb[XUNPCB_ADDR + 1];
        let path = if sun_family == AF_UNIX && sun_len > 2 {
            if sun_len > XUNPCB_ADDR_MAX || XUNPCB_ADDR + sun_len > unpcb.len() {
                return Err(LayoutError::Unsupported);
            }
            let raw = &unpcb[XUNPCB_ADDR + 2..XUNPCB_ADDR + sun_len];
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            Some(raw[..end].to_vec())
        } else {
            None
        };
        let Some(xso) = rec.get(XSO_SOCKET) else {
            return Err(LayoutError::Unsupported);
        };
        if xso.len() < XSOCKET_MIN {
            return Err(LayoutError::Unsupported);
        }
        let kind = match le_i16(xso, XSOCKET_TYPE) {
            SOCK_STREAM => "stream".to_string(),
            SOCK_DGRAM => "dgram".to_string(),
            SOCK_SEQPACKET => "seqpacket".to_string(),
            n => format!("type-{n}"),
        };
        out.push(UnixSocketFact {
            path,
            kind,
            listening: le_u32(xso, XSOCKET_OPTIONS) & SO_ACCEPTCONN != 0,
        });
    }
    Ok(out)
}

/// `sysctl NET_RT_DUMP` output: a sequence of `rt_msghdr` records; only
/// `RTM_GET` entries carry routes. The destination family sets the
/// fact family, the netmask the prefix length (`RTF_HOST` without a
/// mask is a host route), `RTA_GATEWAY` the next hop, and `RTA_IFP`
/// the interface name.
pub fn rt_dump(buf: &[u8]) -> Result<Vec<RouteFact>, LayoutError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if buf.len() - pos < RT_MSGHDR_LEN {
            return Err(LayoutError::Truncated);
        }
        let msglen = le_u16(buf, pos) as usize;
        if msglen < RT_MSGHDR_LEN || pos + msglen > buf.len() {
            return Err(LayoutError::Truncated);
        }
        let msg = &buf[pos..pos + msglen];
        if msg[2] != RTM_VERSION {
            return Err(LayoutError::Unsupported);
        }
        if msg[3] == RTM_GET {
            out.push(rt_one(msg)?);
        }
        pos += msglen;
    }
    Ok(out)
}

fn rt_one(m: &[u8]) -> Result<RouteFact, LayoutError> {
    let flags = le_i32(m, 8);
    let addrs = le_i32(m, 12);
    let mut dst = None;
    let mut gw = None;
    let mut mask = None;
    let mut ifp = None;
    let mut p = RT_MSGHDR_LEN;
    for bit in 0..8usize {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        if p + 2 > m.len() {
            return Err(LayoutError::Truncated);
        }
        let len = m[p] as usize;
        if len < 2 || p + len > m.len() {
            return Err(LayoutError::Truncated);
        }
        match bit {
            RTAX_DST => dst = Some(&m[p..p + len]),
            RTAX_GATEWAY => gw = Some(&m[p..p + len]),
            RTAX_NETMASK => mask = Some(&m[p..p + len]),
            RTAX_IFP => ifp = Some(&m[p..p + len]),
            _ => {}
        }
        p += (len + 3) & !3;
    }
    let Some(dst) = dst else {
        return Err(LayoutError::Unsupported);
    };
    let host = flags & RTF_HOST != 0;
    let (family, destination) = match dst[1] {
        AF_INET => {
            if dst.len() < 8 {
                return Err(LayoutError::Unsupported);
            }
            let addr = u32::from_be_bytes(dst[4..8].try_into().unwrap());
            let plen = match mask {
                Some(mk) if mk.len() >= 8 && mk[1] == AF_INET => {
                    u32::from_be_bytes(mk[4..8].try_into().unwrap()).count_ones()
                }
                Some(_) => return Err(LayoutError::Unsupported),
                None if host => 32,
                None => 0,
            };
            let net = addr & mask_v4(plen);
            ("inet", format!("{}/{plen}", std::net::Ipv4Addr::from(net)))
        }
        AF_INET6 => {
            if dst.len() < 24 {
                return Err(LayoutError::Unsupported);
            }
            let addr: [u8; 16] = dst[8..24].try_into().unwrap();
            let plen = match mask {
                Some(mk) if mk.len() >= 24 && mk[1] == AF_INET6 => {
                    mk[8..24].iter().map(|b| b.count_ones()).sum::<u32>()
                }
                Some(_) => return Err(LayoutError::Unsupported),
                None if host => 128,
                None => 0,
            };
            let net = mask_v6(&addr, plen);
            ("inet6", format!("{}/{plen}", std::net::Ipv6Addr::from(net)))
        }
        _ => return Err(LayoutError::Unsupported),
    };
    let gateway = match gw {
        Some(g) if g.len() >= 8 && g[1] == AF_INET => {
            Some(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&g[4..8]).unwrap()).to_string())
        }
        Some(g) if g.len() >= 24 && g[1] == AF_INET6 => {
            Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&g[8..24]).unwrap()).to_string())
        }
        // A link-layer gateway is a direct route: no next hop.
        Some(g) if g[1] == AF_LINK => None,
        Some(_) => return Err(LayoutError::Unsupported),
        None => None,
    };
    let interface = match ifp {
        // sockaddr_dl: sdl_nlen bytes of interface name at offset 8.
        Some(d) if d.len() >= 8 && d[1] == AF_LINK => {
            let n = (d[5] as usize).min(d.len() - 8);
            Some(String::from_utf8_lossy(&d[8..8 + n]).into_owned())
        }
        Some(_) => return Err(LayoutError::Unsupported),
        None => None,
    };
    Ok(RouteFact {
        family: family.to_string(),
        destination,
        gateway,
        interface,
    })
}

fn mask_v4(plen: u32) -> u32 {
    if plen == 0 {
        0
    } else {
        u32::MAX << (32 - plen)
    }
}

fn mask_v6(addr: &[u8; 16], plen: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let bits = (plen as i32 - i32::try_from(i).unwrap() * 8).clamp(0, 8) as u32;
        *o = addr[i] & (0xffu8 << (8 - bits) as u8);
    }
    out
}

/// The `struct proc_fdinfo` records of `proc_pidinfo(PROC_PIDLISTFDS)`:
/// 8-byte `{ fd, fdtype }` pairs.
pub fn proc_fd_list(buf: &[u8]) -> Result<Vec<(i32, u32)>, LayoutError> {
    if !buf.len().is_multiple_of(8) {
        return Err(LayoutError::Truncated);
    }
    Ok(buf
        .chunks_exact(8)
        .map(|c| (le_i32(c, 0), le_u32(c, 4)))
        .collect())
}

/// `sizeof(struct vnode_fdinfowithpath)`: 24 bytes of `proc_fileinfo`,
/// 152 bytes of `vnode_info`, and the 1024-byte path buffer.
pub const VNODE_FDINFO_PATH_LEN: usize = 1200;
const VNODE_PATH_OFF: usize = 176;

/// One `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)` buffer into the file
/// type and the NUL-terminated vnode path (xnu proc_info.h).
pub fn vnode_path_info(buf: &[u8]) -> Result<(i32, Vec<u8>), LayoutError> {
    if buf.len() < VNODE_FDINFO_PATH_LEN {
        return Err(LayoutError::Truncated);
    }
    let fi_type = le_i32(buf, 16);
    let raw = &buf[VNODE_PATH_OFF..VNODE_FDINFO_PATH_LEN];
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    Ok((fi_type, raw[..end].to_vec()))
}

//! The Linux universe enumerators and attribute sources.
//!
//! `linux.mounts` runs first and arms the no-touch gate (KTD26); every
//! other source then runs under the guard in declared order. Attribute
//! sources produce layer attributes (R12): status fields, namespaces,
//! cgroups, id maps, the yama ptrace scope, the Landlock ABI, and the
//! user-namespace sysctls (attributes only, KTD28). The home directory
//! resolves from `etc/passwd`, never `HOME` (KTD15).

use std::collections::BTreeMap;

pub use super::Scan;
use super::{
    Outcome, bfield, check_members, denial_reason, devices, env_members, fact_reason, fd_members,
    flagfield, ifield, ipv4_from_proc, ipv6_from_proc, ipv6_from_route, lossy, masked, member,
    proc_denial, resolvers, run, socket_files, tfield,
};
use crate::data::{Budgets, Data};
use crate::facts::Fact;
use crate::model::{
    AttrValue, Member, NamespaceInode, Universe, UniverseState, Unknown, UnknownReason,
};
use crate::reader::{Denial, Mount, Reader};

/// The capability name table; bits beyond it render as `cap_<n>`.
const CAP_NAMES: &[&str] = &[
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// The five capability sets in `proc/self/status` order.
const CAP_SETS: [(&str, &str); 5] = [
    ("CapInh", "inheritable"),
    ("CapPrm", "permitted"),
    ("CapEff", "effective"),
    ("CapBnd", "bounding"),
    ("CapAmb", "ambient"),
];

/// Status fields the `linux.attr.status` source must all find (R12).
const STATUS_FIELDS: [&str; 7] = [
    "NoNewPrivs",
    "Seccomp",
    "Seccomp_filters",
    "NSpid",
    "Uid",
    "Gid",
    "TracerPid",
];

/// The user-namespace sysctls of signal `linux.sysctl.userns` (KTD28):
/// integer attributes only, each absent when its file is missing.
const USERNS_SYSCTLS: [(&[u8], &str); 3] = [
    (b"proc/sys/user/max_user_namespaces", "max_user_namespaces"),
    (
        b"proc/sys/kernel/unprivileged_userns_clone",
        "unprivileged_userns_clone",
    ),
    (
        b"proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        "apparmor_restrict_unprivileged_userns",
    ),
];

/// Runs every Linux source through the reader and returns the per-source
/// states, attributes, identity fields, and the home verdict (KTD3, R12).
pub fn enumerate<R: Reader>(r: &mut R, data: &Data) -> Scan {
    let budgets = &data.budgets;
    let mut outcomes: BTreeMap<&str, Outcome> = BTreeMap::new();
    let mut unknowns: Vec<Unknown> = Vec::new();
    let mut attributes: BTreeMap<String, AttrValue> = BTreeMap::new();
    let mut euid = None;
    let mut egid = None;
    let mut tracer_pid = None;
    let u = |id: &str| -> &crate::data::Universe {
        data.universes
            .iter()
            .find(|u| u.id == id)
            .unwrap_or_else(|| panic!("declared universe {id}"))
    };

    // 1. Mounts first: the only call allowed before the gate arms.
    let mut mounts: Vec<Mount> = Vec::new();
    let mounts_out = run(|| mountinfo(r, u("linux.mounts"), budgets));
    match mounts_out {
        Ok((members, table)) => {
            mounts = table;
            r.arm_mounts(mounts.clone());
            outcomes.insert("linux.mounts", Outcome::Enumerated(members));
        }
        Err(reason) => {
            r.mounts_unknown();
            outcomes.insert("linux.mounts", Outcome::Unknown(reason));
        }
    }

    // 2. proc/self/status: the attribute fields plus the euid every
    // <euid> path substitutes.
    match run(|| status(r, budgets)) {
        Ok((attrs, st)) => {
            attributes.extend(attrs);
            euid = st.euid;
            egid = st.egid;
            tracer_pid = st.tracer_pid;
        }
        Err(reason) => unknowns.push(unknown("linux.attr.status", reason)),
    }

    // 3. Universes in declared order.
    let unix = run(|| unix_sockets(r, u("linux.unix-sockets"), budgets));
    outcomes.insert("linux.unix-sockets", outcome(unix));

    let sock = run(|| socket_files::enumerate(r, &mounts, euid, budgets));
    outcomes.insert("linux.socket-files", outcome(sock));

    let listeners = run(|| listeners(r, u("linux.listeners"), budgets));
    outcomes.insert("linux.listeners", outcome(listeners));

    outcomes.insert(
        "linux.fds",
        outcome(run(|| fds(r, u("linux.fds"), budgets))),
    );

    outcomes.insert("linux.env-names", outcome(run(|| env_names(r))));

    let caps = run(|| capabilities(r, budgets));
    outcomes.insert("linux.capabilities", outcome(caps));

    let routes = run(|| routes(r, u("linux.routes"), budgets));
    outcomes.insert("linux.routes", outcome(routes));

    let resolv = run(|| resolvers::enumerate_linux(r, budgets));
    outcomes.insert("linux.resolvers", resolv.unwrap_or_else(Outcome::Unknown));

    let ifaces = run(|| interfaces(r, u("linux.interfaces"), budgets));
    outcomes.insert("linux.interfaces", outcome(ifaces));

    let devs = run(|| devices::enumerate(r, &mounts, u("linux.devices"), budgets));
    outcomes.insert("linux.devices", outcome(devs));

    // 4. The remaining attribute sources.
    match run(|| namespaces(r, budgets)) {
        Ok(attrs) => attributes.extend(attrs),
        Err(reason) => unknowns.push(unknown("linux.attr.namespaces", reason)),
    }
    match run(|| cgroups(r, budgets)) {
        Ok(attrs) => attributes.extend(attrs),
        Err(reason) => unknowns.push(unknown("linux.attr.cgroup", reason)),
    }
    match run(|| id_maps(r, budgets)) {
        Ok(attrs) => attributes.extend(attrs),
        Err(reason) => unknowns.push(unknown("linux.attr.id-maps", reason)),
    }
    match run(|| ptrace_scope(r, budgets)) {
        Ok(Some(attr)) => {
            attributes.insert("ptrace_scope".to_string(), attr);
        }
        Ok(None) => {}
        Err(reason) => unknowns.push(unknown("linux.attr.ptrace-scope", reason)),
    }
    match run(|| landlock(r)) {
        Ok(attr) => {
            attributes.insert("landlock-abi".to_string(), attr);
        }
        Err(reason) => unknowns.push(unknown("linux.attr.landlock-abi", reason)),
    }
    match run(|| userns_sysctls(r, budgets)) {
        Ok(attrs) => attributes.extend(attrs),
        Err(reason) => unknowns.push(unknown("linux.sysctl.userns", reason)),
    }

    // 5. The account home from etc/passwd (KTD15).
    let home = run(|| home(r, euid, budgets));

    // Assemble: every declared universe in order, macOS entries not
    // applicable (R24).
    let mut universes = Vec::new();
    for u in &data.universes {
        if u.platform == "linux" {
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
        .filter(|n| n.platform == "linux")
        .map(|n| n.id.clone())
        .collect();
    if r.accepted_ancestor_pidns() {
        attributes.insert(
            "proc-from-ancestor-pidns".to_string(),
            AttrValue::Bool(true),
        );
    }

    Scan {
        universes,
        unknowns,
        attributes,
        not_applicable,
        euid,
        egid,
        home,
        tracer_pid,
        ancestor_pidns: r.accepted_ancestor_pidns(),
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
// linux.mounts
// ---------------------------------------------------------------------------

struct MountRow {
    mount_id: u64,
    parent_id: u64,
    major_minor: String,
    root: Vec<u8>,
    point: Vec<u8>,
    options: String,
    fstype: String,
    source: Vec<u8>,
    writable: bool,
}

fn mountinfo(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<(Vec<Member>, Vec<Mount>), UnknownReason> {
    let bytes = r
        .read(b"proc/self/mountinfo", budgets.bytes_per_file)
        .map_err(proc_denial)?;
    let rows = parse_mountinfo(&bytes)?;
    let members: Vec<Member> = rows.iter().map(mount_member).collect();
    if (members.len() as u64) < u.min_members {
        return Err(UnknownReason::ImplausiblyEmpty);
    }
    check_members(&members, budgets)?;
    let table = rows
        .iter()
        .map(|m| Mount::from_bytes(&m.point, &m.fstype))
        .collect();
    Ok((members, table))
}

fn mount_member(m: &MountRow) -> Member {
    member(
        vec![
            bfield("mount-point", &m.point, true),
            tfield("fstype", &m.fstype, true),
            bfield("mount-root", &m.root, true),
            ifield("mount-id", m.mount_id),
            ifield("parent-id", m.parent_id),
            tfield("major-minor", &m.major_minor, false),
            bfield("mount-source", &m.source, false),
            tfield("options", &m.options, false),
            flagfield("writable", m.writable, false),
        ],
        lossy(&m.point),
    )
}

/// mountinfo: `id parent major:minor root point options [opt...] - fstype
/// source super-opts`. Octal escapes in the byte fields are decoded.
fn parse_mountinfo(bytes: &[u8]) -> Result<Vec<MountRow>, UnknownReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| UnknownReason::Partial)?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            return Err(UnknownReason::Partial);
        };
        if sep < 6 || fields.len() < sep + 3 {
            return Err(UnknownReason::Partial);
        }
        let (pre, post) = (&fields[..sep], &fields[sep + 1..]);
        let deescape = |s: &str| -> Vec<u8> {
            let b = s.as_bytes();
            let mut out = Vec::with_capacity(b.len());
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'\\'
                    && i + 3 < b.len()
                    && b[i + 1].is_ascii_digit()
                    && b[i + 2].is_ascii_digit()
                    && b[i + 3].is_ascii_digit()
                {
                    let v = (b[i + 1] - b'0') as u16 * 64
                        + (b[i + 2] - b'0') as u16 * 8
                        + (b[i + 3] - b'0') as u16;
                    if v <= 255 {
                        out.push(v as u8);
                        i += 4;
                        continue;
                    }
                }
                out.push(b[i]);
                i += 1;
            }
            out
        };
        let mount_id = pre[0].parse().map_err(|_| UnknownReason::Partial)?;
        let parent_id = pre[1].parse().map_err(|_| UnknownReason::Partial)?;
        let options = pre[5].to_string();
        let writable = pre[5].split(',').any(|o| o == "rw");
        rows.push(MountRow {
            mount_id,
            parent_id,
            major_minor: pre[2].to_string(),
            root: deescape(pre[3]),
            point: deescape(pre[4]),
            options,
            fstype: post[0].to_string(),
            source: deescape(post[1]),
            writable,
        });
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// proc/self/status: the status attribute source and the capability set.
// ---------------------------------------------------------------------------

struct Status {
    euid: Option<u32>,
    egid: Option<u32>,
    tracer_pid: Option<u64>,
}

fn status(
    r: &mut impl Reader,
    budgets: &Budgets,
) -> Result<(BTreeMap<String, AttrValue>, Status), UnknownReason> {
    let bytes = r
        .read(b"proc/self/status", budgets.bytes_per_file)
        .map_err(proc_denial)?;
    let fields = status_fields(&bytes);
    let mut attrs = BTreeMap::new();
    for name in STATUS_FIELDS {
        let Some(v) = fields.get(name) else {
            return Err(UnknownReason::Partial);
        };
        match name {
            "Uid" | "Gid" => {
                attrs.insert(name.to_string(), AttrValue::Str(v.to_string()));
            }
            "NSpid" => {
                let depth = v.split_whitespace().count() as i64;
                attrs.insert("nspid-depth".to_string(), AttrValue::Int(depth));
            }
            _ => {
                let n: i64 = v.trim().parse().map_err(|_| UnknownReason::Partial)?;
                attrs.insert(name.to_string(), AttrValue::Int(n));
            }
        }
    }
    let num = |name: &str| -> Option<u32> {
        fields
            .get(name)?
            .split_whitespace()
            .nth(1)
            .and_then(|f| f.parse().ok())
    };
    let st = Status {
        euid: num("Uid"),
        egid: num("Gid"),
        tracer_pid: fields.get("TracerPid").and_then(|v| v.trim().parse().ok()),
    };
    Ok((attrs, st))
}

/// `proc/self/status` as a field-name to value map.
fn status_fields(bytes: &[u8]) -> BTreeMap<String, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            out.insert(k.to_string(), v.trim().to_string());
        }
    }
    out
}

fn capabilities(r: &mut impl Reader, budgets: &Budgets) -> Result<Vec<Member>, UnknownReason> {
    let bytes = r
        .read(b"proc/self/status", budgets.bytes_per_file)
        .map_err(proc_denial)?;
    let fields = status_fields(&bytes);
    let mut masks = [0u64; 5];
    for (i, (field, _)) in CAP_SETS.iter().enumerate() {
        let Some(v) = fields.get(*field) else {
            return Err(UnknownReason::Partial);
        };
        masks[i] = u64::from_str_radix(v.trim(), 16).map_err(|_| UnknownReason::Partial)?;
    }
    let raw = masks
        .iter()
        .map(|m| format!("{m:016x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut members = Vec::new();
    for (i, (_, set)) in CAP_SETS.iter().enumerate() {
        for bit in 0..64 {
            if masks[i] & (1u64 << bit) == 0 {
                continue;
            }
            let name = CAP_NAMES
                .get(bit as usize)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("cap_{bit}"));
            members.push(member(
                vec![
                    tfield("name", &name, true),
                    tfield("set", set, false),
                    tfield("raw-masks", &raw, false),
                ],
                name,
            ));
        }
    }
    check_members(&members, budgets)?;
    Ok(members)
}

// ---------------------------------------------------------------------------
// linux.unix-sockets
// ---------------------------------------------------------------------------

fn unix_sockets(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let bytes = r
        .read(b"proc/net/unix", budgets.bytes_per_file)
        .map_err(proc_denial)?;
    if masked(&bytes, &u.masked["proc/net/unix"]) {
        return Err(UnknownReason::MaskedOrTruncated);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| UnknownReason::Partial)?;
    let mut members = Vec::new();
    let mut unnamed: BTreeMap<(String, bool), u64> = BTreeMap::new();
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 7 || !f[0].ends_with(':') {
            return Err(UnknownReason::Partial);
        }
        let hex = |s: &str| u64::from_str_radix(s, 16);
        let refcount = hex(f[1]).map_err(|_| UnknownReason::Partial)?;
        let flags = hex(f[3]).map_err(|_| UnknownReason::Partial)?;
        let typ = hex(f[4]).map_err(|_| UnknownReason::Partial)?;
        let st = hex(f[5]).map_err(|_| UnknownReason::Partial)?;
        let inode: u64 = f[6].parse().map_err(|_| UnknownReason::Partial)?;
        let listening = flags & 0x10000 != 0;
        let kind = match typ {
            1 => "stream".to_string(),
            2 => "dgram".to_string(),
            5 => "seqpacket".to_string(),
            n => format!("type-{n}"),
        };
        let path = f[7..].join(" ");
        if path.is_empty() {
            *unnamed.entry((kind, listening)).or_default() += 1;
            continue;
        }
        members.push(member(
            vec![
                bfield("path", path.as_bytes(), true),
                tfield("socket-type", &kind, true),
                flagfield("listening", listening, true),
                ifield("inode", inode),
                ifield("refcount", refcount),
                ifield("state", st),
                ifield("unnamed-count", 0),
            ],
            path.clone(),
        ));
    }
    // Unnamed sockets fold into one member per type (universe table).
    for ((kind, listening), count) in unnamed {
        members.push(member(
            vec![
                bfield("path", b"", true),
                tfield("socket-type", &kind, true),
                flagfield("listening", listening, true),
                ifield("inode", 0),
                ifield("refcount", 0),
                ifield("state", 0),
                ifield("unnamed-count", count),
            ],
            format!("<unnamed {kind}>"),
        ));
    }
    check_members(&members, budgets)?;
    Ok(members)
}

// ---------------------------------------------------------------------------
// linux.listeners
// ---------------------------------------------------------------------------

fn listeners(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let mut members = Vec::new();
    for (file, proto) in [("proc/net/tcp", "tcp"), ("proc/net/udp", "udp")] {
        read_inet_table(r, file, proto, u, budgets, &mut members)?;
    }
    // The IPv6 pair is absent only when IPv6 itself is absent.
    match r.metadata(b"proc/net/if_inet6") {
        Ok(_) => {
            for (file, proto) in [("proc/net/tcp6", "tcp6"), ("proc/net/udp6", "udp6")] {
                read_inet_table_v6(r, file, proto, u, budgets, &mut members)?;
            }
        }
        Err(Denial::Absent) => {}
        Err(d) => return Err(proc_denial(d)),
    }
    check_members(&members, budgets)?;
    Ok(members)
}

fn read_inet_table(
    r: &mut impl Reader,
    file: &str,
    proto: &str,
    u: &crate::data::Universe,
    budgets: &Budgets,
    members: &mut Vec<Member>,
) -> Result<(), UnknownReason> {
    let bytes = r
        .read(file.as_bytes(), budgets.bytes_per_file)
        .map_err(proc_denial)?;
    if masked(&bytes, &u.masked[file]) {
        return Err(UnknownReason::MaskedOrTruncated);
    }
    parse_inet(&bytes, proto, members)
}

fn read_inet_table_v6(
    r: &mut impl Reader,
    file: &str,
    proto: &str,
    u: &crate::data::Universe,
    budgets: &Budgets,
    members: &mut Vec<Member>,
) -> Result<(), UnknownReason> {
    let bytes = r
        .read(file.as_bytes(), budgets.bytes_per_file)
        .map_err(denial_reason)?;
    if masked(&bytes, &u.masked[file]) {
        return Err(UnknownReason::MaskedOrTruncated);
    }
    parse_inet(&bytes, proto, members)
}

/// `proc/net/{tcp,tcp6,udp,udp6}` rows: TCP listeners (state 0A) and UDP
/// rows with an unspecified remote join the universe.
fn parse_inet(bytes: &[u8], proto: &str, members: &mut Vec<Member>) -> Result<(), UnknownReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| UnknownReason::Partial)?;
    let v6 = proto.ends_with('6');
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || !f[0].ends_with(':') {
            return Err(UnknownReason::Partial);
        }
        let tcp = proto.starts_with("tcp");
        if tcp && f[3] != "0A" {
            continue;
        }
        let Some((local_addr, local_port)) = addr_port(f[1], v6) else {
            return Err(UnknownReason::Partial);
        };
        if !tcp {
            let Some((rem_addr, rem_port)) = addr_port(f[2], v6) else {
                return Err(UnknownReason::Partial);
            };
            // Only rows with an unspecified remote are members.
            if !(rem_addr == "0.0.0.0" || rem_addr == "::") || rem_port != 0 {
                continue;
            }
        }
        let uid: u64 = f[7].parse().map_err(|_| UnknownReason::Partial)?;
        let inode: u64 = f[9].parse().map_err(|_| UnknownReason::Partial)?;
        let display = if v6 {
            format!("{proto} [{local_addr}]:{local_port}")
        } else {
            format!("{proto} {local_addr}:{local_port}")
        };
        members.push(member(
            vec![
                tfield("protocol", proto, true),
                tfield("local-address", &local_addr, true),
                ifield("port", local_port),
                ifield("inode", inode),
                ifield("uid", uid),
            ],
            display,
        ));
    }
    Ok(())
}

/// `HEXADDR:HEXPORT` into (address string, port).
fn addr_port(field: &str, v6: bool) -> Option<(String, u64)> {
    let (addr, port) = field.split_once(':')?;
    let port = u64::from_str_radix(port, 16).ok()?;
    let addr = if v6 {
        ipv6_from_proc(addr)?.to_string()
    } else {
        ipv4_from_proc(addr)?.to_string()
    };
    Some((addr, port))
}

// ---------------------------------------------------------------------------
// linux.fds and linux.env-names (facts, KTD8)
// ---------------------------------------------------------------------------

fn fds(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let fact = r.facts().fds.clone();
    match fact {
        Fact::Read(entries) => {
            if entries.len() < u.min_members as usize {
                // The listing handle is always a member; an empty
                // inventory is implausibly empty.
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

// ---------------------------------------------------------------------------
// linux.routes
// ---------------------------------------------------------------------------

fn routes(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let mut members = Vec::new();
    let bytes = r
        .read(b"proc/net/route", budgets.bytes_per_file)
        .map_err(proc_denial)?;
    if masked(&bytes, &u.masked["proc/net/route"]) {
        return Err(UnknownReason::MaskedOrTruncated);
    }
    parse_route(&bytes, &mut members)?;
    match r.metadata(b"proc/net/if_inet6") {
        Ok(_) => {
            let b6 = r
                .read(b"proc/net/ipv6_route", budgets.bytes_per_file)
                .map_err(denial_reason)?;
            parse_route6(&b6, &mut members)?;
        }
        Err(Denial::Absent) => {}
        Err(d) => return Err(proc_denial(d)),
    }
    check_members(&members, budgets)?;
    Ok(members)
}

/// `proc/net/route`: `Iface Dest Gw Flags RefCnt Use Metric Mask ...`.
fn parse_route(bytes: &[u8], members: &mut Vec<Member>) -> Result<(), UnknownReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| UnknownReason::Partial)?;
    for line in text.lines().skip(1) {
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            return Err(UnknownReason::Partial);
        }
        let (Some(dest), Some(gw), Some(mask)) = (
            ipv4_from_proc(f[1]),
            ipv4_from_proc(f[2]),
            ipv4_from_proc(f[7]),
        ) else {
            return Err(UnknownReason::Partial);
        };
        let flags = f[3].to_string();
        let refcount: u64 = f[4].parse().map_err(|_| UnknownReason::Partial)?;
        let use_: u64 = f[5].parse().map_err(|_| UnknownReason::Partial)?;
        let metric: u64 = f[6].parse().map_err(|_| UnknownReason::Partial)?;
        let net = u32::from(dest) & u32::from(mask);
        let plen = u32::from(mask).count_ones();
        let prefix = format!("{}/{plen}", std::net::Ipv4Addr::from(net));
        let gw_s = gw.to_string();
        let display = if gw.is_unspecified() {
            format!("{prefix} dev {}", f[0])
        } else {
            format!("{prefix} via {gw} dev {}", f[0])
        };
        members.push(member(
            vec![
                tfield("family", "ipv4", true),
                tfield("destination-prefix", &prefix, true),
                tfield("gateway", &gw_s, true),
                tfield("interface", f[0], true),
                ifield("metric", metric),
                tfield("flags", &flags, false),
                ifield("use", use_),
                ifield("refcount", refcount),
            ],
            display,
        ));
    }
    Ok(())
}

/// `proc/net/ipv6_route`: `dest plen src splen nexthop metric refcount
/// use flags iface`, addresses in plain network order.
fn parse_route6(bytes: &[u8], members: &mut Vec<Member>) -> Result<(), UnknownReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| UnknownReason::Partial)?;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            return Err(UnknownReason::Partial);
        }
        let (Some(dest), Some(nh)) = (ipv6_from_route(f[0]), ipv6_from_route(f[4])) else {
            return Err(UnknownReason::Partial);
        };
        let plen = u64::from_str_radix(f[1], 16).map_err(|_| UnknownReason::Partial)?;
        let metric = u64::from_str_radix(f[5], 16).map_err(|_| UnknownReason::Partial)?;
        let refcount = u64::from_str_radix(f[6], 16).map_err(|_| UnknownReason::Partial)?;
        let use_ = u64::from_str_radix(f[7], 16).map_err(|_| UnknownReason::Partial)?;
        let flags = f[8].to_string();
        let prefix = format!("{dest}/{plen}");
        let gw_s = nh.to_string();
        let display = if nh.is_unspecified() {
            format!("{prefix} dev {}", f[9])
        } else {
            format!("{prefix} via {nh} dev {}", f[9])
        };
        members.push(member(
            vec![
                tfield("family", "ipv6", true),
                tfield("destination-prefix", &prefix, true),
                tfield("gateway", &gw_s, true),
                tfield("interface", f[9], true),
                ifield("metric", metric),
                tfield("flags", &flags, false),
                ifield("use", use_),
                ifield("refcount", refcount),
            ],
            display,
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// linux.interfaces
// ---------------------------------------------------------------------------

fn interfaces(
    r: &mut impl Reader,
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let bytes = r
        .read(b"proc/net/dev", budgets.bytes_per_file)
        .map_err(proc_denial)?;
    if masked(&bytes, &u.masked["proc/net/dev"]) {
        return Err(UnknownReason::MaskedOrTruncated);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| UnknownReason::Partial)?;
    let mut members = Vec::new();
    for line in text.lines().skip(2) {
        if line.is_empty() {
            continue;
        }
        let Some((name, _)) = line.split_once(':') else {
            return Err(UnknownReason::Partial);
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(UnknownReason::Partial);
        }
        // Counters are never emitted (universe table).
        members.push(member(vec![tfield("name", name, true)], name.to_string()));
    }
    check_members(&members, budgets)?;
    Ok(members)
}

// ---------------------------------------------------------------------------
// Attribute sources: namespaces, cgroups, id maps, ptrace scope,
// Landlock ABI, and the user-namespace sysctls.
// ---------------------------------------------------------------------------

fn namespaces(
    r: &mut impl Reader,
    budgets: &Budgets,
) -> Result<BTreeMap<String, AttrValue>, UnknownReason> {
    let entries = r.list(b"proc/self/ns").map_err(proc_denial)?;
    if entries.len() as u64 > budgets.entries_per_listing {
        return Err(UnknownReason::BudgetExceeded);
    }
    let mut ns = Vec::new();
    for (name, _meta) in entries {
        let mut path = b"proc/self/ns/".to_vec();
        path.extend_from_slice(&name);
        let target = r.readlink(&path).map_err(proc_denial)?;
        let text = lossy(&target);
        // Link text is `kind:[inode]`; the name stays the link's name.
        let Some(inner) = text
            .rsplit_once('[')
            .and_then(|(_, rest)| rest.strip_suffix(']'))
        else {
            return Err(UnknownReason::Partial);
        };
        let inode: u64 = inner.parse().map_err(|_| UnknownReason::Partial)?;
        ns.push(NamespaceInode {
            name: lossy(&name),
            inode,
        });
    }
    let mut attrs = BTreeMap::new();
    if let Some(ipc) = ns.iter().find(|n| n.name == "ipc") {
        attrs.insert("ns-ipc-inode".to_string(), AttrValue::Int(ipc.inode as i64));
    }
    attrs.insert("namespaces".to_string(), AttrValue::Namespaces(ns));
    Ok(attrs)
}

fn cgroups(
    r: &mut impl Reader,
    budgets: &Budgets,
) -> Result<BTreeMap<String, AttrValue>, UnknownReason> {
    let bytes = r
        .read(b"proc/self/cgroup", budgets.bytes_per_file)
        .map_err(proc_denial)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| UnknownReason::Partial)?;
    let lines: Vec<String> = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    Ok(BTreeMap::from([(
        "cgroups".to_string(),
        AttrValue::Strings(lines),
    )]))
}

fn id_maps(
    r: &mut impl Reader,
    budgets: &Budgets,
) -> Result<BTreeMap<String, AttrValue>, UnknownReason> {
    let mut attrs = BTreeMap::new();
    for (file, name) in [
        (b"proc/self/uid_map".as_slice(), "uid_map"),
        (b"proc/self/gid_map".as_slice(), "gid_map"),
    ] {
        let bytes = r.read(file, budgets.bytes_per_file).map_err(proc_denial)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| UnknownReason::Partial)?;
        if name == "uid_map" {
            let lines = text.lines().filter(|l| !l.trim().is_empty()).count() as i64;
            attrs.insert("uid-map-lines".to_string(), AttrValue::Int(lines));
        }
        attrs.insert(name.to_string(), AttrValue::Str(text.trim().to_string()));
    }
    Ok(attrs)
}

/// `proc/sys/kernel/yama/ptrace_scope`: absent when the yama directory is
/// missing; an integer attribute otherwise.
fn ptrace_scope(
    r: &mut impl Reader,
    budgets: &Budgets,
) -> Result<Option<AttrValue>, UnknownReason> {
    match r.read(b"proc/sys/kernel/yama/ptrace_scope", budgets.bytes_per_file) {
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes).map_err(|_| UnknownReason::Partial)?;
            let n: i64 = text.trim().parse().map_err(|_| UnknownReason::Partial)?;
            Ok(Some(AttrValue::Int(n)))
        }
        Err(Denial::Absent) => {
            // The signature is a missing yama directory on a real proc.
            match r.metadata(b"proc") {
                Err(Denial::Absent) => Err(UnknownReason::ProcNotMounted),
                Err(d) => Err(denial_reason(d)),
                Ok(_) => match r.metadata(b"proc/sys/kernel/yama") {
                    Err(Denial::Absent) => Ok(None),
                    Err(d) => Err(denial_reason(d)),
                    Ok(_) => Err(UnknownReason::Unreadable),
                },
            }
        }
        Err(d) => Err(denial_reason(d)),
    }
}

/// The Landlock ABI query result (R12): an integer attribute when read,
/// `not-built` or `disabled` otherwise; the domain itself is on the
/// not-observable list.
fn landlock(r: &mut impl Reader) -> Result<AttrValue, UnknownReason> {
    match r.facts().landlock_abi.as_ref() {
        Some(Fact::Read(v)) => Ok(AttrValue::Int(*v as i64)),
        Some(Fact::NotBuilt) => Ok(AttrValue::Str("not-built".to_string())),
        Some(Fact::Disabled) => Ok(AttrValue::Str("disabled".to_string())),
        Some(other) => Err(fact_reason(other)),
        None => Err(UnknownReason::Unreadable),
    }
}

/// `linux.sysctl.userns`: each file is a decimal integer attribute,
/// absent when missing (KTD28). A non-decimal value is `partial`.
fn userns_sysctls(
    r: &mut impl Reader,
    budgets: &Budgets,
) -> Result<BTreeMap<String, AttrValue>, UnknownReason> {
    let mut attrs = BTreeMap::new();
    for (path, name) in USERNS_SYSCTLS {
        match r.read(path, budgets.bytes_per_file) {
            Ok(bytes) => {
                let text = std::str::from_utf8(&bytes).map_err(|_| UnknownReason::Partial)?;
                let n: i64 = text.trim().parse().map_err(|_| UnknownReason::Partial)?;
                attrs.insert(name.to_string(), AttrValue::Int(n));
            }
            Err(Denial::Absent) => match r.metadata(b"proc") {
                Err(Denial::Absent) => return Err(UnknownReason::ProcNotMounted),
                Err(d) => return Err(denial_reason(d)),
                Ok(_) => {}
            },
            Err(d) => return Err(denial_reason(d)),
        }
    }
    Ok(attrs)
}

// ---------------------------------------------------------------------------
// The account home from etc/passwd (KTD15).
// ---------------------------------------------------------------------------

/// Resolves the effective uid's home through the reader. No entry, a
/// missing passwd file, or an unreadable uid all mean `no-account-home`;
/// read failures carry their own reason (R17, KTD15, KTD26).
fn home(
    r: &mut impl Reader,
    euid: Option<u32>,
    budgets: &Budgets,
) -> Result<Vec<u8>, UnknownReason> {
    let Some(euid) = euid else {
        // The uid itself is unreadable, so the account cannot be
        // resolved; the status source already reported its own unknown.
        return Err(UnknownReason::DependsOnUnknown);
    };
    let bytes = r
        .read(b"etc/passwd", budgets.bytes_per_file)
        .map_err(|d| match d {
            Denial::Absent => UnknownReason::NoAccountHome,
            d => denial_reason(d),
        })?;
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 6 {
            continue;
        }
        if f[2].parse::<u32>().ok() == Some(euid) {
            return Ok(f[5].as_bytes().to_vec());
        }
    }
    Err(UnknownReason::NoAccountHome)
}

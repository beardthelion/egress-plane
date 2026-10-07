//! Linux universe enumerators and attribute sources over the reader:
//! complete enumeration or one unknown reason, never a partial set (KTD3,
//! KTD9, KTD11, KTD15, KTD18, KTD24, KTD26, KTD28, KTD30).

use std::collections::BTreeSet;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_probe::data::Data;
use egress_probe::facts::Facts;
use egress_probe::model::{AttrValue, Member, MemberValue, UniverseState, UnknownReason};
use egress_probe::reader::{
    AccessMask, AccessResult, Denial, Meta, Mount, ReadCall, ReadLogEntry, Reader,
};
use egress_probe::snapshot::SnapshotReader;
use egress_probe::universe::linux;

// ---------------------------------------------------------------------------
// Case builder: a snapshot case directory with tree/, facts.toml, and an
// optional manifest.toml.
// ---------------------------------------------------------------------------

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Case {
    dir: PathBuf,
}

impl Case {
    fn linux(name: &str, pid: u64) -> Case {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("probe-linux-tests")
            .join(format!("{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tree")).unwrap();
        let c = Case { dir };
        c.facts(pid, FACTS);
        c
    }

    fn facts(&self, pid: u64, body: &str) -> &Self {
        self.file(
            "facts.toml",
            &format!("platform = \"linux\"\n[process]\nstate = \"read\"\npid = {pid}\n{body}"),
            false,
        )
    }

    fn tree(&self) -> PathBuf {
        self.dir.join("tree")
    }

    fn file(&self, rel: &str, contents: &str, in_tree: bool) -> &Self {
        let base = if in_tree {
            self.tree()
        } else {
            self.dir.clone()
        };
        let p = base.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, contents).unwrap();
        self
    }

    fn dir(&self, rel: &str) -> &Self {
        std::fs::create_dir_all(self.tree().join(rel)).unwrap();
        self
    }

    fn link(&self, rel: &str, target: &str) -> &Self {
        let p = self.tree().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        symlink(target, &p).unwrap();
        self
    }

    fn manifest(&self, text: &str) -> &Self {
        self.file("manifest.toml", text, false)
    }

    fn reader(&self) -> SnapshotReader {
        SnapshotReader::open(&self.dir).unwrap()
    }
}

const FACTS: &str = "\
[env_names]
state = \"read\"
names = [ { name = \"PATH\" }, { name = \"HOME\" } ]
[fds]
state = \"read\"
entries = [
    { fd = 0, target = \"/dev/null\" },
    { fd = 1, target = \"pipe:[66001]\" },
    { fd = 2, target = \"pipe:[66001]\" },
    { fd = 3, target = \"/proc/4242/fd\", probe_own = true },
]
[landlock_abi]
state = \"not-built\"
";

const MOUNTINFO: &str = "\
22 1 259:1 / / rw,relatime - ext4 /dev/sda1 rw
24 22 0:24 / /proc rw - proc proc rw
25 22 0:25 / /sys rw - sysfs sysfs rw
26 22 0:26 / /dev rw - devtmpfs devtmpfs rw
30 22 0:30 / /run rw - tmpfs tmpfs rw
";

const STATUS: &str = "\
Name:\tprobe
Pid:\t4242
TracerPid:\t0
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
NSpid:\t4242
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
NoNewPrivs:\t0
Seccomp:\t0
Seccomp_filters:\t0
";

const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const UDP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";
const UNIX_HEADER: &str = "Num       RefCount Protocol Flags    Type St Inode Path\n";
const DEV_HEADER: &str = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";
const ROUTE_HEADER: &str =
    "Iface\tDestination\tGateway\t\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";

/// A standard proc tree plus the ordinary non-proc files a plain case
/// needs: passwd with a root entry, resolv.conf, and one device node.
fn proc_tree(c: &Case, pid: u64) -> &Case {
    let p = pid.to_string();
    c.dir(&format!("proc/{p}/net"))
        .dir(&format!("proc/{p}/ns"))
        .dir("sys")
        .dir("dev")
        .dir("etc")
        .link("proc/self", &p)
        .link("proc/net", "self/net")
        .file(&format!("proc/{p}/mountinfo"), MOUNTINFO, true)
        .file(&format!("proc/{p}/status"), STATUS, true)
        .file(&format!("proc/{p}/net/tcp"), TCP_HEADER, true)
        .file(&format!("proc/{p}/net/udp"), UDP_HEADER, true)
        .file(&format!("proc/{p}/net/unix"), UNIX_HEADER, true)
        .file(&format!("proc/{p}/net/dev"), DEV_HEADER, true)
        .file(&format!("proc/{p}/net/route"), ROUTE_HEADER, true)
        .file(&format!("proc/{p}/cgroup"), "0::/init.scope\n", true)
        .file(
            &format!("proc/{p}/uid_map"),
            "         0          0 4294967295\n",
            true,
        )
        .file(
            &format!("proc/{p}/gid_map"),
            "         0          0 4294967295\n",
            true,
        )
        .link(&format!("proc/{p}/ns/mnt"), "mnt:[4026531841]")
        .link(&format!("proc/{p}/ns/ipc"), "ipc:[4026531839]")
        .link(&format!("proc/{p}/ns/net"), "net:[4026531993]")
        .file("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n", true)
        .file("etc/resolv.conf", "nameserver 8.8.8.8\n", true)
        .manifest(
            "[[node]]\npath = \"dev/null\"\ntype = \"char\"\nmajor = 1\nminor = 3\naccess = \"write\"\n",
        )
}

fn data() -> Data {
    Data::embedded().unwrap()
}

fn scan(c: &Case) -> linux::Scan {
    let mut r = c.reader();
    linux::enumerate(&mut r, &data())
}

fn universe<'a>(scan: &'a linux::Scan, id: &str) -> &'a egress_probe::model::Universe {
    scan.universes
        .iter()
        .find(|u| u.id == id)
        .unwrap_or_else(|| panic!("universe {id} in scan"))
}

fn members<'a>(scan: &'a linux::Scan, id: &str) -> &'a [Member] {
    &universe(scan, id).members
}

fn unknowns<'a>(scan: &'a linux::Scan, source: &'a str) -> Vec<&'a egress_probe::model::Unknown> {
    scan.unknowns
        .iter()
        .filter(|u| u.source == source)
        .collect()
}

fn field<'a>(m: &'a Member, name: &str) -> Option<&'a MemberValue> {
    m.fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

fn text(m: &Member, name: &str) -> Option<String> {
    match field(m, name) {
        Some(MemberValue::Text(b)) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    }
}

fn int(m: &Member, name: &str) -> Option<u64> {
    match field(m, name) {
        Some(MemberValue::Int(n)) => Some(*n),
        _ => None,
    }
}

fn flag(m: &Member, name: &str) -> Option<bool> {
    match field(m, name) {
        Some(MemberValue::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn attr_int(scan: &linux::Scan, name: &str) -> Option<i64> {
    match scan.attributes.get(name) {
        Some(AttrValue::Int(n)) => Some(*n),
        _ => None,
    }
}

fn displays(scan: &linux::Scan, id: &str) -> BTreeSet<String> {
    members(scan, id)
        .iter()
        .map(|m| m.display.clone())
        .collect()
}

fn has_log_under(r: &impl Reader, prefix: &str) -> bool {
    let p = format!("{prefix}/");
    r.read_log()
        .iter()
        .any(|e| e.path == prefix || e.path.starts_with(&p))
}

// ---------------------------------------------------------------------------
// linux.mounts
// ---------------------------------------------------------------------------

#[test]
fn mountinfo_octal_escapes_decode_to_bytes() {
    let c = Case::linux("mi-octal", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/mountinfo",
        "22 1 259:1 / / rw - ext4 /dev/sda1 rw\n\
         40 22 0:40 / /var/lib/my\\040dir rw - ext4 /dev/sda2 rw\n",
        true,
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.mounts").state,
        UniverseState::Enumerated
    );
    assert!(displays(&s, "linux.mounts").contains("/var/lib/my dir"));
}

#[test]
fn mountinfo_one_malformed_line_is_partial() {
    let c = Case::linux("mi-bad", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/mountinfo",
        "22 1 259:1 / / rw - ext4 /dev/sda1 rw\nnot a mountinfo line\n",
        true,
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.mounts").state,
        UniverseState::Unknown(UnknownReason::Partial)
    );
    // The gate saw a failed mount table: non-proc sources are gated.
    assert_eq!(
        universe(&s, "linux.resolvers").state,
        UniverseState::Unknown(UnknownReason::DependsOnUnknown)
    );
}

#[test]
fn mountinfo_empty_is_implausibly_empty() {
    let c = Case::linux("mi-empty", 4242);
    proc_tree(&c, 4242);
    c.file("proc/4242/mountinfo", "", true);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.mounts").state,
        UniverseState::Unknown(UnknownReason::ImplausiblyEmpty)
    );
}

#[test]
fn no_proc_reports_proc_not_mounted() {
    let c = Case::linux("no-proc", 4242);
    c.dir("etc").dir("dev").dir("sys");
    let s = scan(&c);
    for id in [
        "linux.mounts",
        "linux.unix-sockets",
        "linux.listeners",
        "linux.capabilities",
        "linux.routes",
        "linux.interfaces",
    ] {
        assert_eq!(
            universe(&s, id).state,
            UniverseState::Unknown(UnknownReason::ProcNotMounted),
            "{id}"
        );
    }
    for source in [
        "linux.attr.status",
        "linux.attr.cgroup",
        "linux.attr.id-maps",
        "linux.attr.namespaces",
        "linux.attr.ptrace-scope",
        "linux.sysctl.userns",
    ] {
        assert_eq!(
            unknowns(&s, source)
                .iter()
                .map(|u| u.reason)
                .collect::<Vec<_>>(),
            vec![UnknownReason::ProcNotMounted],
            "{source}"
        );
    }
    for id in ["linux.socket-files", "linux.devices", "linux.resolvers"] {
        assert_eq!(
            universe(&s, id).state,
            UniverseState::Unknown(UnknownReason::DependsOnUnknown),
            "{id}"
        );
    }
    // Facts still enumerate: the fd inventory and env names are not
    // proc sources.
    assert_eq!(universe(&s, "linux.fds").state, UniverseState::Enumerated);
    assert_eq!(
        universe(&s, "linux.env-names").state,
        UniverseState::Enumerated
    );
}

// ---------------------------------------------------------------------------
// linux.listeners and the IPv6 split (AE3, AE15, AE20)
// ---------------------------------------------------------------------------

#[test]
fn ipv6_disabled_is_enumerated_and_complete() {
    // The default tree has no tcp6, udp6, ipv6_route, or if_inet6.
    let c = Case::linux("no-v6", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/net/tcp",
        &format!(
            "{TCP_HEADER}   0: 0100007F:27FF 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24001 1 0000000000000000 100 0 0 10 0\n"
        ),
        true,
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.listeners").state,
        UniverseState::Enumerated
    );
    assert_eq!(
        universe(&s, "linux.routes").state,
        UniverseState::Enumerated
    );
    assert!(unknowns(&s, "linux.listeners").is_empty());
    let ms = members(&s, "linux.listeners");
    assert_eq!(ms.len(), 1);
    assert_eq!(text(&ms[0], "local-address").as_deref(), Some("127.0.0.1"));
    assert_eq!(int(&ms[0], "port"), Some(10239));
    assert_eq!(ms[0].display, "tcp 127.0.0.1:10239");
}

#[test]
fn ipv6_enabled_tcp6_unreadable_is_unknown() {
    let c = Case::linux("v6-eacces", 4242);
    proc_tree(&c, 4242);
    c.file("proc/4242/net/tcp6", TCP_HEADER, true)
        .file("proc/4242/net/udp6", UDP_HEADER, true)
        .file(
            "proc/4242/net/if_inet6",
            "00000000000000000000000000000001 01 80 10 80 lo\n",
            true,
        )
        .manifest(
            "[[node]]\npath = \"proc/4242/net/tcp6\"\ntype = \"error\"\nerrno = \"EACCES\"\n",
        );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.listeners").state,
        UniverseState::Unknown(UnknownReason::Unreadable)
    );
}

#[test]
fn ipv6_enabled_tcp6_missing_is_unknown() {
    let c = Case::linux("v6-missing", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/net/if_inet6",
        "00000000000000000000000000000001 01 80 10 80 lo\n",
        true,
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.listeners").state,
        UniverseState::Unknown(UnknownReason::Unreadable)
    );
}

#[test]
fn masked_and_empty_tables_are_masked_or_truncated() {
    for (name, content) in [
        ("tcp-zero", String::new()),
        ("tcp-rows-no-header", "   0: 0100007F:27FF 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24001 1 0\n".to_string()),
    ] {
        let c = Case::linux(name, 4242);
        proc_tree(&c, 4242);
        c.file("proc/4242/net/tcp", &content, true);
        let s = scan(&c);
        assert_eq!(
            universe(&s, "linux.listeners").state,
            UniverseState::Unknown(UnknownReason::MaskedOrTruncated),
            "{name}"
        );
    }
    // A header-only table is enumerated and empty, never masked.
    let c = Case::linux("tcp-header-only", 4242);
    proc_tree(&c, 4242);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.listeners").state,
        UniverseState::Enumerated
    );
    assert!(members(&s, "linux.listeners").is_empty());
}

#[test]
fn masked_route_dev_and_unix_tables() {
    let c = Case::linux("route-masked", 4242);
    proc_tree(&c, 4242);
    c.file("proc/4242/net/route", "eth0 stuff\n", true);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.routes").state,
        UniverseState::Unknown(UnknownReason::MaskedOrTruncated)
    );

    let c = Case::linux("dev-masked", 4242);
    proc_tree(&c, 4242);
    c.file("proc/4242/net/dev", "Inter-| only one header line\n", true);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.interfaces").state,
        UniverseState::Unknown(UnknownReason::MaskedOrTruncated)
    );

    let c = Case::linux("unix-masked", 4242);
    proc_tree(&c, 4242);
    c.file("proc/4242/net/unix", "garbage\n", true);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.unix-sockets").state,
        UniverseState::Unknown(UnknownReason::MaskedOrTruncated)
    );
}

#[test]
fn udp_rows_with_unspecified_remote_are_members() {
    let c = Case::linux("udp", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/net/udp",
        &format!(
            "{UDP_HEADER}   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 25001 2 0000000000000000 0\n   1: 00000000:0045 0100007F:0035 07 00000000:00000000 00:00000000 00000000     0        0 25002 2 0000000000000000 0\n"
        ),
        true,
    );
    let s = scan(&c);
    // Only the row with an unspecified remote joins the universe; the
    // connected row is not a listener candidate.
    let ms = members(&s, "linux.listeners");
    assert_eq!(ms.len(), 1);
    assert_eq!(ms[0].display, "udp 0.0.0.0:68");
}

// ---------------------------------------------------------------------------
// linux.unix-sockets
// ---------------------------------------------------------------------------

#[test]
fn unix_socket_rows_named_abstract_and_unnamed() {
    let c = Case::linux("unix", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/net/unix",
        &format!(
            "{UNIX_HEADER}\
             ffff888123456780: 00000002 00000000 00010000 0001 01 25123 @/containerd-shim/moby/x/shim.sock\n\
             ffff888123456781: 00000002 00000000 00000000 0001 01 25124 /run/dbus/system_bus_socket\n\
             ffff888123456782: 00000002 00000000 00000000 0001 01 25125\n\
             ffff888123456783: 00000002 00000000 00000000 0001 01 25126\n\
             ffff888123456784: 00000002 00000000 00000000 0002 01 25127\n"
        ),
        true,
    );
    let s = scan(&c);
    let ms = members(&s, "linux.unix-sockets");
    // Two named members plus one folded member per type (stream, dgram).
    assert_eq!(ms.len(), 4);
    let abs = ms
        .iter()
        .find(|m| text(m, "path").as_deref() == Some("@/containerd-shim/moby/x/shim.sock"))
        .expect("abstract member");
    assert_eq!(flag(abs, "listening"), Some(true));
    assert_eq!(text(abs, "socket-type").as_deref(), Some("stream"));
    let stream_fold = ms
        .iter()
        .find(|m| {
            text(m, "socket-type").as_deref() == Some("stream")
                && text(m, "path") == Some(String::new())
        })
        .expect("folded stream member");
    assert_eq!(int(stream_fold, "unnamed-count"), Some(2));
    let dgram_fold = ms
        .iter()
        .find(|m| text(m, "socket-type").as_deref() == Some("dgram"))
        .expect("folded dgram member");
    assert_eq!(int(dgram_fold, "unnamed-count"), Some(1));
}

// ---------------------------------------------------------------------------
// linux.capabilities
// ---------------------------------------------------------------------------

#[test]
fn capability_masks_decode_to_names() {
    let c = Case::linux("caps", 4242);
    proc_tree(&c, 4242);
    // bit 21 (cap_sys_admin) in CapEff and CapBnd; bit 62 beyond the table.
    c.file(
        "proc/4242/status",
        "Name:\tprobe\nPid:\t4242\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
         CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000200000\n\
         CapBnd:\t4000000000200000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n",
        true,
    );
    let s = scan(&c);
    let ms = members(&s, "linux.capabilities");
    let names: BTreeSet<String> = ms
        .iter()
        .map(|m| format!("{}:{}", text(m, "set").unwrap(), text(m, "name").unwrap()))
        .collect();
    assert!(names.contains("effective:cap_sys_admin"));
    assert!(names.contains("bounding:cap_sys_admin"));
    assert!(names.contains("bounding:cap_62"));
    // A missing capability line makes the universe unknown.
    let c = Case::linux("caps-missing", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/status",
        "Name:\tprobe\nPid:\t4242\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
         CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n",
        true,
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.capabilities").state,
        UniverseState::Unknown(UnknownReason::Partial)
    );
}

// ---------------------------------------------------------------------------
// linux.resolvers
// ---------------------------------------------------------------------------

#[test]
fn resolv_conf_absent_and_hop_rules() {
    // Missing file is the declared absent signature.
    let c = Case::linux("resolv-absent", 4242);
    proc_tree(&c, 4242);
    std::fs::remove_file(c.tree().join("etc/resolv.conf")).unwrap();
    let s = scan(&c);
    assert_eq!(universe(&s, "linux.resolvers").state, UniverseState::Absent);

    // A dangling one-hop link is absent too.
    let c = Case::linux("resolv-dangle", 4242);
    proc_tree(&c, 4242);
    std::fs::remove_file(c.tree().join("etc/resolv.conf")).unwrap();
    c.link("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf");
    let s = scan(&c);
    assert_eq!(universe(&s, "linux.resolvers").state, UniverseState::Absent);

    // A second hop is link-policy.
    let c = Case::linux("resolv-2hop", 4242);
    proc_tree(&c, 4242);
    std::fs::remove_file(c.tree().join("etc/resolv.conf")).unwrap();
    c.dir("run/systemd/resolve")
        .file(
            "run/systemd/resolve/resolv.conf",
            "nameserver 1.1.1.1\n",
            true,
        )
        .link("run/systemd/resolve/stub-resolv.conf", "resolv.conf")
        .link("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf");
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.resolvers").state,
        UniverseState::Unknown(UnknownReason::LinkPolicy)
    );
}

#[test]
fn resolv_conf_value_checks_and_unrecognized_lines() {
    let c = Case::linux("resolv-values", 4242);
    proc_tree(&c, 4242);
    c.file(
        "etc/resolv.conf",
        "# comment\nnameserver 8.8.8.8\nsearch a.example b.example\noptions ndots:5 timeout:3\nweird directive here\n; another comment\nnameserver ::1\n",
        true,
    );
    let s = scan(&c);
    let ds = displays(&s, "linux.resolvers");
    assert!(ds.contains("nameserver 8.8.8.8"));
    assert!(ds.contains("nameserver ::1"));
    assert!(ds.contains("search a.example b.example"));
    assert!(ds.contains("options ndots:5 timeout:3"));
    // The unrecognized line is counted, never echoed.
    assert!(!ds.iter().any(|d| d.contains("weird")));
    let m = members(&s, "linux.resolvers")
        .iter()
        .find(|m| text(m, "directive").as_deref() == Some("nameserver"))
        .unwrap();
    assert_eq!(int(m, "unrecognized-count"), Some(1));

    // A nameserver value that is not an IP literal is partial.
    let c = Case::linux("resolv-bad", 4242);
    proc_tree(&c, 4242);
    c.file("etc/resolv.conf", "nameserver not-an-ip\n", true);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.resolvers").state,
        UniverseState::Unknown(UnknownReason::Partial)
    );
}

// ---------------------------------------------------------------------------
// linux.socket-files and the KTD30 mount listings
// ---------------------------------------------------------------------------

#[test]
fn socket_dir_eacces_makes_socket_files_unknown() {
    let c = Case::linux("run-eacces", 4242);
    proc_tree(&c, 4242);
    c.dir("run")
        .dir("tmp")
        .manifest("[[node]]\npath = \"run\"\ntype = \"error\"\nerrno = \"EACCES\"\n");
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.socket-files").state,
        UniverseState::Unknown(UnknownReason::Unreadable)
    );
}

#[test]
fn socket_at_a_non_directory_mount_point_is_a_member() {
    let c = Case::linux("odd-sock", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/mountinfo",
        &format!("{MOUNTINFO}40 22 0:40 / /opt/odd/ctl.sock rw - tmpfs tmpfs rw\n"),
        true,
    )
    .dir("opt/odd")
    .manifest("[[node]]\npath = \"opt/odd/ctl.sock\"\ntype = \"socket\"\naccess = \"write\"\n");
    let s = scan(&c);
    let ms = members(&s, "linux.socket-files");
    assert_eq!(ms.len(), 1);
    assert_eq!(text(&ms[0], "path").as_deref(), Some("/opt/odd/ctl.sock"));
    assert_eq!(flag(&ms[0], "writable"), Some(true));
}

#[test]
fn mount_point_on_no_touch_mount_makes_socket_files_unknown() {
    let c = Case::linux("nfs-mountpoint", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/mountinfo",
        &format!("{MOUNTINFO}40 22 0:40 / /mnt/ctl.sock rw - nfs4 server:/x rw\n"),
        true,
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.socket-files").state,
        UniverseState::Unknown(UnknownReason::NetworkFilesystemNotTouched)
    );
}

#[test]
fn non_canonical_dir_mounts_are_listed_at_depth_one() {
    let c = Case::linux("ktd30", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/mountinfo",
        &format!(
            "{MOUNTINFO}40 22 0:40 / /host/run rw - tmpfs tmpfs rw\n41 22 0:41 / /host/dev rw - devtmpfs devtmpfs rw\n"
        ),
        true,
    )
    .dir("host/run")
    .dir("host/dev")
    .manifest(
        "[[node]]\npath = \"host/run/docker.sock\"\ntype = \"socket\"\naccess = \"write\"\n\
         [[node]]\npath = \"host/dev/sda\"\ntype = \"block\"\nmajor = 8\nminor = 0\naccess = \"read\"\n",
    );
    let mut r = c.reader();
    let s = linux::enumerate(&mut r, &data());
    // The socket under the bound dir is a socket-files member (KTD30).
    let ms = members(&s, "linux.socket-files");
    assert_eq!(ms.len(), 1);
    assert_eq!(
        text(&ms[0], "path").as_deref(),
        Some("/host/run/docker.sock")
    );
    // The block node under the bound dir is a devices member.
    let ds = members(&s, "linux.devices");
    assert!(
        ds.iter()
            .any(|m| text(m, "path").as_deref() == Some("/host/dev/sda"))
    );
    // Canonical mount points get no extra listing: the KTD30 rule never
    // lists `proc`, `sys`, or `dev/shm` themselves. (proc/4242/ns is the
    // namespaces attribute source, `dev`/`run` are listed by their own
    // universes, and `var/run` hops to `run`.)
    for e in r.read_log() {
        if e.kind == ReadCall::List {
            assert!(
                !["proc", "sys", "sys/fs/cgroup", "dev/shm"].contains(&e.path.as_str()),
                "canonical mount point listed: {e:?}"
            );
        }
    }
}

#[test]
fn a_listing_over_the_entries_budget_is_budget_exceeded() {
    let c = Case::linux("many-entries", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/mountinfo",
        &format!("{MOUNTINFO}40 22 0:40 / /host/run rw - tmpfs tmpfs rw\n"),
        true,
    )
    .dir("host/run")
    .manifest(
        "[[node]]\npath = \"host/run/a.sock\"\ntype = \"socket\"\naccess = \"write\"\n\
         [[node]]\npath = \"host/run/b.sock\"\ntype = \"socket\"\naccess = \"write\"\n\
         [[node]]\npath = \"host/run/c.sock\"\ntype = \"socket\"\naccess = \"write\"\n",
    );
    // A one-entry listing budget turns the depth-1 mount listing over.
    let files: Vec<(&str, &str)> = egress_probe::data::EMBEDDED
        .iter()
        .map(|f| {
            if f.path == "data/probe/budgets.toml" {
                (
                    f.path,
                    "members-per-universe = 200000\nbytes-per-file = 16777216\nentries-per-listing = 1\ndev-listing-depth = 4\nbytes-per-member-string = 4096\nreport-bytes = 67108864\nactive-targets = 16\nconnect-timeout-ms = 3000\nrun-deadline-ms = 60000\n",
                )
            } else {
                (f.path, f.text)
            }
        })
        .collect();
    let d = egress_probe::data::load(&files).unwrap();
    let mut r = c.reader();
    let s = linux::enumerate(&mut r, &d);
    assert_eq!(
        universe(&s, "linux.socket-files").state,
        UniverseState::Unknown(UnknownReason::BudgetExceeded)
    );
}

#[test]
fn dir_mount_on_no_touch_filesystem_makes_both_unknown() {
    let c = Case::linux("ktd30-notouch", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/mountinfo",
        &format!("{MOUNTINFO}40 22 0:40 / /mnt/fuse rw - fuse.sshfs host:/x rw\n"),
        true,
    )
    .dir("mnt/fuse");
    let mut r = c.reader();
    let s = linux::enumerate(&mut r, &data());
    assert_eq!(
        universe(&s, "linux.socket-files").state,
        UniverseState::Unknown(UnknownReason::NetworkFilesystemNotTouched)
    );
    assert_eq!(
        universe(&s, "linux.devices").state,
        UniverseState::Unknown(UnknownReason::NetworkFilesystemNotTouched)
    );
    assert!(!has_log_under(&r, "mnt/fuse"));
}

#[test]
fn mounts_unknown_gates_everything_outside_proc_and_sys() {
    let c = Case::linux("mounts-unknown", 4242);
    proc_tree(&c, 4242);
    c.manifest("[[node]]\npath = \"proc/4242/mountinfo\"\ntype = \"error\"\nerrno = \"EACCES\"\n");
    let mut r = c.reader();
    let s = linux::enumerate(&mut r, &data());
    assert_eq!(
        universe(&s, "linux.mounts").state,
        UniverseState::Unknown(UnknownReason::Unreadable)
    );
    for id in ["linux.socket-files", "linux.devices", "linux.resolvers"] {
        assert_eq!(
            universe(&s, id).state,
            UniverseState::Unknown(UnknownReason::DependsOnUnknown),
            "{id}"
        );
    }
    // After the mountinfo read failed, no performed call touched a path
    // outside proc/ and sys/.
    for e in r.read_log() {
        assert!(
            e.path.starts_with("proc/")
                || e.path.starts_with("sys/")
                || e.path == "proc"
                || e.path == "sys",
            "read log entry outside proc/sys: {e:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// linux.fds and linux.env-names (facts)
// ---------------------------------------------------------------------------

#[test]
fn fd_fact_states_and_members() {
    // fs-type-mismatch and proc-self-mismatch propagate as unknowns.
    for (state, reason) in [
        ("fs-type-mismatch", UnknownReason::FsTypeMismatch),
        ("proc-self-mismatch", UnknownReason::ProcSelfMismatch),
        ("unreadable", UnknownReason::Unreadable),
    ] {
        let c = Case::linux(&format!("fds-{state}"), 4242);
        proc_tree(&c, 4242);
        c.facts(
            4242,
            &format!(
                "[env_names]\nstate = \"read\"\nnames = []\n\
                 [fds]\nstate = \"{state}\"\n\
                 [landlock_abi]\nstate = \"not-built\"\n"
            ),
        );
        let s = scan(&c);
        assert_eq!(
            universe(&s, "linux.fds").state,
            UniverseState::Unknown(reason),
            "{state}"
        );
    }

    // An empty inventory is implausibly empty: the listing handle is
    // always a member.
    let c = Case::linux("fds-empty", 4242);
    proc_tree(&c, 4242);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = []\n\
         [landlock_abi]\nstate = \"not-built\"\n",
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.fds").state,
        UniverseState::Unknown(UnknownReason::ImplausiblyEmpty)
    );

    // Labels and target kinds.
    let c = Case::linux("fds-kinds", 4242);
    proc_tree(&c, 4242);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = [\n\
             { fd = 0, target = \"/dev/null\" },\n\
             { fd = 1, target = \"pipe:[66001]\" },\n\
             { fd = 2, target = \"pipe:[66001]\" },\n\
             { fd = 3, target = \"/proc/4242/fd\", probe_own = true },\n\
             { fd = 5, target = \"socket:[777001]\" },\n\
             { fd = 6, target = \"anon_inode:[io_uring]\" },\n\
             { fd = 7, target = \"anon_inode:bpf-map\" },\n\
             { fd = 8, target = \"anon_inode:[pidfd]\" },\n\
         ]\n\
         [landlock_abi]\nstate = \"not-built\"\n",
    );
    let s = scan(&c);
    let ms = members(&s, "linux.fds");
    let at = |fd: u64, want_label: &str, want_kind: &str| {
        let m = ms
            .iter()
            .find(|m| int(m, "fd") == Some(fd))
            .unwrap_or_else(|| panic!("fd {fd} member"));
        assert_eq!(text(m, "label").as_deref(), Some(want_label), "fd {fd}");
        assert_eq!(text(m, "kind").as_deref(), Some(want_kind), "fd {fd}");
        m.display.clone()
    };
    assert_eq!(at(0, "stdin", "path"), "fd 0: /dev/null");
    assert_eq!(at(1, "stdout", "pipe"), "fd 1: pipe:[66001]");
    assert_eq!(at(2, "stderr", "pipe"), "fd 2: pipe:[66001]");
    assert_eq!(at(3, "probe-own", "path"), "fd 3: /proc/4242/fd");
    assert_eq!(at(5, "inherited", "socket"), "fd 5: socket:[777001]");
    let m = ms.iter().find(|m| int(m, "fd") == Some(6)).unwrap();
    assert_eq!(text(m, "anon-name").as_deref(), Some("[io_uring]"));
    assert_eq!(text(m, "kind").as_deref(), Some("anon"));
    let m = ms.iter().find(|m| int(m, "fd") == Some(7)).unwrap();
    assert_eq!(text(m, "anon-name").as_deref(), Some("bpf-map"));
    let m = ms.iter().find(|m| int(m, "fd") == Some(8)).unwrap();
    assert_eq!(text(m, "anon-name").as_deref(), Some("[pidfd]"));
    // The socket member's inode is display-only.
    let m = ms.iter().find(|m| int(m, "fd") == Some(5)).unwrap();
    assert_eq!(int(m, "inode"), Some(777001));
}

#[test]
fn env_names_members_and_no_separator_placeholder() {
    let c = Case::linux("env", 4242);
    proc_tree(&c, 4242);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = [ { name = \"PATH\" }, { name = \"DEPLOY_ghp_abc123\" }, { no_separator = true } ]\n\
         [fds]\nstate = \"read\"\nentries = [ { fd = 3, target = \"/proc/4242/fd\", probe_own = true } ]\n\
         [landlock_abi]\nstate = \"not-built\"\n",
    );
    let s = scan(&c);
    let ds = displays(&s, "linux.env-names");
    assert!(ds.contains("PATH"));
    assert!(ds.contains("<no-separator>"));
    let m = members(&s, "linux.env-names")
        .iter()
        .find(|m| text(m, "name").as_deref() == Some("DEPLOY_ghp_abc123"))
        .unwrap();
    assert_eq!(flag(m, "redacted"), Some(true));
}

// ---------------------------------------------------------------------------
// linux.devices
// ---------------------------------------------------------------------------

#[test]
fn device_nodes_list_with_attributes_and_depth_bound() {
    let c = Case::linux("devs", 4242);
    proc_tree(&c, 4242);
    c.dir("dev/a/b/c/d").manifest(
        "[[node]]\npath = \"dev/null\"\ntype = \"char\"\nmajor = 1\nminor = 3\naccess = \"write\"\n\
         [[node]]\npath = \"dev/kvm\"\ntype = \"char\"\nmajor = 10\nminor = 232\naccess = \"write\"\n\
         [[node]]\npath = \"dev/odd\"\ntype = \"char\"\nmajor = 10\nminor = 232\naccess = \"write\"\n\
         [[node]]\npath = \"dev/sda\"\ntype = \"block\"\nmajor = 8\nminor = 0\naccess = \"none\"\n\
         [[node]]\npath = \"dev/a/b/c/deep\"\ntype = \"char\"\nmajor = 1\nminor = 1\naccess = \"write\"\n\
         [[node]]\npath = \"dev/a/b/c/d/deeper\"\ntype = \"char\"\nmajor = 1\nminor = 2\naccess = \"write\"\n",
    );
    let s = scan(&c);
    let ms = members(&s, "linux.devices");
    let paths: BTreeSet<String> = ms.iter().map(|m| text(m, "path").unwrap()).collect();
    // null, kvm, odd, sda, deep are listed; deeper is beyond depth 4.
    for p in [
        "/dev/null",
        "/dev/kvm",
        "/dev/odd",
        "/dev/sda",
        "/dev/a/b/c/deep",
    ] {
        assert!(paths.contains(p), "missing device member {p}");
    }
    assert!(!paths.contains("/dev/a/b/c/d/deeper"));
    let kvm = ms
        .iter()
        .find(|m| text(m, "path").as_deref() == Some("/dev/kvm"))
        .unwrap();
    assert_eq!(text(kvm, "node-type").as_deref(), Some("char"));
    assert_eq!(text(kvm, "device").as_deref(), Some("10:232"));
    assert_eq!(flag(kvm, "accessible"), Some(true));
    let sda = ms
        .iter()
        .find(|m| text(m, "path").as_deref() == Some("/dev/sda"))
        .unwrap();
    assert_eq!(text(sda, "node-type").as_deref(), Some("block"));
    assert_eq!(flag(sda, "accessible"), Some(false));

    // An empty dev is implausibly empty: /dev/null always exists.
    let c = Case::linux("devs-empty", 4242);
    proc_tree(&c, 4242);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.devices").state,
        UniverseState::Enumerated
    );
    let c = Case::linux("devs-truly-empty", 4242);
    proc_tree(&c, 4242);
    // Remove the dev/null manifest node.
    std::fs::remove_file(c.dir.join("manifest.toml")).unwrap();
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.devices").state,
        UniverseState::Unknown(UnknownReason::ImplausiblyEmpty)
    );
}

// ---------------------------------------------------------------------------
// linux.routes and linux.interfaces
// ---------------------------------------------------------------------------

#[test]
fn route_tables_parse_to_prefix_members() {
    let c = Case::linux("routes", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/net/route",
        &format!(
            "{ROUTE_HEADER}eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        ),
        true,
    )
    .file(
        "proc/4242/net/ipv6_route",
        "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0\n",
        true,
    )
    .file("proc/4242/net/if_inet6", "00000000000000000000000000000001 01 80 10 80 lo\n", true)
    .file(
        "proc/4242/net/dev",
        &format!("{DEV_HEADER}    lo:  1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n  eth0:  5000      50    0    0    0     0          0         0     5000      50    0    0    0     0       0          0\n"),
        true,
    );
    let s = scan(&c);
    let ds = displays(&s, "linux.routes");
    assert!(ds.contains("0.0.0.0/0 via 192.168.0.1 dev eth0"), "{ds:?}");
    assert!(ds.contains("192.168.1.0/24 dev eth0"), "{ds:?}");
    assert!(ds.contains("fe80::/64 dev eth0"), "{ds:?}");
    let names = displays(&s, "linux.interfaces");
    assert!(names.contains("eth0"));
    assert!(names.contains("lo"));
}

// ---------------------------------------------------------------------------
// Attribute sources
// ---------------------------------------------------------------------------

#[test]
fn status_attributes_and_tracer_pid() {
    let c = Case::linux("attrs", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/status",
        "Name:\tprobe\nPid:\t4242\nTracerPid:\t77\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
         NSpid:\t4242\t1\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n\
         NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n",
        true,
    );
    let s = scan(&c);
    assert_eq!(attr_int(&s, "TracerPid"), Some(77));
    assert_eq!(attr_int(&s, "Seccomp"), Some(2));
    assert_eq!(attr_int(&s, "Seccomp_filters"), Some(1));
    assert_eq!(attr_int(&s, "NoNewPrivs"), Some(1));
    assert_eq!(attr_int(&s, "nspid-depth"), Some(2));
    assert_eq!(s.tracer_pid, Some(77));
    assert_eq!(s.euid, Some(0));
    assert_eq!(s.egid, Some(0));
}

#[test]
fn namespaces_cgroups_and_id_maps_attributes() {
    let c = Case::linux("attrs2", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/uid_map",
        "         0          1          1\n",
        true,
    );
    let s = scan(&c);
    match s.attributes.get("namespaces") {
        Some(AttrValue::Namespaces(ns)) => {
            assert!(ns.iter().any(|n| n.name == "ipc" && n.inode == 4026531839));
        }
        other => panic!("namespaces attribute: {other:?}"),
    }
    assert_eq!(attr_int(&s, "ns-ipc-inode"), Some(4026531839));
    assert_eq!(attr_int(&s, "uid-map-lines"), Some(1));
    match s.attributes.get("cgroups") {
        Some(AttrValue::Strings(lines)) => assert!(lines.iter().any(|l| l.contains("init.scope"))),
        other => panic!("cgroups attribute: {other:?}"),
    }
}

#[test]
fn ptrace_scope_absent_and_read() {
    // No yama directory: the attribute source is absent, not unknown.
    let c = Case::linux("no-yama", 4242);
    proc_tree(&c, 4242);
    let s = scan(&c);
    assert!(unknowns(&s, "linux.attr.ptrace-scope").is_empty());
    assert!(!s.attributes.contains_key("ptrace_scope"));

    let c = Case::linux("yama", 4242);
    proc_tree(&c, 4242);
    c.dir("proc/sys/kernel/yama")
        .file("proc/sys/kernel/yama/ptrace_scope", "1\n", true);
    let s = scan(&c);
    assert_eq!(attr_int(&s, "ptrace_scope"), Some(1));
}

#[test]
fn landlock_abi_states() {
    let c = Case::linux("landlock", 4242);
    proc_tree(&c, 4242);
    let s = scan(&c);
    match s.attributes.get("landlock-abi") {
        Some(AttrValue::Str(v)) => assert_eq!(v, "not-built"),
        other => panic!("landlock-abi attribute: {other:?}"),
    }
    assert!(unknowns(&s, "linux.attr.landlock-abi").is_empty());

    let c = Case::linux("landlock-v", 4242);
    proc_tree(&c, 4242);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = []\n\
         [landlock_abi]\nstate = \"read\"\nversion = 3\n",
    );
    let s = scan(&c);
    assert_eq!(attr_int(&s, "landlock-abi"), Some(3));
}

// ---------------------------------------------------------------------------
// linux.sysctl.userns (KTD28: attributes only, never a route)
// ---------------------------------------------------------------------------

#[test]
fn userns_sysctls_are_integer_attributes_only() {
    let c = Case::linux("userns", 4242);
    proc_tree(&c, 4242);
    c.dir("proc/sys/user")
        .dir("proc/sys/kernel")
        .file("proc/sys/user/max_user_namespaces", "15000\n", true)
        .file(
            "proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            "0\n",
            true,
        );
    let s = scan(&c);
    assert_eq!(attr_int(&s, "max_user_namespaces"), Some(15000));
    assert_eq!(
        attr_int(&s, "apparmor_restrict_unprivileged_userns"),
        Some(0)
    );
    // A missing sysctl file is absent, not an unknown.
    assert!(unknowns(&s, "linux.sysctl.userns").is_empty());
    assert_eq!(attr_int(&s, "unprivileged_userns_clone"), None);

    let c = Case::linux("userns-bad", 4242);
    proc_tree(&c, 4242);
    c.dir("proc/sys/user")
        .file("proc/sys/user/max_user_namespaces", "plenty\n", true);
    let s = scan(&c);
    assert_eq!(
        unknowns(&s, "linux.sysctl.userns")
            .iter()
            .map(|u| u.reason)
            .collect::<Vec<_>>(),
        vec![UnknownReason::Partial]
    );
}

// ---------------------------------------------------------------------------
// Home resolution from etc/passwd (KTD15)
// ---------------------------------------------------------------------------

#[test]
fn home_comes_from_the_account_file() {
    let c = Case::linux("home", 4242);
    proc_tree(&c, 4242);
    c.file(
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/sh\napp:x:12345:12345:app:/home/app:/bin/sh\n",
        true,
    )
    .file(
        "proc/4242/status",
        "Name:\tprobe\nPid:\t4242\nTracerPid:\t0\nUid:\t12345\t12345\t12345\t12345\nGid:\t12345\t12345\t12345\t12345\n\
         NSpid:\t4242\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n",
        true,
    );
    let s = scan(&c);
    assert_eq!(s.euid, Some(12345));
    assert_eq!(s.home.as_deref(), Ok(b"/home/app".as_slice()));
}

#[test]
fn no_passwd_entry_is_no_account_home() {
    let c = Case::linux("no-home", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/status",
        "Name:\tprobe\nPid:\t4242\nTracerPid:\t0\nUid:\t12345\t12345\t12345\t12345\nGid:\t12345\t12345\t12345\t12345\n\
         NSpid:\t4242\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n",
        true,
    );
    let s = scan(&c);
    assert_eq!(s.home, Err(UnknownReason::NoAccountHome));
}

// ---------------------------------------------------------------------------
// Budgets and the panic guard (KTD18, KTD3)
// ---------------------------------------------------------------------------

#[test]
fn member_string_over_budget_is_budget_exceeded() {
    let c = Case::linux("long-point", 4242);
    proc_tree(&c, 4242);
    let long = "x".repeat(5000);
    c.file(
        "proc/4242/mountinfo",
        &format!("{MOUNTINFO}40 22 0:40 / /{long} rw - tmpfs tmpfs rw\n"),
        true,
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "linux.mounts").state,
        UniverseState::Unknown(UnknownReason::BudgetExceeded)
    );
}

#[test]
fn members_budget_exceeded_is_budget_exceeded() {
    let c = Case::linux("many-caps", 4242);
    proc_tree(&c, 4242);
    c.file(
        "proc/4242/status",
        "Name:\tprobe\nPid:\t4242\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
         CapInh:\t0\nCapPrm:\t0\nCapEff:\tFFFFFFFFFFFFFFFF\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n",
        true,
    );
    // A tiny members budget turns the capabilities universe over.
    let files: Vec<(&str, &str)> = egress_probe::data::EMBEDDED
        .iter()
        .map(|f| {
            if f.path == "data/probe/budgets.toml" {
                (f.path, "members-per-universe = 4\nbytes-per-file = 16777216\nentries-per-listing = 100000\ndev-listing-depth = 4\nbytes-per-member-string = 4096\nreport-bytes = 67108864\nactive-targets = 16\nconnect-timeout-ms = 3000\nrun-deadline-ms = 60000\n")
            } else {
                (f.path, f.text)
            }
        })
        .collect();
    let d = egress_probe::data::load(&files).unwrap();
    let mut r = c.reader();
    let s = linux::enumerate(&mut r, &d);
    assert_eq!(
        universe(&s, "linux.capabilities").state,
        UniverseState::Unknown(UnknownReason::BudgetExceeded)
    );
}

/// A reader that delegates to a snapshot reader but panics on `list`.
struct PanicOnList(SnapshotReader);

impl Reader for PanicOnList {
    fn read(&mut self, path: &[u8], limit: u64) -> Result<Vec<u8>, Denial> {
        self.0.read(path, limit)
    }
    fn list(&mut self, _path: &[u8]) -> Result<Vec<(Vec<u8>, Meta)>, Denial> {
        panic!("injected listing panic");
    }
    fn metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        self.0.metadata(path)
    }
    fn access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial> {
        self.0.access(path, mask)
    }
    fn readlink(&mut self, path: &[u8]) -> Result<Vec<u8>, Denial> {
        self.0.readlink(path)
    }
    fn signal_metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        self.0.signal_metadata(path)
    }
    fn signal_access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial> {
        self.0.signal_access(path, mask)
    }
    fn facts(&self) -> &Facts {
        self.0.facts()
    }
    fn read_log(&self) -> &[ReadLogEntry] {
        self.0.read_log()
    }
    fn arm_mounts(&mut self, mounts: Vec<Mount>) {
        self.0.arm_mounts(mounts);
    }
    fn mounts_unknown(&mut self) {
        self.0.mounts_unknown();
    }
    fn accepted_ancestor_pidns(&self) -> bool {
        self.0.accepted_ancestor_pidns()
    }
}

#[test]
fn a_panicking_source_is_internal_failure_and_the_rest_enumerate() {
    let c = Case::linux("panic", 4242);
    proc_tree(&c, 4242);
    let mut r = PanicOnList(c.reader());
    let s = linux::enumerate(&mut r, &data());
    // The panic in `list` makes every listing source an internal failure,
    // but enumeration keeps going.
    assert_eq!(
        universe(&s, "linux.devices").state,
        UniverseState::Unknown(UnknownReason::InternalFailure)
    );
    assert_eq!(
        universe(&s, "linux.mounts").state,
        UniverseState::Enumerated
    );
    assert_eq!(
        universe(&s, "linux.listeners").state,
        UniverseState::Enumerated
    );
}

// ---------------------------------------------------------------------------
// Not applicable (R24): every macOS source is listed, never attempted.
// ---------------------------------------------------------------------------

#[test]
fn macos_sources_are_not_applicable_on_linux() {
    let c = Case::linux("na", 4242);
    proc_tree(&c, 4242);
    let s = scan(&c);
    for id in [
        "macos.mounts",
        "macos.fds",
        "macos.env-names",
        "macos.devices",
    ] {
        assert_eq!(universe(&s, id).state, UniverseState::NotApplicable, "{id}");
    }
    assert!(
        s.not_applicable
            .iter()
            .any(|id| id == "macos.attr.sandbox-check")
    );
}

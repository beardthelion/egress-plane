//! macOS record parsers, universe enumerators, and attribute sources
//! (KTD3, KTD15, KTD17, KTD26, KTD31, R24). The `pcblist_n`, route
//! dump, and `proc_pidfdinfo` decoders run here as pure byte-buffer
//! parsers; the enumerators run over snapshot facts and trees.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_probe::data::Data;
use egress_probe::model::{AttrValue, Member, MemberValue, UniverseState, UnknownReason};
use egress_probe::reader::Reader;
use egress_probe::snapshot::SnapshotReader;
use egress_probe::universe::macos;
use egress_probe::universe::macos::LayoutError;

// ---------------------------------------------------------------------------
// Case builder: a snapshot case directory with tree/, facts.toml, and an
// optional manifest.toml.
// ---------------------------------------------------------------------------

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Case {
    dir: PathBuf,
}

impl Case {
    fn macos(name: &str, pid: u64) -> Case {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("probe-macos-tests")
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
            &format!("platform = \"macos\"\n[process]\nstate = \"read\"\npid = {pid}\n{body}"),
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

    fn manifest(&self, text: &str) -> &Self {
        self.file("manifest.toml", text, false)
    }

    fn reader(&self) -> SnapshotReader {
        SnapshotReader::open(&self.dir).unwrap()
    }
}

/// The minimal complete fact set: mounts, empty tables, the attribute
/// sources, and the numeric identity.
const FACTS: &str = "\
[env_names]
state = \"read\"
names = [ { name = \"PATH\" } ]
[fds]
state = \"read\"
entries = [
    { fd = 0, target = \"/dev/null\" },
    { fd = 1, target = \"pipe\" },
    { fd = 5, target = \"KQUEUE\" },
]
[mounts]
state = \"read\"
entries = [
    { path = \"/\", fstype = \"apfs\", source = \"/dev/disk3s1\", readonly = false },
    { path = \"/dev\", fstype = \"devfs\" },
]
[unix_sockets]
state = \"read\"
entries = []
[listeners]
state = \"read\"
entries = []
[routes]
state = \"read\"
entries = []
[interfaces]
state = \"read\"
entries = [ { name = \"lo0\", families = [\"link\", \"inet\", \"inet6\"] } ]
[sandbox_check]
state = \"read\"
result = 0
[hv_vmm_present]
state = \"read\"
present = true
[identity]
state = \"read\"
euid = 501
egid = 20
[traced]
state = \"read\"
traced = false
";

/// The ordinary non-fact tree a plain case needs: `private/var/run`,
/// `private/tmp`, a resolver stub, and device nodes.
fn macos_tree(c: &Case) -> &Case {
    c.dir("private/var/run")
        .dir("private/tmp")
        .dir("dev")
        .file("private/etc/resolv.conf", "nameserver 192.168.64.1\n", true)
        .manifest(
            "[[node]]\npath = \"dev/null\"\ntype = \"char\"\nmajor = 3\nminor = 2\naccess = \"write\"\n\
             [[node]]\npath = \"dev/bpf0\"\ntype = \"char\"\nmajor = 23\nminor = 0\naccess = \"write\"\n",
        )
}

fn data() -> Data {
    Data::embedded().unwrap()
}

fn scan(c: &Case) -> macos::Scan {
    let mut r = c.reader();
    macos::enumerate(&mut r, &data())
}

fn universe<'a>(scan: &'a macos::Scan, id: &str) -> &'a egress_probe::model::Universe {
    scan.universes
        .iter()
        .find(|u| u.id == id)
        .unwrap_or_else(|| panic!("universe {id} in scan"))
}

fn members<'a>(scan: &'a macos::Scan, id: &str) -> &'a [Member] {
    &universe(scan, id).members
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

fn flag(m: &Member, name: &str) -> Option<bool> {
    match field(m, name) {
        Some(MemberValue::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn displays(scan: &macos::Scan, id: &str) -> BTreeSet<String> {
    members(scan, id)
        .iter()
        .map(|m| m.display.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Record parsers (KTD17).
// ---------------------------------------------------------------------------

/// Builds one `pcblist_n` buffer: the 24-byte `xinpgen` header, then
/// records of (kind, payload) sub-structures at 8-byte strides, then
/// the 24-byte trailer when records exist.
fn pcblist(records: &[Vec<(u32, Vec<u8>)>]) -> Vec<u8> {
    let mut buf = vec![0u8; 8];
    buf[0..4].copy_from_slice(&24u32.to_le_bytes());
    buf.resize(24, 0);
    for rec in records {
        for (kind, payload) in rec {
            let len = (payload.len() + 8) as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&kind.to_le_bytes());
            buf.extend_from_slice(payload);
            while !buf.len().is_multiple_of(8) {
                buf.push(0);
            }
        }
    }
    if !records.is_empty() {
        buf.extend_from_slice(&24u32.to_le_bytes());
        buf.resize(buf.len() + 20, 0);
    }
    buf
}

fn inpcb(lport: u16, fport: u16, vflag: u8, laddr: [u8; 16], faddr: [u8; 16]) -> Vec<u8> {
    // Payload bytes after the 8-byte len/kind head: the offsets below
    // are the xinpcb_n field offsets minus 8.
    let mut p = vec![0u8; 96];
    p[8..10].copy_from_slice(&fport.to_be_bytes());
    p[10..12].copy_from_slice(&lport.to_be_bytes());
    p[36] = vflag;
    p[40..56].copy_from_slice(&faddr);
    p[56..72].copy_from_slice(&laddr);
    p
}

fn xtcpcb(state: i32) -> Vec<u8> {
    // t_state at struct offset 36: payload offset 28.
    let mut p = vec![0u8; 200];
    p[28..32].copy_from_slice(&state.to_le_bytes());
    p
}

fn xsocket(so_type: i16, so_options: u32) -> Vec<u8> {
    // so_type at struct offset 16, so_options at 20.
    let mut p = vec![0u8; 40];
    p[8..10].copy_from_slice(&so_type.to_le_bytes());
    p[12..16].copy_from_slice(&so_options.to_le_bytes());
    p
}

fn unpcb(path: Option<&[u8]>) -> Vec<u8> {
    // xu_addr at struct offset 76: payload offset 68.
    let mut p = vec![0u8; 500];
    match path {
        Some(path) => {
            p[68] = (path.len() + 2) as u8;
            p[69] = 1; // AF_UNIX
            p[70..70 + path.len()].copy_from_slice(path);
        }
        None => {
            p[68] = 2;
            p[69] = 1;
        }
    }
    p
}

#[test]
fn tcp_pcblist_listens_and_established() {
    // A LISTEN socket and an ESTABLISHED socket; only the listener is
    // a member.
    let mut v4 = [0u8; 16];
    v4[12..16].copy_from_slice(&[127, 0, 0, 1]);
    let zero = [0u8; 16];
    let buf = pcblist(&[
        vec![
            (0x10, inpcb(8080, 0, 0x1, v4, zero)),
            (0x01, xsocket(1, 0)),
            (0x20, xtcpcb(1)),
        ],
        vec![
            (0x10, inpcb(8081, 443, 0x1, v4, v4)),
            (0x01, xsocket(1, 0)),
            (0x20, xtcpcb(4)),
        ],
    ]);
    let out = macos::pcblist_inet(&buf, "tcp").unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].protocol, "tcp");
    assert_eq!(out[0].address, "127.0.0.1");
    assert_eq!(out[0].port, 8080);
}

#[test]
fn udp_pcblist_unspecified_remote() {
    let v4 = [0u8; 16];
    let remote = {
        let mut r = [0u8; 16];
        r[12..16].copy_from_slice(&[8, 8, 8, 8]);
        r
    };
    let buf = pcblist(&[
        vec![(0x10, inpcb(68, 0, 0x1, v4, v4)), (0x01, xsocket(2, 0))],
        vec![
            (0x10, inpcb(69, 53, 0x1, v4, remote)),
            (0x01, xsocket(2, 0)),
        ],
    ]);
    let out = macos::pcblist_inet(&buf, "udp").unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].port, 68);
}

#[test]
fn pcblist_ipv6_members() {
    let mut v6 = [0u8; 16];
    v6[15] = 1; // ::1
    let buf = pcblist(&[vec![
        (0x10, inpcb(80, 0, 0x2, v6, [0u8; 16])),
        (0x01, xsocket(1, 0)),
        (0x20, xtcpcb(1)),
    ]]);
    let out = macos::pcblist_inet(&buf, "tcp").unwrap();
    assert_eq!(out[0].protocol, "tcp6");
    assert_eq!(out[0].address, "::1");
}

#[test]
fn unix_pcblist_named_and_unnamed() {
    let buf = pcblist(&[
        vec![
            (0x200, unpcb(Some(b"/var/run/syslog"))),
            (0x01, xsocket(1, 0x2)),
        ],
        vec![(0x200, unpcb(None)), (0x01, xsocket(2, 0))],
    ]);
    let out = macos::pcblist_unix(&buf).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].path.as_deref(), Some(&b"/var/run/syslog"[..]));
    assert!(out[0].listening);
    assert_eq!(out[0].kind, "stream");
    assert_eq!(out[1].path, None);
    assert_eq!(out[1].kind, "dgram");
}

#[test]
fn pcblist_trailing_garbage_is_truncated() {
    let mut buf = pcblist(&[vec![
        (0x10, inpcb(80, 0, 0x1, [0u8; 16], [0u8; 16])),
        (0x01, xsocket(1, 0)),
        (0x20, xtcpcb(1)),
    ]]);
    buf.truncate(buf.len() - 4);
    assert!(macos::pcblist_inet(&buf, "tcp").is_err());
    // A record claimed length that overruns the buffer.
    let mut bad = pcblist(&[]);
    bad.extend_from_slice(&100u32.to_le_bytes());
    bad.extend_from_slice(&0x10u32.to_le_bytes());
    assert_eq!(
        macos::pcblist_inet(&bad, "tcp"),
        Err(LayoutError::Truncated)
    );
}

#[test]
fn pcblist_header_only_is_empty() {
    let buf = pcblist(&[]);
    assert_eq!(macos::pcblist_inet(&buf, "tcp"), Ok(vec![]));
    assert_eq!(macos::pcblist_unix(&buf), Ok(vec![]));
    // Too short even for the header is truncated, never empty.
    assert_eq!(macos::pcblist_unix(&buf[..12]), Err(LayoutError::Truncated));
}

#[test]
fn pcblist_foreign_layout_is_unsupported() {
    // A pcb record whose vflag names no address family.
    let buf = pcblist(&[vec![
        (0x10, inpcb(80, 0, 0x0, [0u8; 16], [0u8; 16])),
        (0x01, xsocket(1, 0)),
        (0x20, xtcpcb(1)),
    ]]);
    assert_eq!(
        macos::pcblist_inet(&buf, "tcp"),
        Err(LayoutError::Unsupported)
    );
    // A bad xinpgen length.
    let mut buf = pcblist(&[]);
    buf[0] = 100;
    assert_eq!(macos::pcblist_unix(&buf), Err(LayoutError::Unsupported));
}

#[test]
fn rt_dump_one_route() {
    let mut msg = vec![0u8; 92];
    let body = {
        // sockaddr_in dst 10.0.0.0, gw 192.168.64.1, netmask
        // 255.255.255.0, plus sockaddr_dl ifp en0.
        let mut b = Vec::new();
        let sin = |addr: [u8; 4]| {
            let mut s = vec![16u8, 2u8, 0, 0];
            s.extend_from_slice(&addr);
            s.resize(16, 0);
            s
        };
        b.extend_from_slice(&sin([10, 0, 0, 0]));
        b.extend_from_slice(&sin([192, 168, 64, 1]));
        b.extend_from_slice(&sin([255, 255, 255, 0]));
        // sockaddr_dl: len 20, family AF_LINK(18), nlen 3, name en0.
        let mut dl = vec![20u8, 18u8, 0, 0, 0, 3, 0, 0];
        dl.extend_from_slice(b"en0");
        dl.resize(20, 0);
        b.extend_from_slice(&dl);
        b
    };
    let msglen = 92 + body.len();
    msg[0..2].copy_from_slice(&(msglen as u16).to_le_bytes());
    msg[2] = 5; // RTM_VERSION
    msg[3] = 4; // RTM_GET
    msg[8..12].copy_from_slice(&2i32.to_le_bytes()); // RTF_GATEWAY
    msg[12..16].copy_from_slice(&0b10111i32.to_le_bytes()); // dst gw netmask ifp
    msg.extend_from_slice(&body);
    let out = macos::rt_dump(&msg).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].family, "inet");
    assert_eq!(out[0].destination, "10.0.0.0/24");
    assert_eq!(out[0].gateway.as_deref(), Some("192.168.64.1"));
    assert_eq!(out[0].interface.as_deref(), Some("en0"));
}

#[test]
fn rt_dump_truncated_record_is_an_error() {
    let msg = vec![0u8; 40];
    assert_eq!(macos::rt_dump(&msg), Err(LayoutError::Truncated));
}

#[test]
fn proc_fd_list_and_vnode_path() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&3i32.to_le_bytes());
    buf.extend_from_slice(&2u32.to_le_bytes()); // fd 3, socket
    buf.extend_from_slice(&4i32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // fd 4, vnode
    let out = macos::proc_fd_list(&buf).unwrap();
    assert_eq!(out, vec![(3, 2), (4, 1)]);
    buf.push(0);
    assert_eq!(macos::proc_fd_list(&buf), Err(LayoutError::Truncated));

    let mut vi = vec![0u8; macos::VNODE_FDINFO_PATH_LEN];
    vi[16..20].copy_from_slice(&1i32.to_le_bytes()); // fi_type vnode
    vi[176..176 + 9].copy_from_slice(b"/dev/null");
    let (ty, path) = macos::vnode_path_info(&vi).unwrap();
    assert_eq!(ty, 1);
    assert_eq!(path, b"/dev/null");
    assert_eq!(
        macos::vnode_path_info(&vi[..200]),
        Err(LayoutError::Truncated)
    );
}

// ---------------------------------------------------------------------------
// The macOS universes over snapshot facts (KTD3, R24).
// ---------------------------------------------------------------------------

#[test]
fn linux_sets_are_not_applicable_on_macos() {
    let c = Case::macos("na", 4242);
    macos_tree(&c);
    let s = scan(&c);
    for id in [
        "linux.mounts",
        "linux.unix-sockets",
        "linux.listeners",
        "linux.devices",
        "linux.routes",
    ] {
        assert_eq!(universe(&s, id).state, UniverseState::NotApplicable, "{id}");
    }
    for source in [
        "linux.unix-sockets",
        "linux.devices",
        "linux.attr.status",
        "linux.attr.landlock-abi",
    ] {
        assert!(s.not_applicable.contains(&source.to_string()), "{source}");
    }
}

#[test]
fn mounts_members_and_attributes() {
    let c = Case::macos("mounts", 4242);
    macos_tree(&c);
    let s = scan(&c);
    assert_eq!(
        universe(&s, "macos.mounts").state,
        UniverseState::Enumerated
    );
    assert!(displays(&s, "macos.mounts").contains("/"));
    assert!(displays(&s, "macos.mounts").contains("/dev"));
    assert_eq!(s.euid, Some(501));
    assert_eq!(s.egid, Some(20));
    assert_eq!(
        s.attributes.get("hv_vmm_present"),
        Some(&AttrValue::Bool(true))
    );
    assert_eq!(s.attributes.get("sandbox_check"), Some(&AttrValue::Int(0)));
    assert_eq!(s.attributes.get("traced"), Some(&AttrValue::Bool(false)));
    // The fixed home verdict (KTD15).
    assert_eq!(s.home.clone().unwrap_err(), UnknownReason::NoAccountHome);
    // No attribute or universe unknowns on a clean run.
    assert!(s.unknowns.is_empty(), "{:?}", s.unknowns);
}

#[test]
fn missing_mounts_degrades_gated_sources() {
    let c = Case::macos("no-mounts", 4242);
    macos_tree(&c);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = [{ fd = 0, target = \"/dev/null\" }]\n\
         [mounts]\nstate = \"unreadable\"\n\
         [interfaces]\nstate = \"read\"\nentries = [{ name = \"lo0\", families = [\"link\", \"inet\"] }]\n",
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "macos.mounts").state,
        UniverseState::Unknown(UnknownReason::Unreadable)
    );
    assert_eq!(
        universe(&s, "macos.resolvers").state,
        UniverseState::Unknown(UnknownReason::DependsOnUnknown)
    );
    assert_eq!(
        universe(&s, "macos.devices").state,
        UniverseState::Unknown(UnknownReason::DependsOnUnknown)
    );
    // Fact-fed universes still enumerate.
    assert_eq!(
        universe(&s, "macos.interfaces").state,
        UniverseState::Enumerated
    );
}

#[test]
fn no_touch_mount_is_not_statd() {
    let c = Case::macos("smbfs", 4242);
    macos_tree(&c);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = [{ fd = 0, target = \"/dev/null\" }]\n\
         [mounts]\nstate = \"read\"\n\
         entries = [ { path = \"/\", fstype = \"apfs\" }, { path = \"/Volumes/share\", fstype = \"smbfs\" } ]\n\
         [identity]\nstate = \"read\"\neuid = 501\negid = 20\n",
    );
    let mut r = c.reader();
    let s = macos::enumerate(&mut r, &data());
    assert!(displays(&s, "macos.mounts").contains("/Volumes/share"));
    // The mount point is never stat'd for the socket-files scan.
    assert!(
        !r.read_log()
            .iter()
            .any(|e| e.path.starts_with("Volumes/share"))
    );
    assert_eq!(
        universe(&s, "macos.socket-files").state,
        UniverseState::Enumerated
    );
}

#[test]
fn sockets_devices_resolvers_enumerate() {
    let c = Case::macos("dev", 4242);
    macos_tree(&c);
    c.manifest(
        "[[node]]\npath = \"dev/null\"\ntype = \"char\"\nmajor = 3\nminor = 2\naccess = \"write\"\n\
         [[node]]\npath = \"dev/bpf0\"\ntype = \"char\"\nmajor = 23\nminor = 0\naccess = \"write\"\n\
         [[node]]\npath = \"dev/disk0\"\ntype = \"block\"\nmajor = 14\nminor = 1\naccess = \"none\"\n\
         [[node]]\npath = \"private/var/run/syslog\"\ntype = \"socket\"\naccess = \"write\"\n",
    );
    let s = scan(&c);
    // Devices: char and block only, access marks.
    let devs = members(&s, "macos.devices");
    assert_eq!(devs.len(), 3);
    assert_eq!(text(&devs[0], "node-type").as_deref(), Some("char"));
    let bpf = devs
        .iter()
        .find(|m| text(m, "path").as_deref() == Some("/dev/bpf0"))
        .expect("bpf0 member");
    assert_eq!(flag(bpf, "accessible"), Some(true));
    let disk = devs
        .iter()
        .find(|m| text(m, "path").as_deref() == Some("/dev/disk0"))
        .expect("disk0 member");
    assert_eq!(flag(disk, "accessible"), Some(false));
    assert_eq!(text(disk, "node-type").as_deref(), Some("block"));
    // Socket files: the manifest socket under private/var/run.
    assert!(displays(&s, "macos.socket-files").contains("/private/var/run/syslog"));
    // Resolvers: the stub nameserver member names its file.
    let res = members(&s, "macos.resolvers");
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].display, "nameserver 192.168.64.1");
    assert_eq!(text(&res[0], "file").as_deref(), Some("resolv.conf"));
    // Empty tables are enumerated, not unknown.
    assert_eq!(
        universe(&s, "macos.unix-sockets").state,
        UniverseState::Enumerated
    );
    assert_eq!(
        universe(&s, "macos.listeners").state,
        UniverseState::Enumerated
    );
}

#[test]
fn interfaces_deduplicate_and_name_families() {
    let c = Case::macos("ifaces", 4242);
    macos_tree(&c);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = [{ fd = 0, target = \"/dev/null\" }]\n\
         [mounts]\nstate = \"read\"\nentries = [{ path = \"/\", fstype = \"apfs\" }, { path = \"/dev\", fstype = \"devfs\" }]\n\
         [interfaces]\nstate = \"read\"\n\
         entries = [ { name = \"en0\", families = [\"link\", \"inet\", \"inet6\"] }, { name = \"lo0\", families = [\"link\", \"inet\"] } ]\n",
    );
    let s = scan(&c);
    let ifaces = members(&s, "macos.interfaces");
    assert_eq!(ifaces.len(), 2);
    assert_eq!(
        text(&ifaces[0], "families").as_deref(),
        Some("link,inet,inet6")
    );
}

#[test]
fn route_and_listener_members_display() {
    let c = Case::macos("routes", 4242);
    macos_tree(&c);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = [{ fd = 0, target = \"/dev/null\" }]\n\
         [mounts]\nstate = \"read\"\nentries = [{ path = \"/\", fstype = \"apfs\" }, { path = \"/dev\", fstype = \"devfs\" }]\n\
         [listeners]\nstate = \"read\"\n\
         entries = [ { protocol = \"tcp\", address = \"0.0.0.0\", port = 22 }, { protocol = \"tcp6\", address = \"::\", port = 22 } ]\n\
         [routes]\nstate = \"read\"\n\
         entries = [ { family = \"inet\", destination = \"0.0.0.0/0\", gateway = \"192.168.64.1\", interface = \"en0\" } ]\n",
    );
    let s = scan(&c);
    let ls = members(&s, "macos.listeners");
    assert_eq!(ls.len(), 2);
    assert_eq!(ls[0].display, "tcp 0.0.0.0:22");
    assert_eq!(ls[1].display, "tcp6 [::]:22");
    let rs = members(&s, "macos.routes");
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].display, "0.0.0.0/0 via 192.168.64.1 dev en0");
}

#[test]
fn resolver_files_join_member_identity() {
    let c = Case::macos("resolver-dir", 4242);
    macos_tree(&c);
    c.dir("private/etc/resolver");
    c.file(
        "private/etc/resolver/dev",
        "nameserver 127.0.0.1\nport 5553\n",
        true,
    );
    c.file(
        "private/etc/resolver/corp",
        "search corp.example\nnameserver 10.1.1.1\n",
        true,
    );
    let s = scan(&c);
    let res = members(&s, "macos.resolvers");
    // The stub member plus the two files' directives, each carrying
    // its file name.
    assert_eq!(res.len(), 4);
    let corp = res
        .iter()
        .find(|m| {
            text(m, "file").as_deref() == Some("corp")
                && text(m, "directive").as_deref() == Some("nameserver")
        })
        .expect("corp nameserver member");
    assert_eq!(text(corp, "value").as_deref(), Some("10.1.1.1"));
}

#[test]
fn unsupported_layout_fact_reports_unknown() {
    let c = Case::macos("bad-layout", 4242);
    macos_tree(&c);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = [{ fd = 0, target = \"/dev/null\" }]\n\
         [mounts]\nstate = \"read\"\nentries = [{ path = \"/\", fstype = \"apfs\" }, { path = \"/dev\", fstype = \"devfs\" }]\n\
         [listeners]\nstate = \"unsupported-layout\"\n",
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "macos.listeners").state,
        UniverseState::Unknown(UnknownReason::UnsupportedLayout)
    );
}

#[test]
fn empty_mount_table_is_implausibly_empty() {
    let c = Case::macos("empty-mounts", 4242);
    macos_tree(&c);
    c.facts(
        4242,
        "[env_names]\nstate = \"read\"\nnames = []\n\
         [fds]\nstate = \"read\"\nentries = [{ fd = 0, target = \"/dev/null\" }]\n\
         [mounts]\nstate = \"read\"\nentries = []\n",
    );
    let s = scan(&c);
    assert_eq!(
        universe(&s, "macos.mounts").state,
        UniverseState::Unknown(UnknownReason::ImplausiblyEmpty)
    );
}

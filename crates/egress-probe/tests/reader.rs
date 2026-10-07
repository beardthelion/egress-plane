//! The probe reader abstraction over live and snapshot filesystems:
//! errno-preserving reads, metadata, access checks, filesystem types, the
//! allowlisted hop policy, kernel-filesystem checks, the no-touch gate,
//! the manifest overlay, facts, and the read log (KTD4, KTD9, KTD11,
//! KTD12, KTD24, KTD26, KTD31).

use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::discover::open::NodeType;
use egress_probe::reader::{AccessMask, AccessResult, Denial, Mount, ReadCall, Reader};
use egress_probe::snapshot::SnapshotReader;

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
            .join("probe-reader-tests")
            .join(format!("{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tree")).unwrap();
        let c = Case { dir };
        c.file(
            "facts.toml",
            format!(
                "platform = \"linux\"\n\
                 [process]\nstate = \"read\"\npid = {pid}\n\
                 [env_names]\nstate = \"read\"\nnames = []\n\
                 [fds]\nstate = \"read\"\nentries = []\n\
                 [landlock_abi]\nstate = \"not-built\"\n"
            )
            .as_str(),
            false,
        );
        c
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

/// A standard proc tree: `proc/self` -> `pid`, `proc/net` -> `self/net`,
/// and a pid directory with the usual files.
fn proc_tree(c: &Case, pid: u64) -> &Case {
    let p = pid.to_string();
    c.dir(&format!("proc/{p}/net"))
        .dir(&format!("proc/{p}/ns"))
        .dir("sys")
        .link("proc/self", &p)
        .link("proc/net", "self/net")
        .file(&format!("proc/{p}/mountinfo"), MOUNTINFO, true)
        .file(&format!("proc/{p}/status"), &status_text(&p, "0"), true)
        .file(
            &format!("proc/{p}/net/tcp"),
            "  sl  local_address rem_address   st\n",
            true,
        )
        .file(&format!("proc/{p}/net/unix"), "Num  RefCount\n", true)
        .file(&format!("proc/{p}/net/dev"), "a:\nb:\n", true)
        .file(&format!("proc/{p}/cgroup"), "0::/\n", true)
        .file(
            &format!("proc/{p}/uid_map"),
            "         0          0          1\n",
            true,
        )
        .file(
            &format!("proc/{p}/gid_map"),
            "         0          0          1\n",
            true,
        )
}

fn status_text(pid: &str, nspid_extra: &str) -> String {
    let nspid = if nspid_extra.is_empty() {
        pid.to_string()
    } else {
        format!("{pid} {nspid_extra}")
    };
    format!(
        "Name:\tprobe\nPid:\t{pid}\nTracerPid:\t0\nNSpid:\t{nspid}\nSeccomp:\t0\nNoNewPrivs:\t0\n"
    )
}

const MOUNTINFO: &str = "22 1 259:1 / / rw - ext4 /dev/sda1 rw\n\
                         24 22 0:24 / /proc rw - proc proc rw\n\
                         25 22 0:25 / /sys rw - sysfs sysfs rw\n\
                         26 22 0:26 / /dev rw - devtmpfs devtmpfs rw\n\
                         30 22 0:30 / /run rw - tmpfs tmpfs rw\n";

fn base_mounts() -> Vec<Mount> {
    vec![
        Mount::new("/", "ext4"),
        Mount::new("/proc", "proc"),
        Mount::new("/sys", "sysfs"),
        Mount::new("/dev", "devtmpfs"),
        Mount::new("/run", "tmpfs"),
    ]
}

fn armed(c: &Case) -> SnapshotReader {
    let mut r = c.reader();
    r.arm_mounts(base_mounts());
    r
}

fn has_call(r: &impl Reader, kind: ReadCall, path: &str) -> bool {
    r.read_log()
        .iter()
        .any(|e| e.kind == kind && e.path == path)
}

fn has_call_under(r: &impl Reader, path: &str) -> bool {
    let prefix = format!("{path}/");
    r.read_log()
        .iter()
        .any(|e| e.path == path || e.path.starts_with(&prefix))
}

// ---------------------------------------------------------------------------
// Errno-preserving reads and the manifest overlay (KTD9, KTD12).
// ---------------------------------------------------------------------------

#[test]
fn read_distinguishes_absent_unreadable_and_descriptor_limit() {
    let c = Case::linux("errno", 4242);
    proc_tree(&c, 4242);
    c.dir("etc")
        .file("etc/ok.conf", "x\n", true)
        .file("etc/denied.conf", "x\n", true)
        .file("etc/exhausted.conf", "x\n", true)
        .manifest(
            "[[node]]\npath = \"etc/denied.conf\"\ntype = \"error\"\nerrno = \"EACCES\"\n\
             [[node]]\npath = \"etc/exhausted.conf\"\ntype = \"error\"\nerrno = \"EMFILE\"\n",
        );
    let mut r = armed(&c);
    assert_eq!(r.read(b"etc/ok.conf", 1024).unwrap(), b"x\n");
    assert_eq!(r.read(b"etc/missing.conf", 1024), Err(Denial::Absent));
    assert_eq!(
        r.read(b"etc/denied.conf", 1024),
        Err(Denial::Unreadable(libc::EACCES))
    );
    // EMFILE is a descriptor limit, never "not present" (KTD9).
    assert_eq!(
        r.read(b"etc/exhausted.conf", 1024),
        Err(Denial::DescriptorLimit)
    );
}

#[test]
fn metadata_reports_manifest_node_types_and_fields() {
    let c = Case::linux("meta", 4242);
    proc_tree(&c, 4242);
    c.dir("run").dir("dev").manifest(
        "[[node]]\npath = \"run/docker.sock\"\ntype = \"socket\"\nmode = 0o660\n\
         uid = 1000\ngid = 1000\naccess = \"write\"\n\
         [[node]]\npath = \"dev/kvm\"\ntype = \"char\"\nmajor = 10\nminor = 232\n\
         access = \"write\"\n",
    );
    let mut r = armed(&c);
    let st = r.metadata(b"run/docker.sock").unwrap();
    assert_eq!(st.kind, NodeType::Socket);
    assert_eq!(st.mode & 0o777, 0o660);
    assert_eq!((st.uid, st.gid), (1000, 1000));

    let st = r.metadata(b"dev/kvm").unwrap();
    assert_eq!(st.kind, NodeType::Char);
    assert_eq!(st.device, Some((10, 232)));
}

#[test]
fn access_uses_manifest_declaration_then_the_real_check() {
    let c = Case::linux("access", 4242);
    proc_tree(&c, 4242);
    c.dir("run").file("run/real.txt", "x", true).manifest(
        "[[node]]\npath = \"run/docker.sock\"\ntype = \"socket\"\naccess = \"write\"\n\
             [[node]]\npath = \"run/shut.sock\"\ntype = \"socket\"\naccess = \"none\"\n",
    );
    let mut r = armed(&c);
    assert_eq!(
        r.access(b"run/docker.sock", AccessMask::WRITE).unwrap(),
        AccessResult::Granted
    );
    assert_eq!(
        r.access(b"run/shut.sock", AccessMask::READ).unwrap(),
        AccessResult::Refused
    );
    // A path with no manifest node goes through the real access check.
    assert_eq!(
        r.access(b"run/real.txt", AccessMask::READ).unwrap(),
        AccessResult::Granted
    );
    assert_eq!(
        r.access(b"run/missing", AccessMask::READ),
        Err(Denial::Absent)
    );
}

#[test]
fn listing_merges_virtual_nodes_in_byte_order() {
    let c = Case::linux("listmerge", 4242);
    proc_tree(&c, 4242);
    c.dir("run")
        .file("run/app.env", "x", true)
        .file("run/zreal", "x", true)
        .manifest(
            "[[node]]\npath = \"run/docker.sock\"\ntype = \"socket\"\naccess = \"write\"\n\
             [[node]]\npath = \"run/chardev\"\ntype = \"char\"\nmajor = 10\nminor = 200\n",
        );
    let mut r = armed(&c);
    let entries = r.list(b"run").unwrap();
    let kinds: Vec<(&[u8], NodeType)> = entries
        .iter()
        .map(|(n, m)| (n.as_slice(), m.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (b"app.env".as_slice(), NodeType::File),
            (b"chardev".as_slice(), NodeType::Char),
            (b"docker.sock".as_slice(), NodeType::Socket),
            (b"zreal".as_slice(), NodeType::File),
        ]
    );
}

// ---------------------------------------------------------------------------
// Kernel filesystem checks (KTD24).
// ---------------------------------------------------------------------------

#[test]
fn snapshot_fs_override_on_proc_is_a_mismatch() {
    let c = Case::linux("fakeproc", 4242);
    proc_tree(&c, 4242);
    c.manifest("[[node]]\npath = \"proc\"\ntype = \"meta\"\nfs = \"tmpfs\"\n");
    let mut r = c.reader();
    assert_eq!(
        r.read(b"proc/self/mountinfo", 1 << 20),
        Err(Denial::FsTypeMismatch)
    );
}

#[test]
fn snapshot_local_fs_override_on_sys_is_a_mismatch() {
    let c = Case::linux("fakesys", 4242);
    proc_tree(&c, 4242);
    c.dir("sys/kernel")
        .file("sys/kernel/x", "1\n", true)
        .manifest("[[node]]\npath = \"sys\"\ntype = \"meta\"\nfs = \"local\"\n");
    let mut r = armed(&c);
    assert_eq!(r.read(b"sys/kernel/x", 1024), Err(Denial::FsTypeMismatch));
}

#[test]
fn proc_self_wrong_pid_makes_every_self_read_mismatch() {
    let c = Case::linux("wrongpid", 4242);
    proc_tree(&c, 4242);
    c.dir("proc/999");
    std::fs::remove_file(c.tree().join("proc/self")).unwrap();
    c.link("proc/self", "999")
        .file("proc/999/status", &status_text("999", ""), true)
        .file("proc/999/mountinfo", MOUNTINFO, true);
    let mut r = armed(&c);
    assert_eq!(
        r.read(b"proc/self/mountinfo", 1 << 20),
        Err(Denial::ProcSelfMismatch)
    );
    assert_eq!(
        r.read(b"proc/net/tcp", 1 << 20),
        Err(Denial::ProcSelfMismatch)
    );
    assert_eq!(
        r.read(b"proc/self/status", 1 << 20),
        Err(Denial::ProcSelfMismatch)
    );
    assert!(!r.accepted_ancestor_pidns());
}

#[test]
fn ancestor_pid_namespace_is_accepted_through_nspid() {
    let c = Case::linux("nspid-ok", 1);
    proc_tree(&c, 1);
    // The link names the outer pid; NSpid records 4242 -> 1.
    std::fs::remove_file(c.tree().join("proc/self")).unwrap();
    c.link("proc/self", "4242")
        .dir("proc/4242/net")
        .file("proc/4242/mountinfo", MOUNTINFO, true)
        .file("proc/4242/status", &status_text("4242", "1"), true);
    let mut r = c.reader();
    r.read(b"proc/self/mountinfo", 1 << 20).unwrap();
    assert!(r.accepted_ancestor_pidns());
}

#[test]
fn ancestor_pid_namespace_rejected_variants() {
    for (name, status) in [
        ("nspid-last", Some(status_text("4242", "7"))),
        ("nspid-first", Some(status_text("5000", "1"))),
        ("nspid-none", Some("Name:\tx\nPid:\t4242\n".to_string())),
    ] {
        let c = Case::linux(name, 1);
        c.dir("proc/4242")
            .dir("proc/self")
            .file("proc/4242/status", status.as_deref().unwrap(), true)
            .file("proc/4242/mountinfo", MOUNTINFO, true);
        std::fs::remove_dir(c.tree().join("proc/self")).unwrap();
        c.link("proc/self", "4242");
        let mut r = c.reader();
        assert_eq!(
            r.read(b"proc/self/mountinfo", 1 << 20),
            Err(Denial::ProcSelfMismatch),
            "{name}"
        );
        assert!(!r.accepted_ancestor_pidns(), "{name}");
    }

    // Wrong filesystem on the status file also fails the check.
    let c = Case::linux("nspid-tmpfs", 1);
    c.dir("proc/4242")
        .file("proc/4242/status", &status_text("4242", "1"), true)
        .file("proc/4242/mountinfo", MOUNTINFO, true)
        .link("proc/self", "4242")
        .manifest("[[node]]\npath = \"proc/4242/status\"\ntype = \"meta\"\nfs = \"tmpfs\"\n");
    let mut r = c.reader();
    assert_eq!(
        r.read(b"proc/self/mountinfo", 1 << 20),
        Err(Denial::ProcSelfMismatch)
    );
}

// ---------------------------------------------------------------------------
// Allowlisted hops (KTD11).
// ---------------------------------------------------------------------------

#[test]
fn proc_self_and_proc_net_and_dmi_hops_resolve() {
    let c = Case::linux("hops", 4242);
    proc_tree(&c, 4242);
    c.dir("sys/devices/virtual/dmi/id")
        .file("sys/devices/virtual/dmi/id/sys_vendor", "Test\n", true)
        .link("sys/class/dmi/id", "../../devices/virtual/dmi/id");
    let mut r = c.reader();
    // The mountinfo read precedes the gate and resolves the self hop.
    assert_eq!(
        r.read(b"proc/self/mountinfo", 1 << 20).unwrap(),
        MOUNTINFO.as_bytes()
    );
    r.arm_mounts(base_mounts());
    r.read(b"proc/net/tcp", 1 << 20).unwrap();
    assert!(has_call(&r, ReadCall::Read, "proc/4242/net/tcp"));
    // The proc/net hop goes through proc/self/net without tripping the
    // one-hop rule.
    assert_eq!(
        r.read(b"sys/class/dmi/id/sys_vendor", 1024).unwrap(),
        b"Test\n"
    );
    assert!(has_call(
        &r,
        ReadCall::Read,
        "sys/devices/virtual/dmi/id/sys_vendor"
    ));
}

#[test]
fn dmi_hop_rejects_other_targets() {
    let c = Case::linux("dmi-hop", 4242);
    proc_tree(&c, 4242);
    c.dir("sys/class/dmi")
        .dir("sys/devices/virtual/dmi/id")
        .file("sys/devices/other/id/sys_vendor", "x", true)
        .link("sys/class/dmi/id", "../../devices/other/id");
    let mut r = armed(&c);
    assert_eq!(
        r.read(b"sys/class/dmi/id/sys_vendor", 1024),
        Err(Denial::LinkPolicy)
    );
}

#[test]
fn resolv_conf_each_permitted_target_resolves() {
    for target in [
        "run/systemd/resolve/stub-resolv.conf",
        "run/systemd/resolve/resolv.conf",
        "run/resolvconf/resolv.conf",
        "run/NetworkManager/resolv.conf",
        "etc/resolvconf/run/resolv.conf",
    ] {
        let c = Case::linux("resolv-ok", 4242);
        proc_tree(&c, 4242);
        c.dir("etc");
        // Link text relative to etc/ lands on the target through `..`
        // normalization.
        let text = if let Some(rest) = target.strip_prefix("etc/") {
            rest.to_string()
        } else {
            format!("../{target}")
        };
        c.link("etc/resolv.conf", &text)
            .file(target, "nameserver 1.1.1.1\n", true);
        let mut r = armed(&c);
        assert_eq!(
            r.read(b"etc/resolv.conf", 1 << 20).unwrap(),
            b"nameserver 1.1.1.1\n",
            "{target}"
        );
        assert!(has_call(&r, ReadCall::Read, target), "{target}");
    }
}

#[test]
fn resolv_conf_forbidden_targets_are_link_policy() {
    for target in [
        "../var/run/secrets/kubernetes.io/serviceaccount/token",
        "../host/root/.ssh/id_rsa",
        "shadow",
        "../run/other/resolv.conf",
    ] {
        let c = Case::linux("resolv-bad", 4242);
        proc_tree(&c, 4242);
        c.dir("etc")
            .dir("var/run/secrets/kubernetes.io/serviceaccount");
        c.file("etc/shadow", "SENTINEL-shadow\n", true)
            .file("host/root/.ssh/id_rsa", "SENTINEL-key\n", true)
            .file(
                "var/run/secrets/kubernetes.io/serviceaccount/token",
                "SENTINEL-token\n",
                true,
            )
            .file("run/other/resolv.conf", "nameserver 9.9.9.9\n", true)
            .link("etc/resolv.conf", target);
        let mut r = armed(&c);
        assert_eq!(
            r.read(b"etc/resolv.conf", 1 << 20),
            Err(Denial::LinkPolicy),
            "{target}"
        );
        // No content read of the target was performed.
        assert!(!has_call(&r, ReadCall::Read, "etc/shadow"), "{target}");
        assert!(
            !has_call(&r, ReadCall::Read, "host/root/.ssh/id_rsa"),
            "{target}"
        );
        assert!(
            !has_call(
                &r,
                ReadCall::Read,
                "run/secrets/kubernetes.io/serviceaccount/token"
            ),
            "{target}"
        );
        assert!(
            !has_call(&r, ReadCall::Read, "run/other/resolv.conf"),
            "{target}"
        );
    }
}

#[test]
fn resolv_conf_to_a_fifo_at_a_permitted_path_is_link_policy() {
    let c = Case::linux("resolv-fifo", 4242);
    proc_tree(&c, 4242);
    c.dir("etc")
        .link("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
        .manifest("[[node]]\npath = \"run/systemd/resolve/stub-resolv.conf\"\ntype = \"fifo\"\n");
    let mut r = armed(&c);
    assert_eq!(r.read(b"etc/resolv.conf", 1 << 20), Err(Denial::LinkPolicy));
}

#[test]
fn resolv_conf_second_hop_is_link_policy() {
    let c = Case::linux("resolv-2hop", 4242);
    proc_tree(&c, 4242);
    c.dir("etc")
        .dir("run/systemd/resolve")
        .file(
            "run/systemd/resolve/resolv.conf",
            "nameserver 1.1.1.1\n",
            true,
        )
        .link("run/systemd/resolve/stub-resolv.conf", "resolv.conf")
        .link("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf");
    let mut r = armed(&c);
    assert_eq!(r.read(b"etc/resolv.conf", 1 << 20), Err(Denial::LinkPolicy));
}

#[test]
fn proc_mounts_and_etc_mtab_are_not_allowlisted() {
    let c = Case::linux("mtab", 4242);
    proc_tree(&c, 4242);
    c.dir("etc")
        .link("proc/mounts", "self/mountinfo")
        .link("etc/mtab", "../proc/mounts");
    let mut r = armed(&c);
    assert_eq!(r.read(b"proc/mounts", 1 << 20), Err(Denial::LinkPolicy));
    assert_eq!(r.read(b"etc/mtab", 1 << 20), Err(Denial::LinkPolicy));
}

#[test]
fn a_link_off_the_allowlist_is_never_followed() {
    let c = Case::linux("offlist", 4242);
    proc_tree(&c, 4242);
    c.dir("opt/real")
        .file("opt/real/x.txt", "x\n", true)
        .link("opt/alias", "real");
    let mut r = armed(&c);
    assert_eq!(r.read(b"opt/alias/x.txt", 1024), Err(Denial::LinkPolicy));
}

#[test]
fn absolute_link_targets_reroot_inside_the_root() {
    let c = Case::linux("abs-link", 4242);
    proc_tree(&c, 4242);
    c.dir("etc")
        .file(
            "run/systemd/resolve/resolv.conf",
            "nameserver 1.1.1.1\n",
            true,
        )
        .link("etc/resolv.conf", "/run/systemd/resolve/resolv.conf");
    let mut r = armed(&c);
    assert_eq!(
        r.read(b"etc/resolv.conf", 1 << 20).unwrap(),
        b"nameserver 1.1.1.1\n"
    );

    // An absolute target that escapes the root is refused, never re-rooted
    // outside it.
    let c = Case::linux("abs-escape", 4242);
    proc_tree(&c, 4242);
    c.dir("etc").link("etc/resolv.conf", "/../etc/passwd");
    let mut r = armed(&c);
    assert_eq!(r.read(b"etc/resolv.conf", 1 << 20), Err(Denial::LinkPolicy));
}

// ---------------------------------------------------------------------------
// Metadata-only resolution of symlinked signal paths (KTD31).
// ---------------------------------------------------------------------------

fn atomic_writer_case(name: &str) -> Case {
    let c = Case::linux(name, 4242);
    proc_tree(&c, 4242);
    let sa = "run/secrets/kubernetes.io/serviceaccount";
    c.dir(sa)
        .dir(format!("{sa}/..2026_10_03_10_36_00.123456789").as_str())
        .file(
            format!("{sa}/..2026_10_03_10_36_00.123456789/token").as_str(),
            "SENTINEL-token\n",
            true,
        )
        .link(
            format!("{sa}/..data").as_str(),
            "..2026_10_03_10_36_00.123456789",
        )
        .link(format!("{sa}/token").as_str(), "..data/token")
        .link("var/run", "/run");
    c
}

#[test]
fn symlinked_credential_signal_resolves_for_metadata_and_access() {
    let c = atomic_writer_case("aw-ok");
    let mut r = armed(&c);
    let st = r
        .signal_metadata(b"var/run/secrets/kubernetes.io/serviceaccount/token")
        .unwrap();
    assert_eq!(st.kind, NodeType::File);
    assert_eq!(st.size, "SENTINEL-token\n".len() as u64);
    assert_eq!(
        r.signal_access(
            b"var/run/secrets/kubernetes.io/serviceaccount/token",
            AccessMask::READ
        )
        .unwrap(),
        AccessResult::Granted
    );
    // The chain used readlink and metadata only, never a content read.
    assert!(
        !r.read_log().iter().any(|e| e.kind == ReadCall::Read),
        "read log: {:?}",
        r.read_log()
    );
}

#[test]
fn signal_chain_third_hop_or_outside_parent_is_link_policy() {
    // A third hop (the final target is still a symlink).
    let c = atomic_writer_case("aw-3hop");
    let sa = "run/secrets/kubernetes.io/serviceaccount";
    c.dir(format!("{sa}/..2026_10_03_10_36_00.123456789/x").as_str())
        .file(
            format!("{sa}/..2026_10_03_10_36_00.123456789/x/token").as_str(),
            "t",
            true,
        );
    std::fs::remove_file(
        c.tree()
            .join(format!("{sa}/..2026_10_03_10_36_00.123456789/token")),
    )
    .unwrap();
    c.link(
        format!("{sa}/..2026_10_03_10_36_00.123456789/token").as_str(),
        "x/token",
    );
    let mut r = armed(&c);
    assert_eq!(
        r.signal_metadata(b"var/run/secrets/kubernetes.io/serviceaccount/token"),
        Err(Denial::LinkPolicy)
    );

    // A hop target outside the signal's parent directory.
    let c = atomic_writer_case("aw-outside");
    std::fs::remove_file(c.tree().join(format!("{sa}/token"))).unwrap();
    c.link(format!("{sa}/token").as_str(), "../../../etc/passwd")
        .file("etc/passwd", "root:x:0:0::/root:/bin/sh\n", true);
    let mut r = armed(&c);
    assert_eq!(
        r.signal_metadata(b"var/run/secrets/kubernetes.io/serviceaccount/token"),
        Err(Denial::LinkPolicy)
    );
    assert!(!has_call(&r, ReadCall::Read, "etc/passwd"));
}

// ---------------------------------------------------------------------------
// The no-touch gate and mount-table states (KTD26).
// ---------------------------------------------------------------------------

#[test]
fn calls_on_no_touch_mounts_are_refused_without_a_log_entry() {
    let c = Case::linux("nfs-home", 4242);
    proc_tree(&c, 4242);
    c.dir("home/u/.aws")
        .file("home/u/.aws/credentials", "SENTINEL-aws\n", true)
        .link("home/u/sock", "/tmp/x");
    let mut r = c.reader();
    let mut mounts = base_mounts();
    mounts.push(Mount::new("/home", "nfs4"));
    r.arm_mounts(mounts);
    // Every call kind is refused before the filesystem is touched.
    assert_eq!(
        r.read(b"home/u/.aws/credentials", 1024),
        Err(Denial::NotTouched)
    );
    assert_eq!(r.list(b"home/u"), Err(Denial::NotTouched));
    assert_eq!(
        r.metadata(b"home/u/.aws/credentials"),
        Err(Denial::NotTouched)
    );
    assert_eq!(
        r.access(b"home/u/.aws/credentials", AccessMask::READ),
        Err(Denial::NotTouched)
    );
    assert_eq!(r.readlink(b"home/u/sock"), Err(Denial::NotTouched));
    assert!(!has_call_under(&r, "home"));

    // virtiofs is local and touched.
    let mut r = c.reader();
    let mut mounts = base_mounts();
    mounts.push(Mount::new("/home", "virtiofs"));
    r.arm_mounts(mounts);
    assert_eq!(
        r.metadata(b"home/u/.aws/credentials").unwrap().kind,
        NodeType::File
    );
}

#[test]
fn a_manifest_fs_override_blocks_calls_the_mount_table_would_allow() {
    let c = Case::linux("overlay-notouch", 4242);
    proc_tree(&c, 4242);
    c.dir("run").manifest(
        "[[node]]\npath = \"run\"\ntype = \"meta\"\nfs = \"fuse.sshfs\"\n\
             [[node]]\npath = \"run/docker.sock\"\ntype = \"socket\"\naccess = \"write\"\n",
    );
    // The mount table says run/ is ordinary tmpfs; the manifest override
    // still blocks every call under it (KTD12).
    let mut r = armed(&c);
    assert_eq!(r.metadata(b"run/docker.sock"), Err(Denial::NotTouched));
    assert_eq!(r.read(b"run/x", 1024), Err(Denial::NotTouched));
    assert!(!has_call_under(&r, "run"));

    // With mounts unknown the same calls refuse as depends-on-unknown,
    // also without touching the path.
    let mut r = c.reader();
    r.mounts_unknown();
    assert_eq!(
        r.metadata(b"run/docker.sock"),
        Err(Denial::DependsOnUnknown)
    );
    assert!(!has_call_under(&r, "run"));
}

#[test]
fn an_intermediate_component_on_a_no_touch_mount_is_refused() {
    let c = Case::linux("nfs-mid", 4242);
    proc_tree(&c, 4242);
    c.dir("mnt/local").file("mnt/local/x", "x", true);
    let mut r = c.reader();
    let mut mounts = base_mounts();
    mounts.push(Mount::new("/mnt", "nfs4"));
    mounts.push(Mount::new("/mnt/local", "ext4"));
    r.arm_mounts(mounts);
    // The walk opens mnt, which sits on NFS.
    assert_eq!(r.metadata(b"mnt/local/x"), Err(Denial::NotTouched));
    assert!(!has_call_under(&r, "mnt"));
}

#[test]
fn the_gate_covers_proc_and_sys_once_armed() {
    let c = Case::linux("fuse-proc", 4242);
    proc_tree(&c, 4242);
    c.dir("proc/fake").file("proc/fake/x", "x", true);
    let mut r = c.reader();
    let mut mounts = base_mounts();
    mounts.push(Mount::new("/proc/fake", "fuse.sshfs"));
    r.arm_mounts(mounts);
    assert_eq!(r.read(b"proc/fake/x", 1024), Err(Denial::NotTouched));
}

#[test]
fn calls_before_the_mount_table_are_refused_not_performed() {
    let c = Case::linux("unarmed", 4242);
    proc_tree(&c, 4242);
    c.dir("etc").file("etc/hostname", "h\n", true);
    let mut r = c.reader();
    assert_eq!(r.metadata(b"etc/hostname"), Err(Denial::DependsOnUnknown));
    assert!(r.read_log().is_empty(), "{:?}", r.read_log());
}

#[test]
fn the_mountinfo_read_precedes_the_gate() {
    let c = Case::linux("pre-arm", 4242);
    proc_tree(&c, 4242);
    let mut r = c.reader();
    assert_eq!(
        r.read(b"proc/self/mountinfo", 1 << 20).unwrap(),
        MOUNTINFO.as_bytes()
    );
    assert!(has_call(&r, ReadCall::Read, "proc/4242/mountinfo"));
}

#[test]
fn mounts_unknown_blocks_everything_outside_proc_and_sys() {
    let c = Case::linux("mounts-unknown", 4242);
    proc_tree(&c, 4242);
    c.dir("run")
        .manifest("[[node]]\npath = \"run/docker.sock\"\ntype = \"socket\"\naccess = \"write\"\n");
    let mut r = c.reader();
    r.mounts_unknown();
    assert_eq!(
        r.metadata(b"run/docker.sock"),
        Err(Denial::DependsOnUnknown)
    );
    assert!(!has_call(&r, ReadCall::Metadata, "run/docker.sock"));
    // proc/ and sys/ sources still proceed, under the same kernel checks.
    assert_eq!(
        r.read(b"proc/self/status", 1 << 20).unwrap(),
        status_text("4242", "0").as_bytes()
    );
}

// ---------------------------------------------------------------------------
// Credential paths carry no content method; the read log records calls.
// ---------------------------------------------------------------------------

#[test]
fn content_reads_under_credential_paths_are_refused() {
    let c = Case::linux("cred-read", 4242);
    proc_tree(&c, 4242);
    c.dir("run/secrets")
        .file("run/secrets/api-key", "SENTINEL\n", true)
        .link("var/run", "/run");
    let mut r = armed(&c);
    assert_eq!(
        r.read(b"var/run/secrets/api-key", 1024),
        Err(Denial::LinkPolicy)
    );
    assert!(!has_call(&r, ReadCall::Read, "run/secrets/api-key"));
    // Metadata and listing calls are still allowed there.
    assert_eq!(
        r.metadata(b"run/secrets/api-key").unwrap().kind,
        NodeType::File
    );
}

#[test]
fn the_read_log_records_every_call_kind_with_resolved_paths() {
    let c = Case::linux("log", 4242);
    proc_tree(&c, 4242);
    c.dir("etc")
        .file("etc/hostname", "h\n", true)
        .file("etc/motd", "hi\n", true)
        .link("etc/motd-link", "motd");
    let mut r = armed(&c);
    r.read(b"etc/hostname", 1024).unwrap();
    r.list(b"etc").unwrap();
    r.metadata(b"etc/hostname").unwrap();
    r.access(b"etc/hostname", AccessMask::READ).unwrap();
    assert_eq!(r.readlink(b"etc/motd-link").unwrap(), b"motd");
    let log: Vec<(ReadCall, &str)> = r
        .read_log()
        .iter()
        .map(|e| (e.kind, e.path.as_str()))
        .collect();
    for kind in [
        ReadCall::Read,
        ReadCall::List,
        ReadCall::Metadata,
        ReadCall::Access,
        ReadCall::Readlink,
    ] {
        assert!(
            log.iter().any(|(k, _)| *k == kind),
            "missing {kind:?} in {log:?}"
        );
    }
    assert!(log.contains(&(ReadCall::Readlink, "etc/motd-link")));
    assert!(log.contains(&(ReadCall::Metadata, "etc/hostname")));
}

// ---------------------------------------------------------------------------
// The live reader over the same trait.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn the_live_reader_runs_the_same_pipeline() {
    use egress_probe::facts::{Fact, Facts, Platform, ProcessFact};
    use egress_probe::reader::LiveReader;

    let pid = std::process::id() as u64;
    let mut r = LiveReader::live(Facts {
        platform: Some(Platform::Linux),
        process: Fact::Read(ProcessFact { pid }),
        ..Default::default()
    })
    .unwrap();
    let mounts = r.read(b"proc/self/mountinfo", 1 << 20).unwrap();
    assert!(!mounts.is_empty());
    // The proc/self hop resolved to the live pid, checked by KTD24.
    assert!(has_call(
        &r,
        ReadCall::Read,
        &format!("proc/{pid}/mountinfo")
    ));
}

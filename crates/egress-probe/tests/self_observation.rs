//! Linux live self-observation: the process is made non-dumpable before
//! anything else, the descriptor inventory runs `fstatfs` and the
//! `proc/self` check before listing, env names come from the in-memory
//! environ array, and no descriptor is ever hidden (KTD8, KTD25, R17).
//!
//! The parent tests re-exec this test binary with a marker environment
//! variable; the child runs the live entry sequence and dumps its facts
//! to a file the parent inspects.

use std::io::Read;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;

use egress_probe::facts::{EnvName, Fact, FdEntry};
use egress_probe::model::{Member, MemberField, MemberValue};
use egress_probe::universe;

/// Env var that turns this binary's `child_entry` test into a fact dump.
const CHILD_OUT: &str = "EGRESS_PROBE_CHILD_FACTS";
/// A sentinel env value the child gets; it must appear in no output.
const SENTINEL_NAME: &str = "EGRESS_PROBE_CHILD_SENTINEL";
const SENTINEL_VALUE: &str = "s3ns1t1v3-child-value";

// ---------------------------------------------------------------------------
// The child: runs the live entry sequence and writes its facts.
// ---------------------------------------------------------------------------

/// The child entry point: runs the probe's first actions (non-dumpable,
/// descriptor inventory, env names, pid, Landlock) and writes the facts
/// to `$EGRESS_PROBE_CHILD_FACTS` one line per entry. Runs as a no-op
/// when the marker is unset so the normal suite never makes the test
/// process non-dumpable.
#[test]
fn child_entry() {
    let Some(out) = std::env::var_os(CHILD_OUT) else {
        return;
    };
    let facts = egress_probe::facts::linux::collect();
    // PR_GET_DUMPABLE after the entry: the process must be non-dumpable.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    let mut text = format!("dumpable {dumpable}\n");
    if let Some(p) = facts.process.read() {
        text.push_str(&format!("pid {}\n", p.pid));
    }
    match &facts.fds {
        Fact::Read(entries) => {
            for e in entries {
                text.push_str(&format!(
                    "fd {} {} {}\n",
                    e.fd,
                    u8::from(e.probe_own),
                    e.target
                ));
            }
        }
        other => text.push_str(&format!("fds-state {other:?}\n")),
    }
    if let Some(names) = facts.env_names.read() {
        for n in names {
            match n {
                EnvName::Name(b) => {
                    text.push_str(&format!("env {}\n", String::from_utf8_lossy(b.as_slice())))
                }
                EnvName::NoSeparator => text.push_str("env <no-separator>\n"),
            }
        }
    }
    std::fs::write(&out, &text).unwrap();
}

/// Spawns this test binary as `child_entry` and returns the dumped facts.
fn run_child(fd5: Option<RawFd>, extra_env: &[(&str, &str)]) -> String {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "self-observation-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.arg("child_entry")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_OUT, &out)
        .env(SENTINEL_NAME, SENTINEL_VALUE);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if let Some(fd) = fd5 {
        // Hand the child an inherited socket on descriptor 5.
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(fd, 5) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let status = cmd.status().unwrap();
    assert!(status.success(), "child failed: {status}");
    let mut text = String::new();
    std::fs::File::open(&out)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    text
}

struct ChildFacts {
    dumpable: i64,
    fds: Vec<FdEntry>,
    env: Vec<String>,
    raw: String,
}

fn parse_child(text: &str) -> ChildFacts {
    let mut f = ChildFacts {
        dumpable: -1,
        fds: Vec::new(),
        env: Vec::new(),
        raw: text.to_string(),
    };
    for line in text.lines() {
        let mut parts = line.splitn(2, ' ');
        match (parts.next(), parts.next()) {
            (Some("dumpable"), Some(v)) => f.dumpable = v.parse().unwrap(),
            (Some("fd"), Some(rest)) => {
                let mut it = rest.splitn(3, ' ');
                let fd = it.next().unwrap().parse().unwrap();
                let own = it.next().unwrap() == "1";
                let target = it.next().unwrap().to_string();
                f.fds.push(FdEntry {
                    fd,
                    target,
                    probe_own: own,
                });
            }
            (Some("env"), Some(name)) => f.env.push(name.to_string()),
            _ => {}
        }
    }
    f
}

fn member(members: &[Member], fd: u64) -> &Member {
    members
        .iter()
        .find(|m| {
            matches!(m.fields.iter().find(|f| f.name == "fd"),
                Some(MemberField { value: MemberValue::Int(n), .. }) if *n == fd)
        })
        .unwrap_or_else(|| panic!("fd {fd} member in {members:?}"))
}

fn text(m: &Member, name: &str) -> Option<String> {
    m.fields
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| match &f.value {
            MemberValue::Text(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        })
}

// ---------------------------------------------------------------------------
// Parent assertions (AE14 and the must-not descriptor-leak case).
// ---------------------------------------------------------------------------

#[test]
fn child_is_non_dumpable_and_env_names_carry_no_values() {
    let f = parse_child(&run_child(None, &[]));
    assert_eq!(f.dumpable, 0, "PR_GET_DUMPABLE after the entry");
    // Environment names are enumerated without their values (R17).
    assert!(f.env.iter().any(|n| n == SENTINEL_NAME));
    assert!(
        !f.raw.contains(SENTINEL_VALUE),
        "sentinel value leaked into facts output"
    );
    assert!(f.env.iter().all(|n| !n.contains('=')));
}

#[test]
fn inherited_socket_on_fd5_is_an_inherited_socket_member() {
    let (a, _b) = UnixStream::pair().unwrap();
    let f = parse_child(&run_child(Some(a.as_raw_fd()), &[]));
    let members = universe::fd_members(&f.fds);
    let m5 = member(&members, 5);
    assert_eq!(text(m5, "label").as_deref(), Some("inherited"));
    assert_eq!(text(m5, "kind").as_deref(), Some("socket"));
    // Descriptors 0 to 2 are labeled, the listing handle is probe-own.
    for (fd, label) in [(0, "stdin"), (1, "stdout"), (2, "stderr")] {
        assert_eq!(text(member(&members, fd), "label").as_deref(), Some(label));
    }
    assert!(
        members
            .iter()
            .any(|m| text(m, "label").as_deref() == Some("probe-own"))
    );
    // Every descriptor in the child's inventory is a member.
    assert_eq!(members.len(), f.fds.len());
}

#[test]
fn a_child_with_no_extra_descriptors_reports_no_inherited_member() {
    let f = parse_child(&run_child(None, &[]));
    let members = universe::fd_members(&f.fds);
    assert!(
        !members
            .iter()
            .any(|m| text(m, "label").as_deref() == Some("inherited")),
        "inherited members with no inherited descriptors: {members:?}"
    );
}

// ---------------------------------------------------------------------------
// The adapter's checks, in-process (KTD8).
// ---------------------------------------------------------------------------

#[test]
fn the_real_inventory_lists_the_listing_handle_once() {
    let Fact::Read(entries) = egress_probe::facts::linux::descriptor_inventory() else {
        panic!("descriptor inventory failed on this kernel");
    };
    let own = entries.iter().filter(|e| e.probe_own).count();
    assert_eq!(
        own, 1,
        "exactly the listing handle is probe-own: {entries:?}"
    );
    let numbers: std::collections::BTreeSet<u64> = entries.iter().map(|e| e.fd).collect();
    assert_eq!(numbers.len(), entries.len(), "a descriptor listed twice");
}

#[test]
fn a_non_proc_listing_handle_is_fs_type_mismatch() {
    // The snapshot-only seam replaces the handle's reported filesystem.
    let fact = egress_probe::facts::linux::descriptor_inventory_with_fs(0x0102ff94); // tmpfs
    assert_eq!(fact, Fact::FsTypeMismatch);
    // The universe turns the fact state into its unknown reason.
    let reason = universe::fact_reason(&fact);
    assert_eq!(reason, egress_probe::model::UnknownReason::FsTypeMismatch);
}

#[test]
fn env_names_come_from_environ_without_values() {
    let Fact::Read(names) = egress_probe::facts::linux::env_names() else {
        panic!("env_names fact unreadable");
    };
    assert!(
        names
            .iter()
            .any(|n| matches!(n, EnvName::Name(b) if b == b"PATH"))
    );
    for n in &names {
        if let EnvName::Name(b) = n {
            assert!(!b.contains(&b'='), "value bytes in env name: {b:?}");
        }
    }
}

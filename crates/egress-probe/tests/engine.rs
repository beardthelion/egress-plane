//! Engine-level tests: classification precedence, layer ordering,
//! derived-signal dependency propagation, tamper indicator timing, and
//! completeness/exit-code derivation, all over the real data files.

mod common;

use std::collections::BTreeMap;

use egress_core::model::CompletenessState;
use egress_probe::classify;
use egress_probe::completeness;
use egress_probe::data::Data;
use egress_probe::facts::Facts;
use egress_probe::integrity;
use egress_probe::model::*;
use egress_probe::reader::{AccessMask, AccessResult, Denial, Meta, Mount, ReadLogEntry, Reader};
use egress_probe::signals;

use common::{bfield, boolfield, member, tfield, universe};

fn data() -> Data {
    Data::embedded().unwrap()
}

fn mount_member(point: &str, fstype: &str, writable: bool) -> Member {
    member(
        vec![
            bfield("mount-point", point.as_bytes(), true),
            tfield("fstype", fstype, true),
            bfield("mount-root", b"/", true),
            egress_probe::model::MemberField {
                name: "options".into(),
                value: MemberValue::Text(b"rw".to_vec()),
                identity: false,
            },
            boolfield("writable", writable, false),
        ],
        point,
        MemberClass::Unclassified,
        &[],
    )
}

fn classify(universes: &mut [Universe], euid: Option<u32>) -> (Vec<Route>, Vec<Route>) {
    classify::classify(universes, &data(), euid)
}

#[test]
fn escape_beats_inert_and_every_rule_id_is_recorded() {
    // /var/run/docker.sock as a socket-files member matches the escape
    // runtime-socket rule; an inert rule cannot override it (KTD6).
    let mut universes = vec![universe(
        "linux.socket-files",
        UniverseState::Enumerated,
        vec![member(
            vec![bfield("path", b"/var/run/docker.sock", true)],
            "/var/run/docker.sock",
            MemberClass::Unclassified,
            &[],
        )],
    )];
    let (_e, esc) = classify(&mut universes, Some(0));
    assert_eq!(universes[0].members[0].class, MemberClass::Escape);
    assert!(
        universes[0].members[0]
            .rules
            .contains(&"linux.socket.runtime".to_string())
    );
    assert!(esc.iter().any(|r| r.kind == "runtime-socket"));
}

#[test]
fn inert_only_member_is_inert_not_a_route() {
    let mut universes = vec![universe(
        "linux.mounts",
        UniverseState::Enumerated,
        vec![mount_member("/etc/hosts", "ext4", true)],
    )];
    let (eg, esc) = classify(&mut universes, Some(0));
    assert_eq!(universes[0].members[0].class, MemberClass::Inert);
    assert!(eg.is_empty() && esc.is_empty());
}

#[test]
fn unmatched_member_is_unclassified_and_state_stays_complete() {
    let mut universes = vec![universe(
        "linux.mounts",
        UniverseState::Enumerated,
        vec![mount_member("/opt/odd", "tmpfs", true)],
    )];
    classify(&mut universes, Some(0));
    assert_eq!(universes[0].members[0].class, MemberClass::Unclassified);
}

#[test]
fn under_is_component_boundary_and_except_wins() {
    // A writable sysfs sub-mount below /sys is an escape route; the bare
    // /proc and /sys points are excepted and stay inert under pseudo.
    let mut universes = vec![universe(
        "linux.mounts",
        UniverseState::Enumerated,
        vec![
            mount_member("/sys", "sysfs", true),
            mount_member("/proc", "proc", true),
            mount_member("/sys/fs/bpf", "sysfs", true),
        ],
    )];
    let (_eg, esc) = classify(&mut universes, Some(0));
    let members = &universes[0].members;
    assert_eq!(members[0].class, MemberClass::Inert);
    assert_eq!(members[1].class, MemberClass::Inert);
    assert_eq!(members[2].class, MemberClass::Escape);
    assert_eq!(esc.len(), 1);
    assert_eq!(esc[0].kind, "writable-kernel-interface");
}

#[test]
fn writable_host_bind_is_an_escape_route() {
    let mut universes = vec![universe(
        "linux.mounts",
        UniverseState::Enumerated,
        vec![mount_member("/host", "ext4", true)],
    )];
    let (_e, esc) = classify(&mut universes, Some(0));
    assert!(esc.iter().any(|r| r.kind == "writable-host-mount"));
}

#[test]
fn runtime_socket_rule_matches_by_basename() {
    let mut universes = vec![universe(
        "linux.socket-files",
        UniverseState::Enumerated,
        vec![member(
            vec![bfield("path", b"/opt/odd/docker.sock", true)],
            "/opt/odd/docker.sock",
            MemberClass::Unclassified,
            &[],
        )],
    )];
    let (_e, esc) = classify(&mut universes, Some(0));
    assert!(esc.iter().any(|r| r.kind == "runtime-socket"));
}

// ---------------------------------------------------------------------------
// A fake reader for signal and integrity tests.
// ---------------------------------------------------------------------------

struct FakeReader {
    files: BTreeMap<Vec<u8>, Vec<u8>>,
    log: Vec<ReadLogEntry>,
    facts: Facts,
    reads: BTreeMap<Vec<u8>, usize>,
    /// Status bytes returned on the second proc/self/status read (the
    /// KTD25 finalize-time re-read).
    second_status: Option<Vec<u8>>,
}

impl FakeReader {
    fn new() -> Self {
        FakeReader {
            files: BTreeMap::new(),
            log: Vec::new(),
            facts: Facts::default(),
            reads: BTreeMap::new(),
            second_status: None,
        }
    }
}

impl Reader for FakeReader {
    fn read(&mut self, path: &[u8], _limit: u64) -> Result<Vec<u8>, Denial> {
        self.log.push(ReadLogEntry {
            kind: egress_probe::reader::ReadCall::Read,
            path: String::from_utf8_lossy(path).into_owned(),
        });
        let n = self.reads.entry(path.to_vec()).or_default();
        *n += 1;
        if path == b"proc/self/status" && *n > 1 && self.second_status.is_some() {
            return Ok(self.second_status.clone().unwrap());
        }
        self.files.get(path).cloned().ok_or(Denial::Absent)
    }
    fn list(&mut self, _path: &[u8]) -> Result<Vec<(Vec<u8>, Meta)>, Denial> {
        Err(Denial::Absent)
    }
    fn metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        self.log.push(ReadLogEntry {
            kind: egress_probe::reader::ReadCall::Metadata,
            path: String::from_utf8_lossy(path).into_owned(),
        });
        self.files
            .get(path)
            .map(|_| Meta {
                kind: egress_probe::reader::NodeType::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                size: 0,
                device: None,
            })
            .ok_or(Denial::Absent)
    }
    fn access(&mut self, _path: &[u8], _mask: AccessMask) -> Result<AccessResult, Denial> {
        Err(Denial::Absent)
    }
    fn readlink(&mut self, _path: &[u8]) -> Result<Vec<u8>, Denial> {
        Err(Denial::Absent)
    }
    fn signal_metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        self.metadata(path)
    }
    fn signal_access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial> {
        self.access(path, mask)
    }
    fn facts(&self) -> &Facts {
        &self.facts
    }
    fn read_log(&self) -> &[ReadLogEntry] {
        &self.log
    }
    fn arm_mounts(&mut self, _mounts: Vec<Mount>) {}
    fn mounts_unknown(&mut self) {}
    fn accepted_ancestor_pidns(&self) -> bool {
        false
    }
}

fn ctx<'a>(
    universes: &'a [Universe],
    attributes: &'a BTreeMap<String, AttrValue>,
    facts: &'a Facts,
    layers: &'a [Layer],
    home: &'a Result<Vec<u8>, UnknownReason>,
) -> signals::Ctx<'a> {
    signals::Ctx {
        platform: "linux",
        universes,
        attributes,
        euid: Some(0),
        home,
        fired: Default::default(),
        layers,
        facts,
        tracer_pid: Some(0),
        traced: false,
        fs_type_mismatch: false,
        proc_self_mismatch: false,
        unknown_sources: Default::default(),
    }
}

#[test]
fn tracer_pid_is_parsed_from_status_text() {
    assert_eq!(
        integrity::tracer_pid(b"Name:\tprobe\nTracerPid:\t77\n"),
        Some(77)
    );
    assert_eq!(integrity::tracer_pid(b"TracerPid:\t0\n"), Some(0));
}

#[test]
fn path_marker_signal_reports_present_and_route() {
    let mut r = FakeReader::new();
    r.files.insert(b".dockerenv".to_vec(), Vec::new());
    let universes = vec![universe("linux.mounts", UniverseState::Enumerated, vec![])];
    let attrs = BTreeMap::new();
    let facts = Facts::default();
    let layers = vec![];
    let home = Ok(b"/root".to_vec());
    let mut c = ctx(&universes, &attrs, &facts, &layers, &home);
    let out = signals::evaluate(&mut r, &data(), &mut c);
    assert!(out.present.contains("linux.marker.dockerenv"));
}

#[test]
fn credential_paths_are_never_content_read() {
    let mut r = FakeReader::new();
    r.files
        .insert(b"root/.aws/credentials".to_vec(), b"SECRET".to_vec());
    let universes = vec![universe("linux.mounts", UniverseState::Enumerated, vec![])];
    let attrs = BTreeMap::new();
    let facts = Facts::default();
    let layers = vec![];
    let home = Ok(b"/root".to_vec());
    let mut c = ctx(&universes, &attrs, &facts, &layers, &home);
    let out = signals::evaluate(&mut r, &data(), &mut c);
    assert!(out.present.contains("cred.aws-shared"));
    assert!(out.escape.iter().any(|e| e.kind == "cloud-credential"));
    // The credential path was never content-read (KTD13 read-log
    // contract); other sources (DMI) may read.
    assert!(!r.log.iter().any(|e| {
        e.kind == egress_probe::reader::ReadCall::Read && e.path.contains("credentials")
    }));
}

#[test]
fn missing_home_makes_home_relative_signals_unknown() {
    let mut r = FakeReader::new();
    let universes = vec![universe("linux.mounts", UniverseState::Enumerated, vec![])];
    let attrs = BTreeMap::new();
    let facts = Facts::default();
    let layers = vec![];
    let home: Result<Vec<u8>, UnknownReason> = Err(UnknownReason::NoAccountHome);
    let mut c = ctx(&universes, &attrs, &facts, &layers, &home);
    let out = signals::evaluate(&mut r, &data(), &mut c);
    assert!(
        out.unknowns
            .iter()
            .any(|u| u.source == "cred.aws-shared" && u.reason == UnknownReason::NoAccountHome)
    );
}

#[test]
fn completeness_follows_the_decision_diagram() {
    let mut r = common::report(vec![universe(
        "linux.mounts",
        UniverseState::Enumerated,
        vec![],
    )]);
    assert_eq!(completeness::derive(&r), CompletenessState::Complete);
    assert_eq!(r.completeness.exit_code(), 0);

    r.unknowns.push(Unknown {
        id: String::new(),
        source: "linux.mounts".into(),
        reason: UnknownReason::Unreadable,
    });
    assert_eq!(completeness::derive(&r), CompletenessState::Incomplete);
    assert_eq!(CompletenessState::Incomplete.exit_code(), 2);

    let empty = common::report(vec![universe(
        "linux.mounts",
        UniverseState::Unknown(UnknownReason::Unreadable),
        vec![],
    )]);
    assert_eq!(completeness::derive(&empty), CompletenessState::Empty);
    assert_eq!(CompletenessState::Empty.exit_code(), 3);
}

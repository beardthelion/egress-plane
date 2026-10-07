//! Shared builders and probe-schema validation for egress-probe tests.
#![allow(dead_code)]

use std::collections::BTreeMap;

use egress_core::model::CompletenessState;
use egress_probe::facts::Platform;
use egress_probe::model::*;

pub fn tool() -> Tool {
    Tool {
        name: "egress-plane".into(),
        version: "0.1.0".into(),
        data_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
    }
}

/// A text member field. `identity` marks a KTD5 identity component.
pub fn tfield(name: &str, value: &str, identity: bool) -> MemberField {
    MemberField {
        name: name.into(),
        value: MemberValue::Text(value.as_bytes().to_vec()),
        identity,
    }
}

/// A text member field from raw bytes.
pub fn bfield(name: &str, value: &[u8], identity: bool) -> MemberField {
    MemberField {
        name: name.into(),
        value: MemberValue::Text(value.to_vec()),
        identity,
    }
}

/// An integer member field, display-only by default.
pub fn ifield(name: &str, value: u64) -> MemberField {
    MemberField {
        name: name.into(),
        value: MemberValue::Int(value),
        identity: false,
    }
}

/// A boolean member field. `identity` marks a KTD5 identity component.
pub fn boolfield(name: &str, value: bool, identity: bool) -> MemberField {
    MemberField {
        name: name.into(),
        value: MemberValue::Bool(value),
        identity,
    }
}

pub fn member(
    fields: Vec<MemberField>,
    display: &str,
    class: MemberClass,
    rules: &[&str],
) -> Member {
    Member {
        id: String::new(),
        fields,
        display: display.into(),
        class,
        rules: rules.iter().map(|r| r.to_string()).collect(),
        ordinal: 0,
    }
}

pub fn universe(id: &str, state: UniverseState, members: Vec<Member>) -> Universe {
    Universe {
        id: id.into(),
        state,
        members,
    }
}

/// A minimal linux passive report: no layers, no routes, no unknowns.
pub fn report(universes: Vec<Universe>) -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        tool: tool(),
        source: Source::Snapshot,
        platform: Platform::Linux,
        privilege: Privilege {
            euid: 1000,
            egid: 1000,
        },
        mode: Mode::Passive,
        nonce: None,
        completeness: CompletenessState::Complete,
        layers: Vec::new(),
        egress_routes: Vec::new(),
        escape_routes: Vec::new(),
        unknowns: Vec::new(),
        tamper_indicators: Vec::new(),
        not_observable: Vec::new(),
        not_applicable: Vec::new(),
        unclassified: Vec::new(),
        universes,
        signals: Vec::new(),
        active_checks: Vec::new(),
        caveats: Vec::new(),
    }
}

/// A `linux.listeners` member on `address` with `port` display-only (the
/// universe's identity is protocol plus local address; the port is
/// display-only per the universe table).
pub fn listener(address: &str, port: u64) -> Member {
    member(
        vec![
            tfield("protocol", "tcp", true),
            tfield("address", address, true),
            ifield("port", port),
            ifield("inode", 0),
            ifield("uid", 0),
        ],
        &format!("tcp {address}:{port}"),
        MemberClass::Unclassified,
        &[],
    )
}

/// A `linux.mounts` member with the given mount point bytes.
pub fn mount(point: &[u8], fstype: &str, class: MemberClass, rules: &[&str]) -> Member {
    let display = format!("{} ({fstype})", String::from_utf8_lossy(point));
    member(
        vec![
            bfield("path", point, true),
            tfield("fstype", fstype, true),
            tfield("mount_root", "/", true),
            ifield("mount_id", 35),
            tfield("source", "/dev/sda1", false),
            tfield("options", "rw,relatime", false),
            boolfield("writable", true, false),
        ],
        &display,
        class,
        rules,
    )
}

/// A report that fills every section and every optional field, so the
/// schema validation covers the whole shape.
pub fn full_report() -> Report {
    let mut r = report(vec![
        universe(
            "linux.mounts",
            UniverseState::Enumerated,
            vec![
                mount(b"/", "ext4", MemberClass::Inert, &["linux.mount.system"]),
                mount(
                    b"/host",
                    "ext4",
                    MemberClass::Escape,
                    &["linux.mount.host-rw-bind"],
                ),
                mount(b"/data", "tmpfs", MemberClass::Unclassified, &[]),
            ],
        ),
        universe("linux.resolvers", UniverseState::Absent, Vec::new()),
        universe(
            "linux.listeners",
            UniverseState::Unknown(UnknownReason::Unreadable),
            Vec::new(),
        ),
        universe("macos.mounts", UniverseState::NotApplicable, Vec::new()),
    ]);
    // The unclassified member needs a route-free entry; the escape member
    // gets a route below.
    r.layers.push(Layer {
        id: String::new(),
        family: LayerFamily::Container,
        kind: "docker".into(),
        evidence: vec![Evidence {
            class: EvidenceClass::FilesystemMarker,
            detail: "/.dockerenv".into(),
        }],
        attributes: BTreeMap::from([
            (
                "namespaces".into(),
                AttrValue::Namespaces(vec![
                    NamespaceInode {
                        name: "mnt".into(),
                        inode: 4026531840,
                    },
                    NamespaceInode {
                        name: "net".into(),
                        inode: 4026531993,
                    },
                ]),
            ),
            ("seccomp".into(), AttrValue::Int(2)),
            ("no_new_privs".into(), AttrValue::Bool(true)),
            (
                "cgroups".into(),
                AttrValue::Strings(vec!["0::/docker/abc".into()]),
            ),
            ("uid_map".into(), AttrValue::Str("0 0 4294967295".into())),
        ]),
    });
    // Escape route on the /host mount member.
    let host_member = &r.universes[0].members[1];
    r.escape_routes.push(Route {
        id: String::new(),
        kind: "writable-host-mount".into(),
        rule: Some("linux.mount.host-rw-bind".into()),
        signal: None,
        member: Some(MemberRef::of("linux.mounts", host_member)),
        location: None,
        verified: false,
        display: "/host (ext4)".into(),
    });
    r.egress_routes.push(Route {
        id: String::new(),
        kind: "metadata-endpoint".into(),
        rule: None,
        signal: Some("cloud.metadata-endpoint".into()),
        member: None,
        location: Some(b"/well-known/metadata".to_vec()),
        verified: false,
        display: "169.254.169.254".into(),
    });
    r.unknowns.push(Unknown {
        id: String::new(),
        source: "linux.listeners".into(),
        reason: UnknownReason::Unreadable,
    });
    r.tamper_indicators.push(TamperIndicator {
        id: String::new(),
        indicator: "loader-env".into(),
        strength: TamperStrength::Weak,
        display: "LD_PRELOAD present".into(),
    });
    r.not_observable.push(NotObservable {
        id: "netfilter-rules".into(),
        statement: "iptables and nftables rules of this and any outer network namespace".into(),
        reason: "no unprivileged read exists".into(),
    });
    r.signals.push(Signal {
        id: String::new(),
        signal: "linux.marker.dockerenv".into(),
        state: SignalState::Present,
    });
    r.active_checks.push(ActiveCheck {
        id: String::new(),
        target: "203.0.113.10:443".into(),
        result: "connected".into(),
    });
    r.completeness = CompletenessState::Incomplete;
    r
}

/// Serializes a report to a JSON value for assertions and schema checks.
pub fn to_value(report: &Report) -> serde_json::Value {
    serde_json::from_str(&egress_probe::json::to_json(report)).expect("report JSON parses")
}

const SCHEMA: &str = include_str!("../../../../schema/egress-probe.v1.json");

/// Validates a serialized probe report against `schema/egress-probe.v1.json`.
pub fn validate(json: &str) -> Result<(), String> {
    let instance: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    validate_value(&instance)
}

pub fn validate_value(instance: &serde_json::Value) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).map_err(|e| e.to_string())?;
    let url = "urn:egress-plane:egress-probe.v1.json";
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler
        .add_resource(url, schema)
        .map_err(|e| e.to_string())?;
    let idx = compiler
        .compile(url, &mut schemas)
        .map_err(|e| format!("{e:#}"))?;
    schemas
        .validate(instance, idx)
        .map_err(|e| format!("{e:#}"))
}

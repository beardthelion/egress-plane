//! Output contract tests for the probe report: determinism, identity,
//! escaping and control characters (KTD27), redaction (KTD14), the report
//! byte budget (KTD18), the text layout, and schema validation.

mod common;

use common::*;
use egress_core::model::CompletenessState;
use egress_probe::facts::Platform;
use egress_probe::json;
use egress_probe::model::*;
use egress_probe::text;
use serde_json::Value;

fn universe_members<'a>(v: &'a Value, id: &str) -> &'a [Value] {
    v["universes"]
        .as_array()
        .expect("universes array")
        .iter()
        .find(|u| u["id"] == id)
        .unwrap_or_else(|| panic!("universe {id} exists"))
        .get("members")
        .and_then(Value::as_array)
        .expect("members array")
}

fn universe_state<'a>(v: &'a Value, id: &str) -> &'a str {
    v["universes"]
        .as_array()
        .expect("universes array")
        .iter()
        .find(|u| u["id"] == id)
        .unwrap_or_else(|| panic!("universe {id} exists"))
        .get("state")
        .and_then(Value::as_str)
        .expect("state string")
}

// ---------------------------------------------------------------------------
// Determinism and identity
// ---------------------------------------------------------------------------

#[test]
fn the_same_report_finalized_twice_is_byte_identical() {
    let r = full_report();
    assert_eq!(json::to_json(&r), json::to_json(&r));
    assert_eq!(text::render(&r), text::render(&r));
}

#[test]
fn insertion_order_does_not_change_the_output() {
    let mut shuffled = full_report();
    shuffled.universes[0].members.reverse();
    shuffled.layers.reverse();
    shuffled.unknowns.reverse();
    shuffled.caveats.reverse();
    let mut r = full_report();
    assert_eq!(json::to_json(&r), json::to_json(&shuffled));
    // Universes render in declared order, so the shuffled member order
    // inside linux.mounts must still produce identical JSON.
    r.universes[0]
        .members
        .sort_by(|a, b| b.display.cmp(&a.display));
    assert_eq!(json::to_json(&r), json::to_json(&full_report()));
}

#[test]
fn display_only_fields_change_no_id() {
    // Two single-member reports whose members differ only in display-only
    // fields must produce the same member id (KTD5).
    let id_of = |port: u64| -> String {
        let r = report(vec![universe(
            "linux.listeners",
            UniverseState::Enumerated,
            vec![listener("127.0.0.1", port)],
        )]);
        to_value(&r)["universes"][0]["members"][0]["id"]
            .as_str()
            .expect("member id")
            .to_string()
    };
    assert_eq!(id_of(80), id_of(443));

    // Descriptor number, inode, device number, mount id, and pid are
    // display-only on their universes as well.
    let fd_id = |fd: u64, inode: u64| -> String {
        let m = member(
            vec![
                tfield("label", "inherited", true),
                tfield("target_kind", "socket", true),
                ifield("fd", fd),
                ifield("inode", inode),
            ],
            "fd socket",
            MemberClass::Unclassified,
            &[],
        );
        let r = report(vec![universe(
            "linux.fds",
            UniverseState::Enumerated,
            vec![m],
        )]);
        to_value(&r)["universes"][0]["members"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // Descriptor number and socket inode are both display-only.
    assert_eq!(fd_id(3, 77), fd_id(9, 77));
    assert_eq!(fd_id(3, 77), fd_id(3, 4001));

    let dev_id = |major: u64| -> String {
        let m = member(
            vec![
                tfield("path", "/dev/sda", true),
                tfield("node_type", "block", true),
                ifield("mode", 0o660),
                MemberField {
                    name: "device".into(),
                    value: MemberValue::Int(major),
                    identity: false,
                },
            ],
            "/dev/sda",
            MemberClass::Unclassified,
            &[],
        );
        let r = report(vec![universe(
            "linux.devices",
            UniverseState::Enumerated,
            vec![m],
        )]);
        to_value(&r)["universes"][0]["members"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(dev_id(8), dev_id(259));

    // A pid display field changes no id either.
    let pid_id = |pid: u64| -> String {
        let m = member(
            vec![tfield("kind", "process", true), ifield("pid", pid)],
            "process",
            MemberClass::Unclassified,
            &[],
        );
        let r = report(vec![universe(
            "linux.fds",
            UniverseState::Enumerated,
            vec![m],
        )]);
        to_value(&r)["universes"][0]["members"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(pid_id(1), pid_id(4242));

    // Mount ids are display-only on linux.mounts members.
    let mount_id = |id: u64| -> String {
        let mut m = mount(b"/x", "ext4", MemberClass::Unclassified, &[]);
        m.fields
            .iter_mut()
            .find(|f| f.name == "mount_id")
            .unwrap()
            .value = MemberValue::Int(id);
        let r = report(vec![universe(
            "linux.mounts",
            UniverseState::Enumerated,
            vec![m],
        )]);
        to_value(&r)["universes"][0]["members"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(mount_id(35), mount_id(900));

    // Namespace inodes are display-only on layer attributes.
    let layer_id = |inode: u64| -> String {
        let mut r = report(Vec::new());
        r.layers.push(Layer {
            id: String::new(),
            family: LayerFamily::Container,
            kind: "docker".into(),
            evidence: Vec::new(),
            attributes: [(
                "namespaces".to_string(),
                AttrValue::Namespaces(vec![NamespaceInode {
                    name: "pid".into(),
                    inode,
                }]),
            )]
            .into_iter()
            .collect(),
        });
        to_value(&r)["layers"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(layer_id(4026531836), layer_id(4026532001));
}

#[test]
fn identical_listeners_get_ordinals_in_port_order() {
    // Same identity (protocol + local address); ports 80 and 443 differ.
    // Sorted display order is numeric on the port field, so the port-80
    // listener takes ordinal 0 (KTD5).
    let r = report(vec![universe(
        "linux.listeners",
        UniverseState::Enumerated,
        vec![listener("0.0.0.0", 443), listener("0.0.0.0", 80)],
    )]);
    let v = to_value(&r);
    let members = universe_members(&v, "linux.listeners");
    assert_eq!(members.len(), 2);
    let by_port = |p: u64| {
        members
            .iter()
            .find(|m| m["port"] == p)
            .expect("member with port")
    };
    assert_eq!(by_port(80)["ordinal"], 0);
    assert_eq!(by_port(443)["ordinal"], 1);
    assert_ne!(by_port(80)["id"], by_port(443)["id"]);
}

// ---------------------------------------------------------------------------
// Control characters and non-UTF-8 (KTD27)
// ---------------------------------------------------------------------------

fn mount_with_hostile_point(point: &[u8]) -> Value {
    let r = report(vec![universe(
        "linux.mounts",
        UniverseState::Enumerated,
        vec![mount(point, "ext4", MemberClass::Unclassified, &[])],
    )]);
    to_value(&r)
}

#[test]
fn control_characters_emit_display_and_bytes_only() {
    for hostile in [
        b"/mnt/a\x1b[2J".to_vec(),
        "/mnt/\u{202e}txt".as_bytes().to_vec(),
        b"/mnt/\xc2\x9bx".to_vec(),          // U+009B (CSI)
        b"/mnt/\x1b]52;c;YQ==\x07".to_vec(), // OSC 52
        b"/mnt/x\ry".to_vec(),
        b"/mnt/x\x08y".to_vec(),
    ] {
        let v = mount_with_hostile_point(&hostile);
        let m = &universe_members(&v, "linux.mounts")[0];
        assert!(
            m.get("path").is_none(),
            "exact field must be omitted for {hostile:?}"
        );
        assert!(
            m["path_display"].is_string(),
            "escaped display for {hostile:?}"
        );
        assert!(m["path_bytes"].is_string(), "hex bytes for {hostile:?}");
        // No raw control or format character reaches the JSON document.
        let json = serde_json::to_string(&v).unwrap();
        for c in hostile.iter().copied().filter(|b| b.is_ascii_control()) {
            assert!(
                !json.as_bytes().contains(&c),
                "raw byte {c:#04x} in output for {hostile:?}"
            );
        }
        assert!(!json.contains('\u{202e}'));
        assert!(!json.contains('\u{9b}'));
        // The text report escapes as well.
        let r = report(vec![universe(
            "linux.mounts",
            UniverseState::Enumerated,
            vec![mount(&hostile, "ext4", MemberClass::Unclassified, &[])],
        )]);
        let t = text::render(&r);
        for c in hostile.iter().copied().filter(|b| b.is_ascii_control()) {
            assert!(!t.as_bytes().contains(&c), "raw byte {c:#04x} in text");
        }
        assert!(!t.contains('\u{202e}'));
    }
}

#[test]
fn a_non_utf8_mount_point_emits_display_and_bytes() {
    let v = mount_with_hostile_point(b"/mnt/\xff\xfe");
    let m = &universe_members(&v, "linux.mounts")[0];
    assert!(m.get("path").is_none());
    assert_eq!(m["path_bytes"], "2f6d6e742ffffe");
    assert_eq!(m["path_display"], "/mnt/\\x{ff}\\x{fe}");
}

// ---------------------------------------------------------------------------
// Redaction (KTD14)
// ---------------------------------------------------------------------------

#[test]
fn a_secret_shaped_env_name_is_redacted() {
    // Covers AE12.
    let m = member(
        vec![bfield("name", b"DEPLOY_ghp_abc123", true)],
        "DEPLOY_ghp_abc123",
        MemberClass::Unclassified,
        &[],
    );
    let r = report(vec![universe(
        "linux.env-names",
        UniverseState::Enumerated,
        vec![m],
    )]);
    let j = json::to_json(&r);
    let t = text::render(&r);
    assert!(j.contains("DEPLOY_<redacted>"));
    assert!(t.contains("DEPLOY_<redacted>"));
    assert!(!j.contains("ghp_abc123"));
    assert!(!t.contains("ghp_abc123"));
}

#[test]
fn sentinel_strings_are_redacted_everywhere() {
    let m1 = member(
        vec![
            tfield("path", "/data", true),
            tfield("fstype", "nfs", true),
            tfield("mount_root", "/", true),
            tfield("source", "https://u:sentinel@host/", false),
        ],
        "/data",
        MemberClass::Unclassified,
        &[],
    );
    let m2 = member(
        vec![
            tfield("path", "/more", true),
            tfield("fstype", "ext4", true),
            tfield("options", "rw,ghp_sentinel", false),
        ],
        "/more",
        MemberClass::Unclassified,
        &[],
    );
    let fd = member(
        vec![
            tfield("label", "inherited", true),
            tfield("target_kind", "path", true),
            bfield("target", b"/run/ghp_sentinel/x", true),
        ],
        "fd to /run/ghp_sentinel/x",
        MemberClass::Unclassified,
        &[],
    );
    let sock = member(
        vec![
            tfield("abstract_name", "@ghp_sentinel", true),
            tfield("socket_type", "stream", true),
        ],
        "@ghp_sentinel",
        MemberClass::Unclassified,
        &[],
    );
    let mut r = report(vec![
        universe("linux.mounts", UniverseState::Enumerated, vec![m1, m2]),
        universe("linux.fds", UniverseState::Enumerated, vec![fd]),
        universe("linux.unix-sockets", UniverseState::Enumerated, vec![sock]),
    ]);
    r.layers.push(Layer {
        id: String::new(),
        family: LayerFamily::Host,
        kind: "unrecognized".into(),
        evidence: Vec::new(),
        attributes: [(
            "cgroups".to_string(),
            AttrValue::Strings(vec!["1:name=ghp_sentinel".into()]),
        )]
        .into_iter()
        .collect(),
    });
    let j = json::to_json(&r);
    let t = text::render(&r);
    for needle in ["sentinel", "ghp_sentinel"] {
        assert!(!j.contains(needle), "JSON leaks {needle}");
        assert!(!t.contains(needle), "text leaks {needle}");
    }
    assert!(j.contains("<redacted>"));
    assert!(t.contains("<redacted>"));
}

// ---------------------------------------------------------------------------
// Header fields, nonce, caveats (KTD16, KTD23)
// ---------------------------------------------------------------------------

#[test]
fn layer_order_basis_is_family_rank() {
    let v = to_value(&report(Vec::new()));
    assert_eq!(v["layer_order_basis"], "family-rank");
    let t = text::render(&report(Vec::new()));
    assert!(t.contains("layer order basis: family-rank"));
}

#[test]
fn nonce_and_context_caveat_and_namespace_inodes() {
    // Covers AE18.
    let mut r = full_report();
    r.nonce = Some("5f3a".into());
    let v = to_value(&r);
    assert_eq!(v["nonce"], "5f3a");
    let caveats: Vec<&str> = v["caveats"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(caveats.contains(&"self-reported-context"));
    let namespaces = &v["layers"][0]["attributes"]["namespaces"];
    assert_eq!(namespaces[0]["name"], "mnt");
    assert_eq!(namespaces[0]["inode"], 4026531840_u64);
    let t = text::render(&r);
    assert!(t.contains("nonce: 5f3a"));
    assert!(t.contains("self-reported-context"));
    assert!(t.contains("mnt"));
}

// ---------------------------------------------------------------------------
// Report byte budget (KTD18)
// ---------------------------------------------------------------------------

#[test]
fn an_over_budget_universe_becomes_a_budget_unknown() {
    // One universe whose rendered members exceed the cap is replaced by an
    // unknown; later universes still render and output stays under the cap.
    let big: Vec<Member> = (0..40)
        .map(|i| {
            member(
                vec![
                    tfield("path", &format!("/big/{i:03}"), true),
                    tfield("fstype", "ext4", true),
                    tfield("mount_root", "/", true),
                ],
                &format!("/big/{i:03}"),
                MemberClass::Unclassified,
                &[],
            )
        })
        .collect();
    let small = || {
        universe(
            "linux.resolvers",
            UniverseState::Enumerated,
            vec![member(
                vec![
                    tfield("directive", "nameserver", true),
                    tfield("value", "127.0.0.11", true),
                ],
                "nameserver 127.0.0.11",
                MemberClass::Unclassified,
                &[],
            )],
        )
    };
    let r = report(vec![
        universe("linux.mounts", UniverseState::Enumerated, big),
        small(),
        universe(
            "linux.env-names",
            UniverseState::Enumerated,
            vec![member(
                vec![tfield("name", "PATH", true)],
                "PATH",
                MemberClass::Unclassified,
                &[],
            )],
        ),
    ]);
    // The unbounded render keeps every universe enumerated.
    let unbounded = to_value(&r);
    assert_eq!(universe_state(&unbounded, "linux.mounts"), "enumerated");
    assert_eq!(universe_members(&unbounded, "linux.mounts").len(), 40);

    // A cap that fits everything but the mounts members.
    let cap = 3000;
    let out = json::to_json_bounded(&r, cap);
    assert!(
        out.len() <= cap as usize,
        "output {} bytes over cap {cap}",
        out.len()
    );
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(universe_state(&v, "linux.mounts"), "unknown");
    assert_eq!(
        v["universes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == "linux.mounts")
            .unwrap()["reason"],
        "budget-exceeded"
    );
    assert_eq!(universe_members(&v, "linux.mounts").len(), 0);
    // Later universes still render.
    assert_eq!(universe_state(&v, "linux.resolvers"), "enumerated");
    assert_eq!(universe_members(&v, "linux.resolvers").len(), 1);
    assert_eq!(universe_members(&v, "linux.env-names").len(), 1);
    // The replacement is an unknown, and the run is incomplete.
    let unknowns: Vec<(&str, &str)> = v["unknowns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| (u["source"].as_str().unwrap(), u["reason"].as_str().unwrap()))
        .collect();
    assert!(unknowns.contains(&("linux.mounts", "budget-exceeded")));
    assert_eq!(v["completeness"]["state"], "incomplete");
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

#[test]
fn a_full_report_validates_against_the_schema() {
    let out = json::to_json(&full_report());
    validate(&out).expect("full report validates");
}

#[test]
fn removing_a_required_field_fails_schema_validation() {
    for field in [
        "not_observable",
        "source",
        "layer_order_basis",
        "tamper_indicators",
        "caveats",
    ] {
        let mut v = to_value(&full_report());
        v.as_object_mut().unwrap().remove(field);
        assert!(
            validate_value(&v).is_err(),
            "report without {field} must fail"
        );
    }
}

#[test]
fn a_verified_route_in_a_passive_report_fails_schema_validation() {
    let mut v = to_value(&full_report());
    v["egress_routes"][0]["verified"] = Value::Bool(true);
    assert!(validate_value(&v).is_err());

    // Active mode may carry verified routes.
    let mut r = full_report();
    r.mode = Mode::Active;
    r.egress_routes[0].verified = true;
    let mut v = to_value(&r);
    v["egress_routes"][0]["verified"] = Value::Bool(true);
    validate_value(&v).expect("active report with a verified route validates");
}

// ---------------------------------------------------------------------------
// Text layout
// ---------------------------------------------------------------------------

#[test]
fn no_text_line_outside_headings_starts_at_column_zero() {
    // A hostile member string cannot forge report structure: every
    // environment-derived string is escaped, so only section headings
    // start at column 0.
    let mut r = full_report();
    r.universes.push(universe(
        "linux.env-names",
        UniverseState::Enumerated,
        vec![member(
            vec![bfield("name", b"EVIL\nLayers (9)\npwned", true)],
            "EVIL\nLayers (9)\npwned",
            MemberClass::Unclassified,
            &[],
        )],
    ));
    let t = text::render(&r);
    let headings: Vec<&str> = t
        .lines()
        .filter(|l| !l.starts_with(' ') && !l.is_empty())
        .collect();
    for h in &headings {
        let is_heading = h.starts_with("egress-plane probe") || h.ends_with(')') || *h == "Inert";
        assert!(is_heading, "line at column 0 is not a heading: {h:?}");
    }
    assert!(!headings.iter().any(|h| h.contains("pwned")));
    // The escaped newline appears inside an indented member line.
    assert!(t.contains("EVIL\\u{a}"));
}

#[test]
fn text_sections_appear_in_the_declared_order() {
    let t = text::render(&full_report());
    let order = [
        "Layers",
        "Egress routes",
        "Escape routes",
        "Unknowns",
        "Tamper indicators",
        "Not observable",
        "Not applicable",
        "Unclassified",
        "Inert",
        "Active checks",
        "Caveats",
    ];
    let mut pos = 0;
    for section in order {
        let idx = t[pos..]
            .find(section)
            .unwrap_or_else(|| panic!("section {section} after offset {pos}"));
        pos += idx + section.len();
    }
}

#[test]
fn completeness_state_maps_to_the_exit_code() {
    let mut r = report(Vec::new());
    r.completeness = CompletenessState::Incomplete;
    assert_eq!(r.exit_code(), 2);
    r.completeness = CompletenessState::Empty;
    assert_eq!(r.exit_code(), 3);
}

#[test]
fn platform_and_source_appear_in_both_outputs() {
    let v = to_value(&full_report());
    assert_eq!(v["platform"], "linux");
    assert_eq!(v["source"], "snapshot");
    assert_eq!(v["kind"], "environment-probe");
    assert_eq!(v["mode"], "passive");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["privilege"]["euid"], 1000);
    assert_eq!(v["privilege"]["root"], false);
    let mut r = full_report();
    r.platform = Platform::Macos;
    assert_eq!(to_value(&r)["platform"], "macos");
}

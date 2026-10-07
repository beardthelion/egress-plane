//! Self-tests for the probe snapshot harness. Each error-path test drives a
//! synthetic report that must fail, so the comparison rules are load-bearing.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::model::{CompletenessState, ToolError};
use egress_corpus::probe::compare::{CaseContext, compare};
use egress_corpus::probe::labels::{Expected, parse_expected, parse_facts, parse_manifest};
use egress_corpus::probe::{ReadCall, ReadLogEntry, ScanOutput, discover_cases, run};
use egress_corpus::{Pending, load_pending, parse_pending};
use serde_json::json;

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/probe")
}

/// Builds the JSON a correct probe would emit for `expected` (U1 synthetic
/// shape; the real schema lands in U3, and the harness compares it as JSON).
fn json_from(expected: &Expected, platform: &str) -> String {
    // Members are grouped per universe, matching the emitted schema shape:
    // each member carries `id`, `class`, `rules`, and `display`.
    let mut universe_members: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut next_member = 0usize;
    let add_member = |universe: &str,
                      class: &str,
                      rules: Vec<String>,
                      display: &str,
                      members_out: &mut BTreeMap<String, Vec<serde_json::Value>>,
                      next: &mut usize| {
        let mid = format!("m{next}");
        *next += 1;
        members_out
            .entry(universe.to_string())
            .or_default()
            .push(json!({"id": mid, "class": class, "rules": rules, "display": display}));
        mid
    };
    let mut egress = Vec::new();
    let mut escape = Vec::new();
    for r in &expected.routes {
        let id = r
            .rule
            .clone()
            .or_else(|| r.signal.clone())
            .unwrap_or_default();
        let mut v = json!({
            "id": format!("route-{id}"),
            "kind": r.kind,
            "verified": false,
            "display": r.member.clone().unwrap_or_else(|| id.clone()),
        });
        if let Some(rule) = &r.rule {
            v["rule"] = rule.clone().into();
        }
        if let Some(signal) = &r.signal {
            v["signal"] = signal.clone().into();
        }
        if let Some(m) = &r.member {
            if r.rule.is_some() {
                let mid = add_member(
                    "synthetic",
                    &r.class,
                    vec![r.rule.clone().unwrap_or_default()],
                    m,
                    &mut universe_members,
                    &mut next_member,
                );
                v["member"] = mid.into();
            } else {
                v["location"] = m.clone().into();
            }
        }
        if r.class == "egress" {
            egress.push(v);
        } else {
            escape.push(v);
        }
    }
    let mut unclassified = Vec::new();
    for u in &expected.unclassified {
        let mid = add_member(
            &u.universe,
            "unclassified",
            vec![],
            &u.member,
            &mut universe_members,
            &mut next_member,
        );
        unclassified.push(json!({"universe": u.universe, "member": mid}));
    }
    for i in &expected.inert {
        add_member(
            &i.universe,
            "inert",
            vec![i.rule.clone()],
            &i.member,
            &mut universe_members,
            &mut next_member,
        );
    }
    let mut layers_sorted = expected.layers.clone();
    layers_sorted.sort_by_key(|l| l.order);
    let layers: Vec<serde_json::Value> = layers_sorted
        .iter()
        .map(|l| {
            let mut attrs = serde_json::Map::new();
            for a in &expected.attributes {
                if a.layer == l.kind {
                    attrs.insert(a.name.clone(), a.value.clone().into());
                }
            }
            let mut v = json!({"family": l.family, "kind": l.kind, "attributes": attrs});
            if let Some(c) = &l.evidence_classes {
                v["evidence_classes"] = c.clone().into();
            }
            v
        })
        .collect();
    let unknowns: Vec<serde_json::Value> = expected
        .unknowns
        .iter()
        .map(|u| json!({"id": "u", "source": u.source, "reason": u.reason}))
        .collect();
    let tamper: Vec<serde_json::Value> = expected
        .tamper
        .iter()
        .map(
            |t| json!({"id": "t", "indicator": t.indicator, "strength": t.strength, "display": ""}),
        )
        .collect();
    let report = json!({
        "schema_version": 1,
        "kind": "environment-probe",
        "tool": {"name": "egress-plane", "version": "0.1.0", "data_digest": "sha256:00"},
        "source": "snapshot",
        "platform": platform,
        "layer_order_basis": "family-rank",
        "privilege": {"euid": 0, "egid": 0, "root": true},
        "mode": "passive",
        "nonce": null,
        "completeness": {"state": expected.state.as_str()},
        "layers": layers,
        "egress_routes": egress,
        "escape_routes": escape,
        "unknowns": unknowns,
        "tamper_indicators": tamper,
        "not_observable": [],
        "not_applicable": expected.not_applicable.clone().unwrap_or_default(),
        "unclassified": unclassified,
        "universes": universe_members.iter().map(|(id, members)| json!({"id": id, "state": "enumerated", "members": members})).collect::<Vec<_>>(),
        "signals": [],
        "active_checks": [],
        "caveats": [{"id": "self-reported-context", "text": "self-reported"}],
    });
    serde_json::to_string_pretty(&report).unwrap()
}

fn output_from(expected: &Expected, platform: &str) -> ScanOutput {
    ScanOutput {
        json: json_from(expected, platform),
        text: "probe report\n".to_string(),
        read_log: vec![],
    }
}

fn ctx(platform: &str) -> CaseContext {
    CaseContext {
        platform: platform.to_string(),
        ..Default::default()
    }
}

fn ok(output: ScanOutput) -> Result<ScanOutput, ToolError> {
    Ok(output)
}

const BASIC: &str = r#"
state = "incomplete"
exit_code = 2
absent_text = ["hunter2"]
absent_routes = ["exposed-listener"]

[[layers]]
order = 1
family = "container"
kind = "docker"
evidence_classes = ["filesystem-marker", "kernel"]

[[routes]]
class = "escape"
kind = "runtime-socket"
rule = "linux.socket.runtime"
member = "/var/run/docker.sock"

[[routes]]
class = "egress"
kind = "dns-resolver"
rule = "resolver.nameserver"
member = "nameserver 10.0.0.2"

[[routes]]
class = "escape"
kind = "privileged-mode"
signal = "linux.privileged"

[[unknowns]]
source = "linux.listeners"
reason = "unreadable"

[[tamper]]
indicator = "loader-env"
strength = "weak"

[[unclassified]]
universe = "linux.env-names"
member = "WEIRD_NAME"

[[inert]]
universe = "linux.interfaces"
rule = "linux.iface.loopback"
member = "lo"

[[attributes]]
layer = "docker"
name = "proc-from-ancestor-pidns"
value = "true"
"#;

fn basic() -> Expected {
    parse_expected(BASIC, "linux/routes/basic").expect("basic label parses")
}

#[test]
fn happy_path_exact_match_passes() {
    let e = basic();
    let outcome = compare(&e, &ctx("linux"), &ok(output_from(&e, "linux")));
    assert!(outcome.passed(), "{:?}", outcome.failures);
}

#[test]
fn loader_reads_every_field() {
    let e = basic();
    assert_eq!(e.state, CompletenessState::Incomplete);
    assert_eq!(e.exit_code, 2);
    assert_eq!(e.layers.len(), 1);
    assert_eq!(e.routes.len(), 3);
    assert_eq!(e.unknowns.len(), 1);
    assert_eq!(e.tamper.len(), 1);
    assert_eq!(e.unclassified.len(), 1);
    assert_eq!(e.inert.len(), 1);
    assert_eq!(e.attributes.len(), 1);
    assert_eq!(e.absent_routes, vec!["exposed-listener".to_string()]);
    assert_eq!(e.absent_text, vec!["hunter2".to_string()]);
    assert_eq!(e.routes[0].rule.as_deref(), Some("linux.socket.runtime"));
    assert_eq!(e.routes[2].signal.as_deref(), Some("linux.privileged"));
}

#[test]
fn missing_route_fails_naming_the_route() {
    let e = basic();
    let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
    report["escape_routes"].as_array_mut().unwrap().remove(0);
    let output = ScanOutput {
        json: serde_json::to_string(&report).unwrap(),
        text: String::new(),
        read_log: vec![],
    };
    let outcome = compare(&e, &ctx("linux"), &ok(output));
    assert!(!outcome.passed());
    let msg = outcome.failures.join("\n");
    assert!(msg.contains("missing route"), "{msg}");
    assert!(msg.contains("runtime-socket"), "{msg}");
    assert!(msg.contains("/var/run/docker.sock"), "{msg}");
    assert!(msg.contains("linux.socket.runtime"), "{msg}");
}

#[test]
fn extra_route_layer_unknown_tamper_fails() {
    for key in ["escape_routes", "layers", "unknowns", "tamper_indicators"] {
        let e = basic();
        let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
        let extra = report[key].as_array().unwrap()[0].clone();
        report[key].as_array_mut().unwrap().push(extra);
        let output = ScanOutput {
            json: serde_json::to_string(&report).unwrap(),
            text: String::new(),
            read_log: vec![],
        };
        let outcome = compare(&e, &ctx("linux"), &ok(output));
        assert!(!outcome.passed(), "{key}: a duplicate entry must fail");
        let msg = outcome.failures.join("\n");
        assert!(msg.contains("unexpected"), "{key}: {msg}");
    }
}

#[test]
fn route_with_wrong_member_fails() {
    let e = basic();
    let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
    // Point the escape route at a member whose display differs.
    report["universes"][0]["members"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "mx", "display": "/other/path.sock"}));
    report["escape_routes"][0]["member"] = "mx".into();
    let output = ScanOutput {
        json: serde_json::to_string(&report).unwrap(),
        text: String::new(),
        read_log: vec![],
    };
    assert!(!compare(&e, &ctx("linux"), &ok(output)).passed());
}

fn members_of<'a>(
    report: &'a mut serde_json::Value,
    universe: &str,
) -> &'a mut Vec<serde_json::Value> {
    report["universes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|u| u["id"].as_str() == Some(universe))
        .unwrap_or_else(|| panic!("no universe {universe}"))
        .get_mut("members")
        .and_then(|m| m.as_array_mut())
        .unwrap()
}

#[test]
fn missing_unclassified_member_fails_but_extra_passes() {
    let e = basic();
    let missing = output_from(&e, "linux");
    let mut report: serde_json::Value = serde_json::from_str(&missing.json).unwrap();
    members_of(&mut report, "linux.env-names").clear();
    let outcome = compare(
        &e,
        &ctx("linux"),
        &ok(ScanOutput {
            json: serde_json::to_string(&report).unwrap(),
            text: String::new(),
            read_log: vec![],
        }),
    );
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("WEIRD_NAME"));

    // An extra unclassified member is tolerated (at-least check).
    let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
    report["unclassified"]
        .as_array_mut()
        .unwrap()
        .push(json!({"universe": "linux.env-names", "member": "ANOTHER"}));
    let outcome = compare(
        &e,
        &ctx("linux"),
        &ok(ScanOutput {
            json: serde_json::to_string(&report).unwrap(),
            text: String::new(),
            read_log: vec![],
        }),
    );
    assert!(outcome.passed(), "{:?}", outcome.failures);
}

#[test]
fn absent_text_in_text_but_not_json_fails() {
    let e = basic();
    let mut o = output_from(&e, "linux");
    o.text = "the report says hunter2\n".into();
    let outcome = compare(&e, &ctx("linux"), &ok(o));
    assert!(!outcome.passed());
    assert!(
        outcome
            .failures
            .join("\n")
            .contains("forbidden text \"hunter2\"")
            || outcome.failures.join("\n").contains("hunter2")
    );
}

#[test]
fn absent_text_inside_identity_hash_passes() {
    let e = parse_expected(
        "state = \"complete\"\nexit_code = 0\nabsent_text = [\"abc\"]\n",
        "linux/rules/x",
    )
    .unwrap();
    let mut o = output_from(&e, "linux");
    // `id` fields (identity hashes) and `*_bytes` hex fields are not text.
    let mut report: serde_json::Value = serde_json::from_str(&o.json).unwrap();
    report["universes"].as_array_mut().unwrap().push(json!({
        "id": "synthetic",
        "state": "enumerated",
        "members": [
            {"id": "00000abc00000000", "display": "fine"},
            {"id": "def", "display": "member", "path_bytes": "616263"},
        ],
    }));
    o.json = serde_json::to_string(&report).unwrap();
    let outcome = compare(&e, &ctx("linux"), &ok(o));
    assert!(outcome.passed(), "{:?}", outcome.failures);
}

#[test]
fn missing_inert_and_attribute_fail_naming_them() {
    let e = basic();
    // Drop the loopback inert member and the layer attribute.
    let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
    members_of(&mut report, "linux.interfaces").clear();
    report["layers"][0]["attributes"]
        .as_object_mut()
        .unwrap()
        .clear();
    let outcome = compare(
        &e,
        &ctx("linux"),
        &ok(ScanOutput {
            json: serde_json::to_string(&report).unwrap(),
            text: String::new(),
            read_log: vec![],
        }),
    );
    let msg = outcome.failures.join("\n");
    assert!(msg.contains("missing inert member"), "{msg}");
    assert!(msg.contains("proc-from-ancestor-pidns"), "{msg}");

    // An extra attribute is tolerated.
    let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
    report["layers"][0]["attributes"]
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), "1".into());
    let outcome = compare(
        &e,
        &ctx("linux"),
        &ok(ScanOutput {
            json: serde_json::to_string(&report).unwrap(),
            text: String::new(),
            read_log: vec![],
        }),
    );
    assert!(outcome.passed(), "{:?}", outcome.failures);
}

#[test]
fn absent_route_kind_must_not_appear() {
    let e = basic();
    let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
    report["egress_routes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind": "exposed-listener", "rule": "listener.exposed", "member": "x"}));
    let outcome = compare(
        &e,
        &ctx("linux"),
        &ok(ScanOutput {
            json: serde_json::to_string(&report).unwrap(),
            text: String::new(),
            read_log: vec![],
        }),
    );
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("exposed-listener"));
}

#[test]
fn state_mismatch_and_tool_error_fail() {
    let e = basic();
    let mut report: serde_json::Value = serde_json::from_str(&json_from(&e, "linux")).unwrap();
    report["completeness"]["state"] = "complete".into();
    let outcome = compare(
        &e,
        &ctx("linux"),
        &ok(ScanOutput {
            json: serde_json::to_string(&report).unwrap(),
            text: String::new(),
            read_log: vec![],
        }),
    );
    assert!(!outcome.passed());

    let outcome = compare(&e, &ctx("linux"), &Err(ToolError::Internal("boom")));
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("tool error"));
}

#[test]
fn unreadable_json_fails_the_case() {
    let outcome = compare(
        &basic(),
        &ctx("linux"),
        &ok(ScanOutput {
            json: "not json".into(),
            text: String::new(),
            read_log: vec![],
        }),
    );
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("does not parse"));
}

#[test]
fn content_read_under_credential_path_fails() {
    for path in [
        "var/run/secrets/kubernetes.io/serviceaccount/token",
        "run/secrets/db_password",
        "root/.aws/credentials",
        "root/.ssh/id_rsa",
        "home/u/.kube/config",
        "etc/shadow",
        "var/run/docker.sock",
    ] {
        let e = parse_expected("state = \"complete\"\nexit_code = 0\n", "linux/rules/x").unwrap();
        let outcome = compare(
            &e,
            &ctx("linux"),
            &ok(ScanOutput {
                json: json_from(&e, "linux"),
                text: String::new(),
                read_log: vec![ReadLogEntry {
                    kind: ReadCall::Read,
                    path: path.to_string(),
                }],
            }),
        );
        assert!(!outcome.passed(), "{path}: a content read must fail");
        assert!(
            outcome.failures.join("\n").contains("metadata-only"),
            "{path}: {:?}",
            outcome.failures
        );
    }
    // Metadata and listing calls on the same paths are fine.
    let e = parse_expected("state = \"complete\"\nexit_code = 0\n", "linux/rules/x").unwrap();
    let outcome = compare(
        &e,
        &ctx("linux"),
        &ok(ScanOutput {
            json: json_from(&e, "linux"),
            text: String::new(),
            read_log: vec![
                ReadLogEntry {
                    kind: ReadCall::Metadata,
                    path: "var/run/secrets/kubernetes.io/serviceaccount/token".into(),
                },
                ReadLogEntry {
                    kind: ReadCall::List,
                    path: "root/.ssh".into(),
                },
                ReadLogEntry {
                    kind: ReadCall::Access,
                    path: "root/.aws/credentials".into(),
                },
            ],
        }),
    );
    assert!(outcome.passed(), "{:?}", outcome.failures);
}

#[test]
fn call_under_no_touch_mount_fails() {
    let e = parse_expected("state = \"complete\"\nexit_code = 0\n", "linux/rules/x").unwrap();
    let context = CaseContext {
        platform: "linux".into(),
        mounts: vec![
            (vec![], "ext4".to_string()),
            (vec!["mnt".to_string()], "nfs4".to_string()),
            (
                vec!["mnt".to_string(), "local".to_string()],
                "ext4".to_string(),
            ),
        ],
        no_touch_overrides: vec![],
    };
    for kind in [
        ReadCall::Read,
        ReadCall::List,
        ReadCall::Metadata,
        ReadCall::Access,
    ] {
        let outcome = compare(
            &e,
            &context,
            &ok(ScanOutput {
                json: json_from(&e, "linux"),
                text: String::new(),
                read_log: vec![ReadLogEntry {
                    kind,
                    path: "mnt/data/file".into(),
                }],
            }),
        );
        assert!(!outcome.passed(), "{kind:?} under nfs4 must fail");
    }
    // Walking through a no-touch parent fails even when the final component
    // sits on a touchable sub-mount (the walk opens every component).
    let outcome = compare(
        &e,
        &context,
        &ok(ScanOutput {
            json: json_from(&e, "linux"),
            text: String::new(),
            read_log: vec![ReadLogEntry {
                kind: ReadCall::Metadata,
                path: "mnt/local/x".into(),
            }],
        }),
    );
    assert!(!outcome.passed(), "mnt is no-touch even below mnt/local");
}

#[test]
fn manifest_fs_override_fails_without_mountinfo() {
    let e = parse_expected("state = \"complete\"\nexit_code = 0\n", "linux/rules/x").unwrap();
    let context = CaseContext {
        platform: "linux".into(),
        mounts: vec![],
        no_touch_overrides: vec![vec!["run".to_string()]],
    };
    let outcome = compare(
        &e,
        &context,
        &ok(ScanOutput {
            json: json_from(&e, "linux"),
            text: String::new(),
            read_log: vec![ReadLogEntry {
                kind: ReadCall::List,
                path: "run".into(),
            }],
        }),
    );
    assert!(!outcome.passed());
}

#[test]
fn label_validation_rejects_bad_values() {
    for text in [
        "state = \"bogus\"\nexit_code = 0\n",
        "state = \"complete\"\nexit_code = 2\n",
        "state = \"complete\"\nexit_code = 0\nsurprise = 1\n",
        "state = \"complete\"\nexit_code = 0\n[[unknowns]]\nsource = \"x\"\nreason = \"weird\"\n",
        "state = \"complete\"\nexit_code = 0\n[[routes]]\nclass = \"sideways\"\nkind = \"k\"\nrule = \"r\"\n",
        "state = \"complete\"\nexit_code = 0\n[[routes]]\nclass = \"escape\"\nkind = \"k\"\n",
        "state = \"complete\"\nexit_code = 0\n[[routes]]\nclass = \"escape\"\nkind = \"k\"\nrule = \"r\"\nsignal = \"s\"\n",
        "state = \"complete\"\nexit_code = 0\n[[layers]]\norder = 1\nfamily = \"moon\"\nkind = \"k\"\n",
        "state = \"complete\"\nexit_code = 0\n[[tamper]]\nindicator = \"i\"\nstrength = \"medium\"\n",
        "not toml [",
    ] {
        let err = parse_expected(text, "linux/routes/the-case").unwrap_err();
        assert!(err.contains("linux/routes/the-case"), "{text:?} -> {err}");
    }
}

#[test]
fn facts_validation_rejects_malformed_tables() {
    let good_linux = r#"
platform = "linux"
[process]
state = "read"
pid = 4242
[env_names]
state = "read"
names = [{ name = "PATH" }, { no_separator = true }]
[fds]
state = "fs-type-mismatch"
[landlock_abi]
state = "disabled"
"#;
    let f = parse_facts(good_linux, "linux/rules/x").unwrap();
    assert_eq!(f.pid, 4242);

    for text in [
        // Missing process table.
        "platform = \"linux\"\n[env_names]\nstate = \"read\"\n[fds]\nstate = \"read\"\n[landlock_abi]\nstate = \"read\"\nversion = 1\n",
        // Missing a required fact (landlock_abi).
        "platform = \"linux\"\n[process]\nstate = \"read\"\npid = 1\n[env_names]\nstate = \"read\"\n[fds]\nstate = \"read\"\n",
        // Unknown top-level field.
        "platform = \"linux\"\nsurprise = 1\n[process]\nstate = \"read\"\npid = 1\n[env_names]\nstate = \"read\"\n[fds]\nstate = \"read\"\n[landlock_abi]\nstate = \"read\"\nversion = 1\n",
        // A macOS-only fact on a Linux case.
        "platform = \"linux\"\n[process]\nstate = \"read\"\npid = 1\n[env_names]\nstate = \"read\"\n[fds]\nstate = \"read\"\n[landlock_abi]\nstate = \"read\"\nversion = 1\n[mounts]\nstate = \"read\"\n",
        // Unknown field inside a fact table.
        "platform = \"linux\"\n[process]\nstate = \"read\"\npid = 1\nextra = 2\n[env_names]\nstate = \"read\"\n[fds]\nstate = \"read\"\n[landlock_abi]\nstate = \"read\"\nversion = 1\n",
        // An env entry that is neither name nor no_separator.
        "platform = \"linux\"\n[process]\nstate = \"read\"\npid = 1\n[env_names]\nstate = \"read\"\nnames = [{ other = \"x\" }]\n[fds]\nstate = \"read\"\n[landlock_abi]\nstate = \"read\"\nversion = 1\n",
        // Fact data carried by a non-read state.
        "platform = \"linux\"\n[process]\nstate = \"read\"\npid = 1\n[env_names]\nstate = \"unreadable\"\nnames = [{ name = \"PATH\" }]\n[fds]\nstate = \"read\"\n[landlock_abi]\nstate = \"read\"\nversion = 1\n",
        // An fds-only state on another fact.
        "platform = \"linux\"\n[process]\nstate = \"read\"\npid = 1\n[env_names]\nstate = \"fs-type-mismatch\"\n[fds]\nstate = \"read\"\n[landlock_abi]\nstate = \"read\"\nversion = 1\n",
        "platform = \"plan9\"\n[process]\nstate = \"read\"\npid = 1\n",
    ] {
        let err = parse_facts(text, "linux/completeness/x").unwrap_err();
        assert!(err.contains("linux/completeness/x"), "{text:?} -> {err}");
    }
}

#[test]
fn manifest_validation_rejects_bad_nodes() {
    let good = r#"
[[node]]
path = "run/docker.sock"
type = "socket"
access = "write"
[[node]]
path = "dev/kvm"
type = "char"
major = 10
minor = 232
[[node]]
path = "proc"
type = "meta"
fs = "tmpfs"
[[node]]
path = "proc/4242/net/tcp"
type = "error"
errno = "EMFILE"
"#;
    let m = parse_manifest(good, "linux/routes/x").unwrap();
    assert_eq!(m.nodes.len(), 4);

    for text in [
        "[[node]]\npath = \"x\"\ntype = \"symlink\"\n",
        "[[node]]\npath = \"/abs\"\ntype = \"socket\"\n",
        "[[node]]\npath = \"x\"\ntype = \"error\"\n",
        "[[node]]\npath = \"x\"\ntype = \"char\"\n",
        "[[node]]\npath = \"x\"\ntype = \"socket\"\nmajor = 1\n",
        "[[node]]\npath = \"x\"\ntype = \"socket\"\nerrno = \"EACCES\"\n",
        "[[node]]\npath = \"x\"\ntype = \"error\"\nerrno = \"EDQUOT\"\n",
        "[[node]]\npath = \"x\"\ntype = \"socket\"\naccess = \"maybe\"\n",
        "[[node]]\npath = \"a\"\ntype = \"meta\"\n[[node]]\npath = \"a\"\ntype = \"meta\"\n",
        "[[node]]\npath = \"x/../y\"\ntype = \"meta\"\n",
    ] {
        let err = parse_manifest(text, "linux/routes/x").unwrap_err();
        assert!(err.contains("linux/routes/x"), "{text:?} -> {err}");
    }
}

// Run-level tests over a temporary corpus.

static NEXT: AtomicUsize = AtomicUsize::new(0);

const LINUX_FACTS: &str = r#"
platform = "linux"
[process]
state = "read"
pid = 4242
[env_names]
state = "read"
names = [{ name = "PATH" }]
[fds]
state = "read"
entries = [{ fd = 0, target = "/dev/null" }]
[landlock_abi]
state = "not-built"
"#;

const COMPLETE_EMPTY: &str = "state = \"complete\"\nexit_code = 0\n";

fn temp_corpus(cases: &[&str]) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "probe-corpus-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    for id in cases {
        let dir = root.join(id);
        fs::create_dir_all(dir.join("tree")).unwrap();
        fs::write(dir.join("facts.toml"), LINUX_FACTS).unwrap();
        fs::write(dir.join("expected.toml"), COMPLETE_EMPTY).unwrap();
    }
    root
}

fn pending(ids: &[&str]) -> Pending {
    Pending {
        cases: ids.iter().map(|s| s.to_string()).collect(),
    }
}

/// A scan that reports exactly what each case's labels ask for.
fn perfect_scan(dir: &Path) -> Result<ScanOutput, ToolError> {
    let text = fs::read_to_string(dir.join("expected.toml")).unwrap();
    let expected = parse_expected(&text, "case").unwrap();
    let platform = dir
        .parent()
        .and_then(Path::parent)
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("linux")
        .to_string();
    Ok(output_from(&expected, &platform))
}

fn stub(_: &Path) -> Result<ScanOutput, ToolError> {
    Err(ToolError::Internal("snapshot probing is not implemented"))
}

#[test]
fn run_passes_when_every_case_passes() {
    let root = temp_corpus(&["linux/routes/a", "macos/layers/b"]);
    fs::write(root.join("macos/layers/b/facts.toml"), MACOS_FACTS).unwrap();
    let s = run(&root, &pending(&[]), perfect_scan);
    assert!(s.passed(), "{:?}", s.errors);
    assert_eq!(s.cases.len(), 2);
}

#[test]
fn failing_non_pending_case_fails_run() {
    let root = temp_corpus(&["linux/routes/a"]);
    let s = run(&root, &pending(&[]), stub);
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("linux/routes/a"));
}

#[test]
fn pending_case_that_passes_fails_run_with_removal_message() {
    let root = temp_corpus(&["linux/routes/a"]);
    let s = run(&root, &pending(&["linux/routes/a"]), perfect_scan);
    assert!(!s.passed());
    let msg = s.errors.join("\n");
    assert!(msg.contains("linux/routes/a"), "{msg}");
    assert!(msg.contains("remove it from pending.toml"), "{msg}");
}

#[test]
fn pending_entry_naming_a_missing_case_fails() {
    let root = temp_corpus(&["linux/routes/a"]);
    let s = run(
        &root,
        &pending(&["linux/routes/a", "linux/routes/gone"]),
        stub,
    );
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("linux/routes/gone"));
}

#[test]
fn malformed_facts_toml_is_a_harness_error_not_a_case_failure() {
    let root = temp_corpus(&["linux/completeness/bad"]);
    fs::write(
        root.join("linux/completeness/bad/facts.toml"),
        "platform = \"linux\"\nsurprise = 1\n",
    )
    .unwrap();
    let s = run(&root, &pending(&["linux/completeness/bad"]), stub);
    assert!(!s.passed());
    let msg = s.errors.join("\n");
    assert!(msg.contains("linux/completeness/bad"), "{msg}");
    assert!(msg.contains("facts.toml"), "{msg}");
    assert!(s.cases.is_empty(), "a malformed case is not a case result");
}

#[test]
fn manifest_node_also_in_tree_is_a_harness_error() {
    let root = temp_corpus(&["linux/rules/dup"]);
    let dir = root.join("linux/rules/dup");
    fs::write(dir.join("tree/run.sock"), "x").unwrap();
    fs::write(
        dir.join("manifest.toml"),
        "[[node]]\npath = \"run.sock\"\ntype = \"socket\"\n",
    )
    .unwrap();
    let s = run(&root, &pending(&["linux/rules/dup"]), stub);
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("linux/rules/dup"));

    // The same shape is required in reverse for meta nodes.
    let root = temp_corpus(&["linux/rules/ghost"]);
    fs::write(
        root.join("linux/rules/ghost/manifest.toml"),
        "[[node]]\npath = \"missing\"\ntype = \"meta\"\n",
    )
    .unwrap();
    let s = run(&root, &pending(&["linux/rules/ghost"]), stub);
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("linux/rules/ghost"));
}

#[test]
fn must_not_case_without_absent_labels_is_a_harness_error() {
    let root = temp_corpus(&["linux/routes/must-not-x"]);
    let s = run(&root, &pending(&["linux/routes/must-not-x"]), stub);
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("absent"));
}

#[test]
fn run_level_read_log_assertions_hold() {
    // A case whose mountinfo places /home on nfs4: any call under it fails.
    let root = temp_corpus(&["linux/routes/nfs"]);
    let dir = root.join("linux/routes/nfs");
    fs::create_dir_all(dir.join("tree/proc/self")).unwrap();
    fs::write(
        dir.join("tree/proc/self/mountinfo"),
        "30 22 0:30 / /home rw,relatime - nfs4 server:/home rw\n",
    )
    .unwrap();
    let s = run(&root, &pending(&[]), |_| {
        Ok(ScanOutput {
            json: json_from(&parse_expected(COMPLETE_EMPTY, "x").unwrap(), "linux"),
            text: String::new(),
            read_log: vec![ReadLogEntry {
                kind: ReadCall::Metadata,
                path: "home/u/.aws/credentials".into(),
            }],
        })
    });
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("no-touch"), "{:?}", s.errors);

    // Manifest fs override flags calls even when mountinfo is unreadable.
    let root = temp_corpus(&["linux/completeness/override"]);
    let dir = root.join("linux/completeness/override");
    fs::create_dir_all(dir.join("tree/proc/self")).unwrap();
    fs::create_dir_all(dir.join("tree/run")).unwrap();
    fs::write(
        dir.join("tree/proc/self/mountinfo"),
        "30 22 0:30 / /run rw - tmpfs tmpfs rw\n",
    )
    .unwrap();
    fs::write(
        dir.join("manifest.toml"),
        "[[node]]\npath = \"proc/self/mountinfo\"\ntype = \"error\"\nerrno = \"EACCES\"\n\n[[node]]\npath = \"run\"\ntype = \"meta\"\nfs = \"fuse.sshfs\"\n",
    )
    .unwrap();
    let s = run(&root, &pending(&[]), |_| {
        Ok(ScanOutput {
            json: json_from(&parse_expected(COMPLETE_EMPTY, "x").unwrap(), "linux"),
            text: String::new(),
            read_log: vec![ReadLogEntry {
                kind: ReadCall::List,
                path: "run".into(),
            }],
        })
    });
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("no-touch"), "{:?}", s.errors);
}

#[test]
fn pending_ledger_rejects_duplicates_and_unknown_keys() {
    assert!(parse_pending("cases = [\"a/b/c\", \"a/b/c\"]\n", "p").is_err());
    assert!(parse_pending("cases = []\nextra = 1\n", "p").is_err());
}

// Integration with the real corpus and the stub snapshot entry point. The
// real gate runs in `probe_corpus.rs`; these tests pin the harness behavior
// itself against the authored cases.

const MACOS_FACTS: &str = r#"
platform = "macos"
[process]
state = "read"
pid = 900
[env_names]
state = "read"
names = [{ name = "PATH" }]
[fds]
state = "read"
entries = [{ fd = 0, target = "/dev/null" }]
[mounts]
state = "read"
entries = [{ path = "/", fstype = "apfs" }]
[unix_sockets]
state = "read"
[listeners]
state = "read"
[routes]
state = "read"
[interfaces]
state = "read"
entries = [{ name = "lo0" }]
[sandbox_check]
state = "read"
result = 0
[hv_vmm_present]
state = "read"
present = true
[identity]
state = "read"
euid = 501
egid = 20
[traced]
state = "read"
traced = false
"#;

/// A ledger naming every case in the real corpus.
fn all_pending() -> Pending {
    let cases = discover_cases(&corpus_root()).expect("corpus discovers");
    Pending {
        cases: cases.into_iter().map(|c| c.id).collect(),
    }
}

#[test]
fn real_ledger_loads_and_names_only_existing_cases() {
    let all = all_pending();
    assert!(!all.cases.is_empty());
    let real = load_pending(&corpus_root().join("pending.toml")).expect("pending.toml loads");
    assert_eq!(real.cases, all.cases, "pending.toml must name every case");
}

#[test]
fn real_corpus_loads_and_every_case_fails_against_the_stub() {
    let cases = discover_cases(&corpus_root()).expect("corpus discovers");
    assert!(cases.len() >= 60, "corpus has {} cases", cases.len());
    let s = run(&corpus_root(), &all_pending(), stub);
    assert!(s.passed(), "{:#?}", s.errors);
    for c in &s.cases {
        assert!(!c.outcome.passed(), "{} passed against the stub", c.id);
        assert!(
            c.outcome.failures.join("\n").contains("tool error"),
            "{}: {:?}",
            c.id,
            c.outcome.failures
        );
    }
}

#[test]
fn removing_any_one_case_from_the_ledger_turns_the_run_red() {
    let full = all_pending();
    let mut by_case = BTreeMap::new();
    for id in &full.cases {
        let mut p = full.clone();
        p.cases.remove(id);
        let s = run(&corpus_root(), &p, stub);
        by_case.insert(id.clone(), s);
    }
    for (id, s) in &by_case {
        assert!(!s.passed(), "{id} passed while out of the ledger");
        assert!(s.errors.join("\n").contains(id.as_str()), "{id}");
    }
}

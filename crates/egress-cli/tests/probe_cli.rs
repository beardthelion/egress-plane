//! End-to-end tests of `egress-plane probe`: schema-valid JSON, exit
//! codes, usage errors, the nonce and caveats, environment names without
//! values, and the active-mode limits and outcomes.

mod support;

use std::ffi::OsStr;
use std::ffi::OsString;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use support::{Temp, run, run_with};

fn probe(args: &[&str]) -> support::Run {
    let mut full: Vec<OsString> = vec!["probe".into()];
    full.extend(args.iter().map(OsString::from));
    let refs: Vec<&OsStr> = full.iter().map(OsString::as_os_str).collect();
    run(&refs)
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).expect("stdout is one JSON document")
}

const SCHEMA: &str = include_str!("../../../schema/egress-probe.v1.json");

fn validate(instance: &serde_json::Value) -> Result<(), String> {
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

#[test]
fn probe_json_validates_against_the_schema() {
    let r = probe(&["--format", "json"]);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    assert!(r.stderr.is_empty(), "{}", r.stderr);
    let v = json(&r.stdout);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "environment-probe");
    assert_eq!(v["source"], "live");
    assert_eq!(v["mode"], "passive");
    assert_eq!(v["nonce"], serde_json::Value::Null);
    assert_eq!(v["active_checks"], serde_json::json!([]));
    validate(&v).expect("probe JSON validates against the schema");
    let expected = match v["completeness"]["state"].as_str().unwrap() {
        "complete" => 0,
        "incomplete" => 2,
        "empty" => 3,
        other => panic!("unknown state {other}"),
    };
    assert_eq!(r.code, expected);
}

#[test]
fn probe_text_report_runs() {
    let r = probe(&[]);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    assert!(r.stdout.starts_with("egress-plane probe"), "{}", r.stdout);
}

#[test]
fn probe_spawns_no_tool() {
    let t = Temp::new("probe-traps");
    let bin = t.path("bin");
    let marks = t.path("marks");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&marks).unwrap();
    for name in ["cargo", "rustc", "node", "python", "python3", "tsc", "git"] {
        let p = bin.join(name);
        std::fs::write(
            &p,
            format!("#!/bin/sh\necho ran > '{}'\n", marks.join(name).display()),
        )
        .unwrap();
        support::chmod(&p, 0o755);
        assert_ne!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o111,
            0
        );
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_egress-plane"));
    cmd.args(["probe"]).env("PATH", &bin);
    let out = run_with(&mut cmd);
    assert!(matches!(out.code, 0 | 2 | 3), "{}", out.stderr);
    let left: Vec<_> = std::fs::read_dir(&marks).unwrap().flatten().collect();
    assert!(left.is_empty(), "a trap binary ran: {left:?}");
}

#[test]
fn probe_emits_env_names_never_values() {
    const NAME: &str = "EGRESS_PROBE_SENTINEL_7F3A";
    const VALUE: &str = "s3cr3t-probe-sentinel-7f3a";
    for format in ["text", "json"] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_egress-plane"));
        cmd.args(["probe", "--format", format]).env(NAME, VALUE);
        let out = run_with(&mut cmd);
        assert!(matches!(out.code, 0 | 2 | 3), "{format}: {}", out.stderr);
        assert!(out.stdout.contains(NAME), "{format}: name not reported");
        assert!(
            !out.stdout.contains(VALUE),
            "{format}: stdout holds the value"
        );
        assert!(
            !out.stderr.contains(VALUE),
            "{format}: stderr holds the value"
        );
    }
}

#[test]
fn probe_nonce_reaches_the_report_with_the_self_reported_caveat() {
    // Covers AE18: the nonce is echoed and every report carries
    // `self-reported-context`.
    let r = probe(&["--nonce", "5f3a", "--format", "json"]);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    let v = json(&r.stdout);
    assert_eq!(v["nonce"], "5f3a");
    assert!(
        v["caveats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "self-reported-context"),
        "no self-reported-context caveat"
    );
    let text = probe(&["--nonce", "5f3a"]);
    assert!(text.stdout.contains("nonce: 5f3a"), "{}", text.stdout);

    let long = "a".repeat(65);
    for bad in ["XYZ", long.as_str(), "", "5F3A"] {
        let r = probe(&["--nonce", bad]);
        assert_eq!(r.code, 1, "{bad}");
        assert!(r.stdout.is_empty(), "{bad}: stdout {:?}", r.stdout);
        assert!(r.stderr.contains("usage"), "{bad}: {:?}", r.stderr);
    }
}

#[test]
fn probe_usage_errors_are_tool_errors_with_nothing_on_stdout() {
    let cases: Vec<Vec<String>> = vec![
        vec!["--allow".into(), "127.0.0.1:1".into()],
        vec!["--active".into()],
        vec![
            "--active".into(),
            "--allow".into(),
            "api.example.com:443".into(),
        ],
        vec!["--active".into(), "--allow".into(), "127.0.0.1:0".into()],
        vec![
            "--active".into(),
            "--allow".into(),
            "127.0.0.1:1".into(),
            "--allow".into(),
            "127.0.0.1:1".into(),
        ],
        vec!["somepath".into()],
        vec!["--bogus".into()],
        vec!["--format".into(), "yaml".into()],
        vec!["--nonce".into()],
        vec!["--allow".into()],
    ];
    for args in cases {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = probe(&refs);
        assert_eq!(r.code, 1, "{args:?}");
        assert!(r.stdout.is_empty(), "{args:?}: {:?}", r.stdout);
        assert!(r.stderr.contains("usage"), "{args:?}: {:?}", r.stderr);
    }
    // 17 allow entries overflow the active-targets budget.
    let mut many: Vec<String> = vec!["--active".into()];
    for p in 1..=17 {
        many.push("--allow".into());
        many.push(format!("127.0.0.1:{p}"));
    }
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let r = probe(&refs);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains("usage"), "{}", r.stderr);
    // 16 is within the budget (a refused run, not a usage error).
    let mut fine: Vec<String> = vec!["--active".into()];
    for p in 1..=16 {
        fine.push("--allow".into());
        fine.push(format!("169.254.169.254:{p}"));
    }
    fine.push("--format".into());
    fine.push("json".into());
    let refs: Vec<&str> = fine.iter().map(String::as_str).collect();
    let r = probe(&refs);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    let v = json(&r.stdout);
    assert_eq!(v["active_checks"].as_array().unwrap().len(), 16);
    assert!(
        v["active_checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["result"] == "refused-metadata-address")
    );
}

#[test]
fn probe_active_refuses_metadata_forms_without_a_socket() {
    // Covers AE11: every mapped form of a metadata address records
    // `refused-metadata-address` and creates no connection.
    let r = probe(&[
        "--active",
        "--allow",
        "169.254.169.254:80",
        "--allow",
        "[::ffff:169.254.169.254]:81",
        "--allow",
        "[::a9fe:a9fe]:82",
        "--allow",
        "[64:ff9b::a9fe:a9fe]:83",
        "--allow",
        "[::ffff:168.63.129.16]:84",
        "--allow",
        "[64:ff9b::6464:64c8]:85",
        "--allow",
        "[fd00:ec2::254]:86",
        "--allow",
        "[fd00:ec2::23]:87",
        "--allow",
        "[fd20:ce::254]:88",
        "--allow",
        "[fd00:c1::a9fe:a9fe]:89",
        "--allow",
        "[2001:0:a9fe:a9fe::]:90",
        "--allow",
        "[2002:a9fe:a9fe::]:91",
        "--allow",
        "[fd00::a9fe:a9fe]:92",
        "--format",
        "json",
    ]);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    let v = json(&r.stdout);
    assert_eq!(v["mode"], "active");
    let checks = v["active_checks"].as_array().unwrap();
    assert_eq!(checks.len(), 13, "{checks:?}");
    assert!(
        checks
            .iter()
            .all(|c| c["result"] == "refused-metadata-address"),
        "{checks:?}"
    );
    // The canonicalized target is recorded, not the raw literal.
    assert!(checks.iter().any(|c| c["target"] == "169.254.169.254:81"));
}

#[test]
fn probe_active_refuses_special_addresses() {
    let r = probe(&[
        "--active",
        "--allow",
        "0.0.0.0:80",
        "--allow",
        "[::]:81",
        "--allow",
        "255.255.255.255:82",
        "--allow",
        "224.0.0.1:83",
        "--allow",
        "[ff02::1]:84",
        "--format",
        "json",
    ]);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    let v = json(&r.stdout);
    let checks = v["active_checks"].as_array().unwrap();
    assert_eq!(checks.len(), 5, "{checks:?}");
    assert!(
        checks
            .iter()
            .all(|c| c["result"] == "refused-special-address"),
        "{checks:?}"
    );
}

#[test]
fn probe_active_connects_only_to_listed_targets() {
    // Covers AE6: a listening loopback port records `connected`, a
    // closed one `refused`, and nothing else is attempted.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap().port();
    let r = probe(&[
        "--active",
        "--allow",
        &format!("127.0.0.1:{open}"),
        "--format",
        "json",
    ]);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    let v = json(&r.stdout);
    let checks = v["active_checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1, "{checks:?}");
    assert_eq!(checks[0]["target"], format!("127.0.0.1:{open}"));
    assert_eq!(checks[0]["result"], "connected");

    // A port nothing listens on records `refused`.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let r = probe(&[
        "--active",
        "--allow",
        &format!("127.0.0.1:{closed}"),
        "--format",
        "json",
    ]);
    assert!(matches!(r.code, 0 | 2 | 3), "{}: {}", r.code, r.stderr);
    let v = json(&r.stdout);
    let checks = v["active_checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1, "{checks:?}");
    assert_eq!(checks[0]["result"], "refused");
}

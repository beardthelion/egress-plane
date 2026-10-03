//! End-to-end tests of `egress-plane scan`: exit codes (R17, KTD13), the text
//! report (R9), JSON on stdout, tool errors on stderr only, caveats (R23),
//! redaction (R21), and the no-subprocess, no-host-environment rule (KTD1,
//! KTD7).

mod support;

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use support::{Temp, case, corpus, run, run_with, scan, scan_default};

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).expect("stdout is one JSON document")
}

/// Runs both formats and checks that they agree on the exit code and that
/// the JSON state matches it.
fn both(root: &Path, code: i32, state: &str) -> (String, String) {
    let text = scan(root, "text");
    let j = scan(root, "json");
    assert_eq!(text.code, code, "text exit code; stderr: {}", text.stderr);
    assert_eq!(j.code, code, "json exit code; stderr: {}", j.stderr);
    assert!(text.stderr.is_empty(), "stderr: {}", text.stderr);
    assert!(j.stderr.is_empty(), "stderr: {}", j.stderr);
    let v = json(&j.stdout);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["completeness"]["state"], state);
    assert!(
        text.stdout
            .lines()
            .any(|l| l == format!("State: {state} (exit code {code})")),
        "text header names the state:\n{}",
        text.stdout
    );
    (text.stdout, j.stdout)
}

fn section<'a>(text: &'a str, heading: &str) -> Vec<&'a str> {
    let mut lines = text.lines().skip_while(|l| !l.starts_with(heading));
    assert!(lines.next().is_some(), "no section {heading}:\n{text}");
    lines.take_while(|l| !l.is_empty()).collect()
}

#[test]
fn text_is_the_default_format() {
    let root = case("mixed/ordinary/three-languages");
    let d = scan_default(&root);
    let t = scan(&root, "text");
    assert_eq!(d.code, 0);
    assert_eq!(d.stdout, t.stdout);
    assert!(d.stdout.starts_with("egress-plane "));
}

#[test]
fn covers_ae8_python2_file_is_a_parse_error_gap() {
    let (text, _) = both(
        &case("python/completeness/ae8-python2-print-parse-error"),
        2,
        "incomplete",
    );
    let spots = section(&text, "Blind spots");
    let i = spots
        .iter()
        .position(|l| *l == "  parse-error (coverage gap)")
        .unwrap_or_else(|| panic!("no parse-error group:\n{text}"));
    assert!(spots[i + 1].trim_start().starts_with("legacy.py"), "{text}");
}

#[test]
fn covers_ae9_go_only_is_empty_and_no_egress_python_is_complete() {
    let (text, j) = both(&case("mixed/completeness/ae9-go-only-empty"), 3, "empty");
    let v = json(&j);
    for lang in ["python", "javascript", "rust"] {
        assert_eq!(v["completeness"]["coverage"][lang]["scanned"], 0);
    }
    assert!(text.contains("Coverage: python 0 scanned"), "{text}");
    both(
        &case("python/completeness/ae9-no-egress-complete"),
        0,
        "complete",
    );
}

#[test]
fn covers_ae17_path_outside_root_is_a_gap_and_never_printed() {
    let (text, j) = both(
        &case("rust/completeness/ae17-path-attribute-absolute"),
        2,
        "incomplete",
    );
    assert!(text.contains("reference-outside-root"), "{text}");
    assert!(!text.contains("/opt/payload") && !j.contains("/opt/payload"));
}

#[test]
fn covers_ae19_planted_pyvenv_is_incomplete_and_real_venv_is_complete() {
    let (text, _) = both(
        &case("python/completeness/ae19-unconfirmed-venv"),
        2,
        "incomplete",
    );
    assert!(
        text.contains("  unconfirmed-exclusion (coverage gap)"),
        "{text}"
    );
    assert!(
        section(&text, "Excluded")
            .iter()
            .any(|l| l.contains("src/lib")),
        "{text}"
    );
    let (text, _) = both(
        &case("python/completeness/confirmed-venv-excluded"),
        0,
        "complete",
    );
    assert!(
        section(&text, "Excluded")
            .iter()
            .any(|l| l.contains(".venv") && l.contains("install-output")),
        "{text}"
    );
}

const DOM: &str = "Browser DOM-mediated requests are not covered";

#[test]
fn covers_ae25_js_tree_carries_the_browser_dom_caveat_and_python_does_not() {
    let (text, j) = both(
        &case("javascript/completeness/ae25-js-only-caveat"),
        0,
        "complete",
    );
    assert!(section(&text, "Caveats").iter().any(|l| l.contains(DOM)));
    assert_eq!(json(&j)["caveats"][0]["id"], "browser-dom");

    let (text, j) = both(
        &case("python/completeness/ae25-python-only-no-caveat"),
        0,
        "complete",
    );
    assert!(!text.contains(DOM), "{text}");
    assert_eq!(json(&j)["caveats"], serde_json::json!([]));
}

#[test]
fn must_not_caveat_changes_no_exit_code() {
    // A JS tree with a parse error is incomplete and still carries the caveat.
    let (text, _) = both(
        &case("javascript/completeness/parse-error"),
        2,
        "incomplete",
    );
    assert!(text.contains(DOM), "{text}");
}

#[test]
fn manifest_parse_failure_exits_2_never_1() {
    for c in [
        "python/completeness/pyproject-parse-error",
        "javascript/completeness/package-json-parse-error",
        "rust/completeness/cargo-toml-parse-error",
    ] {
        let (text, _) = both(&case(c), 2, "incomplete");
        assert!(
            text.contains("manifest-parse-error (coverage gap)"),
            "{c}:\n{text}"
        );
    }
}

#[test]
fn nonexistent_root_is_a_tool_error_on_stderr_only() {
    let t = Temp::new("missing");
    let missing = t.path("does-not-exist");
    for format in ["text", "json"] {
        let r = scan(&missing, format);
        assert_eq!(r.code, 1, "{format}");
        assert!(r.stdout.is_empty(), "{format}: stdout {:?}", r.stdout);
        assert!(r.stderr.contains("scan root not found"), "{:?}", r.stderr);
    }
    t.file("plain.py", "x = 1\n");
    let r = scan(&t.path("plain.py"), "json");
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(!r.stderr.is_empty());
}

#[test]
fn usage_errors_are_tool_errors_with_nothing_on_stdout() {
    let root = case("mixed/ordinary/three-languages");
    let r = root.as_os_str();
    let cases: Vec<Vec<&OsStr>> = vec![
        vec![],
        vec![OsStr::new("scan")],
        vec![OsStr::new("frobnicate"), r],
        vec![
            OsStr::new("scan"),
            r,
            OsStr::new("--format"),
            OsStr::new("yaml"),
        ],
        vec![OsStr::new("scan"), r, OsStr::new("--format")],
        vec![OsStr::new("scan"), r, OsStr::new("extra")],
        vec![OsStr::new("scan"), r, OsStr::new("--bogus")],
    ];
    for args in cases {
        let out = run(&args);
        assert_eq!(out.code, 1, "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: {:?}", out.stdout);
        assert!(out.stderr.contains("usage"), "{args:?}: {:?}", out.stderr);
    }
    // `--format=json` is accepted, as is the option before the root.
    let a = run(&[OsStr::new("scan"), OsStr::new("--format=json"), r]);
    let b = scan(&root, "json");
    assert_eq!(a.code, 0, "{}", a.stderr);
    assert_eq!(a.stdout, b.stdout);
}

#[test]
fn text_groups_sites_by_destination_and_lists_dependencies_once() {
    let (text, _) = both(
        &case("mixed/ordinary/shared-env-destination"),
        0,
        "complete",
    );
    let sites = section(&text, "Egress sites");
    let headings: Vec<_> = sites
        .iter()
        .filter(|l| l.starts_with("  ") && !l.starts_with("    "))
        .collect();
    assert_eq!(headings, vec![&"  env:WEBHOOK_URL"], "{text}");
    let members: Vec<_> = sites.iter().filter(|l| l.starts_with("    ")).collect();
    assert_eq!(members.len(), 2, "{text}");
    assert!(members.iter().any(|l| l.contains("hooks/notify.py")));
    assert!(members.iter().any(|l| l.contains("web/src/notify.js")));

    let deps = section(&text, "Unscanned dependencies");
    assert_eq!(deps.len(), 2, "{text}");
    assert_eq!(deps.iter().filter(|l| l.contains(" yaml")).count(), 1);
    assert_eq!(deps.iter().filter(|l| l.contains(" lodash")).count(), 1);
    assert!(
        deps.iter()
            .any(|l| l.contains("hooks/config.py") && l.contains("hooks/notify.py")),
        "{text}"
    );
}

/// Every corpus case that lists `absent_text` (redaction, out-of-root paths)
/// keeps those strings out of both the text report and the JSON (R21, AE14).
#[test]
fn covers_ae14_absent_text_never_appears_in_either_format() {
    let mut checked = 0;
    for lang in ["python", "javascript", "rust", "mixed"] {
        let Ok(cats) = std::fs::read_dir(corpus().join(lang)) else {
            continue;
        };
        for cat in cats.flatten() {
            for c in std::fs::read_dir(cat.path()).unwrap().flatten() {
                let expected: toml::Table = std::fs::read_to_string(c.path().join("expected.toml"))
                    .unwrap()
                    .parse()
                    .unwrap();
                let Some(v) = expected.get("absent_text") else {
                    continue;
                };
                let root = c.path().join("tree");
                let text = scan(&root, "text").stdout;
                let j = scan(&root, "json").stdout;
                for s in v.as_array().unwrap() {
                    let s = s.as_str().unwrap();
                    assert!(
                        !text.contains(s),
                        "{}: text holds {s:?}",
                        c.path().display()
                    );
                    assert!(!j.contains(s), "{}: JSON holds {s:?}", c.path().display());
                }
                checked += 1;
            }
        }
    }
    assert!(checked >= 10, "only {checked} cases list absent_text");
    let text = scan(&case("python/tricky/ae14-redaction-userinfo-query"), "text").stdout;
    assert!(
        text.contains("https://<redacted>@api.example.com/x?token=<redacted>&page=2"),
        "{text}"
    );
}

const TRAPS: [&str; 7] = ["cargo", "rustc", "node", "python", "python3", "tsc", "git"];
const SENTINELS: [(&str, &str); 3] = [
    ("CARGO_MANIFEST_DIR", "sentinel-manifest-dir-7c41"),
    ("OUT_DIR", "sentinel-out-dir-7c41"),
    ("WEBHOOK_URL", "sentinel-webhook-7c41"),
];

/// KTD1, KTD7: the binary spawns no subprocess and never reads a host
/// environment value into its output.
#[test]
fn must_not_spawn_tools_or_read_host_environment() {
    let t = Temp::new("traps");
    let bin = t.path("bin");
    let marks = t.path("marks");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&marks).unwrap();
    for name in TRAPS {
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
    // The traps themselves work: running one leaves a marker.
    Command::new(bin.join("git")).status().unwrap();
    assert!(marks.join("git").exists());
    std::fs::remove_file(marks.join("git")).unwrap();

    let root = corpus().join("mixed");
    for format in ["text", "json"] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_egress-plane"));
        cmd.args([OsStr::new("scan"), root.as_os_str()])
            .args(["--format", format])
            .env("PATH", &bin);
        for (k, v) in SENTINELS {
            cmd.env(k, v);
        }
        let out = run_with(&mut cmd);
        assert!(matches!(out.code, 0 | 2), "{format}: {}", out.stderr);
        assert!(
            out.stdout.contains("WEBHOOK_URL"),
            "the env name is reported"
        );
        for (_, v) in SENTINELS {
            assert!(!out.stdout.contains(v), "{format}: stdout holds {v}");
            assert!(!out.stderr.contains(v), "{format}: stderr holds {v}");
        }
    }
    let left: Vec<_> = std::fs::read_dir(&marks).unwrap().flatten().collect();
    assert!(left.is_empty(), "a trap binary ran: {left:?}");
}

/// KTD13: parser messages never reach output, so a failing token's text does
/// not either.
#[test]
fn must_not_parse_error_text_reaches_output() {
    let t = Temp::new("parse-sentinel");
    t.file("a.py", "def f(:\n    sentinelpy91 ===== sentinelpy91\n")
        .file("b.js", "function (( sentineljs91 }}} sentineljs91 <<<\n")
        .file("c.rs", "fn main() { let sentinelrs91 = = ; }\n");
    let (text, j) = both(&t.base, 2, "incomplete");
    for s in ["sentinelpy91", "sentineljs91", "sentinelrs91"] {
        assert!(!text.contains(s), "text holds {s}:\n{text}");
        assert!(!j.contains(s), "JSON holds {s}");
    }
    assert_eq!(
        section(&text, "Blind spots")
            .iter()
            .filter(|l| l.starts_with("    "))
            .count(),
        3,
        "{text}"
    );
}

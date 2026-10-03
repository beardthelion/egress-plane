//! Self-tests for the corpus harness. Each error-path test drives a
//! synthetic report that must fail, so the comparison rules are load-bearing.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::model::{
    BlindSpot, Bucket, Caveat, Completeness, CompletenessState, Coverage, Destination,
    DestinationKind, Excluded, Language, Location, Report, RuntimeRange, SCHEMA_VERSION, Site,
    Tool, ToolError, UnscannedDependency,
};
use egress_corpus::compare::compare;
use egress_corpus::labels::{Expected, load_expected, parse_expected};
use egress_corpus::{Pending, discover_cases, load_pending, parse_pending, run_corpus};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus")
}

fn language_of(mechanism: &str) -> Language {
    Language::parse(mechanism.split(':').next().unwrap()).unwrap()
}

/// Builds the report a perfect scanner would produce for `expected`.
fn report_from(expected: &Expected) -> Report {
    let sites = expected
        .sites
        .iter()
        .enumerate()
        .map(|(i, s)| Site {
            id: format!("{i:016x}"),
            language: language_of(&s.mechanism),
            file: s.file.clone(),
            file_bytes: None,
            symbol: s.symbol.clone(),
            bucket: Bucket::Primitive,
            mechanism: s.mechanism.clone(),
            destination: Destination {
                kind: DestinationKind::Expr,
                value: s.destination.clone(),
                default: None,
                display: s.destination.clone(),
            },
            ordinal: 0,
            labels: s.labels.clone().unwrap_or_default(),
            location: Some(Location {
                line: 7 + i as u32,
                column: 1,
            }),
        })
        .collect();
    let blind_spots = expected
        .blind_spots
        .iter()
        .enumerate()
        .map(|(i, b)| BlindSpot {
            id: format!("{:016x}", 1000 + i),
            language: None,
            file: b.file.clone(),
            file_bytes: None,
            symbol: b.symbol.clone(),
            kind: b.kind,
            whole_file: b.kind.is_whole_file(),
            coverage_gap: b.kind.is_whole_file(),
            construct: String::new(),
            ordinal: 0,
            labels: vec![],
            location: None,
        })
        .collect();
    let unscanned_dependencies = expected
        .unscanned_dependencies
        .iter()
        .map(|d| UnscannedDependency {
            id: "0".repeat(16),
            language: d.language,
            package: d.package.clone(),
            files: vec![],
        })
        .collect();
    let excluded = expected
        .excluded
        .iter()
        .map(|e| Excluded {
            path: e.path.clone(),
            path_bytes: None,
            reason: e.reason,
        })
        .collect();
    let caveats = expected
        .caveats
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|id| Caveat {
            id,
            text: String::from("caveat text"),
        })
        .collect();
    Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "egress-plane".into(),
            version: "0.1.0".into(),
            data_digest: "sha256:00".into(),
            runtime_range: RuntimeRange {
                python: "3.8 to 3.13".into(),
                node: "18 to 22".into(),
                rust: "1.97.1".into(),
            },
        },
        completeness: Completeness {
            state: expected.state,
            budget_exceeded: vec![],
            coverage: Coverage::default(),
        },
        caveats,
        sites,
        blind_spots,
        unscanned_dependencies,
        excluded,
    }
}

const BASIC: &str = r#"
state = "incomplete"
exit_code = 2
caveats = []
absent_text = ["hunter2"]

[[sites]]
file = "src/notify.py"
symbol = "send"
mechanism = "python:requests.post"
destination = "env:WEBHOOK_URL"

[[sites]]
file = "vendor/client.py"
symbol = "<module>"
mechanism = "python:socket.create_connection"
destination = "db.internal:5432"
labels = ["vendored"]

[[blind_spots]]
file = "src/dyn.py"
symbol = "load"
kind = "dynamic-import"

[[blind_spots]]
file = "legacy/old.py"
symbol = "<module>"
kind = "parse-error"

[[unscanned_dependencies]]
language = "python"
package = "leftpad"

[[excluded]]
path = ".venv"
reason = "install-output"
"#;

fn basic() -> Expected {
    parse_expected(BASIC, "inline/basic").expect("basic label parses")
}

fn ok(report: Report) -> Result<Report, ToolError> {
    Ok(report)
}

#[test]
fn happy_path_exact_match_passes() {
    let e = basic();
    let outcome = compare(&e, &ok(report_from(&e)));
    assert!(outcome.passed(), "{:?}", outcome.failures);
    assert!(outcome.false_positives.is_empty());
}

#[test]
fn loader_reads_every_field() {
    let e = basic();
    assert_eq!(e.state, CompletenessState::Incomplete);
    assert_eq!(e.exit_code, 2);
    assert_eq!(e.sites.len(), 2);
    assert_eq!(e.blind_spots.len(), 2);
    assert_eq!(e.unscanned_dependencies.len(), 1);
    assert_eq!(e.excluded.len(), 1);
    assert_eq!(e.caveats, Some(vec![]));
    assert_eq!(e.absent_text, vec!["hunter2".to_string()]);
    assert_eq!(
        e.sites[1].labels.as_deref(),
        Some(&[egress_core::model::Label::Vendored][..])
    );
    assert_eq!(e.sites[0].labels, None);
}

#[test]
fn missing_site_fails_and_names_it() {
    let e = basic();
    let mut r = report_from(&e);
    r.sites.remove(0);
    let outcome = compare(&e, &ok(r));
    assert!(!outcome.passed());
    let msg = outcome.failures.join("\n");
    assert!(msg.contains("missing site"), "{msg}");
    assert!(msg.contains("python:requests.post"), "{msg}");
    assert!(msg.contains("env:WEBHOOK_URL"), "{msg}");
    assert!(msg.contains("src/notify.py"), "{msg}");
}

#[test]
fn site_with_wrong_destination_fails() {
    let e = basic();
    let mut r = report_from(&e);
    r.sites[0].destination.display = "env:OTHER".into();
    let outcome = compare(&e, &ok(r));
    assert!(!outcome.passed());
    assert_eq!(outcome.false_positives.len(), 1, "the wrong site is extra");
}

#[test]
fn site_with_wrong_labels_fails_when_labels_are_given() {
    let e = basic();
    let mut r = report_from(&e);
    r.sites[1].labels = vec![];
    assert!(!compare(&e, &ok(r)).passed());
}

#[test]
fn labels_are_ignored_when_not_given() {
    let e = basic();
    let mut r = report_from(&e);
    r.sites[0].labels = vec![egress_core::model::Label::Test];
    assert!(compare(&e, &ok(r)).passed());
}

#[test]
fn missing_blind_spot_in_evasive_case_fails() {
    let e = parse_expected(
        r#"
state = "complete"
exit_code = 0
[[blind_spots]]
file = "src/a.py"
symbol = "run"
kind = "dynamic-code"
"#,
        "python/evasive/x",
    )
    .unwrap();
    let mut r = report_from(&e);
    r.blind_spots.clear();
    let outcome = compare(&e, &ok(r));
    assert!(!outcome.passed());
    let msg = outcome.failures.join("\n");
    assert!(msg.contains("missing blind spot"), "{msg}");
    assert!(msg.contains("dynamic-code"), "{msg}");
}

#[test]
fn missing_blind_spot_in_closure_case_fails() {
    let e = parse_expected(
        r#"
state = "complete"
exit_code = 0
[[blind_spots]]
file = "src/a.py"
symbol = "go"
kind = "reflective-unknown"
"#,
        "python/closure/x",
    )
    .unwrap();
    let mut r = report_from(&e);
    r.blind_spots.clear();
    let outcome = compare(&e, &ok(r));
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("reflective-unknown"));
}

#[test]
fn blind_spot_with_wrong_kind_fails() {
    let e = basic();
    let mut r = report_from(&e);
    r.blind_spots[0].kind = egress_core::model::BlindSpotKind::DynamicCode;
    assert!(!compare(&e, &ok(r)).passed());
}

#[test]
fn state_mismatch_fails() {
    let e = basic();
    let mut r = report_from(&e);
    r.completeness.state = CompletenessState::Complete;
    let outcome = compare(&e, &ok(r));
    assert!(!outcome.passed());
    let msg = outcome.failures.join("\n");
    assert!(msg.contains("state"), "{msg}");
    assert!(msg.contains("exit code"), "{msg}");
}

#[test]
fn tool_error_fails_case() {
    let e = basic();
    let outcome = compare(&e, &Err(ToolError::Internal("boom")));
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("tool error"));
}

#[test]
fn exit_code_inconsistent_with_state_is_malformed() {
    let err = parse_expected("state = \"complete\"\nexit_code = 2\n", "case/x").unwrap_err();
    assert!(err.contains("case/x"), "{err}");
    assert!(err.contains("exit_code"), "{err}");
}

#[test]
fn missing_unscanned_dependency_fails() {
    let e = basic();
    let mut r = report_from(&e);
    r.unscanned_dependencies.clear();
    let outcome = compare(&e, &ok(r));
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("leftpad"));
}

#[test]
fn missing_excluded_entry_fails() {
    let e = basic();
    let mut r = report_from(&e);
    r.excluded.clear();
    assert!(!compare(&e, &ok(r)).passed());
}

#[test]
fn caveat_set_mismatch_fails() {
    let e = basic();
    let mut r = report_from(&e);
    r.caveats.push(Caveat {
        id: "browser-dom".into(),
        text: "t".into(),
    });
    assert!(!compare(&e, &ok(r)).passed());

    let js = parse_expected(
        "state = \"complete\"\nexit_code = 0\ncaveats = [\"browser-dom\"]\n",
        "js",
    )
    .unwrap();
    let mut r = report_from(&js);
    r.caveats.clear();
    assert!(!compare(&js, &ok(r)).passed());
}

#[test]
fn absent_text_found_in_output_fails() {
    let e = basic();
    let mut r = report_from(&e);
    r.blind_spots[0].construct = "exec('pw=hunter2')".into();
    let outcome = compare(&e, &ok(r));
    assert!(!outcome.passed());
    assert!(outcome.failures.join("\n").contains("hunter2"));
}

#[test]
fn absent_text_ignores_identity_hashes() {
    let e = parse_expected(
        "state = \"complete\"\nexit_code = 0\nabsent_text = [\"abc\"]\n",
        "x",
    )
    .unwrap();
    let mut r = report_from(&e);
    r.sites.push(Site {
        id: "00000abc00000000".into(),
        language: Language::Python,
        file: "a.py".into(),
        file_bytes: None,
        symbol: "<module>".into(),
        bucket: Bucket::Primitive,
        mechanism: "python:os.system".into(),
        destination: Destination {
            kind: DestinationKind::Expr,
            value: "x".into(),
            default: None,
            display: "expr:x".into(),
        },
        ordinal: 0,
        labels: vec![],
        location: None,
    });
    assert!(compare(&e, &ok(r)).passed());
}

#[test]
fn extra_site_passes_and_counts_false_positive() {
    let e = basic();
    let mut r = report_from(&e);
    let mut extra = r.sites[0].clone();
    extra.symbol = "other".into();
    r.sites.push(extra);
    let mut extra_bs = r.blind_spots[0].clone();
    extra_bs.symbol = "elsewhere".into();
    r.blind_spots.push(extra_bs);
    let outcome = compare(&e, &ok(r));
    assert!(outcome.passed(), "{:?}", outcome.failures);
    assert_eq!(outcome.false_positives.len(), 2);
}

#[test]
fn duplicate_labels_need_duplicate_sites() {
    let e = parse_expected(
        r#"
state = "complete"
exit_code = 0
[[sites]]
file = "a.py"
symbol = "f"
mechanism = "python:os.system"
destination = "param:1:f"
[[sites]]
file = "a.py"
symbol = "f"
mechanism = "python:os.system"
destination = "param:1:f"
"#,
        "dup",
    )
    .unwrap();
    let mut r = report_from(&e);
    assert!(compare(&e, &ok(r.clone())).passed());
    r.sites.pop();
    assert!(!compare(&e, &ok(r)).passed());
}

#[test]
fn matching_ignores_location() {
    let e = basic();
    let mut r = report_from(&e);
    for (i, s) in r.sites.iter_mut().enumerate() {
        s.location = Some(Location {
            line: 900 + i as u32,
            column: 42,
        });
    }
    r.blind_spots[0].location = Some(Location { line: 3, column: 9 });
    assert!(compare(&e, &ok(r)).passed());
}

#[test]
fn malformed_labels_are_rejected_with_origin() {
    let cases = [
        "state = \"complete\"\n",
        "state = \"bogus\"\nexit_code = 0\n",
        "state = \"complete\"\nexit_code = 0\nsurprise = 1\n",
        "state = \"complete\"\nexit_code = 0\n[[blind_spots]]\nfile = \"a\"\nsymbol = \"b\"\nkind = \"not-a-kind\"\n",
        "state = \"complete\"\nexit_code = 0\n[[sites]]\nfile = \"a\"\nsymbol = \"b\"\nmechanism = \"requests.post\"\ndestination = \"x\"\n",
        "state = \"complete\"\nexit_code = 0\n[[sites]]\nfile = \"/abs.py\"\nsymbol = \"b\"\nmechanism = \"python:x\"\ndestination = \"x\"\n",
        "state = \"complete\"\nexit_code = 0\n[[sites]]\nfile = \"a.py\"\nsymbol = \"b\"\nmechanism = \"python:x\"\ndestination = \"x\"\nlabels = [\"shiny\"]\n",
        "state = \"complete\"\nexit_code = 0\n[[unscanned_dependencies]]\nlanguage = \"go\"\npackage = \"x\"\n",
        "not toml at all [",
    ];
    for text in cases {
        let err = parse_expected(text, "lang/cat/the-case").unwrap_err();
        assert!(err.contains("lang/cat/the-case"), "{text:?} -> {err}");
    }
}

// Run-level tests over a temporary corpus.

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn temp_corpus(cases: &[(&str, &str)]) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "corpus-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    for (id, expected) in cases {
        let dir = root.join(id);
        fs::create_dir_all(dir.join("tree")).unwrap();
        fs::write(dir.join("tree/main.py"), "x = 1\n").unwrap();
        fs::write(dir.join("expected.toml"), expected).unwrap();
    }
    root
}

const COMPLETE_EMPTY: &str = "state = \"complete\"\nexit_code = 0\n";

fn pending(ids: &[&str]) -> Pending {
    Pending {
        cases: ids.iter().map(|s| s.to_string()).collect(),
    }
}

/// A scanner that reports exactly what each case expects.
fn perfect_scan(root: &Path) -> Result<Report, ToolError> {
    let expected = load_expected(&root.parent().unwrap().join("expected.toml")).unwrap();
    Ok(report_from(&expected))
}

#[test]
fn run_passes_when_every_case_passes() {
    let root = temp_corpus(&[
        ("python/ordinary/a", COMPLETE_EMPTY),
        ("rust/evasive/b", COMPLETE_EMPTY),
    ]);
    let s = run_corpus(&root, &pending(&[]), perfect_scan);
    assert!(s.passed(), "{:?}", s.errors);
    assert_eq!(s.cases.len(), 2);
}

#[test]
fn failing_non_pending_case_fails_run() {
    let root = temp_corpus(&[("python/ordinary/a", COMPLETE_EMPTY)]);
    let s = run_corpus(&root, &pending(&[]), |_| Err(ToolError::Internal("stub")));
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("python/ordinary/a"));
}

#[test]
fn failing_pending_case_does_not_fail_run() {
    let root = temp_corpus(&[("python/ordinary/a", COMPLETE_EMPTY)]);
    let s = run_corpus(&root, &pending(&["python/ordinary/a"]), |_| {
        Err(ToolError::Internal("stub"))
    });
    assert!(s.passed(), "{:?}", s.errors);
}

#[test]
fn pending_case_that_passes_fails_run_with_removal_message() {
    let root = temp_corpus(&[("python/ordinary/a", COMPLETE_EMPTY)]);
    let s = run_corpus(&root, &pending(&["python/ordinary/a"]), perfect_scan);
    assert!(!s.passed());
    let msg = s.errors.join("\n");
    assert!(msg.contains("python/ordinary/a"), "{msg}");
    assert!(msg.contains("remove it from pending.toml"), "{msg}");
}

#[test]
fn stale_pending_entry_fails_run() {
    let root = temp_corpus(&[("python/ordinary/a", COMPLETE_EMPTY)]);
    let s = run_corpus(
        &root,
        &pending(&["python/ordinary/a", "python/ordinary/gone"]),
        |_| Err(ToolError::Internal("stub")),
    );
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("python/ordinary/gone"));
}

#[test]
fn malformed_expected_fails_run_with_case_path() {
    let root = temp_corpus(&[
        ("python/ordinary/good", COMPLETE_EMPTY),
        ("python/tricky/bad", "state = \"complete\"\n"),
    ]);
    let s = run_corpus(&root, &pending(&[]), perfect_scan);
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("python/tricky/bad"));
}

#[test]
fn unknown_language_or_category_fails_run() {
    for (id, named) in [("go/ordinary/a", "go:"), ("python/misc/a", "python/misc:")] {
        let root = temp_corpus(&[(id, COMPLETE_EMPTY)]);
        let s = run_corpus(&root, &pending(&[]), perfect_scan);
        assert!(!s.passed(), "{id}");
        assert!(s.errors.join("\n").contains(named), "{id}: {:?}", s.errors);
    }
}

#[test]
fn case_without_tree_fails_run() {
    let root = temp_corpus(&[("python/ordinary/a", COMPLETE_EMPTY)]);
    fs::remove_dir_all(root.join("python/ordinary/a/tree")).unwrap();
    let s = run_corpus(&root, &pending(&[]), perfect_scan);
    assert!(!s.passed());
    assert!(s.errors.join("\n").contains("tree"));
}

#[test]
fn false_positives_are_summed_across_cases() {
    let root = temp_corpus(&[("python/ordinary/a", COMPLETE_EMPTY)]);
    let s = run_corpus(&root, &pending(&[]), |tree| {
        let mut r = perfect_scan(tree)?;
        let other = report_from(&basic());
        r.sites = other.sites;
        Ok(r)
    });
    assert!(s.passed(), "{:?}", s.errors);
    assert_eq!(s.false_positive_count(), 2);
}

#[test]
fn pending_ledger_rejects_duplicates_and_unknown_keys() {
    assert!(parse_pending("cases = [\"a/b/c\", \"a/b/c\"]\n", "p").is_err());
    assert!(parse_pending("cases = []\nextra = 1\n", "p").is_err());
    let p = parse_pending("cases = [\"a/b/c\"]\n", "p").unwrap();
    assert!(p.cases.contains("a/b/c"));
}

// Integration with the real corpus and a tool-error stub. The real scanner
// runs against the real ledger in `tests/corpus.rs`; these tests pin the
// harness behavior itself, so they keep a stub as the scan and a ledger
// that lists every case.

fn stub(_: &Path) -> Result<Report, ToolError> {
    Err(ToolError::Internal("stub scan"))
}

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
    let real = load_pending(&corpus_root().join("pending.toml")).expect("pending.toml loads");
    for id in &real.cases {
        assert!(all.cases.contains(id), "{id} is not a corpus case");
    }
}

#[test]
fn real_corpus_loads_and_every_case_fails_against_the_stub() {
    let cases = discover_cases(&corpus_root()).expect("corpus discovers");
    assert!(cases.len() > 100, "corpus has {} cases", cases.len());
    for c in &cases {
        load_expected(&c.dir.join("expected.toml")).unwrap();
    }
    let s = run_corpus(&corpus_root(), &all_pending(), stub);
    assert!(s.passed(), "{:#?}", s.errors);
}

#[test]
fn removing_any_one_case_from_the_ledger_turns_the_run_red() {
    let full = all_pending();
    assert!(
        full.cases.len() > 100,
        "ledger has {} cases",
        full.cases.len()
    );
    let mut by_case = BTreeMap::new();
    for id in &full.cases {
        let mut p = full.clone();
        p.cases.remove(id);
        let s = run_corpus(&corpus_root(), &p, stub);
        by_case.insert(id.clone(), s);
    }
    for (id, s) in &by_case {
        assert!(!s.passed(), "{id} passed while out of the ledger");
        assert!(s.errors.join("\n").contains(id.as_str()), "{id}");
    }
}

#[test]
fn ae9_go_only_case_fails_against_the_stub() {
    let id = "mixed/completeness/ae9-go-only-empty";
    let e = load_expected(&corpus_root().join(id).join("expected.toml")).unwrap();
    assert_eq!(e.state, CompletenessState::Empty);
    assert_eq!(e.exit_code, 3);
    let mut p = all_pending();
    assert!(p.cases.remove(id), "{id} is a corpus case");
    let s = run_corpus(&corpus_root(), &p, stub);
    assert!(!s.passed());
    let msg = s.errors.join("\n");
    assert!(msg.contains(id) && msg.contains("tool error"), "{msg}");
}

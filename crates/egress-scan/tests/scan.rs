//! Scan wiring (U3): discovery, pre-scan, frontend registry, per-file fault
//! isolation, worker stacks, the in-flight byte cap, completeness, caveats,
//! and budgets.

#[path = "../../egress-core/tests/support/mod.rs"]
mod support;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use egress_core::discover::{Budgets, Config};
use egress_core::ir::FileIr;
use egress_core::json::to_json;
use egress_core::model::*;
use egress_scan::{Frontend, FrontendError, Registry, ScanOptions, SourceInput, scan, scan_with};
use support::Tree;

fn kinds(r: &Report) -> Vec<(String, BlindSpotKind)> {
    let mut v: Vec<_> = r
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind))
        .collect();
    v.sort();
    v
}

/// A frontend that records every file it lowers and fails on request.
#[derive(Default)]
struct Recorder {
    lang: Option<Language>,
    seen: Mutex<Vec<String>>,
}

impl Frontend for Recorder {
    fn language(&self) -> Language {
        self.lang.unwrap_or(Language::Python)
    }

    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        self.seen.lock().unwrap().push(input.file.to_string());
        if input.text.contains("PANIC") {
            panic!("frontend bug with {}", input.text);
        }
        if input.text.contains("SYNTAX") {
            return Err(FrontendError::Parse);
        }
        Ok(FileIr::new(input.language))
    }
}

struct Shared(Arc<Recorder>);

impl Frontend for Shared {
    fn language(&self) -> Language {
        self.0.language()
    }
    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        self.0.lower(input)
    }
}

fn with_recorder(lang: Language) -> (ScanOptions, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        lang: Some(lang),
        ..Recorder::default()
    });
    let mut registry = Registry::new();
    registry.register(Shared(Arc::clone(&rec)));
    (
        ScanOptions {
            registry,
            ..ScanOptions::default()
        },
        rec,
    )
}

fn budgets(files: u64, bytes: u64, findings: u64) -> Config {
    Config {
        budgets: Budgets::parse(&format!(
            "files = {files}\nbytes = {bytes}\nfindings = {findings}\nresolver_steps = 1000\n"
        ))
        .unwrap(),
        ..Config::default()
    }
}

#[test]
fn covers_ae10_notebook_makes_the_scan_incomplete() {
    let t = Tree::new("ae10");
    t.file("app.py", "x = 1\n").file("analysis.ipynb", "{}");
    let r = scan(&t.root).unwrap();
    assert_eq!(r.completeness.state, CompletenessState::Incomplete);
    assert_eq!(r.exit_code(), 2);
    assert_eq!(r.completeness.coverage.python.scanned, 1);
    assert_eq!(r.completeness.coverage.unsupported.skipped, 1);
    assert_eq!(
        kinds(&r),
        vec![("analysis.ipynb".into(), BlindSpotKind::UnsupportedFileType)]
    );
}

#[test]
fn covers_ae9_go_only_is_empty_and_inert_python_complete() {
    let t = Tree::new("ae9-go");
    t.file("main.go", "package main\n");
    let r = scan(&t.root).unwrap();
    assert_eq!(r.completeness.state, CompletenessState::Empty);
    assert_eq!(r.exit_code(), 3);
    assert_eq!(r.completeness.coverage, Coverage::default());

    let t = Tree::new("ae9-py");
    t.file("calc.py", "def add(a, b):\n    return a + b\n");
    let r = scan(&t.root).unwrap();
    assert_eq!(r.completeness.state, CompletenessState::Complete);
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.completeness.coverage.python.scanned, 1);
}

#[test]
fn notebooks_only_is_empty_with_the_blind_spot_listed() {
    let t = Tree::new("only-ipynb");
    t.file("a.ipynb", "{}");
    let r = scan(&t.root).unwrap();
    assert_eq!(r.completeness.state, CompletenessState::Empty);
    assert_eq!(
        kinds(&r),
        vec![("a.ipynb".into(), BlindSpotKind::UnsupportedFileType)]
    );
}

#[test]
fn covers_ae25_caveat_follows_javascript_and_keeps_the_state() {
    let t = Tree::new("ae25-js");
    t.file("index.js", "export const a = 1;\n");
    let r = scan(&t.root).unwrap();
    let ids: Vec<_> = r.caveats.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, vec!["browser-dom"]);
    assert_eq!(r.completeness.state, CompletenessState::Complete);
    assert_eq!(r.exit_code(), 0);

    let t = Tree::new("ae25-py");
    t.file("app.py", "x = 1\n");
    assert!(scan(&t.root).unwrap().caveats.is_empty());
}

#[test]
fn tool_metadata_comes_from_the_embedded_data() {
    let t = Tree::new("tool");
    t.file("app.py", "");
    let r = scan(&t.root).unwrap();
    let data = egress_core::data::Data::embedded().unwrap();
    assert_eq!(r.tool.name, "egress-plane");
    assert_eq!(r.tool.data_digest, data.data_digest);
    assert_eq!(r.tool.runtime_range, data.runtime_range);
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn root_errors_are_tool_errors() {
    let t = Tree::new("root-err");
    t.file("f.py", "");
    assert_eq!(
        scan(&t.path("f.py")).err(),
        Some(ToolError::RootNotDirectory)
    );
    assert_eq!(scan(&t.path("nope")).err(), Some(ToolError::RootNotFound));
}

#[test]
fn covers_ae26_files_budget_cut_is_deterministic() {
    let t = Tree::new("ae26");
    for n in ["d.py", "a.py", "c.py", "b.py"] {
        t.file(n, "x = 1\n");
    }
    let (mut opts, rec) = with_recorder(Language::Python);
    opts.config = budgets(2, 1 << 30, 1000);
    let out = scan_with(&t.root, &opts).unwrap();
    let r = &out.report;
    assert_eq!(r.completeness.budget_exceeded, vec![BudgetReason::Files]);
    assert_eq!(r.completeness.state, CompletenessState::Incomplete);
    assert_eq!(r.exit_code(), 2);
    assert_eq!(r.completeness.coverage.python.scanned, 2);
    assert_eq!(r.completeness.coverage.python.skipped, 2);
    let mut seen = rec.seen.lock().unwrap().clone();
    seen.sort();
    assert_eq!(seen, vec!["a.py", "b.py"]);
    let again = scan_with(&t.root, &opts).unwrap();
    assert_eq!(to_json(r), to_json(&again.report));
}

#[test]
fn covers_ae26_bytes_budget_cut() {
    let t = Tree::new("ae26-bytes");
    for n in ["a.py", "b.py", "c.py"] {
        t.file(n, "x = 1\n");
    }
    let opts = ScanOptions {
        config: budgets(100, 7, 1000),
        ..ScanOptions::default()
    };
    let r = scan_with(&t.root, &opts).unwrap().report;
    assert_eq!(r.completeness.budget_exceeded, vec![BudgetReason::Bytes]);
    assert_eq!(r.exit_code(), 2);
}

#[test]
fn findings_budget_keeps_identity_order_regardless_of_workers() {
    let t = Tree::new("findings");
    for i in 0..20 {
        t.file(&format!("nb{i:02}.ipynb"), "{}");
    }
    t.file("app.py", "");
    let run = |workers| {
        let opts = ScanOptions {
            config: budgets(100, 1 << 30, 5),
            workers,
            ..ScanOptions::default()
        };
        scan_with(&t.root, &opts).unwrap().report
    };
    let one = run(1);
    let eight = run(8);
    assert_eq!(to_json(&one), to_json(&eight));
    assert_eq!(one.blind_spots.len(), 5);
    let files: Vec<_> = one.blind_spots.iter().map(|b| b.file.as_str()).collect();
    assert_eq!(
        files,
        vec![
            "nb00.ipynb",
            "nb01.ipynb",
            "nb02.ipynb",
            "nb03.ipynb",
            "nb04.ipynb"
        ]
    );
    assert!(
        one.completeness
            .budget_exceeded
            .contains(&BudgetReason::Findings)
    );
    assert_eq!(one.completeness.state, CompletenessState::Incomplete);
}

#[test]
fn default_budgets_leave_ordinary_trees_alone() {
    let t = Tree::new("default-budgets");
    t.file("a.py", "").file("b.js", "").file("c.rs", "");
    let r = scan(&t.root).unwrap();
    assert!(r.completeness.budget_exceeded.is_empty());
}

#[test]
fn panicking_frontend_is_isolated_to_its_file() {
    let t = Tree::new("panic");
    t.file("ok.py", "x = 1\n")
        .file("boom.py", "PANIC\u{1b}[2J\n")
        .file("bad.py", "SYNTAX\n");
    let (mut opts, _rec) = with_recorder(Language::Python);
    opts.workers = 4;
    let out = scan_with(&t.root, &opts).unwrap();
    assert_eq!(
        kinds(&out.report),
        vec![
            ("bad.py".into(), BlindSpotKind::ParseError),
            ("boom.py".into(), BlindSpotKind::FrontendFailure),
        ]
    );
    let lowered: Vec<_> = out.files.iter().map(|f| f.file.display.clone()).collect();
    assert_eq!(lowered, vec!["ok.py"]);
    assert_eq!(out.report.completeness.coverage.python.scanned, 1);
    assert_eq!(out.report.completeness.coverage.python.skipped, 2);
    assert_eq!(out.report.exit_code(), 2);
}

struct DeepRecursion;

#[inline(never)]
fn recurse(n: u32, pad: &mut [u8; 2048]) -> u32 {
    pad[0] = pad[0].wrapping_add(1);
    if n == 0 {
        return u32::from(pad[0]);
    }
    let mut next = [0u8; 2048];
    next[1] = pad[0];
    recurse(n - 1, &mut next).wrapping_add(u32::from(std::hint::black_box(next[2047])))
}

impl Frontend for DeepRecursion {
    fn language(&self) -> Language {
        Language::Rust
    }
    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        // About 4 KiB per frame times 5,000 frames: well past an 8 MiB stack.
        let mut pad = [0u8; 2048];
        std::hint::black_box(recurse(5_000, &mut pad));
        Ok(FileIr::new(input.language))
    }
}

#[test]
fn workers_have_a_64_mib_stack() {
    let t = Tree::new("deep-stack");
    t.file("src/lib.rs", "fn main() {}\n");
    let mut registry = Registry::new();
    registry.register(DeepRecursion);
    let opts = ScanOptions {
        registry,
        ..ScanOptions::default()
    };
    let out = scan_with(&t.root, &opts).unwrap();
    assert_eq!(out.files.len(), 1);
    assert!(out.report.blind_spots.is_empty());
}

struct InFlight {
    now: AtomicU64,
    max: AtomicU64,
}

struct InFlightFe(Arc<InFlight>);

impl Frontend for InFlightFe {
    fn language(&self) -> Language {
        Language::Javascript
    }
    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        let n = input.text.len() as u64;
        let now = self.0.now.fetch_add(n, Ordering::SeqCst) + n;
        self.0.max.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(5));
        self.0.now.fetch_sub(n, Ordering::SeqCst);
        Ok(FileIr::new(input.language))
    }
}

#[test]
fn in_flight_bytes_stay_under_the_cap() {
    let t = Tree::new("in-flight");
    for i in 0..40 {
        t.file(&format!("f{i:02}.js"), "x".repeat(1000));
    }
    let probe = Arc::new(InFlight {
        now: AtomicU64::new(0),
        max: AtomicU64::new(0),
    });
    let mut registry = Registry::new();
    registry.register(InFlightFe(Arc::clone(&probe)));
    let opts = ScanOptions {
        registry,
        workers: 8,
        in_flight_bytes: 3000,
        ..ScanOptions::default()
    };
    let out = scan_with(&t.root, &opts).unwrap();
    assert_eq!(out.files.len(), 40);
    let max = probe.max.load(Ordering::SeqCst);
    assert!(max <= 3000, "in-flight peak {max}");
    assert!(max >= 2000, "workers ran in parallel ({max})");
}

#[test]
fn prescan_rejects_before_the_frontend_runs() {
    let t = Tree::new("prescan");
    t.file(
        "deep.py",
        format!("x = {}{}\n", "[".repeat(100_000), "]".repeat(100_000)),
    )
    .file("ok.py", "x = 1\n");
    let (opts, rec) = with_recorder(Language::Python);
    let out = scan_with(&t.root, &opts).unwrap();
    assert_eq!(
        kinds(&out.report),
        vec![("deep.py".into(), BlindSpotKind::TooDeeplyNested)]
    );
    assert_eq!(*rec.seen.lock().unwrap(), vec!["ok.py".to_string()]);
}

#[test]
fn read_failures_become_whole_file_blind_spots() {
    let t = Tree::new("read-fail");
    t.file("latin.py", b"s = '\xe9'\n").file("ok.py", "");
    let r = scan(&t.root).unwrap();
    assert_eq!(
        kinds(&r),
        vec![("latin.py".into(), BlindSpotKind::Undecodable)]
    );
    assert_eq!(r.completeness.coverage.python.skipped, 1);
    assert_eq!(r.completeness.coverage.python.scanned, 1);
}

#[test]
fn content_and_hook_labels_reach_lowered_files() {
    let t = Tree::new("labels");
    t.file("app.js", format!("var a = '{}';\n", "x".repeat(1200)))
        .file("gen.js", "// Code generated by tool. DO NOT EDIT.\n")
        .file(
            "Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        )
        .file("build.rs", "fn main() {}\n");
    let mut registry = Registry::new();
    registry.register(Recorder {
        lang: Some(Language::Javascript),
        ..Recorder::default()
    });
    registry.register(Recorder {
        lang: Some(Language::Rust),
        ..Recorder::default()
    });
    let opts = ScanOptions {
        registry,
        ..ScanOptions::default()
    };
    let out = scan_with(&t.root, &opts).unwrap();
    let labels = |p: &str| {
        out.files
            .iter()
            .find(|f| f.file.display == p)
            .unwrap()
            .labels
            .clone()
    };
    assert_eq!(labels("app.js"), vec![Label::Minified]);
    assert_eq!(labels("gen.js"), vec![Label::Generated]);
    assert_eq!(labels("build.rs"), vec![Label::BuildHook]);
}

#[test]
fn covers_ae24_hostile_repository_finishes_without_control_characters() {
    let t = Tree::new("ae24");
    t.fifo("src/pipe.py")
        .file(
            "src/deep.py",
            format!("x = {}{}\n", "(".repeat(100_000), ")".repeat(100_000)),
        )
        .file("src/esc\u{1b}]0;pwned\u{7}.py", "x = 1\n")
        .file("src/app.py", "x = 1\n")
        .link("src/share.py", "/net/host/share/x.py");
    let root = t.root.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(scan(&root));
    });
    let r = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("scan blocked")
        .unwrap();
    assert_eq!(r.exit_code(), 2);
    assert_eq!(
        kinds(&r),
        vec![
            ("src/deep.py".into(), BlindSpotKind::TooDeeplyNested),
            ("src/pipe.py".into(), BlindSpotKind::NotRegularFile),
            ("src/share.py".into(), BlindSpotKind::SymlinkOutsideRoot),
        ]
    );
    let json = to_json(&r);
    assert!(
        !json.chars().any(|c| c.is_control() && c != '\n'),
        "raw control character in JSON"
    );
    assert!(!json.contains("/net/host") && !json.contains("share/x.py"));
}

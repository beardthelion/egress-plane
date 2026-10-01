//! Global resource budgets (KTD19, AE26).

mod support;

use std::path::Path;

use egress_core::discover::budgets::{BUDGETS_TOML, apply_findings_budget};
use egress_core::discover::{Budgets, Config, discover};
use egress_core::model::*;
use support::Tree;

fn reduced(files: u64, bytes: u64) -> Config {
    let text =
        format!("files = {files}\nbytes = {bytes}\nfindings = 1000\nresolver_steps = 1000\n");
    Config {
        budgets: Budgets::parse(&text).unwrap(),
        ..Config::default()
    }
}

#[test]
fn embedded_budgets_load() {
    let b = Budgets::embedded();
    assert_eq!(b, Budgets::parse(BUDGETS_TOML).unwrap());
    assert!(b.files >= 100_000 && b.bytes >= 1 << 30 && b.findings >= 100_000);
    assert!(b.resolver_steps > 0);
}

#[test]
fn malformed_budget_tables_are_rejected() {
    assert!(Budgets::parse("files = 1\n").is_err());
    assert!(Budgets::parse("files = -1\nbytes = 1\nfindings = 1\nresolver_steps = 1\n").is_err());
    assert!(
        Budgets::parse("files = 1\nbytes = 1\nfindings = 1\nresolver_steps = 1\nextra = 2\n")
            .is_err()
    );
}

fn five_files(t: &Tree) {
    for name in ["e.py", "a.py", "c.py", "b.py", "d.py"] {
        t.file(name, "x = 1\n");
    }
}

#[test]
fn covers_ae26_files_budget_parses_the_bytewise_first_files() {
    let t = Tree::new("budget-files");
    five_files(&t);
    let d = discover(&t.root, &reduced(2, 1 << 30)).unwrap();
    let parsed: Vec<_> = d.sources.iter().map(|s| s.file.display.clone()).collect();
    assert_eq!(parsed, vec!["a.py", "b.py"]);
    assert_eq!(d.budget_exceeded, vec![BudgetReason::Files]);
    assert_eq!(d.coverage.python.skipped, 3);
    assert!(d.blind_spots.is_empty(), "budget skips carry no entries");
}

#[test]
fn covers_ae26_bytes_budget_cuts_the_same_way() {
    let t = Tree::new("budget-bytes");
    five_files(&t);
    let d = discover(&t.root, &reduced(100, 13)).unwrap();
    let parsed: Vec<_> = d.sources.iter().map(|s| s.file.display.clone()).collect();
    assert_eq!(parsed, vec!["a.py", "b.py"]);
    assert_eq!(d.budget_exceeded, vec![BudgetReason::Bytes]);
    assert_eq!(d.coverage.python.skipped, 3);
}

fn bs(file: &str) -> BlindSpot {
    BlindSpot {
        id: String::new(),
        language: None,
        file: file.into(),
        file_bytes: None,
        symbol: "<module>".into(),
        kind: BlindSpotKind::UnsupportedFileType,
        whole_file: true,
        coverage_gap: true,
        construct: String::new(),
        ordinal: 0,
        labels: vec![],
        location: None,
    }
}

#[test]
fn findings_budget_keeps_the_first_findings_in_identity_order() {
    let mut r = Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "egress-plane".into(),
            version: "0".into(),
            data_digest: String::new(),
            runtime_range: RuntimeRange {
                python: String::new(),
                node: String::new(),
                rust: String::new(),
            },
        },
        completeness: Completeness {
            state: CompletenessState::Incomplete,
            budget_exceeded: vec![],
            coverage: Coverage::default(),
        },
        caveats: vec![],
        sites: vec![],
        blind_spots: ["d.ipynb", "b.ipynb", "a.ipynb", "c.ipynb"]
            .map(bs)
            .to_vec(),
        unscanned_dependencies: vec![],
        excluded: vec![],
    };
    egress_core::identity::finalize(&mut r);
    let mut first = r.clone();
    assert!(apply_findings_budget(&mut first, 2));
    let kept: Vec<_> = first.blind_spots.iter().map(|b| b.file.as_str()).collect();
    assert_eq!(kept, vec!["a.ipynb", "b.ipynb"]);
    let mut same = r.clone();
    assert!(!apply_findings_budget(&mut same, 4));
    assert_eq!(same, r);
}

#[test]
fn default_budgets_are_not_exhausted_on_the_corpus() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus");
    let mut checked = 0;
    for lang in std::fs::read_dir(&corpus).unwrap().flatten() {
        if !lang.path().is_dir() {
            continue;
        }
        for cat in std::fs::read_dir(lang.path()).unwrap().flatten() {
            for case in std::fs::read_dir(cat.path()).unwrap().flatten() {
                let tree = case.path().join("tree");
                let d = discover(&tree, &Config::default())
                    .unwrap_or_else(|e| panic!("{}: {e}", tree.display()));
                assert!(d.budget_exceeded.is_empty(), "{}", tree.display());
                checked += 1;
            }
        }
    }
    assert!(checked > 100);
}

//! Global resource budgets.

mod common;
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
fn files_budget_parses_the_bytewise_first_files() {
    let t = Tree::new("budget-files");
    five_files(&t);
    let d = discover(&t.root, &reduced(2, 1 << 30)).unwrap();
    let parsed: Vec<_> = d.sources.iter().map(|s| s.file.display.clone()).collect();
    assert_eq!(parsed, vec!["a.py", "b.py"]);
    assert_eq!(d.budget_exceeded, vec![BudgetReason::Files]);
    assert_eq!(d.coverage.languages[Language::Python].skipped, 3);
    assert!(d.blind_spots.is_empty(), "budget skips carry no entries");
}

#[test]
fn bytes_budget_cuts_the_same_way() {
    let t = Tree::new("budget-bytes");
    five_files(&t);
    let d = discover(&t.root, &reduced(100, 13)).unwrap();
    let parsed: Vec<_> = d.sources.iter().map(|s| s.file.display.clone()).collect();
    assert_eq!(parsed, vec!["a.py", "b.py"]);
    assert_eq!(d.budget_exceeded, vec![BudgetReason::Bytes]);
    assert_eq!(d.coverage.languages[Language::Python].skipped, 3);
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
            runtime_range: RuntimeRange::default(),
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
        dependencies: None,
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

/// Two direct sites (the first is the `param:` inner site), two derived
/// sites naming it, one blind spot, one unscanned dependency: six findings
/// in the KTD11 keep order.
fn mixed_report() -> Report {
    let mut r = Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "egress-plane".into(),
            version: "0".into(),
            data_digest: String::new(),
            runtime_range: RuntimeRange::default(),
        },
        completeness: Completeness {
            state: CompletenessState::Incomplete,
            budget_exceeded: vec![],
            coverage: Coverage::default(),
        },
        caveats: vec![],
        sites: vec![
            common::site(
                "api.py",
                "post_json",
                "python:requests.post",
                egress_core::destination::param(1, "post_json"),
                5,
            ),
            common::site(
                "b.py",
                "f",
                "python:requests.get",
                egress_core::destination::literal("https://b.invalid"),
                3,
            ),
        ],
        blind_spots: vec![bs("a.ipynb")],
        unscanned_dependencies: vec![UnscannedDependency {
            id: String::new(),
            language: Language::Javascript,
            package: "left-pad".into(),
            files: vec!["a.js".into()],
            reason: None,
            distribution: vec![],
            distribution_source: None,
            mark: None,
        }],
        excluded: vec![],
        dependencies: None,
    };
    egress_core::identity::finalize(&mut r);
    let inner_id = r
        .sites
        .iter()
        .find(|s| s.symbol == "post_json")
        .unwrap()
        .id
        .clone();
    for (arg, dest) in [(1, "https://hook.invalid"), (2, "https://o.invalid")] {
        let s = common::site(
            "cli.py",
            "main",
            "python:requests.post",
            egress_core::destination::literal(dest),
            9,
        );
        r.sites.push(common::derived(
            s,
            common::via(&inner_id, arg, &[("api.py", "post_json")]),
        ));
    }
    egress_core::identity::finalize(&mut r);
    r
}

#[test]
fn findings_budget_keeps_unscanned_dependencies_over_derived_sites() {
    let r = mixed_report();
    assert_eq!(r.sites.iter().filter(|s| s.via.is_some()).count(), 2);
    // A cap that fits the blind spot, both direct sites, and the unscanned
    // dependency but not the derived sites keeps every coverage entry and
    // drops only the derived sites (KTD11).
    let mut c = r.clone();
    assert!(apply_findings_budget(&mut c, 4));
    assert_eq!(c.blind_spots.len(), 1);
    assert_eq!(c.sites.len(), 2);
    assert!(c.sites.iter().all(|s| s.via.is_none()));
    assert_eq!(c.unscanned_dependencies.len(), 1);
    // One slot wider keeps the first derived site only.
    let mut c = r.clone();
    assert!(apply_findings_budget(&mut c, 5));
    assert_eq!(c.sites.iter().filter(|s| s.via.is_some()).count(), 1);
    // A cap that fits everything cuts nothing.
    let mut c = r.clone();
    assert!(!apply_findings_budget(&mut c, 6));
    assert_eq!(c, r);
}

#[test]
fn no_derived_site_survives_a_dropped_inner_site() {
    let r = mixed_report();
    // Keep the blind spot and one direct site: whichever direct site is
    // dropped, no derived site remains, because all of them sort after
    // the direct ones.
    let mut c = r.clone();
    assert!(apply_findings_budget(&mut c, 2));
    assert_eq!(c.sites.len(), 1);
    assert!(c.sites.iter().all(|s| s.via.is_none()));
    assert!(c.unscanned_dependencies.is_empty());
    // Cap below every site still keeps the blind spot.
    let mut c = r.clone();
    assert!(apply_findings_budget(&mut c, 1));
    assert!(c.sites.is_empty());
    assert_eq!(c.blind_spots.len(), 1);
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

fn steps(resolver_steps: u64) -> Config {
    let text = format!(
        "files = 100\nbytes = 100000\nfindings = 1000\nresolver_steps = {resolver_steps}\n"
    );
    Config {
        budgets: Budgets::parse(&text).unwrap(),
        ..Config::default()
    }
}

fn link_tree(name: &str) -> Tree {
    let t = Tree::new(name);
    t.file("a/b/c/d/e/real.py", "x = 1\n")
        .link("l1.py", "a/b/c/d/e/real.py")
        .link("l2.py", "a/b/c/d/e/real.py")
        .link("l3", "a/b/c/d/e");
    t
}

#[test]
fn symlink_resolution_is_charged_against_the_resolver_budget() {
    let t = link_tree("budget-links-ok");
    let d = discover(&t.root, &steps(1000)).unwrap();
    assert!(d.budget_exceeded.is_empty());
    assert!(d.blind_spots.is_empty());
    assert_eq!(d.excluded.len(), 3);

    // Resolving l1.py alone takes more than three steps (a readlink and six
    // components), so every link becomes a gap once the budget runs out.
    let t = link_tree("budget-links-cut");
    let d = discover(&t.root, &steps(3)).unwrap();
    assert_eq!(d.budget_exceeded, vec![BudgetReason::ResolverSteps]);
    let mut spots: Vec<_> = d
        .blind_spots
        .iter()
        .map(|b| (b.file.as_str(), b.kind, b.coverage_gap))
        .collect();
    spots.sort();
    assert_eq!(
        spots,
        vec![
            ("l1.py", BlindSpotKind::ResolutionLimit, true),
            ("l2.py", BlindSpotKind::ResolutionLimit, true),
            ("l3", BlindSpotKind::ResolutionLimit, true),
        ]
    );
    assert!(d.excluded.is_empty());
    // The real file is still scanned.
    assert_eq!(d.sources.len(), 1);
}

#[test]
fn deep_self_referencing_links_are_bounded_by_the_budget() {
    // A link that climbs out of a deep chain and back down to itself costs
    // a full splice per hop; the budget cuts it off deterministically.
    let t = Tree::new("budget-deep");
    let depth = 60;
    let chain = "a/".repeat(depth);
    t.dir(&chain);
    let target = format!("{}{}x", "../".repeat(depth), chain);
    t.link(&format!("{chain}x"), &target);
    t.file("m.py", "");
    t.link("l.py", format!("{chain}x"));
    let d = discover(&t.root, &steps(500)).unwrap();
    assert_eq!(d.budget_exceeded, vec![BudgetReason::ResolverSteps]);
    assert!(
        d.blind_spots
            .iter()
            .any(|b| b.kind == BlindSpotKind::ResolutionLimit && b.coverage_gap)
    );
}

// ---- U6: dependency budgets -------------------------------------------------

use egress_core::discover::budgets::{DEPENDENCY_BUDGETS_TOML, DependencyBudgets};

#[test]
fn embedded_dependency_budgets_load() {
    let b = DependencyBudgets::embedded();
    assert_eq!(
        b,
        DependencyBudgets::parse(DEPENDENCY_BUDGETS_TOML).unwrap()
    );
    assert!(b.packages > 0 && b.files > 0 && b.bytes > 0);
    assert!(b.inventory_entries > 0 && b.lockfile_bytes > 0 && b.metadata_bytes > 0);
}

#[test]
fn malformed_dependency_budget_tables_are_rejected() {
    // A missing key fails; an unknown key fails (deny_unknown_fields).
    assert!(DependencyBudgets::parse("packages = 1\n").is_err());
    assert!(
        DependencyBudgets::parse(
            "packages = 1\nfiles = 1\nbytes = 1\nfindings = 1\nresolver_steps = 1\ninventory_entries = 1\nlockfile_bytes = 1\nmetadata_bytes = 1\nextra = 2\n"
        )
        .is_err()
    );
}

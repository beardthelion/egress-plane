//! The classification stage in `scan_with`: findings from the lowered
//! IR reach the report with identities, coverage counts loaded-as-code
//! files, and the resolver and findings budgets apply after classification.

#[path = "../../egress-core/tests/support/mod.rs"]
mod support;

use egress_core::discover::{Budgets, Config};
use egress_core::ir::{Expr, FileIr, Import, Reference, Root, Span, UseKind};
use egress_core::model::*;
use egress_core::resolve::{GenericRules, SpecifierRules};
use egress_scan::{Frontend, FrontendError, Registry, ScanOptions, SourceInput, scan_with};
use support::Tree;

/// A Python frontend over a line protocol: `import <module>` binds the
/// module; `import <local> from <specifier>` binds a whole module by path;
/// `call <module>.<member> <literal>` calls a member with one literal
/// argument.
struct LineFrontend {
    rules: GenericRules,
}

fn loc(n: usize) -> (Span, Location) {
    let n = n as u32 + 1;
    (
        Span {
            start: n * 100,
            end: n * 100 + 1,
        },
        Location { line: n, column: 1 },
    )
}

impl Frontend for LineFrontend {
    fn language(&self) -> Language {
        Language::Python
    }

    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        let mut ir = FileIr::new(Language::Python);
        for (i, line) in input.text.lines().enumerate() {
            let (span, location) = loc(i);
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                ["import", m] => ir.imports.push(Import {
                    local: Some(m.to_string()),
                    specifier: m.to_string(),
                    members: vec![],
                    type_only: false,
                    star: false,
                    re_export: false,
                    default: false,
                    symbol: "<module>".into(),
                    span,
                    location,
                }),
                ["import", l, "from", spec] => ir.imports.push(Import {
                    local: Some(l.to_string()),
                    specifier: spec.to_string(),
                    members: vec![],
                    type_only: false,
                    star: false,
                    re_export: false,
                    default: false,
                    symbol: "<module>".into(),
                    span,
                    location,
                }),
                ["call", chain, arg] => {
                    let mut parts = chain.split('.');
                    let root = parts.next().unwrap_or_default().to_string();
                    ir.references.push(Reference {
                        root: Root::Import(root),
                        members: parts.map(str::to_string).collect(),
                        calls_in_chain: vec![],
                        use_kind: UseKind::Call,
                        args: vec![Expr::Literal(arg.to_string())],
                        kwargs: vec![],
                        receiver: None,
                        text: format!("{chain}({arg:?})"),
                        symbol: "<module>".into(),
                        span,
                        location,
                    });
                }
                _ => {}
            }
        }
        Ok(ir)
    }

    fn specifier_rules(&self) -> Option<&dyn SpecifierRules> {
        Some(&self.rules)
    }
}

fn options(budgets: Budgets) -> ScanOptions {
    let mut registry = Registry::new();
    registry.register(LineFrontend {
        rules: GenericRules {
            extensions: vec![".py".into()],
            index_names: vec!["__init__".into()],
        },
    });
    ScanOptions {
        registry,
        config: Config {
            budgets,
            ..Config::default()
        },
        ..ScanOptions::default()
    }
}

fn default_budgets() -> Budgets {
    Config::default().budgets
}

#[test]
fn classified_sites_and_dependencies_reach_the_report_with_identities() {
    let t = Tree::new("classify-stage");
    t.file(
        "app.py",
        "import requests\nimport yaml\ncall requests.post https://h.example/x\n",
    );
    let out = scan_with(&t.root, &options(default_budgets())).unwrap();
    let r = &out.report;
    assert_eq!(r.sites.len(), 1, "{:?}", r.sites);
    let s = &r.sites[0];
    assert_eq!(s.mechanism, "python:requests.post");
    assert_eq!(s.destination.display, "https://h.example/x");
    assert_eq!(s.file, "app.py");
    assert_eq!(s.id.len(), 16);
    let deps: Vec<_> = r
        .unscanned_dependencies
        .iter()
        .map(|d| d.package.as_str())
        .collect();
    assert_eq!(deps, vec!["yaml"]);
    assert_eq!(r.unscanned_dependencies[0].id.len(), 16);
    assert_eq!(r.completeness.state, CompletenessState::Complete);
}

#[test]
fn frontend_specifier_rules_resolve_first_party_imports() {
    let t = Tree::new("classify-stage-rules");
    t.file("helper.py", "import requests\n");
    t.file(
        "app.py",
        "import h from ./helper\ncall h.requests.post https://h.example/y\n",
    );
    let out = scan_with(&t.root, &options(default_budgets())).unwrap();
    let mechs: Vec<_> = out
        .report
        .sites
        .iter()
        .map(|s| (s.file.as_str(), s.mechanism.as_str()))
        .collect();
    assert_eq!(mechs, vec![("app.py", "python:requests.post")]);
    assert!(
        out.report.blind_spots.is_empty(),
        "{:?}",
        out.report.blind_spots
    );
}

#[test]
fn loaded_as_code_counts_as_skipped_unsupported_and_makes_the_account_incomplete() {
    let t = Tree::new("classify-stage-loaded");
    t.file("payload.dat", "data");
    t.file("app.py", "import p from ./payload.dat\n");
    let out = scan_with(&t.root, &options(default_budgets())).unwrap();
    let r = &out.report;
    let gaps: Vec<_> = r
        .blind_spots
        .iter()
        .map(|b| (b.file.as_str(), b.kind, b.whole_file, b.coverage_gap))
        .collect();
    assert_eq!(
        gaps,
        vec![("payload.dat", BlindSpotKind::LoadedAsCode, true, true)]
    );
    assert_eq!(r.completeness.coverage.unsupported.skipped, 1);
    assert_eq!(r.completeness.state, CompletenessState::Incomplete);
    assert_eq!(r.exit_code(), 2);
}

#[test]
fn exhausted_resolver_budget_is_listed_and_makes_the_account_incomplete() {
    let t = Tree::new("classify-stage-resolver");
    t.file(
        "app.py",
        "import requests\ncall requests.post https://h.example/x\n",
    );
    let budgets = Budgets {
        resolver_steps: 0,
        ..default_budgets()
    };
    let a = scan_with(&t.root, &options(budgets)).unwrap().report;
    let b = scan_with(&t.root, &options(budgets)).unwrap().report;
    assert_eq!(a, b);
    assert_eq!(
        a.completeness.budget_exceeded,
        vec![BudgetReason::ResolverSteps]
    );
    assert_eq!(a.completeness.state, CompletenessState::Incomplete);
    assert!(a.sites.is_empty());
    assert!(
        a.blind_spots
            .iter()
            .all(|x| x.kind == BlindSpotKind::ResolutionLimit),
        "{:?}",
        a.blind_spots
    );
    assert_eq!(a.blind_spots.len(), 2);
}

#[test]
fn resolver_budget_exhausted_in_discovery_and_classification_is_listed_once() {
    // Symlink resolution in discovery and alias resolution in classification
    // charge the same budget; running out in both lists the reason once.
    let t = Tree::new("classify-stage-resolver-twice");
    t.file(
        "app.py",
        "import requests\ncall requests.post https://h.example/x\n",
    );
    t.file("a/b/c/real.py", "");
    t.link("l.py", "a/b/c/real.py");
    let budgets = Budgets {
        resolver_steps: 0,
        ..default_budgets()
    };
    let r = scan_with(&t.root, &options(budgets)).unwrap().report;
    assert_eq!(
        r.completeness.budget_exceeded,
        vec![BudgetReason::ResolverSteps]
    );
    assert!(
        r.blind_spots
            .iter()
            .any(|b| b.file == "l.py" && b.kind == BlindSpotKind::ResolutionLimit),
        "{:?}",
        r.blind_spots
    );
    assert!(
        r.blind_spots
            .iter()
            .any(|b| b.file == "app.py" && b.kind == BlindSpotKind::ResolutionLimit),
        "{:?}",
        r.blind_spots
    );
}

#[test]
fn findings_budget_applies_after_classification() {
    let t = Tree::new("classify-stage-findings");
    t.file(
        "app.py",
        "import requests\nimport yaml\ncall requests.post https://h.example/x\n",
    );
    let budgets = Budgets {
        findings: 1,
        ..default_budgets()
    };
    let r = scan_with(&t.root, &options(budgets)).unwrap().report;
    assert!(
        r.completeness
            .budget_exceeded
            .contains(&BudgetReason::Findings)
    );
    assert_eq!(r.completeness.state, CompletenessState::Incomplete);
    assert_eq!(
        r.sites.len() + r.blind_spots.len() + r.unscanned_dependencies.len(),
        1
    );
}

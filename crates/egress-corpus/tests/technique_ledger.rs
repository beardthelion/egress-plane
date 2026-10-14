//! The technique ledger guards (KTD6, R8, R9): every row is well
//! formed, every `covered_by` is in the vocabulary, every license
//! matches the collection it cites, every non-`gap` non-`outside-*`
//! row names a case the corpus or a spec row claims, every seeded
//! collection has a row, and a `gap` row fails until resolved.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_corpus::spec::{
    self, SpecKind, check_techniques, load_spec, load_techniques, parse_techniques,
};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus")
}

fn spec_cases(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for kind in [SpecKind::Evasive, SpecKind::Closure] {
        for r in load_spec(&root.join(kind.file()), kind).unwrap_or_else(|e| panic!("{e}")) {
            out.insert(r.case);
            out.insert(r.twin);
        }
    }
    out
}

fn ledger_row(class: &str, source: &str, license: &str, covered_by: &str, case: &str) -> String {
    let case_line = if case.is_empty() {
        String::new()
    } else {
        format!("case = \"{case}\"\n")
    };
    format!(
        "[[technique]]\nclass = \"{class}\"\nlanguage = \"python\"\nsource = \"{source}\"\nlicense = \"{license}\"\ncovered_by = \"{covered_by}\"\n{case_line}revision = \"3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a\"\nreplay = \"pending\"\n"
    )
}

// ---- synthetic roots --------------------------------------------------------

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn tmp_root() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ledger-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---- real file --------------------------------------------------------------

#[test]
fn ledger_rows_pass_every_guard() {
    let root = corpus();
    let rows = load_techniques(&root.join("techniques.toml")).unwrap_or_else(|e| panic!("{e}"));
    assert!(!rows.is_empty(), "techniques.toml holds no rows");
    let errors = check_techniques(&root, &spec_cases(&root), &rows);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

// ---- negative scenarios -----------------------------------------------------

#[test]
fn row_without_revision_fails() {
    let text = concat!(
        "[[technique]]\n",
        "class = \"builtins recovery\"\n",
        "language = \"python\"\n",
        "source = \"https://github.com/jailctf/pyjailbreaker\"\n",
        "license = \"none-detected\"\n",
        "covered_by = \"introspection-roots\"\n",
        "case = \"python/evasive/introspection-subclasses\"\n",
        "replay = \"pending\"\n"
    );
    let e = parse_techniques(text, "techniques.toml").unwrap_err();
    assert!(e.contains("revision"), "{e}");
    assert!(e.contains("builtins recovery"), "{e}");
}

#[test]
fn unknown_covered_by_fails() {
    let text = ledger_row(
        "mystery",
        "https://github.com/jailctf/pyjailbreaker",
        "none-detected",
        "unknown-family",
        "python/evasive/introspection-subclasses",
    );
    let e = parse_techniques(&text, "techniques.toml").unwrap_err();
    assert!(e.contains("vocabulary"), "{e}");
}

#[test]
fn license_mismatch_with_the_source_fails() {
    let root = tmp_root();
    let text = ledger_row(
        "mystery",
        "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "GPL-3.0",
        "introspection-roots",
        "python/evasive/introspection-subclasses",
    );
    let rows = parse_techniques(&text, "techniques.toml").unwrap();
    let mut spec_ids = BTreeSet::new();
    spec_ids.insert("python/evasive/introspection-subclasses".to_string());
    let errors = check_techniques(&root, &spec_ids, &rows);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("GPL-3.0") && e.contains("MIT")),
        "{}",
        errors.join("\n")
    );
}

#[test]
fn unknown_source_fails() {
    let root = tmp_root();
    let text = ledger_row(
        "mystery",
        "https://example.invalid/not-a-collection",
        "MIT",
        "introspection-roots",
        "python/evasive/introspection-subclasses",
    );
    let rows = parse_techniques(&text, "techniques.toml").unwrap();
    let errors = check_techniques(&root, &BTreeSet::new(), &rows);
    assert!(
        errors.iter().any(|e| e.contains("seeded collections")),
        "{}",
        errors.join("\n")
    );
}

#[test]
fn case_that_nothing_claims_fails() {
    let root = tmp_root();
    let text = ledger_row(
        "mystery",
        "https://github.com/jailctf/pyjailbreaker",
        "none-detected",
        "introspection-roots",
        "python/evasive/no-such-case",
    );
    let rows = parse_techniques(&text, "techniques.toml").unwrap();
    let errors = check_techniques(&root, &BTreeSet::new(), &rows);
    assert!(
        errors.iter().any(|e| e.contains("no-such-case")),
        "{}",
        errors.join("\n")
    );
}

#[test]
fn case_named_by_a_spec_row_passes_before_the_case_exists() {
    let root = tmp_root();
    let text = ledger_row(
        "mystery",
        "https://github.com/jailctf/pyjailbreaker",
        "none-detected",
        "introspection-roots",
        "python/evasive/introspection-subclasses",
    );
    let rows = parse_techniques(&text, "techniques.toml").unwrap();
    let mut spec_ids = BTreeSet::new();
    spec_ids.insert("python/evasive/introspection-subclasses".to_string());
    let errors = check_techniques(&root, &spec_ids, &rows);
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("introspection-subclasses")),
        "{}",
        errors.join("\n")
    );
}

#[test]
fn gap_row_fails_with_the_fixed_message() {
    let root = tmp_root();
    let text = ledger_row(
        "uncoverable trick",
        "https://github.com/jailctf/pyjailbreaker",
        "none-detected",
        "gap",
        "",
    );
    let rows = parse_techniques(&text, "techniques.toml").unwrap();
    let errors = check_techniques(&root, &BTreeSet::new(), &rows);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("gap: fix by a new family or closure class (R9)")),
        "{}",
        errors.join("\n")
    );
}

#[test]
fn seeded_collection_without_a_row_fails() {
    let root = tmp_root();
    // One row cites pyjailbreaker; the other four collections have none.
    let text = ledger_row(
        "builtins recovery",
        "https://github.com/jailctf/pyjailbreaker",
        "none-detected",
        "introspection-roots",
        "python/evasive/introspection-subclasses",
    );
    let rows = parse_techniques(&text, "techniques.toml").unwrap();
    let mut spec_ids = BTreeSet::new();
    spec_ids.insert("python/evasive/introspection-subclasses".to_string());
    let errors = check_techniques(&root, &spec_ids, &rows);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("PayloadsAllTheThings") && e.contains("no technique row")),
        "{}",
        errors.join("\n")
    );
}

#[test]
fn malformed_revision_shape_fails() {
    let text = concat!(
        "[[technique]]\n",
        "class = \"builtins recovery\"\n",
        "language = \"python\"\n",
        "source = \"https://github.com/jailctf/pyjailbreaker\"\n",
        "license = \"none-detected\"\n",
        "covered_by = \"introspection-roots\"\n",
        "case = \"python/evasive/introspection-subclasses\"\n",
        "revision = \"HEAD\"\n",
        "replay = \"pending\"\n"
    );
    let e = parse_techniques(text, "techniques.toml").unwrap_err();
    assert!(e.contains("revision"), "{e}");
}

#[test]
fn vocabularies_stay_in_sync_with_the_guard() {
    // Every evasive family and closure class is a legal covered_by, as
    // are gap and the two outside-* values.
    for v in spec::EVASIVE_FAMILIES
        .iter()
        .chain(spec::CLOSURE_CLASSES.iter())
    {
        assert!(spec::covered_by_known(v), "{v}");
    }
    for v in spec::OUTSIDE_COVERAGE {
        assert!(spec::covered_by_known(v), "{v}");
    }
    assert!(spec::covered_by_known("gap"));
    assert!(!spec::covered_by_known("dynamic-code"));
}

//! The spec matrix guards (KTD5): every row is well formed, every
//! family and closure class has a row per applicable language, every
//! `must-not-` twin name is prefixed, and an authored row's twin tree
//! differs from its case on the row's axis alone. `spec_matrix_is_complete`
//! is the Definition of Done check and stays ignored until U4 authors
//! every row.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::model::Language;
use egress_corpus::spec::{
    RowStatus, SpecKind, SpecLabel, SpecRow, check_authored, check_coverage, incomplete_rows,
    load_spec, parse_spec,
};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus")
}

fn load_all() -> Vec<SpecRow> {
    let root = corpus();
    let mut rows = load_spec(&root.join("evasive-spec.toml"), SpecKind::Evasive)
        .unwrap_or_else(|e| panic!("{e}"));
    rows.extend(
        load_spec(&root.join("closure-spec.toml"), SpecKind::Closure)
            .unwrap_or_else(|e| panic!("{e}")),
    );
    rows
}

fn row(case: &str, language: Language, family: &str, twin: &str, status: RowStatus) -> SpecRow {
    SpecRow {
        case: case.to_string(),
        language,
        family: family.to_string(),
        label: SpecLabel {
            kind: "dynamic-import".to_string(),
            symbol: "probe".to_string(),
            count: 1,
            absent_text: Vec::new(),
        },
        twin: twin.to_string(),
        axis: "literal name vs non-literal name".to_string(),
        status,
        note: None,
    }
}

fn spec_text(case: &str, language: &str, family: &str, twin: &str, status: &str) -> String {
    format!(
        "[[row]]\ncase = \"{case}\"\nlanguage = \"{language}\"\nfamily = \"{family}\"\nlabel = {{ kind = \"dynamic-import\", symbol = \"probe\", count = 1 }}\ntwin = \"{twin}\"\naxis = \"literal name vs non-literal name\"\nstatus = \"{status}\"\n"
    )
}

// ---- synthetic roots --------------------------------------------------------

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn tmp_root() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "spec-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_case(root: &Path, id: &str, files: &[(&str, &str)]) {
    for (rel, text) in files {
        let p = root.join(id).join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
}

// ---- real files -------------------------------------------------------------

#[test]
fn spec_files_parse_and_cover_every_family() {
    let rows = load_all();
    assert!(!rows.is_empty(), "spec files hold no rows");
    let mut errors = check_coverage(&rows, SpecKind::Evasive);
    errors.extend(check_coverage(&rows, SpecKind::Closure));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn authored_rows_have_conforming_twins() {
    let rows = load_all();
    let errors = check_authored(&corpus(), &rows);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Definition of Done check: red until U4 authors or refuses every
/// row. Run explicitly with `--ignored`; ignored so the suite stays
/// green while rows are pending.
#[test]
#[ignore = "Definition of Done: red until every spec row is authored (U4)"]
fn spec_matrix_is_complete() {
    let rows = load_all();
    let errors = incomplete_rows(&rows);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

// ---- negative scenarios -----------------------------------------------------

#[test]
fn authored_row_naming_a_missing_case_fails() {
    let root = tmp_root();
    let rows = vec![row(
        "python/evasive/nonliteral-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        RowStatus::Authored,
    )];
    let errors = check_authored(&root, &rows);
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("python/evasive/nonliteral-import"),
        "{}",
        errors[0]
    );
}

#[test]
fn twin_must_start_with_must_not() {
    let text = spec_text(
        "python/evasive/nonliteral-import",
        "python",
        "dynamic-loading",
        "python/evasive/literal-import",
        "pending",
    );
    let e = parse_spec(&text, "evasive-spec.toml", SpecKind::Evasive).unwrap_err();
    assert!(e.contains("must-not-"), "{e}");
}

#[test]
fn twin_extra_file_fails_naming_row_and_axis() {
    let root = tmp_root();
    write_case(
        &root,
        "python/evasive/nonliteral-import",
        &[
            ("expected.toml", "state = \"complete\"\n"),
            ("tree/app.py", "x = 1\n"),
        ],
    );
    write_case(
        &root,
        "python/evasive/must-not-literal-import",
        &[
            ("expected.toml", "state = \"complete\"\n"),
            ("tree/app.py", "x = 1\n"),
            ("tree/extra.py", "y = 2\n"),
        ],
    );
    let rows = vec![row(
        "python/evasive/nonliteral-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        RowStatus::Authored,
    )];
    let errors = check_authored(&root, &rows);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("nonliteral-import"), "{}", errors[0]);
    assert!(
        errors[0].contains("literal name vs non-literal name"),
        "{}",
        errors[0]
    );
}

#[test]
fn twin_differing_in_two_files_fails() {
    let root = tmp_root();
    write_case(
        &root,
        "python/evasive/nonliteral-import",
        &[
            ("expected.toml", "state = \"complete\"\n"),
            ("tree/app.py", "x = 1\n"),
            ("tree/util.py", "u = 1\n"),
        ],
    );
    write_case(
        &root,
        "python/evasive/must-not-literal-import",
        &[
            ("expected.toml", "state = \"complete\"\n"),
            ("tree/app.py", "x = 2\n"),
            ("tree/util.py", "u = 2\n"),
        ],
    );
    let rows = vec![row(
        "python/evasive/nonliteral-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        RowStatus::Authored,
    )];
    let errors = check_authored(&root, &rows);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("2 files"), "{}", errors[0]);
}

#[test]
fn twin_differing_in_more_than_three_lines_fails() {
    let root = tmp_root();
    write_case(
        &root,
        "python/evasive/nonliteral-import",
        &[("expected.toml", "s\n"), ("tree/app.py", "a\nb\nc\nd\ne\n")],
    );
    write_case(
        &root,
        "python/evasive/must-not-literal-import",
        &[("expected.toml", "s\n"), ("tree/app.py", "a\nB\nC\nD\ne\n")],
    );
    let rows = vec![row(
        "python/evasive/nonliteral-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        RowStatus::Authored,
    )];
    let errors = check_authored(&root, &rows);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("at most 3"), "{}", errors[0]);
}

#[test]
fn conforming_twin_passes() {
    let root = tmp_root();
    write_case(
        &root,
        "python/evasive/nonliteral-import",
        &[
            ("expected.toml", "state = \"complete\"\nexit_code = 0\n"),
            ("tree/app.py", "x = name\ny = 2\n"),
        ],
    );
    write_case(
        &root,
        "python/evasive/must-not-literal-import",
        &[
            ("expected.toml", "state = \"complete\"\nexit_code = 0\n"),
            ("tree/app.py", "x = \"os\"\ny = 2\n"),
        ],
    );
    let rows = vec![row(
        "python/evasive/nonliteral-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        RowStatus::Authored,
    )];
    assert!(check_authored(&root, &rows).is_empty());
}

#[test]
fn removing_the_only_scope_injection_row_for_python_fails_coverage() {
    let rows: Vec<SpecRow> = load_all()
        .into_iter()
        .filter(|r| !(r.family == "scope-injection" && r.language == Language::Python))
        .collect();
    let errors = check_coverage(&rows, SpecKind::Evasive);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("scope-injection") && e.contains("python")),
        "{}",
        errors.join("\n")
    );
}

#[test]
fn native_and_macro_code_does_not_apply_to_python() {
    let text = spec_text(
        "python/evasive/extern-block",
        "python",
        "native-and-macro-code",
        "python/evasive/must-not-safe-function",
        "pending",
    );
    let e = parse_spec(&text, "evasive-spec.toml", SpecKind::Evasive).unwrap_err();
    assert!(e.contains("does not apply"), "{e}");
}

#[test]
fn refused_row_requires_a_note() {
    let text = spec_text(
        "python/evasive/nonliteral-import",
        "python",
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        "refused-by-safety-check",
    );
    let e = parse_spec(&text, "evasive-spec.toml", SpecKind::Evasive).unwrap_err();
    assert!(e.contains("note"), "{e}");
}

#[test]
fn pending_and_refused_rows_need_no_cases_on_disk() {
    let root = tmp_root();
    let mut pending = row(
        "python/evasive/nonliteral-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        RowStatus::Pending,
    );
    pending.note = None;
    let mut refused = row(
        "python/evasive/other-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-other-import",
        RowStatus::RefusedBySafetyCheck,
    );
    refused.note = Some("dynamic import by class".to_string());
    assert!(check_authored(&root, &[pending, refused]).is_empty());
}

#[test]
fn incomplete_rows_lists_pending_and_refused() {
    let rows = vec![row(
        "python/evasive/nonliteral-import",
        Language::Python,
        "dynamic-loading",
        "python/evasive/must-not-literal-import",
        RowStatus::Pending,
    )];
    let errors = incomplete_rows(&rows);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("nonliteral-import"), "{}", errors[0]);
}

#[test]
fn spec_case_ids_are_collectible_for_the_ledger() {
    // The technique ledger resolves `case` against this set.
    let ids: BTreeSet<String> = load_all().into_iter().map(|r| r.case).collect();
    assert!(!ids.is_empty());
}

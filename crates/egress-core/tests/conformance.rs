//! Language conformance (R3, KTD3): every entry in `Language::ALL` is
//! wired end to end, meaning a registered frontend, its three data files
//! with `language` keys that agree, its schema enum value and
//! per-language properties, a corpus directory whose categories each
//! hold a case or sit in `deferred.toml`, and a labels table. `check`
//! returns one named finding per missing piece; the tests below include
//! a deliberately incomplete language, which shows AE1's RED half
//! without leaving the workspace red.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use egress_core::data::guards::{self, Deferred};
use egress_core::model::Language;

/// Every finding name `check` can emit. The recipe test (U12) reads this
/// list, so a new kind of missing piece gets a new entry here.
pub const FINDING_NAMES: [&str; 10] = [
    "frontend-missing",
    "data-file-missing",
    "data-language-mismatch",
    "schema-enum-missing",
    "schema-coverage-property-missing",
    "schema-runtime-range-property-missing",
    "corpus-dir-missing",
    "category-uncovered",
    "category-deferral-stale",
    "label-entry-missing",
];

/// One named gap in a language's wiring.
#[derive(Debug)]
struct Finding {
    /// One of `FINDING_NAMES`.
    name: &'static str,
    /// What is missing or stale, path-prefixed where a path applies.
    detail: String,
}

/// Corpus categories, mirroring `egress_corpus::CATEGORIES`. This crate
/// cannot depend on the corpus harness, so a new category is added to
/// both lists together.
const CATEGORIES: [&str; 7] = [
    "ordinary",
    "tricky",
    "evasive",
    "closure",
    "primitives",
    "completeness",
    "dependencies",
];

/// The pieces a language is checked against: plain values and roots, so
/// a test can feed a synthetic repository (KTD3).
struct Inputs<'a> {
    /// Language names with a registered frontend.
    frontends: BTreeSet<&'a str>,
    /// The `data/` directory.
    data_root: &'a Path,
    /// The parsed `schema/egress-report.v1.json`.
    schema: &'a serde_json::Value,
    /// The `fixtures/corpus/` directory.
    corpus_root: &'a Path,
    /// The parsed `fixtures/corpus/deferred.toml`.
    deferred: &'a Deferred,
    /// The text of `data/labels.toml`.
    labels: &'a str,
}

/// Names each piece `name` (runtime-range key `runtime_key`) lacks, in
/// declaration order: frontend, data files, schema, corpus, labels.
fn check(inputs: &Inputs<'_>, name: &str, runtime_key: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let f = |name: &'static str, detail: String| Finding { name, detail };

    if !inputs.frontends.contains(name) {
        out.push(f(
            "frontend-missing",
            format!("{name}: no registered frontend"),
        ));
    }

    for kind in ["primitives", "catalog", "inventory"] {
        let rel = format!("data/{kind}/{name}.toml");
        match std::fs::read_to_string(inputs.data_root.join(format!("{kind}/{name}.toml"))) {
            Err(_) => out.push(f("data-file-missing", format!("{rel}: not found"))),
            Ok(text) => {
                let declared = toml::from_str::<toml::Table>(&text).ok().and_then(|t| {
                    t.get("language")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                });
                if declared.as_deref() != Some(name) {
                    out.push(f(
                        "data-language-mismatch",
                        format!(
                            "{rel}: language {:?} where {name:?} was expected",
                            declared.as_deref().unwrap_or("<none>")
                        ),
                    ));
                }
            }
        }
    }

    let schema = inputs.schema;
    let enum_has = schema["$defs"]["language"]["enum"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(name)));
    if !enum_has {
        out.push(f(
            "schema-enum-missing",
            format!("schema $defs/language enum lacks {name:?}"),
        ));
    }
    // `properties`, not `required`, decides coverage.
    let coverage = &schema["properties"]["completeness"]["properties"]["coverage"]["properties"];
    if !coverage.as_object().is_some_and(|o| o.contains_key(name)) {
        out.push(f(
            "schema-coverage-property-missing",
            format!("schema completeness.coverage properties lack {name:?}"),
        ));
    }
    let range = &schema["properties"]["tool"]["properties"]["runtime_range"]["properties"];
    if !range
        .as_object()
        .is_some_and(|o| o.contains_key(runtime_key))
    {
        out.push(f(
            "schema-runtime-range-property-missing",
            format!("schema tool.runtime_range properties lack {runtime_key:?}"),
        ));
    }

    let lang_dir = inputs.corpus_root.join(name);
    if !lang_dir.is_dir() {
        out.push(f(
            "corpus-dir-missing",
            format!("fixtures/corpus/{name}: not a directory"),
        ));
    } else {
        for cat in CATEGORIES {
            let id = format!("{name}/{cat}");
            let holds_case = std::fs::read_dir(lang_dir.join(cat))
                .map(|rd| rd.flatten().any(|e| e.path().is_dir()))
                .unwrap_or(false);
            match (holds_case, inputs.deferred.categories.contains_key(&id)) {
                (false, false) => out.push(f(
                    "category-uncovered",
                    format!("{id}: holds no case and is not in deferred.toml"),
                )),
                (true, true) => out.push(f(
                    "category-deferral-stale",
                    format!("{id}: deferred but holds a case; remove the entry"),
                )),
                _ => {}
            }
        }
    }

    let has_label_entry = toml::from_str::<toml::Table>(inputs.labels)
        .ok()
        .is_some_and(|t| {
            ["vendored", "generated", "minified", "test"]
                .iter()
                .any(|rule| {
                    t.get(*rule)
                        .and_then(|r| r.as_table())
                        .is_some_and(|r| r.contains_key(name))
                })
        });
    if !has_label_entry {
        out.push(f(
            "label-entry-missing",
            format!("data/labels.toml has no per-language table for {name:?}"),
        ));
    }

    out
}

fn names(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.name).collect()
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Declared languages whose frontend crate is not registered yet, like
/// `pending.toml` for corpus cases. The entry leaves when the frontend
/// lands (egress-go registers in P8 U6); a listed language that gains a
/// frontend without leaving the list fails the stale-entry guard.
const FRONTEND_PENDING: &[&str] = &[];

/// The real repository, checked once per `Language::ALL` entry.
#[test]
fn every_language_in_the_table_is_fully_wired() {
    let registry = egress_scan::Registry::builtin();
    let frontends: BTreeSet<&str> = Language::ALL
        .iter()
        .filter(|l| registry.get(**l).is_some())
        .map(|l| l.as_str())
        .collect();
    // A pending language must still lack a registered frontend; the
    // registration turns this red until the entry leaves the list.
    for p in FRONTEND_PENDING {
        assert!(
            !frontends.contains(*p),
            "{p} has a registered frontend; remove it from FRONTEND_PENDING"
        );
    }
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schema/egress-report.v1.json"))
            .unwrap_or_else(|e| panic!("schema: {e}"));
    let data_root = repo().join("data");
    let corpus_root = repo().join("fixtures/corpus");
    let text = std::fs::read_to_string(corpus_root.join("deferred.toml"))
        .unwrap_or_else(|e| panic!("deferred.toml: {e}"));
    let deferred = guards::parse_deferred(&text).unwrap_or_else(|e| panic!("{e}"));
    let inputs = Inputs {
        frontends,
        data_root: &data_root,
        schema: &schema,
        corpus_root: &corpus_root,
        deferred: &deferred,
        labels: egress_core::discover::labels::LABELS_TOML,
    };
    let mut findings = Vec::new();
    for lang in Language::ALL {
        findings.extend(check(&inputs, lang.as_str(), lang.spec().runtime_key));
    }
    // A pending language is allowed exactly the frontend-missing finding.
    findings.retain(|f| {
        !(f.name == "frontend-missing"
            && FRONTEND_PENDING
                .iter()
                .any(|p| f.detail == format!("{p}: no registered frontend")))
    });
    assert!(
        findings.is_empty(),
        "conformance findings:\n{}",
        findings
            .iter()
            .map(|f| format!("  {}: {}", f.name, f.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A complete synthetic repository for the made-up language `zz`
/// (runtime-range key `zz`): mutating one piece at a time shows the
/// finding that piece's absence produces.
struct Synthetic {
    data: support::Tree,
    corpus: support::Tree,
    schema: serde_json::Value,
    deferred: Deferred,
    labels: String,
    frontends: BTreeSet<String>,
}

impl Synthetic {
    fn inputs(&self) -> Inputs<'_> {
        Inputs {
            frontends: self.frontends.iter().map(String::as_str).collect(),
            data_root: &self.data.root,
            schema: &self.schema,
            corpus_root: &self.corpus.root,
            deferred: &self.deferred,
            labels: &self.labels,
        }
    }
}

fn schema_for(name: &str, runtime_key: &str) -> serde_json::Value {
    let mut s = serde_json::json!({
        "$defs": { "language": { "enum": [] } },
        "properties": {
            "completeness": { "properties": { "coverage": { "properties": {}, "required": [] } } },
            "tool": { "properties": { "runtime_range": { "properties": {}, "required": [] } } },
        }
    });
    s["$defs"]["language"]["enum"]
        .as_array_mut()
        .unwrap()
        .push(name.into());
    s["properties"]["completeness"]["properties"]["coverage"]["properties"]
        .as_object_mut()
        .unwrap()
        .insert(name.to_string(), serde_json::json!({}));
    s["properties"]["tool"]["properties"]["runtime_range"]["properties"]
        .as_object_mut()
        .unwrap()
        .insert(runtime_key.to_string(), serde_json::json!({}));
    s
}

fn synthetic() -> Synthetic {
    let data = support::Tree::new("conformance-data");
    for kind in ["primitives", "catalog", "inventory"] {
        data.file(&format!("{kind}/zz.toml"), "language = \"zz\"\n");
    }
    let corpus = support::Tree::new("conformance-corpus");
    // Five categories hold a case each; `evasive` and `closure` are
    // deferred, mirroring the real corpus.
    for cat in [
        "ordinary",
        "tricky",
        "primitives",
        "completeness",
        "dependencies",
    ] {
        corpus.dir(&format!("zz/{cat}/a-case/tree"));
        corpus.file(
            &format!("zz/{cat}/a-case/expected.toml"),
            "state = \"complete\"\nexit_code = 0\n",
        );
    }
    Synthetic {
        data,
        corpus,
        schema: schema_for("zz", "zz"),
        deferred: Deferred {
            categories: [
                ("zz/evasive".to_string(), "hardening plan".to_string()),
                ("zz/closure".to_string(), "hardening plan".to_string()),
            ]
            .into_iter()
            .collect(),
            ..Deferred::default()
        },
        labels: "[test]\n\n[test.zz]\n".to_string(),
        frontends: ["zz".to_string()].into_iter().collect(),
    }
}

/// AE1's RED half: a language with no frontend, data, schema entry,
/// corpus dir, or label entry yields every one of the nine findings.
#[test]
fn a_language_with_no_pieces_yields_every_named_finding() {
    let empty = support::Tree::new("conformance-empty");
    let schema = serde_json::json!({});
    let deferred = Deferred::default();
    let inputs = Inputs {
        frontends: BTreeSet::new(),
        data_root: &empty.root,
        schema: &schema,
        corpus_root: &empty.root,
        deferred: &deferred,
        labels: "",
    };
    let v = check(&inputs, "zz", "zz");
    assert_eq!(
        names(&v),
        [
            "frontend-missing",
            "data-file-missing",
            "data-file-missing",
            "data-file-missing",
            "schema-enum-missing",
            "schema-coverage-property-missing",
            "schema-runtime-range-property-missing",
            "corpus-dir-missing",
            "label-entry-missing",
        ]
    );
    for want in ["primitives/zz.toml", "catalog/zz.toml", "inventory/zz.toml"] {
        assert!(v.iter().any(|f| f.detail.contains(want)), "{want}: {v:?}");
    }
}

/// A synthetic language is otherwise complete, so one misplaced
/// `language` key is the only finding.
#[test]
fn a_data_file_whose_language_disagrees_is_named() {
    let s = synthetic();
    s.data.file("catalog/zz.toml", "language = \"python\"\n");
    let v = check(&s.inputs(), "zz", "zz");
    assert_eq!(names(&v), ["data-language-mismatch"], "{v:?}");
    assert!(v[0].detail.contains("data/catalog/zz.toml"), "{v:?}");
}

#[test]
fn a_category_with_no_case_and_no_deferral_is_uncovered() {
    let mut s = synthetic();
    s.deferred.categories.remove("zz/evasive");
    let v = check(&s.inputs(), "zz", "zz");
    assert_eq!(names(&v), ["category-uncovered"], "{v:?}");
    assert!(v[0].detail.contains("evasive"), "{v:?}");
}

#[test]
fn a_deferred_category_is_quiet_until_a_case_lands() {
    let s = synthetic();
    let v = check(&s.inputs(), "zz", "zz");
    assert!(v.is_empty(), "{v:?}");
    // Once a case lands, the deferral is stale and must leave the ledger.
    s.corpus.dir("zz/evasive/a-case");
    let v = check(&s.inputs(), "zz", "zz");
    assert_eq!(names(&v), ["category-deferral-stale"], "{v:?}");
    assert!(v[0].detail.contains("zz/evasive"), "{v:?}");
}

/// `required` is not checked: a schema that lists the language there but
/// not in `properties` still yields the finding.
#[test]
fn coverage_required_does_not_stand_in_for_properties() {
    let mut s = synthetic();
    s.schema["properties"]["completeness"]["properties"]["coverage"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("zz");
    s.schema["properties"]["completeness"]["properties"]["coverage"]["required"]
        .as_array_mut()
        .unwrap()
        .push("zz".into());
    let v = check(&s.inputs(), "zz", "zz");
    assert_eq!(names(&v), ["schema-coverage-property-missing"], "{v:?}");
}

/// The runtime-range check uses the runtime key, not the language name:
/// `node` for javascript, so a schema holding `javascript` under
/// `runtime_range` still fails.
#[test]
fn runtime_range_is_checked_under_its_key_not_the_language_name() {
    let s = synthetic();
    let schema = schema_for("javascript", "javascript");
    let inputs = Inputs {
        schema: &schema,
        ..s.inputs()
    };
    let v = check(&inputs, "javascript", "node");
    let range: Vec<&Finding> = v
        .iter()
        .filter(|f| f.name == "schema-runtime-range-property-missing")
        .collect();
    assert_eq!(range.len(), 1, "{v:?}");
    assert!(range[0].detail.contains("node"), "{v:?}");
    assert!(
        v.iter()
            .all(|f| f.name != "schema-coverage-property-missing"),
        "{v:?}"
    );
}

// ---- the recipe document (U12, R26, R28) -----------------------------------

/// A `### Step N:` section runs from its heading to the next heading of
/// any level. Returns (heading line, section text) pairs in order.
fn recipe_steps(text: &str) -> Vec<(String, &str)> {
    let mut bounds = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.starts_with('#') {
            bounds.push(offset);
        }
        offset += line.len();
    }
    bounds.push(text.len());
    let mut steps = Vec::new();
    for w in bounds.windows(2) {
        let section = &text[w[0]..w[1]];
        let heading = section.lines().next().unwrap_or_default().to_string();
        if heading.starts_with("### Step ") {
            steps.push((heading, section));
        }
    }
    steps
}

/// The tokens between backticks on one line.
fn backticked(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find('`') {
        rest = &rest[i + 1..];
        let Some(j) = rest.find('`') else {
            break;
        };
        out.push(rest[..j].to_string());
        rest = &rest[j + 1..];
    }
    out
}

/// Every test function name in the crates' tests trees: besides the
/// finding names, these are the only citations a `Fails when skipped:`
/// line may use, so the recipe cannot cite a guard that does not exist.
/// Only an attribute at a line's start counts, which keeps test
/// attributes inside fixture string literals out of the list.
fn test_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![repo().join("crates")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
            .flatten()
        {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let in_tests = p.components().any(|c| c.as_os_str() == "tests");
            if !(in_tests && p.extension().is_some_and(|x| x == "rs")) {
                continue;
            }
            let text =
                std::fs::read_to_string(&p).unwrap_or_else(|err| panic!("{}: {err}", p.display()));
            let mut test_attr = false;
            for line in text.lines() {
                let t = line.trim_start();
                if t.starts_with("#[test]") {
                    test_attr = true;
                } else if test_attr && t.starts_with("fn ") {
                    let name: String = t[3..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    names.insert(name);
                    test_attr = false;
                } else if !(t.is_empty() || t.starts_with('#') || t.starts_with("//")) {
                    // Attributes and doc comments may sit between the
                    // attribute and the function; anything else ends it.
                    test_attr = false;
                }
            }
        }
    }
    names
}

/// Every way the recipe fails its side of the contract: a finding named
/// in no step, a mechanical step without a guard line, a guard line
/// citing a name that is neither a finding nor a real test, a missing
/// next-language record, and the characters the writing rules forbid.
fn recipe_violations(text: &str, tests: &BTreeSet<String>) -> Vec<String> {
    let mut v = Vec::new();
    for (ch, what) in [
        ('\u{2014}', "em dash"),
        ('\u{2013}', "en dash"),
        ('\u{2018}', "curly single quote"),
        ('\u{2019}', "curly single quote"),
        ('\u{201C}', "curly double quote"),
        ('\u{201D}', "curly double quote"),
        ('\u{2026}', "ellipsis character"),
    ] {
        if text.contains(ch) {
            v.push(format!("the document holds a {what} (U+{:04X})", ch as u32));
        }
    }
    let steps = recipe_steps(text);
    if steps.is_empty() {
        v.push("the document has no `### Step` sections".to_string());
    }
    for name in FINDING_NAMES {
        if !steps.iter().any(|(_, s)| s.contains(name)) {
            v.push(format!("finding `{name}` is named in no step"));
        }
    }
    for (heading, section) in &steps {
        // The guard is a paragraph: it starts at `Fails when skipped:` and
        // runs to the next blank line or heading, so a citation wrapped
        // onto a continuation line is still checked.
        let mut has_fails = false;
        let mut in_fails = false;
        for line in section.lines() {
            let t = line.trim_start();
            if t.starts_with("Fails when skipped:") {
                has_fails = true;
                in_fails = true;
            } else if in_fails && (t.is_empty() || t.starts_with('#')) {
                in_fails = false;
            }
            if in_fails {
                for tok in backticked(t) {
                    if !FINDING_NAMES.contains(&tok.as_str()) && !tests.contains(&tok) {
                        v.push(format!(
                            "{heading:?}: `{tok}` is no finding name and no test function"
                        ));
                    }
                }
            }
        }
        if !has_fails && !heading.contains("(judgment)") {
            v.push(format!(
                "mechanical step {heading:?} carries no `Fails when skipped:` line"
            ));
        }
    }
    if !text
        .lines()
        .any(|l| l.starts_with('#') && l.contains("Java") && l.to_lowercase().contains("next"))
    {
        v.push("no section names Java as the next language".to_string());
    }
    if !text.contains("Kotlin") {
        v.push("Kotlin is never mentioned".to_string());
    }
    if !text.contains("parser") {
        v.push("the parser question is not recorded".to_string());
    }
    v
}

fn recipe_text() -> String {
    let path = repo().join("docs/adding-a-language.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// R26: the committed recipe names every finding inside a step section
/// and cites only tests that exist. R28: it records Java as next.
#[test]
fn recipe_names_every_conformance_finding() {
    let v = recipe_violations(&recipe_text(), &test_names());
    assert!(v.is_empty(), "recipe violations:\n  {}", v.join("\n  "));
}

/// Removing one finding's coverage is reported by name.
#[test]
fn a_recipe_dropping_a_finding_name_fails_naming_it() {
    let text = recipe_text().replace("label-entry-missing", "frontend-missing");
    let v = recipe_violations(&text, &test_names());
    assert!(v.iter().any(|s| s.contains("label-entry-missing")), "{v:?}");
}

/// A citation that is neither a finding name nor a real test is
/// reported: the document cannot point at a guard that does not exist.
#[test]
fn a_recipe_citing_a_test_that_does_not_exist_fails_naming_it() {
    let text = recipe_text().replacen(
        "no_deny_list_module_is_wholly_inert",
        "no_such_guard_exists",
        1,
    );
    let v = recipe_violations(&text, &test_names());
    assert!(
        v.iter().any(|s| s.contains("no_such_guard_exists")),
        "{v:?}"
    );
}

/// Finding names in the introduction do not count: each must appear
/// inside a step section.
#[test]
fn finding_names_outside_any_step_do_not_count() {
    let text = recipe_text();
    let first_step = text.find("### Step ").unwrap_or_else(|| panic!("no steps"));
    let (head, tail) = text.split_at(first_step);
    let mut tail = tail.to_string();
    for name in FINDING_NAMES {
        tail = tail.replace(name, "the omitted finding");
    }
    let text = format!("{head}\n{}\n{tail}", FINDING_NAMES.join(", "));
    let v = recipe_violations(&text, &test_names());
    let unreported: Vec<&&str> = FINDING_NAMES
        .iter()
        .filter(|n| !v.iter().any(|s| s.contains(**n)))
        .collect();
    assert!(unreported.is_empty(), "not reported: {unreported:?}\n{v:?}");
}

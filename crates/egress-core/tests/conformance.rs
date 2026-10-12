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
const FRONTEND_PENDING: &[&str] = &["go"];

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

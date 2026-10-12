//! The language table: `Language::ALL` plus one spec row per language
//! drives extension and shebang routing, manifest ownership, data
//! loading, and the coverage and runtime-range maps.

mod common;
mod support;

use egress_core::data::{EMBEDDED, load};
use egress_core::discover::manifests::ManifestKind;
use egress_core::discover::{Config, FileKind, discover};
use egress_core::json::to_json;
use egress_core::model::*;
use support::Tree;

/// A coverage map filled in reverse table order still serializes in
/// table order, `unsupported` last.
#[test]
fn coverage_keys_follow_the_language_table() {
    let mut r = common::report(vec![], vec![]);
    let mut languages = LanguageMap::default();
    for lang in Language::ALL.iter().rev() {
        languages.insert(
            *lang,
            CoverageCounts {
                scanned: 1,
                skipped: 0,
            },
        );
    }
    r.completeness.coverage.languages = languages;
    let json = to_json(&r);
    let coverage = &json[json.find("\"coverage\"").unwrap()..json.find("\"caveats\"").unwrap()];
    let keys = [
        "\"python\"",
        "\"javascript\"",
        "\"rust\"",
        "\"go\"",
        "\"unsupported\"",
    ];
    let pos: Vec<usize> = keys
        .iter()
        .map(|k| {
            coverage
                .find(k)
                .unwrap_or_else(|| panic!("no {k} in {coverage}"))
        })
        .collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}\n{coverage}");
}

/// The runtime-range map emits the javascript entry under `node` and
/// all keys in table order, whatever order the map was filled in.
#[test]
fn runtime_range_uses_the_node_key_for_javascript() {
    let mut r = common::report(vec![], vec![]);
    r.tool.runtime_range = [
        (Language::Rust, "c".to_string()),
        (Language::Javascript, "a".to_string()),
        (Language::Python, "b".to_string()),
    ]
    .into_iter()
    .collect();
    let json = to_json(&r);
    let rr = &json[json.find("\"runtime_range\"").unwrap()..json.find("\"completeness\"").unwrap()];
    let pos: Vec<usize> = ["\"python\"", "\"node\"", "\"rust\""]
        .iter()
        .map(|k| rr.find(k).unwrap_or_else(|| panic!("no {k} in {rr}")))
        .collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}\n{rr}");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["tool"]["runtime_range"]["node"], "a");
    assert_eq!(v["tool"]["runtime_range"]["python"], "b");
    assert_eq!(v["tool"]["runtime_range"]["rust"], "c");
}

/// A data file whose `language` key disagrees with the runtime it is
/// loaded as fails, naming the file.
#[test]
fn a_data_file_with_the_wrong_language_key_fails_naming_it() {
    let files: Vec<(&str, &str)> = EMBEDDED
        .iter()
        .map(|f| {
            (
                f.path,
                if f.path == "data/primitives/javascript.toml" {
                    "language = \"python\"\nruntime_range = \"18-22\"\n"
                } else {
                    f.text
                },
            )
        })
        .collect();
    let e = load(&files).unwrap_err();
    assert!(
        e.contains("data/primitives/javascript.toml") && e.contains("python"),
        "{e}"
    );
}

/// Extensions no spec row lists stay `Other`; `.go` routes to Go while
/// `main.GO` is a case-sensitive miss; a `python3` shebang still routes
/// to Python.
#[test]
fn unrouted_extensions_stay_other_and_shebangs_route() {
    let t = Tree::new("language-table");
    t.file("main.go", "package main\n")
        .file("main.GO", "package main\n")
        .file("prog.hs", "main = pure ()\n")
        .file("tool", "#!/usr/bin/env python3\nprint(1)\n");
    let d = discover(&t.root, &Config::default()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        d.index.get(b"main.go".as_slice()),
        Some(&FileKind::Source(Language::Go))
    );
    assert_eq!(d.index.get(b"main.GO".as_slice()), Some(&FileKind::Other));
    assert_eq!(d.index.get(b"prog.hs".as_slice()), Some(&FileKind::Other));
    let tool = d
        .sources
        .iter()
        .find(|s| s.file.display == "tool")
        .unwrap_or_else(|| panic!("the shebang file was not admitted"));
    assert_eq!(tool.language, Language::Python);
}

/// Every manifest kind is claimed by exactly one spec row, and every
/// name a spec row lists resolves back to a kind of that language.
#[test]
fn manifest_kinds_route_through_the_language_table() {
    for kind in ManifestKind::ALL {
        let owners: Vec<Language> = Language::ALL
            .into_iter()
            .filter(|l| {
                l.spec()
                    .manifests
                    .iter()
                    .any(|m| m.as_bytes() == kind.file_name())
            })
            .collect();
        assert_eq!(owners, [kind.language()], "{:?}", kind.file_name());
    }
    for lang in Language::ALL {
        for name in lang.spec().manifests {
            let kind = ManifestKind::for_name(name.as_bytes())
                .unwrap_or_else(|| panic!("{name} names no manifest kind"));
            assert_eq!(kind.language(), lang, "{name}");
        }
    }
}

/// The spec row's name is the `as_str` form, so data files, corpus
/// directories, and `data/labels.toml` per-language tables share one
/// key.
#[test]
fn spec_names_match_as_str() {
    for lang in Language::ALL {
        assert_eq!(lang.spec().name, lang.as_str());
        assert_eq!(Language::parse(lang.spec().name), Some(lang));
    }
}

//! Dependency-mode resolution inside installed code (KTD10): a
//! per-instance pass through `tree::run` with the frontends'
//! `dependency_rules` installed as overrides. Python probes only the
//! import root; JavaScript and Rust reuse the rules their scoped
//! discovery builds.

#[path = "../../egress-core/tests/support/mod.rs"]
mod support;

use std::collections::BTreeSet;

use egress_core::data::Data;
use egress_core::discover::open::RootDir;
use egress_core::discover::{Config, Discovery, discover_scoped};
use egress_core::model::{BlindSpotKind, Language};
use egress_core::resolve::SpecifierRules;
use egress_scan::tree::{self, TreePass};
use egress_scan::{Registry, ScanOptions};
use support::Tree;

fn data() -> &'static Data {
    static DATA: std::sync::OnceLock<Data> = std::sync::OnceLock::new();
    DATA.get_or_init(|| Data::embedded().expect("embedded data"))
}

fn scoped(t: &Tree, root: &str, prefixes: &[&str]) -> Discovery {
    let rootdir = RootDir::open(&t.path(root)).unwrap();
    let ps: Vec<&[u8]> = prefixes.iter().map(|p| p.as_bytes()).collect();
    discover_scoped(&rootdir, &ps, &Config::default(), None).unwrap()
}

/// Runs the dependency pass over `root`/`prefixes` with each frontend's
/// `dependency_rules` installed as the language override (KTD10).
fn dependency_pass(t: &Tree, root: &str, prefixes: &[&str], import_root: &[u8]) -> TreePass {
    let d = scoped(t, root, prefixes);
    let options = ScanOptions::default();
    let registry = Registry::builtin();
    let mut overrides: Vec<(Language, Box<dyn SpecifierRules>)> = Vec::new();
    for lang in Language::ALL {
        if let Some(rules) = registry
            .get(lang)
            .and_then(|fe| fe.dependency_rules(import_root))
        {
            overrides.push((lang, rules));
        }
    }
    tree::run(
        data(),
        &d,
        &options,
        &tree::TreeOptions {
            overrides: &overrides,
            resolver_budget: Config::default().budgets.resolver_steps,
        },
    )
    .unwrap()
}

/// The same pass with no overrides: first-party `PythonRules` and the
/// linked/repo rules, as `scan_with` runs it.
fn first_party_pass(t: &Tree, root: &str, prefixes: &[&str]) -> TreePass {
    let d = scoped(t, root, prefixes);
    let options = ScanOptions::default();
    tree::run(
        data(),
        &d,
        &options,
        &tree::TreeOptions {
            overrides: &[],
            resolver_budget: Config::default().budgets.resolver_steps,
        },
    )
    .unwrap()
}

fn packages(pass: &TreePass) -> BTreeSet<String> {
    pass.classified
        .unscanned_dependencies
        .iter()
        .map(|d| format!("{}:{}", d.language.as_str(), d.package))
        .collect()
}

#[test]
fn dependency_rules_hook_replaces_only_python_rules() {
    let r = Registry::builtin();
    assert!(
        r.get(Language::Python)
            .unwrap()
            .dependency_rules(b"")
            .is_some()
    );
    assert!(
        r.get(Language::Javascript)
            .unwrap()
            .dependency_rules(b"")
            .is_none()
    );
    assert!(
        r.get(Language::Rust)
            .unwrap()
            .dependency_rules(b"")
            .is_none()
    );
}

#[test]
fn absolute_imports_probe_only_the_import_root() {
    // `import widget.core` resolves inside the package. `import
    // pooler` and `import urllib3` probe the import root only, so the
    // decoys beside the importing file are never seen: `pooler`
    // resolves external and `urllib3` reports no `shadowed-module`.
    let t = Tree::new("dep-import-root");
    t.file(
        "sitepk/widget/__init__.py",
        "import widget.core\nimport pooler\nimport urllib3\n",
    );
    t.file("sitepk/widget/core.py", "class A:\n    pass\n");
    t.file("sitepk/widget/pooler.py", "def decoy():\n    pass\n");
    t.file("sitepk/widget/urllib3.py", "def decoy():\n    pass\n");
    let pass = dependency_pass(&t, "sitepk", &["widget"], b"");
    assert_eq!(
        packages(&pass),
        BTreeSet::from(["python:pooler".to_string()]),
        "{:?}",
        pass.classified.unscanned_dependencies
    );
    assert!(pass.blind_spots.is_empty(), "{:?}", pass.blind_spots);
    // First-party rules probe the importing file's ancestors: both
    // decoys resolve first-party, and `urllib3` reports
    // `shadowed-module` because it is a catalogued egress name.
    let fp = first_party_pass(&t, "sitepk", &["widget"]);
    assert_eq!(
        packages(&fp),
        BTreeSet::new(),
        "{:?}",
        fp.classified.unscanned_dependencies
    );
    assert!(
        fp.blind_spots
            .iter()
            .any(|b| b.kind == BlindSpotKind::ShadowedModule),
        "{:?}",
        fp.blind_spots
    );
}

#[test]
fn relative_imports_resolve_inside_the_package() {
    let t = Tree::new("dep-relative");
    t.file("sitepk/requests/__init__.py", "from . import adapters\n");
    t.file("sitepk/requests/adapters.py", "class A:\n    pass\n");
    let pass = dependency_pass(&t, "sitepk", &["requests"], b"");
    assert_eq!(
        packages(&pass),
        BTreeSet::new(),
        "{:?}",
        pass.classified.unscanned_dependencies
    );
    assert!(pass.blind_spots.is_empty(), "{:?}", pass.blind_spots);
}

#[test]
fn must_not_dependency_sibling_shadow() {
    // AE15: foo/client.py imports http.client beside foo/http.py. The
    // dependency pass reports no `shadowed-module` blind spot; the same
    // files under first-party rules report one, so the fixture
    // discriminates.
    let t = Tree::new("dep-shadow");
    t.file("sitepk/foo/__init__.py", "from . import client\n");
    t.file(
        "sitepk/foo/client.py",
        "import http.client\n\ndef connect():\n    return http.client.HTTPConnection('egress.example')\n",
    );
    t.file("sitepk/foo/http.py", "def decoy():\n    return None\n");
    let pass = dependency_pass(&t, "sitepk", &["foo"], b"");
    assert!(
        !pass
            .blind_spots
            .iter()
            .any(|b| b.kind == BlindSpotKind::ShadowedModule),
        "{:?}",
        pass.blind_spots
    );
    assert!(
        pass.classified
            .sites
            .iter()
            .any(|s| s.mechanism == "python:http.client.HTTPConnection"),
        "{:?}",
        pass.classified.sites
    );
    let fp = first_party_pass(&t, "sitepk", &["foo"]);
    assert!(
        fp.blind_spots
            .iter()
            .any(|b| b.kind == BlindSpotKind::ShadowedModule),
        "{:?}",
        fp.blind_spots
    );
}

#[test]
fn namespace_package_import_is_not_a_self_dependency() {
    // AE14: inside google/auth/, `from google import auth` names
    // `google.auth`, the scanning package's own key, which the closure
    // drops. The pass records the import, never a `google.auth`
    // dependency.
    let t = Tree::new("dep-namespace");
    t.file(
        "sitepk/google/auth/__init__.py",
        "from google import auth\n",
    );
    t.file(
        "sitepk/google/auth/session.py",
        "def load():\n    return {}\n",
    );
    let pass = dependency_pass(&t, "sitepk", &["google/auth"], b"");
    assert_eq!(
        packages(&pass),
        BTreeSet::from(["python:google".to_string()]),
        "{:?}",
        pass.classified.unscanned_dependencies
    );
    let rec = &pass.classified.unscanned_imports[&(Language::Python, "google".to_string())];
    assert!(rec.specifiers.contains("google.auth"), "{rec:?}");
    assert!(rec.members.contains("auth"), "{rec:?}");
}

#[test]
fn js_dependency_pass_resolves_its_own_name_and_lists_externals() {
    // KTD10: JavaScript reuses `JsRules` built from the scoped
    // discovery; the hook returns no override.
    let t = Tree::new("dep-js");
    t.file(
        "node_modules/leftpad/package.json",
        "{\"name\": \"leftpad\", \"main\": \"index.js\"}\n",
    );
    t.file(
        "node_modules/leftpad/index.js",
        "const lp = require('leftpad');\nconst padder = require('padder');\nmodule.exports = lp;\n",
    );
    let pass = dependency_pass(&t, "node_modules", &["leftpad"], b"");
    assert_eq!(
        packages(&pass),
        BTreeSet::from(["javascript:padder".to_string()]),
        "{:?}",
        pass.classified.unscanned_dependencies
    );
    assert!(pass.blind_spots.is_empty(), "{:?}", pass.blind_spots);
}

#[test]
fn rust_dependency_pass_keeps_manifest_renames() {
    // KTD10: Rust reuses `RustRules` built by `link` over the scoped
    // discovery; `use foo::x` with `foo = { package = "bar" }` names
    // the real package.
    let t = Tree::new("dep-rust-rename");
    t.file(
        "crate/Cargo.toml",
        "[package]\nname = \"mine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nfoo = { package = \"bar\", version = \"1\" }\n",
    );
    t.file("crate/src/lib.rs", "use foo::x;\n");
    let pass = dependency_pass(&t, "crate", &["src", "Cargo.toml"], b"");
    assert_eq!(
        packages(&pass),
        BTreeSet::from(["rust:bar".to_string()]),
        "{:?}",
        pass.classified.unscanned_dependencies
    );
}

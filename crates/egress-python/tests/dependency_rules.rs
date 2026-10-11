//! Dependency-mode Python specifier rules (KTD10): absolute imports
//! probe only the import root, relative imports resolve exactly as
//! first-party, and a sibling module can never shadow a standard
//! library name (AE15). `PythonRules` itself is unchanged.

use egress_core::resolve::{SpecifierKind, SpecifierRules};
use egress_python::{DependencyPythonRules, PythonRules};

fn b(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn bare(spec: &str, probes: &[&str]) -> SpecifierKind {
    SpecifierKind::Bare {
        probes: probes.iter().map(|p| b(p)).collect(),
        module: spec.into(),
    }
}

fn path(probes: &[&str]) -> SpecifierKind {
    SpecifierKind::Path {
        probes: probes.iter().map(|p| b(p)).collect(),
    }
}

#[test]
fn absolute_imports_probe_only_the_import_root() {
    let rules = DependencyPythonRules {
        import_root: b"site-packages".to_vec(),
    };
    assert_eq!(
        rules.classify(b"site-packages/requests/api.py", "urllib3"),
        bare(
            "urllib3",
            &[
                "site-packages/urllib3.py",
                "site-packages/urllib3/__init__.py",
            ],
        )
    );
    // An empty import root is the discovered root itself.
    let rules = DependencyPythonRules {
        import_root: Vec::new(),
    };
    assert_eq!(
        rules.classify(b"requests/api.py", "urllib3"),
        bare("urllib3", &["urllib3.py", "urllib3/__init__.py"])
    );
    // A dotted specifier probes its full path under the root only.
    assert_eq!(
        rules.classify(b"requests/api.py", "requests.adapters"),
        bare(
            "requests.adapters",
            &["requests/adapters.py", "requests/adapters/__init__.py",],
        )
    );
}

#[test]
fn must_not_probe_the_importing_files_ancestors() {
    // AE15: `import http` in foo/client.py must not probe foo/http.py;
    // under `PythonRules` the ancestor probe would find it and report a
    // shadowed module.
    let dep = DependencyPythonRules {
        import_root: Vec::new(),
    };
    assert_eq!(
        dep.classify(b"foo/client.py", "http"),
        bare("http", &["http.py", "http/__init__.py"])
    );
    let fp = PythonRules.classify(b"foo/client.py", "http");
    assert_eq!(
        fp,
        bare(
            "http",
            &[
                "http.py",
                "http/__init__.py",
                "src/http.py",
                "src/http/__init__.py",
                "foo/http.py",
                "foo/http/__init__.py",
            ],
        )
    );
}

#[test]
fn relative_imports_resolve_as_first_party() {
    let rules = DependencyPythonRules {
        import_root: Vec::new(),
    };
    assert_eq!(
        rules.classify(b"requests/__init__.py", "."),
        path(&["requests/__init__.py"])
    );
    assert_eq!(
        rules.classify(b"requests/api.py", ".adapters"),
        path(&["requests/adapters.py", "requests/adapters/__init__.py",])
    );
    assert_eq!(
        rules.classify(b"requests/__init__.py", "..x"),
        path(&["x.py", "x/__init__.py"])
    );
    assert_eq!(
        rules.classify(b"requests/__init__.py", "...x"),
        SpecifierKind::OutsideRoot
    );
    // `from . import adapters` reaches the submodule through
    // `submodule`, as it does first-party.
    assert_eq!(
        rules.submodule(".", "adapters").as_deref(),
        Some(".adapters")
    );
    assert_eq!(rules.submodule("a", "b").as_deref(), Some("a.b"));
}

#[test]
fn must_not_change_first_party_python_rules() {
    // The probe lists `PythonRules` produces today, verbatim: the scan
    // root, `src/`, then the importing file's ancestors deepest first.
    let rules = PythonRules;
    assert_eq!(
        rules.classify(b"site-packages/requests/api.py", "urllib3"),
        bare(
            "urllib3",
            &[
                "urllib3.py",
                "urllib3/__init__.py",
                "src/urllib3.py",
                "src/urllib3/__init__.py",
                "site-packages/requests/urllib3.py",
                "site-packages/requests/urllib3/__init__.py",
                "site-packages/urllib3.py",
                "site-packages/urllib3/__init__.py",
            ],
        )
    );
    assert_eq!(
        rules.classify(b"a/b/c.py", "http.client"),
        bare(
            "http.client",
            &[
                "http/client.py",
                "http/client/__init__.py",
                "src/http/client.py",
                "src/http/client/__init__.py",
                "a/b/http/client.py",
                "a/b/http/client/__init__.py",
                "a/http/client.py",
                "a/http/client/__init__.py",
            ],
        )
    );
    assert_eq!(rules.classify(b"a/b/c.py", "."), path(&["a/b/__init__.py"]));
    assert_eq!(
        rules.classify(b"a/b/c.py", ".util"),
        path(&["a/b/util.py", "a/b/util/__init__.py"])
    );
    assert_eq!(
        rules.classify(b"a/b/c.py", "..util"),
        path(&["a/util.py", "a/util/__init__.py"])
    );
    assert_eq!(
        rules.classify(b"a/b/c.py", "...util"),
        path(&["util.py", "util/__init__.py"])
    );
    assert_eq!(
        rules.classify(b"a/b/c.py", "....util"),
        SpecifierKind::OutsideRoot
    );
    assert_eq!(rules.classify(b"a.py", "a..b"), bare("a..b", &[]));
}

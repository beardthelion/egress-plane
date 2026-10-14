//! Discovery: walk, routing, exclusions, labels, symlinks, and path encoding.

mod support;

use egress_core::discover::{Config, Discovery, FileKind, discover};
use egress_core::model::{BlindSpotKind, ExcludedReason, Label, Language, ToolError};
use support::{Tree, privileged};

fn run(t: &Tree) -> Discovery {
    discover(&t.root, &Config::default()).unwrap_or_else(|e| panic!("tool error: {e}"))
}

fn spots(d: &Discovery) -> Vec<(String, BlindSpotKind)> {
    let mut v: Vec<_> = d
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind))
        .collect();
    v.sort();
    v
}

fn excluded(d: &Discovery) -> Vec<(String, ExcludedReason)> {
    let mut v: Vec<_> = d
        .excluded
        .iter()
        .map(|x| (x.path.clone(), x.reason))
        .collect();
    v.sort();
    v
}

fn sources(d: &Discovery) -> Vec<(String, Language)> {
    d.sources
        .iter()
        .map(|s| (s.file.display.clone(), s.language))
        .collect()
}

/// Every string discovery could put in a report.
fn all_text(d: &Discovery) -> String {
    let mut s = String::new();
    for b in &d.blind_spots {
        s += &format!("{} {} {}\n", b.file, b.symbol, b.construct);
    }
    for x in &d.excluded {
        s += &format!("{}\n", x.path);
    }
    for f in &d.sources {
        s += &format!("{}\n", f.file.display);
    }
    s
}

// ---- file types and routing ------------------------------------------------

#[test]
fn notebook_is_unsupported_and_skipped() {
    let t = Tree::new("ipynb");
    t.file("app.py", "x = 1\n").file("analysis.ipynb", "{}");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("analysis.ipynb".into(), BlindSpotKind::UnsupportedFileType)]
    );
    let b = &d.blind_spots[0];
    assert!(b.whole_file && b.coverage_gap);
    assert_eq!(d.coverage.unsupported.skipped, 1);
    assert_eq!(sources(&d), vec![("app.py".into(), Language::Python)]);
}

#[test]
fn haskell_only_tree_has_no_supported_files() {
    let t = Tree::new("haskell");
    t.file(
        "Main.hs",
        "module Main where\nmain :: IO ()\nmain = pure ()\n",
    );
    let d = run(&t);
    assert!(d.sources.is_empty());
    assert!(d.blind_spots.is_empty());
    assert!(d.languages.is_empty());
    assert_eq!(d.index.get(b"Main.hs".as_slice()), Some(&FileKind::Other));
}

#[test]
fn sourceless_and_archived_python_are_unsupported() {
    let t = Tree::new("pyc");
    t.file("pkg/mod.pyc", [0u8, 1, 2])
        .file("a.pyz", "x")
        .file("b.egg", "x")
        .file("c.whl", "x")
        .file("d.WASM", "x");
    let d = run(&t);
    let kinds: Vec<_> = spots(&d);
    assert_eq!(
        kinds,
        vec![
            ("a.pyz".into(), BlindSpotKind::UnsupportedFileType),
            ("b.egg".into(), BlindSpotKind::UnsupportedFileType),
            ("c.whl".into(), BlindSpotKind::UnsupportedFileType),
            ("d.WASM".into(), BlindSpotKind::UnsupportedFileType),
            ("pkg/mod.pyc".into(), BlindSpotKind::UnsupportedFileType),
        ]
    );
    assert_eq!(d.coverage.unsupported.skipped, 5);
}

#[test]
fn every_supported_extension_routes_to_its_language() {
    let t = Tree::new("exts");
    for f in ["a.py", "b.pyi", "c.pyw"] {
        t.file(f, "");
    }
    for f in [
        "d.js", "e.mjs", "f.cjs", "g.jsx", "h.ts", "i.tsx", "j.mts", "k.cts",
    ] {
        t.file(f, "");
    }
    t.file("l.rs", "");
    let d = run(&t);
    let langs: Vec<Language> = d.sources.iter().map(|s| s.language).collect();
    assert_eq!(langs.iter().filter(|l| **l == Language::Python).count(), 3);
    assert_eq!(
        langs.iter().filter(|l| **l == Language::Javascript).count(),
        8
    );
    assert_eq!(langs.iter().filter(|l| **l == Language::Rust).count(), 1);
}

#[test]
fn shebang_routes_extensionless_scripts() {
    let t = Tree::new("shebang");
    t.file("bin/tool", "#!/usr/bin/env python3\nprint(1)\n")
        .file("bin/serve", "#!/usr/bin/env node\nconsole.log(1)\n")
        .file("bin/py2", "#!/usr/bin/python3.12 -u\n")
        .file("bin/denotool", "#!/usr/bin/env -S deno run\n")
        .file("bin/buntool", "#!/usr/local/bin/bun\n")
        .file("bin/deploy", "#!/bin/sh\necho hi\n")
        .file("Makefile", "all:\n");
    let d = run(&t);
    assert_eq!(
        sources(&d),
        vec![
            ("bin/buntool".into(), Language::Javascript),
            ("bin/denotool".into(), Language::Javascript),
            ("bin/py2".into(), Language::Python),
            ("bin/serve".into(), Language::Javascript),
            ("bin/tool".into(), Language::Python),
        ]
    );
    assert!(d.blind_spots.is_empty(), "{:?}", spots(&d));
    assert_eq!(
        d.index.get(b"bin/deploy".as_slice()),
        Some(&FileKind::Other)
    );
}

// ---- exclusions -------------------------------------------------------------

#[test]
fn venv_without_home_is_an_unconfirmed_exclusion() {
    let t = Tree::new("venv-unconfirmed");
    t.file("src/app.py", "")
        .file("src/lib/pyvenv.cfg", "version = 3.12.3\n")
        .file("src/lib/client.py", "import socket\n");
    let d = run(&t);
    assert_eq!(
        excluded(&d),
        vec![("src/lib".into(), ExcludedReason::UnconfirmedInstallOutput)]
    );
    assert_eq!(
        spots(&d),
        vec![("src/lib".into(), BlindSpotKind::UnconfirmedExclusion)]
    );
    let b = &d.blind_spots[0];
    assert!(b.coverage_gap && !b.whole_file);
    assert_eq!(sources(&d), vec![("src/app.py".into(), Language::Python)]);
}

#[test]
fn venv_with_home_is_excluded_without_a_gap() {
    let t = Tree::new("venv-confirmed");
    t.file("src/app.py", "")
        .file("src/lib/pyvenv.cfg", "home = /usr/bin\nversion = 3.12.3\n")
        .file("src/lib/client.py", "import socket\n");
    let d = run(&t);
    assert_eq!(
        excluded(&d),
        vec![("src/lib".into(), ExcludedReason::InstallOutput)]
    );
    assert!(d.blind_spots.is_empty(), "{:?}", spots(&d));
    assert!(!d.index.contains_key(b"src/lib/client.py".as_slice()));
}

#[test]
fn planted_markers_are_unconfirmed_and_real_ones_confirmed() {
    let t = Tree::new("markers");
    let tag = "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n";
    t.file("src/CACHEDIR.TAG", tag)
        .file("src/main.py", "")
        .file("web/node_modules/x.js", "")
        .file("web/index.js", "")
        .file(
            "Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        )
        .file("target/CACHEDIR.TAG", tag)
        .file("target/debug/gen.rs", "")
        .file("package.json", "{}")
        .file("node_modules/dep/index.js", "")
        .file("lib/modules/m.js", "");
    let d = run(&t);
    assert_eq!(
        excluded(&d),
        vec![
            ("node_modules".into(), ExcludedReason::InstallOutput),
            ("src".into(), ExcludedReason::UnconfirmedInstallOutput),
            ("target".into(), ExcludedReason::InstallOutput),
            (
                "web/node_modules".into(),
                ExcludedReason::UnconfirmedInstallOutput
            ),
        ]
    );
    assert_eq!(
        spots(&d),
        vec![
            ("src".into(), BlindSpotKind::UnconfirmedExclusion),
            (
                "web/node_modules".into(),
                BlindSpotKind::UnconfirmedExclusion
            ),
        ]
    );
    // A directory merely named `modules` is walked; confirmed install output
    // is never walked.
    assert!(d.index.contains_key(b"lib/modules/m.js".as_slice()));
    assert!(!d.index.keys().any(|k| k.starts_with(b"node_modules")));
}

#[test]
fn unconfirmed_exclusion_without_supported_files_is_not_a_gap() {
    let t = Tree::new("target-docs");
    t.file("app.py", "").file("target/notes.txt", "x");
    let d = run(&t);
    assert_eq!(
        excluded(&d),
        vec![("target".into(), ExcludedReason::UnconfirmedInstallOutput)]
    );
    assert!(d.blind_spots.is_empty());
}

#[test]
fn gitignore_does_not_exclude() {
    let t = Tree::new("gitignore");
    t.file(".gitignore", "secret.py\nbuild/\n")
        .file("secret.py", "")
        .file("build/gen.py", "");
    let d = run(&t);
    let s = sources(&d);
    assert!(s.contains(&("secret.py".into(), Language::Python)));
    assert!(s.contains(&("build/gen.py".into(), Language::Python)));
}

#[test]
fn git_directories_are_excluded_and_gap_only_with_supported_files() {
    let t = Tree::new("git");
    t.file(".git/HEAD", "ref: refs/heads/main\n")
        .file(".git/hooks/pre-commit.sample", "#!/bin/sh\n")
        .file("sub/.git/hooks/evil.py", "import os\n")
        .file("app.py", "");
    let d = run(&t);
    assert_eq!(
        excluded(&d),
        vec![
            (".git".into(), ExcludedReason::Vcs),
            ("sub/.git".into(), ExcludedReason::Vcs),
        ]
    );
    assert_eq!(
        spots(&d),
        vec![("sub/.git".into(), BlindSpotKind::UnconfirmedExclusion)]
    );
}

// ---- labels -----------------------------------------------------------------

#[test]
fn path_labels_never_change_what_is_scanned() {
    let t = Tree::new("labels");
    t.file("vendor/httplib_copy/client.py", "")
        .file("dist/app.min.js", "")
        .file("tests/test_api.py", "")
        .file("src/api.spec.ts", "")
        .file("src/main.py", "");
    let d = run(&t);
    let labels = |p: &str| -> Vec<Label> {
        d.sources
            .iter()
            .find(|s| s.file.display == p)
            .unwrap_or_else(|| panic!("{p} not scanned"))
            .labels
            .clone()
    };
    assert_eq!(
        labels("vendor/httplib_copy/client.py"),
        vec![Label::Vendored]
    );
    assert_eq!(
        labels("dist/app.min.js"),
        vec![Label::Generated, Label::Minified]
    );
    assert_eq!(labels("tests/test_api.py"), vec![Label::Test]);
    assert_eq!(labels("src/api.spec.ts"), vec![Label::Test]);
    assert_eq!(labels("src/main.py"), vec![]);
}

/// The Go label rules are language-scoped: `*_test.go` and `testdata`
/// dirs carry `test`, but only for Go files.
#[test]
fn go_test_labels_apply_to_go_files_only() {
    let t = Tree::new("go-labels");
    t.file("pkg/a.go", "package pkg\n")
        .file("pkg/a_test.go", "package pkg\n")
        .file("pkg/testdata/golden.go", "package testdata\n")
        .file("pkg/testdata/golden.py", "x = 1\n")
        .file("main.py", "x = 1\n");
    let d = run(&t);
    let labels = |p: &str| -> Vec<Label> {
        d.sources
            .iter()
            .find(|s| s.file.display == p)
            .unwrap_or_else(|| panic!("{p} not scanned"))
            .labels
            .clone()
    };
    assert_eq!(labels("pkg/a.go"), vec![]);
    assert_eq!(labels("pkg/a_test.go"), vec![Label::Test]);
    assert_eq!(labels("pkg/testdata/golden.go"), vec![Label::Test]);
    assert_eq!(labels("pkg/testdata/golden.py"), vec![]);
    assert_eq!(labels("main.py"), vec![]);
}

// ---- symlinks ---------------------------------------------------------------

#[test]
fn outside_link_is_reported_and_target_never_printed() {
    let t = Tree::new("symlinks");
    let target = t.outside_file("payload_dir/evil.py", "import socket\n");
    t.file("src/real.py", "x = 1\n")
        .link("src/evil.py", &target)
        .link("src/alias.py", "real.py");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("src/evil.py".into(), BlindSpotKind::SymlinkOutsideRoot)]
    );
    assert_eq!(
        excluded(&d),
        vec![("src/alias.py".into(), ExcludedReason::SymlinkAlias)]
    );
    // The real file is scanned once, under its own path.
    assert_eq!(sources(&d), vec![("src/real.py".into(), Language::Python)]);
    let text = all_text(&d);
    assert!(!text.contains("payload_dir"), "{text}");
    assert!(!text.contains(&*t.outside.to_string_lossy()), "{text}");
    assert_eq!(d.coverage.languages[Language::Python].skipped, 1);
}

#[test]
fn outside_target_in_unsearchable_directory_is_never_touched() {
    if privileged() {
        return;
    }
    let t = Tree::new("hostile");
    let target = t.outside_file("locked/x.py", "import socket\n");
    support::chmod(&t.outside.join("locked"), 0o000);
    t.file("src/app.py", "").link("src/share.py", &target);
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("src/share.py".into(), BlindSpotKind::SymlinkOutsideRoot)]
    );
}

#[test]
fn climbing_and_chained_links_are_outside_by_lexical_resolution() {
    let t = Tree::new("climb");
    t.outside_file("x.py", "");
    t.file("src/app.py", "")
        .link("src/up.py", "../../outside/x.py")
        .link("a.py", "b.py")
        .link("b.py", "../outside.py")
        .link("deep/abs_climb.py", "../../root/../outside/x.py");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![
            ("a.py".into(), BlindSpotKind::SymlinkOutsideRoot),
            ("b.py".into(), BlindSpotKind::SymlinkOutsideRoot),
            (
                "deep/abs_climb.py".into(),
                BlindSpotKind::SymlinkOutsideRoot
            ),
            ("src/up.py".into(), BlindSpotKind::SymlinkOutsideRoot),
        ]
    );
    assert!(!all_text(&d).contains("outside"));
}

#[test]
fn absolute_link_into_the_root_is_an_alias() {
    let t = Tree::new("abs-in");
    t.file("src/real.py", "");
    let canon = std::fs::canonicalize(&t.root).unwrap();
    t.link("src/abs.py", canon.join("src/real.py"));
    let d = run(&t);
    assert_eq!(
        excluded(&d),
        vec![("src/abs.py".into(), ExcludedReason::SymlinkAlias)]
    );
    assert!(d.blind_spots.is_empty());
}

#[test]
fn directory_cycles_terminate_and_hop_limits_are_listed() {
    let t = Tree::new("cycle");
    t.file("a/m.py", "")
        .link("a/loop", "..")
        .link("b", "a")
        .link("x.py", "y.py")
        .link("y.py", "x.py");
    let d = run(&t);
    assert_eq!(sources(&d), vec![("a/m.py".into(), Language::Python)]);
    assert_eq!(
        excluded(&d),
        vec![
            ("a/loop".into(), ExcludedReason::SymlinkAlias),
            ("b".into(), ExcludedReason::SymlinkAlias),
            ("x.py".into(), ExcludedReason::SymlinkHopLimit),
            ("y.py".into(), ExcludedReason::SymlinkHopLimit),
        ]
    );
}

#[test]
fn broken_link_is_listed_and_leaves_no_gap() {
    let t = Tree::new("broken");
    t.file("src/app.py", "").link("src/gone.py", "missing.py");
    let d = run(&t);
    assert_eq!(
        excluded(&d),
        vec![("src/gone.py".into(), ExcludedReason::BrokenSymlink)]
    );
    assert!(d.blind_spots.is_empty());
}

#[test]
fn link_into_an_excluded_directory_is_a_gap() {
    let t = Tree::new("into-excluded");
    t.file("package.json", "{}")
        .file("node_modules/foo/index.js", "")
        .link("src/foo.js", "../node_modules/foo/index.js");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("src/foo.js".into(), BlindSpotKind::ReferenceIntoExcluded)]
    );
    assert!(d.blind_spots[0].coverage_gap);
}

#[test]
fn root_given_as_a_symlink_is_canonicalized() {
    let t = Tree::new("root-link");
    t.file("pkg/app.py", "");
    let link = t.base.join("root-alias");
    std::os::unix::fs::symlink(&t.root, &link).unwrap();
    let d = discover(&link, &Config::default()).unwrap();
    assert_eq!(sources(&d), vec![("pkg/app.py".into(), Language::Python)]);
}

#[test]
fn root_that_is_a_file_or_missing_is_a_tool_error() {
    let t = Tree::new("root-errors");
    t.file("f.py", "");
    assert_eq!(
        discover(&t.path("f.py"), &Config::default()).err(),
        Some(ToolError::RootNotDirectory)
    );
    assert_eq!(
        discover(&t.path("missing"), &Config::default()).err(),
        Some(ToolError::RootNotFound)
    );
}

// ---- hostile names and permissions -----------------------------------------

#[test]
fn non_utf8_name_is_reported_byte_preserving() {
    let t = Tree::new("non-utf8");
    t.file_bytes(b"src/\xffbad.py", "x = 1\n").file("ok.py", "");
    let d = run(&t);
    let b = d
        .blind_spots
        .iter()
        .find(|b| b.kind == BlindSpotKind::NonUtf8Path)
        .expect("non-utf8-path blind spot");
    assert_eq!(b.file, "src/\\x{ff}bad.py");
    assert_eq!(b.file_bytes.as_deref(), Some("7372632fff6261642e7079"));
    assert!(b.whole_file && b.coverage_gap);
    assert_eq!(sources(&d), vec![("ok.py".into(), Language::Python)]);
}

#[test]
fn esc_in_a_file_name_is_scanned_normally() {
    let t = Tree::new("esc");
    t.file("a\u{1b}[31mb.py", "");
    let d = run(&t);
    assert_eq!(d.sources.len(), 1);
    assert_eq!(d.sources[0].file.display, "a\u{1b}[31mb.py");
}

#[test]
fn unsearchable_directory_is_an_unreadable_gap_not_a_tool_error() {
    if privileged() {
        return;
    }
    let t = Tree::new("unsearchable");
    t.file("ok.py", "").file("locked/hidden.py", "");
    t.chmod("locked", 0o000);
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("locked".into(), BlindSpotKind::Unreadable)]
    );
    assert!(d.blind_spots[0].coverage_gap);
}

#[test]
fn source_named_link_to_a_file_not_scanned_as_that_language_is_a_gap() {
    let t = Tree::new("alias-kind");
    t.file("payload.txt", "import subprocess\nsubprocess.run(['x'])\n")
        .file("payload", "import socket\n")
        .file("payload.dat", "require('child_process').exec('x')\n")
        .file("lib.js", "fetch('https://x')\n")
        .file("real.py", "")
        .file("tool", "#!/usr/bin/env python3\n")
        .dir("pkg")
        .link("net.py", "payload.txt")
        .link("bare.py", "payload")
        .link("net.js", "payload.dat")
        .link("cross.py", "lib.js")
        .link("alias.py", "real.py")
        .link("stub.pyi", "real.py")
        .link("script.py", "tool")
        .link("pkg.py", "pkg")
        .link("data.txt", "payload.dat");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![
            ("bare.py".into(), BlindSpotKind::LoadedAsCode),
            ("cross.py".into(), BlindSpotKind::LoadedAsCode),
            ("net.js".into(), BlindSpotKind::LoadedAsCode),
            ("net.py".into(), BlindSpotKind::LoadedAsCode),
        ]
    );
    for b in &d.blind_spots {
        assert!(b.coverage_gap && b.whole_file, "{b:?}");
    }
    assert_eq!(
        d.blind_spots
            .iter()
            .find(|b| b.file == "net.js")
            .unwrap()
            .language,
        Some(Language::Javascript)
    );
    // Links whose target is scanned under the same language stay aliases.
    assert_eq!(
        excluded(&d),
        vec![
            ("alias.py".into(), ExcludedReason::SymlinkAlias),
            ("data.txt".into(), ExcludedReason::SymlinkAlias),
            ("pkg.py".into(), ExcludedReason::SymlinkAlias),
            ("script.py".into(), ExcludedReason::SymlinkAlias),
            ("stub.pyi".into(), ExcludedReason::SymlinkAlias),
        ]
    );
    assert_eq!(d.coverage.languages[Language::Python].skipped, 3);
    assert_eq!(d.coverage.languages[Language::Javascript].skipped, 1);
}

#[test]
fn unlistable_subtree_in_an_unconfirmed_exclusion_is_a_gap() {
    if privileged() {
        return;
    }
    let t = Tree::new("unc-unlistable");
    t.file("app.py", "")
        .file("unc/CACHEDIR.TAG", "x")
        .file("unc/deep/z.py", "")
        .file("nm/node_modules/p/q/h.js", "")
        .file("whole/node_modules/x.js", "");
    t.chmod("unc/deep", 0o000)
        .chmod("nm/node_modules/p/q", 0o000)
        .chmod("whole/node_modules", 0o000);
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![
            (
                "nm/node_modules".into(),
                BlindSpotKind::UnconfirmedExclusion
            ),
            ("unc".into(), BlindSpotKind::UnconfirmedExclusion),
            (
                "whole/node_modules".into(),
                BlindSpotKind::UnconfirmedExclusion
            ),
        ]
    );
    assert!(d.blind_spots.iter().all(|b| b.coverage_gap));
}

#[test]
fn unconfirmed_exclusion_with_unlistable_entries_is_a_gap() {
    if privileged() {
        return;
    }
    // Readable but not searchable: the names list, but no entry can be
    // `lstat`ed, so the directory cannot be shown to hold no source.
    let t = Tree::new("unc-nosearch");
    t.file("app.py", "")
        .file("unc/CACHEDIR.TAG", "x")
        .file("unc/deep/z.py", "");
    t.chmod("unc/deep", 0o444);
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("unc".into(), BlindSpotKind::UnconfirmedExclusion)]
    );
}

#[test]
fn directory_whose_entries_cannot_be_statted_is_an_unreadable_gap() {
    if privileged() {
        return;
    }
    let t = Tree::new("nosearch");
    t.file("ok.py", "").file("half/hidden.py", "");
    t.chmod("half", 0o444);
    let d = run(&t);
    assert_eq!(spots(&d), vec![("half".into(), BlindSpotKind::Unreadable)]);
    assert!(d.blind_spots[0].coverage_gap);
}

// ---- U6: scoped discovery ---------------------------------------------------

use egress_core::discover::open::RootDir;
use egress_core::discover::{ScopedRule, discover_scoped};

fn scoped(t: &Tree, prefixes: &[&str]) -> egress_core::discover::Discovery {
    let root = RootDir::open(&t.root).unwrap();
    let ps: Vec<&[u8]> = prefixes.iter().map(|p| p.as_bytes()).collect();
    discover_scoped(&root, &ps, &Config::default(), None).unwrap()
}

fn scoped_with_rule(
    t: &Tree,
    prefixes: &[&str],
    rule: &egress_core::discover::FileRule<'_>,
) -> egress_core::discover::Discovery {
    let root = RootDir::open(&t.root).unwrap();
    let ps: Vec<&[u8]> = prefixes.iter().map(|p| p.as_bytes()).collect();
    discover_scoped(&root, &ps, &Config::default(), Some(rule)).unwrap()
}

fn names(d: &egress_core::discover::Discovery) -> Vec<String> {
    let mut v: Vec<String> = d
        .index
        .keys()
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn scoped_prefix_indexes_only_the_package() {
    let t = Tree::new("scoped-npm");
    t.file("node_modules/leftpad/index.js", "module.exports = 1;\n");
    t.file("node_modules/leftpad/package.json", "{}");
    t.file("node_modules/leftpad/node_modules/inner/index.js", "x");
    t.file("other/app.js", "x");
    let d = scoped(&t, &["node_modules/leftpad"]);
    assert_eq!(
        names(&d),
        vec![
            "node_modules/leftpad/index.js".to_string(),
            "node_modules/leftpad/package.json".to_string(),
        ]
    );
    // A nested node_modules inside the prefix is classified as an
    // install output like it is under full discovery.
    assert!(
        d.excluded_dirs
            .contains(b"node_modules/leftpad/node_modules".as_slice())
    );
}

#[test]
fn scoped_file_prefixes_index_exactly_those_paths() {
    let t = Tree::new("scoped-venv");
    t.file("lib/python3.12/site-packages/six.py", "x=1\n");
    t.file("lib/python3.12/site-packages/requests/__init__.py", "x=1\n");
    t.file("lib/python3.12/site-packages/requests/api.py", "x=1\n");
    t.file("lib/python3.12/site-packages/other.py", "x=1\n");
    let d = scoped(
        &t,
        &[
            "lib/python3.12/site-packages/six.py",
            "lib/python3.12/site-packages/requests",
        ],
    );
    assert_eq!(
        names(&d),
        vec![
            "lib/python3.12/site-packages/requests/__init__.py".to_string(),
            "lib/python3.12/site-packages/requests/api.py".to_string(),
            "lib/python3.12/site-packages/six.py".to_string(),
        ]
    );
}

#[test]
fn must_not_walk_outside_prefix() {
    let t = Tree::new("scoped-outside");
    t.file("pkg/a.py", "x=1\n");
    t.file("sibling/evil.py", "x=1\n");
    let d = scoped(&t, &["pkg"]);
    assert_eq!(names(&d), vec!["pkg/a.py".to_string()]);
    assert!(d.blind_spots.is_empty());
}

#[test]
fn rust_prefixes_skip_tests_benches_examples() {
    let t = Tree::new("scoped-rust");
    t.file("src/lib.rs", "pub fn x() {}\n");
    t.file("build.rs", "fn main() {}\n");
    t.file("Cargo.toml", "[package]\nname=\"x\"\nversion=\"1\"\n");
    t.file("tests/t.rs", "fn t() {}\n");
    t.file("benches/b.rs", "fn b() {}\n");
    t.file("examples/e.rs", "fn e() {}\n");
    let d = scoped(&t, &["src", "build.rs", "Cargo.toml"]);
    assert_eq!(
        names(&d),
        vec![
            "Cargo.toml".to_string(),
            "build.rs".to_string(),
            "src/lib.rs".to_string(),
        ]
    );
}

#[test]
fn pyc_and_so_are_per_file_gaps_while_the_py_scans() {
    let t = Tree::new("scoped-pyc");
    t.file("pkg/six.py", "x=1\n");
    t.file("pkg/six.pyc", "\x00\x01");
    t.file("pkg/orphan.pyc", "\x00\x01");
    t.file("pkg/native.so", "\x00\x01");
    let d = scoped(&t, &["pkg"]);
    let sources: Vec<String> = d.sources.iter().map(|s| s.file.display.clone()).collect();
    // Compiled caches and natives are never sources; each shows up as
    // a per-file unsupported gap.
    assert_eq!(sources, vec!["pkg/six.py".to_string()]);
    let gaps: Vec<String> = d
        .blind_spots
        .iter()
        .filter(|b| b.kind == BlindSpotKind::UnsupportedFileType)
        .map(|b| b.file.clone())
        .collect();
    assert_eq!(gaps.len(), 3);
}

#[test]
fn the_scoped_file_rule_drops_and_gaps_sources() {
    let t = Tree::new("scoped-rule");
    t.file("pkg/a.py", "x=1\n");
    t.file("pkg/b.py", "x=1\n");
    let rule = |p: &[u8]| match p {
        b"pkg/a.py" => ScopedRule::Skip,
        b"pkg/b.py" => ScopedRule::Gap,
        _ => ScopedRule::Include,
    };
    let d = scoped_with_rule(&t, &["pkg"], &rule);
    assert!(d.sources.is_empty());
    let gaps: Vec<String> = d
        .blind_spots
        .iter()
        .filter(|b| b.kind == BlindSpotKind::UnsupportedFileType)
        .map(|b| b.file.clone())
        .collect();
    assert_eq!(gaps, vec!["pkg/b.py".to_string()]);
    // Both files stay indexed so resolution still sees them.
    assert!(names(&d).contains(&"pkg/a.py".to_string()));
}

// ---- Go native files (KTD12) ------------------------------------------------

/// A `.s`, `.syso`, or C-family file beside a Go source is a file-level
/// native-code blind spot; other names in the same directory are not.
#[test]
fn native_files_list_beside_go_sources() {
    let t = Tree::new("go-native");
    t.file("pkg/main.go", "package main\n")
        .file("pkg/asm_amd64.s", "")
        .file("pkg/up.S", "")
        .file("pkg/arch.sx", "")
        .file("pkg/blob.syso", "")
        .file("pkg/hello.c", "")
        .file("pkg/wrap.cc", "")
        .file("pkg/impl.cpp", "")
        .file("pkg/more.cxx", "")
        .file("pkg/bridge.m", "")
        .file("pkg/notes.h", "")
        .file("pkg/README.s.txt", "");
    let d = run(&t);
    let mut b: Vec<(String, String)> = d
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.construct.clone()))
        .collect();
    b.sort();
    assert_eq!(
        b,
        vec![
            ("pkg/arch.sx".to_string(), "assembly".to_string()),
            ("pkg/asm_amd64.s".to_string(), "assembly".to_string()),
            ("pkg/blob.syso".to_string(), "syso object".to_string()),
            ("pkg/bridge.m".to_string(), "Objective-C source".to_string()),
            ("pkg/hello.c".to_string(), "C source".to_string()),
            ("pkg/impl.cpp".to_string(), "C++ source".to_string()),
            ("pkg/more.cxx".to_string(), "C++ source".to_string()),
            ("pkg/up.S".to_string(), "assembly".to_string()),
            ("pkg/wrap.cc".to_string(), "C++ source".to_string()),
        ]
    );
    for s in &d.blind_spots {
        assert_eq!(s.kind, BlindSpotKind::NativeCode);
        assert_eq!(s.symbol, "<module>");
        assert_eq!(s.language, Some(Language::Go));
        assert!(!s.coverage_gap);
        assert!(s.location.is_none());
    }
}

/// The listing is keyed to the directory that holds a Go source, so a
/// `.c` file in a Go-free directory is not listed.
#[test]
fn a_native_file_in_a_go_free_dir_is_not_listed() {
    let t = Tree::new("go-native-no-dir");
    t.file("pkg/main.go", "package main\n")
        .file("util/helper.c", "")
        .file("util/helper.py", "x = 1\n");
    let d = run(&t);
    assert!(d.blind_spots.is_empty(), "{:?}", spots(&d));
}

/// A Python-only tree never produces the listing.
#[test]
fn a_python_only_tree_lists_no_native_files() {
    let t = Tree::new("go-native-python");
    t.file("app.py", "x = 1\n").file("helper.c", "");
    let d = run(&t);
    assert!(d.blind_spots.is_empty(), "{:?}", spots(&d));
}

/// The listing reads the index only: an unreadable native file is still
/// listed once and never becomes an unreadable gap.
#[test]
fn a_native_listing_never_opens_the_file() {
    if privileged() {
        return;
    }
    let t = Tree::new("go-native-unreadable");
    t.file("pkg/main.go", "package main\n")
        .file("pkg/secret.s", "")
        .chmod("pkg/secret.s", 0o000);
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("pkg/secret.s".to_string(), BlindSpotKind::NativeCode)]
    );
    assert!(!d.blind_spots[0].coverage_gap);
}

/// Files under excluded directories are not indexed, so they are not
/// listed even beside an indexed Go source.
#[test]
fn native_listing_respects_exclusions() {
    let t = Tree::new("go-native-excluded");
    t.file("pkg/main.go", "package main\n")
        .file(".git/x/main.go", "package main\n")
        .file(".git/x/asm.s", "");
    let d = run(&t);
    assert!(
        d.blind_spots
            .iter()
            .all(|b| b.kind != BlindSpotKind::NativeCode),
        "{:?}",
        spots(&d)
    );
}

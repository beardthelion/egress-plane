//! Discovery: walk, routing, exclusions, labels, symlinks, and path encoding
//! (KTD12, R15, R18, R19, R22).

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
fn covers_ae10_notebook_is_unsupported_and_skipped() {
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
fn covers_ae9_go_only_tree_has_no_supported_files() {
    let t = Tree::new("go");
    t.file("main.go", "package main\n")
        .file("go.mod", "module x\n");
    let d = run(&t);
    assert!(d.sources.is_empty());
    assert!(d.blind_spots.is_empty());
    assert!(d.languages.is_empty());
    assert_eq!(d.index.get(b"main.go".as_slice()), Some(&FileKind::Other));
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
fn covers_ae19_venv_without_home_is_an_unconfirmed_exclusion() {
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
fn covers_ae19_venv_with_home_is_excluded_without_a_gap() {
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
fn covers_ae11_path_labels_never_change_what_is_scanned() {
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

// ---- symlinks ---------------------------------------------------------------

#[test]
fn covers_ae12_outside_link_is_reported_and_target_never_printed() {
    let t = Tree::new("ae12");
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
    assert_eq!(d.coverage.python.skipped, 1);
}

#[test]
fn covers_ae24_outside_target_in_unsearchable_directory_is_never_touched() {
    if privileged() {
        return;
    }
    let t = Tree::new("ae24");
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
    assert_eq!(d.coverage.python.skipped, 3);
    assert_eq!(d.coverage.javascript.skipped, 1);
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

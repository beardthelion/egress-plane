//! Named dependency roots: KTD2 overlap and dedupe rules, KTD3 marker
//! detection, KTD4 labels, and the KTD5 npm lookup-path rule. Every
//! rejection is a `ToolError::DependencyRoot` naming the 1-based argument
//! ordinal and never a path.

mod support;

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use egress_core::discover::dependency_roots::{NamedRoot, open};
use egress_core::discover::open::RootDir;
use egress_core::model::{DependencyRootKind, DependencyRootProblem, ToolError};
use support::Tree;

fn mkdir(p: &Path) -> PathBuf {
    std::fs::create_dir_all(p).unwrap();
    p.to_path_buf()
}

fn mkfile(p: &Path) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, b"").unwrap();
}

/// An npm root: `dir/node_modules` holding one package. To stay on Node's
/// lookup path (KTD5), `dir` must be an ancestor of the scan root.
fn npm(dir: &Path) -> PathBuf {
    let d = dir.join("node_modules");
    mkfile(&d.join("leftpad/package.json"));
    d
}

/// A `site-packages`-shaped root.
fn sitepk(dir: &Path) -> PathBuf {
    let d = dir.join("sitepk");
    mkdir(&d.join("leftpy-1.0.0.dist-info"));
    d
}

/// A venv root.
fn venv(dir: &Path) -> PathBuf {
    let d = dir.join("venv");
    mkfile(&d.join("pyvenv.cfg"));
    mkdir(&d.join("lib/python3.12/site-packages"));
    d
}

/// A Cargo vendor root.
fn vendor(dir: &Path) -> PathBuf {
    let d = dir.join("vendor");
    mkfile(&d.join("serde-1.0.200/.cargo-checksum.json"));
    d
}

/// A Cargo `registry/src` root: index dirs holding `name-version` dirs.
fn registry_src(dir: &Path) -> PathBuf {
    let d = dir.join("registry/src");
    mkfile(&d.join("index.crates.io-a1b2c3d4/serde-1.0.200/.cargo-ok"));
    mkfile(&d.join("index.crates.io-a1b2c3d4/serde-1.0.200/Cargo.toml.orig"));
    d
}

/// A single Cargo registry index directory.
fn registry_index(dir: &Path) -> PathBuf {
    let d = dir.join("index.crates.io-a1b2c3d4");
    mkfile(&d.join("serde-1.0.200/.cargo-ok"));
    mkfile(&d.join("serde-1.0.200/Cargo.toml.orig"));
    d
}

/// A Cargo `git/checkouts` root.
fn git_checkouts(dir: &Path) -> PathBuf {
    let d = dir.join("git/checkouts");
    mkfile(&d.join("ruff-b18f69e2b025fac7/0be08a2/.cargo-ok"));
    mkdir(&d.join("ruff-b18f69e2b025fac7/0be08a2/.git"));
    d
}

fn open_with(t: &Tree, roots: &[PathBuf]) -> Result<Vec<NamedRoot>, ToolError> {
    let scan = RootDir::open(&t.root).unwrap();
    open(&scan, roots)
}

fn kinds(t: &Tree, roots: &[PathBuf]) -> Vec<(DependencyRootKind, String)> {
    open_with(t, roots)
        .unwrap()
        .iter()
        .map(|r| (r.kind, r.label.clone()))
        .collect()
}

fn expect_err(t: &Tree, roots: &[PathBuf], ordinal: usize, problem: DependencyRootProblem) {
    let e = open_with(t, roots).unwrap_err();
    assert_eq!(
        e,
        ToolError::DependencyRoot { ordinal, problem },
        "roots {roots:?}"
    );
    let text = e.to_string();
    for r in roots {
        assert!(
            !text.contains(&*r.to_string_lossy()),
            "message {text:?} leaks the path {r:?}"
        );
    }
}

// ---- KTD2: existence, kind, overlap ----------------------------------------

#[test]
fn missing_root_is_an_ordinal_error_without_a_path() {
    let t = Tree::new("dep-missing");
    let missing = t.outside.join("nope");
    expect_err(&t, &[missing], 1, DependencyRootProblem::NotFound);
}

#[test]
fn a_named_file_is_not_a_directory() {
    let t = Tree::new("dep-file");
    let f = t.outside_file("plain", "x");
    expect_err(&t, &[f], 1, DependencyRootProblem::NotDirectory);
}

#[test]
fn an_unrecognized_directory_is_an_error() {
    let t = Tree::new("dep-unrecognized");
    let d = mkdir(&t.outside.join("plaindir"));
    mkfile(&d.join("README"));
    expect_err(&t, &[d], 1, DependencyRootProblem::UnrecognizedLayout);
}

#[test]
fn the_ordinal_is_the_1_based_argument_position() {
    let t = Tree::new("dep-ordinal");
    let good = sitepk(&t.outside);
    let missing = t.outside.join("nope");
    expect_err(&t, &[good, missing], 2, DependencyRootProblem::NotFound);
}

#[test]
fn a_root_equal_to_the_scan_root_is_an_error() {
    let t = Tree::new("dep-equal");
    // A `pyvenv.cfg` makes the scan root a recognizable kind, so the
    // overlap rule, not unrecognized-layout, produces the error.
    t.file("pyvenv.cfg", "");
    expect_err(
        &t,
        std::slice::from_ref(&t.root),
        1,
        DependencyRootProblem::OverlapsScanRoot,
    );
}

#[test]
fn a_root_containing_the_scan_root_is_an_error() {
    let t = Tree::new("dep-contains");
    // `t.base` holds `root/` and `outside/`, so it contains the scan
    // root; a marker file makes it a recognizable kind.
    mkfile(&t.base.join("pyvenv.cfg"));
    expect_err(
        &t,
        std::slice::from_ref(&t.base),
        1,
        DependencyRootProblem::OverlapsScanRoot,
    );
}

#[test]
fn a_root_named_twice_is_used_once() {
    let t = Tree::new("dep-twice");
    // `base/node_modules` is on the lookup path from `base/root`.
    let d = npm(&t.base);
    // A different spelling of the same canonical path also dedupes.
    let link = t.outside.join("alias");
    symlink(&d, &link).unwrap();
    let roots = open_with(&t, &[d.clone(), d.clone(), link]).unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].ordinal, 1);
    assert_eq!(roots[0].kind, DependencyRootKind::Npm);
}

#[test]
fn a_root_strictly_inside_another_is_an_error_in_either_order() {
    let t = Tree::new("dep-nested");
    // `venv` inside `sitepk` is a Python root strictly inside another
    // named root.
    let outer = sitepk(&t.outside);
    let inner = venv(&outer);
    expect_err(
        &t,
        &[outer.clone(), inner.clone()],
        2,
        DependencyRootProblem::InsideAnotherRoot,
    );
    expect_err(
        &t,
        &[inner, outer],
        1,
        DependencyRootProblem::InsideAnotherRoot,
    );
}

// ---- KTD4: labels -----------------------------------------------------------

#[test]
fn an_in_root_label_is_the_relative_path_and_outside_is_the_kind() {
    let t = Tree::new("dep-labels");
    t.dir("deps/node_modules");
    mkfile(&t.path("deps/node_modules/leftpad/package.json"));
    let inside = t.path("deps/node_modules");
    let outside = venv(&t.outside);
    let got = kinds(&t, &[inside, outside]);
    assert_eq!(
        got,
        vec![
            (DependencyRootKind::Npm, "deps/node_modules".to_string()),
            (DependencyRootKind::Python, "python".to_string()),
        ]
    );
}

#[test]
fn a_symlinked_root_is_resolved_once_and_labeled_by_its_target() {
    let t = Tree::new("dep-symlink");
    let real = npm(&t.base);
    let link = t.outside.join("link-nm");
    symlink(&real, &link).unwrap();
    let got = kinds(&t, &[link]);
    assert_eq!(got, vec![(DependencyRootKind::Npm, "npm".to_string())]);
}

#[test]
fn an_in_root_symlink_to_an_in_root_dir_gets_the_target_relative_label() {
    let t = Tree::new("dep-symlink-in");
    t.dir("depdir/node_modules");
    t.link("link", "depdir/node_modules");
    let got = kinds(&t, &[t.path("link")]);
    assert_eq!(
        got,
        vec![(DependencyRootKind::Npm, "depdir/node_modules".to_string())]
    );
}

// ---- KTD3: marker detection -------------------------------------------------

#[test]
fn each_marker_row_is_recognized() {
    let t = Tree::new("dep-kinds");
    // `base/node_modules` is the only outside npm root on the lookup path.
    let cases: Vec<(PathBuf, DependencyRootKind)> = vec![
        (npm(&t.base), DependencyRootKind::Npm),
        (sitepk(&t.outside.join("b")), DependencyRootKind::Python),
        (venv(&t.outside.join("c")), DependencyRootKind::Python),
        (
            vendor(&t.outside.join("d")),
            DependencyRootKind::CargoVendor,
        ),
        (
            registry_src(&t.outside.join("e")),
            DependencyRootKind::CargoRegistry,
        ),
        (
            registry_index(&t.outside.join("f")),
            DependencyRootKind::CargoRegistry,
        ),
        (
            git_checkouts(&t.outside.join("g")),
            DependencyRootKind::CargoGit,
        ),
    ];
    for (root, want) in cases {
        let got = kinds(&t, std::slice::from_ref(&root));
        assert_eq!(got.len(), 1, "{root:?}");
        assert_eq!(got[0].0, want, "{root:?}");
        assert_eq!(got[0].1, want.as_str(), "{root:?}");
    }
}

#[test]
fn an_empty_node_modules_is_an_npm_root() {
    let t = Tree::new("dep-empty-nm");
    let d = mkdir(&t.outside.join("base/node_modules"));
    // Its parent must be an ancestor of the scan root to satisfy KTD5.
    let scan = mkdir(&t.outside.join("base/proj"));
    let sr = RootDir::open(&scan).unwrap();
    let roots = open(&sr, &[d]).unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].kind, DependencyRootKind::Npm);
}

#[test]
fn a_package_lock_marker_makes_an_unnamed_directory_npm() {
    let t = Tree::new("dep-pkglock");
    let scan = mkdir(&t.outside.join("base/proj"));
    let d = mkdir(&t.outside.join("base/mods"));
    mkfile(&d.join(".package-lock.json"));
    let sr = RootDir::open(&scan).unwrap();
    let roots = open(&sr, &[d]).unwrap();
    assert_eq!(roots[0].kind, DependencyRootKind::Npm);
}

#[test]
fn must_not_detect_go_vendor_as_cargo() {
    let t = Tree::new("dep-go-vendor");
    let d = t.outside.join("vendor");
    mkfile(&d.join("modules.txt"));
    mkfile(&d.join("github.com/pkg/errors/errors.go"));
    expect_err(&t, &[d], 1, DependencyRootProblem::UnrecognizedLayout);
}

#[test]
fn a_directory_matching_two_kinds_is_an_error() {
    let t = Tree::new("dep-two-kinds");
    let d = mkdir(&t.outside.join("mods"));
    mkfile(&d.join(".package-lock.json"));
    mkdir(&d.join("foo-1.0.dist-info"));
    expect_err(&t, &[d], 1, DependencyRootProblem::UnrecognizedLayout);
}

// ---- KTD5: the npm lookup path ----------------------------------------------

#[test]
fn an_outside_npm_root_off_the_lookup_path_is_an_error() {
    let t = Tree::new("dep-npm-offpath");
    // `outside/` is a sibling of `root/`, so a `node_modules` there is
    // never on Node's lookup path from the scan root.
    let d = npm(&t.outside);
    expect_err(&t, &[d], 1, DependencyRootProblem::NpmNotOnLookupPath);
}

#[test]
fn an_outside_npm_root_on_the_lookup_path_is_accepted() {
    let t = Tree::new("dep-npm-onpath");
    // `base/node_modules` is found by lookup from `base/root` and deeper.
    let d = npm(&t.base);
    let got = kinds(&t, &[d]);
    assert_eq!(got, vec![(DependencyRootKind::Npm, "npm".to_string())]);
}

#[test]
fn an_in_root_npm_directory_needs_no_lookup_check() {
    let t = Tree::new("dep-npm-inroot");
    t.dir("sub/node_modules");
    let got = kinds(&t, &[t.path("sub/node_modules")]);
    assert_eq!(
        got,
        vec![(DependencyRootKind::Npm, "sub/node_modules".to_string())]
    );
}

// ---- ordering ---------------------------------------------------------------

#[test]
fn the_first_bad_argument_in_order_is_the_error() {
    let t = Tree::new("dep-order");
    let bad1 = t.outside.join("nope1");
    let bad2 = t.outside.join("nope2");
    expect_err(&t, &[bad1, bad2], 1, DependencyRootProblem::NotFound);
}

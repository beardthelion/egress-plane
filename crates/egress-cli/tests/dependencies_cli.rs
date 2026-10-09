//! End-to-end tests of `egress-plane scan --deps`: flag forms, usage
//! errors, fixed root-validation messages with ordinals and no paths,
//! kind detection, and the empty dependency section of a valid run.

mod support;

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use support::{Run, Temp, case, run};

fn mkdir(p: &Path) -> PathBuf {
    std::fs::create_dir_all(p).unwrap();
    p.to_path_buf()
}

fn mkfile(p: &Path) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, b"").unwrap();
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).expect("stdout is one JSON document")
}

/// A `site-packages`-shaped root.
fn sitepk(dir: &Path) -> PathBuf {
    let d = dir.join("sitepk");
    mkdir(&d.join("leftpy-1.0.0.dist-info"));
    d
}

/// `egress-plane scan <root> --format json` plus one `--deps` per path.
fn deps_run(root: &Path, deps: &[&Path]) -> Run {
    let mut args: Vec<OsString> = vec![
        "scan".into(),
        root.as_os_str().into(),
        "--format".into(),
        "json".into(),
    ];
    for d in deps {
        args.push("--deps".into());
        args.push(d.as_os_str().into());
    }
    let refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    run(&refs)
}

/// A minimal complete scan root: one JS file that egresses nowhere.
fn project(t: &Temp) -> PathBuf {
    let root = t.path("proj");
    mkdir(&root);
    std::fs::write(root.join("app.js"), "const x = 1;\n").unwrap();
    root
}

#[test]
fn deps_parses_before_and_after_the_root_in_both_forms() {
    let t = Temp::new("deps-forms");
    let root = project(&t);
    let dep = sitepk(&t.base.join("named"));

    let after = deps_run(&root, &[&dep]);
    assert_eq!(after.code, 0, "{}", after.stderr);
    let section = &json(&after.stdout)["dependencies"];
    assert_eq!(
        section["roots"],
        serde_json::json!([{"label": "python", "kind": "python"}])
    );
    assert_eq!(section["packages"], serde_json::json!([]));
    // The text report runs too; its dependency section lands in U12.
    let text = run(&[
        OsStr::new("scan"),
        root.as_os_str(),
        OsStr::new("--deps"),
        dep.as_os_str(),
    ]);
    assert_eq!(text.code, 0, "{}", text.stderr);

    for args in [
        vec![
            OsString::from("scan"),
            OsString::from("--deps"),
            dep.as_os_str().into(),
            root.as_os_str().into(),
            OsString::from("--format=json"),
        ],
        vec![
            OsString::from("scan"),
            root.as_os_str().into(),
            OsString::from(format!("--deps={}", dep.display())),
            OsString::from("--format"),
            OsString::from("json"),
        ],
        vec![
            OsString::from("scan"),
            OsString::from(format!("--deps={}", dep.display())),
            root.as_os_str().into(),
            OsString::from("--format"),
            OsString::from("json"),
        ],
    ] {
        let refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
        let r = run(&refs);
        assert_eq!(r.code, 0, "{refs:?}: {}", r.stderr);
        assert_eq!(r.stdout, after.stdout, "{refs:?}");
    }
}

#[test]
fn bare_deps_is_a_usage_error() {
    let t = Temp::new("deps-bare");
    let root = project(&t);
    let r = run(&[OsStr::new("scan"), root.as_os_str(), OsStr::new("--deps")]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains("--deps needs a value"), "{}", r.stderr);
    assert!(r.stderr.contains("usage"), "{}", r.stderr);
}

#[test]
fn deps_after_double_dash_is_a_second_positional_root() {
    let t = Temp::new("deps-dashdash");
    let root = project(&t);
    let r = run(&[
        OsStr::new("scan"),
        root.as_os_str(),
        OsStr::new("--"),
        OsStr::new("--deps"),
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains("more than one scan root"), "{}", r.stderr);
}

#[test]
fn invalid_roots_exit_1_with_a_fixed_ordinal_message_and_no_path() {
    let t = Temp::new("deps-invalid");
    let root = project(&t);
    let missing = t.path("does-not-exist");
    let file = t.path("plain.txt");
    std::fs::write(&file, "x").unwrap();
    let unrecognized = mkdir(&t.path("just-a-dir"));

    for (dep, message) in [
        (&missing, "dependency root 1: not found"),
        (&file, "dependency root 1: not a directory"),
        (&unrecognized, "dependency root 1: unrecognized layout"),
    ] {
        let r = deps_run(&root, &[dep]);
        assert_eq!(r.code, 1, "{dep:?}");
        assert!(r.stdout.is_empty(), "{dep:?}: {:?}", r.stdout);
        assert!(r.stderr.contains(message), "{dep:?}: {}", r.stderr);
        assert!(
            !r.stderr.contains(&*dep.to_string_lossy()),
            "{dep:?}: stderr leaks the path: {}",
            r.stderr
        );
    }

    // The ordinal is the 1-based argument position.
    let good = sitepk(&t.base.join("named"));
    let r = deps_run(&root, &[&good, &missing]);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("dependency root 2: not found"),
        "{}",
        r.stderr
    );
}

#[test]
fn a_root_equal_to_or_containing_the_scan_root_is_an_error() {
    let t = Temp::new("deps-overlap");
    let root = project(&t);
    // Kind detection runs before the overlap rule (KTD2), so the
    // overlap cases need a marker that makes the named dir a root kind.
    mkfile(&root.join("pyvenv.cfg"));
    mkfile(&t.base.join("pyvenv.cfg"));
    for dep in [root.clone(), t.base.clone()] {
        let r = deps_run(&root, &[&dep]);
        assert_eq!(r.code, 1, "{dep:?}");
        assert!(r.stdout.is_empty());
        assert!(
            r.stderr.contains("equals or contains the scan root"),
            "{dep:?}: {}",
            r.stderr
        );
    }
}

#[test]
fn a_root_named_twice_is_used_once() {
    let t = Temp::new("deps-twice");
    let root = project(&t);
    let dep = sitepk(&t.base.join("named"));
    let r = deps_run(&root, &[&dep, &dep]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        json(&r.stdout)["dependencies"]["roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_root_strictly_inside_another_is_an_error() {
    let t = Temp::new("deps-nested");
    let root = project(&t);
    let outer = sitepk(&t.base.join("named"));
    let inner = mkdir(&outer.join("venv"));
    mkfile(&inner.join("pyvenv.cfg"));
    let r = deps_run(&root, &[&outer, &inner]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(
        r.stderr.contains("inside another named dependency root"),
        "{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains(&*inner.to_string_lossy()),
        "stderr leaks the path: {}",
        r.stderr
    );
}

#[test]
fn a_symlinked_root_is_accepted_and_labeled_by_kind_or_relative_path() {
    let t = Temp::new("deps-symlink");
    let root = project(&t);
    // Outside: the label is the kind name.
    let real = sitepk(&t.base.join("named"));
    let link = t.path("link-sitepk");
    symlink(&real, &link).unwrap();
    let r = deps_run(&root, &[&link]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        json(&r.stdout)["dependencies"]["roots"][0]["label"],
        "python"
    );
    assert!(!r.stdout.contains(&*real.to_string_lossy()), "{}", r.stdout);

    // Inside: the label is the canonical path relative to the scan root.
    // (`mods`, not `node_modules`, so first-party discovery does not
    // exclude the directory and the link stays a plain alias.)
    mkfile(&root.join("depdir/mods/.package-lock.json"));
    symlink(root.join("depdir/mods"), root.join("link")).unwrap();
    let r = deps_run(&root, &[&root.join("link")]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        json(&r.stdout)["dependencies"]["roots"][0],
        serde_json::json!({"label": "depdir/mods", "kind": "npm"})
    );
}

#[test]
fn each_marker_row_is_recognized_including_an_empty_node_modules() {
    let t = Temp::new("deps-kinds");
    // The scan root sits under `wrap/` so an outside npm root is on the
    // lookup path.
    let wrap = mkdir(&t.path("wrap"));
    let root = mkdir(&wrap.join("proj"));
    std::fs::write(root.join("app.js"), "const x = 1;\n").unwrap();

    let nm = mkdir(&wrap.join("node_modules")); // empty: still npm
    let mods = mkdir(&wrap.join("mods"));
    mkfile(&mods.join(".package-lock.json"));
    let venv = mkdir(&t.path("venv"));
    mkfile(&venv.join("pyvenv.cfg"));
    let sitepk = sitepk(&t.base);
    let vendor = mkdir(&t.path("vendor"));
    mkfile(&vendor.join("serde-1.0.200/.cargo-checksum.json"));
    let reg = mkdir(&t.path("registry/src"));
    mkfile(&reg.join("index.crates.io-a1/serde-1.0.200/.cargo-ok"));
    mkfile(&reg.join("index.crates.io-a1/serde-1.0.200/Cargo.toml.orig"));
    let idx = mkdir(&t.path("index.crates.io-a1"));
    mkfile(&idx.join("serde-1.0.200/.cargo-ok"));
    mkfile(&idx.join("serde-1.0.200/Cargo.toml.orig"));
    let git = mkdir(&t.path("git/checkouts"));
    mkfile(&git.join("ruff-b18f69e/0be08a2/.cargo-ok"));
    mkdir(&git.join("ruff-b18f69e/0be08a2/.git"));

    for (dep, kind) in [
        (nm, "npm"),
        (mods, "npm"),
        (venv, "python"),
        (sitepk, "python"),
        (vendor, "cargo-vendor"),
        (reg, "cargo-registry"),
        (idx, "cargo-registry"),
        (git, "cargo-git"),
    ] {
        let r = deps_run(&root, &[&dep]);
        assert_eq!(r.code, 0, "{dep:?}: {}", r.stderr);
        assert_eq!(
            json(&r.stdout)["dependencies"]["roots"][0],
            serde_json::json!({"label": kind, "kind": kind}),
            "{dep:?}"
        );
    }
}

#[test]
fn must_not_detect_go_vendor_as_cargo() {
    let t = Temp::new("deps-go-vendor");
    let root = project(&t);
    let vendor = mkdir(&t.path("vendor"));
    mkfile(&vendor.join("modules.txt"));
    mkfile(&vendor.join("github.com/pkg/errors/errors.go"));
    let r = deps_run(&root, &[&vendor]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains("unrecognized layout"), "{}", r.stderr);
}

#[test]
fn a_root_matching_two_kinds_is_an_error() {
    let t = Temp::new("deps-two-kinds");
    let root = project(&t);
    let d = mkdir(&t.path("mods"));
    mkfile(&d.join(".package-lock.json"));
    mkdir(&d.join("foo-1.0.dist-info"));
    let r = deps_run(&root, &[&d]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains("unrecognized layout"), "{}", r.stderr);
}

#[test]
fn an_outside_npm_root_off_the_lookup_path_is_an_error() {
    let t = Temp::new("deps-npm-path");
    let root = project(&t);
    // `named/` is a sibling of `proj/`, never on Node's lookup path.
    let nm = mkdir(&t.path("named/node_modules"));
    mkfile(&nm.join("leftpad/package.json"));
    let r = deps_run(&root, &[&nm]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(
        r.stderr.contains("npm root is not on the lookup path"),
        "{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains(&*nm.to_string_lossy()),
        "stderr leaks the path: {}",
        r.stderr
    );
}

/// Covers AE11. The inventory check that distinguishes this from two
/// unrelated roots lands in U4; this test is ignored until then and must
/// pass by the end of U4.
#[ignore = "AE11 completes in U4"]
#[test]
fn two_outside_npm_roots_holding_the_same_package_are_ambiguous() {
    let t = Temp::new("deps-ambiguous");
    let wrap = mkdir(&t.path("wrap"));
    let root = mkdir(&wrap.join("proj"));
    std::fs::write(root.join("app.js"), "const x = 1;\n").unwrap();
    // Both parents (`wrap` and `wrap/mid`) are ancestors of the scan root,
    // so each npm root is on the lookup path and holds `leftpad` at
    // locator `leftpad`.
    for dir in [wrap.clone(), wrap.join("mid")] {
        mkdir(&dir.join("node_modules"));
        mkfile(&dir.join("node_modules/leftpad/package.json"));
    }
    let r = deps_run(
        &root,
        &[&wrap.join("node_modules"), &wrap.join("mid/node_modules")],
    );
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stdout.is_empty(), "{:?}", r.stdout);
    assert!(
        r.stderr.contains("ambiguous dependency roots"),
        "{}",
        r.stderr
    );
}

/// Covers AE1: a scan that names no dependency root carries no
/// `dependencies` key and no dependency-mode fields.
#[test]
fn a_scan_without_deps_has_no_dependency_content() {
    let root = case("javascript/dependencies/leftpad-no-root");
    let r = run(&[
        OsStr::new("scan"),
        root.as_os_str(),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v = json(&r.stdout);
    assert!(v.get("dependencies").is_none(), "{}", r.stdout);
    let entry = &v["unscanned_dependencies"][0];
    assert_eq!(entry["package"], "leftpad");
    for key in ["reason", "distribution", "distribution_source", "mark"] {
        assert!(entry.get(key).is_none(), "entry holds {key}: {}", r.stdout);
    }
}

//! Build and install hook detection.

mod support;

use egress_core::discover::{Config, Discovery, discover};
use egress_core::model::{BlindSpotKind, Label};
use support::Tree;

fn run(t: &Tree) -> Discovery {
    discover(&t.root, &Config::default()).unwrap_or_else(|e| panic!("tool error: {e}"))
}

fn hooks(d: &Discovery) -> Vec<String> {
    let mut v: Vec<String> = d
        .blind_spots
        .iter()
        .filter(|b| b.kind == BlindSpotKind::BuildHook)
        .map(|b| {
            assert!(!b.coverage_gap && !b.whole_file, "hooks are not gaps");
            assert_eq!(b.symbol, "<module>");
            b.file.clone()
        })
        .collect();
    v.sort();
    v
}

const CARGO: &str = "[package]\nname = \"a\"\nversion = \"0.1.0\"\n";

#[test]
fn covers_ae5_build_rs_is_a_hook_and_scanned_as_source() {
    let t = Tree::new("build-rs");
    t.file("Cargo.toml", CARGO)
        .file("build.rs", "fn main() {}\n")
        .file("src/lib.rs", "");
    let d = run(&t);
    assert_eq!(hooks(&d), vec!["build.rs"]);
    assert_eq!(d.blind_spots.len(), 1, "hook blind spot only");
    let b = d
        .sources
        .iter()
        .find(|s| s.file.display == "build.rs")
        .expect("build.rs scanned");
    assert!(b.labels.contains(&Label::BuildHook));
}

#[test]
fn cargo_build_key_names_the_hook_file_and_false_disables_it() {
    let t = Tree::new("build-key");
    t.file("Cargo.toml", format!("{CARGO}build = \"tools/gen.rs\"\n"))
        .file("tools/gen.rs", "fn main() {}\n")
        .file("build.rs", "fn main() {}\n");
    let d = run(&t);
    assert_eq!(hooks(&d), vec!["tools/gen.rs"]);

    let t = Tree::new("build-false");
    t.file("Cargo.toml", format!("{CARGO}build = false\n"))
        .file("build.rs", "fn main() {}\n");
    assert!(hooks(&run(&t)).is_empty());
}

#[test]
fn virtual_workspace_manifest_has_no_build_script() {
    let t = Tree::new("virtual");
    t.file("Cargo.toml", "[workspace]\nmembers = []\n")
        .file("build.rs", "fn main() {}\n");
    assert!(hooks(&run(&t)).is_empty());
}

#[test]
fn every_hook_family_yields_one_blind_spot() {
    let t = Tree::new("families");
    t.file(
        "rs/Cargo.toml",
        format!("{CARGO}\n[lib]\nproc-macro = true\n"),
    )
    .file("rs/src/lib.rs", "")
    .file(
        "js/package.json",
        r#"{"scripts":{"postinstall":"node x.js","test":"t","build":"b"}}"#,
    )
    .file("native/binding.gyp", "{}")
    .file("py/setup.py", "")
    .file("py/extras.pth", "import os\n")
    .file("py/sitecustomize.py", "")
    .file("py/usercustomize.py", "")
    .file(
        "py2/pyproject.toml",
        "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\"_build\"]\n",
    );
    let d = run(&t);
    assert_eq!(
        hooks(&d),
        vec![
            "js/package.json",
            "native/binding.gyp",
            "py/extras.pth",
            "py/setup.py",
            "py/sitecustomize.py",
            "py/usercustomize.py",
            "py2/pyproject.toml",
            "rs/Cargo.toml",
        ]
    );
}

#[test]
fn each_lifecycle_script_is_its_own_hook() {
    let t = Tree::new("lifecycle");
    t.file(
        "package.json",
        r#"{"scripts":{"preinstall":"a","install":"b","postinstall":"c","prepare":"d","prepack":"e","prepublish":"f"}}"#,
    );
    assert_eq!(hooks(&run(&t)).len(), 6);
}

#[test]
fn test_and_build_scripts_are_not_hooks() {
    let t = Tree::new("not-hooks");
    t.file(
        "package.json",
        r#"{"scripts":{"test":"jest","build":"tsc"}}"#,
    )
    .file(
        "pyproject.toml",
        "[build-system]\nrequires = [\"setuptools\"]\nbuild-backend = \"setuptools.build_meta\"\n",
    )
    .file("index.js", "");
    let d = run(&t);
    assert!(d.blind_spots.is_empty(), "{:?}", d.blind_spots);
}

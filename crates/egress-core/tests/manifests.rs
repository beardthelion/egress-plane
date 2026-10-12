//! Bounded manifest reading and manifest-declared paths.

mod support;

use egress_core::discover::manifests::parse_jsonc;
use egress_core::discover::{Config, Discovery, discover};
use egress_core::model::{BlindSpotKind, Language};
use support::Tree;

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

fn text(d: &Discovery) -> String {
    d.blind_spots
        .iter()
        .map(|b| format!("{} {} {}\n", b.file, b.symbol, b.construct))
        .collect()
}

fn assert_outside(t: &Tree, manifest: &str) {
    let d = run(t);
    assert_eq!(
        spots(&d),
        vec![(manifest.to_string(), BlindSpotKind::ReferenceOutsideRoot)],
        "{manifest}"
    );
    let b = &d.blind_spots[0];
    assert!(b.coverage_gap && !b.whole_file);
    let s = text(&d);
    for frag in ["outside", "base.json", "lib.rs", ".."] {
        assert!(!s.contains(frag), "{manifest}: output holds {frag:?}: {s}");
    }
}

#[test]
fn cargo_lib_path_outside_root() {
    let t = Tree::new("cargo-lib-outside");
    t.file(
        "Cargo.toml",
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[lib]\npath = \"../../outside/lib.rs\"\n",
    );
    assert_outside(&t, "Cargo.toml");
}

#[test]
fn cargo_absolute_bin_path() {
    let t = Tree::new("cargo-bin-abs");
    t.file(
        "Cargo.toml",
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[[bin]]\nname = \"x\"\npath = \"/opt/outside/lib.rs\"\n",
    );
    assert_outside(&t, "Cargo.toml");
}

#[test]
fn package_json_workspaces_outside_root() {
    let t = Tree::new("workspaces-outside");
    t.file("package.json", r#"{"name":"a","workspaces":["../*"]}"#);
    assert_outside(&t, "package.json");
    let t = Tree::new("workspaces-object-outside");
    t.file(
        "package.json",
        r#"{"workspaces":{"packages":["pkgs/*","../outside/*"]}}"#,
    );
    assert_outside(&t, "package.json");
}

#[test]
fn tsconfig_extends_outside_root() {
    let t = Tree::new("tsconfig-extends-outside");
    t.file("tsconfig.json", r#"{"extends": "../../base.json"}"#);
    assert_outside(&t, "tsconfig.json");
}

#[test]
fn tsconfig_paths_outside_root() {
    let t = Tree::new("tsconfig-paths-outside");
    t.file(
        "tsconfig.json",
        r#"{"compilerOptions":{"baseUrl":".","paths":{"@x/*":["../outside/*"]}}}"#,
    );
    assert_outside(&t, "tsconfig.json");
}

#[test]
fn pyproject_backend_path_outside_root() {
    let t = Tree::new("backend-path-outside");
    t.file(
        "pyproject.toml",
        "[build-system]\nrequires = []\nbuild-backend = \"b\"\nbackend-path = [\"..\"]\n",
    );
    assert_outside(&t, "pyproject.toml");
}

#[test]
fn in_root_manifest_paths_are_not_gaps() {
    let t = Tree::new("in-root-refs");
    t.file(
        "Cargo.toml",
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[lib]\npath = \"src/x.rs\"\n",
    )
    .file("src/x.rs", "")
    .file(
        "package.json",
        r#"{"workspaces":["packages/*"],"bin":{"t":"./bin/t.js"}}"#,
    )
    .file("bin/t.js", "");
    let d = run(&t);
    assert!(d.blind_spots.is_empty(), "{:?}", spots(&d));
}

#[test]
fn tsconfig_jsonc_as_tsc_init_writes_it_parses() {
    let t = Tree::new("tsconfig-jsonc");
    t.file(
        "tsconfig.json",
        "{\n  /* Visit https://aka.ms/tsconfig */\n  \"extends\": \"./configs/base.json\",\n  \"compilerOptions\": {\n    \"target\": \"es2016\", // trailing comment\n    \"strict\": true,\n  },\n}\n",
    )
    .file(
        "configs/base.json",
        "{\n  // base\n  \"compilerOptions\": { \"module\": \"commonjs\", },\n}\n",
    )
    .file("src/index.ts", "");
    let d = run(&t);
    assert!(d.blind_spots.is_empty(), "{:?}", spots(&d));
}

#[test]
fn package_json_with_a_comment_is_a_parse_error() {
    let t = Tree::new("package-json-comment");
    t.file(
        "package.json",
        "{\n  // no comments in package.json\n  \"name\": \"a\"\n}\n",
    )
    .file("index.js", "");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("package.json".into(), BlindSpotKind::ManifestParseError)]
    );
    assert!(d.blind_spots[0].whole_file && d.blind_spots[0].coverage_gap);
    // Manifest blind spots leave coverage counts alone.
    assert_eq!(d.coverage.languages[Language::Javascript].skipped, 0);
    assert_eq!(d.coverage.unsupported.skipped, 0);
}

#[test]
fn truncated_oversized_and_deep_manifests_are_parse_errors() {
    let t = Tree::new("bad-manifests");
    t.file("a/Cargo.toml", "[package\nname = \"a\"\nversion = ")
        .file("b/package.json", {
            let mut s = String::from("{\"name\":\"");
            s.push_str(&"x".repeat(9 * 1024 * 1024));
            s.push_str("\"}");
            s
        })
        .file("c/pyproject.toml", {
            let mut s = String::from("[");
            s.push_str(&vec!["a"; 100_000].join("."));
            s.push_str("]\nx = 1\n");
            s
        })
        .file("d/pyproject.toml", {
            let mut s = String::from("x = ");
            s.push_str(&"{a = ".repeat(100_000));
            s.push_str(&"}".repeat(100_000));
            s
        })
        .file("e/package.json", "[".repeat(100_000))
        .file("f/setup.cfg", b"[metadata]\nname = \xff\n");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![
            ("a/Cargo.toml".into(), BlindSpotKind::ManifestParseError),
            ("b/package.json".into(), BlindSpotKind::ManifestParseError),
            ("c/pyproject.toml".into(), BlindSpotKind::ManifestParseError),
            ("d/pyproject.toml".into(), BlindSpotKind::ManifestParseError),
            ("e/package.json".into(), BlindSpotKind::ManifestParseError),
            ("f/setup.cfg".into(), BlindSpotKind::ManifestParseError),
        ]
    );
}

#[test]
fn symlinked_manifest_is_never_read() {
    let t = Tree::new("manifest-link");
    let target = t.outside_file("pkg.json", r#"{"scripts":{"postinstall":"evil"}}"#);
    t.link("package.json", &target).file("index.js", "");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("package.json".into(), BlindSpotKind::SymlinkOutsideRoot)]
    );
}

#[test]
fn jsonc_parser_accepts_comments_and_trailing_commas_only() {
    let v = parse_jsonc("{ /* c */ \"a\": [1, 2,], // x\n \"b\": \"//not a comment\", }").unwrap();
    assert_eq!(v["a"], serde_json::json!([1, 2]));
    assert_eq!(v["b"], "//not a comment");
    assert!(parse_jsonc("{\"a\": 1 /* unterminated").is_err());
    assert!(parse_jsonc("{,}").is_err());
    assert!(parse_jsonc(&"[".repeat(100_000)).is_err());
}

// ---- KTD17: declared Python distribution names ------------------------------

#[test]
fn pyproject_project_and_poetry_declarations_are_collected() {
    let t = Tree::new("pyproject-declared");
    t.file(
        "pyproject.toml",
        "[project]\nname = \"a\"\ndependencies = [\"PyYAML>=6\", \"requests[security]\", \"httpx @ https://x/r.whl\"]\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\nPyJWT = \"^2\"\n",
    );
    let d = run(&t);
    assert_eq!(
        d.manifests.pyproject[0].declared,
        ["PyYAML", "requests", "httpx", "PyJWT"]
    );
    assert_eq!(
        d.manifests.python_declarations,
        ["PyYAML", "requests", "httpx", "PyJWT"]
    );
}

#[test]
fn setup_cfg_install_requires_is_collected() {
    let t = Tree::new("setup-cfg-declared");
    t.file(
        "setup.cfg",
        "[metadata]\nname = a\n\n[options]\ninstall_requires =\n    PyYAML>=6\n    requests; python_version>\"3\"\nzip_safe = False\n",
    );
    let d = run(&t);
    assert_eq!(d.manifests.setup_cfg[0].declared, ["PyYAML", "requests"]);
    assert_eq!(d.manifests.python_declarations, ["PyYAML", "requests"]);
}

#[test]
fn a_malformed_pyproject_contributes_no_declarations() {
    let t = Tree::new("bad-pyproject-decl");
    t.file("pyproject.toml", "[project\nname = \"a\"\n");
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("pyproject.toml".into(), BlindSpotKind::ManifestParseError)]
    );
    assert!(d.manifests.python_declarations.is_empty());
}

// ---- go.mod / go.work -------------------------------------------------------

use egress_core::discover::manifests::{GoReplace, GoReplaceTarget, ManifestKind, parse};

#[test]
fn go_mod_reads_module_go_require_and_replace() {
    let t = Tree::new("go-mod");
    t.file(
        "go.mod",
        "// head comment\n\
         module example.com/m // trailing comment\n\
         \n\
         go 1.22\n\
         \n\
         toolchain go1.26.0\n\
         tool example.com/t\n\
         \n\
         require example.com/a v1.2.3 // indirect\n\
         \n\
         require (\n\
         \texample.com/b v0.1.0\n\
         \texample.com/c v0.2.0 // indirect\n\
         )\n\
         \n\
         replace example.com/b => ./third_party/b\n\
         replace example.com/c v0.2.0 => example.com/cfork v0.3.0\n",
    );
    let d = run(&t);
    assert!(d.blind_spots.is_empty(), "{:?}", d.blind_spots);
    let [m] = &d.manifests.go_mod[..] else {
        panic!("no go.mod parsed: {:?}", d.manifests)
    };
    assert_eq!(m.module.as_deref(), Some("example.com/m"));
    assert_eq!(m.go.as_deref(), Some("1.22"));
    assert_eq!(
        m.require,
        vec![
            ("example.com/a".to_string(), "v1.2.3".to_string()),
            ("example.com/b".to_string(), "v0.1.0".to_string()),
            ("example.com/c".to_string(), "v0.2.0".to_string()),
        ]
    );
    assert_eq!(
        m.replace[0].to,
        GoReplaceTarget::Path(b"third_party/b".to_vec())
    );
    assert_eq!(
        m.replace[1],
        GoReplace {
            from: "example.com/c".to_string(),
            from_version: Some("v0.2.0".to_string()),
            to: GoReplaceTarget::Module {
                path: "example.com/cfork".to_string(),
                version: Some("v0.3.0".to_string()),
            },
        }
    );
}

#[test]
fn go_work_reads_single_and_block_uses() {
    let t = Tree::new("go-work");
    t.file("a/go.mod", "module example.com/a\ngo 1.22\n")
        .file("b/go.mod", "module example.com/b\ngo 1.22\n")
        .file("c/go.mod", "module example.com/c\ngo 1.22\n")
        .file("go.work", "go 1.24\n\nuse ./a\n\nuse (\n\t./b\n\t./c\n)\n");
    let d = run(&t);
    assert!(d.blind_spots.is_empty(), "{:?}", d.blind_spots);
    let [w] = &d.manifests.go_work[..] else {
        panic!("no go.work parsed: {:?}", d.manifests)
    };
    assert_eq!(w.go.as_deref(), Some("1.24"));
    assert_eq!(w.uses, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
}

#[test]
fn an_unterminated_require_block_is_a_parse_error() {
    let t = Tree::new("go-mod-bad");
    t.file(
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/a v1.0.0\n",
    );
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("go.mod".to_string(), BlindSpotKind::ManifestParseError)]
    );
    assert!(d.manifests.go_mod.is_empty());
}

#[test]
fn go_mod_replace_outside_root_is_a_gap() {
    let t = Tree::new("go-mod-outside");
    t.file(
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nreplace example.com/a => ../outside/a\n",
    );
    let d = run(&t);
    assert_eq!(
        spots(&d),
        vec![("go.mod".to_string(), BlindSpotKind::ReferenceOutsideRoot)]
    );
    let s = text(&d);
    assert!(!s.contains("outside") && !s.contains(".."), "{s}");
}

/// A line that is not `verb args`, a known directive with the wrong
/// arity, or a `replace` missing `=>` is malformed rather than skipped.
#[test]
fn a_garbage_go_mod_is_a_parse_error_not_a_skip() {
    for body in [
        "%%% garbage\n",
        ")\n",
        "module\n",
        "go x.y\n",
        "require example.com/a\n",
        "replace example.com/a example.com/b\n",
    ] {
        assert!(
            parse(ManifestKind::GoMod, b"go.mod", body).is_err(),
            "{body:?} parsed"
        );
    }
}

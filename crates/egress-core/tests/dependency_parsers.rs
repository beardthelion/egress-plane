//! Dependency metadata parser tests (U4): byte fixtures only, no paths.

use egress_core::deps::lockfile::{cargo_lock, resolve_edge};
use egress_core::deps::metadata;
use egress_core::deps::version::{Pre, semver};

#[test]
fn record_quoted_path_with_comma_parses() {
    let rows = metadata::record(b"\"a,b/x.py\",sha256=abc,10\nsix.py,,\n").unwrap();
    assert_eq!(rows[0].path, "a,b/x.py");
    assert_eq!(rows[0].sha256.as_deref(), Some("abc"));
    assert_eq!(rows[1].sha256, None);
}

#[test]
fn record_non_sha256_row_is_hashless() {
    let rows = metadata::record(b"m.py,md5=dead,10\n").unwrap();
    assert_eq!(rows[0].sha256, None);
}

#[test]
fn metadata_continuation_and_body_yield_name_and_version() {
    let meta = metadata::metadata(
        b"Metadata-Version: 2.1\nName: leftpy\nVersion: 1.0\nSummary: a summary\n that wraps\n\nbody text ignored\n",
    )
    .unwrap();
    assert_eq!(meta.name, "leftpy");
    assert_eq!(meta.version, "1.0");
}

#[test]
fn top_level_names_derived_from_record() {
    let rows = metadata::record(
        b"yaml/__init__.py,sha256=a,1\nsix.py,sha256=b,1\n_cffi.abi3.so,sha256=c,1\nleftpy-1.0.dist-info/RECORD,,\n__pycache__/x.pyc,,\nsome.pth,,\n../bin/x,,\n",
    )
    .unwrap();
    let names = metadata::top_level_names(&rows);
    assert_eq!(names, vec!["yaml", "six", "_cffi"]);
}

#[test]
fn cargo_checksum_parses_files_and_package() {
    let c =
        metadata::cargo_checksum(br#"{"files":{"src/lib.rs":"aa"},"package":"bb","x":1}"#).unwrap();
    assert_eq!(c.files, [("src/lib.rs".to_string(), "aa".to_string())]);
    assert_eq!(c.package.as_deref(), Some("bb"));
}

#[test]
fn package_json_name_and_version() {
    let m = metadata::package_json(br#"{"name":"leftpad","version":"2.0.0"}"#).unwrap();
    assert_eq!(m.name, "leftpad");
    assert_eq!(m.version, "2.0.0");
}

#[test]
fn cargo_toml_name_version_and_lib_name() {
    let t =
        b"[package]\nname = \"tokio-util\"\nversion = \"0.7.10\"\n[lib]\nname = \"tokio_util\"\n";
    assert_eq!(
        metadata::cargo_toml_name_version(t).unwrap(),
        ("tokio-util".to_string(), "0.7.10".to_string())
    );
    assert_eq!(
        metadata::cargo_toml_lib_name(t).as_deref(),
        Some("tokio_util")
    );
}

#[test]
fn semver_precedence_ranks_patch_and_prerelease() {
    assert!(semver("1.0.9").unwrap() < semver("1.0.10").unwrap());
    assert!(semver("1.0.0-alpha").unwrap() < semver("1.0.0").unwrap());
    assert!(semver("2.0.0") > semver("1.9.9"));
    let v = semver("1.2.3-beta.2").unwrap();
    assert_eq!(v.pre, vec![Pre::Str("beta".to_string()), Pre::Num(2)]);
}

#[test]
fn semver_numeric_before_alphanumeric_prerelease() {
    assert!(semver("1.0.0-1") < semver("1.0.0-alpha"));
    assert_eq!(semver("not.a.version"), None);
}

#[test]
fn cargo_lock_v3_and_v4_parse() {
    for format in [3, 4] {
        let text = format!(
            "version = {format}\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://x\"\nchecksum = \"aa\"\ndependencies = [\"serde_derive\", \"quote 1.0.0 (registry+https://x)\"]\n"
        );
        let lock = cargo_lock(text.as_bytes()).unwrap();
        assert_eq!(lock.format, format);
        assert_eq!(lock.packages[0].name, "serde");
        assert_eq!(lock.packages[0].version, "1.0.200");
        assert_eq!(lock.packages[0].dependencies.len(), 2);
    }
}

#[test]
fn cargo_lock_without_version_is_unsupported() {
    assert!(cargo_lock(b"[[package]]\nname = \"a\"\nversion = \"1\"\n").is_err());
    assert!(cargo_lock(b"version = 5\n[[package]]\nname = \"a\"\nversion = \"1\"\n").is_err());
}

#[test]
fn dependency_edges_resolve_versions() {
    let lock = cargo_lock(
        b"version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\ndependencies = [\"serde_derive\", \"quote 1.0.0\"]\n\n[[package]]\nname = \"serde_derive\"\nversion = \"1.0.200\"\n\n[[package]]\nname = \"quote\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"quote\"\nversion = \"2.0.0\"\n",
    )
    .unwrap();
    let serde = &lock.packages[0];
    assert_eq!(
        resolve_edge(&lock, &serde.dependencies[0]).unwrap().version,
        "1.0.200"
    );
    // A versioned edge resolves exactly.
    assert_eq!(
        resolve_edge(&lock, &serde.dependencies[1]).unwrap().version,
        "1.0.0"
    );
    // An ambiguous bare edge falls back to a locked version.
    let quote = resolve_edge(&lock, "quote").unwrap();
    assert!(["1.0.0", "2.0.0"].contains(&quote.version.as_str()));
}

// ---- KTD16: the `.pth` auto-run line test ----------------------------------

use egress_core::deps::auto_run::pth_has_import_line;

#[test]
fn pth_line_test_hits_and_misses() {
    assert!(pth_has_import_line(b"import os\n"));
    // Tab separator is a hit.
    assert!(pth_has_import_line(b"import\tsys\n"));
    // `importlib` at line start is not.
    assert!(!pth_has_import_line(b"importlib\n"));
    // A `#import` comment line is not.
    assert!(!pth_has_import_line(b"#import os\n"));
    // A path-only line is not.
    assert!(!pth_has_import_line(b"/opt/site/extra\n"));
    // Executable line after a path line.
    assert!(pth_has_import_line(b"/opt/x\nimport os\n"));
}

#[test]
fn pth_line_test_separators_and_bom() {
    // A lone CR separates lines.
    assert!(pth_has_import_line(b"/opt/x\rimport os\n"));
    // A form feed separates lines.
    assert!(pth_has_import_line(b"/opt/x\x0cimport os\n"));
    // A UTF-8 BOM at file start strips.
    assert!(pth_has_import_line(b"\xef\xbb\xbfimport os\n"));
    // U+2028 separates in UTF-8 text.
    assert!(pth_has_import_line("/opt/x\u{2028}import os\n".as_bytes()));
    // Non-UTF-8 bytes fall back to CR/LF splitting only: the 0x0c form
    // feed inside an invalid file does not split, so no hit.
    let weird = b"/opt/x\xff\x0cimport os\n";
    assert!(!pth_has_import_line(weird));
}

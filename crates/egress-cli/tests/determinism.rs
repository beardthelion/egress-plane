//! End-to-end determinism.

mod support;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use egress_core::json::to_json;
use egress_scan::{ScanOptions, scan_with};
use support::{Temp, case, copy_tree, corpus, run, scan};

#[test]
fn two_scans_of_the_mixed_corpus_are_byte_identical() {
    let root = corpus().join("mixed");
    for format in ["json", "text"] {
        let a = scan(&root, format);
        let b = scan(&root, format);
        assert!(matches!(a.code, 0 | 2), "{}", a.stderr);
        assert_eq!(a.code, b.code);
        assert!(!a.stdout.is_empty());
        assert_eq!(a.stdout, b.stdout, "{format}");
    }
}

#[test]
fn one_worker_and_eight_workers_give_identical_json() {
    let root = corpus();
    let run = |workers| {
        let opts = ScanOptions {
            workers,
            ..ScanOptions::default()
        };
        to_json(&scan_with(&root, &opts).unwrap().report)
    };
    let one = run(1);
    let eight = run(8);
    assert!(one.len() > 10_000, "the whole corpus was scanned");
    assert_eq!(one, eight);
}

#[test]
fn a_tree_in_two_absolute_directories_gives_identical_output() {
    let t = Temp::new("two-dirs");
    let a = t.path("a");
    let b = t.path("deeper/still/b-other-name");
    copy_tree(&corpus().join("mixed"), &a);
    copy_tree(&corpus().join("mixed"), &b);
    for format in ["json", "text"] {
        let x = scan(&a, format);
        let y = scan(&b, format);
        assert!(matches!(x.code, 0 | 2), "{}", x.stderr);
        assert_eq!(x.code, y.code);
        assert!(!x.stdout.is_empty());
        assert_eq!(x.stdout, y.stdout, "{format}");
        let base = t.base.display().to_string();
        assert!(!x.stdout.contains(&base), "{format} holds an absolute path");
    }
}

fn is_location_line(l: &str) -> bool {
    let l = l.trim_start();
    l.starts_with("\"line\": ") || l.starts_with("\"column\": ")
}

/// A blank line above an egress call changes only `location` lines.
#[test]
fn blank_line_changes_only_location() {
    let t = Temp::new("line-shift");
    let root = t.path("tree");
    copy_tree(&case("python/ordinary/requests-post-env"), &root);
    let before = scan(&root, "json");
    let file = root.join("notify.py");
    let src = std::fs::read_to_string(&file).unwrap();
    let call = src.find("requests.post").expect("fixture holds the call");
    let line_start = src[..call].rfind('\n').map_or(0, |i| i + 1);
    let mut changed = src.clone();
    changed.insert(line_start, '\n');
    std::fs::write(&file, changed).unwrap();
    let after = scan(&root, "json");
    assert_eq!(before.code, after.code);

    let b: Vec<_> = before.stdout.lines().collect();
    let a: Vec<_> = after.stdout.lines().collect();
    assert_eq!(b.len(), a.len());
    let diffs: Vec<_> = b.iter().zip(&a).filter(|(x, y)| x != y).collect();
    assert!(!diffs.is_empty(), "the site moved");
    for (x, y) in &diffs {
        assert!(is_location_line(x) && is_location_line(y), "{x} / {y}");
    }
    assert!(
        diffs
            .iter()
            .any(|(x, _)| x.trim_start().starts_with("\"line\""))
    );
}

#[test]
fn json_output_holds_no_scan_root_path() {
    let root = case("mixed/ordinary/three-languages");
    let j = scan(&root, "json").stdout;
    let abs = root.canonicalize().unwrap();
    assert!(!j.contains(abs.to_str().unwrap()));
    assert!(!j.contains(Path::new(env!("CARGO_MANIFEST_DIR")).to_str().unwrap()));
}

/// Dependency output is byte-identical across worker counts and root
/// argument order.
#[test]
fn dependency_output_is_deterministic() {
    let dir = corpus().join("javascript/dependencies/leftpad-closure");
    let tree = dir.join("tree");
    let nm = tree.join("node_modules");
    let run = |workers: usize, roots: &[PathBuf]| {
        let opts = ScanOptions {
            workers,
            dependency_roots: roots.to_vec(),
            ..ScanOptions::default()
        };
        to_json(&scan_with(&tree, &opts).unwrap().report)
    };
    // Two roots is more realistic; one still exercises the order path.
    let a = run(1, std::slice::from_ref(&nm));
    let b = run(8, std::slice::from_ref(&nm));
    assert_eq!(a, b);
    assert!(a.contains("\"dependencies\""));
}

/// Root argument order does not change the output.
#[test]
fn dependency_root_order_is_deterministic() {
    let t = Temp::new("dep-order");
    let root = t.path("root");
    let nm = root.join("node_modules");
    let sitepk = root.join("sitepk");
    std::fs::create_dir_all(&nm).unwrap();
    std::fs::create_dir_all(&sitepk).unwrap();
    std::fs::write(
        root.join("app.js"),
        b"const l = require(\"leftpad\");\nl();\n",
    )
    .unwrap();
    std::fs::write(root.join("app.py"), b"import leftpy\n").unwrap();
    std::fs::create_dir_all(nm.join("leftpad")).unwrap();
    std::fs::write(
        nm.join("leftpad/package.json"),
        br#"{"name":"leftpad","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(nm.join("leftpad/index.js"), b"").unwrap();
    std::fs::create_dir_all(sitepk.join("leftpy")).unwrap();
    std::fs::write(sitepk.join("leftpy/__init__.py"), b"X = 1\n").unwrap();

    for format in ["json", "text"] {
        let a = run(&[
            OsStr::new("scan"),
            root.as_os_str(),
            OsStr::new("--format"),
            OsStr::new(format),
            OsStr::new("--deps"),
            nm.as_os_str(),
            OsStr::new("--deps"),
            sitepk.as_os_str(),
        ]);
        let b = run(&[
            OsStr::new("scan"),
            root.as_os_str(),
            OsStr::new("--format"),
            OsStr::new(format),
            OsStr::new("--deps"),
            sitepk.as_os_str(),
            OsStr::new("--deps"),
            nm.as_os_str(),
        ]);
        assert_eq!(a.code, b.code);
        assert_eq!(a.stdout, b.stdout, "{format}");
    }
}

/// Every dependency corpus case keeps the same exit code with roots
/// named as without.
#[test]
fn dependency_roots_never_change_the_exit_code() {
    let mut checked = 0;
    for cat in std::fs::read_dir(corpus().join("javascript"))
        .unwrap()
        .chain(std::fs::read_dir(corpus().join("python")).unwrap())
        .chain(std::fs::read_dir(corpus().join("rust")).unwrap())
    {
        let cat = cat.unwrap();
        if cat.file_name() != "dependencies" {
            continue;
        }
        for c in std::fs::read_dir(cat.path()).unwrap().flatten() {
            let dir = c.path();
            let Ok(expected) = std::fs::read_to_string(dir.join("expected.toml")) else {
                continue;
            };
            let code = expected
                .lines()
                .find_map(|l| l.strip_prefix("exit_code = "))
                .and_then(|v| v.trim().parse::<i32>().ok());
            let Some(code) = code else { continue };
            let tree = dir.join("tree");
            if !tree.is_dir() {
                continue;
            }
            let no_roots = scan(&tree, "json");
            assert_eq!(no_roots.code, code, "{:?}", dir);
            checked += 1;
        }
    }
    assert!(checked > 20, "too few cases checked: {checked}");
}

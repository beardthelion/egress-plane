//! The safe open path (KTD12, R22): lstat first, per-component no-follow
//! walk, non-blocking open, handle recheck, bounded read, fail closed.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use egress_core::discover::{Config, Discovery, SourceFile, discover};
use egress_core::model::BlindSpotKind;
use support::{Tree, privileged};

fn run(t: &Tree) -> Discovery {
    discover(&t.root, &Config::default()).unwrap_or_else(|e| panic!("tool error: {e}"))
}

fn source<'a>(d: &'a Discovery, p: &str) -> &'a SourceFile {
    d.sources
        .iter()
        .find(|s| s.file.display == p)
        .unwrap_or_else(|| panic!("{p} not admitted"))
}

/// Runs `f` on another thread and fails if it does not finish in time, so a
/// blocking open shows up as a failure instead of a hung test run.
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(20))
        .expect("operation blocked")
}

#[test]
fn reads_a_regular_file() {
    let t = Tree::new("read-ok");
    t.file("src/a.py", "x = 1\n");
    let d = run(&t);
    assert_eq!(d.read_source(source(&d, "src/a.py")).unwrap(), "x = 1\n");
}

#[test]
fn fifo_is_not_regular_and_never_opened() {
    let t = Tree::new("fifo");
    t.file("src/app.py", "").fifo("src/pipe.py");
    let root = t.root.clone();
    let d = within(move || discover(&root, &Config::default()).unwrap());
    let b: Vec<_> = d
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind))
        .collect();
    assert_eq!(
        b,
        vec![("src/pipe.py".into(), BlindSpotKind::NotRegularFile)]
    );
    assert!(d.blind_spots[0].whole_file && d.blind_spots[0].coverage_gap);
    assert_eq!(d.coverage.python.skipped, 1);
}

#[test]
fn unreadable_file_is_a_blind_spot_not_a_tool_error() {
    if privileged() {
        return;
    }
    let t = Tree::new("unreadable");
    t.file("src/a.py", "x = 1\n").chmod("src/a.py", 0o000);
    let d = run(&t);
    assert_eq!(
        d.read_source(source(&d, "src/a.py")),
        Err(BlindSpotKind::Unreadable)
    );
}

#[test]
fn too_large_file_is_skipped_without_reading() {
    let t = Tree::new("too-large");
    t.file("big.js", vec![b' '; 9 * 1024 * 1024])
        .file("ok.js", "");
    let d = run(&t);
    let b: Vec<_> = d
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind))
        .collect();
    assert_eq!(b, vec![("big.js".into(), BlindSpotKind::TooLarge)]);
    assert_eq!(d.sources.len(), 1);
}

#[test]
fn file_that_grows_past_the_cap_after_the_walk_is_too_large() {
    let t = Tree::new("grows");
    t.file("a.js", "x");
    let d = run(&t);
    t.file("a.js", vec![b' '; 8 * 1024 * 1024 + 1]);
    assert_eq!(
        d.read_source(source(&d, "a.js")),
        Err(BlindSpotKind::TooLarge)
    );
}

#[test]
fn latin1_is_undecodable_and_bom_is_stripped() {
    let t = Tree::new("encoding");
    t.file("latin.py", b"s = '\xe9t\xe9'\n")
        .file("bom.py", b"\xef\xbb\xbfx = 1\n");
    let d = run(&t);
    assert_eq!(
        d.read_source(source(&d, "latin.py")),
        Err(BlindSpotKind::Undecodable)
    );
    assert_eq!(d.read_source(source(&d, "bom.py")).unwrap(), "x = 1\n");
}

#[test]
fn file_swapped_for_an_outside_symlink_is_never_followed() {
    let t = Tree::new("swap-link");
    let secret = t.outside_file("secret.py", "TOP_SECRET = 1\n");
    t.file("src/a.py", "x = 1\n");
    let d = run(&t);
    std::fs::remove_file(t.path("src/a.py")).unwrap();
    std::os::unix::fs::symlink(&secret, t.path("src/a.py")).unwrap();
    let got = d.read_source(source(&d, "src/a.py"));
    assert!(got.is_err(), "followed the swapped link: {got:?}");
}

#[test]
fn directory_swapped_for_an_outside_symlink_is_never_followed() {
    let t = Tree::new("swap-dir");
    t.outside_file("src/a.py", "TOP_SECRET = 1\n");
    t.file("src/a.py", "x = 1\n");
    let d = run(&t);
    std::fs::remove_dir_all(t.path("src")).unwrap();
    std::os::unix::fs::symlink(t.outside.join("src"), t.path("src")).unwrap();
    let got = d.read_source(source(&d, "src/a.py"));
    assert!(got.is_err(), "followed the swapped directory: {got:?}");
}

#[test]
fn file_swapped_for_a_fifo_does_not_block() {
    let t = Tree::new("swap-fifo");
    t.file("src/a.py", "x = 1\n");
    let d = run(&t);
    std::fs::remove_file(t.path("src/a.py")).unwrap();
    support::mkfifo(&t.path("src/a.py"));
    let f = source(&d, "src/a.py").clone();
    let d = Arc::new(d);
    let d2 = Arc::clone(&d);
    let got = within(move || d2.read_source(&f));
    assert_eq!(got, Err(BlindSpotKind::NotRegularFile));
}

#[test]
fn concurrent_swap_race_never_yields_outside_content() {
    let t = Tree::new("swap-race");
    let secret = t.outside_file("secret.py", "TOP_SECRET = 1\n");
    t.file("src/a.py", "x = 1\n");
    let d = run(&t);
    let f = source(&d, "src/a.py").clone();
    let stop = Arc::new(AtomicBool::new(false));
    let path = t.path("src/a.py");
    let tmp_file = t.path("src/.a.tmp");
    let tmp_link = t.path("src/.a.lnk");
    let flipper = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut n = 0u32;
            while !stop.load(Ordering::SeqCst) {
                if n.is_multiple_of(2) {
                    let _ = std::fs::remove_file(&tmp_link);
                    let _ = std::os::unix::fs::symlink(&secret, &tmp_link);
                    let _ = std::fs::rename(&tmp_link, &path);
                } else {
                    let _ = std::fs::write(&tmp_file, "x = 1\n");
                    let _ = std::fs::rename(&tmp_file, &path);
                }
                n = n.wrapping_add(1);
            }
        })
    };
    for _ in 0..5000 {
        if let Ok(text) = d.read_source(&f) {
            assert!(!text.contains("TOP_SECRET"), "read the outside file");
        }
    }
    stop.store(true, Ordering::SeqCst);
    flipper.join().unwrap();
}

#[test]
fn unsafe_open_unavailable_never_reads() {
    let t = Tree::new("unsafe-open");
    t.file("src/a.py", "x = 1\n");
    let cfg = Config {
        force_unsafe_open_unavailable: true,
        ..Config::default()
    };
    let d = discover(&t.root, &cfg).unwrap();
    assert_eq!(
        d.read_source(source(&d, "src/a.py")),
        Err(BlindSpotKind::UnsafeOpenUnavailable)
    );
}

#[test]
fn unsafe_open_unavailable_covers_manifest_reads() {
    let t = Tree::new("unsafe-open-manifest");
    t.file("package.json", r#"{"scripts":{"postinstall":"x"}}"#)
        .file("index.js", "");
    let cfg = Config {
        force_unsafe_open_unavailable: true,
        ..Config::default()
    };
    let d = discover(&t.root, &cfg).unwrap();
    let kinds: Vec<_> = d
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![("package.json".into(), BlindSpotKind::UnsafeOpenUnavailable)]
    );
}

//! The safe open path: lstat first, per-component no-follow
//! walk, non-blocking open, handle recheck, bounded read, fail closed.

mod support;

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use egress_core::discover::open::{AccessCheck, NodeType, ReadFail, RootDir};
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
fn only_one_leading_bom_is_stripped_and_the_rest_must_decode() {
    let t = Tree::new("bom-edges");
    t.file("only.py", b"\xef\xbb\xbf")
        .file("twice.py", b"\xef\xbb\xbf\xef\xbb\xbfx\n")
        .file("inner.py", b"x\xef\xbb\xbf\n")
        .file("bad.py", b"\xef\xbb\xbf\xe9\n")
        .file("cut.py", b"\xef\xbb");
    let d = run(&t);
    assert_eq!(d.read_source(source(&d, "only.py")).unwrap(), "");
    assert_eq!(
        d.read_source(source(&d, "twice.py")).unwrap(),
        "\u{feff}x\n"
    );
    assert_eq!(
        d.read_source(source(&d, "inner.py")).unwrap(),
        "x\u{feff}\n"
    );
    assert_eq!(
        d.read_source(source(&d, "bad.py")),
        Err(BlindSpotKind::Undecodable)
    );
    assert_eq!(
        d.read_source(source(&d, "cut.py")),
        Err(BlindSpotKind::Undecodable)
    );
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

// ---------------------------------------------------------------------------
// KTD9 additions: errno-preserving reads, full metadata, no-follow access
// checks, and filesystem types.
// ---------------------------------------------------------------------------

fn open_root(t: &Tree) -> RootDir {
    RootDir::open(&t.root).unwrap()
}

#[test]
fn errno_preserving_read_distinguishes_absent_and_unreadable() {
    let t = Tree::new("read-errno");
    t.file("src/a.py", "x = 1\n");
    let root = open_root(&t);
    let mut fs = Vec::new();
    let got = root.read_file_errno(b"src/missing.py", 1024, &mut fs);
    assert_eq!(got, Err(ReadFail::Errno(libc::ENOENT)));
    let got = root.read_file_errno(b"src/a.py", 1024, &mut fs);
    assert_eq!(got.unwrap(), b"x = 1\n");
    assert!(!fs.is_empty(), "read reports handle filesystem types");
}

#[test]
fn errno_preserving_read_reports_type_and_size_failures() {
    let t = Tree::new("read-errno-kinds");
    t.dir("src").fifo("pipe").file("big.js", vec![b'x'; 4096]);
    let root = open_root(&t);
    let mut fs = Vec::new();
    assert_eq!(
        root.read_file_errno(b"pipe", 1024, &mut fs),
        Err(ReadFail::NotRegular(NodeType::Fifo))
    );
    assert_eq!(
        root.read_file_errno(b"src", 1024, &mut fs),
        Err(ReadFail::NotRegular(NodeType::Dir))
    );
    assert_eq!(
        root.read_file_errno(b"big.js", 1024, &mut fs),
        Err(ReadFail::TooLarge)
    );
}

#[test]
fn errno_preserving_read_reports_a_final_symlink() {
    let t = Tree::new("read-errno-link");
    t.file("real.txt", "x").link("link.txt", "real.txt");
    let root = open_root(&t);
    let mut fs = Vec::new();
    assert_eq!(
        root.read_file_errno(b"link.txt", 1024, &mut fs),
        Err(ReadFail::NotRegular(NodeType::Symlink))
    );
}

#[test]
fn full_metadata_reports_type_owner_mode_and_device() {
    let t = Tree::new("meta-full");
    t.file("plain.txt", "x").fifo("pipe");
    let root = open_root(&t);
    let mut fs = Vec::new();

    let st = root.lstat_full(b"plain.txt", &mut fs).unwrap();
    assert_eq!(st.kind, NodeType::File);
    assert_eq!(st.size, 1);
    let want_mode = std::fs::metadata(t.path("plain.txt")).unwrap().mode();
    assert_eq!(st.mode & 0o777, want_mode & 0o777);
    assert_eq!(st.uid, unsafe { libc::geteuid() });

    let st = root.lstat_full(b"pipe", &mut fs).unwrap();
    assert_eq!(st.kind, NodeType::Fifo);

    let st = root.lstat_full(b"", &mut fs).unwrap();
    assert_eq!(st.kind, NodeType::Dir);
}

#[cfg(target_os = "linux")]
#[test]
fn full_metadata_splits_char_and_block_devices() {
    // /dev/null exists on every Linux host.
    let root = RootDir::open(std::path::Path::new("/")).unwrap();
    let mut fs = Vec::new();
    let st = root.lstat_full(b"dev/null", &mut fs).unwrap();
    assert_eq!(st.kind, NodeType::Char);
    assert_eq!(st.rdev, 259);
    let st = root.lstat_full(b"dev", &mut fs).unwrap();
    assert_eq!(st.kind, NodeType::Dir);
}

#[test]
fn full_listing_reports_entry_types() {
    let t = Tree::new("list-full");
    t.file("d/inner.txt", "x").fifo("d/pipe").dir("d/sub");
    let root = open_root(&t);
    let mut fs = Vec::new();
    let entries = root.list_dir_full(b"d", &mut fs).unwrap();
    let kinds: Vec<(&[u8], NodeType)> = entries
        .iter()
        .map(|(n, st)| (n.as_slice(), st.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (b"inner.txt".as_slice(), NodeType::File),
            (b"pipe".as_slice(), NodeType::Fifo),
            (b"sub".as_slice(), NodeType::Dir),
        ]
    );
    assert!(!fs.is_empty());
}

#[test]
fn access_check_never_follows_a_final_symlink() {
    let t = Tree::new("access-link");
    let target = t.outside_file("writable.txt", "x");
    t.link("link", &target);
    let root = open_root(&t);
    let mut fs = Vec::new();
    let got = root.access_nofollow(b"link", true, true, &mut fs).unwrap();
    // The symlink itself is reported; nothing about the outside target's
    // access result is produced.
    assert_eq!(got, AccessCheck::Symlink);
}

#[test]
fn access_check_grants_and_refuses_real_files() {
    let t = Tree::new("access-real");
    t.file("ro.txt", "x").chmod("ro.txt", 0o444);
    t.file("rw.txt", "x").chmod("rw.txt", 0o644);
    let root = open_root(&t);
    let mut fs = Vec::new();
    assert_eq!(
        root.access_nofollow(b"ro.txt", true, false, &mut fs)
            .unwrap(),
        AccessCheck::Granted
    );
    assert_eq!(
        root.access_nofollow(b"rw.txt", true, true, &mut fs)
            .unwrap(),
        AccessCheck::Granted
    );
    if !privileged() {
        assert_eq!(
            root.access_nofollow(b"ro.txt", false, true, &mut fs)
                .unwrap(),
            AccessCheck::Refused
        );
    }
    let err = root
        .access_nofollow(b"missing", true, false, &mut fs)
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

#[cfg(target_os = "linux")]
#[test]
fn filesystem_type_of_proc_and_tmpfs_handles() {
    let root = RootDir::open(std::path::Path::new("/")).unwrap();
    let mut fs = Vec::new();
    let data = root
        .read_file_errno(b"proc/version", 1 << 20, &mut fs)
        .unwrap();
    assert!(!data.is_empty());
    assert!(
        fs.iter().all(|f| f == "proc"),
        "every handle under /proc reports proc: {fs:?}"
    );

    // Find a tmpfs mount point from this process's own mountinfo that we
    // can list (`proc/mounts` is a symlink, which the walk refuses).
    let info = format!("proc/{}/mountinfo", unsafe { libc::getpid() });
    let mounts = root
        .read_file_errno(info.as_bytes(), 1 << 20, &mut Vec::new())
        .unwrap();
    let text = String::from_utf8_lossy(&mounts);
    let point = text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let sep = f.iter().position(|x| *x == "-")?;
            let fstype = f.get(sep + 1)?;
            let point = f.get(4)?;
            (*fstype == "tmpfs").then(|| point.to_string())
        })
        .find(|p| {
            let rel = p.trim_start_matches('/');
            root.list_dir_full(rel.as_bytes(), &mut Vec::new()).is_ok()
        })
        .expect("no listable tmpfs mount on this host");
    let rel = point.trim_start_matches('/').as_bytes().to_vec();
    let mut fs = Vec::new();
    root.list_dir_full(&rel, &mut fs).unwrap();
    assert_eq!(fs.last().map(String::as_str), Some("tmpfs"), "{point}");
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

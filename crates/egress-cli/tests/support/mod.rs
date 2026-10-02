//! Helpers for running the `egress-plane` binary against fixture trees and
//! temporary trees.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[path = "../../../egress-core/tests/support/mod.rs"]
mod tree;

use tree::restore;
#[allow(unused_imports)]
pub use tree::{chmod, mkfifo};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The corpus root.
pub fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus")
}

/// The scan root of one corpus case, for example `python/ordinary/x`.
pub fn case(rel: &str) -> PathBuf {
    corpus().join(rel).join("tree")
}

/// The captured result of one run of the binary.
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `egress-plane` with `args`, killing it after 60 seconds.
pub fn run(args: &[&OsStr]) -> Run {
    run_with(Command::new(env!("CARGO_BIN_EXE_egress-plane")).args(args))
}

pub fn run_with(cmd: &mut Command) -> Run {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn egress-plane");
    let start = Instant::now();
    // Drain the pipes on their own threads so a large report cannot block.
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut out, &mut v).unwrap();
        v
    });
    let err_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut err, &mut v).unwrap();
        v
    });
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("egress-plane did not finish within 60 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Run {
        code: status.code().expect("exited by signal"),
        stdout: String::from_utf8(out_t.join().unwrap()).expect("stdout is UTF-8"),
        stderr: String::from_utf8(err_t.join().unwrap()).expect("stderr is UTF-8"),
    }
}

/// `egress-plane scan <root> --format <format>`.
pub fn scan(root: &Path, format: &str) -> Run {
    run(&[
        OsStr::new("scan"),
        root.as_os_str(),
        OsStr::new("--format"),
        OsStr::new(format),
    ])
}

/// `egress-plane scan <root>` with the default (text) format.
pub fn scan_default(root: &Path) -> Run {
    run(&[OsStr::new("scan"), root.as_os_str()])
}

/// A temporary directory removed on drop.
pub struct Temp {
    pub base: PathBuf,
}

impl Temp {
    pub fn new(name: &str) -> Temp {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("egress-cli")
            .join(format!("{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        Temp { base }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.base.join(rel)
    }

    pub fn file(&self, rel: &str, contents: impl AsRef<[u8]>) -> &Self {
        self.file_bytes(rel.as_bytes(), contents)
    }

    pub fn file_bytes(&self, rel: &[u8], contents: impl AsRef<[u8]>) -> &Self {
        let p = self.base.join(OsStr::from_bytes(rel));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, contents).unwrap();
        self
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        restore(&self.base);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Copies a directory tree, recreating symlinks as symlinks.
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let ft = e.file_type().unwrap();
        let dst = to.join(e.file_name());
        if ft.is_symlink() {
            symlink(std::fs::read_link(e.path()).unwrap(), &dst).unwrap();
        } else if ft.is_dir() {
            copy_tree(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

/// Characters KTD18 escapes, other than the newline that ends report lines.
pub fn raw_unsafe(text: &str) -> Vec<char> {
    text.chars()
        .filter(|&c| c != '\n' && egress_core::escape::needs_escape(c))
        .collect()
}

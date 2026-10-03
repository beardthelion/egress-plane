//! Real fixture trees in a temporary directory, so symlinks, FIFOs, and
//! permissions behave as they do on disk.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A scan root plus a sibling `outside/` directory, removed on drop.
pub struct Tree {
    pub base: PathBuf,
    pub root: PathBuf,
    pub outside: PathBuf,
}

fn bytes_path(base: &Path, rel: &[u8]) -> PathBuf {
    base.join(OsStr::from_bytes(rel))
}

impl Tree {
    pub fn new(name: &str) -> Tree {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("egress-core-tests")
            .join(format!("{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        Tree {
            base,
            root,
            outside,
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn file(&self, rel: &str, contents: impl AsRef<[u8]>) -> &Self {
        self.file_bytes(rel.as_bytes(), contents)
    }

    pub fn file_bytes(&self, rel: &[u8], contents: impl AsRef<[u8]>) -> &Self {
        let p = bytes_path(&self.root, rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, contents).unwrap();
        self
    }

    pub fn dir(&self, rel: &str) -> &Self {
        std::fs::create_dir_all(self.path(rel)).unwrap();
        self
    }

    pub fn link(&self, rel: &str, target: impl AsRef<Path>) -> &Self {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        symlink(target, &p).unwrap();
        self
    }

    pub fn fifo(&self, rel: &str) -> &Self {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        mkfifo(&p);
        self
    }

    pub fn chmod(&self, rel: &str, mode: u32) -> &Self {
        chmod(&self.path(rel), mode);
        self
    }

    /// Writes a file under the sibling `outside/` directory and returns its
    /// absolute path.
    pub fn outside_file(&self, rel: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let p = self.outside.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, contents).unwrap();
        p
    }
}

pub fn mkfifo(p: &Path) {
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
    assert_eq!(rc, 0, "mkfifo {}", p.display());
}

pub fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Makes every directory under `p` writable and searchable again so it can
/// be removed.
pub fn restore(p: &Path) {
    if let Ok(md) = std::fs::symlink_metadata(p)
        && md.is_dir()
    {
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                restore(&e.path());
            }
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        restore(&self.base);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// True when the process can bypass permission bits (root), which makes
/// permission-denied cases unobservable.
pub fn privileged() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

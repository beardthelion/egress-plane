//! The one open path for in-root content.
//!
//! Every path is a raw repo-relative byte string with `/` separators, resolved
//! from a handle on the canonical root one component at a time. Each
//! intermediate directory is opened with `O_NOFOLLOW | O_DIRECTORY`, so a
//! component swapped for a symlink fails instead of leaving the root. A file
//! is `lstat`ed first and opened only when it is a regular file, then opened
//! with `O_NOFOLLOW | O_NONBLOCK` and its type re-checked on the handle, so a
//! file swapped for a symlink or a FIFO after the walk is never followed or
//! blocked on. The same walk works on Linux and macOS; `openat2` with
//! `RESOLVE_BENEATH` is not used, since the per-component walk already gives
//! the property on both hosts.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::model::ToolError;

/// File type from `lstat`, never following a final symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    File,
    Dir,
    Symlink,
    /// FIFO, socket, or device node.
    Other,
}

/// What `lstat` reported for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub kind: EntryType,
    pub size: u64,
}

/// Why a bounded read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// Not a regular file at `lstat` time or on the opened handle, or a path
    /// component that is no longer a real directory.
    NotRegular,
    TooLarge,
    Unreadable,
}

// ---------------------------------------------------------------------------
// KTD9 additions: errno-preserving reads, full metadata, a no-follow access
// check, and filesystem types. Everything below is additive; the methods
// above keep their signatures and behavior.
// ---------------------------------------------------------------------------

/// The raw file type from `lstat`, with sockets, FIFOs, and character and
/// block devices kept apart instead of merged into [`EntryType::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    File,
    Dir,
    Symlink,
    Socket,
    Fifo,
    Char,
    Block,
    /// Anything else the filesystem reports.
    Other,
}

/// Full metadata for one node: mode, owner, size, raw type, and the device
/// number for character and block nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeStat {
    pub kind: NodeType,
    /// Raw `st_mode` bits (type plus permissions).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// `st_rdev`; meaningful only for [`NodeType::Char`] and
    /// [`NodeType::Block`].
    pub rdev: u64,
}

/// Why a bounded read failed, with the errno preserved so a caller can tell
/// `ENOENT` (absent) from `EMFILE` (descriptor exhaustion) from everything
/// else (KTD9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFail {
    /// The final component exists but is not a regular file; carries its
    /// type so a symlink is distinguishable from a FIFO or a directory.
    NotRegular(NodeType),
    TooLarge,
    /// Any other failure, with the raw errno.
    Errno(i32),
}

/// The result of an access check that never describes a swapped-in
/// symlink's target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCheck {
    /// Every requested mode bit is permitted.
    Granted,
    /// The check ran and was refused (for example `EACCES`, `EPERM`,
    /// `EROFS`).
    Refused,
    /// The final component is a symlink; no access result for its target is
    /// produced.
    Symlink,
}

/// A directory reached from the root through real directories only, so a
/// walk can step one component at a time without reopening every ancestor.
#[derive(Debug)]
pub struct DirHandle(OwnedFd);

fn readlinkat(dir: libc::c_int, name: &CStr) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    loop {
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        if buf.len() >= 1 << 20 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// An open handle on the canonical scan root.
#[derive(Debug)]
pub struct RootDir {
    fd: OwnedFd,
    path: PathBuf,
}

fn cstr(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Splits a repo-relative path into components, rejecting anything that is
/// not a plain name.
fn components(rel: &[u8]) -> io::Result<Vec<&[u8]>> {
    if rel.is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<&[u8]> = rel.split(|b| *b == b'/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == b"." || *p == b"..")
    {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(parts)
}

fn stat_kind(st: &libc::stat) -> EntryType {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => EntryType::File,
        libc::S_IFDIR => EntryType::Dir,
        libc::S_IFLNK => EntryType::Symlink,
        _ => EntryType::Other,
    }
}

fn node_type(st: &libc::stat) -> NodeType {
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => NodeType::File,
        libc::S_IFDIR => NodeType::Dir,
        libc::S_IFLNK => NodeType::Symlink,
        libc::S_IFSOCK => NodeType::Socket,
        libc::S_IFIFO => NodeType::Fifo,
        libc::S_IFCHR => NodeType::Char,
        libc::S_IFBLK => NodeType::Block,
        _ => NodeType::Other,
    }
}

fn fstatat_full(dir: libc::c_int, name: &CStr) -> io::Result<NodeStat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is NUL-terminated and `st` is a valid out pointer.
    check(unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: fstatat succeeded and filled `st`.
    let st = unsafe { st.assume_init() };
    Ok(NodeStat {
        kind: node_type(&st),
        mode: st.st_mode,
        uid: st.st_uid,
        gid: st.st_gid,
        size: st.st_size.max(0) as u64,
        rdev: st.st_rdev,
    })
}

/// The filesystem type of an open handle as a name (KTD9). On Linux the
/// `fstatfs` magic maps to a well-known name, with `0x<hex>` for anything
/// unmapped; on macOS the `f_fstypename` string is used directly.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fstatfs_name(fd: libc::c_int) -> io::Result<String> {
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `st` is a valid out pointer.
    check(unsafe { libc::fstatfs(fd, st.as_mut_ptr()) })?;
    // SAFETY: fstatfs succeeded and filled `st`.
    let st = unsafe { st.assume_init() };
    // `f_type` is signed on glibc and unsigned on musl.
    #[allow(clippy::unnecessary_cast)]
    let name = match st.f_type as i64 {
        libc::PROC_SUPER_MAGIC => "proc".to_string(),
        libc::SYSFS_MAGIC => "sysfs".to_string(),
        libc::TMPFS_MAGIC => "tmpfs".to_string(),
        libc::DEVPTS_SUPER_MAGIC => "devpts".to_string(),
        libc::CGROUP_SUPER_MAGIC => "cgroup".to_string(),
        libc::CGROUP2_SUPER_MAGIC => "cgroup2".to_string(),
        libc::OVERLAYFS_SUPER_MAGIC => "overlay".to_string(),
        other => format!("0x{other:x}"),
    };
    Ok(name)
}

/// The filesystem type of an open handle (KTD9), per `f_fstypename`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn fstatfs_name(fd: libc::c_int) -> io::Result<String> {
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `st` is a valid out pointer.
    check(unsafe { libc::fstatfs(fd, st.as_mut_ptr()) })?;
    // SAFETY: fstatfs succeeded and filled `st`.
    let st = unsafe { st.assume_init() };
    // SAFETY: f_fstypename is a fixed char array holding a NUL-terminated
    // name after a successful fstatfs.
    let name = unsafe { CStr::from_ptr(st.f_fstypename.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
}

/// An access check that never follows a swapped-in final symlink.
///
/// Implementation choice (KTD9): on Linux this calls `faccessat2` with
/// `AT_SYMLINK_NOFOLLOW` through `libc::syscall`, so the kernel evaluates
/// the named object itself even if it was swapped for a symlink between
/// the caller's `lstat` and this call; on macOS it calls `faccessat` with
/// the same flag, which has the `AT_SYMLINK_NOFOLLOW` semantics natively.
/// `EACCES`, `EPERM`, and `EROFS` map to [`AccessCheck::Refused`]; every
/// other errno propagates so `ENOENT` stays distinguishable from a denial.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn faccessat_nofollow(dir: libc::c_int, name: &CStr, mode: libc::c_int) -> io::Result<AccessCheck> {
    // SAFETY: `name` is NUL-terminated; faccessat2 is read-only.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            dir,
            name.as_ptr(),
            mode,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(AccessCheck::Granted);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EROFS) => Ok(AccessCheck::Refused),
        _ => Err(e),
    }
}

/// `faccessat` with `AT_SYMLINK_NOFOLLOW` on macOS (KTD9).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn faccessat_nofollow(dir: libc::c_int, name: &CStr, mode: libc::c_int) -> io::Result<AccessCheck> {
    // SAFETY: `name` is NUL-terminated; faccessat is read-only.
    let rc = unsafe { libc::faccessat(dir, name.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        return Ok(AccessCheck::Granted);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => Ok(AccessCheck::Refused),
        _ => Err(e),
    }
}

fn fstatat_nofollow(dir: libc::c_int, name: &CStr) -> io::Result<Stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is NUL-terminated and `st` is a valid out pointer.
    check(unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: fstatat succeeded and filled `st`.
    let st = unsafe { st.assume_init() };
    Ok(Stat {
        kind: stat_kind(&st),
        size: st.st_size.max(0) as u64,
    })
}

fn fstat(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is a valid out pointer.
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded and filled `st`.
    Ok(unsafe { st.assume_init() })
}

fn openat(dir: libc::c_int, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated; the returned descriptor is owned here.
    let fd = check(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) })?;
    // SAFETY: `fd` is a fresh descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_ptr() -> *mut libc::c_int {
    // SAFETY: always valid for the calling thread.
    unsafe { libc::__errno_location() }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn errno_ptr() -> *mut libc::c_int {
    // SAFETY: always valid for the calling thread.
    unsafe { libc::__error() }
}

impl RootDir {
    /// Canonicalizes `root` and opens it.
    pub fn open(root: &Path) -> Result<RootDir, ToolError> {
        let path = std::fs::canonicalize(root).map_err(|_| ToolError::RootNotFound)?;
        let md = std::fs::metadata(&path).map_err(|_| ToolError::RootNotFound)?;
        if !md.is_dir() {
            return Err(ToolError::RootNotDirectory);
        }
        let c = cstr(path.as_os_str().as_bytes())
            .map_err(|_| ToolError::Internal("root path holds a NUL byte"))?;
        let fd = openat(libc::AT_FDCWD, &c, DIR_FLAGS)
            .map_err(|_| ToolError::Internal("cannot open the scan root"))?;
        Ok(RootDir { fd, path })
    }

    /// The canonical root path. Never printed; used only for lexical
    /// comparison of absolute link targets.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens the directory at `parts`, refusing any symlink component.
    fn open_dir_parts(&self, parts: &[&[u8]]) -> io::Result<Option<OwnedFd>> {
        let mut cur: Option<OwnedFd> = None;
        for p in parts {
            let dir = cur.as_ref().map_or(self.fd.as_raw_fd(), |f| f.as_raw_fd());
            cur = Some(openat(dir, &cstr(p)?, DIR_FLAGS)?);
        }
        Ok(cur)
    }

    /// Runs `f` with the parent directory handle and the final name of `rel`.
    fn with_parent<T>(
        &self,
        rel: &[u8],
        f: impl FnOnce(libc::c_int, &CStr) -> io::Result<T>,
    ) -> io::Result<T> {
        let parts = components(rel)?;
        let (last, dirs) = parts
            .split_last()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent = self.open_dir_parts(dirs)?;
        let dir = parent
            .as_ref()
            .map_or(self.fd.as_raw_fd(), |f| f.as_raw_fd());
        f(dir, &cstr(last)?)
    }

    /// `lstat` of an in-root path, never following its final component.
    pub fn lstat(&self, rel: &[u8]) -> io::Result<Stat> {
        if rel.is_empty() {
            return Ok(Stat {
                kind: EntryType::Dir,
                size: 0,
            });
        }
        self.with_parent(rel, fstatat_nofollow)
    }

    /// The target bytes of an in-root symlink.
    pub fn readlink(&self, rel: &[u8]) -> io::Result<Vec<u8>> {
        self.with_parent(rel, readlinkat)
    }

    fn at_parts<T>(
        &self,
        dir: Option<&DirHandle>,
        name: &[u8],
        f: impl FnOnce(libc::c_int, &CStr) -> io::Result<T>,
    ) -> io::Result<T> {
        if components(name)?.len() != 1 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let fd = dir.map_or(self.fd.as_raw_fd(), |d| d.0.as_raw_fd());
        f(fd, &cstr(name)?)
    }

    /// `lstat` of the single component `name` in `dir` (the root when
    /// `None`), never following it.
    pub fn lstat_at(&self, dir: Option<&DirHandle>, name: &[u8]) -> io::Result<Stat> {
        self.at_parts(dir, name, fstatat_nofollow)
    }

    /// Opens the real directory `name` in `dir` (the root when `None`),
    /// refusing a symlink.
    pub fn open_dir_at(&self, dir: Option<&DirHandle>, name: &[u8]) -> io::Result<DirHandle> {
        self.at_parts(dir, name, |fd, n| openat(fd, n, DIR_FLAGS).map(DirHandle))
    }

    /// The target bytes of the symlink `name` in `dir` (the root when
    /// `None`).
    pub fn readlink_at(&self, dir: Option<&DirHandle>, name: &[u8]) -> io::Result<Vec<u8>> {
        self.at_parts(dir, name, readlinkat)
    }

    /// Lists a directory: each entry's name and `lstat` result, sorted by
    /// name bytes. Entries that vanish while listing are skipped; any other
    /// `lstat` failure fails the whole listing, so an entry is never dropped
    /// silently.
    pub fn list_dir(&self, rel: &[u8]) -> io::Result<Vec<(Vec<u8>, Stat)>> {
        let parts = components(rel)?;
        let fd = match self.open_dir_parts(&parts)? {
            Some(fd) => fd,
            None => openat(self.fd.as_raw_fd(), c".", DIR_FLAGS)?,
        };
        let raw = fd.as_raw_fd();
        // fdopendir takes ownership of a descriptor; give it a duplicate so
        // `fd` stays valid for fstatat below.
        // SAFETY: `raw` is an open descriptor.
        let dup = check(unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) })?;
        // SAFETY: `dup` is an open directory descriptor we own.
        let dirp = unsafe { libc::fdopendir(dup) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: fdopendir failed, so `dup` is still ours to close.
            unsafe { libc::close(dup) };
            return Err(e);
        }
        let mut names = Vec::new();
        let result = loop {
            // SAFETY: errno is thread-local and writable.
            unsafe { *errno_ptr() = 0 };
            // SAFETY: `dirp` is a valid open directory stream.
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                // SAFETY: errno is thread-local and readable.
                let err = unsafe { *errno_ptr() };
                break if err == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(err))
                };
            }
            // SAFETY: `d_name` is a NUL-terminated name inside the entry.
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            let b = name.to_bytes();
            if b != b"." && b != b".." {
                names.push(b.to_vec());
            }
        };
        // SAFETY: `dirp` is valid and closed exactly once; this closes `dup`.
        unsafe { libc::closedir(dirp) };
        result?;
        names.sort();
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            match fstatat_nofollow(raw, &cstr(&n)?) {
                Ok(st) => out.push((n, st)),
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Reads at most `limit` bytes of a regular in-root file. A file longer
    /// than `limit` is [`ReadError::TooLarge`].
    pub fn read_file(&self, rel: &[u8], limit: u64) -> Result<Vec<u8>, ReadError> {
        self.read_impl(rel, limit, false)
    }

    /// Reads the first `limit` bytes of a regular in-root file, with the same
    /// checks as [`RootDir::read_file`].
    pub fn read_prefix(&self, rel: &[u8], limit: u64) -> Result<Vec<u8>, ReadError> {
        self.read_impl(rel, limit, true)
    }

    fn read_impl(&self, rel: &[u8], limit: u64, prefix: bool) -> Result<Vec<u8>, ReadError> {
        let res = self.with_parent(rel, |dir, name| {
            let st = fstatat_nofollow(dir, name)?;
            if st.kind != EntryType::File {
                return Ok(Err(ReadError::NotRegular));
            }
            if st.size > limit && !prefix {
                return Ok(Err(ReadError::TooLarge));
            }
            let fd = openat(
                dir,
                name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
            )?;
            if stat_kind(&fstat(fd.as_raw_fd())?) != EntryType::File {
                return Ok(Err(ReadError::NotRegular));
            }
            // Sized from the stat, never past the read bound below.
            let cap = usize::try_from(st.size.min(limit).saturating_add(1)).unwrap_or(0);
            let mut out = Vec::with_capacity(cap);
            let mut file = std::fs::File::from(fd);
            use std::io::Read;
            (&mut file).take(limit + 1).read_to_end(&mut out)?;
            if prefix {
                out.truncate(limit as usize);
            } else if out.len() as u64 > limit {
                return Ok(Err(ReadError::TooLarge));
            }
            Ok(Ok(out))
        });
        match res {
            Ok(r) => r,
            Err(e) => Err(match e.raw_os_error() {
                // A symlink where a directory or the file was expected, or a
                // component that is no longer a directory.
                Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EMLINK) => {
                    ReadError::NotRegular
                }
                _ => ReadError::Unreadable,
            }),
        }
    }

    // ---------------------------------------------------------------------
    // KTD9 additions. Each observed method also records the filesystem type
    // of every handle the walk opened into `fs`, in walk order, so callers
    // can verify kernel filesystems (KTD24).
    // ---------------------------------------------------------------------

    /// `open_dir_parts` that also records each opened handle's filesystem
    /// type.
    fn open_dir_parts_fs(
        &self,
        parts: &[&[u8]],
        fs: &mut Vec<String>,
    ) -> io::Result<Option<OwnedFd>> {
        let mut cur: Option<OwnedFd> = None;
        for p in parts {
            let dir = cur.as_ref().map_or(self.fd.as_raw_fd(), |f| f.as_raw_fd());
            let fd = openat(dir, &cstr(p)?, DIR_FLAGS)?;
            fs.push(fstatfs_name(fd.as_raw_fd())?);
            cur = Some(fd);
        }
        Ok(cur)
    }

    /// `with_parent` that records the filesystem type of every opened
    /// directory handle.
    fn with_parent_fs<T>(
        &self,
        rel: &[u8],
        fs: &mut Vec<String>,
        f: impl FnOnce(libc::c_int, &CStr) -> io::Result<T>,
    ) -> io::Result<T> {
        let parts = components(rel)?;
        let (last, dirs) = parts
            .split_last()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let parent = self.open_dir_parts_fs(dirs, fs)?;
        let dir = parent
            .as_ref()
            .map_or(self.fd.as_raw_fd(), |f| f.as_raw_fd());
        f(dir, &cstr(last)?)
    }

    /// Full `lstat` of an in-root path (KTD9): raw file type, mode, owner,
    /// size, and device number, never following the final component.
    pub fn lstat_full(&self, rel: &[u8], fs: &mut Vec<String>) -> io::Result<NodeStat> {
        if rel.is_empty() {
            let st = fstat(self.fd.as_raw_fd())?;
            return Ok(NodeStat {
                kind: node_type(&st),
                mode: st.st_mode,
                uid: st.st_uid,
                gid: st.st_gid,
                size: st.st_size.max(0) as u64,
                rdev: st.st_rdev,
            });
        }
        self.with_parent_fs(rel, fs, fstatat_full)
    }

    /// The target bytes of an in-root symlink, recording the filesystem
    /// type of every opened directory handle (KTD9). A parent directory
    /// that cannot be opened for reading but can be traversed (for
    /// example `proc/self/ns` once the process is non-dumpable, which
    /// shows `dr-x--x--x root`) is crossed with a single `readlinkat`
    /// on the remaining components.
    pub fn readlink_observed(&self, rel: &[u8], fs: &mut Vec<String>) -> io::Result<Vec<u8>> {
        let parts = components(rel)?;
        let Some((last, dirs)) = parts.split_last() else {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        };
        let mut cur: Option<OwnedFd> = None;
        for (i, p) in dirs.iter().enumerate() {
            let dir = cur.as_ref().map_or(self.fd.as_raw_fd(), |f| f.as_raw_fd());
            match openat(dir, &cstr(p)?, DIR_FLAGS) {
                Ok(fd) => {
                    fs.push(fstatfs_name(fd.as_raw_fd())?);
                    cur = Some(fd);
                }
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    let mut tail = dirs[i].to_vec();
                    for p in &dirs[i + 1..] {
                        tail.push(b'/');
                        tail.extend_from_slice(p);
                    }
                    tail.push(b'/');
                    tail.extend_from_slice(last);
                    return readlinkat(dir, &cstr(&tail)?);
                }
                Err(e) => return Err(e),
            }
        }
        let dir = cur.as_ref().map_or(self.fd.as_raw_fd(), |f| f.as_raw_fd());
        readlinkat(dir, &cstr(last)?)
    }

    /// An access check that cannot follow a swapped-in final symlink
    /// (KTD9). `read` and `write` select the `R_OK` and `W_OK` bits. A
    /// symlink at the final component is reported as
    /// [`AccessCheck::Symlink`]; anything else gets `faccessat2` with
    /// `AT_SYMLINK_NOFOLLOW` on Linux (`faccessat` on macOS), so a swap
    /// between the type check and the access check still cannot reach the
    /// target.
    pub fn access_nofollow(
        &self,
        rel: &[u8],
        read: bool,
        write: bool,
        fs: &mut Vec<String>,
    ) -> io::Result<AccessCheck> {
        let mut mode = 0;
        if read {
            mode |= libc::R_OK;
        }
        if write {
            mode |= libc::W_OK;
        }
        self.with_parent_fs(rel, fs, |dir, name| {
            let st = fstatat_full(dir, name)?;
            if st.kind == NodeType::Symlink {
                return Ok(AccessCheck::Symlink);
            }
            faccessat_nofollow(dir, name, mode)
        })
    }

    /// Lists a directory like [`RootDir::list_dir`], but each entry carries
    /// full metadata ([`NodeStat`]) and the filesystem types of the opened
    /// handles go to `fs` (KTD9).
    pub fn list_dir_full(
        &self,
        rel: &[u8],
        fs: &mut Vec<String>,
    ) -> io::Result<Vec<(Vec<u8>, NodeStat)>> {
        let parts = components(rel)?;
        let fd = match self.open_dir_parts_fs(&parts, fs)? {
            Some(fd) => fd,
            None => {
                let fd = openat(self.fd.as_raw_fd(), c".", DIR_FLAGS)?;
                fs.push(fstatfs_name(fd.as_raw_fd())?);
                fd
            }
        };
        let raw = fd.as_raw_fd();
        // SAFETY: `raw` is an open descriptor.
        let dup = check(unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) })?;
        // SAFETY: `dup` is an open directory descriptor we own.
        let dirp = unsafe { libc::fdopendir(dup) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: fdopendir failed, so `dup` is still ours to close.
            unsafe { libc::close(dup) };
            return Err(e);
        }
        let mut names = Vec::new();
        let result = loop {
            // SAFETY: errno is thread-local and writable.
            unsafe { *errno_ptr() = 0 };
            // SAFETY: `dirp` is a valid open directory stream.
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                // SAFETY: errno is thread-local and readable.
                let err = unsafe { *errno_ptr() };
                break if err == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(err))
                };
            }
            // SAFETY: `d_name` is a NUL-terminated name inside the entry.
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            let b = name.to_bytes();
            if b != b"." && b != b".." {
                names.push(b.to_vec());
            }
        };
        // SAFETY: `dirp` is valid and closed exactly once; this closes `dup`.
        unsafe { libc::closedir(dirp) };
        result?;
        names.sort();
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            match fstatat_full(raw, &cstr(&n)?) {
                Ok(st) => out.push((n, st)),
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Reads at most `limit` bytes of a regular in-root file, preserving
    /// the errno on failure ([`ReadFail`], KTD9) and recording the
    /// filesystem type of every opened handle into `fs`.
    pub fn read_file_errno(
        &self,
        rel: &[u8],
        limit: u64,
        fs: &mut Vec<String>,
    ) -> Result<Vec<u8>, ReadFail> {
        // The file handle's filesystem type goes in `file_fs` (appended to
        // `fs` after the walk's directory entries).
        let mut file_fs = Vec::new();
        let res = self.with_parent_fs(rel, fs, |dir, name| {
            let st = fstatat_full(dir, name)?;
            if st.kind != NodeType::File {
                return Ok(Err(ReadFail::NotRegular(st.kind)));
            }
            if st.size > limit {
                return Ok(Err(ReadFail::TooLarge));
            }
            let fd = openat(
                dir,
                name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
            )?;
            file_fs.push(fstatfs_name(fd.as_raw_fd())?);
            let kind = node_type(&fstat(fd.as_raw_fd())?);
            if kind != NodeType::File {
                return Ok(Err(ReadFail::NotRegular(kind)));
            }
            let cap = usize::try_from(st.size.min(limit).saturating_add(1)).unwrap_or(0);
            let mut out = Vec::with_capacity(cap);
            let mut file = std::fs::File::from(fd);
            use std::io::Read;
            (&mut file).take(limit + 1).read_to_end(&mut out)?;
            if out.len() as u64 > limit {
                return Ok(Err(ReadFail::TooLarge));
            }
            Ok(Ok(out))
        });
        fs.extend(file_fs);
        match res {
            Ok(r) => r,
            Err(e) => Err(ReadFail::Errno(e.raw_os_error().unwrap_or(0))),
        }
    }
}

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
}

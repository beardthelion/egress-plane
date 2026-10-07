//! The Linux live adapters (KTD8, KTD17, KTD25).
//!
//! The first action of a live run is `prctl(PR_SET_DUMPABLE, 0)`; only
//! then does the adapter inventory descriptors (checking the listing
//! handle's filesystem and the `proc/self` hop before listing), read the
//! environment names from the in-memory `environ` vector, record the
//! pid, and query the Landlock ABI. Nothing here reads secret contents,
//! other processes, or network state.

use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, RawFd};

use super::{EnvName, Fact, Facts, FdEntry, Platform, ProcessFact};
use crate::facts::ffi;

/// `procfs` magic from `fstatfs` on the listing handle (KTD8, KTD24).
const PROC_SUPER_MAGIC: i64 = 0x9fa0;

/// The Linux startup facts in the KTD8 order: the process is already
/// non-dumpable when this returns.
pub fn collect() -> Facts {
    set_non_dumpable();
    let fds = descriptor_inventory();
    let env_names = env_names();
    let process = Fact::Read(ProcessFact {
        pid: unsafe { libc::getpid() } as u64,
    });
    Facts {
        platform: Some(Platform::Linux),
        process,
        env_names,
        fds,
        landlock_abi: Some(landlock_abi()),
        ..Default::default()
    }
}

/// `prctl(PR_SET_DUMPABLE, 0)`: the first action of a live run (KTD25),
/// so a tracing parent cannot observe the environment we are about to
/// enumerate.
pub fn set_non_dumpable() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

/// Environment names from the process `environ` vector (R17): only the
/// bytes before the first `=` are kept; entries without a separator are
/// `NoSeparator` and their bytes are dropped.
pub fn env_names() -> Fact<Vec<EnvName>> {
    let mut out = Vec::new();
    // SAFETY: `environ` is a stable process-lifetime vector of C
    // strings; we only read pointers and copy the name bytes.
    unsafe {
        let p = ffi::environ;
        if p.is_null() {
            return Fact::Read(out);
        }
        let mut i = 0isize;
        while !(*p.offset(i)).is_null() {
            let bytes = CStr::from_ptr(*p.offset(i)).to_bytes();
            match bytes.iter().position(|b| *b == b'=') {
                Some(n) => out.push(EnvName::Name(bytes[..n].to_vec())),
                None => out.push(EnvName::NoSeparator),
            }
            i += 1;
        }
    }
    Fact::Read(out)
}

/// The inherited-descriptor inventory (KTD8): opens `proc/self/fd`,
/// records its handle as the probe's own, verifies the handle's
/// filesystem is procfs and that `proc/self` names this pid (or the
/// accepted ancestor pid namespace), then lists every descriptor with
/// its observed link target through that one handle.
pub fn descriptor_inventory() -> Fact<Vec<FdEntry>> {
    inventory(fs_magic)
}

/// The snapshot-only seam for the filesystem-magic check: the caller
/// supplies the magic the listing handle reports, so tests can replay
/// the `fs-type-mismatch` path without a real fake-proc mount.
#[cfg(feature = "snapshot")]
pub fn descriptor_inventory_with_fs(magic: i64) -> Fact<Vec<FdEntry>> {
    inventory(|_| magic)
}

fn inventory(magic_of: impl FnOnce(RawFd) -> i64) -> Fact<Vec<FdEntry>> {
    // SAFETY: read-only open of our own descriptor directory.
    let fd = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Fact::Unreadable;
    }
    if magic_of(fd) != PROC_SUPER_MAGIC {
        unsafe {
            libc::close(fd);
        }
        return Fact::FsTypeMismatch;
    }
    if !proc_self_names_self() {
        unsafe {
            libc::close(fd);
        }
        return Fact::ProcSelfMismatch;
    }
    // fdopendir takes ownership of the recorded handle, so the listing
    // goes through exactly the fd we checked.
    let dirp = unsafe { libc::fdopendir(fd) };
    if dirp.is_null() {
        unsafe {
            libc::close(fd);
        }
        return Fact::Unreadable;
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `dirp` is a live DIR* we own.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    let mut out = Vec::new();
    for name in names {
        let Ok(fd_num) = std::str::from_utf8(&name).unwrap_or("").parse::<u64>() else {
            continue;
        };
        let Ok(cname) = std::ffi::CString::new(name) else {
            continue;
        };
        let mut buf = vec![0u8; 4096];
        // SAFETY: `fd` names the descriptor directory and `cname` one of
        // its entries; readlinkat never follows the link.
        let n = unsafe { libc::readlinkat(fd, cname.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        let target = if n < 0 {
            "<unreadable>".to_string()
        } else {
            String::from_utf8_lossy(&buf[..n as usize]).into_owned()
        };
        out.push(FdEntry {
            fd: fd_num,
            target,
            probe_own: fd_num == fd as u64,
        });
    }
    out.sort_by_key(|e| e.fd);
    unsafe {
        libc::closedir(dirp);
    }
    Fact::Read(out)
}

fn fs_magic(fd: RawFd) -> i64 {
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid statfs buffer and `fd` is open.
    if unsafe { libc::fstatfs(fd, &mut st) } != 0 {
        return -1;
    }
    st.f_type as i64
}

/// Whether `proc/self` resolves to this process's pid, or to a pid that
/// is this process in an ancestor pid namespace (the KTD24 chain: the
/// outer pid's `NSpid` must end with our pid).
fn proc_self_names_self() -> bool {
    let pid = unsafe { libc::getpid() } as u64;
    let target = match std::fs::read_link("/proc/self") {
        Ok(t) => t,
        Err(_) => return false,
    };
    let text = target.as_os_str().as_bytes();
    let Ok(target_pid) = String::from_utf8_lossy(text).trim().parse::<u64>() else {
        return false;
    };
    if target_pid == pid {
        return true;
    }
    ancestor_pidns_accepts(pid, target_pid)
}

/// Reads `proc/<outer>/status` (a procfs path, checked by magic) and
/// accepts when its `NSpid` chain ends with `pid`.
fn ancestor_pidns_accepts(pid: u64, outer: u64) -> bool {
    let path = format!("/proc/{outer}/status");
    let f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if fs_magic(f.as_raw_fd()) != PROC_SUPER_MAGIC {
        return false;
    }
    let mut buf = vec![0u8; 1 << 20];
    use std::io::Read;
    let n = match f.take(1 << 20).read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let text = String::from_utf8_lossy(&buf[..n]);
    let Some(nspid) = text
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:").map(str::trim))
    else {
        return false;
    };
    nspid
        .split_whitespace()
        .next_back()
        .and_then(|t| t.parse::<u64>().ok())
        == Some(pid)
}

/// The Landlock ABI version: the `CREATE_RULESET_VERSION` query returns
/// the ABI number, `ENOSYS` (not built) or `EOPNOTSUPP` (disabled).
fn landlock_abi() -> Fact<u32> {
    let rc = ffi::landlock_create_ruleset_version();
    if rc >= 0 {
        Fact::Read(rc as u32)
    } else {
        match (-rc) as i32 {
            libc::ENOSYS => Fact::NotBuilt,
            libc::EOPNOTSUPP => Fact::Disabled,
            _ => Fact::Unreadable,
        }
    }
}

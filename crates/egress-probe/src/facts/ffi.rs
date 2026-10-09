//! FFI declarations the pinned libc does not export (KTD17).
//!
//! Linux: the `environ` symbol (env names are read from the process
//! image, never `proc/self/environ`, so values never cross the reader)
//! and the Landlock ruleset-version flag for the ABI query. The KTD7
//! passive guard permits `libc::syscall` only in this file and only for
//! `SYS_landlock_create_ruleset`.

/// The `landlock_create_ruleset` ABI-version query flag
/// (`LANDLOCK_CREATE_RULESET_VERSION`, `(1U << 0)` in linux/landlock.h).
#[cfg(target_os = "linux")]
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    /// The process environment vector: `NAME=VALUE` strings. Only the
    /// bytes before `=` are ever copied out (R17).
    pub static mut environ: *const *const std::ffi::c_char;
}

/// The `landlock_create_ruleset` ABI-version query: a NULL ruleset
/// pointer with the VERSION flag. Returns the ABI number, `-ENOSYS`
/// when Landlock is not built, `-EOPNOTSUPP` when disabled.
#[cfg(target_os = "linux")]
#[rustfmt::skip]
pub fn landlock_create_ruleset_version() -> i64 {
    // SAFETY: a NULL ruleset pointer with the VERSION flag performs a
    // pure query with no side effects; the KTD7 passive guard permits
    // libc::syscall only in this file for this call and only where the
    // name sits on the same line (kept on one line deliberately).
    let v = LANDLOCK_CREATE_RULESET_VERSION;
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, v) }
}

// ---------------------------------------------------------------------------
// macOS (all behind cfg(target_os = "macos")).
// ---------------------------------------------------------------------------

/// `proc_pidinfo` flavors (sys/proc_info.h): the descriptor list and the
/// per-descriptor vnode-path record.
#[cfg(target_os = "macos")]
pub const PROC_PIDLISTFDS: libc::c_int = 1;
#[cfg(target_os = "macos")]
pub const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;

/// `procx` descriptor types reported by `PROC_PIDLISTFDS`
/// (sys/proc_info.h `PROX_FDTYPE_*`).
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_VNODE: u32 = 1;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_SOCKET: u32 = 2;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_PSHM: u32 = 3;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_PSEM: u32 = 4;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_KQUEUE: u32 = 5;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_PIPE: u32 = 6;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_FSEVENTS: u32 = 7;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_NETPOLICY: u32 = 9;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_CHANNEL: u32 = 10;
#[cfg(target_os = "macos")]
pub const PROX_FDTYPE_NEXUS: u32 = 11;

/// The traced-state sysctl (`kern.proc.pid`): `libc::KERN_PROC` /
/// `libc::KERN_PROC_PID` name the mib, `P_TRACED` is the flag bit in
/// `extern_proc.p_flag` (sys/proc.h).
#[cfg(target_os = "macos")]
pub const P_TRACED: u32 = 0x00000800;
/// Byte offset of `extern_proc.p_flag` inside the LP64 `kinfo_proc`:
/// `p_un` (16) plus two pointers.
#[cfg(target_os = "macos")]
pub const KINFO_PROC_P_FLAG_OFFSET: usize = 32;

/// `NET_RT_DUMP` on the `net.route` sysctl tree (`PF_ROUTE`); the
/// address family sits in `mib[3]` and the command in `mib[4]`
/// (net/route.h).
#[cfg(target_os = "macos")]
pub const NET_RT_DUMP: libc::c_int = 1;

/// `statfs.f_flags` bit naming a read-only mount (sys/mount.h).
#[cfg(target_os = "macos")]
pub const MNT_RDONLY: u32 = 0x1;

/// `getfsstat` `flags` argument: report cached state only, so a mount
/// that would block on a network filesystem's server never stalls the
/// probe (KTD26).
#[cfg(target_os = "macos")]
pub const MNT_NOWAIT: libc::c_int = 2;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// `sandbox_check` (sandbox.h): a NULL operation on the probe's own
    /// pid reports whether seatbelt denies by default; nonzero or a
    /// negative result means the sandbox is in force.
    pub fn sandbox_check(
        pid: libc::pid_t,
        operation: *const std::ffi::c_char,
        type_: libc::c_int,
        ...
    ) -> libc::c_int;
}

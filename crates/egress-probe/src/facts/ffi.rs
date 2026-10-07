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

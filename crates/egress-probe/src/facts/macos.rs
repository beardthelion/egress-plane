//! The macOS live adapters (KTD8, KTD17, KTD25, KTD26).
//!
//! Facts arrive through sysctl, libproc, and the C runtime: the
//! `_NSGetEnviron` name list (names only), the `proc_pidinfo`
//! descriptor inventory (taken first, per the universe table),
//! `getfsstat` mounts, the `pcblist_n` socket and listener tables,
//! `NET_RT_DUMP` routes, `getifaddrs` interfaces, `sandbox_check`,
//! `kern.hv_vmm_present`, the numeric identity, and the `P_TRACED`
//! flag. Nothing here reads secret contents, other processes, or
//! network state. Every record parser treats a layout it cannot walk
//! with confidence as `unsupported-layout`, never a short result
//! (KTD17); the byte layouts are decoded in `universe::macos` so the
//! same code is testable off-platform.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;

use super::{
    EnvName, Fact, Facts, FdEntry, IdentityFact, InterfaceFact, ListenerFact, MountFact, Platform,
    ProcessFact, RouteFact, UnixSocketFact,
};
use crate::facts::ffi;
use crate::universe::macos as records;

/// The macOS startup facts. The descriptor inventory is taken first
/// (the universe table's "taken first" note); the traced flag is the
/// KTD25 start read, read again at finalize by the engine.
pub fn collect() -> Facts {
    let fds = fd_inventory();
    Facts {
        platform: Some(Platform::Macos),
        process: Fact::Read(ProcessFact {
            pid: unsafe { libc::getpid() } as u64,
        }),
        env_names: env_names(),
        fds,
        mounts: Some(mounts()),
        unix_sockets: Some(unix_sockets()),
        listeners: Some(listeners()),
        routes: Some(routes()),
        interfaces: Some(interfaces()),
        sandbox_check: Some(sandbox()),
        hv_vmm_present: Some(hv_vmm()),
        identity: Some(identity()),
        traced: Some(traced()),
        ..Default::default()
    }
}

/// Environment names from the `_NSGetEnviron` vector (R17): only the
/// bytes before the first `=` are kept; entries without a separator
/// are `NoSeparator` and their bytes are dropped.
pub fn env_names() -> Fact<Vec<EnvName>> {
    let mut out = Vec::new();
    // SAFETY: `_NSGetEnviron` returns the address of the stable
    // process-lifetime environ vector; we only read pointers and copy
    // the name bytes.
    unsafe {
        let pp = libc::_NSGetEnviron();
        if pp.is_null() {
            return Fact::Read(out);
        }
        let p = *pp;
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

/// The inherited-descriptor inventory: `PROC_PIDLISTFDS` on the probe's
/// own pid, then a `vnode_fdinfowithpath` record per vnode descriptor.
/// The list itself has no probe-owned entry.
fn fd_inventory() -> Fact<Vec<FdEntry>> {
    let pid = unsafe { libc::getpid() };
    // Two-pass read: the first call returns the needed size.
    let need = unsafe { libc::proc_pidinfo(pid, ffi::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Fact::Unreadable;
    }
    let mut buf = vec![0u8; need as usize];
    // SAFETY: `buf` is `need` bytes and `proc_pidinfo` writes at most
    // `buffersize` bytes into it.
    let got =
        unsafe { libc::proc_pidinfo(pid, ffi::PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast(), need) };
    if got <= 0 {
        return Fact::Unreadable;
    }
    buf.truncate(got as usize);
    let list = match records::proc_fd_list(&buf) {
        Ok(l) => l,
        Err(_) => return Fact::UnsupportedLayout,
    };
    let mut out = Vec::new();
    for (fd, fdtype) in list {
        if fd < 0 {
            continue;
        }
        out.push(FdEntry {
            fd: fd as u64,
            target: fd_target(pid, fd, fdtype),
            probe_own: false,
        });
    }
    out.sort_by_key(|e| e.fd);
    Fact::Read(out)
}

/// The display target for one descriptor: the vnode path for a vnode,
/// a type label for the rest.
fn fd_target(pid: libc::c_int, fd: libc::c_int, fdtype: u32) -> String {
    match fdtype {
        ffi::PROX_FDTYPE_VNODE => {
            let mut buf = vec![0u8; records::VNODE_FDINFO_PATH_LEN];
            // SAFETY: `buf` is the full record size the flavor writes.
            let n = unsafe {
                libc::proc_pidfdinfo(
                    pid,
                    fd,
                    ffi::PROC_PIDFDVNODEPATHINFO,
                    buf.as_mut_ptr().cast(),
                    buf.len() as libc::c_int,
                )
            };
            if n <= 0 {
                return "<unreadable>".to_string();
            }
            match records::vnode_path_info(&buf[..(n as usize).min(buf.len())]) {
                Ok((_, path)) if !path.is_empty() => String::from_utf8_lossy(&path).into_owned(),
                _ => "<no-path>".to_string(),
            }
        }
        ffi::PROX_FDTYPE_SOCKET => "socket".to_string(),
        ffi::PROX_FDTYPE_PIPE => "pipe".to_string(),
        ffi::PROX_FDTYPE_KQUEUE => "KQUEUE".to_string(),
        ffi::PROX_FDTYPE_PSHM => "PSHM".to_string(),
        ffi::PROX_FDTYPE_PSEM => "PSEM".to_string(),
        ffi::PROX_FDTYPE_FSEVENTS => "FSEVENTS".to_string(),
        ffi::PROX_FDTYPE_NETPOLICY => "NETPOLICY".to_string(),
        ffi::PROX_FDTYPE_CHANNEL => "CHANNEL".to_string(),
        ffi::PROX_FDTYPE_NEXUS => "NEXUS".to_string(),
        n => format!("fdtype-{n}"),
    }
}

/// `getfsstat` with `MNT_NOWAIT` (never blocks on a network
/// filesystem's server, KTD26).
fn mounts() -> Fact<Vec<MountFact>> {
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, ffi::MNT_NOWAIT) };
    if count < 0 {
        return Fact::Unreadable;
    }
    if count == 0 {
        return Fact::Read(Vec::new());
    }
    let size = std::mem::size_of::<libc::statfs>();
    let mut buf = vec![unsafe { std::mem::zeroed::<libc::statfs>() }; count as usize];
    // SAFETY: `buf` holds `count` statfs slots and `getfsstat` writes
    // at most `count * size` bytes into it.
    let got = unsafe {
        libc::getfsstat(
            buf.as_mut_ptr(),
            (count as usize * size) as libc::c_int,
            ffi::MNT_NOWAIT,
        )
    };
    if got < 0 {
        return Fact::Unreadable;
    }
    let mut out = Vec::new();
    for st in &buf[..got as usize] {
        // SAFETY: getfsstat filled `st`; its name fields are fixed
        // NUL-terminated arrays inside the struct.
        let path = unsafe { CStr::from_ptr(st.f_mntonname.as_ptr()) }
            .to_bytes()
            .to_vec();
        let fstype = unsafe { CStr::from_ptr(st.f_fstypename.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let source = unsafe { CStr::from_ptr(st.f_mntfromname.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        out.push(MountFact {
            path,
            fstype,
            source: Some(source),
            readonly: Some(st.f_flags & ffi::MNT_RDONLY != 0),
        });
    }
    Fact::Read(out)
}

/// A `sysctlbyname` two-pass read into a byte buffer.
fn sysctl_bytes(name: &'static CStr) -> Option<Vec<u8>> {
    let mut len: usize = 0;
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// A `sysctl` two-pass read into a byte buffer.
fn sysctl_mib(mib: &[libc::c_int]) -> Option<Vec<u8>> {
    let mut len: usize = 0;
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr().cast_mut(),
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr().cast_mut(),
            mib.len() as u32,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// `net.local.stream.pcblist_n` plus `net.local.dgram.pcblist_n`
/// (KTD17): one fact, atomic on layout failure.
fn unix_sockets() -> Fact<Vec<UnixSocketFact>> {
    let mut out = Vec::new();
    for name in [c"net.local.stream.pcblist_n", c"net.local.dgram.pcblist_n"] {
        let Some(buf) = sysctl_bytes(name) else {
            return Fact::Unreadable;
        };
        match records::pcblist_unix(&buf) {
            Ok(v) => out.extend(v),
            Err(_) => return Fact::UnsupportedLayout,
        }
    }
    Fact::Read(out)
}

/// `net.inet.tcp.pcblist_n` plus `net.inet.udp.pcblist_n`, both
/// address families within each table (`inp_vflag` selects the member
/// family).
fn listeners() -> Fact<Vec<ListenerFact>> {
    let mut out = Vec::new();
    for (name, proto) in [
        (c"net.inet.tcp.pcblist_n", "tcp"),
        (c"net.inet.udp.pcblist_n", "udp"),
    ] {
        let Some(buf) = sysctl_bytes(name) else {
            return Fact::Unreadable;
        };
        match records::pcblist_inet(&buf, proto) {
            Ok(v) => out.extend(v),
            Err(_) => return Fact::UnsupportedLayout,
        }
    }
    Fact::Read(out)
}

/// `sysctl { CTL_NET, PF_ROUTE, 0, af, NET_RT_DUMP, 0 }` for both
/// address families.
fn routes() -> Fact<Vec<RouteFact>> {
    let mut out = Vec::new();
    for af in [libc::AF_INET, libc::AF_INET6] {
        let mib = [libc::CTL_NET, libc::PF_ROUTE, 0, af, ffi::NET_RT_DUMP, 0];
        let Some(buf) = sysctl_mib(&mib) else {
            return Fact::Unreadable;
        };
        match records::rt_dump(&buf) {
            Ok(v) => out.extend(v),
            Err(_) => return Fact::UnsupportedLayout,
        }
    }
    Fact::Read(out)
}

/// `getifaddrs` interface names, deduplicated, with the address
/// families each carries.
fn interfaces() -> Fact<Vec<InterfaceFact>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out pointer; on success the returned
    // list is freed with `freeifaddrs` below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Fact::Unreadable;
    }
    let mut names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut cur = head;
    // SAFETY: `head` is a live `ifaddrs` chain owned by us until the
    // `freeifaddrs` call after the loop.
    unsafe {
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() {
                continue;
            }
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let family = match (*ifa.ifa_addr).sa_family as i32 {
                libc::AF_INET => "inet".to_string(),
                libc::AF_INET6 => "inet6".to_string(),
                libc::AF_LINK => "link".to_string(),
                n => format!("af-{n}"),
            };
            names.entry(name).or_default().insert(family);
        }
        libc::freeifaddrs(head);
    }
    Fact::Read(
        names
            .into_iter()
            .map(|(name, families)| InterfaceFact {
                name,
                families: families.into_iter().collect(),
            })
            .collect(),
    )
}

/// `sandbox_check(getpid(), NULL, 0)`: the seatbelt verdict on a NULL
/// operation (universe table).
fn sandbox() -> Fact<i64> {
    // SAFETY: a NULL operation is a pure query on the probe's own pid.
    let rc = unsafe { ffi::sandbox_check(libc::getpid(), std::ptr::null(), 0) };
    Fact::Read(rc as i64)
}

/// `kern.hv_vmm_present`: a present hypervisor framework reports the
/// VM layer.
fn hv_vmm() -> Fact<bool> {
    let Some(buf) = sysctl_bytes(c"kern.hv_vmm_present") else {
        return Fact::Unreadable;
    };
    if buf.len() < 4 {
        return Fact::UnsupportedLayout;
    }
    Fact::Read(i32::from_le_bytes(buf[..4].try_into().unwrap()) != 0)
}

/// Numeric `geteuid`/`getegid`; no name lookup (KTD15).
fn identity() -> Fact<IdentityFact> {
    Fact::Read(IdentityFact {
        euid: unsafe { libc::geteuid() } as u32,
        egid: unsafe { libc::getegid() } as u32,
    })
}

/// The `P_TRACED` flag of `extern_proc` inside the `kern.proc.pid`
/// `kinfo_proc` record on the probe's own pid (KTD25, start read).
fn traced() -> Fact<bool> {
    let pid = unsafe { libc::getpid() };
    let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let Some(buf) = sysctl_mib(&mib) else {
        return Fact::Unreadable;
    };
    let off = ffi::KINFO_PROC_P_FLAG_OFFSET;
    if buf.len() < off + 4 {
        return Fact::UnsupportedLayout;
    }
    let flags = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
    Fact::Read(flags & ffi::P_TRACED != 0)
}

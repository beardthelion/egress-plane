//! Kernel-filesystem and `proc/self` verification (KTD24).
//!
//! Every handle the reader opens under `proc/` must sit on a real procfs
//! and every handle under `sys/` on a real sysfs, which catches a tmpfs or
//! FUSE filesystem mounted over them and a regular file or `/dev/null`
//! bind-mounted over a single proc file. The `proc/self` hop must name the
//! probe's own pid directory, with one accepted exception for an ancestor
//! pid namespace verified through the `NSpid` chain. Both checks are cheap
//! forgery detection, not authentication (KTD23).

/// The `NSpid` pid list from a `proc/<pid>/status` body, or `None` when the
/// line is absent or unparseable.
pub fn nspid_line(status: &[u8]) -> Option<Vec<u64>> {
    let text = std::str::from_utf8(status).ok()?;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("NSpid:") else {
            continue;
        };
        let pids: Option<Vec<u64>> = rest
            .split_whitespace()
            .map(|f| f.parse::<u64>().ok())
            .collect();
        return pids;
    }
    None
}

/// The ancestor pid namespace acceptance of KTD24: the status file of the
/// pid `proc/self` names (`target`) must carry an `NSpid` line whose first
/// field is `target` (the outer namespace pid) and whose last field is the
/// probe's own `pid`. Anything else is a `proc-self-mismatch`.
pub fn nspid_accepts(status: &[u8], target: u64, pid: u64) -> bool {
    match nspid_line(status) {
        Some(chain) => chain.first() == Some(&target) && chain.last() == Some(&pid),
        None => false,
    }
}

/// The filesystem name a resolved path's handles must all report, from the
/// path's top-level component: `proc` under `proc/`, `sysfs` under `sys/`,
/// nothing elsewhere.
pub fn expected_fs(top_component: &[u8]) -> Option<&'static str> {
    match top_component {
        b"proc" => Some("proc"),
        b"sys" => Some("sysfs"),
        _ => None,
    }
}

/// The `TracerPid` value of a `proc/<pid>/status` body, or `None` when the
/// line is absent or unparseable.
pub fn tracer_pid(status: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(status).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

/// True when every opened handle reported the expected filesystem. An empty
/// list (a call that opened no handle, such as `lstat` on a top component)
/// passes vacuously.
pub fn fs_matches(fs_types: &[String], expected: &str) -> bool {
    fs_types.iter().all(|f| f == expected)
}

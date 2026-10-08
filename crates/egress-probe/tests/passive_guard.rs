//! The KTD7 passive-mode guard: no source file outside `src/active.rs`
//! may create sockets, connect, or call a name service, and passive
//! mode never invokes the active module.

use std::path::{Path, PathBuf};

/// Socket entry points `egress-probe` sources may never name outside
/// `src/active.rs`.
const SOCKET_NAMES: &[&str] = &[
    "TcpStream",
    "UdpSocket",
    "UnixStream",
    "UnixDatagram",
    "TcpListener",
    "UnixListener",
    "libc::socket",
    "libc::connect",
    "libc::socketpair",
    "if_nametoindex",
];

/// Directory-service and resolver names neither crate may name (KTD7,
/// KTD15, R17).
const NAME_SERVICE_NAMES: &[&str] = &[
    "getpwuid",
    "getpwnam",
    "getgrgid",
    "getgrnam",
    "getaddrinfo",
    "getnameinfo",
    "gethostbyname",
    "ToSocketAddrs",
    "lookup_host",
    "home_dir",
    "localtime",
    "chrono",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn passive_sources_name_no_socket_or_name_service() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&manifest.join("src"), &mut files);
    rust_files(&manifest.join("../egress-core/src"), &mut files);
    let mut violations = Vec::new();
    for f in &files {
        if f.ends_with("src/active.rs") {
            continue;
        }
        let in_probe = f.starts_with(manifest.join("src").as_path());
        let text = std::fs::read_to_string(f).unwrap();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            for name in NAME_SERVICE_NAMES {
                if trimmed.contains(name) {
                    violations.push(format!("{}: {trimmed}", f.display()));
                }
            }
            if in_probe {
                for name in SOCKET_NAMES {
                    if trimmed.contains(name) {
                        violations.push(format!("{}: {trimmed}", f.display()));
                    }
                }
                // libc::syscall is allowed only in facts/ffi.rs and only
                // when the line names SYS_landlock_create_ruleset.
                if trimmed.contains("libc::syscall") {
                    let allowed = f.ends_with("src/facts/ffi.rs")
                        && trimmed.contains("SYS_landlock_create_ruleset");
                    if !allowed {
                        violations.push(format!("{}: {trimmed}", f.display()));
                    }
                }
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn passive_mode_never_runs_an_active_check() {
    // A passive run produces an empty active_checks section; the
    // connector surface lives only in src/active.rs, which the guard
    // above keeps empty until the active-mode unit lands.
    let r = crate::common::report(vec![]);
    assert!(r.active_checks.is_empty());
}

mod common;

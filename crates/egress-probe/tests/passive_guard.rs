//! The KTD7 passive-mode guard: no source file outside `src/active.rs`
//! may create sockets, connect, or call a name service, and passive
//! mode never invokes the active module.

use std::path::{Path, PathBuf};

use egress_probe::facts::Facts;
use egress_probe::reader::{AccessMask, AccessResult, Denial, Meta, Mount, ReadLogEntry, Reader};

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

/// A connector that counts its calls; passive mode must never reach it.
struct Counting(usize);

impl egress_probe::active::Connector for Counting {
    fn connect(
        &mut self,
        _addr: &std::net::SocketAddr,
        _timeout: std::time::Duration,
    ) -> egress_probe::active::ConnectOutcome {
        self.0 += 1;
        egress_probe::active::ConnectOutcome::Connected
    }
}

/// A reader that denies every call, enough to drive a pipeline pass.
struct DenyReader(egress_probe::facts::Facts);

impl Reader for DenyReader {
    fn read(&mut self, _path: &[u8], _limit: u64) -> Result<Vec<u8>, Denial> {
        Err(Denial::Absent)
    }
    fn list(&mut self, _path: &[u8]) -> Result<Vec<(Vec<u8>, Meta)>, Denial> {
        Err(Denial::Absent)
    }
    fn metadata(&mut self, _path: &[u8]) -> Result<Meta, Denial> {
        Err(Denial::Absent)
    }
    fn access(&mut self, _path: &[u8], _mask: AccessMask) -> Result<AccessResult, Denial> {
        Err(Denial::Absent)
    }
    fn readlink(&mut self, _path: &[u8]) -> Result<Vec<u8>, Denial> {
        Err(Denial::Absent)
    }
    fn signal_metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        self.metadata(path)
    }
    fn signal_access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial> {
        self.access(path, mask)
    }
    fn facts(&self) -> &Facts {
        &self.0
    }
    fn read_log(&self) -> &[ReadLogEntry] {
        &[]
    }
    fn arm_mounts(&mut self, _mounts: Vec<Mount>) {}
    fn mounts_unknown(&mut self) {}
    fn accepted_ancestor_pidns(&self) -> bool {
        false
    }
}

#[test]
fn passive_mode_never_runs_an_active_check() {
    // The counting fake proves the active module is never invoked on a
    // passive run: a full pipeline pass over it produces an empty
    // active_checks section and zero connector calls (KTD7).
    let data = egress_probe::data::Data::embedded().unwrap();
    let mut reader = DenyReader(egress_probe::facts::Facts::default());
    let request = egress_probe::live::Request {
        mode: egress_probe::model::Mode::Passive,
        nonce: None,
        targets: Vec::new(),
        output: egress_probe::live::Output::Json,
    };
    let mut counting = Counting(0);
    let rendered = egress_probe::live::run_with(
        &mut reader,
        &data,
        egress_probe::model::Source::Snapshot,
        &request,
        &mut counting,
    );
    assert_eq!(counting.0, 0, "a passive run reached the connector");
    let json: serde_json::Value = serde_json::from_str(&rendered.output).unwrap();
    assert_eq!(json["active_checks"], serde_json::json!([]));
}

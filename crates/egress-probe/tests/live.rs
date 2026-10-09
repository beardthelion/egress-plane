//! Live smoke matrix (U9): each test is `#[ignore]` and runs only when
//! its environment exists; a missing precondition is a fixed failure,
//! never a silent skip. Linux rows run the static musl binary named by
//! `EGRESS_PROBE_STATIC_BIN`.

use std::path::PathBuf;
use std::process::Command;

/// The static binary under test; every Linux row fails with this fixed
/// message when the build has not run.
fn static_bin() -> PathBuf {
    let p = std::env::var("EGRESS_PROBE_STATIC_BIN")
        .expect("set EGRESS_PROBE_STATIC_BIN to the musl release binary");
    let p = PathBuf::from(p);
    assert!(p.is_file(), "EGRESS_PROBE_STATIC_BIN is not a file");
    p
}

fn run(bin: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin).args(args).output().expect("binary runs");
    let code = out.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json(bin: &PathBuf) -> serde_json::Value {
    let (code, stdout, _stderr) = run(bin, &["probe", "--format", "json"]);
    assert!(
        [0, 2, 3].contains(&code),
        "probe exited {code}; stdout: {stdout}"
    );
    serde_json::from_str(&stdout).expect("probe json parses")
}

/// The universes that must never be unknown on a live run (the drift
/// gate, U9).
const DRIFT_UNIVERSES: &[&str] = &[
    "linux.mounts",
    "linux.unix-sockets",
    "linux.socket-files",
    "linux.listeners",
    "linux.fds",
    "linux.env-names",
    "linux.capabilities",
    "linux.routes",
    "linux.interfaces",
    "linux.devices",
];

/// The unknowns a live run may carry: everything else is drift between
/// the snapshot corpus and the real host and fails the row.
/// Sources allowed to be unknown when a no-touch mount is on the host
/// (a fuse or network mount we may never stat) or the loader line is
/// unreadable; everything else is drift.
const NAMED_UNKNOWN_PREFIXES: &[&str] = &["linux.loader.", "cred.", "proxy.config-files"];

const NAMED_UNKNOWN_REASONS: &[(&str, &str)] = &[
    ("linux.socket-files", "network-filesystem-not-touched"),
    ("linux.devices", "network-filesystem-not-touched"),
];

fn drift_gate(report: &serde_json::Value) {
    // Unknown reasons by source, for the universe-state check below.
    let unknown_reason = |id: &str| {
        report["unknowns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["source"].as_str() == Some(id))
            .and_then(|u| u["reason"].as_str().map(str::to_string))
    };
    for u in report["universes"].as_array().unwrap() {
        let Some(id) = u["id"].as_str() else { continue };
        if !DRIFT_UNIVERSES.contains(&id) || u["state"] != "unknown" {
            continue;
        }
        // A named no-touch unknown is expected on hosts with network or
        // fuse mounts (KTD26/KTD30); anything else is drift.
        let named = NAMED_UNKNOWN_REASONS
            .iter()
            .any(|(s, re)| *s == id && Some(*re) == unknown_reason(id).as_deref());
        assert!(named, "drift gate: {id} unknown on a live run");
    }
    for u in report["unknowns"].as_array().unwrap() {
        let src = u["source"].as_str().unwrap();
        let reason = u["reason"].as_str().unwrap();
        let allowed = reason == "no-account-home"
            || NAMED_UNKNOWN_PREFIXES.iter().any(|p| src.starts_with(p))
            || NAMED_UNKNOWN_REASONS
                .iter()
                .any(|(s, re)| *s == src && *re == reason);
        assert!(allowed, "unlisted live unknown {src} {}", u["reason"]);
    }
}

#[test]
#[ignore]
fn live_static_binary_has_no_interpreter() {
    // Red proof: run once against the dynamic build — it carries
    // PT_INTERP and this assertion fails.
    let bin = static_bin();
    let elf = std::fs::read(&bin).unwrap();
    // ELF program headers: count PT_INTERP (type 1) entries.
    let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(elf[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;
    for i in 0..phnum {
        let p_type = u32::from_le_bytes(
            elf[phoff + i * phentsize..phoff + i * phentsize + 4]
                .try_into()
                .unwrap(),
        );
        assert_ne!(p_type, 3, "PT_INTERP present: the binary is not static");
    }
}

#[test]
#[ignore]
fn live_static_ignores_ld_preload() {
    // Red proof: the dynamic build prints the loader's "cannot be
    // preloaded" message on stderr.
    let bin = static_bin();
    let out = Command::new(bin)
        .args(["probe", "--format", "json"])
        .env("LD_PRELOAD", "/nonexistent/egress-sentinel-preload.so")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("cannot be preloaded"),
        "static binary honoured LD_PRELOAD: {stderr}"
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["tamper_indicators"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["indicator"] == "loader-env" && t["strength"] == "weak")
    );
}

#[test]
#[ignore]
fn live_traced_probe() {
    assert!(
        Command::new("strace").arg("--version").output().is_ok(),
        "strace not installed"
    );
    let bin = static_bin();
    let tmp = std::env::temp_dir().join("egress-probe-trace.txt");
    let out = Command::new("strace")
        .args(["-f", "-o"])
        .arg(&tmp)
        .arg(&bin)
        .args(["probe", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "traced probe must exit 2");
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["tamper_indicators"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["indicator"] == "traced" && t["strength"] == "strong")
    );

    // The passive trace holds no network call (KTD7). Red proof: the
    // same assertion against `probe --active --allow 127.0.0.1:1`
    // finds `socket` and `connect`.
    let tmp2 = std::env::temp_dir().join("egress-probe-nettrace.txt");
    Command::new("strace")
        .args(["-f", "-e", "trace=%network", "-o"])
        .arg(&tmp2)
        .arg(&bin)
        .args(["probe"])
        .output()
        .unwrap();
    let trace = std::fs::read_to_string(&tmp2).unwrap();
    for call in ["socket(", "connect(", "sendto(", "sendmsg("] {
        assert!(!trace.contains(call), "passive run made a {call} call");
    }
}

#[test]
#[ignore]
fn live_linux_host() {
    let report = json(&static_bin());
    drift_gate(&report);
}

#[test]
#[ignore]
fn live_docker_runtime_socket() {
    Command::new("docker")
        .args(["info"])
        .output()
        .expect("docker usable");
    let bin = static_bin();
    let host_bin = bin.canonicalize().unwrap();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{}:/egress-plane:ro", host_bin.display()),
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "ubuntu:24.04",
            "/egress-plane",
            "probe",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("container output: {}", String::from_utf8_lossy(&out.stdout)));
    assert!(
        report["layers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["kind"] == "docker")
    );
    assert!(
        report["escape_routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "runtime-socket")
    );
    drift_gate(&report);
}

#[test]
#[ignore]
fn live_docker_odd_path_socket() {
    Command::new("docker")
        .args(["info"])
        .output()
        .expect("docker usable");
    let bin = static_bin();
    let host_bin = bin.canonicalize().unwrap();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{}:/egress-plane:ro", host_bin.display()),
            "-v",
            "/var/run/docker.sock:/opt/odd/ctl.sock",
            "ubuntu:24.04",
            "/egress-plane",
            "probe",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("/opt/odd/ctl.sock"),
        "odd-path socket absent: {stdout}"
    );
}

#[test]
#[ignore]
fn live_bubblewrap_sandbox() {
    assert!(
        Command::new("bwrap").arg("--version").output().is_ok(),
        "bwrap not installed"
    );
    let probe = Command::new("bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "/bin/true"])
        .output()
        .unwrap();
    assert!(
        probe.status.success(),
        "bwrap cannot unshare user namespaces on this host: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let bin = static_bin();
    let out = Command::new("bwrap")
        .args([
            "--unshare-all",
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            "/tmp",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
        ])
        .arg(&bin)
        .args(["probe", "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stdout)));
    assert!(
        report["layers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["kind"] == "bubblewrap")
    );
}

#[test]
#[ignore]
fn live_github_actions_job() {
    assert!(
        std::env::var("GITHUB_ACTIONS").is_ok(),
        "not running under GitHub Actions"
    );
    let report = json(&static_bin());
    assert!(
        report["layers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["kind"] == "github-actions")
    );
}

#[test]
#[ignore]
fn live_macos_host() {
    assert_eq!(std::env::consts::OS, "macos", "not running on macOS");
    let bin = std::env::var("EGRESS_PROBE_BIN")
        .map(PathBuf::from)
        .expect("set EGRESS_PROBE_BIN to the macOS build");
    let report = json(&bin);
    for u in report["universes"].as_array().unwrap() {
        if u["id"].as_str().unwrap().starts_with("linux.") {
            assert_eq!(u["state"], "not-applicable");
        }
    }
    for u in report["unknowns"].as_array().unwrap() {
        let reason = u["reason"].as_str().unwrap();
        assert!(
            reason == "no-account-home" || reason == "unsupported-layout",
            "unlisted macOS unknown: {} {}",
            u["source"],
            reason
        );
    }
}

#[test]
#[ignore]
fn live_macos_seatbelt() {
    assert_eq!(std::env::consts::OS, "macos", "not running on macOS");
    let bin = std::env::var("EGRESS_PROBE_BIN")
        .map(PathBuf::from)
        .expect("set EGRESS_PROBE_BIN to the macOS build");
    let out = Command::new("sandbox-exec")
        .args(["-p", "(version 1)(allow default)(deny network*)"])
        .arg(&bin)
        .args(["probe", "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        report["layers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["kind"] == "seatbelt")
    );
}

/// The live-matrix workflow is hardened (not ignored): read-once
/// permissions, no `pull_request_target`, no secrets to steps, and every
/// `uses:` line pinned to a full commit SHA.
#[test]
fn workflow_is_hardened() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/probe-live.yml");
    let text = std::fs::read_to_string(&path).expect("probe-live.yml exists");
    assert!(text.contains("permissions:\n  contents: read"));
    assert!(!text.contains("pull_request_target"));
    assert!(!text.contains("secrets."));
    for line in text.lines().filter(|l| l.trim_start().starts_with("uses:")) {
        let target = line.split("uses:").nth(1).unwrap().trim();
        let sha = target.rsplit('@').next().unwrap();
        let comment = sha.find(' ').map(|i| &sha[..i]).unwrap_or(sha);
        assert!(
            comment.len() == 40 && comment.chars().all(|c| c.is_ascii_hexdigit()),
            "uses line not pinned to a commit SHA: {line}"
        );
    }
}

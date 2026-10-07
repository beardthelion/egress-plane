//! Normalized syscall-backed facts (KTD4).
//!
//! Facts are the probe inputs a filesystem tree cannot carry: the process
//! id, the inherited descriptor inventory, environment variable names, the
//! Landlock ABI query, and on macOS the mount, socket, listener, route,
//! interface, and identity tables. Live adapters (added with the
//! enumerators) produce them from the OS; the snapshot reader parses the
//! same normalized set from a case's `facts.toml`.
//!
//! A fact is never partially read: an adapter reports `read` with its data
//! or a fixed state, and consumers treat every non-`read` state uniformly.

use serde::Deserialize;

/// The host platform the probe is running against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Macos,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
        }
    }
}

/// The state one adapter fact ended in.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Fact<T> {
    /// The adapter produced data.
    Read(T),
    /// The adapter could not produce the fact.
    #[default]
    Unreadable,
    /// The kernel has no support built in (Landlock `ENOSYS`).
    NotBuilt,
    /// Support exists but is disabled (Landlock `EOPNOTSUPP`).
    Disabled,
    /// The record layout cannot be parsed with confidence (KTD17).
    UnsupportedLayout,
    /// A kernel filesystem check failed (KTD8).
    FsTypeMismatch,
    /// The process filesystem describes another process (KTD8).
    ProcSelfMismatch,
}

impl<T> Fact<T> {
    /// The data when the fact was read.
    pub fn read(&self) -> Option<&T> {
        match self {
            Self::Read(v) => Some(v),
            _ => None,
        }
    }
}

/// The probe's own process id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFact {
    pub pid: u64,
}

/// One environment variable name (bytes before the first `=`), or an entry
/// with no separator whose bytes are never emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvName {
    Name(Vec<u8>),
    NoSeparator,
}

/// One descriptor in the startup inventory (KTD8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdEntry {
    /// The descriptor number; display-only.
    pub fd: u64,
    /// The `readlink` text (`/path`, `socket:[i]`, `pipe:[i]`, `anon_inode:[n]`).
    pub target: String,
    /// True for the adapter's own listing handle.
    pub probe_own: bool,
}

/// A macOS mount from `getfsstat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountFact {
    pub path: Vec<u8>,
    pub fstype: String,
    pub source: Option<String>,
    pub readonly: Option<bool>,
}

/// A macOS unix socket record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixSocketFact {
    pub path: Option<Vec<u8>>,
    pub kind: String,
    pub listening: bool,
}

/// A macOS listener record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerFact {
    pub protocol: String,
    pub address: String,
    pub port: u16,
}

/// A macOS routing-table record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFact {
    pub family: String,
    pub destination: String,
    pub gateway: Option<String>,
    pub interface: Option<String>,
}

/// A macOS interface from `getifaddrs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceFact {
    pub name: String,
    pub families: Vec<String>,
}

/// The probe's numeric identity (`euid`, `egid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFact {
    pub euid: u32,
    pub egid: u32,
}

/// The normalized fact set one run consumes. macOS-only facts are absent on
/// Linux and vice versa.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub platform: Option<Platform>,
    pub process: Fact<ProcessFact>,
    pub env_names: Fact<Vec<EnvName>>,
    pub fds: Fact<Vec<FdEntry>>,
    /// Linux: the Landlock ABI version query.
    pub landlock_abi: Option<Fact<u32>>,
    /// macOS: `getfsstat` mounts.
    pub mounts: Option<Fact<Vec<MountFact>>>,
    /// macOS: `pcblist_n` unix sockets.
    pub unix_sockets: Option<Fact<Vec<UnixSocketFact>>>,
    /// macOS: `pcblist_n` listeners.
    pub listeners: Option<Fact<Vec<ListenerFact>>>,
    /// macOS: `NET_RT_DUMP` routes.
    pub routes: Option<Fact<Vec<RouteFact>>>,
    /// macOS: `getifaddrs` interfaces.
    pub interfaces: Option<Fact<Vec<InterfaceFact>>>,
    /// macOS: `sandbox_check` result.
    pub sandbox_check: Option<Fact<i64>>,
    /// macOS: `kern.hv_vmm_present`.
    pub hv_vmm_present: Option<Fact<bool>>,
    /// macOS: numeric euid and egid.
    pub identity: Option<Fact<IdentityFact>>,
    /// macOS: the `P_TRACED` flag.
    pub traced: Option<Fact<bool>>,
}

impl Facts {
    /// The probe's own pid, when the process fact was read.
    pub fn pid(&self) -> Option<u64> {
        self.process.read().map(|p| p.pid)
    }
}

// ---------------------------------------------------------------------------
// facts.toml parsing (snapshot replay; the corpus harness validates the file
// on its own before this parser sees a real case).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFacts {
    platform: String,
    process: Option<RawProcess>,
    env_names: Option<RawEnvNames>,
    fds: Option<RawFds>,
    landlock_abi: Option<RawLandlockAbi>,
    mounts: Option<RawMounts>,
    unix_sockets: Option<RawUnixSockets>,
    listeners: Option<RawListeners>,
    routes: Option<RawRoutes>,
    interfaces: Option<RawInterfaces>,
    sandbox_check: Option<RawSandboxCheck>,
    hv_vmm_present: Option<RawHvVmm>,
    identity: Option<RawIdentity>,
    traced: Option<RawTraced>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProcess {
    state: String,
    pid: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvNames {
    state: String,
    names: Option<Vec<RawEnvName>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvName {
    name: Option<String>,
    no_separator: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFds {
    state: String,
    entries: Option<Vec<RawFd>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFd {
    fd: u64,
    target: String,
    probe_own: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLandlockAbi {
    state: String,
    version: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMounts {
    state: String,
    entries: Option<Vec<RawMount>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMount {
    path: String,
    fstype: String,
    source: Option<String>,
    readonly: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnixSockets {
    state: String,
    entries: Option<Vec<RawUnixSocket>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnixSocket {
    path: Option<String>,
    kind: String,
    listening: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListeners {
    state: String,
    entries: Option<Vec<RawListener>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    protocol: String,
    address: String,
    port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoutes {
    state: String,
    entries: Option<Vec<RawRouteEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouteEntry {
    family: String,
    destination: String,
    gateway: Option<String>,
    interface: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterfaces {
    state: String,
    entries: Option<Vec<RawInterface>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterface {
    name: String,
    families: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSandboxCheck {
    state: String,
    result: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHvVmm {
    state: String,
    present: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    state: String,
    euid: Option<u32>,
    egid: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTraced {
    state: String,
    traced: Option<bool>,
}

/// Turns a `state` string plus a `read`-state projection into a [`Fact`].
fn fact<T>(state: &str, data: impl FnOnce() -> Option<T>) -> Result<Fact<T>, String> {
    match state {
        "read" => data()
            .map(Fact::Read)
            .ok_or_else(|| "state \"read\" without data".to_string()),
        "unreadable" => Ok(Fact::Unreadable),
        "not-built" => Ok(Fact::NotBuilt),
        "disabled" => Ok(Fact::Disabled),
        "unsupported-layout" => Ok(Fact::UnsupportedLayout),
        "fs-type-mismatch" => Ok(Fact::FsTypeMismatch),
        "proc-self-mismatch" => Ok(Fact::ProcSelfMismatch),
        other => Err(format!("unknown fact state {other:?}")),
    }
}

fn need<T>(what: &str, v: Option<T>) -> Result<T, String> {
    v.ok_or_else(|| format!("state \"read\" without `{what}`"))
}

/// Parses `facts.toml` text into the normalized fact set. `platform` and a
/// readable `process` fact with `pid` are required; every other table is
/// optional and defaults to unreadable when missing.
pub fn parse_facts(text: &str) -> Result<Facts, String> {
    let raw: RawFacts = toml::from_str(text).map_err(|e| format!("malformed facts.toml: {e}"))?;
    let platform = match raw.platform.as_str() {
        "linux" => Platform::Linux,
        "macos" => Platform::Macos,
        other => return Err(format!("malformed facts.toml: unknown platform {other:?}")),
    };

    let process = match raw.process {
        Some(p) => fact(&p.state, || {
            Some(ProcessFact {
                pid: need("pid", p.pid).ok()?,
            })
        })
        .map_err(|e| format!("malformed facts.toml: process: {e}"))?,
        None => return Err("malformed facts.toml: missing fact table `process`".into()),
    };

    let env_names = match raw.env_names {
        Some(t) => fact(&t.state, || {
            t.names.map(|names| {
                names
                    .into_iter()
                    .map(|n| match (n.name, n.no_separator) {
                        (Some(name), _) => EnvName::Name(name.into_bytes()),
                        _ => EnvName::NoSeparator,
                    })
                    .collect()
            })
        })
        .map_err(|e| format!("malformed facts.toml: env_names: {e}"))?,
        None => Fact::Unreadable,
    };

    let fds = match raw.fds {
        Some(t) => fact(&t.state, || {
            t.entries.map(|entries| {
                entries
                    .into_iter()
                    .map(|e| FdEntry {
                        fd: e.fd,
                        target: e.target,
                        probe_own: e.probe_own.unwrap_or(false),
                    })
                    .collect()
            })
        })
        .map_err(|e| format!("malformed facts.toml: fds: {e}"))?,
        None => Fact::Unreadable,
    };

    let landlock_abi = raw
        .landlock_abi
        .map(|t| fact(&t.state, || t.version))
        .transpose()
        .map_err(|e| format!("malformed facts.toml: landlock_abi: {e}"))?;

    let mounts = raw
        .mounts
        .map(|t| {
            fact(&t.state, || {
                t.entries.map(|entries| {
                    entries
                        .into_iter()
                        .map(|m| MountFact {
                            path: m.path.into_bytes(),
                            fstype: m.fstype,
                            source: m.source,
                            readonly: m.readonly,
                        })
                        .collect()
                })
            })
        })
        .transpose()
        .map_err(|e| format!("malformed facts.toml: mounts: {e}"))?;

    let unix_sockets = raw
        .unix_sockets
        .map(|t| {
            fact(&t.state, || {
                t.entries.map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| UnixSocketFact {
                            path: e.path.map(String::into_bytes),
                            kind: e.kind,
                            listening: e.listening.unwrap_or(false),
                        })
                        .collect()
                })
            })
        })
        .transpose()
        .map_err(|e| format!("malformed facts.toml: unix_sockets: {e}"))?;

    let listeners = raw
        .listeners
        .map(|t| {
            fact(&t.state, || {
                t.entries.map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| ListenerFact {
                            protocol: e.protocol,
                            address: e.address,
                            port: e.port,
                        })
                        .collect()
                })
            })
        })
        .transpose()
        .map_err(|e| format!("malformed facts.toml: listeners: {e}"))?;

    let routes = raw
        .routes
        .map(|t| {
            fact(&t.state, || {
                t.entries.map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| RouteFact {
                            family: e.family,
                            destination: e.destination,
                            gateway: e.gateway,
                            interface: e.interface,
                        })
                        .collect()
                })
            })
        })
        .transpose()
        .map_err(|e| format!("malformed facts.toml: routes: {e}"))?;

    let interfaces = raw
        .interfaces
        .map(|t| {
            fact(&t.state, || {
                t.entries.map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| InterfaceFact {
                            name: e.name,
                            families: e.families.unwrap_or_default(),
                        })
                        .collect()
                })
            })
        })
        .transpose()
        .map_err(|e| format!("malformed facts.toml: interfaces: {e}"))?;

    let sandbox_check = raw
        .sandbox_check
        .map(|t| fact(&t.state, || t.result))
        .transpose()
        .map_err(|e| format!("malformed facts.toml: sandbox_check: {e}"))?;

    let hv_vmm_present = raw
        .hv_vmm_present
        .map(|t| fact(&t.state, || t.present))
        .transpose()
        .map_err(|e| format!("malformed facts.toml: hv_vmm_present: {e}"))?;

    let identity = raw
        .identity
        .map(|t| {
            fact(&t.state, || {
                Some(IdentityFact {
                    euid: need("euid", t.euid).ok()?,
                    egid: need("egid", t.egid).ok()?,
                })
            })
        })
        .transpose()
        .map_err(|e| format!("malformed facts.toml: identity: {e}"))?;

    let traced = raw
        .traced
        .map(|t| fact(&t.state, || t.traced))
        .transpose()
        .map_err(|e| format!("malformed facts.toml: traced: {e}"))?;

    Ok(Facts {
        platform: Some(platform),
        process,
        env_names,
        fds,
        landlock_abi,
        mounts,
        unix_sockets,
        listeners,
        routes,
        interfaces,
        sandbox_check,
        hv_vmm_present,
        identity,
        traced,
    })
}

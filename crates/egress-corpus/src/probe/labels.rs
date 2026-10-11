//! Snapshot case files for the probe corpus.
//!
//! A case at `fixtures/probe/<platform>/<category>/<case>/` holds `tree/`
//! (files and symlinks as git stores them), `facts.toml` (the normalized
//! syscall-backed facts the platform's adapters would produce),
//! `manifest.toml` (optional overlay for nodes git cannot store: sockets,
//! FIFOs, device nodes, metadata and filesystem-type overrides, forced
//! errors), and `expected.toml` (labels). Every file denies unknown fields
//! and every error names the case, so a typo cannot turn into a label that
//! never matches.

use std::path::Path;

use egress_core::model::CompletenessState;
use serde::Deserialize;

/// Closed unknown-reason vocabulary (KTD3).
const UNKNOWN_REASONS: &[&str] = &[
    "proc-not-mounted",
    "unreadable",
    "partial",
    "implausibly-empty",
    "masked-or-truncated",
    "budget-exceeded",
    "link-policy",
    "internal-failure",
    "depends-on-unknown",
    "unsupported-layout",
    "no-account-home",
    "fs-type-mismatch",
    "proc-self-mismatch",
    "network-filesystem-not-touched",
    "descriptor-limit",
    "traced",
];

const LAYER_FAMILIES: &[&str] = &["cloud", "ci", "container", "sandbox", "host"];

/// Evidence source classes (KTD16).
const EVIDENCE_CLASSES: &[&str] = &[
    "kernel",
    "filesystem-marker",
    "environment-name",
    "firmware",
    "resolver-config",
    "network-interface",
];

const TAMPER_STRENGTHS: &[&str] = &["strong", "weak"];

/// Fact states common to every adapter fact.
const FACT_STATES: &[&str] = &["read", "unreadable", "not-built", "disabled"];

/// `errno` values a manifest `error` node may force (KTD12).
const MANIFEST_ERRNOS: &[&str] = &["EACCES", "EPERM", "ENOENT", "EMFILE"];

const NODE_KINDS: &[&str] = &["socket", "fifo", "char", "block", "meta", "error"];

const NODE_ACCESS: &[&str] = &["none", "read", "write"];

// ---------------------------------------------------------------------------
// expected.toml
// ---------------------------------------------------------------------------

/// Parsed and validated labels for one probe case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub state: CompletenessState,
    pub exit_code: i32,
    /// Exact set; `order` is the 1-based position in the emitted layer list,
    /// outermost first.
    pub layers: Vec<ExpectedLayer>,
    /// Exact multiset over both route sections.
    pub routes: Vec<ExpectedRoute>,
    /// Exact multiset.
    pub unknowns: Vec<ExpectedUnknown>,
    /// Exact multiset.
    pub tamper: Vec<ExpectedTamper>,
    /// At-least set on `(universe, member display)`.
    pub unclassified: Vec<ExpectedUnclassified>,
    /// At-least set on `(universe, rule, member display)`.
    pub inert: Vec<ExpectedInert>,
    /// At-least set on `(layer kind, attribute name, value display)`.
    pub attributes: Vec<ExpectedAttribute>,
    /// When present, the report's not-applicable list must equal this set.
    pub not_applicable: Option<Vec<String>>,
    /// Route kinds that must not appear in either route section.
    pub absent_routes: Vec<String>,
    /// Strings that must not appear in the JSON or the text output.
    pub absent_text: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedLayer {
    pub order: u32,
    pub family: String,
    pub kind: String,
    pub evidence_classes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedRoute {
    /// `escape` or `egress`.
    pub class: String,
    pub kind: String,
    /// Exactly one of `rule` / `signal` is set.
    pub rule: Option<String>,
    pub signal: Option<String>,
    /// Member display string for member-bearing routes; the route location
    /// for signal routes at a fixed path. Absent for derived-signal routes.
    pub member: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedUnknown {
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTamper {
    pub indicator: String,
    pub strength: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedUnclassified {
    pub universe: String,
    pub member: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedInert {
    pub universe: String,
    pub rule: String,
    pub member: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAttribute {
    /// Kind of the layer that must carry the attribute.
    pub layer: String,
    pub name: String,
    /// Display string form of the attribute value.
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExpected {
    state: String,
    exit_code: i32,
    #[serde(default)]
    layers: Vec<RawLayer>,
    #[serde(default)]
    routes: Vec<RawRoute>,
    #[serde(default)]
    unknowns: Vec<RawUnknown>,
    #[serde(default)]
    tamper: Vec<RawTamper>,
    #[serde(default)]
    unclassified: Vec<RawUnclassified>,
    #[serde(default)]
    inert: Vec<RawInert>,
    #[serde(default)]
    attributes: Vec<RawAttribute>,
    not_applicable: Option<Vec<String>>,
    #[serde(default)]
    absent_routes: Vec<String>,
    #[serde(default)]
    absent_text: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLayer {
    order: u32,
    family: String,
    kind: String,
    evidence_classes: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    class: String,
    kind: String,
    rule: Option<String>,
    signal: Option<String>,
    member: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnknown {
    source: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTamper {
    indicator: String,
    strength: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnclassified {
    universe: String,
    member: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInert {
    universe: String,
    rule: String,
    member: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttribute {
    layer: String,
    name: String,
    value: String,
}

/// Parses label text. `origin` names the case in every error message.
pub fn parse_expected(text: &str, origin: &str) -> Result<Expected, String> {
    let raw: RawExpected =
        toml::from_str(text).map_err(|e| format!("{origin}: malformed expected.toml: {e}"))?;
    let bad = |what: String| format!("{origin}: malformed expected.toml: {what}");

    let state = CompletenessState::parse(&raw.state)
        .ok_or_else(|| bad(format!("unknown state {:?}", raw.state)))?;
    if raw.exit_code != state.exit_code() {
        return Err(bad(format!(
            "exit_code {} disagrees with state {:?}, which exits {}",
            raw.exit_code,
            raw.state,
            state.exit_code()
        )));
    }

    let mut layers = Vec::new();
    let mut orders = std::collections::BTreeSet::new();
    for l in raw.layers {
        if !orders.insert(l.order) {
            return Err(bad(format!("duplicate layer order {}", l.order)));
        }
        if !LAYER_FAMILIES.contains(&l.family.as_str()) {
            return Err(bad(format!("unknown layer family {:?}", l.family)));
        }
        check_nonempty("layer kind", &l.kind).map_err(&bad)?;
        if let Some(classes) = &l.evidence_classes {
            for c in classes {
                if !EVIDENCE_CLASSES.contains(&c.as_str()) {
                    return Err(bad(format!("unknown evidence class {c:?}")));
                }
            }
        }
        layers.push(ExpectedLayer {
            order: l.order,
            family: l.family,
            kind: l.kind,
            evidence_classes: l.evidence_classes,
        });
    }

    let mut routes = Vec::new();
    for r in raw.routes {
        if r.class != "escape" && r.class != "egress" {
            return Err(bad(format!("unknown route class {:?}", r.class)));
        }
        check_nonempty("route kind", &r.kind).map_err(&bad)?;
        match (&r.rule, &r.signal) {
            (Some(rule), None) => check_nonempty("route rule", rule).map_err(&bad)?,
            (None, Some(signal)) => check_nonempty("route signal", signal).map_err(&bad)?,
            (Some(_), Some(_)) => {
                return Err(bad("route names both `rule` and `signal`".into()));
            }
            (None, None) => {
                return Err(bad("route names neither `rule` nor `signal`".into()));
            }
        }
        if let Some(m) = &r.member {
            check_nonempty("route member", m).map_err(&bad)?;
        }
        routes.push(ExpectedRoute {
            class: r.class,
            kind: r.kind,
            rule: r.rule,
            signal: r.signal,
            member: r.member,
        });
    }

    let mut unknowns = Vec::new();
    for u in raw.unknowns {
        check_nonempty("unknown source", &u.source).map_err(&bad)?;
        if !UNKNOWN_REASONS.contains(&u.reason.as_str()) {
            return Err(bad(format!("unknown reason {:?}", u.reason)));
        }
        unknowns.push(ExpectedUnknown {
            source: u.source,
            reason: u.reason,
        });
    }

    let mut tamper = Vec::new();
    for t in raw.tamper {
        check_nonempty("tamper indicator", &t.indicator).map_err(&bad)?;
        if !TAMPER_STRENGTHS.contains(&t.strength.as_str()) {
            return Err(bad(format!("unknown tamper strength {:?}", t.strength)));
        }
        tamper.push(ExpectedTamper {
            indicator: t.indicator,
            strength: t.strength,
        });
    }

    let mut unclassified = Vec::new();
    for u in raw.unclassified {
        check_nonempty("unclassified universe", &u.universe).map_err(&bad)?;
        check_nonempty("unclassified member", &u.member).map_err(&bad)?;
        unclassified.push(ExpectedUnclassified {
            universe: u.universe,
            member: u.member,
        });
    }

    let mut inert = Vec::new();
    for i in raw.inert {
        check_nonempty("inert universe", &i.universe).map_err(&bad)?;
        check_nonempty("inert rule", &i.rule).map_err(&bad)?;
        check_nonempty("inert member", &i.member).map_err(&bad)?;
        inert.push(ExpectedInert {
            universe: i.universe,
            rule: i.rule,
            member: i.member,
        });
    }

    let mut attributes = Vec::new();
    for a in raw.attributes {
        check_nonempty("attribute layer", &a.layer).map_err(&bad)?;
        check_nonempty("attribute name", &a.name).map_err(&bad)?;
        check_nonempty("attribute value", &a.value).map_err(&bad)?;
        attributes.push(ExpectedAttribute {
            layer: a.layer,
            name: a.name,
            value: a.value,
        });
    }

    if let Some(na) = &raw.not_applicable {
        for n in na {
            check_nonempty("not_applicable entry", n).map_err(&bad)?;
        }
    }
    for k in &raw.absent_routes {
        check_nonempty("absent_routes entry", k).map_err(&bad)?;
    }
    for t in &raw.absent_text {
        check_nonempty("absent_text entry", t).map_err(&bad)?;
    }

    Ok(Expected {
        state,
        exit_code: raw.exit_code,
        layers,
        routes,
        unknowns,
        tamper,
        unclassified,
        inert,
        attributes,
        not_applicable: raw.not_applicable,
        absent_routes: raw.absent_routes,
        absent_text: raw.absent_text,
    })
}

/// Reads and parses `path`; errors name the path.
pub fn load_expected(path: &Path) -> Result<Expected, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    parse_expected(&text, &origin)
}

// ---------------------------------------------------------------------------
// facts.toml
// ---------------------------------------------------------------------------

/// A validated `facts.toml`. The harness needs only the platform and the pid
/// (to resolve the `proc/self` hop target); the field-level checks exist so a
/// malformed case is a harness error, never a silently skipped source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub platform: String,
    /// `process.pid`, the pid `proc/self` must resolve to (KTD24).
    pub pid: u64,
}

/// Fact tables each platform's adapters produce. A missing table is a
/// malformed case, never an unknown, so every case states every fact.
const LINUX_FACTS: &[&str] = &["process", "env_names", "fds", "landlock_abi"];

const MACOS_FACTS: &[&str] = &[
    "process",
    "env_names",
    "fds",
    "mounts",
    "unix_sockets",
    "listeners",
    "routes",
    "interfaces",
    "sandbox_check",
    "hv_vmm_present",
    "identity",
    "traced",
];

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

/// One environment entry: either a `name` (bytes before the first `=`, never
/// the value) or `no_separator = true` for an entry with no `=` at all, whose
/// raw bytes are never emitted (the member is `<no-separator>`).
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

/// One descriptor at probe start. `target` is the readlink text
/// (`/some/path`, `socket:[1234]`, `pipe:[55]`, `anon_inode:[io_uring]`);
/// `probe_own` marks the adapter's own listing handle. Descriptors 0 to 2 are
/// the standard streams; everything else is inherited (KTD8, R28).
///
/// `fd` and `probe_own` are shape-pinned here; the snapshot reader consumes
/// them in U2.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFd {
    #[allow(dead_code)]
    fd: u64,
    #[allow(dead_code)]
    target: String,
    #[allow(dead_code)]
    probe_own: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLandlockAbi {
    state: String,
    /// ABI version when `state = "read"`.
    version: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMounts {
    state: String,
    entries: Option<Vec<RawMount>>,
}

/// A macOS mount (`getfsstat` output, normalized). `source` and `readonly`
/// are shape-pinned; the snapshot reader consumes them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMount {
    path: String,
    fstype: String,
    #[allow(dead_code)]
    source: Option<String>,
    #[allow(dead_code)]
    readonly: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnixSockets {
    state: String,
    entries: Option<Vec<RawUnixSocket>>,
}

/// A macOS unix socket (`pcblist_n` record, normalized). No `path` means an
/// unnamed socket; unnamed sockets fold into one member per type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnixSocket {
    #[allow(dead_code)]
    path: Option<String>,
    kind: String,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    gateway: Option<String>,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    families: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSandboxCheck {
    state: String,
    /// Raw `sandbox_check` return value; non-zero means sandboxed.
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

/// Parses `facts.toml`. Validates platform, the required fact set, each
/// fact's state vocabulary, and the data each state permits.
pub fn parse_facts(text: &str, origin: &str) -> Result<Facts, String> {
    let raw: RawFacts =
        toml::from_str(text).map_err(|e| format!("{origin}: malformed facts.toml: {e}"))?;
    let bad = |what: String| format!("{origin}: malformed facts.toml: {what}");

    if raw.platform != "linux" && raw.platform != "macos" {
        return Err(bad(format!("unknown platform {:?}", raw.platform)));
    }
    let required: &[&str] = if raw.platform == "linux" {
        LINUX_FACTS
    } else {
        MACOS_FACTS
    };

    let mut present: Vec<(&str, &str)> = Vec::new(); // (table, state)
    let mut pid = None;

    if let Some(p) = &raw.process {
        check_state("process", &p.state, &[]).map_err(&bad)?;
        let v = p
            .pid
            .ok_or_else(|| bad("fact `process` is missing `pid`".into()))?;
        pid = Some(v);
        present.push(("process", p.state.as_str()));
    }
    if let Some(f) = &raw.env_names {
        check_state("env_names", &f.state, &[]).map_err(&bad)?;
        check_read_only_data("env_names", &f.state, f.names.is_some()).map_err(&bad)?;
        if let Some(names) = &f.names {
            for n in names {
                match (&n.name, n.no_separator) {
                    (Some(name), None) => {
                        check_nonempty("env_names entry name", name).map_err(&bad)?
                    }
                    (None, Some(true)) => {}
                    (Some(_), Some(_)) | (None, Some(false)) | (None, None) => {
                        return Err(bad(
                            "env_names entry must carry `name` or `no_separator = true`".into(),
                        ));
                    }
                }
            }
        }
        present.push(("env_names", f.state.as_str()));
    }
    if let Some(f) = &raw.fds {
        // KTD8: the descriptor inventory can fail its kernel checks.
        check_state("fds", &f.state, &["fs-type-mismatch", "proc-self-mismatch"]).map_err(&bad)?;
        check_read_only_data("fds", &f.state, f.entries.is_some()).map_err(&bad)?;
        present.push(("fds", f.state.as_str()));
    }
    if let Some(f) = &raw.landlock_abi {
        check_state("landlock_abi", &f.state, &[]).map_err(&bad)?;
        check_read_only_data("landlock_abi", &f.state, f.version.is_some()).map_err(&bad)?;
        if f.state == "read" && f.version.is_none() {
            return Err(bad("fact `landlock_abi` is missing `version`".into()));
        }
        present.push(("landlock_abi", f.state.as_str()));
    }
    if let Some(f) = &raw.mounts {
        check_state("mounts", &f.state, &[]).map_err(&bad)?;
        check_read_only_data("mounts", &f.state, f.entries.is_some()).map_err(&bad)?;
        if let Some(entries) = &f.entries {
            for m in entries {
                check_nonempty("mounts entry path", &m.path).map_err(&bad)?;
                check_nonempty("mounts entry fstype", &m.fstype).map_err(&bad)?;
            }
        }
        present.push(("mounts", f.state.as_str()));
    }
    for (name, table, state, has_entries) in [
        (
            "unix_sockets",
            raw.unix_sockets.is_some(),
            raw.unix_sockets.as_ref().map(|t| t.state.as_str()),
            raw.unix_sockets
                .as_ref()
                .map(|t| t.entries.is_some())
                .unwrap_or(false),
        ),
        (
            "listeners",
            raw.listeners.is_some(),
            raw.listeners.as_ref().map(|t| t.state.as_str()),
            raw.listeners
                .as_ref()
                .map(|t| t.entries.is_some())
                .unwrap_or(false),
        ),
        (
            "routes",
            raw.routes.is_some(),
            raw.routes.as_ref().map(|t| t.state.as_str()),
            raw.routes
                .as_ref()
                .map(|t| t.entries.is_some())
                .unwrap_or(false),
        ),
        (
            "interfaces",
            raw.interfaces.is_some(),
            raw.interfaces.as_ref().map(|t| t.state.as_str()),
            raw.interfaces
                .as_ref()
                .map(|t| t.entries.is_some())
                .unwrap_or(false),
        ),
    ] {
        if !table {
            continue;
        }
        let state = state.unwrap_or_default();
        // KTD17: the socket-table adapters may find a record layout they
        // cannot parse, reported as `unsupported-layout`.
        let extra: &[&str] = if name == "unix_sockets" || name == "listeners" {
            &["unsupported-layout"]
        } else {
            &[]
        };
        check_state(name, state, extra).map_err(&bad)?;
        check_read_only_data(name, state, has_entries).map_err(&bad)?;
        present.push((name, state));
    }
    if let Some(t) = &raw.unix_sockets
        && let Some(entries) = &t.entries
    {
        for e in entries {
            if e.kind != "stream" && e.kind != "dgram" {
                return Err(bad(format!("unix_sockets entry kind {:?}", e.kind)));
            }
        }
    }
    if let Some(t) = &raw.listeners
        && let Some(entries) = &t.entries
    {
        for e in entries {
            if e.protocol != "tcp" && e.protocol != "udp" {
                return Err(bad(format!("listeners entry protocol {:?}", e.protocol)));
            }
            check_nonempty("listeners entry address", &e.address).map_err(&bad)?;
        }
    }
    if let Some(t) = &raw.routes
        && let Some(entries) = &t.entries
    {
        for e in entries {
            if e.family != "inet" && e.family != "inet6" {
                return Err(bad(format!("routes entry family {:?}", e.family)));
            }
            check_nonempty("routes entry destination", &e.destination).map_err(&bad)?;
        }
    }
    if let Some(t) = &raw.interfaces
        && let Some(entries) = &t.entries
    {
        for e in entries {
            check_nonempty("interfaces entry name", &e.name).map_err(&bad)?;
        }
    }
    if let Some(f) = &raw.sandbox_check {
        check_state("sandbox_check", &f.state, &[]).map_err(&bad)?;
        check_read_only_data("sandbox_check", &f.state, f.result.is_some()).map_err(&bad)?;
        if f.state == "read" && f.result.is_none() {
            return Err(bad("fact `sandbox_check` is missing `result`".into()));
        }
        present.push(("sandbox_check", f.state.as_str()));
    }
    if let Some(f) = &raw.hv_vmm_present {
        check_state("hv_vmm_present", &f.state, &[]).map_err(&bad)?;
        check_read_only_data("hv_vmm_present", &f.state, f.present.is_some()).map_err(&bad)?;
        if f.state == "read" && f.present.is_none() {
            return Err(bad("fact `hv_vmm_present` is missing `present`".into()));
        }
        present.push(("hv_vmm_present", f.state.as_str()));
    }
    if let Some(f) = &raw.identity {
        check_state("identity", &f.state, &[]).map_err(&bad)?;
        let has = f.euid.is_some() || f.egid.is_some();
        check_read_only_data("identity", &f.state, has).map_err(&bad)?;
        if f.state == "read" && (f.euid.is_none() || f.egid.is_none()) {
            return Err(bad("fact `identity` is missing `euid` or `egid`".into()));
        }
        present.push(("identity", f.state.as_str()));
    }
    if let Some(f) = &raw.traced {
        check_state("traced", &f.state, &[]).map_err(&bad)?;
        check_read_only_data("traced", &f.state, f.traced.is_some()).map_err(&bad)?;
        if f.state == "read" && f.traced.is_none() {
            return Err(bad("fact `traced` is missing `traced`".into()));
        }
        present.push(("traced", f.state.as_str()));
    }

    for name in required {
        if !present.iter().any(|(n, _)| n == name) {
            return Err(bad(format!("missing fact table `{name}`")));
        }
    }
    for (name, _) in &present {
        if !required.contains(name) {
            return Err(bad(format!(
                "fact `{name}` is not produced on {}",
                raw.platform
            )));
        }
    }

    Ok(Facts {
        platform: raw.platform,
        pid: pid.unwrap_or_default(),
    })
}

fn check_state(fact: &str, state: &str, extra: &[&str]) -> Result<(), String> {
    if FACT_STATES.contains(&state) || extra.contains(&state) {
        Ok(())
    } else {
        Err(format!("fact `{fact}` has unknown state {state:?}"))
    }
}

/// Adapter data is meaningful only for `state = "read"`.
fn check_read_only_data(fact: &str, state: &str, has_data: bool) -> Result<(), String> {
    if state != "read" && has_data {
        Err(format!(
            "fact `{fact}` carries data while state is {state:?}"
        ))
    } else {
        Ok(())
    }
}

/// Reads and parses `path`; errors name the path.
pub fn load_facts(path: &Path) -> Result<Facts, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    parse_facts(&text, &origin)
}

// ---------------------------------------------------------------------------
// manifest.toml
// ---------------------------------------------------------------------------

/// A parsed `manifest.toml` overlay: nodes git cannot store plus metadata,
/// filesystem-type, and forced-error overrides (KTD12).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub nodes: Vec<ManifestNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestNode {
    /// In-root path, `/`-separated, no leading slash.
    pub path: String,
    pub kind: NodeKind,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub access: Option<String>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    /// Filesystem type override: `proc`, `sysfs`, `tmpfs`, `devtmpfs`,
    /// `local`, or a mount fstype.
    pub fs: Option<String>,
    /// Forced errno for `error` nodes.
    pub errno: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Socket,
    Fifo,
    Char,
    Block,
    Meta,
    Error,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(default)]
    node: Vec<RawNode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    access: Option<String>,
    major: Option<u32>,
    minor: Option<u32>,
    fs: Option<String>,
    errno: Option<String>,
}

/// Parses `manifest.toml` and validates each node's field set.
pub fn parse_manifest(text: &str, origin: &str) -> Result<Manifest, String> {
    let raw: RawManifest =
        toml::from_str(text).map_err(|e| format!("{origin}: malformed manifest.toml: {e}"))?;
    let bad = |what: String| format!("{origin}: malformed manifest.toml: {what}");

    let mut nodes = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for n in raw.node {
        check_path(&n.path).map_err(&bad)?;
        if !seen.insert(n.path.clone()) {
            return Err(bad(format!("duplicate node {:?}", n.path)));
        }
        if !NODE_KINDS.contains(&n.kind.as_str()) {
            return Err(bad(format!("unknown node type {:?}", n.kind)));
        }
        if let Some(a) = &n.access
            && !NODE_ACCESS.contains(&a.as_str())
        {
            return Err(bad(format!("unknown access {a:?}")));
        }
        if let Some(f) = &n.fs {
            check_nonempty("fs", f).map_err(&bad)?;
        }
        if let Some(e) = &n.errno
            && !MANIFEST_ERRNOS.contains(&e.as_str())
        {
            return Err(bad(format!("unknown errno {e:?}")));
        }
        let kind = match n.kind.as_str() {
            "socket" => NodeKind::Socket,
            "fifo" => NodeKind::Fifo,
            "char" => NodeKind::Char,
            "block" => NodeKind::Block,
            "meta" => NodeKind::Meta,
            _ => NodeKind::Error,
        };
        match kind {
            NodeKind::Error => {
                if n.errno.is_none() {
                    return Err(bad(format!("error node {:?} has no `errno`", n.path)));
                }
                if n.mode.is_some()
                    || n.uid.is_some()
                    || n.gid.is_some()
                    || n.access.is_some()
                    || n.major.is_some()
                    || n.minor.is_some()
                    || n.fs.is_some()
                {
                    return Err(bad(format!(
                        "error node {:?} may only carry `errno`",
                        n.path
                    )));
                }
            }
            NodeKind::Char | NodeKind::Block => {
                if n.major.is_none() || n.minor.is_none() {
                    return Err(bad(format!(
                        "{} node {:?} needs `major` and `minor`",
                        n.kind, n.path
                    )));
                }
                if n.errno.is_some() {
                    return Err(bad(format!("node {:?} may not carry `errno`", n.path)));
                }
            }
            NodeKind::Socket | NodeKind::Fifo | NodeKind::Meta => {
                if n.major.is_some() || n.minor.is_some() || n.errno.is_some() {
                    return Err(bad(format!(
                        "{} node {:?} may not carry `major`, `minor`, or `errno`",
                        n.kind, n.path
                    )));
                }
            }
        }
        nodes.push(ManifestNode {
            path: n.path,
            kind,
            mode: n.mode,
            uid: n.uid,
            gid: n.gid,
            access: n.access,
            major: n.major,
            minor: n.minor,
            fs: n.fs,
            errno: n.errno,
        });
    }
    Ok(Manifest { nodes })
}

/// Checks manifest nodes against `tree/`: virtual nodes (socket, fifo, char,
/// block) must not exist there, and `meta` nodes must — unless the node is
/// a synthesized directory, which the manifest's own descendants imply.
pub fn check_manifest_tree(manifest: &Manifest, tree: &Path, origin: &str) -> Result<(), String> {
    for n in &manifest.nodes {
        let exists = tree.join(&n.path).symlink_metadata().is_ok();
        match n.kind {
            NodeKind::Socket | NodeKind::Fifo | NodeKind::Char | NodeKind::Block if exists => {
                return Err(format!(
                    "{origin}: {} node {:?} also exists in tree/",
                    kind_name(n.kind),
                    n.path
                ));
            }
            NodeKind::Meta if !exists => {
                let has_descendants = manifest
                    .nodes
                    .iter()
                    .any(|m| m.path != n.path && m.path.starts_with(&format!("{}/", n.path)));
                if !has_descendants {
                    return Err(format!(
                        "{origin}: meta node {:?} does not exist in tree/",
                        n.path
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn kind_name(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Socket => "socket",
        NodeKind::Fifo => "fifo",
        NodeKind::Char => "char",
        NodeKind::Block => "block",
        NodeKind::Meta => "meta",
        NodeKind::Error => "error",
    }
}

/// Reads, parses, and tree-checks `path`; errors name the path.
pub fn load_manifest(path: &Path, tree: &Path) -> Result<Manifest, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    let manifest = parse_manifest(&text, &origin)?;
    check_manifest_tree(&manifest, tree, &origin)?;
    Ok(manifest)
}

fn check_nonempty(what: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{what} is empty"))
    } else {
        Ok(())
    }
}

/// Label paths are root-relative, `/`-separated, and never carry `.` or `..`.
fn check_path(path: &str) -> Result<(), String> {
    check_nonempty("path", path)?;
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!("path {path:?} is not root-relative"));
    }
    Ok(())
}

//! Embedded probe data: the universe table, classification rules, named
//! signals, layer conditions, the not-observable list, filesystem sets,
//! budgets, and the active-mode refused list (KTD3, KTD6, KTD18, KTD19,
//! KTD21, KTD24, KTD26).
//!
//! The files under `data/probe/` are embedded at compile time and parsed
//! into the typed structures below; every file denies unknown fields and
//! every error names its file. `Data::embedded` computes `data_digest`
//! over these files only, so probe data changes never touch the code
//! layer's digest (KTD19): `egress_core::data::EMBEDDED` is not extended.
//!
//! The `guards` submodule holds the data guards that
//! `tests/data_coverage.rs` runs on the real data and on mutated copies.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use egress_core::data::{DataFile, data_digest};

use crate::model::UnknownReason;

/// Every probe data file this module embeds (KTD19).
pub const EMBEDDED: &[DataFile] = &[
    DataFile {
        path: "data/probe/universes.toml",
        text: include_str!("../../../data/probe/universes.toml"),
    },
    DataFile {
        path: "data/probe/rules.toml",
        text: include_str!("../../../data/probe/rules.toml"),
    },
    DataFile {
        path: "data/probe/signals.toml",
        text: include_str!("../../../data/probe/signals.toml"),
    },
    DataFile {
        path: "data/probe/layers.toml",
        text: include_str!("../../../data/probe/layers.toml"),
    },
    DataFile {
        path: "data/probe/not-observable.toml",
        text: include_str!("../../../data/probe/not-observable.toml"),
    },
    DataFile {
        path: "data/probe/filesystems.toml",
        text: include_str!("../../../data/probe/filesystems.toml"),
    },
    DataFile {
        path: "data/probe/budgets.toml",
        text: include_str!("../../../data/probe/budgets.toml"),
    },
    DataFile {
        path: "data/probe/active.toml",
        text: include_str!("../../../data/probe/active.toml"),
    },
];

/// The R9 finite sets every platform declares, either as a universe or as
/// not applicable.
const R9_SETS: [&str; 8] = [
    "mounts",
    "unix-sockets",
    "listeners",
    "fds",
    "env-names",
    "capabilities",
    "routes",
    "resolvers",
];

const PLATFORMS: [&str; 2] = ["linux", "macos"];

/// Evidence source classes (KTD16); duplicated in the corpus harness's
/// label checks, which cannot depend on this crate.
const EVIDENCE_CLASSES: &[&str] = &[
    "kernel",
    "filesystem-marker",
    "environment-name",
    "firmware",
    "resolver-config",
    "network-interface",
];

/// Fact names a `fact` condition may test (the `facts.toml` tables).
const FACT_NAMES: &[&str] = &[
    "process",
    "env_names",
    "fds",
    "landlock_abi",
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

/// The fixed family ranks of KTD16.
fn family_rank(family: &str) -> Option<u32> {
    match family {
        "cloud" => Some(1),
        "ci" => Some(2),
        "container" => Some(3),
        "sandbox" => Some(4),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Typed data
// ---------------------------------------------------------------------------

/// All loaded probe data.
#[derive(Debug, Clone)]
pub struct Data {
    pub data_digest: String,
    pub universes: Vec<Universe>,
    pub attribute_sources: Vec<AttributeSource>,
    pub not_applicable: Vec<NotApplicable>,
    pub rules: Vec<Rule>,
    pub signals: Vec<Signal>,
    pub layers: Vec<Layer>,
    pub not_observable: Vec<NotObservable>,
    pub filesystems: Filesystems,
    pub budgets: Budgets,
    pub active: Vec<Refused>,
}

impl Data {
    /// Loads the embedded data files.
    pub fn embedded() -> Result<Data, String> {
        let files: Vec<(&str, &str)> = EMBEDDED.iter().map(|f| (f.path, f.text)).collect();
        load(&files)
    }

    pub fn universe(&self, id: &str) -> Option<&Universe> {
        self.universes.iter().find(|u| u.id == id)
    }

    pub fn rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn signal(&self, id: &str) -> Option<&Signal> {
        self.signals.iter().find(|s| s.id == id)
    }

    /// Whether `fstype` is a never-touched filesystem on `platform`
    /// (KTD26): an exact entry or a `no-touch-prefixes` match.
    pub fn no_touch_fstype(&self, platform: &str, fstype: &str) -> bool {
        let set = match platform {
            "linux" => &self.filesystems.linux,
            "macos" => &self.filesystems.macos,
            _ => return false,
        };
        set.no_touch.iter().any(|f| f == fstype)
            || set
                .no_touch_prefixes
                .iter()
                .any(|p| fstype.starts_with(p.as_str()))
    }
}

/// One declared finite set (KTD3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Universe {
    pub id: String,
    /// `linux` or `macos`.
    pub platform: String,
    /// The R9 set this universe answers for, when it is one.
    pub set: Option<String>,
    pub source: String,
    /// The absent-signature id; `None` when a missing source is an
    /// unknown, never an absence.
    pub absent: Option<String>,
    /// Enumerated sets with fewer members are `implausibly-empty`.
    pub min_members: u64,
    /// Header-bearing proc tables: each file's first lines must match
    /// these prefixes in order, else `masked-or-truncated`.
    pub masked: BTreeMap<String, Vec<String>>,
    pub identity: Vec<String>,
    pub display: Vec<String>,
    /// Notable unknown reasons beyond the generic set.
    pub unknowns: Vec<UnknownReason>,
}

/// An R12 confinement attribute source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeSource {
    pub id: String,
    pub platform: String,
    pub source: String,
}

/// An R24 not-applicable entry: a source declared for another platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotApplicable {
    pub id: String,
    pub platform: String,
    /// The R9 set this entry covers, when it covers one.
    pub set: Option<String>,
}

/// The class a rule assigns (KTD6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleClass {
    Escape,
    Egress,
    Inert,
}

impl RuleClass {
    pub const ALL: [RuleClass; 3] = [Self::Escape, Self::Egress, Self::Inert];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Escape => "escape",
            Self::Egress => "egress",
            Self::Inert => "inert",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// Predicates on one member field of a match clause. Positive tests
/// (`equals`, `in`, `prefix`, `suffix`, `under`, `basename-in`, `device`,
/// `member-of`) are alternatives: a field carrying any of them must match
/// at least one. Negative tests (`not-in`, `not-prefix`) must all hold.
/// `flag` compares a boolean attribute field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Predicate {
    pub equals: Option<String>,
    pub in_: Vec<String>,
    pub not_in: Vec<String>,
    pub prefix: Vec<String>,
    pub not_prefix: Vec<String>,
    pub suffix: Vec<String>,
    /// Path equal to or below the value on a component boundary.
    pub under: Vec<String>,
    /// Last path component in the list.
    pub basename_in: Vec<String>,
    pub flag: Option<bool>,
    /// The field equals a member path of the named universe
    /// (cross-universe test, `linux.mount.socket-bind`).
    pub member_of: Option<String>,
    /// `major:minor` device numbers.
    pub device: Vec<String>,
}

/// One match clause: a field-name to predicate map; every field's
/// predicate must hold.
pub type MatchClause = BTreeMap<String, Predicate>;

/// One classification rule (KTD6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub universes: Vec<String>,
    /// OR'd clauses: the rule applies when any clause matches.
    pub clauses: Vec<MatchClause>,
    /// When every predicate in this clause holds, the rule does not
    /// apply.
    pub except: Option<MatchClause>,
    pub class: RuleClass,
    /// Route kind; required for escape and egress, forbidden for inert.
    pub kind: Option<String>,
    /// Route kind used instead when a route member's destination prefix
    /// length is zero (`route.any`).
    pub default_route_kind: Option<String>,
    /// Required for inert, forbidden otherwise.
    pub justification: Option<String>,
    /// `fixtures/probe/` case that labels this rule.
    pub fixture: String,
}

/// A signal's platform applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalPlatform {
    Linux,
    Macos,
    Both,
}

/// Signal kinds; `integrity` entries are produced by the integrity checks
/// rather than evaluated over members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignalKind {
    PathMarker,
    CredentialPath,
    CredentialDir,
    DmiValue,
    SysctlValue,
    Derived,
    Integrity,
}

impl SignalKind {
    pub const ALL: [SignalKind; 7] = [
        Self::PathMarker,
        Self::CredentialPath,
        Self::CredentialDir,
        Self::DmiValue,
        Self::SysctlValue,
        Self::Derived,
        Self::Integrity,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PathMarker => "path-marker",
            Self::CredentialPath => "credential-path",
            Self::CredentialDir => "credential-dir",
            Self::DmiValue => "dmi-value",
            Self::SysctlValue => "sysctl-value",
            Self::Derived => "derived",
            Self::Integrity => "integrity",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// One DMI value check; entries are AND'd within a `group` and OR'd
/// across groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmiValue {
    pub path: String,
    pub group: u32,
    pub equals: Option<String>,
    pub prefix: Option<String>,
}

/// A mount member condition inside a derived signal or layer clause:
/// every present field must match the mount member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountCond {
    pub fstype: Vec<String>,
    /// Exact mount point.
    pub point: Vec<String>,
    /// Mount point equal to or below one of these.
    pub under: Vec<String>,
    pub writable: Option<bool>,
}

/// One condition of a derived signal or a layer. All set fields must hold
/// (each list field is an OR over its values); `attr` requires `equals`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Condition {
    /// Signal ids that fired.
    pub signal: Vec<String>,
    /// env-names members equal to / starting with these.
    pub env: Vec<String>,
    pub env_prefix: Vec<String>,
    /// A cgroup line containing one of these.
    pub cgroup_contains: Vec<String>,
    /// A nameserver member value.
    pub resolver: Vec<String>,
    /// A search or domain member value equal to / ending in these.
    pub resolver_search: Vec<String>,
    pub resolver_search_suffix: Vec<String>,
    /// Attribute name plus `equals`.
    pub attr: Option<String>,
    pub equals: Option<String>,
    /// `all-effective`: every known capability in the effective set.
    pub capabilities: Vec<String>,
    /// A detected layer of one of these families (after-layers only).
    pub layer_family: Vec<String>,
    /// An interface member equal to / starting with these.
    pub interface: Vec<String>,
    pub interface_prefix: Vec<String>,
    /// A mount member matching / no mount member matching.
    pub mount: Option<MountCond>,
    pub no_mount: Option<MountCond>,
    /// The fstype of the mount at `/`.
    pub root_fstype: Vec<String>,
    /// A fact that is true or nonzero.
    pub fact: Vec<String>,
    /// The KTD16 evidence class this condition contributes.
    pub evidence: Option<String>,
}

/// The route a signal produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalRoute {
    pub class: RuleClass,
    pub kind: String,
}

/// The tamper indicator a signal produces (KTD25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalTamper {
    pub indicator: String,
    pub strength: crate::model::TamperStrength,
}

/// One named signal (R11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub id: String,
    pub platform: SignalPlatform,
    pub kind: SignalKind,
    pub paths: Vec<String>,
    /// Directory to list (`credential-dir`; `path-marker` with
    /// `name_contains`).
    pub dir: Option<String>,
    /// Entry-name filter for `dir` listings on a `path-marker`.
    pub name_contains: Option<String>,
    /// `credential-dir` entry filters (`id_` names excluding `.pub`).
    pub entry_prefix: Option<String>,
    pub entry_exclude_suffix: Option<String>,
    /// env-names members a `derived` signal matches.
    pub names: Vec<String>,
    pub name_prefixes: Vec<String>,
    /// `dmi-value` checks.
    pub values: Vec<DmiValue>,
    /// Attribute names the signal produces (`sysctl-value`, KTD28).
    pub attributes: Vec<String>,
    /// Evaluate after layer detection.
    pub after_layers: bool,
    pub any: Vec<Condition>,
    pub all: Vec<Condition>,
    pub route: Option<SignalRoute>,
    pub tamper: Option<SignalTamper>,
    pub fixture: String,
}

impl Signal {
    /// Whether any declared path is home-relative (governs the
    /// `no-account-home` unknown-label allowance, KTD15).
    pub fn home_relative(&self) -> bool {
        self.paths.iter().any(|p| p.contains("<home>"))
            || self.dir.as_deref().is_some_and(|d| d.contains("<home>"))
    }
}

/// One detectable layer kind (KTD16, KTD29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub family: String,
    pub kind: String,
    pub rank: u32,
    /// Additionally requires that no other kind of the same family was
    /// detected (generic-ci, oci-generic, seccomp-filter).
    pub no_other_in_family: bool,
    pub any: Vec<Condition>,
    pub all: Vec<Condition>,
    pub fixture: String,
}

/// One entry of the R23 not-observable list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotObservable {
    pub id: String,
    pub platform: String,
    pub statement: String,
    pub reason: String,
}

/// One platform's filesystem sets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemSet {
    /// Fstypes never touched (R31).
    pub no_touch: Vec<String>,
    pub no_touch_prefixes: Vec<String>,
    /// Required filesystem magic per in-root top-level directory (KTD24).
    pub magic: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filesystems {
    pub linux: FilesystemSet,
    pub macos: FilesystemSet,
}

/// The deterministic budgets (KTD18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budgets {
    pub members_per_universe: u64,
    pub bytes_per_file: u64,
    pub entries_per_listing: u64,
    pub dev_listing_depth: u64,
    pub bytes_per_member_string: u64,
    pub report_bytes: u64,
    pub active_targets: u64,
    pub connect_timeout_ms: u64,
    pub run_deadline_ms: u64,
}

/// One refused active-mode destination (KTD21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// An IP literal or `addr/prefix` range.
    pub value: String,
    pub result: RefusedResult,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusedResult {
    MetadataAddress,
    SpecialAddress,
}

impl RefusedResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetadataAddress => "refused-metadata-address",
            Self::SpecialAddress => "refused-special-address",
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUniverses {
    #[serde(default)]
    universe: Vec<RawUniverse>,
    #[serde(default)]
    attribute_source: Vec<RawAttributeSource>,
    #[serde(default)]
    not_applicable: Vec<RawNotApplicable>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUniverse {
    id: String,
    platform: String,
    set: Option<String>,
    source: String,
    absent: Option<String>,
    #[serde(default)]
    min_members: u64,
    #[serde(default)]
    masked: BTreeMap<String, Vec<String>>,
    identity: Vec<String>,
    display: Vec<String>,
    #[serde(default)]
    unknowns: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttributeSource {
    id: String,
    platform: String,
    source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNotApplicable {
    id: String,
    platform: String,
    set: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    universes: Vec<String>,
    r#match: Option<MatchClauseRaw>,
    #[serde(default)]
    any: Vec<MatchClauseRaw>,
    except: Option<MatchClauseRaw>,
    class: String,
    kind: Option<String>,
    #[serde(rename = "default-route-kind")]
    default_route_kind: Option<String>,
    justification: Option<String>,
    fixture: Option<String>,
}

type MatchClauseRaw = BTreeMap<String, RawPredicate>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPredicate {
    equals: Option<toml::Value>,
    #[serde(rename = "in", default)]
    in_: Vec<toml::Value>,
    #[serde(rename = "not-in", default)]
    not_in: Vec<toml::Value>,
    #[serde(default)]
    prefix: Vec<String>,
    #[serde(rename = "not-prefix", default)]
    not_prefix: Vec<String>,
    #[serde(default)]
    suffix: Vec<String>,
    #[serde(default)]
    under: Vec<String>,
    #[serde(rename = "basename-in", default)]
    basename_in: Vec<String>,
    flag: Option<bool>,
    #[serde(rename = "member-of")]
    member_of: Option<String>,
    #[serde(default)]
    device: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignals {
    #[serde(default)]
    signal: Vec<RawSignal>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignal {
    id: String,
    platform: String,
    kind: String,
    #[serde(default)]
    paths: Vec<String>,
    dir: Option<String>,
    #[serde(rename = "name-contains")]
    name_contains: Option<String>,
    #[serde(rename = "entry-prefix")]
    entry_prefix: Option<String>,
    #[serde(rename = "entry-exclude-suffix")]
    entry_exclude_suffix: Option<String>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(rename = "name-prefixes", default)]
    name_prefixes: Vec<String>,
    #[serde(default)]
    values: Vec<RawDmiValue>,
    #[serde(default)]
    attributes: Vec<String>,
    #[serde(rename = "after-layers", default)]
    after_layers: bool,
    #[serde(default)]
    any: Vec<RawCondition>,
    #[serde(default)]
    all: Vec<RawCondition>,
    route: Option<RawSignalRoute>,
    tamper: Option<RawSignalTamper>,
    fixture: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDmiValue {
    path: String,
    #[serde(default)]
    group: u32,
    equals: Option<String>,
    prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignalRoute {
    class: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignalTamper {
    indicator: String,
    strength: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCondition {
    #[serde(default)]
    signal: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(rename = "env-prefix", default)]
    env_prefix: Vec<String>,
    #[serde(rename = "cgroup-contains", default)]
    cgroup_contains: Vec<String>,
    #[serde(default)]
    resolver: Vec<String>,
    #[serde(rename = "resolver-search", default)]
    resolver_search: Vec<String>,
    #[serde(rename = "resolver-search-suffix", default)]
    resolver_search_suffix: Vec<String>,
    attr: Option<String>,
    equals: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(rename = "layer-family", default)]
    layer_family: Vec<String>,
    #[serde(default)]
    interface: Vec<String>,
    #[serde(rename = "interface-prefix", default)]
    interface_prefix: Vec<String>,
    mount: Option<RawMountCond>,
    #[serde(rename = "no-mount")]
    no_mount: Option<RawMountCond>,
    #[serde(rename = "root-fstype", default)]
    root_fstype: Vec<String>,
    #[serde(default)]
    fact: Vec<String>,
    evidence: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMountCond {
    #[serde(default)]
    fstype: Vec<String>,
    #[serde(default)]
    point: Vec<String>,
    #[serde(default)]
    under: Vec<String>,
    writable: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLayers {
    #[serde(default)]
    layer: Vec<RawLayer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLayer {
    family: String,
    kind: String,
    rank: u32,
    #[serde(rename = "no-other-in-family", default)]
    no_other_in_family: bool,
    #[serde(default)]
    any: Vec<RawCondition>,
    #[serde(default)]
    all: Vec<RawCondition>,
    fixture: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNotObservable {
    #[serde(default)]
    source: Vec<RawNotObservableEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNotObservableEntry {
    id: String,
    platform: String,
    statement: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFilesystems {
    linux: RawFilesystemSet,
    macos: RawFilesystemSet,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFilesystemSet {
    #[serde(rename = "no-touch", default)]
    no_touch: Vec<String>,
    #[serde(rename = "no-touch-prefixes", default)]
    no_touch_prefixes: Vec<String>,
    #[serde(default)]
    magic: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudgets {
    #[serde(rename = "members-per-universe")]
    members_per_universe: u64,
    #[serde(rename = "bytes-per-file")]
    bytes_per_file: u64,
    #[serde(rename = "entries-per-listing")]
    entries_per_listing: u64,
    #[serde(rename = "dev-listing-depth")]
    dev_listing_depth: u64,
    #[serde(rename = "bytes-per-member-string")]
    bytes_per_member_string: u64,
    #[serde(rename = "report-bytes")]
    report_bytes: u64,
    #[serde(rename = "active-targets")]
    active_targets: u64,
    #[serde(rename = "connect-timeout-ms")]
    connect_timeout_ms: u64,
    #[serde(rename = "run-deadline-ms")]
    run_deadline_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawActive {
    #[serde(default)]
    refused: Vec<RawRefused>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRefused {
    value: String,
    result: String,
    reason: String,
}

fn nonempty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn check_platform(path: &str, what: &str, platform: &str) -> Result<(), String> {
    if PLATFORMS.contains(&platform) {
        Ok(())
    } else {
        Err(format!("{path}: {what}: unknown platform {platform:?}"))
    }
}

/// A predicate value renders to a canonical string for member-field
/// comparison: strings pass through, integers render decimal, booleans
/// render `true`/`false`.
fn value_string(v: &toml::Value, path: &str, what: &str) -> Result<String, String> {
    match v {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(n) => Ok(n.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        other => Err(format!(
            "{path}: {what}: unsupported predicate value {other}"
        )),
    }
}

fn build_predicate(path: &str, what: &str, raw: RawPredicate) -> Result<Predicate, String> {
    let equals = raw
        .equals
        .map(|v| value_string(&v, path, what))
        .transpose()?;
    let mut in_ = Vec::new();
    for v in raw.in_ {
        in_.push(value_string(&v, path, what)?);
    }
    let mut not_in = Vec::new();
    for v in raw.not_in {
        not_in.push(value_string(&v, path, what)?);
    }
    let p = Predicate {
        equals,
        in_,
        not_in,
        prefix: raw.prefix,
        not_prefix: raw.not_prefix,
        suffix: raw.suffix,
        under: raw.under,
        basename_in: raw.basename_in,
        flag: raw.flag,
        member_of: raw.member_of,
        device: raw.device,
    };
    if p.equals.is_none()
        && p.in_.is_empty()
        && p.not_in.is_empty()
        && p.prefix.is_empty()
        && p.not_prefix.is_empty()
        && p.suffix.is_empty()
        && p.under.is_empty()
        && p.basename_in.is_empty()
        && p.flag.is_none()
        && p.member_of.is_none()
        && p.device.is_empty()
    {
        return Err(format!("{path}: {what}: empty predicate"));
    }
    Ok(p)
}

fn build_clause(path: &str, what: &str, raw: MatchClauseRaw) -> Result<MatchClause, String> {
    let mut clause = MatchClause::new();
    for (field, pred) in raw {
        if field.is_empty() {
            return Err(format!("{path}: {what}: empty field name"));
        }
        clause.insert(
            field.clone(),
            build_predicate(path, &format!("{what}: field {field}"), pred)?,
        );
    }
    if clause.is_empty() {
        return Err(format!("{path}: {what}: empty match clause"));
    }
    Ok(clause)
}

fn build_condition(path: &str, what: &str, raw: RawCondition) -> Result<Condition, String> {
    let c = Condition {
        signal: raw.signal,
        env: raw.env,
        env_prefix: raw.env_prefix,
        cgroup_contains: raw.cgroup_contains,
        resolver: raw.resolver,
        resolver_search: raw.resolver_search,
        resolver_search_suffix: raw.resolver_search_suffix,
        attr: raw.attr,
        equals: raw.equals,
        capabilities: raw.capabilities,
        layer_family: raw.layer_family,
        interface: raw.interface,
        interface_prefix: raw.interface_prefix,
        mount: raw
            .mount
            .map(|m| build_mount_cond(path, what, m))
            .transpose()?,
        no_mount: raw
            .no_mount
            .map(|m| build_mount_cond(path, what, m))
            .transpose()?,
        root_fstype: raw.root_fstype,
        fact: raw.fact,
        evidence: raw.evidence,
    };
    if (c.attr.is_none()) != (c.equals.is_none()) {
        return Err(format!("{path}: {what}: `attr` and `equals` go together"));
    }
    if c.signal.is_empty()
        && c.env.is_empty()
        && c.env_prefix.is_empty()
        && c.cgroup_contains.is_empty()
        && c.resolver.is_empty()
        && c.resolver_search.is_empty()
        && c.resolver_search_suffix.is_empty()
        && c.attr.is_none()
        && c.capabilities.is_empty()
        && c.layer_family.is_empty()
        && c.interface.is_empty()
        && c.interface_prefix.is_empty()
        && c.mount.is_none()
        && c.no_mount.is_none()
        && c.root_fstype.is_empty()
        && c.fact.is_empty()
    {
        return Err(format!("{path}: {what}: empty condition"));
    }
    for cap in &c.capabilities {
        if cap != "all-effective" {
            return Err(format!(
                "{path}: {what}: unknown capabilities condition {cap:?}"
            ));
        }
    }
    for fam in &c.layer_family {
        if family_rank(fam).is_none() {
            return Err(format!("{path}: {what}: unknown layer family {fam:?}"));
        }
    }
    for f in &c.fact {
        if !FACT_NAMES.contains(&f.as_str()) {
            return Err(format!("{path}: {what}: unknown fact {f:?}"));
        }
    }
    if let Some(e) = &c.evidence
        && !EVIDENCE_CLASSES.contains(&e.as_str())
    {
        return Err(format!("{path}: {what}: unknown evidence class {e:?}"));
    }
    Ok(c)
}

fn build_mount_cond(path: &str, what: &str, raw: RawMountCond) -> Result<MountCond, String> {
    if raw.fstype.is_empty()
        && raw.point.is_empty()
        && raw.under.is_empty()
        && raw.writable.is_none()
    {
        return Err(format!("{path}: {what}: empty mount condition"));
    }
    Ok(MountCond {
        fstype: raw.fstype,
        point: raw.point,
        under: raw.under,
        writable: raw.writable,
    })
}

fn check_fs_path(path: &str, what: &str, p: &str) -> Result<(), String> {
    if p.is_empty() || !p.starts_with('/') && !p.starts_with("<home>") && !p.starts_with("<euid>") {
        return Err(format!("{path}: {what}: malformed path {p:?}"));
    }
    Ok(())
}

/// Loads data from `(path, text)` pairs. All eight `data/probe/` files are
/// required; any other file only enters the digest.
pub fn load(files: &[(&str, &str)]) -> Result<Data, String> {
    let get = |path: &str| -> Result<&str, String> {
        files
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, t)| *t)
            .ok_or_else(|| format!("{path}: missing data file"))
    };
    let path = "data/probe/universes.toml";
    let ru: RawUniverses =
        toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;
    let path = "data/probe/rules.toml";
    let rr: RawRules = toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;
    let path = "data/probe/signals.toml";
    let rs: RawSignals =
        toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;
    let path = "data/probe/layers.toml";
    let rl: RawLayers =
        toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;
    let path = "data/probe/not-observable.toml";
    let rn: RawNotObservable =
        toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;
    let path = "data/probe/filesystems.toml";
    let rf: RawFilesystems =
        toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;
    let path = "data/probe/budgets.toml";
    let rb: RawBudgets =
        toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;
    let path = "data/probe/active.toml";
    let ra: RawActive =
        toml::from_str(get(path)?).map_err(|e| format!("{path}: malformed: {e}"))?;

    // Universes.
    let upath = "data/probe/universes.toml";
    let mut universes = Vec::new();
    for u in ru.universe {
        let what = format!("universe {}", u.id);
        check_platform(upath, &what, &u.platform)?;
        if u.id.is_empty() {
            return Err(format!("{upath}: universe with an empty id"));
        }
        if let Some(set) = &u.set
            && !R9_SETS.contains(&set.as_str())
        {
            return Err(format!("{upath}: {what}: unknown R9 set {set:?}"));
        }
        if u.identity.is_empty() {
            return Err(format!("{upath}: {what}: no identity fields"));
        }
        let mut unknowns = Vec::new();
        for r in u.unknowns {
            let reason = UnknownReason::parse(&r).ok_or_else(|| {
                format!("{upath}: {what}: unknown reason {r:?} is not in the KTD3 enum")
            })?;
            unknowns.push(reason);
        }
        universes.push(Universe {
            id: u.id,
            platform: u.platform,
            set: u.set,
            source: u.source,
            absent: u.absent,
            min_members: u.min_members,
            masked: u.masked,
            identity: u.identity,
            display: u.display,
            unknowns,
        });
    }

    let mut attribute_sources = Vec::new();
    for a in ru.attribute_source {
        let what = format!("attribute source {}", a.id);
        check_platform(upath, &what, &a.platform)?;
        if a.id.is_empty() {
            return Err(format!("{upath}: attribute source with an empty id"));
        }
        attribute_sources.push(AttributeSource {
            id: a.id,
            platform: a.platform,
            source: a.source,
        });
    }

    // R24: an entry names a universe or attribute source declared for a
    // different platform.
    let mut not_applicable = Vec::new();
    for n in ru.not_applicable {
        let what = format!("not-applicable entry {}", n.id);
        check_platform(upath, &what, &n.platform)?;
        let other_platform = universes
            .iter()
            .find(|u| u.id == n.id)
            .map(|u| u.platform.as_str())
            .or_else(|| {
                attribute_sources
                    .iter()
                    .find(|a| a.id == n.id)
                    .map(|a| a.platform.as_str())
            });
        match other_platform {
            None => {
                return Err(format!(
                    "{upath}: {what}: no universe or attribute source with this id"
                ));
            }
            Some(p) if p == n.platform => {
                return Err(format!(
                    "{upath}: {what}: the source is declared for {p}, the same platform"
                ));
            }
            _ => {}
        }
        if let Some(set) = &n.set
            && !R9_SETS.contains(&set.as_str())
        {
            return Err(format!("{upath}: {what}: unknown R9 set {set:?}"));
        }
        not_applicable.push(NotApplicable {
            id: n.id,
            platform: n.platform,
            set: n.set,
        });
    }

    // Rules.
    let rpath = "data/probe/rules.toml";
    let universe_ids: BTreeSet<&str> = universes.iter().map(|u| u.id.as_str()).collect();
    let mut rules = Vec::new();
    for r in rr.rule {
        let what = format!("rule {}", r.id);
        if r.id.is_empty() {
            return Err(format!("{rpath}: rule with an empty id"));
        }
        if r.universes.is_empty() {
            return Err(format!("{rpath}: {what}: no universes"));
        }
        for u in &r.universes {
            if !universe_ids.contains(u.as_str()) {
                return Err(format!("{rpath}: {what}: unknown universe {u:?}"));
            }
        }
        let class = RuleClass::parse(&r.class)
            .ok_or_else(|| format!("{rpath}: {what}: unknown class {:?}", r.class))?;
        match (class, nonempty(&r.kind), nonempty(&r.justification)) {
            (RuleClass::Inert, k, j) => {
                if k.is_some() {
                    return Err(format!("{rpath}: {what}: an inert rule takes no kind"));
                }
                if j.is_none() {
                    return Err(format!(
                        "{rpath}: {what}: an inert rule needs a justification"
                    ));
                }
            }
            (_, k, j) => {
                if k.is_none() {
                    return Err(format!(
                        "{rpath}: {what}: an escape or egress rule needs a kind"
                    ));
                }
                if j.is_some() {
                    return Err(format!(
                        "{rpath}: {what}: an escape or egress rule takes no justification"
                    ));
                }
            }
        }
        let mut clauses = Vec::new();
        if let Some(m) = r.r#match {
            clauses.push(build_clause(rpath, &what, m)?);
        }
        for c in r.any {
            clauses.push(build_clause(rpath, &format!("{what}: any"), c)?);
        }
        if clauses.is_empty() {
            return Err(format!("{rpath}: {what}: no match clause"));
        }
        let except = r
            .except
            .map(|c| build_clause(rpath, &format!("{what}: except"), c))
            .transpose()?;
        // `member-of` references resolve against the universe table.
        for clause in clauses.iter().chain(except.iter()) {
            for pred in clause.values() {
                if let Some(u) = &pred.member_of
                    && !universe_ids.contains(u.as_str())
                {
                    return Err(format!(
                        "{rpath}: {what}: member-of names unknown universe {u:?}"
                    ));
                }
            }
        }
        if class == RuleClass::Inert && r.default_route_kind.is_some() {
            return Err(format!(
                "{rpath}: {what}: an inert rule takes no default-route-kind"
            ));
        }
        rules.push(Rule {
            id: r.id,
            universes: r.universes,
            clauses,
            except,
            class,
            kind: nonempty(&r.kind).map(str::to_string),
            default_route_kind: nonempty(&r.default_route_kind).map(str::to_string),
            justification: nonempty(&r.justification).map(str::to_string),
            fixture: nonempty(&r.fixture)
                .ok_or_else(|| format!("{rpath}: {what}: missing fixture"))?
                .to_string(),
        });
    }

    // Signals.
    let spath = "data/probe/signals.toml";
    let mut signals = Vec::new();
    for s in rs.signal {
        let what = format!("signal {}", s.id);
        if s.id.is_empty() {
            return Err(format!("{spath}: signal with an empty id"));
        }
        let platform = match s.platform.as_str() {
            "linux" => SignalPlatform::Linux,
            "macos" => SignalPlatform::Macos,
            "both" => SignalPlatform::Both,
            other => {
                return Err(format!("{spath}: {what}: unknown platform {other:?}"));
            }
        };
        let kind = SignalKind::parse(&s.kind)
            .ok_or_else(|| format!("{spath}: {what}: unknown kind {:?}", s.kind))?;
        for p in s.paths.iter().chain(s.dir.iter()) {
            check_fs_path(spath, &what, p)?;
        }
        let route = s
            .route
            .map(|r| {
                let class = RuleClass::parse(&r.class)
                    .ok_or_else(|| format!("{spath}: {what}: unknown route class {:?}", r.class))?;
                if class == RuleClass::Inert {
                    return Err(format!("{spath}: {what}: a route is never inert"));
                }
                if r.kind.trim().is_empty() {
                    return Err(format!("{spath}: {what}: empty route kind"));
                }
                Ok(SignalRoute {
                    class,
                    kind: r.kind,
                })
            })
            .transpose()?;
        let tamper = s
            .tamper
            .map(|t| {
                let strength =
                    crate::model::TamperStrength::parse(&t.strength).ok_or_else(|| {
                        format!("{spath}: {what}: unknown tamper strength {:?}", t.strength)
                    })?;
                if t.indicator.trim().is_empty() {
                    return Err(format!("{spath}: {what}: empty tamper indicator"));
                }
                Ok(SignalTamper {
                    indicator: t.indicator,
                    strength,
                })
            })
            .transpose()?;
        if route.is_some() && tamper.is_some() {
            return Err(format!(
                "{spath}: {what}: a signal takes `route` or `tamper`, never both"
            ));
        }
        let mut any = Vec::new();
        for c in s.any {
            any.push(build_condition(spath, &format!("{what}: any"), c)?);
        }
        let mut all = Vec::new();
        for c in s.all {
            all.push(build_condition(spath, &format!("{what}: all"), c)?);
        }
        // Kind-specific payloads.
        match kind {
            SignalKind::PathMarker => {
                if s.paths.is_empty() && s.dir.is_none() {
                    return Err(format!(
                        "{spath}: {what}: a path-marker needs paths or a dir"
                    ));
                }
            }
            SignalKind::CredentialPath => {
                if s.paths.is_empty() {
                    return Err(format!("{spath}: {what}: a credential-path needs paths"));
                }
            }
            SignalKind::CredentialDir => {
                if s.dir.is_none() {
                    return Err(format!("{spath}: {what}: a credential-dir needs a dir"));
                }
            }
            SignalKind::DmiValue => {
                if s.values.is_empty() {
                    return Err(format!("{spath}: {what}: a dmi-value needs values"));
                }
            }
            SignalKind::SysctlValue => {
                if s.paths.is_empty() || s.attributes.is_empty() {
                    return Err(format!(
                        "{spath}: {what}: a sysctl-value needs paths and attributes"
                    ));
                }
            }
            SignalKind::Derived => {
                if any.is_empty()
                    && all.is_empty()
                    && s.names.is_empty()
                    && s.name_prefixes.is_empty()
                {
                    return Err(format!(
                        "{spath}: {what}: a derived signal has nothing to match"
                    ));
                }
            }
            SignalKind::Integrity => {
                if !s.paths.is_empty()
                    || s.dir.is_some()
                    || !s.names.is_empty()
                    || !s.name_prefixes.is_empty()
                    || !s.values.is_empty()
                    || !any.is_empty()
                    || !all.is_empty()
                {
                    return Err(format!(
                        "{spath}: {what}: an integrity signal declares only a tamper"
                    ));
                }
                if tamper.is_none() {
                    return Err(format!(
                        "{spath}: {what}: an integrity signal needs a tamper"
                    ));
                }
            }
        }
        if s.name_contains.is_some() && s.dir.is_none() {
            return Err(format!("{spath}: {what}: name-contains needs a dir"));
        }
        if (s.entry_prefix.is_some() || s.entry_exclude_suffix.is_some())
            && kind != SignalKind::CredentialDir
        {
            return Err(format!(
                "{spath}: {what}: entry filters belong to credential-dir"
            ));
        }
        let values: Vec<DmiValue> = s
            .values
            .into_iter()
            .map(|v| {
                if v.path.is_empty() || (v.equals.is_none() && v.prefix.is_none()) {
                    Err(format!(
                        "{spath}: {what}: a dmi value needs a path and an equals or prefix"
                    ))
                } else {
                    Ok(DmiValue {
                        path: v.path,
                        group: v.group,
                        equals: v.equals,
                        prefix: v.prefix,
                    })
                }
            })
            .collect::<Result<_, _>>()?;
        signals.push(Signal {
            id: s.id,
            platform,
            kind,
            paths: s.paths,
            dir: s.dir,
            name_contains: s.name_contains,
            entry_prefix: s.entry_prefix,
            entry_exclude_suffix: s.entry_exclude_suffix,
            names: s.names,
            name_prefixes: s.name_prefixes,
            values,
            attributes: s.attributes,
            after_layers: s.after_layers,
            any,
            all,
            route,
            tamper,
            fixture: nonempty(&s.fixture)
                .ok_or_else(|| format!("{spath}: {what}: missing fixture"))?
                .to_string(),
        });
    }

    // A signal that references a detected layer must run after layers.
    for s in &signals {
        if !s.after_layers
            && s.any
                .iter()
                .chain(s.all.iter())
                .any(|c| !c.layer_family.is_empty())
        {
            return Err(format!(
                "{spath}: signal {}: a condition on a detected layer needs after-layers",
                s.id
            ));
        }
    }

    // Condition references must name declared signals.
    for s in &signals {
        for c in s.any.iter().chain(s.all.iter()) {
            for sig in &c.signal {
                if !signals.iter().any(|x| &x.id == sig) {
                    return Err(format!(
                        "{spath}: signal {}: condition names unknown signal {sig:?}",
                        s.id
                    ));
                }
            }
        }
    }

    // Layers.
    let lpath = "data/probe/layers.toml";
    let mut layers = Vec::new();
    for l in rl.layer {
        let what = format!("layer {}", l.kind);
        let rank = family_rank(&l.family)
            .ok_or_else(|| format!("{lpath}: {what}: unknown family {:?}", l.family))?;
        if l.rank != rank {
            return Err(format!(
                "{lpath}: {what}: rank {} disagrees with the family rank {rank} (KTD16)",
                l.rank
            ));
        }
        if l.kind.is_empty() {
            return Err(format!("{lpath}: layer with an empty kind"));
        }
        let mut any = Vec::new();
        for c in l.any {
            any.push(build_condition(lpath, &format!("{what}: any"), c)?);
        }
        let mut all = Vec::new();
        for c in l.all {
            all.push(build_condition(lpath, &format!("{what}: all"), c)?);
        }
        if any.is_empty() && all.is_empty() {
            return Err(format!("{lpath}: {what}: no conditions"));
        }
        for c in any.iter().chain(all.iter()) {
            for sig in &c.signal {
                if !signals.iter().any(|x| &x.id == sig) {
                    return Err(format!(
                        "{lpath}: {what}: condition names unknown signal {sig:?}"
                    ));
                }
            }
            if c.evidence.is_none() {
                return Err(format!(
                    "{lpath}: {what}: a layer condition needs an evidence class"
                ));
            }
        }
        layers.push(Layer {
            family: l.family,
            kind: l.kind,
            rank: l.rank,
            no_other_in_family: l.no_other_in_family,
            any,
            all,
            fixture: nonempty(&l.fixture)
                .ok_or_else(|| format!("{lpath}: {what}: missing fixture"))?
                .to_string(),
        });
    }

    // Not-observable list.
    let npath = "data/probe/not-observable.toml";
    let mut not_observable = Vec::new();
    for n in rn.source {
        let what = format!("not-observable {}", n.id);
        check_platform(npath, &what, &n.platform)?;
        if n.id.is_empty() || n.statement.trim().is_empty() || n.reason.trim().is_empty() {
            return Err(format!(
                "{npath}: {what}: id, statement, and reason are required"
            ));
        }
        not_observable.push(NotObservable {
            id: n.id,
            platform: n.platform,
            statement: n.statement,
            reason: n.reason,
        });
    }

    // Ids are unique within each collection, and a rule or signal id never
    // equals a universe, attribute-source, or not-observable id. One
    // exception: a rule and a signal may share an id when they describe
    // the same check at two levels (a path-marker signal probing fixed
    // paths and a rule matching members at those paths, as with
    // `linux.socket.host-ipc`); the share is allowed only when the route
    // class and kind agree, so the shared id denotes one thing.
    let mut seen = BTreeSet::new();
    for (what, id) in universes
        .iter()
        .map(|u| ("universe", u.id.as_str()))
        .chain(
            attribute_sources
                .iter()
                .map(|a| ("attribute source", a.id.as_str())),
        )
        .chain(rules.iter().map(|r| ("rule", r.id.as_str())))
        .chain(signals.iter().map(|s| ("signal", s.id.as_str())))
        .chain(
            not_observable
                .iter()
                .map(|n| ("not-observable", n.id.as_str())),
        )
    {
        if !seen.insert((what, id)) {
            return Err(format!("data/probe: duplicate {what} id {id:?}"));
        }
    }
    for (what, id) in rules
        .iter()
        .map(|r| ("rule", r.id.as_str()))
        .chain(signals.iter().map(|s| ("signal", s.id.as_str())))
        .chain(
            not_observable
                .iter()
                .map(|n| ("not-observable", n.id.as_str())),
        )
    {
        if universes.iter().any(|u| u.id == id) || attribute_sources.iter().any(|a| a.id == id) {
            return Err(format!(
                "data/probe: {what} id {id:?} names a declared source"
            ));
        }
    }
    for n in &not_observable {
        if rules.iter().any(|r| r.id == n.id) || signals.iter().any(|s| s.id == n.id) {
            return Err(format!(
                "data/probe: not-observable id {:?} names a rule or signal",
                n.id
            ));
        }
    }
    for r in &rules {
        if let Some(s) = signals.iter().find(|s| s.id == r.id) {
            let route = s.route.as_ref().ok_or_else(|| {
                format!(
                    "data/probe: rule {} shares an id with a signal that produces no route",
                    r.id
                )
            })?;
            if route.class != r.class || route.kind != r.kind.as_deref().unwrap_or("") {
                return Err(format!(
                    "data/probe: rule {} and signal {} share an id but disagree on class or kind",
                    r.id, s.id
                ));
            }
        }
    }

    // Filesystems.
    let fpath = "data/probe/filesystems.toml";
    let filesystems = Filesystems {
        linux: build_fs_set(fpath, "linux", rf.linux)?,
        macos: build_fs_set(fpath, "macos", rf.macos)?,
    };

    let budgets = Budgets {
        members_per_universe: rb.members_per_universe,
        bytes_per_file: rb.bytes_per_file,
        entries_per_listing: rb.entries_per_listing,
        dev_listing_depth: rb.dev_listing_depth,
        bytes_per_member_string: rb.bytes_per_member_string,
        report_bytes: rb.report_bytes,
        active_targets: rb.active_targets,
        connect_timeout_ms: rb.connect_timeout_ms,
        run_deadline_ms: rb.run_deadline_ms,
    };

    // Active-mode refused list.
    let apath = "data/probe/active.toml";
    let mut active = Vec::new();
    for r in ra.refused {
        let what = format!("refused {}", r.value);
        let result = match r.result.as_str() {
            "refused-metadata-address" => RefusedResult::MetadataAddress,
            "refused-special-address" => RefusedResult::SpecialAddress,
            other => {
                return Err(format!("{apath}: {what}: unknown result {other:?}"));
            }
        };
        if parse_addr_or_prefix(&r.value).is_none() {
            return Err(format!(
                "{apath}: {what}: not an IP literal or addr/prefix range"
            ));
        }
        if r.reason.trim().is_empty() {
            return Err(format!("{apath}: {what}: missing reason"));
        }
        active.push(Refused {
            value: r.value,
            result,
            reason: r.reason,
        });
    }

    Ok(Data {
        data_digest: data_digest(files),
        universes,
        attribute_sources,
        not_applicable,
        rules,
        signals,
        layers,
        not_observable,
        filesystems,
        budgets,
        active,
    })
}

fn build_fs_set(
    path: &str,
    platform: &str,
    raw: RawFilesystemSet,
) -> Result<FilesystemSet, String> {
    let mut magic = BTreeMap::new();
    for (dir, hex) in raw.magic {
        let v = u64::from_str_radix(hex.trim_start_matches("0x"), 16).map_err(|e| {
            format!("{path}: {platform} magic for {dir}: not a hex value {hex:?}: {e}")
        })?;
        magic.insert(dir, v);
    }
    Ok(FilesystemSet {
        no_touch: raw.no_touch,
        no_touch_prefixes: raw.no_touch_prefixes,
        magic,
    })
}

/// Parses `169.254.0.0/16`-style ranges and bare IP literals.
fn parse_addr_or_prefix(value: &str) -> Option<()> {
    use std::net::IpAddr;
    use std::str::FromStr;
    match value.split_once('/') {
        None => IpAddr::from_str(value).ok().map(|_| ()),
        Some((addr, prefix)) => {
            let ip = IpAddr::from_str(addr).ok()?;
            let bits: u32 = prefix.parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            (bits <= max).then_some(())
        }
    }
}

// ---------------------------------------------------------------------------
// Data guards. Each returns the list of violations; empty means pass.
// ---------------------------------------------------------------------------

pub mod guards {
    use super::*;
    use egress_core::data::guards::Deferred;
    use std::path::Path;

    /// Every platform declares each R9 finite set, either as a universe or
    /// as a not-applicable entry covering the set (R9, R24).
    pub fn roster(data: &Data) -> Vec<String> {
        let mut out = Vec::new();
        for platform in PLATFORMS {
            for set in R9_SETS {
                let covered = data
                    .universes
                    .iter()
                    .any(|u| u.platform == platform && u.set.as_deref() == Some(set))
                    || data
                        .not_applicable
                        .iter()
                        .any(|n| n.platform == platform && n.set.as_deref() == Some(set));
                if !covered {
                    out.push(format!(
                        "{platform}: R9 set {set} is neither a universe nor not applicable"
                    ));
                }
            }
        }
        out
    }

    /// The labels one fixture case carries, for the fixture guard.
    #[derive(Debug, Default)]
    struct CaseLabels {
        route_rules: BTreeSet<String>,
        route_signals: BTreeSet<String>,
        inert_rules: BTreeSet<String>,
        /// `(family, kind)` pairs of `[[layers]]` entries.
        layer_kinds: BTreeSet<(String, String)>,
        tamper_indicators: BTreeSet<String>,
        attribute_names: BTreeSet<String>,
        unknown_sources: BTreeSet<String>,
    }

    fn case_exists(corpus_root: &Path, case: &str) -> bool {
        let d = corpus_root.join(case);
        d.join("tree").is_dir()
            && d.join("facts.toml").is_file()
            && d.join("expected.toml").is_file()
    }

    fn case_labels(corpus_root: &Path, case: &str) -> Result<CaseLabels, String> {
        let text = std::fs::read_to_string(corpus_root.join(case).join("expected.toml"))
            .map_err(|e| format!("{case}: cannot read expected.toml: {e}"))?;
        let v: toml::Table =
            toml::from_str(&text).map_err(|e| format!("{case}: malformed expected.toml: {e}"))?;
        let mut labels = CaseLabels::default();
        let collect = |labels: &mut BTreeSet<String>, table: &str, key: &str| {
            if let Some(arr) = v.get(table).and_then(|t| t.as_array()) {
                for entry in arr {
                    if let Some(s) = entry.get(key).and_then(|k| k.as_str()) {
                        labels.insert(s.to_string());
                    }
                }
            }
        };
        collect(&mut labels.route_rules, "routes", "rule");
        collect(&mut labels.route_signals, "routes", "signal");
        collect(&mut labels.inert_rules, "inert", "rule");
        collect(&mut labels.tamper_indicators, "tamper", "indicator");
        collect(&mut labels.attribute_names, "attributes", "name");
        collect(&mut labels.unknown_sources, "unknowns", "source");
        if let Some(arr) = v.get("layers").and_then(|t| t.as_array()) {
            for entry in arr {
                let family = entry.get("family").and_then(|f| f.as_str());
                let kind = entry.get("kind").and_then(|k| k.as_str());
                if let (Some(f), Some(k)) = (family, kind) {
                    labels.layer_kinds.insert((f.to_string(), k.to_string()));
                }
            }
        }
        Ok(labels)
    }

    /// The `(family, kind)` layer kinds whose conditions reference
    /// `signal` — a fixture that labels such a layer labels the signal
    /// through layer evidence.
    fn evidence_kinds<'a>(data: &'a Data, signal: &str) -> BTreeSet<(&'a str, &'a str)> {
        data.layers
            .iter()
            .filter(|l| {
                l.any
                    .iter()
                    .chain(l.all.iter())
                    .any(|c| c.signal.iter().any(|s| s == signal))
            })
            .map(|l| (l.family.as_str(), l.kind.as_str()))
            .collect()
    }

    /// Whether `labels` label signal `s` in case `fixture`. An unknown
    /// naming the signal counts only for a `<home>` signal on macOS
    /// (KTD15: home-relative signals are always `no-account-home` there);
    /// everywhere else an unknown label proves nothing about the signal.
    fn signal_labeled(data: &Data, s: &Signal, labels: &CaseLabels, fixture: &str) -> bool {
        // A route may name the signal through `signal`, or through `rule`
        // when the producing entry is a derived signal (the corpus labels
        // linux.privileged that way); ids are unique across rules and
        // signals, so the reference is unambiguous.
        if labels.route_signals.contains(&s.id) || labels.route_rules.contains(&s.id) {
            return true;
        }
        if evidence_kinds(data, &s.id).iter().any(|k| {
            labels
                .layer_kinds
                .contains(&(k.0.to_string(), k.1.to_string()))
        }) {
            return true;
        }
        if let Some(t) = &s.tamper
            && labels.tamper_indicators.contains(&t.indicator)
        {
            return true;
        }
        if s.attributes
            .iter()
            .any(|a| labels.attribute_names.contains(a))
        {
            return true;
        }
        let macos_home_unknown = fixture.starts_with("macos/")
            && s.home_relative()
            && matches!(s.platform, SignalPlatform::Macos | SignalPlatform::Both);
        if macos_home_unknown && labels.unknown_sources.contains(&s.id) {
            return true;
        }
        false
    }

    fn check(
        out: &mut Vec<String>,
        corpus_root: &Path,
        deferred: &Deferred,
        what: &str,
        fixture: &str,
        labeled: impl FnOnce(&CaseLabels) -> bool,
        missing_label: &str,
    ) {
        if deferred.cases.contains(fixture) {
            return;
        }
        if !case_exists(corpus_root, fixture) {
            out.push(format!(
                "{what}: fixture {fixture} does not exist and is not listed in deferred.toml"
            ));
            return;
        }
        match case_labels(corpus_root, fixture) {
            Ok(labels) => {
                if !labeled(&labels) {
                    out.push(format!("{what}: fixture {fixture} {missing_label}"));
                }
            }
            Err(e) => out.push(format!("{what}: {e}")),
        }
    }

    /// Every rule, signal, and layer names a fixture case that exists and
    /// labels it, or a case in `fixtures/probe/deferred.toml`: a route
    /// with the rule id for escape and egress rules, an `[[inert]]` label
    /// for inert rules, a labeled layer kind for layers, and for signals
    /// a route, layer evidence, a tamper entry, an `[[attributes]]` label
    /// naming a produced attribute, or (macOS `<home>` signals only) an
    /// unknown naming the signal.
    pub fn fixtures(data: &Data, corpus_root: &Path, deferred: &Deferred) -> Vec<String> {
        let mut out = Vec::new();
        for r in &data.rules {
            let what = format!("rule {}", r.id);
            let id = r.id.clone();
            match r.class {
                RuleClass::Escape | RuleClass::Egress => check(
                    &mut out,
                    corpus_root,
                    deferred,
                    &what,
                    &r.fixture,
                    move |l| l.route_rules.contains(&id),
                    "labels no route with this rule id",
                ),
                RuleClass::Inert => check(
                    &mut out,
                    corpus_root,
                    deferred,
                    &what,
                    &r.fixture,
                    move |l| l.inert_rules.contains(&id),
                    "labels no [[inert]] entry with this rule id",
                ),
            }
        }
        for s in &data.signals {
            let what = format!("signal {}", s.id);
            check(
                &mut out,
                corpus_root,
                deferred,
                &what,
                &s.fixture,
                |l| signal_labeled(data, s, l, &s.fixture),
                "labels no route, layer evidence, tamper entry, or produced attribute for this signal",
            );
        }
        for layer in &data.layers {
            let what = format!("layer {}", layer.kind);
            let key = (layer.family.clone(), layer.kind.clone());
            check(
                &mut out,
                corpus_root,
                deferred,
                &what,
                &layer.fixture,
                move |l| l.layer_kinds.contains(&key),
                "labels no layer of this family and kind",
            );
        }
        out
    }

    /// Deferred ledger entries no data entry references, or whose case now
    /// exists on disk and must leave the ledger.
    pub fn stale_deferred(data: &Data, corpus_root: &Path, deferred: &Deferred) -> Vec<String> {
        let referenced: BTreeSet<&str> = data
            .rules
            .iter()
            .map(|r| r.fixture.as_str())
            .chain(data.signals.iter().map(|s| s.fixture.as_str()))
            .chain(data.layers.iter().map(|l| l.fixture.as_str()))
            .collect();
        let mut out = Vec::new();
        for d in &deferred.cases {
            if !referenced.contains(d.as_str()) {
                out.push(format!(
                    "{d}: deferred.toml names a case no data entry uses; remove it"
                ));
            }
            if corpus_root.join(d).exists() {
                out.push(format!(
                    "{d}: deferred case now exists; remove it from deferred.toml"
                ));
            }
        }
        out
    }
}

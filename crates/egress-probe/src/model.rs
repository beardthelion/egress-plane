//! The probe report model.
//!
//! One finalized report renders as deterministic JSON against
//! `schema/egress-probe.v1.json` and as an escaped text report. The model
//! holds environment-derived bytes raw: redaction (KTD14) and the
//! control-character check (KTD27) run in [`crate::identity::finalize`],
//! never at enumeration time, so a secret or a hostile string is scrubbed
//! before identity and before output.
//!
//! Collections are sorted by identity components before output; universes
//! keep their declared order.

use std::collections::BTreeMap;

pub use egress_core::model::CompletenessState;

use crate::facts::Platform;

/// Version of the probe JSON report format (KTD1).
pub const SCHEMA_VERSION: u32 = 1;

/// The `kind` value, so a later join can tell the two reports apart (R22).
pub const KIND: &str = "environment-probe";

/// The fixed layer-order convention (KTD16): a fixed family rank, never a
/// measurement.
pub const LAYER_ORDER_BASIS: &str = "family-rank";

/// The rendered-report byte cap (KTD18): 64 MiB.
pub const REPORT_BUDGET_BYTES: u64 = 64 * 1024 * 1024;

/// The KTD23 caveat every report carries.
pub const SELF_REPORTED_CAVEAT: &str = "self-reported-context";

/// The KTD15 caveat every Linux report carries.
pub const HOME_CAVEAT: &str = "home-from-account-database";

/// Whether the report describes a live run or a corpus replay. The field
/// is informational; it never gates behavior (KTD23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    Live,
    Snapshot,
}

impl Source {
    pub const ALL: [Source; 2] = [Self::Live, Self::Snapshot];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Snapshot => "snapshot",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// The run mode: passive sends nothing, active adds bounded checks (R3, R4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    Passive,
    Active,
}

impl Mode {
    pub const ALL: [Mode; 2] = [Self::Passive, Self::Active];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// The numeric identity the probe ran under; names are never resolved
/// (KTD15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Privilege {
    pub euid: u32,
    pub egid: u32,
}

impl Privilege {
    pub fn root(self) -> bool {
        self.euid == 0
    }
}

/// The tool block shared with the code layer's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub version: String,
    /// `sha256:<hex>` over the probe data files only (KTD19).
    pub data_digest: String,
}

/// The closed unknown-reason vocabulary (KTD3). Reasons never carry input
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnknownReason {
    ProcNotMounted,
    Unreadable,
    Partial,
    ImplausiblyEmpty,
    MaskedOrTruncated,
    BudgetExceeded,
    LinkPolicy,
    InternalFailure,
    DependsOnUnknown,
    UnsupportedLayout,
    NoAccountHome,
    FsTypeMismatch,
    ProcSelfMismatch,
    NetworkFilesystemNotTouched,
    DescriptorLimit,
    Traced,
}

impl UnknownReason {
    pub const ALL: [UnknownReason; 16] = [
        Self::ProcNotMounted,
        Self::Unreadable,
        Self::Partial,
        Self::ImplausiblyEmpty,
        Self::MaskedOrTruncated,
        Self::BudgetExceeded,
        Self::LinkPolicy,
        Self::InternalFailure,
        Self::DependsOnUnknown,
        Self::UnsupportedLayout,
        Self::NoAccountHome,
        Self::FsTypeMismatch,
        Self::ProcSelfMismatch,
        Self::NetworkFilesystemNotTouched,
        Self::DescriptorLimit,
        Self::Traced,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcNotMounted => "proc-not-mounted",
            Self::Unreadable => "unreadable",
            Self::Partial => "partial",
            Self::ImplausiblyEmpty => "implausibly-empty",
            Self::MaskedOrTruncated => "masked-or-truncated",
            Self::BudgetExceeded => "budget-exceeded",
            Self::LinkPolicy => "link-policy",
            Self::InternalFailure => "internal-failure",
            Self::DependsOnUnknown => "depends-on-unknown",
            Self::UnsupportedLayout => "unsupported-layout",
            Self::NoAccountHome => "no-account-home",
            Self::FsTypeMismatch => "fs-type-mismatch",
            Self::ProcSelfMismatch => "proc-self-mismatch",
            Self::NetworkFilesystemNotTouched => "network-filesystem-not-touched",
            Self::DescriptorLimit => "descriptor-limit",
            Self::Traced => "traced",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// The classification of one member after rule matching (KTD6):
/// escape over egress over inert; unclassified when no rule matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemberClass {
    Escape,
    Egress,
    Inert,
    Unclassified,
}

impl MemberClass {
    pub const ALL: [MemberClass; 4] = [Self::Escape, Self::Egress, Self::Inert, Self::Unclassified];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Escape => "escape",
            Self::Egress => "egress",
            Self::Inert => "inert",
            Self::Unclassified => "unclassified",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A member field value. `Text` holds raw environment bytes that pass
/// through redaction and the KTD27 encoder; `Int` and `Bool` are numbers
/// and flags such as ports, modes, and owners.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberValue {
    Text(Vec<u8>),
    Int(u64),
    Bool(bool),
}

impl MemberValue {
    /// The canonical bytes this value contributes to identity keys, to
    /// identity-component sorting, and to [`MemberRef`] matching.
    pub fn key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Text(b) => b.clone(),
            Self::Int(n) => n.to_string().into_bytes(),
            Self::Bool(b) => (if *b { "true" } else { "false" }).as_bytes().to_vec(),
        }
    }

    /// The sort weight inside a display-order key: `Int` compares
    /// numerically, `Bool` false before true, `Text` byte-wise.
    fn display_order(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Int(n) => (1, n.to_be_bytes().to_vec()),
            Self::Bool(b) => (2, vec![u8::from(*b)]),
            Self::Text(b) => (0, b.clone()),
        }
    }
}

/// One named field of a member, in the universe's declared field order.
/// `identity` marks a KTD5 identity component; display-only fields
/// (ports, pids, descriptor numbers, inodes, device numbers, mount ids,
/// counters) never enter identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberField {
    pub name: String,
    pub value: MemberValue,
    pub identity: bool,
}

/// One enumerated member of a universe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Filled by `finalize`; empty before.
    pub id: String,
    /// Fields in declared order, identity and display-only mixed.
    pub fields: Vec<MemberField>,
    /// The rendered member description; escaped at output.
    pub display: String,
    pub class: MemberClass,
    /// Every rule id that matched, in any order before `finalize`.
    pub rules: Vec<String>,
    /// Filled by `finalize`: the member's rank among identical siblings in
    /// sorted display order (KTD5).
    pub ordinal: u32,
}

impl Member {
    /// The identity components in declared order: each identity field's
    /// name and canonical value bytes (KTD5).
    pub fn identity_components(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for f in &self.fields {
            if f.identity {
                out.push(f.name.as_bytes().to_vec());
                out.push(f.value.key_bytes());
            }
        }
        out
    }

    /// The display-order key for identical siblings: the display-only
    /// field values in declared order, then the display string.
    pub(crate) fn display_order_key(&self) -> Vec<(u8, Vec<u8>)> {
        let mut out: Vec<(u8, Vec<u8>)> = self
            .fields
            .iter()
            .filter(|f| !f.identity)
            .map(|f| f.value.display_order())
            .collect();
        out.push((0, self.display.as_bytes().to_vec()));
        out
    }
}

/// The per-source state of one universe (the state decision of KTD3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UniverseState {
    /// Read and fully parsed; `members` may still be empty.
    Enumerated,
    /// The declared absent signature matched: complete, zero members.
    Absent,
    /// Could not be read or enumerated; the run is incomplete.
    Unknown(UnknownReason),
    /// Not declared on this platform (R24).
    NotApplicable,
}

impl UniverseState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enumerated => "enumerated",
            Self::Absent => "absent",
            Self::Unknown(_) => "unknown",
            Self::NotApplicable => "not-applicable",
        }
    }

    /// The unknown reason, when the state is `Unknown`.
    pub fn reason(&self) -> Option<UnknownReason> {
        match self {
            Self::Unknown(r) => Some(*r),
            _ => None,
        }
    }
}

/// One declared universe and its per-source state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Universe {
    /// The declared universe id, for example `linux.mounts`.
    pub id: String,
    pub state: UniverseState,
    pub members: Vec<Member>,
}

/// A route's pointer to the member it describes, carried as the member's
/// identity components so `finalize` can bind it to the member id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRef {
    pub universe: String,
    /// The member's identity components; redacted in `finalize` exactly as
    /// the member's own fields are, so binding survives redaction.
    pub components: Vec<Vec<u8>>,
    /// The member id this reference resolved to; filled by `finalize`,
    /// `None` when no member carries these components.
    pub resolved: Option<String>,
}

impl MemberRef {
    /// The reference pointing at `member` in `universe`.
    pub fn of(universe: &str, member: &Member) -> MemberRef {
        MemberRef {
            universe: universe.to_string(),
            components: member.identity_components(),
            resolved: None,
        }
    }
}

/// One egress or escape route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Filled by `finalize`.
    pub id: String,
    /// The route kind from the rule or signal data, for example
    /// `runtime-socket` or `writable-host-mount`.
    pub kind: String,
    /// The matching rule id, when the route comes from a member rule.
    pub rule: Option<String>,
    /// The producing signal id, when the route comes from a signal.
    pub signal: Option<String>,
    /// The member the route describes, resolved to its id in `finalize`.
    pub member: Option<MemberRef>,
    /// A fixed-path location for signal routes; KTD27-encoded at output.
    pub location: Option<Vec<u8>>,
    /// Always false in passive mode (R3).
    pub verified: bool,
    /// The rendered route description; escaped at output.
    pub display: String,
}

/// One explicit unknown: a source the probe could not read or enumerate
/// (R13). `source` is the universe, signal, or attribute-source id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    /// Filled by `finalize`.
    pub id: String,
    pub source: String,
    pub reason: UnknownReason,
}

/// Tamper-indicator strength (R29): strong makes the run incomplete,
/// weak is listed only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TamperStrength {
    Strong,
    Weak,
}

impl TamperStrength {
    pub const ALL: [TamperStrength; 2] = [Self::Strong, Self::Weak];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Weak => "weak",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// One tamper indicator (KTD25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TamperIndicator {
    /// Filled by `finalize`.
    pub id: String,
    /// The declared indicator id, for example `traced` or `loader-env`.
    pub indicator: String,
    pub strength: TamperStrength,
    /// The rendered description; escaped at output.
    pub display: String,
}

/// One not-observable source (R23): a declared entry no unprivileged
/// process can read, reported every run for the platform and never
/// attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotObservable {
    pub id: String,
    /// What cannot be seen.
    pub statement: String,
    /// Why it cannot be seen.
    pub reason: String,
}

/// The per-source state of one named signal (R11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignalState {
    Present,
    Absent,
    Unknown,
    NotApplicable,
}

impl SignalState {
    pub const ALL: [SignalState; 4] = [
        Self::Present,
        Self::Absent,
        Self::Unknown,
        Self::NotApplicable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not-applicable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// One declared signal and its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    /// Filled by `finalize`; a hash over the declared signal id.
    pub id: String,
    /// The declared signal id, for example `linux.marker.dockerenv`.
    pub signal: String,
    pub state: SignalState,
}

/// One recorded active-mode check (R4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCheck {
    /// Filled by `finalize`.
    pub id: String,
    /// The canonicalized `IP:port` literal.
    pub target: String,
    /// `connected`, `refused`, `timed-out`, `unreachable`, `error:<errno>`,
    /// or a refusal reason from `data/probe/active.toml`.
    pub result: String,
}

/// A layer family in fixed rank order (KTD16): outermost first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LayerFamily {
    Cloud,
    Ci,
    Container,
    Sandbox,
    Host,
}

impl LayerFamily {
    pub const ALL: [LayerFamily; 5] = [
        Self::Cloud,
        Self::Ci,
        Self::Container,
        Self::Sandbox,
        Self::Host,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloud => "cloud",
            Self::Ci => "ci",
            Self::Container => "container",
            Self::Sandbox => "sandbox",
            Self::Host => "host",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// The evidence source classes of KTD16.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceClass {
    Kernel,
    FilesystemMarker,
    EnvironmentName,
    Firmware,
    ResolverConfig,
    NetworkInterface,
}

impl EvidenceClass {
    pub const ALL: [EvidenceClass; 6] = [
        Self::Kernel,
        Self::FilesystemMarker,
        Self::EnvironmentName,
        Self::Firmware,
        Self::ResolverConfig,
        Self::NetworkInterface,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::FilesystemMarker => "filesystem-marker",
            Self::EnvironmentName => "environment-name",
            Self::Firmware => "firmware",
            Self::ResolverConfig => "resolver-config",
            Self::NetworkInterface => "network-interface",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// One piece of evidence for a detected layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub class: EvidenceClass,
    /// What was observed, for example `/.dockerenv` or the env name
    /// `GITHUB_ACTIONS`; presence only, never a value (R17).
    pub detail: String,
}

/// A namespace name with its display-only inode (KTD23): the auditor
/// compares it against `/proc/<agent pid>/ns/*` from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceInode {
    pub name: String,
    /// Display-only; never enters identity (KTD5).
    pub inode: u64,
}

/// A layer attribute value: confinement facts reported as attributes of
/// their layer, with no computed claim (R12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
    /// A list of environment-derived strings, for example cgroup lines.
    Strings(Vec<String>),
    /// The probe's namespace names with display-only inodes (KTD23).
    Namespaces(Vec<NamespaceInode>),
}

/// One detected environment layer, ordered by family rank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// Filled by `finalize`.
    pub id: String,
    pub family: LayerFamily,
    /// The declared kind, for example `docker` or `unrecognized`.
    pub kind: String,
    pub evidence: Vec<Evidence>,
    /// Confinement facts and other attributes (R12); keys sorted.
    pub attributes: BTreeMap<String, AttrValue>,
}

/// A report caveat, always including `self-reported-context` (KTD23) and,
/// on Linux, `home-from-account-database` (KTD15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caveat {
    pub id: String,
    pub text: String,
}

/// One unclassified member lifted into its own section (R14): the
/// universe id, the member id, and its escaped display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unclassified {
    pub universe: String,
    /// The member id assigned by `finalize`.
    pub member: String,
    /// The member display; escaped at output.
    pub display: String,
}

/// A probe report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub source: Source,
    pub platform: Platform,
    pub privilege: Privilege,
    pub mode: Mode,
    /// The optional caller nonce echoed into the report (KTD23).
    pub nonce: Option<String>,
    pub completeness: CompletenessState,
    pub layers: Vec<Layer>,
    pub egress_routes: Vec<Route>,
    pub escape_routes: Vec<Route>,
    pub unknowns: Vec<Unknown>,
    pub tamper_indicators: Vec<TamperIndicator>,
    pub not_observable: Vec<NotObservable>,
    /// Universe, signal, and attribute-source ids that do not exist on
    /// this platform (R24); `finalize` adds not-applicable universes and
    /// signals itself.
    pub not_applicable: Vec<String>,
    /// Unclassified members, derived by `finalize` (R14).
    pub unclassified: Vec<Unclassified>,
    /// Every declared universe in declared order, including absent,
    /// unknown, and not-applicable ones.
    pub universes: Vec<Universe>,
    pub signals: Vec<Signal>,
    pub active_checks: Vec<ActiveCheck>,
    pub caveats: Vec<Caveat>,
}

impl Report {
    /// The process exit code this report maps to (R15).
    pub fn exit_code(&self) -> i32 {
        self.completeness.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_forms_round_trip() {
        for v in Source::ALL {
            assert_eq!(Source::parse(v.as_str()), Some(v));
        }
        for v in Mode::ALL {
            assert_eq!(Mode::parse(v.as_str()), Some(v));
        }
        for v in UnknownReason::ALL {
            assert_eq!(UnknownReason::parse(v.as_str()), Some(v));
        }
        for v in MemberClass::ALL {
            assert_eq!(MemberClass::parse(v.as_str()), Some(v));
        }
        for v in TamperStrength::ALL {
            assert_eq!(TamperStrength::parse(v.as_str()), Some(v));
        }
        for v in SignalState::ALL {
            assert_eq!(SignalState::parse(v.as_str()), Some(v));
        }
        for v in LayerFamily::ALL {
            assert_eq!(LayerFamily::parse(v.as_str()), Some(v));
        }
        for v in EvidenceClass::ALL {
            assert_eq!(EvidenceClass::parse(v.as_str()), Some(v));
        }
    }
}

//! Report model shared by the scanner, the CLI, and the corpus harness.
//!
//! Collections are sorted by identity components before output. `location` is
//! the only position-bearing field.

/// Version of the JSON report format. Bumped only on a removal, rename, or
/// change of meaning.
pub const SCHEMA_VERSION: u32 = 1;

/// Exit code for a tool error. A tool error writes no JSON.
pub const EXIT_TOOL_ERROR: i32 = 1;

/// A complete scan result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub completeness: Completeness,
    pub caveats: Vec<Caveat>,
    pub sites: Vec<Site>,
    pub blind_spots: Vec<BlindSpot>,
    pub unscanned_dependencies: Vec<UnscannedDependency>,
    pub excluded: Vec<Excluded>,
}

impl Report {
    /// The process exit code this report maps to.
    pub fn exit_code(&self) -> i32 {
        self.completeness.state.exit_code()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub version: String,
    /// `sha256:<hex>` over all embedded data files.
    pub data_digest: String,
    pub runtime_range: RuntimeRange,
}

/// Declared supported runtime range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRange {
    pub python: String,
    pub node: String,
    pub rust: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completeness {
    pub state: CompletenessState,
    /// Each exhausted global budget, sorted.
    pub budget_exceeded: Vec<BudgetReason>,
    pub coverage: Coverage,
}

/// Completeness state. A tool error is not a state: it produces no report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompletenessState {
    Complete,
    Incomplete,
    Empty,
}

impl CompletenessState {
    pub const ALL: [CompletenessState; 3] = [Self::Complete, Self::Incomplete, Self::Empty];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Empty => "empty",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// 0 complete, 2 incomplete, 3 empty.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Complete => 0,
            Self::Incomplete => 2,
            Self::Empty => 3,
        }
    }
}

/// Fixed reasons for an exhausted global budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetReason {
    Files,
    Bytes,
    Findings,
    ResolverSteps,
}

impl BudgetReason {
    pub const ALL: [BudgetReason; 4] = [
        Self::Files,
        Self::Bytes,
        Self::Findings,
        Self::ResolverSteps,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Files => "budget-files",
            Self::Bytes => "budget-bytes",
            Self::Findings => "budget-findings",
            Self::ResolverSteps => "budget-resolver-steps",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// Per-language coverage counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    pub python: CoverageCounts,
    pub javascript: CoverageCounts,
    pub rust: CoverageCounts,
    /// Unsupported code file types and files loaded as code.
    pub unsupported: CoverageCounts,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageCounts {
    pub scanned: u64,
    pub skipped: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Language {
    Python,
    Javascript,
    Rust,
}

impl Language {
    pub const ALL: [Language; 3] = [Self::Python, Self::Javascript, Self::Rust];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Javascript => "javascript",
            Self::Rust => "rust",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A fixed caveat entry from `data/caveats.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caveat {
    /// Stable identifier, for example `browser-dom`.
    pub id: String,
    pub text: String,
}

/// 1-based line and column; the column counts Unicode scalar values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub line: u32,
    pub column: u32,
}

/// Bucket of a reported egress site. Unscanned dependencies and inert
/// references never become sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bucket {
    Primitive,
    Catalogued,
}

impl Bucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primitive => "primitive",
            Self::Catalogued => "catalogued",
        }
    }
}

/// Labels from `data/labels.toml` plus `build-hook`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Label {
    Vendored,
    Generated,
    Minified,
    Test,
    BuildHook,
}

impl Label {
    pub const ALL: [Label; 5] = [
        Self::Vendored,
        Self::Generated,
        Self::Minified,
        Self::Test,
        Self::BuildHook,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vendored => "vendored",
            Self::Generated => "generated",
            Self::Minified => "minified",
            Self::Test => "test",
            Self::BuildHook => "build-hook",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// Kind of a resolved or symbolic destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DestinationKind {
    /// A literal URL, host, or `host:port`.
    Literal,
    /// `env:NAME`.
    Env,
    /// `param:N:<function>`.
    Param,
    /// A template with symbolic holes, for example `{env:BASE}/v1`.
    Template,
    /// `exec:<program>`.
    Exec,
    /// `lib:<library>`.
    Lib,
    /// `expr:<rendered source>`.
    Expr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub kind: DestinationKind,
    /// Normalized, redacted value without the kind prefix.
    pub value: String,
    /// Literal default recorded on an environment read.
    pub default: Option<String>,
    /// Rendered form, for example `env:WEBHOOK_URL`. Escaped at
    /// output time.
    pub display: String,
}

/// One egress site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub id: String,
    pub language: Language,
    /// Repo-relative path with `/` separators. For a non-UTF-8 path this is the
    /// display form and `file_bytes` holds the raw bytes as lowercase hex.
    pub file: String,
    pub file_bytes: Option<String>,
    /// Enclosing symbol path; `<module>` at top level.
    pub symbol: String,
    pub bucket: Bucket,
    /// Data entry ID, for example `python:requests.post`.
    pub mechanism: String,
    pub destination: Destination,
    pub ordinal: u32,
    pub labels: Vec<Label>,
    pub location: Option<Location>,
}

/// Fixed blind-spot reasons (parser messages and I/O error text never
/// reach output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlindSpotKind {
    // Whole-file reasons. Each is a coverage gap.
    ParseError,
    UnsupportedFileType,
    LoadedAsCode,
    SymlinkOutsideRoot,
    NotRegularFile,
    UnsafeOpenUnavailable,
    TooLarge,
    Undecodable,
    Unreadable,
    NonUtf8Path,
    TooDeeplyNested,
    FrontendFailure,
    ManifestParseError,
    // Coverage gaps that are not whole-file.
    ReferenceOutsideRoot,
    ReferenceIntoExcluded,
    UnconfirmedExclusion,
    // Construct-level blind spots.
    /// eval, exec, compile, Function, vm, pickle.loads, string timers.
    DynamicCode,
    /// Non-literal specifier to a loader or require-equivalent, or `require`
    /// used as a value.
    DynamicImport,
    /// Computed or reflective access with a non-literal name on a module
    /// binding or the ambient module.
    ReflectiveAccess,
    /// The same access on a receiver of untracked provenance.
    ReflectiveUnknown,
    /// globals(), locals(), vars(), bare `__builtins__` with a non-literal
    /// key, JS `with`, computed `__all__` behind a star import.
    ScopeInjection,
    /// Writes to the import system (sys.path, sys.modules, require.cache,
    /// Module internals) and importlib.reload.
    ImportSystemMutation,
    /// Assignment to a member of an egress-bucket module.
    Monkeypatch,
    /// Python introspection attributes off the inert list, sys._getframe, and
    /// JS `.constructor` chains on a non-class receiver.
    Introspection,
    /// FFI and raw native code (extern blocks, asm, #[link], ctypes raw
    /// memory, process.dlopen, process.binding, libloading).
    NativeCode,
    /// include! with a non-literal or OUT_DIR path, and invocations of
    /// first-party proc macros.
    MacroCode,
    /// A module holding a blind-spot entry used as a value.
    ModuleEscape,
    ShadowedModule,
    UnresolvedModule,
    ResolutionLimit,
    BuildHook,
}

impl BlindSpotKind {
    pub const ALL: [BlindSpotKind; 31] = [
        Self::ParseError,
        Self::UnsupportedFileType,
        Self::LoadedAsCode,
        Self::SymlinkOutsideRoot,
        Self::NotRegularFile,
        Self::UnsafeOpenUnavailable,
        Self::TooLarge,
        Self::Undecodable,
        Self::Unreadable,
        Self::NonUtf8Path,
        Self::TooDeeplyNested,
        Self::FrontendFailure,
        Self::ManifestParseError,
        Self::ReferenceOutsideRoot,
        Self::ReferenceIntoExcluded,
        Self::UnconfirmedExclusion,
        Self::DynamicCode,
        Self::DynamicImport,
        Self::ReflectiveAccess,
        Self::ReflectiveUnknown,
        Self::ScopeInjection,
        Self::ImportSystemMutation,
        Self::Monkeypatch,
        Self::Introspection,
        Self::NativeCode,
        Self::MacroCode,
        Self::ModuleEscape,
        Self::ShadowedModule,
        Self::UnresolvedModule,
        Self::ResolutionLimit,
        Self::BuildHook,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParseError => "parse-error",
            Self::UnsupportedFileType => "unsupported-file-type",
            Self::LoadedAsCode => "loaded-as-code",
            Self::SymlinkOutsideRoot => "symlink-outside-root",
            Self::NotRegularFile => "not-regular-file",
            Self::UnsafeOpenUnavailable => "unsafe-open-unavailable",
            Self::TooLarge => "too-large",
            Self::Undecodable => "undecodable",
            Self::Unreadable => "unreadable",
            Self::NonUtf8Path => "non-utf8-path",
            Self::TooDeeplyNested => "too-deeply-nested",
            Self::FrontendFailure => "frontend-failure",
            Self::ManifestParseError => "manifest-parse-error",
            Self::ReferenceOutsideRoot => "reference-outside-root",
            Self::ReferenceIntoExcluded => "reference-into-excluded",
            Self::UnconfirmedExclusion => "unconfirmed-exclusion",
            Self::DynamicCode => "dynamic-code",
            Self::DynamicImport => "dynamic-import",
            Self::ReflectiveAccess => "reflective-access",
            Self::ReflectiveUnknown => "reflective-unknown",
            Self::ScopeInjection => "scope-injection",
            Self::ImportSystemMutation => "import-system-mutation",
            Self::Monkeypatch => "monkeypatch",
            Self::Introspection => "introspection",
            Self::NativeCode => "native-code",
            Self::MacroCode => "macro-code",
            Self::ModuleEscape => "module-escape",
            Self::ShadowedModule => "shadowed-module",
            Self::UnresolvedModule => "unresolved-module",
            Self::ResolutionLimit => "resolution-limit",
            Self::BuildHook => "build-hook",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// Whether this reason describes a whole file.
    pub fn is_whole_file(self) -> bool {
        matches!(
            self,
            Self::ParseError
                | Self::UnsupportedFileType
                | Self::LoadedAsCode
                | Self::SymlinkOutsideRoot
                | Self::NotRegularFile
                | Self::UnsafeOpenUnavailable
                | Self::TooLarge
                | Self::Undecodable
                | Self::Unreadable
                | Self::NonUtf8Path
                | Self::TooDeeplyNested
                | Self::FrontendFailure
                | Self::ManifestParseError
        )
    }
}

/// One blind spot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindSpot {
    pub id: String,
    /// `None` for gaps that belong to no language, such as an unsupported file
    /// type or an unconfirmed exclusion.
    pub language: Option<Language>,
    pub file: String,
    pub file_bytes: Option<String>,
    pub symbol: String,
    pub kind: BlindSpotKind,
    pub whole_file: bool,
    /// True when this blind spot makes the account incomplete. A
    /// code-loading `reference-outside-root` is a gap; a non-loading one is not.
    pub coverage_gap: bool,
    /// Redacted, truncated source text of the construct; empty for whole-file
    /// reasons.
    pub construct: String,
    pub ordinal: u32,
    pub labels: Vec<Label>,
    pub location: Option<Location>,
}

/// An imported package that is not in the egress catalog, listed once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnscannedDependency {
    pub id: String,
    pub language: Language,
    pub package: String,
    /// Sorted repo-relative files that import it.
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExcludedReason {
    /// A confirmed package-manager install output.
    InstallOutput,
    /// An install-output-shaped directory without its confirming marker. Also
    /// reported as an `unconfirmed-exclusion` gap when it holds supported code.
    UnconfirmedInstallOutput,
    /// A `.git` directory.
    Vcs,
    /// An in-root symlink whose target is scanned under another path.
    SymlinkAlias,
    BrokenSymlink,
    SymlinkHopLimit,
}

impl ExcludedReason {
    pub const ALL: [ExcludedReason; 6] = [
        Self::InstallOutput,
        Self::UnconfirmedInstallOutput,
        Self::Vcs,
        Self::SymlinkAlias,
        Self::BrokenSymlink,
        Self::SymlinkHopLimit,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstallOutput => "install-output",
            Self::UnconfirmedInstallOutput => "unconfirmed-install-output",
            Self::Vcs => "vcs",
            Self::SymlinkAlias => "symlink-alias",
            Self::BrokenSymlink => "broken-symlink",
            Self::SymlinkHopLimit => "symlink-hop-limit",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A path the scan did not enter, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excluded {
    pub path: String,
    pub path_bytes: Option<String>,
    pub reason: ExcludedReason,
}

/// A failure that produces no report (exit code 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    RootNotFound,
    RootNotDirectory,
    /// An internal failure with a fixed description.
    Internal(&'static str),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootNotFound => f.write_str("scan root not found"),
            Self::RootNotDirectory => f.write_str("scan root is not a directory"),
            Self::Internal(what) => write!(f, "internal error: {what}"),
        }
    }
}

impl std::error::Error for ToolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_r17() {
        assert_eq!(CompletenessState::Complete.exit_code(), 0);
        assert_eq!(CompletenessState::Incomplete.exit_code(), 2);
        assert_eq!(CompletenessState::Empty.exit_code(), 3);
        assert_eq!(EXIT_TOOL_ERROR, 1);
    }

    #[test]
    fn string_forms_round_trip() {
        for k in BlindSpotKind::ALL {
            assert_eq!(BlindSpotKind::parse(k.as_str()), Some(k));
        }
        for l in Label::ALL {
            assert_eq!(Label::parse(l.as_str()), Some(l));
        }
        for r in ExcludedReason::ALL {
            assert_eq!(ExcludedReason::parse(r.as_str()), Some(r));
        }
        for b in BudgetReason::ALL {
            assert_eq!(BudgetReason::parse(b.as_str()), Some(b));
        }
        for s in CompletenessState::ALL {
            assert_eq!(CompletenessState::parse(s.as_str()), Some(s));
        }
        for l in Language::ALL {
            assert_eq!(Language::parse(l.as_str()), Some(l));
        }
        assert_eq!(BlindSpotKind::parse("nope"), None);
    }
}

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
    /// Dependency scan results; present only when a dependency root is named.
    pub dependencies: Option<DependencySection>,
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

/// A map keyed by `Language`. `iter` yields entries in `Language::ALL`
/// order, never insertion order, so output does not depend on how the
/// map was filled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageMap<T> {
    inner: std::collections::BTreeMap<Language, T>,
}

impl<T> LanguageMap<T> {
    pub fn get(&self, language: Language) -> Option<&T> {
        self.inner.get(&language)
    }

    pub fn get_mut(&mut self, language: Language) -> Option<&mut T> {
        self.inner.get_mut(&language)
    }

    pub fn insert(&mut self, language: Language, value: T) {
        self.inner.insert(language, value);
    }

    /// The value for `language`, inserting `T::default()` when absent.
    pub fn or_default(&mut self, language: Language) -> &mut T
    where
        T: Default,
    {
        self.inner.entry(language).or_default()
    }

    /// Entries in `Language::ALL` order.
    pub fn iter(&self) -> impl Iterator<Item = (Language, &T)> {
        Language::ALL
            .iter()
            .filter_map(|l| self.inner.get(l).map(|v| (*l, v)))
    }
}

impl<T> Default for LanguageMap<T> {
    /// An empty map. `Coverage::default` fills every language; loaders
    /// that must cover the table insert one entry per `Language::ALL`.
    fn default() -> Self {
        Self {
            inner: std::collections::BTreeMap::new(),
        }
    }
}

impl<T> FromIterator<(Language, T)> for LanguageMap<T> {
    fn from_iter<I: IntoIterator<Item = (Language, T)>>(it: I) -> Self {
        Self {
            inner: it.into_iter().collect(),
        }
    }
}

impl<T> std::ops::Index<Language> for LanguageMap<T> {
    type Output = T;

    fn index(&self, language: Language) -> &T {
        self.get(language)
            .unwrap_or_else(|| panic!("language map has no {} entry", language.as_str()))
    }
}

/// Declared supported runtime range, one entry per language emitted
/// under its [`LanguageSpec::runtime_key`].
pub type RuntimeRange = LanguageMap<String>;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// Counts per language; every `Language::ALL` key is present.
    pub languages: LanguageMap<CoverageCounts>,
    /// Unsupported code file types and files loaded as code.
    pub unsupported: CoverageCounts,
}

impl Default for Coverage {
    fn default() -> Self {
        Self {
            languages: Language::ALL
                .iter()
                .map(|l| (*l, CoverageCounts::default()))
                .collect(),
            unsupported: CoverageCounts::default(),
        }
    }
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
    Go,
}

impl Language {
    pub const ALL: [Language; 4] = [Self::Python, Self::Javascript, Self::Rust, Self::Go];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Javascript => "javascript",
            Self::Rust => "rust",
            Self::Go => "go",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// The spec row for this language (KTD1): the one place per-language
    /// facts are written down. Adding a language means a variant, a row
    /// here, and the pieces the conformance test names.
    pub fn spec(self) -> &'static LanguageSpec {
        match self {
            Self::Python => &PYTHON_SPEC,
            Self::Javascript => &JAVASCRIPT_SPEC,
            Self::Rust => &RUST_SPEC,
            Self::Go => &GO_SPEC,
        }
    }
}

/// The per-language facts every table-driven shape reads (KTD1). The
/// row's `name` also keys the `data/labels.toml` per-language tables and
/// names the corpus directory.
#[derive(Debug, Clone, Copy)]
pub struct LanguageSpec {
    /// The `as_str` name used in reports and data files.
    pub name: &'static str,
    /// Key under `tool.runtime_range` in JSON output (`node` for
    /// javascript).
    pub runtime_key: &'static str,
    /// Source file extensions, each including the leading dot, matched
    /// byte for byte.
    pub extensions: &'static [&'static str],
    /// Whether a `#!` interpreter basename runs this language
    /// (`python3.11` counts for python; `node`, `deno`, `bun` for
    /// javascript).
    pub shebang: fn(&str) -> bool,
    /// Manifest file names discovery parses for this language.
    pub manifests: &'static [&'static str],
    /// Separator between module and member segments in data entry IDs.
    pub member_separator: &'static str,
}

fn python_shebang(base: &str) -> bool {
    base.strip_prefix("python")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn javascript_shebang(base: &str) -> bool {
    matches!(base, "node" | "nodejs" | "deno" | "bun")
}

fn no_shebang(_: &str) -> bool {
    false
}

static PYTHON_SPEC: LanguageSpec = LanguageSpec {
    name: "python",
    runtime_key: "python",
    extensions: &[".py", ".pyi", ".pyw"],
    shebang: python_shebang,
    manifests: &["pyproject.toml", "setup.cfg"],
    member_separator: ".",
};

static JAVASCRIPT_SPEC: LanguageSpec = LanguageSpec {
    name: "javascript",
    runtime_key: "node",
    extensions: &[".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"],
    shebang: javascript_shebang,
    manifests: &["package.json", "tsconfig.json"],
    member_separator: ".",
};

static RUST_SPEC: LanguageSpec = LanguageSpec {
    name: "rust",
    runtime_key: "rust",
    extensions: &[".rs"],
    shebang: no_shebang,
    manifests: &["Cargo.toml"],
    member_separator: "::",
};

static GO_SPEC: LanguageSpec = LanguageSpec {
    name: "go",
    runtime_key: "go",
    extensions: &[".go"],
    shebang: no_shebang,
    manifests: &["go.mod", "go.work"],
    member_separator: ".",
};

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
    /// Why it stayed unscanned; set only in dependency mode.
    pub reason: Option<UnscannedReason>,
    /// Declaring Python distributions, sorted.
    pub distribution: Vec<String>,
    pub distribution_source: Option<DistributionSource>,
    pub mark: Option<DependencyMark>,
}

/// The dependency section: results of scanning named dependency roots.
/// Present only when at least one dependency root is named on the command
/// line; its findings never enter the first-party collections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencySection {
    /// Every root the scan used, sorted by label then kind.
    pub roots: Vec<DependencyRoot>,
    /// Dependency-scope caveat ids, sorted.
    pub caveats: Vec<String>,
    /// Each exhausted dependency budget, sorted.
    pub budget_exceeded: Vec<DependencyBudgetReason>,
    /// Lockfiles that could not be used, sorted by path then problem.
    pub diagnostics: Vec<LockfileDiagnostic>,
    /// Installed files that run without an import, sorted.
    pub auto_run: Vec<AutoRun>,
    /// Scanned and linked package entries, sorted by identity.
    pub packages: Vec<DependencyPackage>,
}

/// A named dependency root as the report labels it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRoot {
    /// Path relative to the scan root for a root inside it, else the kind
    /// name. Never an absolute path.
    pub label: String,
    pub kind: DependencyRootKind,
}

/// Kind of a named dependency root, from its marker files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyRootKind {
    Npm,
    Python,
    CargoVendor,
    CargoRegistry,
    CargoGit,
}

impl DependencyRootKind {
    pub const ALL: [DependencyRootKind; 5] = [
        Self::Npm,
        Self::Python,
        Self::CargoVendor,
        Self::CargoRegistry,
        Self::CargoGit,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Python => "python",
            Self::CargoVendor => "cargo-vendor",
            Self::CargoRegistry => "cargo-registry",
            Self::CargoGit => "cargo-git",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// One installed package instance, scanned or linked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPackage {
    pub id: String,
    pub language: Language,
    pub package: String,
    /// Label of the named root holding this instance.
    pub root: String,
    /// Name chain from the root to the instance; version-free except for
    /// the `#<n>` rank suffix on multiply-installed Cargo names.
    pub locator: String,
    /// Installed version; emitted, never hashed.
    pub version: String,
    pub strength: VerificationStrength,
    /// A per-file install hash differed or a file was missing or unlisted.
    pub modified: bool,
    /// Inside a root the first-party scan already covers; carries no
    /// findings or importers.
    pub linked: bool,
    /// Catalogued package reached through an uncatalogued member.
    pub catalogued: bool,
    /// Declaring Python distributions, sorted.
    pub distribution: Vec<String>,
    pub distribution_source: Option<DistributionSource>,
    pub mark: Option<DependencyMark>,
    /// Sorted first-party files that import it.
    pub imported_by: Vec<String>,
    /// Sorted ids of package entries that import it.
    pub imported_by_packages: Vec<String>,
    /// The package's own completeness state; never feeds the top-level state.
    pub state: CompletenessState,
    pub coverage: CoverageCounts,
    /// Sites and blind spots in the package's source; `file` is relative to
    /// the package.
    pub sites: Vec<Site>,
    pub blind_spots: Vec<BlindSpot>,
    /// Packages its code imports that stayed unscanned, with reasons.
    pub imports_unscanned: Vec<ImportsUnscanned>,
}

/// A package imported only by dependency code that stayed unscanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportsUnscanned {
    pub language: Language,
    pub package: String,
    pub reason: UnscannedReason,
    /// Declaring Python distributions, sorted.
    pub distribution: Vec<String>,
    pub distribution_source: Option<DistributionSource>,
    pub mark: Option<DependencyMark>,
}

/// A fixed reason an imported dependency stayed unscanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnscannedReason {
    /// No named root holds the instance the import reaches.
    NoSourceInNamedRoot,
    /// The governing lockfile does not lock the installed version.
    VersionMismatch,
    /// Only an archive form exists (Yarn PnP, `.egg`, packed wheel).
    ArchiveOnlyInstall,
    /// A layout the scanner does not support, or metadata it cannot use.
    UnsupportedLayout,
    DependencyBudgetExhausted,
    LockfileUnreadable,
    /// A Cargo registry or git cache with no governing `Cargo.lock`.
    UnlockedSharedCache,
}

impl UnscannedReason {
    pub const ALL: [UnscannedReason; 7] = [
        Self::NoSourceInNamedRoot,
        Self::VersionMismatch,
        Self::ArchiveOnlyInstall,
        Self::UnsupportedLayout,
        Self::DependencyBudgetExhausted,
        Self::LockfileUnreadable,
        Self::UnlockedSharedCache,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoSourceInNamedRoot => "no-source-in-named-root",
            Self::VersionMismatch => "version-mismatch",
            Self::ArchiveOnlyInstall => "archive-only-install",
            Self::UnsupportedLayout => "unsupported-layout",
            Self::DependencyBudgetExhausted => "dependency-budget-exhausted",
            Self::LockfileUnreadable => "lockfile-unreadable",
            Self::UnlockedSharedCache => "unlocked-shared-cache",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// How far the installed source was verified against the lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationStrength {
    /// Locked version matched and per-file install hashes checked.
    ChecksumVerified,
    /// Locked version matched; no per-file hashes exist for this root kind.
    VersionMatched,
    /// No supported lockfile governs the import.
    Unlocked,
}

impl VerificationStrength {
    pub const ALL: [VerificationStrength; 3] =
        [Self::ChecksumVerified, Self::VersionMatched, Self::Unlocked];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChecksumVerified => "checksum-verified",
            Self::VersionMatched => "version-matched",
            Self::Unlocked => "unlocked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A name-signal mark on a dependency name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyMark {
    /// Sorted rules that fired.
    pub rules: Vec<MarkRule>,
    /// Sorted names the marked name resembles.
    pub resembles: Vec<String>,
}

/// Why a dependency name was marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MarkRule {
    /// Non-ASCII name whose confusable skeleton equals another name's.
    ConfusableSkeleton,
    /// Python import name that fails the single-script test.
    MixedScript,
    /// npm or Cargo name holding a non-ASCII character.
    NonAsciiName,
}

impl MarkRule {
    pub const ALL: [MarkRule; 3] = [
        Self::ConfusableSkeleton,
        Self::MixedScript,
        Self::NonAsciiName,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfusableSkeleton => "confusable-skeleton",
            Self::MixedScript => "mixed-script",
            Self::NonAsciiName => "non-ascii-name",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// Where a Python import name's declaring distribution came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DistributionSource {
    /// Installed `RECORD` or `top_level.txt` metadata in a named root.
    InstalledMetadata,
    /// The embedded curated table.
    Curated,
}

impl DistributionSource {
    pub const ALL: [DistributionSource; 2] = [Self::InstalledMetadata, Self::Curated];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstalledMetadata => "installed-metadata",
            Self::Curated => "curated",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// An installed file that runs without being imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoRun {
    pub id: String,
    /// Label of the named root holding the file.
    pub root: String,
    /// File relative to the import root.
    pub file: String,
    pub trigger: AutoRunTrigger,
    /// Installing distribution, or `unattributed` when no `RECORD` lists it.
    pub distribution: String,
}

/// What makes an installed file auto-run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AutoRunTrigger {
    /// A `.pth` file holding a line that starts with `import`.
    PthImportLine,
    Sitecustomize,
    Usercustomize,
}

impl AutoRunTrigger {
    pub const ALL: [AutoRunTrigger; 3] = [
        Self::PthImportLine,
        Self::Sitecustomize,
        Self::Usercustomize,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PthImportLine => "pth-import-line",
            Self::Sitecustomize => "sitecustomize",
            Self::Usercustomize => "usercustomize",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A lockfile the scan could not use, reported repo-relative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileDiagnostic {
    /// Repo-relative path of the lockfile.
    pub lockfile: String,
    pub problem: LockfileProblem,
}

/// Why a governing lockfile could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LockfileProblem {
    ParseError,
    UnknownVersion,
    TooLarge,
    Unreadable,
}

impl LockfileProblem {
    pub const ALL: [LockfileProblem; 4] = [
        Self::ParseError,
        Self::UnknownVersion,
        Self::TooLarge,
        Self::Unreadable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParseError => "parse-error",
            Self::UnknownVersion => "unknown-version",
            Self::TooLarge => "too-large",
            Self::Unreadable => "unreadable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A dependency budget that ran out during selection, inventory, or a
/// per-package pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyBudgetReason {
    Packages,
    Files,
    Bytes,
    Findings,
    ResolverSteps,
    InventoryEntries,
}

impl DependencyBudgetReason {
    pub const ALL: [DependencyBudgetReason; 6] = [
        Self::Packages,
        Self::Files,
        Self::Bytes,
        Self::Findings,
        Self::ResolverSteps,
        Self::InventoryEntries,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Packages => "packages",
            Self::Files => "files",
            Self::Bytes => "bytes",
            Self::Findings => "findings",
            Self::ResolverSteps => "resolver-steps",
            Self::InventoryEntries => "inventory-entries",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
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

/// Why a named dependency root was rejected (KTD2, KTD3, KTD5). Every
/// `Display` text is fixed and never holds a path or a scanned string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyRootProblem {
    /// The named path does not exist.
    NotFound,
    /// The named path exists but is not a directory.
    NotDirectory,
    /// The layout matches no root kind, or matches more than one (KTD3).
    UnrecognizedLayout,
    /// The root could not be listed.
    Unreadable,
    /// The root equals or contains the scan root (KTD2).
    OverlapsScanRoot,
    /// The root lies strictly inside another named root (KTD2).
    InsideAnotherRoot,
    /// An npm root outside the scan root that Node's lookup from the
    /// scan root cannot reach (KTD5).
    NpmNotOnLookupPath,
    /// Two roots hold the same package at the same locator (KTD4, AE11).
    AmbiguousRoots,
    /// Two Python roots hold the same top-level import name, or one venv
    /// has more than one import root (KTD5).
    AmbiguousEnvironment,
}

impl DependencyRootProblem {
    pub const ALL: [DependencyRootProblem; 9] = [
        Self::NotFound,
        Self::NotDirectory,
        Self::UnrecognizedLayout,
        Self::Unreadable,
        Self::OverlapsScanRoot,
        Self::InsideAnotherRoot,
        Self::NpmNotOnLookupPath,
        Self::AmbiguousRoots,
        Self::AmbiguousEnvironment,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not found",
            Self::NotDirectory => "not a directory",
            Self::UnrecognizedLayout => "unrecognized layout",
            Self::Unreadable => "cannot be read",
            Self::OverlapsScanRoot => "equals or contains the scan root",
            Self::InsideAnotherRoot => "inside another named dependency root",
            Self::NpmNotOnLookupPath => "npm root is not on the lookup path",
            Self::AmbiguousRoots => "ambiguous dependency roots",
            Self::AmbiguousEnvironment => "ambiguous Python environment",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A failure that produces no report (exit code 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    RootNotFound,
    RootNotDirectory,
    /// A `--deps` argument was rejected; `ordinal` is its 1-based
    /// argument position.
    DependencyRoot {
        ordinal: usize,
        problem: DependencyRootProblem,
    },
    /// An internal failure with a fixed description.
    Internal(&'static str),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootNotFound => f.write_str("scan root not found"),
            Self::RootNotDirectory => f.write_str("scan root is not a directory"),
            Self::DependencyRoot { ordinal, problem } => {
                write!(f, "dependency root {ordinal}: {}", problem.as_str())
            }
            Self::Internal(what) => write!(f, "internal error: {what}"),
        }
    }
}

impl std::error::Error for ToolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_the_completeness_state() {
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
        for r in UnscannedReason::ALL {
            assert_eq!(UnscannedReason::parse(r.as_str()), Some(r));
        }
        for s in VerificationStrength::ALL {
            assert_eq!(VerificationStrength::parse(s.as_str()), Some(s));
        }
        for m in MarkRule::ALL {
            assert_eq!(MarkRule::parse(m.as_str()), Some(m));
        }
        for s in DistributionSource::ALL {
            assert_eq!(DistributionSource::parse(s.as_str()), Some(s));
        }
        for t in AutoRunTrigger::ALL {
            assert_eq!(AutoRunTrigger::parse(t.as_str()), Some(t));
        }
        for p in LockfileProblem::ALL {
            assert_eq!(LockfileProblem::parse(p.as_str()), Some(p));
        }
        for b in DependencyBudgetReason::ALL {
            assert_eq!(DependencyBudgetReason::parse(b.as_str()), Some(b));
        }
        for k in DependencyRootKind::ALL {
            assert_eq!(DependencyRootKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(BlindSpotKind::parse("nope"), None);
        assert_eq!(UnscannedReason::parse("nope"), None);
    }
}

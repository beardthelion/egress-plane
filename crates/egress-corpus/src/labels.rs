//! `expected.toml` sidecar labels.
//!
//! A label file names what a correct scan of the case's `tree/` must report.
//! Unknown keys, unknown enum values, and an exit code that disagrees with the
//! state are rejected, so a typo cannot turn into a label that never matches.

use std::path::Path;

use egress_core::discover::budgets::DependencyBudgets;
use egress_core::model::{
    AutoRunTrigger, BlindSpotKind, CompletenessState, DependencyBudgetReason, ExcludedReason,
    Label, Language, LockfileProblem, MarkRule, UnscannedReason, VerificationStrength,
};
use serde::Deserialize;

/// Parsed and validated labels for one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub state: CompletenessState,
    pub exit_code: i32,
    pub sites: Vec<ExpectedSite>,
    pub blind_spots: Vec<ExpectedBlindSpot>,
    pub unscanned_dependencies: Vec<ExpectedDependency>,
    pub excluded: Vec<ExpectedExcluded>,
    /// When present, the report's caveat IDs must equal this set.
    pub caveats: Option<Vec<String>>,
    /// Strings that must not appear in any reported string field.
    pub absent_text: Vec<String>,
    /// Dependency roots passed to the scan, relative to the case directory,
    /// in labeled order.
    pub dependency_roots: Vec<String>,
    /// The case's dependency budget override, applied over the defaults.
    pub dependency_budgets: Option<DependencyBudgetOverride>,
    /// Required scanned or linked package entries, matched as a multiset.
    pub dependencies: Vec<ExpectedDependencyPackage>,
    /// Required sites inside dependency package entries.
    pub dependency_sites: Vec<ExpectedDependencySite>,
    /// Required blind spots inside dependency package entries.
    pub dependency_blind_spots: Vec<ExpectedDependencyBlindSpot>,
    /// Required `imports_unscanned` entries inside dependency package entries.
    pub dependency_imports_unscanned: Vec<ExpectedImportsUnscanned>,
    /// Required auto-run inventory entries.
    pub auto_run: Vec<ExpectedAutoRun>,
    /// Required lockfile diagnostics.
    pub dependency_diagnostics: Vec<ExpectedLockfileDiagnostic>,
    /// When present, the dependency section's `budget_exceeded` must equal
    /// this set.
    pub dependency_budget_exceeded: Option<Vec<DependencyBudgetReason>>,
    /// Entries that must not appear among the unscanned dependencies.
    pub absent_unscanned: Vec<ExpectedAbsentPackage>,
    /// Entries that must not appear among the scanned dependency packages.
    pub absent_scanned: Vec<ExpectedAbsentPackage>,
    /// Blind spots that must not appear inside a dependency package entry.
    pub absent_dependency_blind_spots: Vec<ExpectedAbsentDependencyBlindSpot>,
}

/// A required egress site, matched on identity components (never position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSite {
    pub file: String,
    pub symbol: String,
    pub mechanism: String,
    /// The destination's display form, for example `env:WEBHOOK_URL`.
    pub destination: String,
    /// When present, the site's label set must equal this set.
    pub labels: Option<Vec<Label>>,
}

/// A required blind spot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedBlindSpot {
    pub file: String,
    pub symbol: String,
    pub kind: BlindSpotKind,
}

/// A required unscanned-dependency entry. Optional fields compare only when
/// the label carries them; `mark = []` and `distribution = []` require the
/// entry to carry none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDependency {
    pub language: Language,
    pub package: String,
    pub reason: Option<UnscannedReason>,
    /// Required declaring distributions; `[]` requires none.
    pub distribution: Option<Vec<String>>,
    /// Required `resembles` names of the mark; `[]` requires no mark.
    pub mark: Option<Vec<String>>,
    /// Required mark rules.
    pub mark_rules: Option<Vec<MarkRule>>,
}

/// A required dependency package entry (`[[dependencies]]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDependencyPackage {
    pub language: Language,
    pub package: String,
    /// Label of the named root holding the instance.
    pub root: String,
    pub locator: String,
    pub version: String,
    pub strength: VerificationStrength,
    /// The entry's own completeness state.
    pub state: CompletenessState,
    /// An omitted boolean requires false.
    pub modified: bool,
    pub linked: bool,
    pub catalogued: bool,
    pub distribution: Option<Vec<String>>,
    /// Required `resembles` names of the mark; `[]` requires no mark.
    pub mark: Option<Vec<String>>,
    pub mark_rules: Option<Vec<MarkRule>>,
}

/// A required site inside a dependency package entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDependencySite {
    pub package: String,
    pub locator: String,
    pub file: String,
    pub symbol: String,
    pub mechanism: String,
    pub destination: String,
}

/// A required blind spot inside a dependency package entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDependencyBlindSpot {
    pub package: String,
    pub locator: String,
    pub file: String,
    pub symbol: String,
    pub kind: BlindSpotKind,
}

/// A required `imports_unscanned` entry: `package`/`locator` name the
/// importing entry, `imported` the package that stayed unscanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedImportsUnscanned {
    pub package: String,
    pub locator: String,
    pub language: Language,
    pub imported: String,
    pub reason: UnscannedReason,
}

/// A required auto-run inventory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAutoRun {
    pub file: String,
    pub trigger: AutoRunTrigger,
    pub distribution: String,
}

/// A required lockfile diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedLockfileDiagnostic {
    pub lockfile: String,
    pub problem: LockfileProblem,
}

/// A package that must not appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAbsentPackage {
    pub language: Language,
    pub package: String,
}

/// A blind-spot kind that must not appear in a package's entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAbsentDependencyBlindSpot {
    pub package: String,
    pub kind: BlindSpotKind,
}

/// A case's `[dependency_budgets]` table: any subset of the dependency
/// budget keys, applied over [`DependencyBudgets::default`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyBudgetOverride {
    pub packages: Option<u64>,
    pub files: Option<u64>,
    pub bytes: Option<u64>,
    pub findings: Option<u64>,
    pub resolver_steps: Option<u64>,
    pub inventory_entries: Option<u64>,
    pub lockfile_bytes: Option<u64>,
    pub metadata_bytes: Option<u64>,
}

impl DependencyBudgetOverride {
    /// Applies each present key over `base`.
    pub fn apply(&self, base: &mut DependencyBudgets) {
        if let Some(v) = self.packages {
            base.packages = v;
        }
        if let Some(v) = self.files {
            base.files = v;
        }
        if let Some(v) = self.bytes {
            base.bytes = v;
        }
        if let Some(v) = self.findings {
            base.findings = v;
        }
        if let Some(v) = self.resolver_steps {
            base.resolver_steps = v;
        }
        if let Some(v) = self.inventory_entries {
            base.inventory_entries = v;
        }
        if let Some(v) = self.lockfile_bytes {
            base.lockfile_bytes = v;
        }
        if let Some(v) = self.metadata_bytes {
            base.metadata_bytes = v;
        }
    }
}

/// A required `excluded` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedExcluded {
    pub path: String,
    pub reason: ExcludedReason,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExpected {
    state: String,
    exit_code: i32,
    #[serde(default)]
    sites: Vec<RawSite>,
    #[serde(default)]
    blind_spots: Vec<RawBlindSpot>,
    #[serde(default)]
    unscanned_dependencies: Vec<RawDependency>,
    #[serde(default)]
    excluded: Vec<RawExcluded>,
    caveats: Option<Vec<String>>,
    #[serde(default)]
    absent_text: Vec<String>,
    #[serde(default)]
    dependency_root: Vec<RawDependencyRoot>,
    dependency_budgets: Option<RawDependencyBudgets>,
    #[serde(default)]
    dependencies: Vec<RawDependencyPackage>,
    #[serde(default)]
    dependency_sites: Vec<RawDependencySite>,
    #[serde(default)]
    dependency_blind_spots: Vec<RawDependencyBlindSpot>,
    #[serde(default)]
    dependency_imports_unscanned: Vec<RawImportsUnscanned>,
    #[serde(default)]
    auto_run: Vec<RawAutoRun>,
    #[serde(default)]
    dependency_diagnostics: Vec<RawDiagnostic>,
    dependency_budget_exceeded: Option<Vec<String>>,
    #[serde(default)]
    absent_unscanned: Vec<RawAbsentPackage>,
    #[serde(default)]
    absent_scanned: Vec<RawAbsentPackage>,
    #[serde(default)]
    absent_dependency_blind_spots: Vec<RawAbsentBlindSpot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSite {
    file: String,
    symbol: String,
    mechanism: String,
    destination: String,
    labels: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBlindSpot {
    file: String,
    symbol: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependency {
    language: String,
    package: String,
    reason: Option<String>,
    distribution: Option<Vec<String>>,
    mark: Option<Vec<String>>,
    mark_rules: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExcluded {
    path: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependencyRoot {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependencyBudgets {
    packages: Option<u64>,
    files: Option<u64>,
    bytes: Option<u64>,
    findings: Option<u64>,
    resolver_steps: Option<u64>,
    inventory_entries: Option<u64>,
    lockfile_bytes: Option<u64>,
    metadata_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependencyPackage {
    language: String,
    package: String,
    root: String,
    locator: String,
    version: String,
    strength: String,
    state: String,
    #[serde(default)]
    modified: bool,
    #[serde(default)]
    linked: bool,
    #[serde(default)]
    catalogued: bool,
    distribution: Option<Vec<String>>,
    mark: Option<Vec<String>>,
    mark_rules: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependencySite {
    package: String,
    locator: String,
    file: String,
    symbol: String,
    mechanism: String,
    destination: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependencyBlindSpot {
    package: String,
    locator: String,
    file: String,
    symbol: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImportsUnscanned {
    package: String,
    locator: String,
    language: String,
    imported: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAutoRun {
    file: String,
    trigger: String,
    distribution: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDiagnostic {
    lockfile: String,
    problem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAbsentPackage {
    language: String,
    package: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAbsentBlindSpot {
    package: String,
    kind: String,
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

    let mut sites = Vec::new();
    for s in raw.sites {
        check_path(&s.file).map_err(&bad)?;
        check_nonempty("symbol", &s.symbol).map_err(&bad)?;
        check_nonempty("destination", &s.destination).map_err(&bad)?;
        let lang = s.mechanism.split_once(':').map(|(l, _)| l);
        if !matches!(lang, Some(l) if Language::parse(l).is_some()) || s.mechanism.ends_with(':') {
            return Err(bad(format!(
                "mechanism {:?} must be <language>:<entry>",
                s.mechanism
            )));
        }
        let labels = match s.labels {
            None => None,
            Some(ls) => {
                let mut out = Vec::new();
                for l in ls {
                    out.push(Label::parse(&l).ok_or_else(|| bad(format!("unknown label {l:?}")))?);
                }
                Some(out)
            }
        };
        sites.push(ExpectedSite {
            file: s.file,
            symbol: s.symbol,
            mechanism: s.mechanism,
            destination: s.destination,
            labels,
        });
    }

    let mut blind_spots = Vec::new();
    for b in raw.blind_spots {
        check_path(&b.file).map_err(&bad)?;
        check_nonempty("symbol", &b.symbol).map_err(&bad)?;
        let kind = BlindSpotKind::parse(&b.kind)
            .ok_or_else(|| bad(format!("unknown blind-spot kind {:?}", b.kind)))?;
        blind_spots.push(ExpectedBlindSpot {
            file: b.file,
            symbol: b.symbol,
            kind,
        });
    }

    // Shared helpers for the optional name-signal labels: a present key must
    // equal the report value, and an empty `mark` or `distribution` requires
    // the field to be absent.
    let opt_strings =
        |what: &str, raw: Option<Vec<String>>| -> Result<Option<Vec<String>>, String> {
            match raw {
                None => Ok(None),
                Some(v) => {
                    for s in &v {
                        check_nonempty(what, s).map_err(&bad)?;
                    }
                    Ok(Some(v))
                }
            }
        };
    let opt_rules = |raw: Option<Vec<String>>| -> Result<Option<Vec<MarkRule>>, String> {
        match raw {
            None => Ok(None),
            Some(v) => {
                let mut rules = Vec::new();
                for r in v {
                    rules.push(
                        MarkRule::parse(&r)
                            .ok_or_else(|| bad(format!("unknown mark rule {r:?}")))?,
                    );
                }
                Ok(Some(rules))
            }
        }
    };

    let mut unscanned_dependencies = Vec::new();
    for d in raw.unscanned_dependencies {
        let language = Language::parse(&d.language)
            .ok_or_else(|| bad(format!("unknown language {:?}", d.language)))?;
        check_nonempty("package", &d.package).map_err(&bad)?;
        let reason = match &d.reason {
            None => None,
            Some(r) => Some(
                UnscannedReason::parse(r).ok_or_else(|| bad(format!("unknown reason {r:?}")))?,
            ),
        };
        unscanned_dependencies.push(ExpectedDependency {
            language,
            package: d.package,
            reason,
            distribution: opt_strings("distribution entry", d.distribution)?,
            mark: opt_strings("mark entry", d.mark)?,
            mark_rules: opt_rules(d.mark_rules)?,
        });
    }

    let mut excluded = Vec::new();
    for x in raw.excluded {
        check_path(&x.path).map_err(&bad)?;
        let reason = ExcludedReason::parse(&x.reason)
            .ok_or_else(|| bad(format!("unknown excluded reason {:?}", x.reason)))?;
        excluded.push(ExpectedExcluded {
            path: x.path,
            reason,
        });
    }

    for t in &raw.absent_text {
        check_nonempty("absent_text entry", t).map_err(&bad)?;
    }

    let mut dependency_roots = Vec::new();
    for r in raw.dependency_root {
        check_path(&r.path).map_err(&bad)?;
        dependency_roots.push(r.path);
    }

    let dependency_budgets = raw.dependency_budgets.map(|b| DependencyBudgetOverride {
        packages: b.packages,
        files: b.files,
        bytes: b.bytes,
        findings: b.findings,
        resolver_steps: b.resolver_steps,
        inventory_entries: b.inventory_entries,
        lockfile_bytes: b.lockfile_bytes,
        metadata_bytes: b.metadata_bytes,
    });

    let mut dependencies = Vec::new();
    for d in raw.dependencies {
        let language = Language::parse(&d.language)
            .ok_or_else(|| bad(format!("unknown language {:?}", d.language)))?;
        check_nonempty("package", &d.package).map_err(&bad)?;
        check_nonempty("root", &d.root).map_err(&bad)?;
        check_nonempty("locator", &d.locator).map_err(&bad)?;
        check_nonempty("version", &d.version).map_err(&bad)?;
        let strength = VerificationStrength::parse(&d.strength)
            .ok_or_else(|| bad(format!("unknown strength {:?}", d.strength)))?;
        let dep_state = CompletenessState::parse(&d.state)
            .ok_or_else(|| bad(format!("unknown state {:?}", d.state)))?;
        dependencies.push(ExpectedDependencyPackage {
            language,
            package: d.package,
            root: d.root,
            locator: d.locator,
            version: d.version,
            strength,
            state: dep_state,
            modified: d.modified,
            linked: d.linked,
            catalogued: d.catalogued,
            distribution: opt_strings("distribution entry", d.distribution)?,
            mark: opt_strings("mark entry", d.mark)?,
            mark_rules: opt_rules(d.mark_rules)?,
        });
    }

    let mut dependency_sites = Vec::new();
    for s in raw.dependency_sites {
        check_nonempty("package", &s.package).map_err(&bad)?;
        check_nonempty("locator", &s.locator).map_err(&bad)?;
        check_path(&s.file).map_err(&bad)?;
        check_nonempty("symbol", &s.symbol).map_err(&bad)?;
        check_nonempty("destination", &s.destination).map_err(&bad)?;
        let lang = s.mechanism.split_once(':').map(|(l, _)| l);
        if !matches!(lang, Some(l) if Language::parse(l).is_some()) || s.mechanism.ends_with(':') {
            return Err(bad(format!(
                "mechanism {:?} must be <language>:<entry>",
                s.mechanism
            )));
        }
        dependency_sites.push(ExpectedDependencySite {
            package: s.package,
            locator: s.locator,
            file: s.file,
            symbol: s.symbol,
            mechanism: s.mechanism,
            destination: s.destination,
        });
    }

    let mut dependency_blind_spots = Vec::new();
    for b in raw.dependency_blind_spots {
        check_nonempty("package", &b.package).map_err(&bad)?;
        check_nonempty("locator", &b.locator).map_err(&bad)?;
        check_path(&b.file).map_err(&bad)?;
        check_nonempty("symbol", &b.symbol).map_err(&bad)?;
        let kind = BlindSpotKind::parse(&b.kind)
            .ok_or_else(|| bad(format!("unknown blind-spot kind {:?}", b.kind)))?;
        dependency_blind_spots.push(ExpectedDependencyBlindSpot {
            package: b.package,
            locator: b.locator,
            file: b.file,
            symbol: b.symbol,
            kind,
        });
    }

    let mut dependency_imports_unscanned = Vec::new();
    for i in raw.dependency_imports_unscanned {
        check_nonempty("package", &i.package).map_err(&bad)?;
        check_nonempty("locator", &i.locator).map_err(&bad)?;
        let language = Language::parse(&i.language)
            .ok_or_else(|| bad(format!("unknown language {:?}", i.language)))?;
        check_nonempty("imported", &i.imported).map_err(&bad)?;
        let reason = UnscannedReason::parse(&i.reason)
            .ok_or_else(|| bad(format!("unknown reason {:?}", i.reason)))?;
        dependency_imports_unscanned.push(ExpectedImportsUnscanned {
            package: i.package,
            locator: i.locator,
            language,
            imported: i.imported,
            reason,
        });
    }

    let mut auto_run = Vec::new();
    for a in raw.auto_run {
        check_nonempty("file", &a.file).map_err(&bad)?;
        let trigger = AutoRunTrigger::parse(&a.trigger)
            .ok_or_else(|| bad(format!("unknown auto-run trigger {:?}", a.trigger)))?;
        check_nonempty("distribution", &a.distribution).map_err(&bad)?;
        auto_run.push(ExpectedAutoRun {
            file: a.file,
            trigger,
            distribution: a.distribution,
        });
    }

    let mut dependency_diagnostics = Vec::new();
    for d in raw.dependency_diagnostics {
        check_path(&d.lockfile).map_err(&bad)?;
        let problem = LockfileProblem::parse(&d.problem)
            .ok_or_else(|| bad(format!("unknown lockfile problem {:?}", d.problem)))?;
        dependency_diagnostics.push(ExpectedLockfileDiagnostic {
            lockfile: d.lockfile,
            problem,
        });
    }

    let dependency_budget_exceeded = match raw.dependency_budget_exceeded {
        None => None,
        Some(v) => {
            let mut out = Vec::new();
            for b in v {
                out.push(
                    DependencyBudgetReason::parse(&b)
                        .ok_or_else(|| bad(format!("unknown budget name {b:?}")))?,
                );
            }
            Some(out)
        }
    };

    let mut absent_unscanned = Vec::new();
    let mut absent_scanned = Vec::new();
    for (raw_absent, out) in [
        (&raw.absent_unscanned, &mut absent_unscanned),
        (&raw.absent_scanned, &mut absent_scanned),
    ] {
        for d in raw_absent {
            let language = Language::parse(&d.language)
                .ok_or_else(|| bad(format!("unknown language {:?}", d.language)))?;
            check_nonempty("package", &d.package).map_err(&bad)?;
            out.push(ExpectedAbsentPackage {
                language,
                package: d.package.clone(),
            });
        }
    }

    let mut absent_dependency_blind_spots = Vec::new();
    for b in raw.absent_dependency_blind_spots {
        check_nonempty("package", &b.package).map_err(&bad)?;
        let kind = BlindSpotKind::parse(&b.kind)
            .ok_or_else(|| bad(format!("unknown blind-spot kind {:?}", b.kind)))?;
        absent_dependency_blind_spots.push(ExpectedAbsentDependencyBlindSpot {
            package: b.package,
            kind,
        });
    }

    // Absence labels need a positive anchor showing the subject was
    // exercised, so a regression to not scanning cannot leave a must-not
    // case green.
    for b in &absent_dependency_blind_spots {
        if !dependencies.iter().any(|d| d.package == b.package) {
            return Err(bad(format!(
                "absent_dependency_blind_spots names {:?}, which no [[dependencies]] entry labels",
                b.package
            )));
        }
    }
    if !absent_scanned.is_empty() || !absent_unscanned.is_empty() {
        let anchored =
            !dependencies.is_empty() || unscanned_dependencies.iter().any(|d| d.reason.is_some());
        if !anchored {
            return Err(bad(
                "absent_scanned/absent_unscanned need an anchor: a [[dependencies]] entry \
                 or a [[unscanned_dependencies]] entry with a reason"
                    .to_string(),
            ));
        }
    }

    // A must-not dependency case must carry an absence label, or the harness
    // has nothing to check it against.
    let is_must_not = {
        let mut parts = origin.split('/');
        parts.next();
        parts.next() == Some("dependencies")
            && parts.next().is_some_and(|n| n.starts_with("must-not-"))
    };
    if is_must_not {
        let exact_empty = unscanned_dependencies
            .iter()
            .map(|d| (&d.mark, &d.distribution))
            .chain(dependencies.iter().map(|d| (&d.mark, &d.distribution)))
            .any(|(mark, dist)| {
                mark.as_ref().is_some_and(Vec::is_empty) || dist.as_ref().is_some_and(Vec::is_empty)
            });
        if raw.absent_text.is_empty()
            && absent_unscanned.is_empty()
            && absent_scanned.is_empty()
            && absent_dependency_blind_spots.is_empty()
            && !exact_empty
        {
            return Err(bad(
                "a must-not dependency case needs absent_text, absent_unscanned, \
                 absent_scanned, absent_dependency_blind_spots, or an exact-empty \
                 mark or distribution"
                    .to_string(),
            ));
        }
    }

    Ok(Expected {
        state,
        exit_code: raw.exit_code,
        sites,
        blind_spots,
        unscanned_dependencies,
        excluded,
        caveats: raw.caveats,
        absent_text: raw.absent_text,
        dependency_roots,
        dependency_budgets,
        dependencies,
        dependency_sites,
        dependency_blind_spots,
        dependency_imports_unscanned,
        auto_run,
        dependency_diagnostics,
        dependency_budget_exceeded,
        absent_unscanned,
        absent_scanned,
        absent_dependency_blind_spots,
    })
}

/// Reads and parses `path`; errors name the path.
pub fn load_expected(path: &Path) -> Result<Expected, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    parse_expected(&text, &origin)
}

fn check_nonempty(what: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{what} is empty"))
    } else {
        Ok(())
    }
}

/// Labels use repo-relative `/`-separated paths, as the report does.
fn check_path(path: &str) -> Result<(), String> {
    check_nonempty("path", path)?;
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!("path {path:?} is not repo-relative"));
    }
    Ok(())
}

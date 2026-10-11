//! Global resource budgets.

use serde::Deserialize;

use crate::model::Report;

/// Raw text of `data/budgets.toml`.
pub const BUDGETS_TOML: &str = include_str!("../../../../data/budgets.toml");

/// Deterministic global budgets. Tests pass a reduced table through
/// [`Budgets::parse`], the same loader the embedded table uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    /// Supported source files parsed.
    pub files: u64,
    /// Source bytes parsed.
    pub bytes: u64,
    /// Sites, blind spots, and unscanned dependencies kept.
    pub findings: u64,
    /// Resolver steps across the scan.
    pub resolver_steps: u64,
}

impl Budgets {
    pub fn parse(text: &str) -> Result<Budgets, String> {
        toml::from_str(text).map_err(|e| format!("malformed budget table: {e}"))
    }

    pub fn embedded() -> Budgets {
        Budgets::parse(BUDGETS_TOML).expect("embedded data/budgets.toml")
    }
}

/// Deterministic budgets for the dependency pass, kept separate from the
/// first-party [`Budgets`] so a large install tree cannot reduce first-party
/// coverage. `Default` follows `data/budgets.toml` for the shared counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyBudgets {
    /// Installed package instances admitted to the closure.
    pub packages: u64,
    /// Dependency source files parsed.
    pub files: u64,
    /// Dependency source bytes parsed.
    pub bytes: u64,
    /// Dependency findings kept in the report.
    pub findings: u64,
    /// Resolver steps inside dependency code.
    pub resolver_steps: u64,
    /// Directory entries inventoried across named roots.
    pub inventory_entries: u64,
    /// Largest lockfile read, in bytes.
    pub lockfile_bytes: u64,
    /// Largest package metadata file read, in bytes.
    pub metadata_bytes: u64,
}

/// The embedded `data/dependency-budgets.toml` text (KTD14).
pub const DEPENDENCY_BUDGETS_TOML: &str = include_str!("../../../../data/dependency-budgets.toml");

impl DependencyBudgets {
    pub fn parse(text: &str) -> Result<DependencyBudgets, String> {
        toml::from_str(text).map_err(|e| format!("malformed budget table: {e}"))
    }

    pub fn embedded() -> DependencyBudgets {
        DependencyBudgets::parse(DEPENDENCY_BUDGETS_TOML)
            .expect("embedded data/dependency-budgets.toml")
    }
}

impl Default for DependencyBudgets {
    fn default() -> Self {
        Self::embedded()
    }
}

/// Charges files and bytes in byte-wise path order. Once either
/// budget is exhausted, every later file is refused.
#[derive(Debug)]
pub struct Charger {
    budgets: Budgets,
    files: u64,
    bytes: u64,
    exhausted: Option<crate::model::BudgetReason>,
}

impl Charger {
    pub fn new(budgets: Budgets) -> Charger {
        Charger {
            budgets,
            files: 0,
            bytes: 0,
            exhausted: None,
        }
    }

    /// Admits one file of `size` bytes, or reports that a budget is spent.
    pub fn admit(&mut self, size: u64) -> bool {
        use crate::model::BudgetReason;
        if self.exhausted.is_some() {
            return false;
        }
        if self.files + 1 > self.budgets.files {
            self.exhausted = Some(BudgetReason::Files);
            return false;
        }
        if self.bytes.saturating_add(size) > self.budgets.bytes {
            self.exhausted = Some(BudgetReason::Bytes);
            return false;
        }
        self.files += 1;
        self.bytes += size;
        true
    }

    pub fn exhausted(&self) -> Option<crate::model::BudgetReason> {
        self.exhausted
    }
}

/// Applies the findings cap to a report already sorted by
/// [`crate::identity::finalize`]. Findings are counted in a fixed order: blind
/// spots, then sites, then unscanned dependencies, each in identity order, and
/// the first `cap` are kept. Returns true when the cap cut anything.
pub fn apply_findings_budget(report: &mut Report, cap: u64) -> bool {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let total = report.blind_spots.len() + report.sites.len() + report.unscanned_dependencies.len();
    if total <= cap {
        return false;
    }
    let mut left = cap;
    let keep = report.blind_spots.len().min(left);
    report.blind_spots.truncate(keep);
    left -= keep;
    let keep = report.sites.len().min(left);
    report.sites.truncate(keep);
    left -= keep;
    report.unscanned_dependencies.truncate(left);
    true
}

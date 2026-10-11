//! Scan orchestration behind one `scan(root)` entry point.
//!
//! `scan` runs discovery, then reads, pre-scans, and lowers every admitted
//! source file on worker threads with 64 MiB stacks, catching a frontend
//! panic per file and capping the source bytes in flight. It then
//! classifies the lowered files (alias resolution, member-level
//! classification, destinations, and the resolver budget) and assembles the
//! report: completeness and coverage, caveats, identity and ordering,
//! and the findings budget, which applies after classification so it
//! counts every finding.

mod js;
pub mod registry;
pub mod tree;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use egress_core::data::Data;
use egress_core::discover::budgets::{DependencyBudgets, apply_findings_budget};
use egress_core::discover::completeness::{caveats, state};
use egress_core::discover::dependency_roots;
use egress_core::discover::{Config, Discovery, discover};
use egress_core::identity::{EncodedPath, finalize};
use egress_core::ir::FileIr;
use egress_core::model::{
    BudgetReason, Completeness, DependencyRoot, DependencySection, Label, Language, Report,
    SCHEMA_VERSION, Tool, ToolError,
};

pub use registry::{Frontend, FrontendError, Registry, SourceInput};

/// Default cap on source bytes held by workers at once.
pub const DEFAULT_IN_FLIGHT_BYTES: u64 = 64 * 1024 * 1024;

/// Scan settings. `scan` uses the defaults.
#[derive(Clone)]
pub struct ScanOptions {
    pub config: Config,
    pub registry: Registry,
    /// Worker threads; output does not depend on this.
    pub workers: usize,
    /// Cap on the total source bytes held by workers at once. A single file
    /// larger than the cap still runs, alone.
    pub in_flight_bytes: u64,
    /// Dependency roots named on the command line, in argument order.
    /// Empty means no dependency source is read.
    pub dependency_roots: Vec<PathBuf>,
    /// Dependency pass budgets; the corpus overrides them per case.
    pub dependency_budgets: DependencyBudgets,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            config: Config::default(),
            registry: Registry::builtin(),
            workers: std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(8),
            in_flight_bytes: DEFAULT_IN_FLIGHT_BYTES,
            dependency_roots: Vec::new(),
            dependency_budgets: DependencyBudgets::default(),
        }
    }
}

/// One source file a frontend lowered.
pub struct LoweredFile {
    pub path: Vec<u8>,
    pub file: EncodedPath,
    pub language: Language,
    /// Path, content, and hook labels, sorted.
    pub labels: Vec<Label>,
    pub ir: FileIr,
}

/// Everything a scan produced: the report, the lowered files in byte-wise
/// path order, and the discovery result (file index, manifests, exclusions)
/// that later stages resolve against.
pub struct ScanOutput {
    pub report: Report,
    pub files: Vec<LoweredFile>,
    pub discovery: Discovery,
}

/// Scans the repository at `root`.
pub fn scan(root: &Path) -> Result<Report, ToolError> {
    scan_with(root, &ScanOptions::default()).map(|o| o.report)
}

fn data() -> Result<&'static Data, ToolError> {
    static DATA: OnceLock<Result<Data, String>> = OnceLock::new();
    DATA.get_or_init(Data::embedded)
        .as_ref()
        .map_err(|_| ToolError::Internal("embedded data failed to load"))
}

/// Scans `root` with explicit options.
pub fn scan_with(root: &Path, options: &ScanOptions) -> Result<ScanOutput, ToolError> {
    let data = data()?;
    let discovery = discover(root, &options.config)?;
    let pass = tree::run(
        data,
        &discovery,
        options,
        &tree::TreeOptions {
            overrides: &[],
            resolver_budget: options.config.budgets.resolver_steps,
        },
    )?;
    let coverage = pass.coverage;
    let blind_spots = pass.blind_spots;
    let files = pass.files;
    let mut budget_exceeded = pass.budget_exceeded;
    let classified = pass.classified;

    let mut report = Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "egress-plane".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            data_digest: data.data_digest.clone(),
            runtime_range: data.runtime_range.clone(),
        },
        completeness: Completeness {
            state: state(&coverage, &blind_spots, &budget_exceeded),
            budget_exceeded: budget_exceeded.clone(),
            coverage,
        },
        caveats: caveats(&discovery.languages),
        sites: classified.sites,
        blind_spots,
        unscanned_dependencies: classified.unscanned_dependencies,
        excluded: discovery.excluded.clone(),
        dependencies: None,
    };
    finalize(&mut report);
    if apply_findings_budget(&mut report, options.config.budgets.findings) {
        budget_exceeded.push(BudgetReason::Findings);
        report.completeness.budget_exceeded = budget_exceeded;
        report.completeness.state = state(
            &report.completeness.coverage,
            &report.blind_spots,
            &report.completeness.budget_exceeded,
        );
        finalize(&mut report);
    }

    // Named dependency roots are opened and validated only after the
    // first-party report is final (KTD13): a rejected root is a tool
    // error and nothing is printed. Inventory (U4) runs here for its
    // ambiguity tool errors; its instances feed the selection pass in
    // U8, so for now the section carries the roots and no packages.
    if !options.dependency_roots.is_empty() {
        let roots = dependency_roots::open(discovery.root_dir(), &options.dependency_roots)?;
        let _instances =
            dependency_roots::inventory(&roots, &discovery, &options.dependency_budgets)?;
        report.dependencies = Some(DependencySection {
            roots: roots
                .iter()
                .map(|r| DependencyRoot {
                    label: r.label.clone(),
                    kind: r.kind,
                })
                .collect(),
            caveats: Vec::new(),
            budget_exceeded: Vec::new(),
            diagnostics: Vec::new(),
            auto_run: Vec::new(),
            packages: Vec::new(),
        });
        finalize(&mut report);
    }
    Ok(ScanOutput {
        report,
        files,
        discovery,
    })
}

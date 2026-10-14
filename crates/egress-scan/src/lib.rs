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

mod deps;
mod js;
pub mod registry;
pub mod tree;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use egress_core::data::Data;
use egress_core::deps::inventory::Inventory;
use egress_core::discover::budgets::{DependencyBudgets, apply_findings_budget};
use egress_core::discover::completeness::{caveats, state};
use egress_core::discover::dependency_roots;
use egress_core::discover::dependency_roots::NamedRoot;
use egress_core::discover::{Config, Discovery, discover};
use egress_core::identity::{EncodedPath, finalize};
use egress_core::ir::{FileIr, Root};
use egress_core::model::{
    BudgetReason, Completeness, Label, Language, Report, SCHEMA_VERSION, Tool, ToolError,
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

    // Named dependency roots open and inventory now: a rejected root is
    // a tool error before anything is printed either way (KTD13), and
    // installed metadata feeds the KTD17 distribution signal on
    // top-level entries.
    let mut named_roots: Vec<NamedRoot> = Vec::new();
    let mut inventories: Vec<Inventory> = Vec::new();
    if !options.dependency_roots.is_empty() {
        named_roots = dependency_roots::open(discovery.root_dir(), &options.dependency_roots)?;
        inventories =
            dependency_roots::inventory(&named_roots, &discovery, &options.dependency_budgets)?;
    }

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
        caveats: caveats(
            &discovery.languages,
            &go_versions(&discovery),
            &classified.caveat_triggers,
        ),
        sites: classified.sites.clone(),
        blind_spots,
        unscanned_dependencies: classified.unscanned_dependencies.clone(),
        excluded: discovery.excluded.clone(),
        dependencies: None,
    };
    // The KTD17 distribution signal annotates Python entries; it never
    // changes the state (R19).
    egress_core::names::apply_unscanned(
        &mut report.unscanned_dependencies,
        &inventories,
        &discovery.manifests.python_declarations,
        &data.python_distributions,
    );
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

    // The dependency pass runs after the finished first-party report
    // (KTD13): it only adds the section and annotates entries.
    if !options.dependency_roots.is_empty() {
        let section = deps::run(
            data,
            &discovery,
            &named_roots,
            &inventories,
            &classified,
            &mut report,
            options,
        )?;
        report.dependencies = Some(section);
        finalize(&mut report);
    } else {
        // Yarn PnP is detected from the scan root even with no named
        // roots (KTD3).
        deps::annotate_pnp(&discovery, &mut report);
        finalize(&mut report);
    }
    // KTD18's name marking: every name signal annotates in place and
    // never changes state or exit code (R18, R19).
    apply_marks(data, &mut report);
    finalize(&mut report);
    Ok(ScanOutput {
        report,
        files,
        discovery,
    })
}

/// The IR facts one lowered directory carries, for the corpus harness's
/// guards (KTD3). Test support only; [`scan`] is unchanged.
#[derive(Debug, Clone, Default)]
pub struct TreeIr {
    /// `(specifier, member path)` for each import binding in the tree.
    pub imports: Vec<(String, Vec<String>)>,
    /// Every reference whose root names an import, an ambient global, or
    /// a local binding; `Param`, `SelfValue`, `Expression`, and
    /// star-import-only roots are dropped.
    pub references: Vec<TreeReference>,
}

/// One lowered reference with its root resolved to a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeReference {
    pub root: TreeRoot,
    /// The member chain after the root, prefixed by the import's own
    /// member path for [`TreeRoot::Import`].
    pub members: Vec<String>,
}

/// A reference root as the corpus guards consume it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeRoot {
    /// `Root::Import` resolved through the file's own import table: the
    /// module specifier the binding names.
    Import(String),
    /// `Root::Ambient`: the global's name.
    Ambient(String),
    /// `Root::Local`: the local binding's name.
    Local(String),
}

/// The language a file's extension names, if a builtin frontend covers
/// it.
fn extension_language(name: &str) -> Option<Language> {
    Language::ALL
        .into_iter()
        .find(|l| l.spec().extensions.iter().any(|e| name.ends_with(e)))
}

/// Lowers every supported source file under `dir` and returns the
/// (module specifier, member chain) pairs its IR references resolve to,
/// each `Root::Import` resolved through the file's own import table, so
/// the corpus guards can tell code references from comment or string
/// text (KTD3). Corpus-test support only; [`scan`] is unchanged.
pub fn lower_tree(dir: &Path) -> Result<TreeIr, String> {
    let registry = Registry::builtin();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let rd = std::fs::read_dir(&d).map_err(|e| format!("{}: cannot list: {e}", d.display()))?;
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                files.push(p);
            }
        }
    }
    files.sort();
    let mut out = TreeIr::default();
    for path in files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(language) = extension_language(name) else {
            continue;
        };
        let Some(fe) = registry.get(language) else {
            continue;
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: cannot read: {e}", path.display()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let rel = path.strip_prefix(dir).unwrap_or(&path);
        let display = rel.to_string_lossy().into_owned();
        let ir = fe
            .lower(&SourceInput {
                path: rel.as_os_str().as_encoded_bytes(),
                file: &display,
                language,
                text,
            })
            .map_err(|e| format!("{}: cannot lower: {e:?}", path.display()))?;
        for i in &ir.imports {
            out.imports.push((i.specifier.clone(), i.members.clone()));
        }
        for r in &ir.references {
            let (root, members) = match &r.root {
                Root::Import(name) => {
                    match ir
                        .imports
                        .iter()
                        .find(|i| i.local.as_deref() == Some(name.as_str()))
                    {
                        Some(imp) => {
                            let mut members = imp.members.clone();
                            members.extend(r.members.iter().cloned());
                            (TreeRoot::Import(imp.specifier.clone()), members)
                        }
                        // A name only a star import can bind names no
                        // module here.
                        None => continue,
                    }
                }
                Root::Ambient(n) => (TreeRoot::Ambient(n.clone()), r.members.clone()),
                Root::Local(n) => (TreeRoot::Local(n.clone()), r.members.clone()),
                Root::Param(_) | Root::SelfValue | Root::Expression => continue,
            };
            out.references.push(TreeReference { root, members });
        }
    }
    Ok(out)
}

/// The `go` directive versions of every parsed `go.mod` and `go.work`,
/// feeding the `go_newer_than` caveat trigger.
fn go_versions(d: &Discovery) -> Vec<&str> {
    d.manifests
        .go_mod
        .iter()
        .map(|m| &m.go)
        .chain(d.manifests.go_work.iter().map(|w| &w.go))
        .filter_map(|v| v.as_deref())
        .collect()
}

/// Applies KTD18 name marking to top-level unscanned entries,
/// dependency package entries, and `imports_unscanned`: the comparison
/// set is the language's catalogued packages, its standard-library
/// module inventory, and the other dependency names of the same
/// language in the report.
fn apply_marks(data: &egress_core::data::Data, report: &mut Report) {
    let mut comparison: std::collections::BTreeMap<Language, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for lang in Language::ALL {
        let rt = data.runtime(lang);
        let mut set: std::collections::BTreeSet<String> = rt
            .packages
            .iter()
            .map(|p| p.name.clone())
            .chain(rt.inventory.stdlib_modules.iter().cloned())
            .collect();
        report
            .unscanned_dependencies
            .iter()
            .filter(|u| u.language == lang)
            .for_each(|u| {
                set.insert(u.package.clone());
            });
        if let Some(deps) = &report.dependencies {
            for p in &deps.packages {
                if p.language == lang {
                    set.insert(p.package.clone());
                }
                for i in &p.imports_unscanned {
                    if i.language == lang {
                        set.insert(i.package.clone());
                    }
                }
            }
        }
        comparison.insert(lang, set);
    }
    for u in &mut report.unscanned_dependencies {
        u.mark =
            egress_core::names::dependency_mark(u.language, &u.package, &comparison[&u.language]);
    }
    if let Some(deps) = &mut report.dependencies {
        for p in &mut deps.packages {
            p.mark = egress_core::names::dependency_mark(
                p.language,
                &p.package,
                &comparison[&p.language],
            );
            for i in &mut p.imports_unscanned {
                i.mark = egress_core::names::dependency_mark(
                    i.language,
                    &i.package,
                    &comparison[&i.language],
                );
            }
        }
    }
}

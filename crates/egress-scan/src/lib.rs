//! Scan orchestration behind one `scan(root)` entry point (KTD3).
//!
//! `scan` runs discovery, then reads, pre-scans, and lowers every admitted
//! source file on worker threads with 64 MiB stacks, catching a frontend
//! panic per file and capping the source bytes in flight (KTD13). It then
//! classifies the lowered files (U4: alias resolution, member-level
//! classification, destinations, and the resolver budget) and assembles the
//! report: completeness and coverage, caveats (R23), identity and ordering,
//! and the findings budget (KTD19), which applies after classification so it
//! counts every finding.

mod js;
pub mod registry;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

use egress_core::classify::classify;
use egress_core::data::Data;
use egress_core::discover::budgets::apply_findings_budget;
use egress_core::discover::completeness::{caveats, counts_mut, state};
use egress_core::discover::labels::content_labels;
use egress_core::discover::{
    Config, Discovery, SourceFile, WORKER_STACK_BYTES, discover, guard, whole_file_blind_spot,
};
use egress_core::identity::{EncodedPath, finalize};
use egress_core::ir::FileIr;
use egress_core::model::{
    BlindSpotKind, BudgetReason, Completeness, Label, Language, Report, SCHEMA_VERSION, Tool,
    ToolError,
};
use egress_core::prescan;
use egress_core::resolve::{Program, ProgramFile};

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

enum Outcome {
    /// Read and pre-scanned; `ir` is `None` when no frontend is registered.
    Scanned {
        labels: Vec<Label>,
        ir: Option<Box<FileIr>>,
    },
    Failed {
        kind: BlindSpotKind,
        labels: Vec<Label>,
    },
}

fn merge(mut a: Vec<Label>, b: Vec<Label>) -> Vec<Label> {
    a.extend(b);
    a.sort();
    a.dedup();
    a
}

fn process(registry: &Registry, f: &SourceFile, text: &str) -> Outcome {
    let labels = merge(f.labels.clone(), content_labels(text));
    if prescan::too_deep(f.language, text) {
        return Outcome::Failed {
            kind: BlindSpotKind::TooDeeplyNested,
            labels,
        };
    }
    let Some(fe) = registry.get(f.language) else {
        return Outcome::Scanned { labels, ir: None };
    };
    let input = SourceInput {
        path: &f.path,
        file: &f.file.display,
        language: f.language,
        text,
    };
    let kind = match guard(|| fe.lower(&input)) {
        Some(Ok(ir)) => {
            return Outcome::Scanned {
                labels,
                ir: Some(Box::new(ir)),
            };
        }
        Some(Err(FrontendError::Parse)) => BlindSpotKind::ParseError,
        Some(Err(FrontendError::TooDeeplyNested)) => BlindSpotKind::TooDeeplyNested,
        None => BlindSpotKind::FrontendFailure,
    };
    Outcome::Failed { kind, labels }
}

/// Bounds the source bytes held by workers at once (KTD13).
struct Gate {
    used: Mutex<u64>,
    freed: Condvar,
    cap: u64,
}

impl Gate {
    fn acquire(&self, n: u64) {
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        while *used > 0 && *used + n > self.cap {
            used = self.freed.wait(used).unwrap_or_else(|e| e.into_inner());
        }
        *used += n;
    }

    fn release(&self, n: u64) {
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        *used -= n;
        self.freed.notify_all();
    }
}

fn run_workers(d: &Discovery, options: &ScanOptions) -> Result<Vec<Outcome>, ToolError> {
    let n = d.sources.len();
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Outcome>>> = Mutex::new((0..n).map(|_| None).collect());
    let gate = Gate {
        used: Mutex::new(0),
        freed: Condvar::new(),
        cap: options.in_flight_bytes.max(1),
    };
    let work = || {
        loop {
            let i = next.fetch_add(1, Ordering::SeqCst);
            let Some(f) = d.sources.get(i) else { break };
            let mut held = f.size.max(1);
            gate.acquire(held);
            let outcome = match d.read_source(f) {
                Err(kind) => Outcome::Failed {
                    kind,
                    labels: f.labels.clone(),
                },
                Ok(text) => {
                    let actual = (text.len() as u64).max(1);
                    if actual > held {
                        // The file grew after the walk; charge its real size.
                        gate.release(held);
                        held = actual;
                        gate.acquire(held);
                    }
                    guard(|| process(&options.registry, f, &text)).unwrap_or(Outcome::Failed {
                        kind: BlindSpotKind::FrontendFailure,
                        labels: f.labels.clone(),
                    })
                }
            };
            gate.release(held);
            results.lock().unwrap_or_else(|e| e.into_inner())[i] = Some(outcome);
        }
    };
    let workers = options.workers.clamp(1, n.max(1));
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for _ in 0..workers {
            let h = std::thread::Builder::new()
                .stack_size(WORKER_STACK_BYTES)
                .spawn_scoped(s, work)
                .map_err(|_| ToolError::Internal("cannot start a worker thread"))?;
            handles.push(h);
        }
        for h in handles {
            h.join()
                .map_err(|_| ToolError::Internal("a worker thread failed"))?;
        }
        Ok(())
    })?;
    results
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .map(|o| o.ok_or(ToolError::Internal("a source file was not processed")))
        .collect()
}

/// Scans `root` with explicit options.
pub fn scan_with(root: &Path, options: &ScanOptions) -> Result<ScanOutput, ToolError> {
    let data = data()?;
    let discovery = discover(root, &options.config)?;
    let outcomes = run_workers(&discovery, options)?;

    let mut coverage = discovery.coverage.clone();
    let mut blind_spots = discovery.blind_spots.clone();
    let mut files = Vec::new();
    for (f, outcome) in discovery.sources.iter().zip(outcomes) {
        match outcome {
            Outcome::Scanned { labels, ir } => {
                counts_mut(&mut coverage, Some(f.language)).scanned += 1;
                if let Some(ir) = ir {
                    files.push(LoweredFile {
                        path: f.path.clone(),
                        file: f.file.clone(),
                        language: f.language,
                        labels,
                        ir: *ir,
                    });
                }
            }
            Outcome::Failed { kind, labels } => {
                counts_mut(&mut coverage, Some(f.language)).skipped += 1;
                let mut b = whole_file_blind_spot(&f.path, kind, Some(f.language));
                b.labels = labels;
                blind_spots.push(b);
            }
        }
    }

    let mut budget_exceeded = discovery.budget_exceeded.clone();
    let mut linked = Vec::new();
    for lang in Language::ALL {
        if let Some(fe) = options.registry.get(lang) {
            let mut view: Vec<(&[u8], &mut FileIr)> = files
                .iter_mut()
                .filter(|f| f.language == lang)
                .map(|f| (f.path.as_slice(), &mut f.ir))
                .collect();
            if let Some(rules) = fe.link(&discovery.manifests, &discovery.index, &mut view) {
                linked.push((lang, rules));
            } else if let Some(rules) = fe.repo_rules(&discovery) {
                linked.push((lang, rules));
            }
        }
    }
    let mut program = Program::new(&discovery.index, &discovery.excluded_dirs);
    for lang in Language::ALL {
        if let Some((_, rules)) = linked.iter().find(|(l, _)| *l == lang) {
            program.set_rules(lang, rules.as_ref());
        } else if let Some(rules) = options.registry.get(lang).and_then(|f| f.specifier_rules()) {
            program.set_rules(lang, rules);
        }
    }
    for f in &files {
        program.add_file(
            f.path.clone(),
            ProgramFile {
                file: f.file.clone(),
                language: f.language,
                labels: f.labels.clone(),
                ir: &f.ir,
            },
        );
    }
    let classified = classify(data, &program, options.config.budgets.resolver_steps);
    drop(program);
    blind_spots.extend(classified.blind_spots);
    coverage.unsupported.skipped += classified.loaded_as_code;
    // Discovery charges symlink resolution against the same budget and may
    // already have recorded it.
    if classified.resolver_budget_exceeded
        && !budget_exceeded.contains(&BudgetReason::ResolverSteps)
    {
        budget_exceeded.push(BudgetReason::ResolverSteps);
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
        caveats: caveats(&discovery.languages),
        sites: classified.sites,
        blind_spots,
        unscanned_dependencies: classified.unscanned_dependencies,
        excluded: discovery.excluded.clone(),
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
    Ok(ScanOutput {
        report,
        files,
        discovery,
    })
}

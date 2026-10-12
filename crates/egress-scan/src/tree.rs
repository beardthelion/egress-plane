//! The reusable per-tree pass (U6): lowering through classification
//! for one discovered tree, first-party or dependency package. The
//! first-party `scan_with` calls it with no rule overrides and the
//! first-party resolver budget; a dependency pass later overrides
//! Python's specifier rules and supplies the dependency budget.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use egress_core::classify::{Classified, classify};
use egress_core::data::Data;
use egress_core::discover::completeness::counts_mut;
use egress_core::discover::labels::content_labels;
use egress_core::discover::{Discovery, WORKER_STACK_BYTES, guard, whole_file_blind_spot};
use egress_core::ir::FileIr;
use egress_core::model::Coverage;
use egress_core::model::{BlindSpot, BlindSpotKind, BudgetReason, Label, Language, ToolError};
use egress_core::prescan;
use egress_core::resolve::{Program, ProgramFile, SpecifierRules};

use crate::registry::FrontendError;
use crate::{LoweredFile, ScanOptions};

/// What one tree pass produced: the lowered files, coverage and blind
/// spots, budget list, and the classification result the report or the
/// dependency section consumes.
pub struct TreePass {
    pub files: Vec<LoweredFile>,
    pub coverage: Coverage,
    pub blind_spots: Vec<BlindSpot>,
    pub budget_exceeded: Vec<BudgetReason>,
    pub classified: Classified,
}

/// Specifier-rule overrides for a non-first-party pass: a language's
/// repo/link rules are replaced by the supplied rules.
pub struct TreeOptions<'a> {
    /// Per-language specifier rules replacing the repo-derived ones;
    /// first-party passes pass an empty list.
    pub overrides: &'a [(Language, Box<dyn SpecifierRules>)],
    /// The resolver budget this pass is charged against.
    pub resolver_budget: u64,
}

/// Runs lowering through classification on `d`. The work order and
/// inputs are the `scan_with` steps unchanged (U6's characterization
/// rule).
pub fn run(
    data: &Data,
    d: &Discovery,
    options: &ScanOptions,
    tree: &TreeOptions<'_>,
) -> Result<TreePass, ToolError> {
    let outcomes = run_workers(d, options)?;

    let mut coverage = d.coverage.clone();
    let mut blind_spots = d.blind_spots.clone();
    let mut files = Vec::new();
    for (f, outcome) in d.sources.iter().zip(outcomes) {
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

    let mut budget_exceeded = d.budget_exceeded.clone();
    let mut linked = Vec::new();
    for lang in Language::ALL {
        if let Some(fe) = options.registry.get(lang) {
            let mut view: Vec<(&[u8], &mut FileIr)> = files
                .iter_mut()
                .filter(|f| f.language == lang)
                .map(|f| (f.path.as_slice(), &mut f.ir))
                .collect();
            if let Some(rules) = fe.link(&d.manifests, &d.index, &mut view) {
                linked.push((lang, rules));
            } else if let Some(rules) = fe.repo_rules(d) {
                linked.push((lang, rules));
            }
        }
    }
    let mut program = Program::new(&d.index, &d.excluded_dirs);
    for lang in Language::ALL {
        if let Some((_, rules)) = tree.overrides.iter().find(|(l, _)| *l == lang) {
            program.set_rules(lang, rules.as_ref());
        } else if let Some((_, rules)) = linked.iter().find(|(l, _)| *l == lang) {
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
    let classified = classify(data, &program, tree.resolver_budget);
    drop(program);
    blind_spots.extend(classified.blind_spots.iter().cloned());
    coverage.unsupported.skipped += classified.loaded_as_code;
    // Discovery charges symlink resolution against the same budget and may
    // already have recorded it.
    if classified.resolver_budget_exceeded
        && !budget_exceeded.contains(&BudgetReason::ResolverSteps)
    {
        budget_exceeded.push(BudgetReason::ResolverSteps);
    }
    Ok(TreePass {
        files,
        coverage,
        blind_spots,
        budget_exceeded,
        classified,
    })
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

fn process(
    registry: &crate::registry::Registry,
    f: &egress_core::discover::SourceFile,
    text: &str,
) -> Outcome {
    let labels = merge(f.labels.clone(), content_labels(text, f.language));
    if prescan::too_deep(f.language, text) {
        return Outcome::Failed {
            kind: BlindSpotKind::TooDeeplyNested,
            labels,
        };
    }
    let Some(fe) = registry.get(f.language) else {
        return Outcome::Scanned { labels, ir: None };
    };
    let input = crate::registry::SourceInput {
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

/// Bounds the source bytes held by workers at once.
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

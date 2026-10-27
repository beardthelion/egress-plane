//! The dependency pass: selection, closure, assembly, and the KTD13
//! annotation of the finished first-party report.

mod assemble;
mod closure;
mod select;

use std::collections::BTreeMap;

use egress_core::data::Data;
use egress_core::deps::inventory::Inventory;
use egress_core::discover::Discovery;
use egress_core::discover::dependency_roots::NamedRoot;
use egress_core::model::{
    DependencyRootKind, DependencySection, Language, LockfileDiagnostic, Report, ToolError,
    UnscannedReason,
};

use crate::ScanOptions;

use closure::{Candidate, Closure, cargo_pin};
use select::{Importer, Resolved};

/// Runs the full dependency pass and returns the section plus the
/// top-level unscanned annotations (KTD13).
pub fn run(
    data: &Data,
    discovery: &Discovery,
    roots: &[NamedRoot],
    invs: &[Inventory],
    classified: &egress_core::classify::Classified,
    report: &mut Report,
    options: &ScanOptions,
) -> Result<DependencySection, ToolError> {
    // Selection: each top-level unscanned entry resolves per importer
    // file; a resolved instance becomes a depth-0 candidate, a reason
    // annotates the entry.
    let mut frontier: Vec<Candidate> = Vec::new();
    let mut frontier_ix: std::collections::HashMap<(usize, usize), usize> =
        std::collections::HashMap::new();
    let mut diagnostics: Vec<LockfileDiagnostic> = Vec::new();
    let ix = select::SelectIx::new(roots, invs);
    let mut outcomes: BTreeMap<(Language, String), Vec<ImportOutcome>> = BTreeMap::new();
    for u in &classified.unscanned_dependencies {
        for file in &u.files {
            let lock = select::governing_lock(
                discovery,
                file.as_bytes(),
                kind_of(u.language),
                options.dependency_budgets.lockfile_bytes,
            );
            if let select::Lock::Unreadable(d) = &lock {
                diagnostics.push(d.clone());
            }
            let key = resolve_key(classified, u);
            let importer_file = file.as_bytes().to_vec();
            let pin = match u.language {
                Language::Rust => {
                    crate_name(discovery, &importer_file).and_then(|n| cargo_pin(&lock, n, &key))
                }
                Language::Go => go_require(discovery, &importer_file, &key),
                _ => None,
            };
            let outcome = match select::resolve(
                &ix,
                discovery.root_dir(),
                u.language,
                &key,
                &Importer::FirstParty(importer_file),
                pin.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
            ) {
                Resolved::Instance { root, instance } => {
                    // A candidate reached for the first time or by an
                    // earlier importer joins the frontier.
                    match frontier_ix.get(&(root, instance)) {
                        Some(&ci) => frontier[ci].importers.push(file.clone()),
                        None => {
                            frontier_ix.insert((root, instance), frontier.len());
                            frontier.push(Candidate {
                                root,
                                instance,
                                depth: 0,
                                importers: vec![file.clone()],
                                importing_packages: Vec::new(),
                                lock: lock.clone(),
                            });
                        }
                    }
                    ImportOutcome::Reached(root, instance)
                }
                Resolved::Reason(r) => ImportOutcome::Reason(r),
            };
            outcomes
                .entry((u.language, u.package.clone()))
                .or_default()
                .push(outcome);
        }
    }

    // The inventory-entries budget: a root whose listing overflowed
    // marks every instance budget-exhausted (KTD14). A dropped
    // candidate must keep a verdict so its importers report
    // `dependency-budget-exhausted`, not `no-source-in-named-root`,
    // and so the dropped instance still appears in the imports lists.
    let mut dropped: Vec<(usize, usize)> = Vec::new();
    for (ri, inv) in invs.iter().enumerate() {
        if !inv.entries_exceeded {
            continue;
        }
        for ii in 0..inv.instances.len() {
            let before = frontier.len();
            frontier.retain(|c| !(c.root == ri && c.instance == ii));
            if frontier.len() < before {
                dropped.push((ri, ii));
            }
        }
    }

    let Closure {
        mut verdicts,
        diagnostics: mut diag,
        budgets_exhausted: mut be,
    } = closure::run(
        data,
        discovery,
        roots,
        invs,
        frontier,
        options,
        &options.dependency_budgets,
    )?;
    for key in dropped {
        verdicts.entry(key).or_insert_with(|| closure::Verdict {
            reason: Some(UnscannedReason::DependencyBudgetExhausted),
            strength: None,
            lock: select::Lock::Absent,
            importers: Vec::new(),
            importing_packages: Vec::new(),
            pass: None,
        });
    }
    diagnostics.append(&mut diag);
    // Selection pushes one diagnostic per (dep, importer) so identical
    // (lockfile, problem) pairs repeat; dedup before the section takes
    // them.
    diagnostics.sort();
    diagnostics.dedup();
    if invs.iter().any(|i| i.entries_exceeded) {
        be.push(egress_core::model::DependencyBudgetReason::InventoryEntries);
    }

    // KTD13 annotation: an entry's imports all reaching scanned or
    // linked instances drops it; otherwise its reason follows the
    // precedence.
    let mut annotation: BTreeMap<(Language, String), Option<UnscannedReason>> = BTreeMap::new();
    for ((lang, package), outcomes) in &outcomes {
        let mut reasons: Vec<UnscannedReason> = Vec::new();
        let mut all_reached = !outcomes.is_empty();
        for o in outcomes {
            match o {
                ImportOutcome::Reached(r, i) => {
                    // The verdict on the reached instance decides:
                    // a scanned (or linked) instance counts, an
                    // unscanned verdict contributes its reason.
                    match verdicts.get(&(*r, *i)) {
                        Some(v) if v.pass.is_some() => {}
                        Some(v) => {
                            all_reached = false;
                            if let Some(r) = v.reason {
                                reasons.push(r);
                            }
                        }
                        None => {
                            all_reached = false;
                        }
                    }
                }
                ImportOutcome::Reason(r) => {
                    all_reached = false;
                    reasons.push(*r);
                }
            }
        }
        annotation.insert(
            (*lang, package.clone()),
            if all_reached {
                None
            } else {
                reasons.sort_by_key(|r| reason_rank(*r));
                reasons
                    .first()
                    .copied()
                    .or(Some(UnscannedReason::NoSourceInNamedRoot))
            },
        );
    }

    // Apply: drop entries whose imports all reached scanned instances;
    // set the reason on the rest.
    report.unscanned_dependencies.retain_mut(|u| {
        match annotation.get(&(u.language, u.package.clone())) {
            Some(None) => false,
            Some(Some(r)) => {
                u.reason = Some(*r);
                u.package = egress_core::escape::escape(&u.package);
                true
            }
            None => true,
        }
    });

    let outcome = assemble::run(
        data,
        discovery,
        roots,
        invs,
        Closure {
            verdicts,
            diagnostics: diag,
            budgets_exhausted: be,
        },
        report,
        options,
    )?;
    let mut section = outcome.section;
    section.diagnostics = diagnostics;
    Ok(section)
}

enum ImportOutcome {
    Reached(usize, usize),
    Reason(UnscannedReason),
}

/// KTD13 precedence for mixed outcomes.
fn reason_rank(r: UnscannedReason) -> u8 {
    match r {
        UnscannedReason::LockfileUnreadable => 0,
        UnscannedReason::VersionMismatch => 1,
        UnscannedReason::UnlockedSharedCache => 2,
        UnscannedReason::ArchiveOnlyInstall => 3,
        UnscannedReason::UnsupportedLayout => 4,
        UnscannedReason::DependencyBudgetExhausted => 5,
        UnscannedReason::NoSourceInNamedRoot => 6,
    }
}

/// Applies the Yarn PnP reason to JavaScript unscanned entries when
/// no dependency roots are named (KTD3): the detection lives at the
/// scan root, so it runs with zero named roots.
pub fn annotate_pnp(discovery: &Discovery, report: &mut Report) {
    for u in report.unscanned_dependencies.iter_mut() {
        if u.language != Language::Javascript || u.reason.is_some() {
            continue;
        }
        if u.files
            .iter()
            .any(|f| select::pnp_ancestor(discovery.root_dir(), f.as_bytes()))
        {
            u.reason = Some(UnscannedReason::ArchiveOnlyInstall);
        }
    }
}

/// The ecosystem's lockfile-carrying root kind.
fn kind_of(lang: Language) -> Option<DependencyRootKind> {
    match lang {
        Language::Javascript => Some(DependencyRootKind::Npm),
        Language::Python => Some(DependencyRootKind::Python),
        Language::Rust => Some(DependencyRootKind::CargoVendor),
        Language::Go => Some(DependencyRootKind::GoModuleCache),
    }
}

/// The crate a first-party file belongs to: the Cargo manifest whose
/// directory is the file's longest ancestor.
fn crate_name<'d>(discovery: &'d Discovery, file: &[u8]) -> Option<&'d str> {
    discovery
        .manifests
        .cargo
        .iter()
        .filter(|m| {
            m.has_package
                && m.name.is_some()
                && egress_core::paths::within(file, &parent_of(&m.path))
        })
        .max_by_key(|m| m.path.len())
        .and_then(|m| m.name.as_deref())
}

/// The version the file's nearest `go.mod` requires for `module`
/// (KTD9): the pin that picks the modcache instance to scan.
fn go_require(discovery: &Discovery, file: &[u8], module: &str) -> Option<(String, String)> {
    discovery
        .manifests
        .go_mod
        .iter()
        .filter(|m| m.module.is_some() && egress_core::paths::within(file, &parent_of(&m.path)))
        .max_by_key(|m| m.path.len())
        .and_then(|m| {
            m.require
                .iter()
                .filter(|(p, _)| {
                    module == p
                        || module
                            .strip_prefix(p.as_str())
                            .is_some_and(|r| r.starts_with('/') || r.starts_with('.'))
                })
                .max_by_key(|(p, _)| p.len())
        })
        .map(|(p, v)| (p.clone(), v.clone()))
}

fn parent_of(p: &[u8]) -> Vec<u8> {
    egress_core::paths::dir_of(p).to_vec()
}

/// The key an import resolves under, per ecosystem: Python takes the
/// longest recorded specifier (a dotted `google.auth`, not `google`);
/// Rust the first `::` segment; JavaScript the package name (the
/// `@scope/name` pair or the first path segment) (KTD10).
fn resolve_key(
    classified: &egress_core::classify::Classified,
    u: &egress_core::model::UnscannedDependency,
) -> String {
    let spec = classified
        .unscanned_imports
        .get(&(u.language, u.package.clone()))
        .and_then(|rec| rec.specifiers.iter().max_by_key(|s| s.len()).cloned());
    let spec = spec.as_deref().unwrap_or(&u.package);
    match u.language {
        Language::Python => spec.to_string(),
        Language::Rust => spec.split("::").next().unwrap_or(spec).to_string(),
        // The Go specifier is already the module path the import keys on.
        Language::Go => spec.to_string(),
        // The specifier carries member names appended by `.`, so the
        // key is the dep's already-split package (`package_name` does
        // the `@scope/name` and `/` cuts); re-cutting the specifier
        // breaks dotted names (`chart.js`), subpaths (`lodash/fp`),
        // and dots inside a scope (`@my.org/pkg`).
        Language::Javascript => u.package.clone(),
    }
}

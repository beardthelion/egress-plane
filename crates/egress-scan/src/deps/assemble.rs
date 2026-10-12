//! Section assembly: package entries, linked entries, `imports_unscanned`,
//! caveats, and the KTD13 annotation of the finished top-level report.

use egress_core::data::Data;
use egress_core::deps::inventory::{Instance, Inventory};
use egress_core::deps::locator;
use egress_core::discover::Discovery;
use egress_core::discover::dependency_roots::NamedRoot;
use std::collections::BTreeMap;

use egress_core::model::{
    AutoRun, DependencyPackage, DependencyRootKind, DependencySection, ImportsUnscanned, Language,
    Report, ToolError, UnscannedReason, VerificationStrength,
};

use crate::ScanOptions;

use super::closure::Closure;
use super::select::{self, Lock};
use egress_core::deps::verify::Gate;

/// What the dependency pass returns: the section plus the top-level
/// annotation (which unscanned entries stay and under which reason).
pub struct Outcome {
    pub section: DependencySection,
}

/// Builds the section from the closure verdicts and annotates the
/// finished report's unscanned list (KTD13).
pub fn run(
    data: &Data,
    discovery: &Discovery,
    roots: &[NamedRoot],
    invs: &[Inventory],
    closure: Closure,
    _report: &mut Report,
    _options: &ScanOptions,
) -> Result<Outcome, ToolError> {
    let mut packages: Vec<DependencyPackage> = Vec::new();
    let mut diagnostics = closure.diagnostics.clone();
    let mut budgets = closure.budgets_exhausted.clone();

    // Entry ids of scanned packages, keyed by (root, instance), for
    // `imported_by_packages`.
    let mut ids: BTreeMap<(usize, usize), String> = BTreeMap::new();
    for ((ri, ii), verdict) in &closure.verdicts {
        if verdict.pass.is_none() {
            continue;
        }
        let inst = &invs[*ri].instances[*ii];
        let stub = DependencyPackage {
            id: String::new(),
            language: lang_of(roots[*ri].kind),
            package: inst.package.clone(),
            root: roots[*ri].label.clone(),
            locator: locator_for(inst, &verdict.lock),
            version: String::new(),
            strength: VerificationStrength::Unlocked,
            modified: false,
            linked: false,
            catalogued: false,
            distribution: Vec::new(),
            distribution_source: None,
            mark: None,
            imported_by: Vec::new(),
            imported_by_packages: Vec::new(),
            state: egress_core::model::CompletenessState::Empty,
            coverage: Default::default(),
            sites: Vec::new(),
            blind_spots: Vec::new(),
            imports_unscanned: Vec::new(),
        };
        ids.insert(
            (*ri, *ii),
            egress_core::identity::hash_id(&egress_core::identity::dependency_key(&stub)),
        );
    }
    for ((ri, ii), verdict) in &closure.verdicts {
        let inst = &invs[*ri].instances[*ii];
        let kind = roots[*ri].kind;
        let Some(pass) = &verdict.pass else {
            continue;
        };
        let entry = DependencyPackage {
            id: String::new(),
            language: lang_of(kind),
            package: pkg_name(inst),
            root: roots[*ri].label.clone(),
            locator: locator_for(inst, &verdict.lock),
            version: inst.version.clone(),
            strength: verdict.strength.unwrap_or(VerificationStrength::Unlocked),
            modified: pass.modified,
            linked: false,
            catalogued: catalogued(data, lang_of(kind), &inst.package),
            distribution: distribution_for(kind, inst),
            distribution_source: source_for(kind, inst),
            mark: None,
            imported_by: sorted(verdict.importers.clone()),
            imported_by_packages: {
                let mut v: Vec<String> = verdict
                    .importing_packages
                    .iter()
                    .filter_map(|k| ids.get(k).cloned())
                    .collect();
                v.sort();
                v.dedup();
                v
            },
            state: pass.state,
            coverage: pass.coverage,
            // Finding paths are relative to the package, never the
            // root or the scan tree (KTD15).
            sites: pass
                .sites
                .iter()
                .map(|s| {
                    let mut s = s.clone();
                    s.file = rel_to(&s.file, inst.locator.as_bytes());
                    s
                })
                .collect(),
            blind_spots: pass
                .blind_spots
                .iter()
                .map(|b| {
                    let mut b = b.clone();
                    b.file = rel_to(&b.file, inst.locator.as_bytes());
                    b
                })
                .collect(),
            imports_unscanned: imports_unscanned(
                &pass.unscanned,
                &pass.unscanned_resolved,
                &closure.verdicts,
            ),
        };
        packages.push(entry);
    }

    // The auto-run inventory: `.pth`, `sitecustomize.py`, and
    // `usercustomize.py` files are listed whether or not anything
    // imports their distribution (KTD16, AE10).
    let mut auto_run: Vec<AutoRun> = invs
        .iter()
        .enumerate()
        .flat_map(|(ri, inv)| {
            inv.auto_runs.iter().map(move |a| AutoRun {
                id: String::new(),
                root: roots[ri].label.clone(),
                file: a.file.clone(),
                trigger: a.trigger,
                distribution: a.distribution.clone(),
            })
        })
        .collect();
    auto_run.sort_by(|a, b| (&a.root, &a.file).cmp(&(&b.root, &b.file)));

    // Linked entries for the remaining inventory of covered roots,
    // whether or not the closure reached them (KTD11).
    for (ri, root) in roots.iter().enumerate() {
        let label_bytes = root.label.as_bytes();
        if label_bytes == root.kind.as_str().as_bytes() {
            continue;
        }
        let covered = !discovery.excluded_dirs.iter().any(|d| {
            label_bytes == d.as_slice() || label_bytes.starts_with(&[d.as_slice(), b"/"].concat())
        });
        if !covered {
            continue;
        }
        for inst in &invs[ri].instances {
            // Reached instances already have entries; linked covers
            // the rest of the inventory.
            let reached = closure
                .verdicts
                .keys()
                .any(|(r, i)| *r == ri && *i == index_of(&invs[ri], inst));
            if !reached {
                packages.push(linked_entry(discovery, roots, ri, inst));
            }
        }
    }
    packages.sort_by(|a, b| {
        (&a.language, &a.package, &a.locator, &a.root).cmp(&(
            &b.language,
            &b.package,
            &b.locator,
            &b.root,
        ))
    });
    packages.dedup_by(|a, b| {
        a.package == b.package && a.locator == b.locator && a.root == b.root && a.linked == b.linked
    });

    // KTD13's top-level annotation happens in mod.rs over the
    // selection results; the section is assembled here.
    let caveats = caveats(&packages);
    diagnostics.sort_by(|a, b| (&a.lockfile, a.problem).cmp(&(&b.lockfile, b.problem)));
    diagnostics.dedup_by(|a, b| a.lockfile == b.lockfile && a.problem == b.problem);
    budgets.sort();
    budgets.dedup();
    Ok(Outcome {
        section: DependencySection {
            roots: roots
                .iter()
                .map(|r| egress_core::model::DependencyRoot {
                    label: r.label.clone(),
                    kind: r.kind,
                })
                .collect(),
            caveats,
            budget_exceeded: budgets,
            diagnostics,
            auto_run,
            packages,
        },
    })
}

fn index_of(inv: &Inventory, inst: &Instance) -> usize {
    inv.instances
        .iter()
        .position(|i| std::ptr::eq(i, inst))
        .unwrap_or(usize::MAX)
}

/// A linked entry for an in-tree covered instance (KTD11).
fn linked_entry(
    discovery: &Discovery,
    roots: &[NamedRoot],
    ri: usize,
    inst: &Instance,
) -> DependencyPackage {
    // The gate runs for linked entries too: the root's own ancestor
    // lockfile governs the in-tree install (KTD11).
    let lock = select::governing_lock(
        discovery,
        roots[ri].label.as_bytes(),
        roots[ri].kind,
        egress_core::discover::budgets::DependencyBudgets::embedded().lockfile_bytes,
    );
    let (strength, modified) = match super::closure::gate_instance(roots[ri].kind, inst, &lock) {
        Gate::Scan(s) => (
            s,
            super::closure::compute_modified(
                &roots[ri],
                inst,
                roots[ri].kind,
                &import_root(inst),
                discovery,
                &egress_core::discover::budgets::DependencyBudgets::embedded(),
            ),
        ),
        Gate::Unscanned(_) => (VerificationStrength::Unlocked, false),
    };
    DependencyPackage {
        id: String::new(),
        language: lang_of(roots[ri].kind),
        package: pkg_name(inst),
        root: roots[ri].label.clone(),
        locator: inst.locator.clone(),
        version: inst.version.clone(),
        strength,
        modified,
        linked: true,
        catalogued: false,
        distribution: Vec::new(),
        distribution_source: None,
        mark: None,
        imported_by: Vec::new(),
        imported_by_packages: Vec::new(),
        state: egress_core::model::CompletenessState::Complete,
        coverage: Default::default(),
        sites: Vec::new(),
        blind_spots: Vec::new(),
        imports_unscanned: Vec::new(),
    }
}

fn imports_unscanned(
    reasons: &[(Language, String, UnscannedReason)],
    resolved: &[(Language, String, usize, usize)],
    verdicts: &BTreeMap<(usize, usize), super::closure::Verdict>,
) -> Vec<ImportsUnscanned> {
    let mut v: Vec<ImportsUnscanned> = reasons
        .iter()
        .map(|(lang, package, reason)| ImportsUnscanned {
            language: *lang,
            package: egress_core::escape::escape(package),
            reason: *reason,
            distribution: Vec::new(),
            distribution_source: None,
            mark: None,
        })
        .collect();
    for (lang, package, r, i) in resolved {
        if let Some(verdict) = verdicts.get(&(*r, *i))
            && let Some(reason) = verdict.reason
        {
            v.push(ImportsUnscanned {
                language: *lang,
                package: egress_core::escape::escape(package),
                reason,
                distribution: Vec::new(),
                distribution_source: None,
                mark: None,
            });
        }
    }
    v.sort_by(|a, b| (&a.language, &a.package, a.reason).cmp(&(&b.language, &b.package, b.reason)));
    v.dedup_by(|a, b| a.package == b.package && a.language == b.language);
    v
}

/// The emitted package name: escaped for flagged instances (KTD24).
fn pkg_name(inst: &Instance) -> String {
    egress_core::escape::escape(&inst.package)
}

fn lang_of(kind: DependencyRootKind) -> Language {
    match kind {
        DependencyRootKind::Npm => Language::Javascript,
        DependencyRootKind::Python => Language::Python,
        _ => Language::Rust,
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

/// Whether the embedded catalog lists this package (KTD23).
fn catalogued(data: &Data, lang: Language, package: &str) -> bool {
    data.runtime(lang)
        .packages
        .iter()
        .any(|e| e.name == package)
}

/// The `#<n>` rank suffix when the governing Cargo.lock lists more
/// than one version of the name (KTD4).
fn locator_for(inst: &Instance, lock: &Lock) -> String {
    if let Lock::Parsed(select::LockSet::Cargo(l)) = lock {
        let suffix = locator::rank_suffix(l, &inst.package, &inst.version);
        if !suffix.is_empty() {
            return format!("{}{}", inst.locator, suffix);
        }
    }
    inst.locator.clone()
}

fn distribution_for(kind: DependencyRootKind, inst: &Instance) -> Vec<String> {
    match kind {
        DependencyRootKind::Python => inst.distribution.iter().cloned().collect(),
        _ => Vec::new(),
    }
}

fn source_for(
    kind: DependencyRootKind,
    inst: &Instance,
) -> Option<egress_core::model::DistributionSource> {
    match (kind, &inst.distribution) {
        (DependencyRootKind::Python, Some(_)) => {
            Some(egress_core::model::DistributionSource::InstalledMetadata)
        }
        _ => None,
    }
}

/// The dependency-section caveats (KTD10, KTD15).
fn caveats(packages: &[DependencyPackage]) -> Vec<String> {
    let mut v = Vec::new();
    if packages.iter().any(|p| !p.linked) {
        v.push("dependency-conditional-code-included".to_string());
    }
    if packages
        .iter()
        .any(|p| !p.linked && p.language == Language::Javascript)
    {
        v.push("dependency-exports-not-read".to_string());
    }
    v
}

/// The Python import root of an instance: `rel` minus its locator.
fn import_root(inst: &Instance) -> Vec<u8> {
    let locator = inst.locator.as_bytes();
    if inst.rel == locator {
        Vec::new()
    } else if inst.rel.ends_with(&[b"/".as_slice(), locator].concat()) {
        inst.rel[..inst.rel.len() - locator.len() - 1].to_vec()
    } else {
        match inst.rel.iter().rposition(|c| *c == b'/') {
            Some(i) => inst.rel[..i].to_vec(),
            None => Vec::new(),
        }
    }
}

/// A finding's path inside its package: `pkg/file.py` under the
/// `pkg` locator shows as `file.py`.
fn rel_to(file: &str, rel: &[u8]) -> String {
    let rel = String::from_utf8_lossy(rel).into_owned();
    file.strip_prefix(&format!("{rel}/"))
        .unwrap_or(file)
        .to_string()
}

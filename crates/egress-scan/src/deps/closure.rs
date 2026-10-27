//! The closure: breadth-first admission of resolved instances under
//! the dependency budgets, one confined tree pass per instance
//! (KTD9, KTD14), feeding externals back into selection.

use std::collections::BTreeMap;

use egress_core::data::Data;
use egress_core::deps::inventory::{Instance, Inventory};
use egress_core::deps::verify::{self, Gate};
use egress_core::discover::budgets::DependencyBudgets;
use egress_core::discover::completeness::state;
use egress_core::discover::dependency_roots::NamedRoot;
use egress_core::discover::{Discovery, discover_scoped};
use egress_core::model::{
    BlindSpot, BlindSpotKind, CompletenessState, Coverage, CoverageCounts, DependencyBudgetReason,
    DependencyRootKind, Language, LockfileDiagnostic, Site, ToolError, UnscannedReason,
};
use egress_core::paths::{dir_of, join};

use crate::ScanOptions;
use crate::tree;

use super::select::{self, Importer, Lock, LockSet, Resolved};

/// A resolved candidate on the closure frontier.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub root: usize,
    pub instance: usize,
    pub depth: u32,
    /// First-party files that reach it (display paths, sorted).
    pub importers: Vec<String>,
    /// (root, instance) of importing package entries (depth>0).
    pub importing_packages: Vec<(usize, usize)>,
    /// The governing lock, inherited from the first importer.
    pub lock: Lock,
}

/// The closure's verdict for one instance.
pub struct Verdict {
    /// The gate or budget reason when the candidate is not scanned.
    pub reason: Option<UnscannedReason>,
    /// The gate's strength when scanned.
    pub strength: Option<egress_core::model::VerificationStrength>,
    /// The governing lock the first importer handed down (KTD4 ranks
    /// Cargo locators from it).
    pub lock: Lock,
    /// Importers kept for the report when the entry materializes.
    pub importers: Vec<String>,
    /// (root, instance) of scanned entries that import it.
    pub importing_packages: Vec<(usize, usize)>,
    /// What the pass produced when scanned.
    pub pass: Option<InstancePass>,
}

/// What one admitted instance's tree pass produced.
pub struct InstancePass {
    pub sites: Vec<Site>,
    pub blind_spots: Vec<BlindSpot>,
    pub coverage: CoverageCounts,
    pub state: CompletenessState,
    /// Package keys the instance's code imports, for the next depth.
    pub externals: Vec<(Language, String)>,
    /// Externals that stayed unscanned, with reasons.
    pub unscanned: Vec<(Language, String, UnscannedReason)>,
    /// Externals resolved to an instance, for verdict lookup.
    pub unscanned_resolved: Vec<(Language, String, usize, usize)>,
    pub findings: u64,
    pub resolver_steps: u64,
    pub files: u64,
    pub bytes: u64,
    pub modified: bool,
}

/// Runs the closure over the depth-0 frontier.
pub struct Closure {
    /// Verdicts keyed by (root, instance).
    pub verdicts: BTreeMap<(usize, usize), Verdict>,
    /// Lockfile diagnostics collected along the way.
    pub diagnostics: Vec<LockfileDiagnostic>,
    /// The budgets exhausted during admission.
    pub budgets_exhausted: Vec<DependencyBudgetReason>,
}

/// BFS closure (KTD14): the frontier sorts by (depth, language,
/// package, locator); the first package that cannot be admitted
/// exhausts it and every later candidate.
pub fn run(
    data: &Data,
    discovery: &Discovery,
    roots: &[NamedRoot],
    invs: &[Inventory],
    mut frontier: Vec<Candidate>,
    options: &ScanOptions,
    budgets: &DependencyBudgets,
) -> Result<Closure, ToolError> {
    let ix = select::SelectIx::new(roots, invs);
    let mut verdicts: BTreeMap<(usize, usize), Verdict> = BTreeMap::new();
    let mut pending: BTreeMap<(usize, usize), Candidate> = BTreeMap::new();
    for c in std::mem::take(&mut frontier) {
        pending.entry((c.root, c.instance)).or_insert(c);
    }
    let mut diagnostics = Vec::new();
    let mut budgets_exhausted = Vec::new();
    let mut exhausted = false;
    let mut files_left = budgets.files;
    let mut bytes_left = budgets.bytes;
    let mut findings_left = budgets.findings;
    let mut resolver_left = budgets.resolver_steps;
    let mut packages_left = budgets.packages;

    loop {
        // The frontier in KTD14 order.
        let mut level: Vec<Candidate> = pending.values().cloned().collect();
        level.sort_by(|a, b| {
            let ia = &invs[a.root].instances[a.instance];
            let ib = &invs[b.root].instances[b.instance];
            let ka = (
                a.depth,
                lang_of(roots[a.root].kind),
                &ia.package,
                &ia.locator,
            );
            let kb = (
                b.depth,
                lang_of(roots[b.root].kind),
                &ib.package,
                &ib.locator,
            );
            ka.cmp(&kb)
        });
        if level.is_empty() {
            break;
        }
        for cand in level {
            pending.remove(&(cand.root, cand.instance));
            let key = (cand.root, cand.instance);
            if verdicts.contains_key(&key) {
                continue;
            }
            let inst = &invs[cand.root].instances[cand.instance];
            let kind = roots[cand.root].kind;
            if exhausted {
                verdicts.insert(
                    key,
                    Verdict {
                        reason: Some(UnscannedReason::DependencyBudgetExhausted),
                        strength: None,
                        lock: cand.lock.clone(),
                        importers: cand.importers.clone(),
                        importing_packages: cand.importing_packages.clone(),
                        pass: None,
                    },
                );
                continue;
            }
            let gate = gate_instance(kind, inst, &cand.lock);
            if let Gate::Unscanned(reason) = gate {
                verdicts.insert(
                    key,
                    Verdict {
                        reason: Some(reason),
                        strength: None,
                        lock: cand.lock.clone(),
                        importers: cand.importers.clone(),
                        importing_packages: cand.importing_packages.clone(),
                        pass: None,
                    },
                );
                continue;
            }
            if let Lock::Unreadable(d) = &cand.lock {
                diagnostics.push(d.clone());
            }
            if packages_left == 0 {
                verdicts.insert(
                    key,
                    Verdict {
                        reason: Some(UnscannedReason::DependencyBudgetExhausted),
                        strength: None,
                        lock: cand.lock.clone(),
                        importers: cand.importers.clone(),
                        importing_packages: cand.importing_packages.clone(),
                        pass: None,
                    },
                );
                exhausted = true;
                budgets_exhausted.push(DependencyBudgetReason::Packages);
                continue;
            }
            let mut pass = run_instance(data, &roots[cand.root], inst, kind, options)?;
            if pass.files > files_left || pass.bytes > bytes_left {
                exhausted = true;
                if pass.files > files_left {
                    budgets_exhausted.push(DependencyBudgetReason::Files);
                }
                if pass.bytes > bytes_left {
                    budgets_exhausted.push(DependencyBudgetReason::Bytes);
                }
                verdicts.insert(
                    key,
                    Verdict {
                        reason: Some(UnscannedReason::DependencyBudgetExhausted),
                        strength: None,
                        lock: cand.lock.clone(),
                        importers: cand.importers.clone(),
                        importing_packages: cand.importing_packages.clone(),
                        pass: None,
                    },
                );
                continue;
            }
            if pass.findings > findings_left || pass.resolver_steps > resolver_left {
                // A pass exceeding findings or resolver steps is
                // discarded whole (KTD14).
                exhausted = true;
                if pass.findings > findings_left {
                    budgets_exhausted.push(DependencyBudgetReason::Findings);
                }
                if pass.resolver_steps > resolver_left {
                    budgets_exhausted.push(DependencyBudgetReason::ResolverSteps);
                }
                verdicts.insert(
                    key,
                    Verdict {
                        reason: Some(UnscannedReason::DependencyBudgetExhausted),
                        strength: None,
                        lock: cand.lock.clone(),
                        importers: cand.importers.clone(),
                        importing_packages: cand.importing_packages.clone(),
                        pass: None,
                    },
                );
                continue;
            }
            packages_left -= 1;
            files_left -= pass.files;
            bytes_left -= pass.bytes;
            findings_left -= pass.findings;
            resolver_left -= pass.resolver_steps;
            // Queue externals at depth+1; a Reason or an instance the
            // gate later rejects stays in `imports_unscanned` (KTD12).
            for (lang, pkg) in pass.externals.clone() {
                let importer = Importer::InRoot {
                    root: cand.root,
                    file: inst.rel.clone(),
                };
                let pin = if lang == Language::Rust {
                    cargo_pin(&cand.lock, &inst.package, &pkg)
                } else {
                    None
                };
                match select::resolve(
                    &ix,
                    discovery.root_dir(),
                    lang,
                    &pkg,
                    &importer,
                    pin.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
                ) {
                    Resolved::Instance { root, instance } => {
                        let key2 = (root, instance);
                        if let Some(done) = verdicts.get_mut(&key2) {
                            // A cycle's back edge still records the
                            // importer on the already-scanned instance.
                            if !done.importing_packages.contains(&key) {
                                done.importing_packages.push(key);
                            }
                        } else {
                            let entry = pending.entry(key2).or_insert_with(|| Candidate {
                                root,
                                instance,
                                depth: cand.depth + 1,
                                importers: Vec::new(),
                                importing_packages: vec![key],
                                lock: cand.lock.clone(),
                            });
                            if entry.depth > cand.depth + 1 {
                                entry.depth = cand.depth + 1;
                            }
                            if !entry.importing_packages.contains(&key) {
                                entry.importing_packages.push(key);
                            }
                        }
                        // The instance's own verdict decides later; record
                        // the resolution so assembly can look it up.
                        pass.unscanned_resolved
                            .push((lang, pkg.clone(), root, instance));
                    }
                    Resolved::Reason(r) => {
                        pass.unscanned.push((lang, pkg, r));
                    }
                }
            }
            let Gate::Scan(strength) = gate else {
                unreachable!("unscanned handled above")
            };
            verdicts.insert(
                key,
                Verdict {
                    reason: None,
                    strength: Some(strength),
                    lock: cand.lock.clone(),
                    importers: cand.importers.clone(),
                    importing_packages: cand.importing_packages.clone(),
                    pass: Some(pass),
                },
            );
        }
    }
    diagnostics.sort_by(|a, b| (&a.lockfile, a.problem).cmp(&(&b.lockfile, b.problem)));
    diagnostics.dedup_by(|a, b| a.lockfile == b.lockfile && a.problem == b.problem);
    budgets_exhausted.sort();
    budgets_exhausted.dedup();
    Ok(Closure {
        verdicts,
        diagnostics,
        budgets_exhausted,
    })
}

fn lang_of(kind: DependencyRootKind) -> Language {
    kind.language()
}

/// The gate for one instance: inventory flags first, then the lock.
pub fn gate_instance(kind: DependencyRootKind, inst: &Instance, lock: &Lock) -> Gate {
    if inst.flags.unsupported.as_deref() == Some("archive-only-install") {
        return Gate::Unscanned(UnscannedReason::ArchiveOnlyInstall);
    }
    if inst.flags.unsupported.is_some()
        || inst.flags.escaped_name
        || inst.flags.store_layout
        || inst.flags.duplicate_index
    {
        return Gate::Unscanned(UnscannedReason::UnsupportedLayout);
    }
    // A distribution-less Python instance under a governing lock is
    // unsupported layout (KTD7), not version mismatch.
    if kind == DependencyRootKind::Python
        && matches!(lock, Lock::Parsed(_))
        && inst.distribution.is_none()
    {
        return Gate::Unscanned(UnscannedReason::UnsupportedLayout);
    }
    verify::gate(
        kind,
        lock.state(),
        version_match(kind, inst, lock),
        hashes(kind, inst),
    )
}

fn hashes(kind: DependencyRootKind, inst: &Instance) -> bool {
    matches!(
        kind,
        DependencyRootKind::Python | DependencyRootKind::CargoVendor
    ) && !inst.record.is_empty()
}

fn version_match(kind: DependencyRootKind, inst: &Instance, lock: &Lock) -> Option<bool> {
    use egress_core::deps::{lockfile, version};
    let Lock::Parsed(set) = lock else {
        return None;
    };
    Some(match (kind, set) {
        (
            DependencyRootKind::CargoVendor
            | DependencyRootKind::CargoRegistry
            | DependencyRootKind::CargoGit,
            LockSet::Cargo(l),
        ) => {
            let locked: Vec<_> = l
                .packages
                .iter()
                .filter(|p| lockfile::rust_eq(&p.name, &inst.package))
                .collect();
            if locked.is_empty() {
                false
            } else if kind == DependencyRootKind::CargoGit {
                // A git checkout matches by rev prefix, not the
                // package's own version string (KTD7).
                locked.iter().any(|p| {
                    inst.package_checksum.as_ref().is_some_and(|rev| {
                        p.source
                            .as_deref()
                            .is_some_and(|s| lockfile::rev_matches(rev, s))
                    })
                })
            } else {
                locked.iter().any(|p| p.version == inst.version)
            }
        }
        (DependencyRootKind::Npm, LockSet::Npm(l)) => l
            .packages
            .iter()
            .any(|(n, v)| n == &inst.package && version::npm_eq(&inst.version, v)),
        (DependencyRootKind::GoModuleCache, LockSet::Go(set)) => {
            set.contains(&(inst.package.clone(), inst.version.clone()))
        }
        (DependencyRootKind::Python, LockSet::Python(pkgs)) => {
            inst.distribution.as_ref().is_some_and(|d| {
                pkgs.iter().any(|(n, v)| {
                    version::pep503(n) == version::pep503(d) && version::pep440_eq(&inst.version, v)
                })
            })
        }
        _ => false,
    })
}

/// Runs one instance's confined pass (KTD9, KTD15).
fn run_instance(
    data: &Data,
    root: &NamedRoot,
    inst: &Instance,
    kind: DependencyRootKind,
    options: &ScanOptions,
) -> Result<InstancePass, ToolError> {
    // Per-ecosystem prefixes inside the root. The import root for a
    // Python instance is `rel` minus its locator path (a `.py` module
    // keeps the parent dir).
    let locator = inst.locator.as_bytes();
    let import_root = if inst.rel == locator {
        Vec::new()
    } else if inst.rel.ends_with(&join(b"/", locator)) {
        inst.rel[..inst.rel.len() - locator.len() - 1].to_vec()
    } else {
        dir_of(&inst.rel).to_vec()
    };
    let prefixes: Vec<Vec<u8>> = match kind {
        DependencyRootKind::Npm
        | DependencyRootKind::Python
        | DependencyRootKind::GoModuleCache => vec![inst.rel.clone()],
        // `src/` plus `build.rs` when present; an absent build script
        // is not a gap.
        _ => [b"src".as_slice(), b"build.rs"]
            .iter()
            .map(|n| join(&inst.rel, n))
            .filter(|p| root.dir.lstat(p).is_ok())
            .collect(),
    };
    let prefix_refs: Vec<&[u8]> = prefixes.iter().map(Vec::as_slice).collect();
    let mut d = discover_scoped(&root.dir, &prefix_refs, &options.config, None)?;
    // KTD15's Python cache rules: a `.pyc` beside a `.py` it covers
    // (or under `__pycache__/` for one) is dropped; an orphan `.pyc`,
    // `.pyd`, or `.so` keeps its per-file unsupported gap.
    if kind == DependencyRootKind::Python {
        let index = &d.index;
        d.blind_spots.retain(|b| {
            if b.kind != BlindSpotKind::UnsupportedFileType || !b.file.ends_with(".pyc") {
                return true;
            }
            let p = b.file.as_bytes();
            // `x.pyc` covers a sibling `x.py`.
            let py = [&p[..p.len() - 1], b""].concat();
            if index.contains_key(&py) {
                return false;
            }
            // `__pycache__/x.<tag>.pyc` covers `<parent>/x.py`.
            if let Some(stripped) = pycache_source(p)
                && index.contains_key(&stripped)
            {
                return false;
            }
            true
        });
    }
    // The Python dependency rules probe the import root only.
    let overrides: Vec<(Language, Box<dyn egress_core::resolve::SpecifierRules>)> =
        if kind == DependencyRootKind::Python {
            options
                .registry
                .get(Language::Python)
                .and_then(|fe| fe.dependency_rules(&import_root))
                .map(|r| vec![(Language::Python, r)])
                .unwrap_or_default()
        } else {
            Vec::new()
        };
    let pass = tree::run(
        data,
        &d,
        options,
        &tree::TreeOptions {
            overrides: &overrides,
            resolver_budget: u64::MAX,
            derived_sites: false,
        },
    )?;
    let st = state(&pass.coverage, &pass.blind_spots, &pass.budget_exceeded);
    // Package-relative file names: npm/Cargo strip the instance dir;
    // Python strips the import root (KTD9).
    let strip = match kind {
        DependencyRootKind::Python => import_root.clone(),
        _ => inst.rel.clone(),
    };
    let rel = |p: &str| -> String {
        let b = p.as_bytes();
        if !strip.is_empty() && b.starts_with(&strip) && b.len() > strip.len() {
            String::from_utf8_lossy(&b[strip.len() + 1..]).into_owned()
        } else {
            p.to_string()
        }
    };
    let sites: Vec<Site> = pass
        .classified
        .sites
        .iter()
        .map(|s| Site {
            file: rel(&s.file),
            ..s.clone()
        })
        .collect();
    let mut blind_spots: Vec<BlindSpot> = pass
        .blind_spots
        .iter()
        .map(|b| BlindSpot {
            file: rel(&b.file),
            ..b.clone()
        })
        .collect();
    // A cargo instance's `build.rs` is a build hook by layout; the
    // manifest-driven hook detector has no manifests inside a
    // package, so the layout rule fires here (KTD15).
    if matches!(
        kind,
        DependencyRootKind::CargoVendor
            | DependencyRootKind::CargoRegistry
            | DependencyRootKind::CargoGit
    ) {
        let build = join(&inst.rel, b"build.rs");
        if d.index.contains_key(&build) {
            let enc = egress_core::identity::encode_path_bytes(b"build.rs");
            blind_spots.push(BlindSpot {
                id: String::new(),
                language: Some(Language::Rust),
                file: enc.display,
                file_bytes: enc.bytes_hex,
                symbol: "<module>".into(),
                kind: BlindSpotKind::BuildHook,
                whole_file: false,
                coverage_gap: false,
                construct: "build-script".into(),
                ordinal: 0,
                labels: Vec::new(),
                location: None,
            });
        }
    }
    let externals: Vec<(Language, String)> = pass
        .classified
        .unscanned_dependencies
        .iter()
        .map(|u| (u.language, u.package.clone()))
        .collect();
    // The modified mark: per-file hashes, read for admitted packages
    // only (KTD14). The record's paths sit under the instance's
    // import root (Python) or the package dir (vendor).
    let modified = compute_modified(
        root,
        inst,
        kind,
        &import_root,
        &d,
        &options.dependency_budgets,
    );
    let findings =
        (sites.len() + blind_spots.len() + pass.classified.unscanned_dependencies.len()) as u64;
    Ok(InstancePass {
        sites,
        blind_spots,
        coverage: lang_coverage(&pass.coverage, lang_of(kind)),
        state: st,
        externals,
        unscanned: Vec::new(),
        unscanned_resolved: Vec::new(),
        findings,
        resolver_steps: pass.classified.resolver_steps,
        files: d.sources.len() as u64,
        bytes: d.sources.iter().map(|s| s.size).sum(),
        modified,
    })
}

/// The per-file hash comparison for an admitted instance (KTD8):
/// every listed file is read and hashed; a listed file missing or
/// unreadable, a hash that differs, or a package file the record does
/// not list (`__pycache__/` excepted) marks the package modified.
pub fn compute_modified(
    root: &NamedRoot,
    inst: &Instance,
    kind: DependencyRootKind,
    import_root: &[u8],
    d: &Discovery,
    budgets: &DependencyBudgets,
) -> bool {
    if inst.record.is_empty() {
        return false;
    }
    // Record paths: RECORD is relative to the import root; the vendor
    // checksum map is relative to the package dir.
    let base = match kind {
        DependencyRootKind::Python => import_root.to_vec(),
        _ => inst.rel.clone(),
    };
    let mut files: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (path, _hash) in &inst.record {
        let rel = join(&base, path);
        if let Ok(bytes) = root.dir.read_file(&rel, budgets.bytes) {
            files.push((rel, bytes));
        }
    }
    // Unlisted files under the package: every indexed path under the
    // instance's own prefix, minus `__pycache__/`.
    let prefix = match kind {
        DependencyRootKind::Python => Vec::new(),
        _ => join(&inst.rel, b""),
    };
    let recorded: std::collections::HashSet<Vec<u8>> =
        files.iter().map(|(p, _)| p.clone()).collect();
    for path in d.index.keys() {
        if path.split(|&b| b == b'/').any(|s| s == b"__pycache__") {
            continue;
        }
        if !prefix.is_empty() && !path.starts_with(&prefix) {
            continue;
        }
        if !recorded.contains(path) {
            files.push((path.clone(), Vec::new()));
        }
    }
    verify::compare_files(
        &files,
        &inst
            .record
            .iter()
            .map(|(p, h)| (join(&base, p), h.clone()))
            .collect::<Vec<_>>(),
        kind == DependencyRootKind::Python,
    )
    .modified
}

/// The source path a `__pycache__/<x>.<tag>.pyc` covers.
fn pycache_source(p: &[u8]) -> Option<Vec<u8>> {
    let name = p.rsplit(|c| *c == b'/').next()?;
    let stem = name.split(|c| *c == b'.').next()?;
    let dir_end = p.len() - name.len() - 1;
    let dir = &p[..dir_end];
    let parent = &dir[..dir.len().checked_sub(b"__pycache__".len())?];
    Some([parent, stem, b".py"].concat())
}

fn lang_coverage(c: &Coverage, lang: Language) -> CoverageCounts {
    c.languages.get(lang).copied().unwrap_or_default()
}

/// A Cargo dependency edge from the importing package's governing
/// lock: `imp`'s own `dependencies` edges name the locked version of
/// `dep` (KTD5, KTD7).
pub fn cargo_pin(lock: &Lock, imp: &str, dep: &str) -> Option<(String, String)> {
    let Lock::Parsed(LockSet::Cargo(l)) = lock else {
        return None;
    };
    let importer = l
        .by_name
        .get(&imp.replace('-', "_"))
        .and_then(|c| c.first())
        .map(|&i| &l.packages[i])?;
    importer
        .dependencies
        .iter()
        .filter_map(|e| egress_core::deps::lockfile::resolve_edge(l, e))
        .find(|p| egress_core::deps::lockfile::rust_eq(&p.name, dep))
        .map(|p| (p.name.clone(), p.version.clone()))
}

//! Selection: which instance an import reaches, and which gate it
//! passes (KTD5, KTD6, KTD7). Everything here works on already-open
//! handles and the first-party index; nothing new is opened outside
//! named roots.

use egress_core::deps::inventory::{Instance, Inventory};
use egress_core::deps::lockfile::{self, CargoLock, LockfileResult};
use egress_core::deps::verify::LockState;
use egress_core::discover::Discovery;
use egress_core::discover::dependency_roots::NamedRoot;
use egress_core::discover::open::{EntryType, RootDir};
use egress_core::model::{
    DependencyRootKind, Language, LockfileDiagnostic, LockfileProblem, UnscannedReason,
};

/// The outcome of resolving one import against the named roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// A named instance the import reaches.
    Instance { root: usize, instance: usize },
    /// The reason it stays unscanned.
    Reason(UnscannedReason),
}

/// Where an import was seen: a first-party file at depth 0, or a file
/// inside a named root at depth >0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Importer {
    /// Repo-relative file inside the scan root.
    FirstParty(Vec<u8>),
    /// File relative to a named root (its `rel` prefix is the
    /// importing package's `rel`).
    InRoot { root: usize, file: Vec<u8> },
}

/// The governing lockfile for one ecosystem at one point in the run.
#[derive(Debug, Clone)]
pub enum Lock {
    /// No supported lockfile sits in an ancestor directory.
    Absent,
    /// It could not be used; the diagnostic lands in the section.
    Unreadable(LockfileDiagnostic),
    /// A supported lockfile parsed.
    Parsed(LockSet),
}

/// The locked (name -> version) sets per ecosystem.
#[derive(Debug, Clone)]
pub enum LockSet {
    Cargo(CargoLock),
    Npm(lockfile::NpmLock),
    /// poetry.lock and uv.lock pool their versions in one directory.
    Python(Vec<(String, String)>),
}

impl Lock {
    pub fn state(&self) -> LockState {
        match self {
            Lock::Absent => LockState::Absent,
            Lock::Unreadable(_) => LockState::Unreadable,
            Lock::Parsed(_) => LockState::Governing,
        }
    }
}

/// Finds the nearest supported lockfile in an ancestor directory of
/// `file` (a repo-relative first-party path) for `ecosystem`. The
/// directory holding it is also returned for diagnostics.
pub fn governing_lock(
    discovery: &Discovery,
    file: &[u8],
    ecosystem: Option<DependencyRootKind>,
    lockfile_bytes: u64,
) -> Lock {
    // A language with no dependency root kind reads no lockfile.
    let Some(ecosystem) = ecosystem else {
        return Lock::Absent;
    };
    let lock_names: &[&[u8]] = match ecosystem {
        DependencyRootKind::CargoVendor
        | DependencyRootKind::CargoRegistry
        | DependencyRootKind::CargoGit => &[b"Cargo.lock"],
        DependencyRootKind::Npm => &[b"package-lock.json"],
        DependencyRootKind::Python => &[b"poetry.lock", b"uv.lock"],
    };
    // Ancestors of the importer, nearest first: `a/b/f.py` checks
    // `a/b`, `a`, then the scan root.
    let mut dir: Vec<u8> = file.to_vec();
    loop {
        if let Some(i) = dir.iter().rposition(|b| *b == b'/') {
            dir.truncate(i);
        } else {
            dir.clear();
        }
        let mut unreadable: Option<LockfileDiagnostic> = None;
        let mut parsed: Option<LockSet> = None;
        for name in lock_names {
            let rel = if dir.is_empty() {
                name.to_vec()
            } else {
                [dir.as_slice(), b"/", name].concat()
            };
            if !discovery.index.contains_key(&rel) {
                continue;
            }
            let bytes = match discovery.read_indexed(&rel, lockfile_bytes) {
                Ok(b) => b,
                Err(_) => {
                    unreadable = Some(LockfileDiagnostic {
                        lockfile: String::from_utf8_lossy(&rel).into_owned(),
                        problem: LockfileProblem::Unreadable,
                    });
                    continue;
                }
            };
            if bytes.len() as u64 > lockfile_bytes {
                unreadable = Some(LockfileDiagnostic {
                    lockfile: String::from_utf8_lossy(&rel).into_owned(),
                    problem: LockfileProblem::TooLarge,
                });
                continue;
            }
            let result = match ecosystem {
                DependencyRootKind::Npm => match lockfile::package_lock(&bytes) {
                    LockfileResult::Parsed(l) => LockfileResult::Parsed(LockSet::Npm(l)),
                    LockfileResult::NotSupported => LockfileResult::NotSupported,
                    LockfileResult::Unreadable => LockfileResult::Unreadable,
                },
                DependencyRootKind::Python => match *name {
                    b"poetry.lock" => match lockfile::poetry_lock(&bytes) {
                        LockfileResult::Parsed(l) => {
                            LockfileResult::Parsed(LockSet::Python(l.packages))
                        }
                        LockfileResult::NotSupported => LockfileResult::NotSupported,
                        LockfileResult::Unreadable => LockfileResult::Unreadable,
                    },
                    _ => match lockfile::uv_lock(&bytes) {
                        LockfileResult::Parsed(l) => {
                            LockfileResult::Parsed(LockSet::Python(l.packages))
                        }
                        LockfileResult::NotSupported => LockfileResult::NotSupported,
                        LockfileResult::Unreadable => LockfileResult::Unreadable,
                    },
                },
                _ => match cargo_lock_support(&bytes) {
                    LockfileResult::Parsed(l) => LockfileResult::Parsed(LockSet::Cargo(l)),
                    LockfileResult::NotSupported => LockfileResult::NotSupported,
                    LockfileResult::Unreadable => LockfileResult::Unreadable,
                },
            };
            match result {
                LockfileResult::Parsed(LockSet::Python(pkgs)) => {
                    // poetry.lock and uv.lock pool in one directory.
                    match &mut parsed {
                        Some(LockSet::Python(existing)) => existing.extend(pkgs),
                        None => parsed = Some(LockSet::Python(pkgs)),
                        _ => unreachable!(),
                    }
                }
                LockfileResult::Parsed(set) => parsed = Some(set),
                LockfileResult::NotSupported => {}
                LockfileResult::Unreadable => {
                    unreadable = Some(LockfileDiagnostic {
                        lockfile: String::from_utf8_lossy(&rel).into_owned(),
                        problem: LockfileProblem::ParseError,
                    });
                }
            }
        }
        if let Some(d) = unreadable {
            return Lock::Unreadable(d);
        }
        if let Some(set) = parsed {
            return Lock::Parsed(set);
        }
        if dir.is_empty() {
            return Lock::Absent;
        }
    }
}

/// Cargo.lock support check: `cargo_lock_result` splits the matrix's
/// three answers already.
fn cargo_lock_support(bytes: &[u8]) -> LockfileResult<CargoLock> {
    lockfile::cargo_lock_result(bytes)
}

/// Resolves one import to an instance or a reason (KTD5).
pub fn resolve(
    roots: &[NamedRoot],
    invs: &[Inventory],
    scan: &RootDir,
    lang: Language,
    package: &str,
    importer: &Importer,
    pin: Option<(&str, &str)>,
) -> Resolved {
    match lang {
        Language::Javascript => resolve_npm(roots, invs, scan, package, importer),
        Language::Python => resolve_python(roots, invs, package),
        Language::Rust => resolve_cargo(roots, invs, package, importer, pin),
        // No Go module root kind exists yet, so no named root can hold
        // the source a Go import names.
        Language::Go => Resolved::Reason(UnscannedReason::NoSourceInNamedRoot),
    }
}

fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        name.to_vec()
    } else {
        [dir, b"/", name].concat()
    }
}

/// npm: Node's ancestor walk for the importing file, nearest
/// `node_modules/<pkg>` holder wins; a non-directory holder stops the
/// walk with unsupported layout; a holder under no named root is no
/// source (KTD5, AE13).
fn resolve_npm(
    roots: &[NamedRoot],
    invs: &[Inventory],
    scan: &RootDir,
    package: &str,
    importer: &Importer,
) -> Resolved {
    let npm = |i: usize| roots[i].kind == DependencyRootKind::Npm;
    // The candidate path inside one named root for ancestor `anc`:
    // in-root ancestors give `<anc>/node_modules/<pkg>`; the root itself
    // is a `node_modules` directory, so inside it the walk is
    // `<anc>/node_modules/<pkg>` relative to the root's parent.
    let (file, root): (&[u8], &RootDir) = match importer {
        Importer::FirstParty(f) => (f.as_slice(), scan),
        Importer::InRoot { root, file } => (file.as_slice(), &roots[*root].dir),
    };
    let importer_root = match importer {
        Importer::FirstParty(_) => None,
        Importer::InRoot { root, .. } => Some(*root),
    };
    if importer_root.is_none() && pnp_ancestor(scan, file) {
        return Resolved::Reason(UnscannedReason::ArchiveOnlyInstall);
    }
    // The importing file's directory is the first ancestor; an InRoot
    // importer passes its package directory already.
    let mut dir: Vec<u8> = if importer_root.is_some() {
        file.to_vec()
    } else {
        let f = file.to_vec();
        match f.iter().rposition(|b| *b == b'/') {
            Some(i) => f[..i].to_vec(),
            None => Vec::new(),
        }
    };
    loop {
        // Inside an npm root, the root itself is the `node_modules`
        // directory: its empty-ancestor level resolves `<pkg>`
        // directly. Everywhere else the ancestor walk appends
        // `node_modules/<pkg>`.
        let candidate = if dir.is_empty() && importer_root.is_some() {
            package.as_bytes().to_vec()
        } else {
            join(&join(&dir, b"node_modules"), package.as_bytes())
        };
        match root.lstat(&candidate) {
            Ok(st) if st.kind == EntryType::Dir => {
                // Find the instance at this candidate path: inside the
                // same root for dep-internal imports, or across named
                // npm roots for first-party imports (the root's own
                // location relative to the scan root prefixes `rel`).
                for (ri, inv) in invs.iter().enumerate() {
                    if !npm(ri) {
                        continue;
                    }
                    for (ii, inst) in inv.instances.iter().enumerate() {
                        if instance_at_npm(&roots[ri], inst, importer_root, ri, &candidate, scan) {
                            return Resolved::Instance {
                                root: ri,
                                instance: ii,
                            };
                        }
                    }
                }
                return Resolved::Reason(UnscannedReason::NoSourceInNamedRoot);
            }
            Ok(_) => {
                // Nearest holder is a symlink or a file: Node stops
                // here and so do we (AE13's link stop).
                return Resolved::Reason(UnscannedReason::UnsupportedLayout);
            }
            Err(_) => {}
        }
        if dir.is_empty() {
            break;
        }
        if let Some(i) = dir.iter().rposition(|b| *b == b'/') {
            dir.truncate(i);
        } else {
            dir.clear();
        }
    }
    // Ancestors above the scan root: outside npm roots answer the
    // remaining levels, nearest parent of the scan root first.
    if importer_root.is_none() {
        let mut outside: Vec<usize> = invs
            .iter()
            .enumerate()
            .filter(|(i, _)| npm(*i) && !roots[*i].canonical.starts_with(scan.path()))
            .map(|(i, _)| i)
            .collect();
        outside.sort_by_key(|i| std::cmp::Reverse(roots[*i].canonical.components().count()));
        for ri in outside {
            match roots[ri].dir.lstat(package.as_bytes()) {
                Ok(st) if st.kind == EntryType::Dir => {
                    for (ii, inst) in invs[ri].instances.iter().enumerate() {
                        if inst.rel == package.as_bytes()
                            || inst
                                .rel
                                .starts_with(&join(package.as_bytes(), b"/node_modules/"))
                        {
                            return Resolved::Instance {
                                root: ri,
                                instance: ii,
                            };
                        }
                    }
                    return Resolved::Reason(UnscannedReason::NoSourceInNamedRoot);
                }
                Ok(_) => return Resolved::Reason(UnscannedReason::UnsupportedLayout),
                Err(_) => continue,
            }
        }
    }
    Resolved::Reason(UnscannedReason::NoSourceInNamedRoot)
}

/// Whether `inst` sits at `candidate`: for first-party imports the
/// candidate is scan-root-relative and the root's own path prefixes
/// it; for dep-internal imports both are root-relative.
fn instance_at_npm(
    root: &NamedRoot,
    inst: &Instance,
    importer_root: Option<usize>,
    ri: usize,
    candidate: &[u8],
    scan: &RootDir,
) -> bool {
    if importer_root == Some(ri) {
        return inst.rel == candidate;
    }
    // A named root inside the scan root: its canonical path relative
    // to the scan root prefixes every instance `rel`. The label only
    // carries a path when the root sits inside the scan tree.
    if !root.canonical.starts_with(scan.path()) {
        return false;
    }
    candidate == join(root.label.as_bytes(), &inst.rel)
}

/// Python: one environment across the named roots; the full dotted
/// specifier descends to the instance listing it or one of its
/// prefixes (KTD5, KTD10's namespace keys).
fn resolve_python(roots: &[NamedRoot], invs: &[Inventory], key: &str) -> Resolved {
    let mut cand = key;
    loop {
        for (ri, inv) in invs.iter().enumerate() {
            if roots[ri].kind != DependencyRootKind::Python {
                continue;
            }
            for (ii, inst) in inv.instances.iter().enumerate() {
                if inst.imports.iter().any(|n| n == cand) {
                    return Resolved::Instance {
                        root: ri,
                        instance: ii,
                    };
                }
            }
        }
        match cand.rfind('.') {
            Some(i) => cand = &cand[..i],
            None => break,
        }
    }
    Resolved::Reason(UnscannedReason::NoSourceInNamedRoot)
}

/// Rust: the locked name (hyphen-folded) picks the instance among
/// cargo roots; the first-party crate's lock edge fixes the version
/// when the governing lock names one (KTD5).
fn resolve_cargo(
    roots: &[NamedRoot],
    invs: &[Inventory],
    package: &str,
    _importer: &Importer,
    pin: Option<(&str, &str)>,
) -> Resolved {
    // The importer's Cargo.lock edge names the locked version when
    // several instances share a name (KTD5, KTD7).
    if let Some((pn, pv)) = pin {
        for (ri, inv) in invs.iter().enumerate() {
            if !matches!(
                roots[ri].kind,
                DependencyRootKind::CargoVendor
                    | DependencyRootKind::CargoRegistry
                    | DependencyRootKind::CargoGit
            ) {
                continue;
            }
            for (ii, inst) in inv.instances.iter().enumerate() {
                if lockfile::rust_eq(&inst.package, pn) && inst.version == pv {
                    return Resolved::Instance {
                        root: ri,
                        instance: ii,
                    };
                }
            }
        }
    }
    for (ri, inv) in invs.iter().enumerate() {
        let kind = roots[ri].kind;
        if !matches!(
            kind,
            DependencyRootKind::CargoVendor
                | DependencyRootKind::CargoRegistry
                | DependencyRootKind::CargoGit
        ) {
            continue;
        }
        for (ii, inst) in inv.instances.iter().enumerate() {
            if inst.imports.iter().any(|n| lockfile::rust_eq(n, package)) {
                return Resolved::Instance {
                    root: ri,
                    instance: ii,
                };
            }
        }
    }
    Resolved::Reason(UnscannedReason::NoSourceInNamedRoot)
}

/// Yarn PnP detection for a first-party importer file (KTD3): a
/// `.pnp.cjs` in any ancestor directory inside the scan root marks
/// every JavaScript import archive-only, named roots or not.
pub fn pnp_ancestor(scan: &egress_core::discover::open::RootDir, file: &[u8]) -> bool {
    let mut dir = file.to_vec();
    loop {
        if matches!(scan.lstat(&join(&dir, b".pnp.cjs")), Ok(st) if st.kind == EntryType::File) {
            return true;
        }
        match dir.iter().rposition(|b| *b == b'/') {
            Some(i) => dir.truncate(i),
            None => {
                dir.clear();
            }
        }
        if dir.is_empty() {
            // The empty-level check runs before the loop exits.
            return matches!(scan.lstat(&join(&dir, b".pnp.cjs")), Ok(st) if st.kind == EntryType::File);
        }
    }
}

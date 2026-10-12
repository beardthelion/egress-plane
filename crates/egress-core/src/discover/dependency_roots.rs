//! Named dependency roots: opening, overlap validation, and kind
//! detection (KTD2, KTD3).
//!
//! Each path named by `--deps` is opened once with [`RootDir::open`],
//! which canonicalizes it and so resolves a symbolic link at the named
//! path itself; links inside a root are never followed (R2). Validation
//! runs in argument order: a path that does not exist, is not a
//! directory, or matches no marker-table kind is a tool error, as is a
//! root that equals or contains the scan root or lies strictly inside
//! another named root. A root equal to an earlier one is dropped.
//! Detection reads directory entries only, never file contents, and the
//! whole root's markers come from one listing of the root plus one of
//! each child for the two-level registry and git layouts (KTD3). Every
//! failure is a `ToolError::DependencyRoot` that names the 1-based
//! argument ordinal and never a path.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::model::{DependencyRootKind, DependencyRootProblem, ToolError};

use super::open::{EntryType, RootDir};

/// A named dependency root that passed validation.
#[derive(Debug)]
pub struct NamedRoot {
    /// Open handle on the canonical root; all package reads stay inside
    /// it (KTD24).
    pub dir: RootDir,
    /// Detected kind from the marker table (KTD3).
    pub kind: DependencyRootKind,
    /// Report label: the canonical path relative to the scan root for a
    /// root inside it, else the kind name (KTD4).
    pub label: String,
    /// 1-based ordinal of the `--deps` argument that named this root.
    pub ordinal: usize,
    /// Canonical path, used only for overlap checks; never printed (R2).
    pub canonical: PathBuf,
}

fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        name.to_vec()
    } else {
        [dir, b"/", name].concat()
    }
}

fn is_kind(dir: &RootDir, rel: &[u8], kinds: &[EntryType]) -> bool {
    matches!(dir.lstat(rel), Ok(st) if kinds.contains(&st.kind))
}

/// The marker-table kinds a root's layout matches (KTD3). Detection reads
/// one listing of the root plus, for the two-level registry and git
/// layouts, one listing of each child directory.
fn detect(dir: &RootDir) -> Result<Vec<DependencyRootKind>, DependencyRootProblem> {
    let entries = dir
        .list_dir(b"")
        .map_err(|_| DependencyRootProblem::Unreadable)?;
    let has_file = |name: &[u8]| {
        entries
            .iter()
            .any(|(e, st)| e == name && st.kind == EntryType::File)
    };
    let children: Vec<&[u8]> = entries
        .iter()
        .filter(|(_, st)| st.kind == EntryType::Dir)
        .map(|(e, _)| e.as_slice())
        .collect();
    let basename = dir.path().file_name().map(|n| n.as_bytes().to_vec());

    let mut kinds = Vec::new();
    // npm: basename `node_modules`, or a child `.package-lock.json`.
    if basename.as_deref() == Some(b"node_modules") || has_file(b".package-lock.json") {
        kinds.push(DependencyRootKind::Npm);
    }
    // python: a `pyvenv.cfg` child (venv), or a `*.dist-info` child
    // directory (site-packages, dist-packages, pip --target).
    if has_file(b"pyvenv.cfg") || children.iter().any(|e| e.ends_with(b".dist-info")) {
        kinds.push(DependencyRootKind::Python);
    }
    // cargo-vendor: a child directory holding `.cargo-checksum.json`. A
    // Go, PHP, or Ruby vendor tree matches nothing.
    if children
        .iter()
        .any(|e| is_kind(dir, &join(e, b".cargo-checksum.json"), &[EntryType::File]))
    {
        kinds.push(DependencyRootKind::CargoVendor);
    }
    // cargo-registry: the named path is `registry/src` (children are
    // index directories whose children hold `.cargo-ok` and
    // `Cargo.toml.orig`) or one index directory (children hold them
    // directly). cargo-git: `git/checkouts` (`<repo>-<hash>/<rev>/`
    // holding `.cargo-ok` and `.git`).
    let mut registry = false;
    let mut git = false;
    for e in &children {
        if is_kind(dir, &join(e, b".cargo-ok"), &[EntryType::File])
            && is_kind(dir, &join(e, b"Cargo.toml.orig"), &[EntryType::File])
        {
            registry = true;
        }
        let Ok(grand) = dir.list_dir(e) else {
            continue;
        };
        for (g, st) in &grand {
            if st.kind != EntryType::Dir {
                continue;
            }
            let base = join(e, g);
            if !is_kind(dir, &join(&base, b".cargo-ok"), &[EntryType::File]) {
                continue;
            }
            if is_kind(dir, &join(&base, b"Cargo.toml.orig"), &[EntryType::File]) {
                registry = true;
            }
            if is_kind(
                dir,
                &join(&base, b".git"),
                &[EntryType::Dir, EntryType::File],
            ) {
                git = true;
            }
        }
    }
    if registry {
        kinds.push(DependencyRootKind::CargoRegistry);
    }
    if git {
        kinds.push(DependencyRootKind::CargoGit);
    }
    Ok(kinds)
}

/// The report label: the canonical path relative to the scan root for a
/// root inside it, else the kind name (KTD4). Never absolute.
fn label(canonical: &Path, scan: &Path, kind: DependencyRootKind) -> String {
    match canonical.strip_prefix(scan) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
        _ => kind.as_str().to_string(),
    }
}

/// Opens and validates every named root in argument order against the
/// already-open `scan_root` (KTD2). The result lists each distinct
/// canonical root once, in first-mention order.
pub fn open(scan_root: &RootDir, roots: &[PathBuf]) -> Result<Vec<NamedRoot>, ToolError> {
    let scan = scan_root.path();
    let mut out: Vec<NamedRoot> = Vec::new();
    for (i, path) in roots.iter().enumerate() {
        let ordinal = i + 1;
        let err = |problem| ToolError::DependencyRoot { ordinal, problem };
        let dir = match RootDir::open(path) {
            Ok(d) => d,
            Err(ToolError::RootNotDirectory) => {
                return Err(err(DependencyRootProblem::NotDirectory));
            }
            Err(_) => return Err(err(DependencyRootProblem::NotFound)),
        };
        let canonical = dir.path().to_path_buf();
        let kinds = detect(&dir).map_err(err)?;
        let [kind] = kinds.as_slice() else {
            return Err(err(DependencyRootProblem::UnrecognizedLayout));
        };
        let kind = *kind;
        // A root equal to or containing the scan root is unusable.
        if scan.starts_with(&canonical) {
            return Err(err(DependencyRootProblem::OverlapsScanRoot));
        }
        // An npm root outside the scan root is reachable only when its
        // parent directory is an ancestor of the scan root, matching
        // Node's lookup (KTD5).
        if kind == DependencyRootKind::Npm
            && !canonical.starts_with(scan)
            && canonical.parent().is_none_or(|p| !scan.starts_with(p))
        {
            return Err(err(DependencyRootProblem::NpmNotOnLookupPath));
        }
        // A root equal to an earlier root is dropped.
        if out.iter().any(|r| r.canonical == canonical) {
            continue;
        }
        out.push(NamedRoot {
            label: label(&canonical, scan, kind),
            dir,
            kind,
            ordinal,
            canonical,
        });
    }
    // A root strictly inside another named root is a tool error; the
    // ordinal names the inner root.
    for r in &out {
        if out
            .iter()
            .any(|o| !std::ptr::eq(r, o) && r.canonical.starts_with(&o.canonical))
        {
            return Err(ToolError::DependencyRoot {
                ordinal: r.ordinal,
                problem: DependencyRootProblem::InsideAnotherRoot,
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Inventory (U4): the package instances each kind of root holds.
// ---------------------------------------------------------------------------

use crate::deps::inventory::{Instance, InstanceFlags, Inventory};
use crate::deps::locator::{instance_locator, strip_version};
use crate::deps::metadata;
use crate::escape::needs_escape;
use crate::model::DependencyRootKind::*;

use super::Discovery;
use super::budgets::DependencyBudgets;

/// A name that is not UTF-8, or that holds an `escape::needs_escape`
/// character, is never emitted raw (KTD24). The instance is flagged
/// unsupported and its names are escaped.
fn clean_name(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?;
    if s.chars().any(needs_escape) {
        return None;
    }
    Some(s.to_string())
}

/// The escaped display form KTD24 allows for a flagged name.
pub fn escaped_name(raw: &[u8]) -> String {
    crate::escape::escape(&String::from_utf8_lossy(raw))
}

/// Reads one file inside a root under the `metadata_bytes` cap. An
/// absent file yields `Ok(None)`; anything over cap or unreadable is
/// `Err` and flags the instance, not the root.
fn read_meta(
    dir: &RootDir,
    rel: &[u8],
    budgets: &DependencyBudgets,
) -> Option<Result<Vec<u8>, ()>> {
    match dir.read_file(rel, budgets.metadata_bytes) {
        Ok(bytes) => Some(Ok(bytes)),
        Err(super::open::ReadError::NotRegular) => None,
        Err(_) => Some(Err(())),
    }
}

/// Inventory every root; the ambiguity errors of KTD4 and KTD5 run over
/// the joined result. `discovery` reads in-root lockfiles.
pub fn inventory(
    roots: &[NamedRoot],
    discovery: &Discovery,
    budgets: &DependencyBudgets,
) -> Result<Vec<Inventory>, ToolError> {
    let mut out = Vec::new();
    for root in roots {
        out.push(match root.kind {
            Npm => npm_inventory(root, budgets),
            Python => python_inventory(root, budgets),
            CargoVendor => vendor_inventory(root, budgets),
            CargoRegistry => registry_inventory(root, discovery, budgets),
            CargoGit => git_inventory(root, budgets),
        });
    }
    // KTD5: two Python roots holding the same top-level import name.
    let pythons: Vec<usize> = roots
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == Python)
        .map(|(i, _)| i)
        .collect();
    for &i in &pythons {
        for &j in &pythons {
            if j <= i {
                continue;
            }
            let clash = out[i].instances.iter().any(|a| {
                a.imports
                    .iter()
                    .any(|n| out[j].instances.iter().any(|b| b.imports.contains(n)))
            });
            if clash {
                return Err(ToolError::DependencyRoot {
                    ordinal: roots[j].ordinal,
                    problem: DependencyRootProblem::AmbiguousEnvironment,
                });
            }
        }
    }
    // KTD4/AE11: two roots OUTSIDE the scan root of the same kind and
    // language holding the same locator are a tool error.
    for i in 0..out.len() {
        for j in (i + 1)..out.len() {
            if roots[i].kind != roots[j].kind {
                continue;
            }
            if !roots[i].canonical.starts_with(discovery.root_dir().path())
                && !roots[j].canonical.starts_with(discovery.root_dir().path())
            {
                let clash = out[i]
                    .instances
                    .iter()
                    .any(|a| out[j].instances.iter().any(|b| a.locator == b.locator));
                if clash {
                    return Err(ToolError::DependencyRoot {
                        ordinal: roots[j].ordinal,
                        problem: DependencyRootProblem::AmbiguousRoots,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// npm: package children, `@scope` children, and nested `node_modules`
/// recursively (KTD4 chain). `.pnpm` marks the root as the pnpm store
/// layout; symlinked package dirs are never followed or listed (KTD5).
fn npm_inventory(root: &NamedRoot, budgets: &DependencyBudgets) -> Inventory {
    struct Acc<'a> {
        budgets: &'a DependencyBudgets,
        instances: Vec<Instance>,
        entries: u64,
        exceeded: bool,
        store_layout: bool,
    }

    impl Acc<'_> {
        fn list(&mut self, dir: &RootDir, rel: &[u8]) -> Vec<(Vec<u8>, super::open::Stat)> {
            let Ok(v) = dir.list_dir(rel) else {
                return Vec::new();
            };
            self.entries = self.entries.saturating_add(v.len() as u64);
            if self.entries > self.budgets.inventory_entries {
                self.exceeded = true;
            }
            v
        }

        /// Walk `<parent>`'s children as packages at depth `chain`.
        fn walk(&mut self, dir: &RootDir, parent: &[u8], chain: &mut [String]) {
            for (name, st) in self.list(dir, parent).clone() {
                if name.as_slice() == b".pnpm" {
                    self.store_layout = true;
                    continue;
                }
                if st.kind != super::open::EntryType::Dir {
                    continue;
                }
                let rel = join(parent, &name);
                if name.starts_with(b"@") {
                    for (sub, sst) in self.list(dir, &rel).clone() {
                        if sst.kind != super::open::EntryType::Dir {
                            continue;
                        }
                        let mut parts = chain.to_vec();
                        parts.push(format!(
                            "{}/{}",
                            String::from_utf8_lossy(&name),
                            String::from_utf8_lossy(&sub)
                        ));
                        self.one(dir, &join(&rel, &sub), &parts);
                    }
                    continue;
                }
                let mut parts = chain.to_vec();
                parts.push(String::from_utf8_lossy(&name).into_owned());
                self.one(dir, &rel, &parts);
            }
        }

        /// Record one package instance at `rel` whose chain is `parts`,
        /// then descend into its nested `node_modules`.
        fn one(&mut self, dir: &RootDir, rel: &[u8], parts: &[String]) {
            let mut flags = InstanceFlags::default();
            let dir_name = rel.rsplit(|c| *c == b'/').next().unwrap_or(rel);
            if clean_name(dir_name).is_none() {
                flags.escaped_name = true;
            }
            let (pkg_name, version) =
                match read_meta(dir, &join(rel, b"package.json"), self.budgets) {
                    Some(Ok(bytes)) => match metadata::package_json(&bytes) {
                        Ok(m) => (m.name, m.version),
                        Err(_) => {
                            flags.unsupported = Some("unreadable-metadata".to_string());
                            (
                                clean_name(dir_name).unwrap_or_else(|| escaped_name(dir_name)),
                                String::new(),
                            )
                        }
                    },
                    _ => {
                        flags.unsupported = Some("unreadable-metadata".to_string());
                        (
                            clean_name(dir_name).unwrap_or_else(|| escaped_name(dir_name)),
                            String::new(),
                        )
                    }
                };
            let mut parts = parts.to_vec();
            if parts.last().is_some_and(|p| p != &pkg_name) && !pkg_name.is_empty() {
                // The display chain ends on the package name from
                // package.json.
                *parts.last_mut().unwrap() = pkg_name.clone();
            }
            self.instances.push(Instance {
                package: pkg_name.clone(),
                locator: instance_locator(Npm, &parts),
                version,
                rel: rel.to_vec(),
                imports: vec![pkg_name],
                distribution: None,
                record: Vec::new(),
                package_checksum: None,
                flags,
            });
            let mut chain = parts;
            self.walk(dir, &join(rel, b"node_modules"), &mut chain);
        }
    }

    let mut acc = Acc {
        budgets,
        instances: Vec::new(),
        entries: 0,
        exceeded: false,
        store_layout: false,
    };
    acc.walk(&root.dir, b"", &mut Vec::new());
    if acc.store_layout {
        for i in &mut acc.instances {
            i.flags.store_layout = true;
        }
    }
    Inventory {
        kind: Npm,
        instances: acc.instances,
        entries_exceeded: acc.exceeded,
    }
}

/// Python: the import root of the venv or site-packages, the dist-info
/// mapping, and the loose top-level names (KTD5).
fn python_inventory(root: &NamedRoot, budgets: &DependencyBudgets) -> Inventory {
    let mut instances = Vec::new();
    let mut entries = 0u64;
    let mut exceeded = false;
    let mut import_root: Vec<u8> = Vec::new();

    let is_venv = matches!(
        root.dir.lstat(b"pyvenv.cfg"),
        Ok(st) if st.kind == super::open::EntryType::File
    );
    if is_venv {
        // `lib/python<X.Y>/site-packages`; more than one python* dir is
        // the ambiguous-environment tool error.
        if let Ok(libs) = root.dir.list_dir(b"lib") {
            entries += libs.len() as u64;
            let pythons: Vec<Vec<u8>> = libs
                .iter()
                .filter(|(n, st)| {
                    n.starts_with(b"python") && st.kind == super::open::EntryType::Dir
                })
                .map(|(n, _)| n.clone())
                .collect();
            if let Some(p) = pythons.first() {
                import_root = join(b"lib", &join(p, b"site-packages"));
            }
        }
    }

    let Ok(listing) = root.dir.list_dir(&import_root) else {
        return Inventory {
            kind: Python,
            instances,
            entries_exceeded: exceeded,
        };
    };
    entries += listing.len() as u64;
    if entries > budgets.inventory_entries {
        exceeded = true;
    }

    let mut dist_tops: Vec<(Vec<u8>, Vec<String>)> = Vec::new();
    for (name, st) in &listing {
        if st.kind != super::open::EntryType::Dir {
            continue;
        }
        let dir = join(&import_root, name);
        if name.ends_with(b".dist-info") {
            let meta_rel = join(&dir, b"METADATA");
            let (pkg, version) = match read_meta(&root.dir, &meta_rel, budgets) {
                Some(Ok(bytes)) => match metadata::metadata(&bytes) {
                    Ok(m) => (m.name, m.version),
                    Err(_) => (
                        clean_name(name.trim_ascii_end()).unwrap_or_else(|| escaped_name(name)),
                        String::new(),
                    ),
                },
                _ => (String::new(), String::new()),
            };
            let record_rel = join(&dir, b"RECORD");
            let rows = match read_meta(&root.dir, &record_rel, budgets) {
                Some(Ok(bytes)) => metadata::record(&bytes).unwrap_or_default(),
                _ => Vec::new(),
            };
            let mut tops = metadata::top_level_names(&rows);
            // A `.py` module in the RECORD counts as a top-level of
            // this dist only when its stem matches the dist's own
            // normalized name; a module filed under an unrelated dist
            // is a loose top-level module instead (KTD7).
            let norm_pkg = crate::deps::version::pep503(&pkg);
            tops.retain(|t| {
                !rows.iter().any(|r| {
                    r.path.rsplit('/').next() == Some(&format!("{t}.py")) && !r.path.contains('/')
                }) || crate::deps::version::pep503(t) == norm_pkg
            });
            let top_rel = join(&dir, b"top_level.txt");
            if let Some(Ok(bytes)) = read_meta(&root.dir, &top_rel, budgets) {
                for t in metadata::top_level(&bytes) {
                    if !tops.contains(&t) {
                        tops.push(t);
                    }
                }
            }
            dist_tops.push((name.clone(), tops.clone()));
            let mut flags = InstanceFlags::default();
            if pkg.is_empty() {
                flags.unsupported = Some("unreadable-metadata".to_string());
            }
            if clean_name(name).is_none() {
                flags.escaped_name = true;
            }
            // One instance per import key: each top-level name descends
            // through namespace directories to the deepest package that
            // holds `__init__.py`, so `google/` (no init) + `google/auth/`
            // keys as `google.auth` at locator `google/auth` (KTD10).
            let keys = python_keys(&root.dir, &import_root, &tops);
            let record: Vec<(Vec<u8>, String)> = rows
                .iter()
                .filter_map(|r| {
                    r.sha256
                        .as_ref()
                        .map(|h| (r.path.clone().into_bytes(), h.clone()))
                })
                .collect();
            for (key, path) in keys {
                // The locator is the path relative to the import root.
                let locator_path = path[import_root.len()..]
                    .strip_prefix(b"/")
                    .unwrap_or(&path[import_root.len()..])
                    .to_vec();
                instances.push(Instance {
                    package: key.clone(),
                    locator: String::from_utf8_lossy(&locator_path).into_owned(),
                    version: version.clone(),
                    rel: join(&import_root, &locator_path),
                    imports: vec![key.clone()],
                    distribution: Some(pkg.clone()),
                    record: record.clone(),
                    package_checksum: None,
                    flags: flags.clone(),
                });
            }
        }
    }

    // Loose names: top-level packages, modules, and special layouts a
    // dist-info's RECORD does not cover. A `.py` file is covered only
    // by a dist whose normalized name matches its stem (KTD7).
    let covered: Vec<&str> = dist_tops
        .iter()
        .flat_map(|(_, t)| t.iter().map(String::as_str))
        .collect();
    for (name, st) in &listing {
        let dir = join(&import_root, name);
        let Some(name_str) = clean_name(name) else {
            continue;
        };
        if covered.contains(&name_str.split('.').next().unwrap_or(&name_str))
            || name.ends_with(b".dist-info")
            || name == b"bin"
            || name == b"__pycache__"
        {
            continue;
        }
        let mut flags = InstanceFlags::default();
        let mut imports = Vec::new();
        let mut package = name_str.clone();
        if name.ends_with(b".egg") {
            flags.unsupported = Some("archive-only-install".to_string());
            let stem = name
                .strip_suffix(b".egg")
                .unwrap_or(name)
                .split(|c| *c == b'-')
                .next()
                .unwrap_or(name);
            package = String::from_utf8_lossy(stem).into_owned();
            imports.push(package.clone());
        } else if name.ends_with(b".egg-info") || name.starts_with(b"__editable__") {
            flags.unsupported = Some("unsupported-layout".to_string());
            // `leftpy-1.0.egg-info` and `__editable__.leftpy-1.0` hold
            // the import name minus the layout suffix and version.
            let stem = name_str
                .trim_end_matches(".egg-info")
                .trim_start_matches("__editable__.")
                .trim_end_matches(".pth");
            let stem = stem.rsplit_once('-').map(|(n, _)| n).unwrap_or(stem);
            package = stem.to_string();
            imports.push(package.clone());
        } else if name.ends_with(b".pth") {
            // A .pth file is an auto-run artifact, not a package; its
            // trigger lines are inventoried by U9.
            continue;
        } else if st.kind == super::open::EntryType::Dir {
            // Top-level package with no dist-info: namespace or orphan.
            imports.push(name_str.clone());
        } else if name.ends_with(b".py") {
            package = name_str.trim_end_matches(".py").to_string();
            imports.push(package.clone());
        } else {
            continue;
        }
        instances.push(Instance {
            package,
            locator: name_str.clone(),
            version: String::new(),
            rel: dir,
            imports,
            distribution: None,
            record: Vec::new(),
            package_checksum: None,
            flags,
        });
    }

    Inventory {
        kind: Python,
        instances,
        entries_exceeded: exceeded,
    }
}

/// cargo-vendor: `<name>-<version>` directories holding
/// `.cargo-checksum.json`.
fn vendor_inventory(root: &NamedRoot, budgets: &DependencyBudgets) -> Inventory {
    let mut instances = Vec::new();
    let mut entries = 0u64;
    let mut exceeded = false;
    let Ok(listing) = root.dir.list_dir(b"") else {
        return Inventory {
            kind: CargoVendor,
            instances,
            entries_exceeded: exceeded,
        };
    };
    entries += listing.len() as u64;
    if entries > budgets.inventory_entries {
        exceeded = true;
    }
    for (name, st) in &listing {
        if st.kind != super::open::EntryType::Dir {
            continue;
        }
        if !is_kind(
            &root.dir,
            &join(name, b".cargo-checksum.json"),
            &[super::open::EntryType::File],
        ) {
            continue;
        }
        let mut flags = InstanceFlags::default();
        if clean_name(name).is_none() {
            flags.escaped_name = true;
        }
        let pkg = strip_version(&String::from_utf8_lossy(name));
        let (mut version, mut record, mut checksum) = (String::new(), Vec::new(), None);
        match read_meta(&root.dir, &join(name, b".cargo-checksum.json"), budgets) {
            Some(Ok(bytes)) => match metadata::cargo_checksum(&bytes) {
                Ok(c) => {
                    record = c
                        .files
                        .iter()
                        .map(|(p, h)| (p.clone().into_bytes(), h.clone()))
                        .collect();
                    checksum = c.package;
                }
                Err(_) => flags.unsupported = Some("unreadable-metadata".to_string()),
            },
            _ => flags.unsupported = Some("unreadable-metadata".to_string()),
        }
        let mut imports = vec![pkg.clone()];
        if let Some(Ok(bytes)) = read_meta(&root.dir, &join(name, b"Cargo.toml"), budgets) {
            if let Ok((_n, v)) = metadata::cargo_toml_name_version(&bytes) {
                version = v;
            }
            if let Some(lib) = metadata::cargo_toml_lib_name(&bytes)
                && lib != pkg
            {
                imports.push(lib);
            }
        }
        if version.is_empty() {
            version = name
                .rsplit(|c| *c == b'-')
                .next()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default();
        }
        instances.push(Instance {
            package: pkg.clone(),
            locator: pkg.clone(),
            version,
            rel: name.clone(),
            imports,
            distribution: None,
            record,
            package_checksum: checksum,
            flags,
        });
    }
    Inventory {
        kind: CargoVendor,
        instances,
        entries_exceeded: exceeded,
    }
}

/// cargo-registry: probe only the `<name>-<version>` directories a
/// supported `Cargo.lock` in the scan root lists, under each index
/// directory (KTD6's cost bound).
fn registry_inventory(
    root: &NamedRoot,
    discovery: &Discovery,
    budgets: &DependencyBudgets,
) -> Inventory {
    let mut instances = Vec::new();
    let mut exceeded = false;
    // The scan root's supported Cargo.lock files.
    let lock = lock_names(discovery, budgets);
    let Ok(indexes) = root.dir.list_dir(b"") else {
        return Inventory {
            kind: CargoRegistry,
            instances,
            entries_exceeded: exceeded,
        };
    };
    let mut entries = indexes.len() as u64;
    if entries > budgets.inventory_entries {
        exceeded = true;
    }
    let mut seen: Vec<(String, String, Vec<u8>)> = Vec::new();
    for (index, st) in &indexes {
        if st.kind != super::open::EntryType::Dir {
            continue;
        }
        // The name set: locked entries when a lock governs, or every
        // `<name>-<version>` directory present when no lock does (the
        // unlocked cache still resolves, KTD6). Metadata is read only
        // for locked names (KTD6's cost bound).
        let mut names: Vec<(String, String)> = lock.clone();
        if lock.is_empty()
            && let Ok(children) = root.dir.list_dir(index)
        {
            for (child, st) in &children {
                if st.kind != super::open::EntryType::Dir {
                    continue;
                }
                let child = String::from_utf8_lossy(child).into_owned();
                if let Some(pos) = child.rfind('-') {
                    let (n, v) = (child[..pos].to_string(), child[pos + 1..].to_string());
                    if !names.iter().any(|(n2, v2)| n2 == &n && v2 == &v) {
                        names.push((n, v));
                    }
                }
            }
        }
        for (name, version) in &names {
            let locked = lock.iter().any(|(n, v)| n == name && v == version);
            let dir = format!("{}-{}", name, version);
            let rel = join(index, dir.as_bytes());
            if !matches!(root.dir.lstat(&rel), Ok(s) if s.kind == super::open::EntryType::Dir) {
                continue;
            }
            entries += 1;
            if entries > budgets.inventory_entries {
                exceeded = true;
            }
            let mut flags = InstanceFlags::default();
            if seen
                .iter()
                .any(|(n, v, i)| n == name && v == version && i != index)
            {
                flags.duplicate_index = true;
            }
            seen.push((name.clone(), version.clone(), index.clone()));
            let mut record = Vec::new();
            let mut checksum = None;
            if locked
                && let Some(Ok(bytes)) =
                    read_meta(&root.dir, &join(&rel, b".cargo-checksum.json"), budgets)
                && let Ok(c) = metadata::cargo_checksum(&bytes)
            {
                record = c
                    .files
                    .iter()
                    .map(|(p, h)| (p.clone().into_bytes(), h.clone()))
                    .collect();
                checksum = c.package;
            }
            let mut imports = vec![name.clone()];
            if locked
                && let Some(Ok(bytes)) = read_meta(&root.dir, &join(&rel, b"Cargo.toml"), budgets)
                && let Some(lib) = metadata::cargo_toml_lib_name(&bytes)
                && lib != *name
            {
                imports.push(lib);
            }
            instances.push(Instance {
                package: name.clone(),
                locator: name.clone(),
                version: version.clone(),
                rel,
                imports,
                distribution: None,
                record,
                package_checksum: checksum,
                flags,
            });
        }
    }
    // Every copy of a name+version under more than one index
    // directory is unsupported, not just the second (KTD6).
    let counts: std::collections::BTreeMap<(String, String), usize> = instances
        .iter()
        .map(|i| ((i.package.clone(), i.version.clone()), 1))
        .fold(std::collections::BTreeMap::new(), |mut m, (k, n)| {
            *m.entry(k).or_insert(0) += n;
            m
        });
    for i in instances.iter_mut() {
        if counts
            .get(&(i.package.clone(), i.version.clone()))
            .is_some_and(|n| *n > 1)
        {
            i.flags.duplicate_index = true;
        }
    }
    Inventory {
        kind: CargoRegistry,
        instances,
        entries_exceeded: exceeded,
    }
}

/// cargo-git: `<repo>-<hash>/<rev>` checkouts; the package name comes
/// from the checkout's `Cargo.toml`.
fn git_inventory(root: &NamedRoot, budgets: &DependencyBudgets) -> Inventory {
    let mut instances = Vec::new();
    let mut entries = 0u64;
    let mut exceeded = false;
    let Ok(repos) = root.dir.list_dir(b"") else {
        return Inventory {
            kind: CargoGit,
            instances,
            entries_exceeded: exceeded,
        };
    };
    for (repo, st) in &repos {
        if st.kind != super::open::EntryType::Dir {
            continue;
        }
        let Ok(revs) = root.dir.list_dir(repo) else {
            continue;
        };
        entries += revs.len() as u64;
        if entries > budgets.inventory_entries {
            exceeded = true;
        }
        for (rev, rst) in &revs {
            if rst.kind != super::open::EntryType::Dir {
                continue;
            }
            let rel = join(repo, rev);
            // The checkout may hold multiple manifests; a package's
            // name comes from each `Cargo.toml` under the checkout.
            let mut found = Vec::new();
            collect_manifests(&root.dir, &rel, &mut found, 0);
            // A checkout holding more than one package manifest is
            // unsupported layout (U4 test matrix).
            if found.len() > 1 {
                let flags = InstanceFlags {
                    unsupported: Some("unsupported-layout".to_string()),
                    ..Default::default()
                };
                instances.push(Instance {
                    package: String::from_utf8_lossy(repo).into_owned(),
                    locator: String::from_utf8_lossy(repo).into_owned(),
                    version: String::new(),
                    rel: rel.clone(),
                    imports: Vec::new(),
                    distribution: None,
                    record: Vec::new(),
                    package_checksum: None,
                    flags,
                });
                continue;
            }
            for m in found {
                let Some(Ok(bytes)) = read_meta(&root.dir, &m, budgets) else {
                    continue;
                };
                let Ok((name, version)) = metadata::cargo_toml_name_version(&bytes) else {
                    continue;
                };
                let mut flags = InstanceFlags::default();
                if clean_name(&m).is_none() {
                    flags.escaped_name = true;
                }
                let mut imports = vec![name.clone()];
                if let Some(lib) = metadata::cargo_toml_lib_name(&bytes)
                    && lib != name
                {
                    imports.push(lib);
                }
                instances.push(Instance {
                    package: name.clone(),
                    locator: name.clone(),
                    version,
                    rel: rel.clone(),
                    imports,
                    distribution: None,
                    record: Vec::new(),
                    // The checkout's short rev, for the KTD7 prefix
                    // match against the lock source's `#<sha>`.
                    package_checksum: Some(String::from_utf8_lossy(rev).into_owned()),
                    flags,
                });
            }
        }
    }
    Inventory {
        kind: CargoGit,
        instances,
        entries_exceeded: exceeded,
    }
}

/// Depth-capped manifest walk inside a git checkout: `Cargo.toml` files
/// only, at most depth 4.
fn collect_manifests(dir: &RootDir, rel: &[u8], out: &mut Vec<Vec<u8>>, depth: u8) {
    if depth > 4 {
        return;
    }
    if is_kind(
        dir,
        &join(rel, b"Cargo.toml"),
        &[super::open::EntryType::File],
    ) {
        out.push(join(rel, b"Cargo.toml"));
    }
    let Ok(entries) = dir.list_dir(rel) else {
        return;
    };
    for (name, st) in &entries {
        if st.kind != super::open::EntryType::Dir || name.starts_with(b".") {
            continue;
        }
        collect_manifests(dir, &join(rel, name), out, depth + 1);
    }
}

/// The (name, version) pairs a supported `Cargo.lock` in the scan root
/// lists, read through the discovery index under `lockfile_bytes`
/// (KTD24).
fn lock_names(discovery: &Discovery, budgets: &DependencyBudgets) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for path in discovery.index.keys() {
        let name = path.rsplit(|c| *c == b'/').next().unwrap_or(path);
        if name != b"Cargo.lock" {
            continue;
        }
        let Ok(bytes) = discovery.read_indexed(path, budgets.lockfile_bytes) else {
            continue;
        };
        let Ok(lock) = crate::deps::lockfile::cargo_lock(&bytes) else {
            continue;
        };
        for p in &lock.packages {
            if p.source
                .as_deref()
                .is_some_and(|s| s.starts_with("registry+"))
            {
                out.push((p.name.clone(), p.version.clone()));
            }
        }
    }
    out
}

/// Resolves a distribution's top-level names to (import key, path)
/// pairs, descending through PEP 420 namespace directories (no
/// `__init__.py`) to the deepest package holding one (KTD10).
fn python_keys(
    dir: &super::open::RootDir,
    import_root: &[u8],
    tops: &[String],
) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for top in tops {
        walk_namespace(
            dir,
            join(import_root, top.as_bytes()),
            top.clone(),
            &mut out,
        );
    }
    out
}

fn walk_namespace(
    dir: &super::open::RootDir,
    path: Vec<u8>,
    key: String,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    // A file's own name is the key.
    match dir.lstat(&join(&path, b"__init__.py")) {
        Ok(st) if st.kind == super::open::EntryType::File => {
            out.push((key, path));
            return;
        }
        _ => {}
    }
    // No `__init__.py`: a namespace directory; descend into child
    // directories that hold one.
    let mut found = false;
    if let Ok(children) = dir.list_dir(&path) {
        for (name, st) in children {
            if st.kind != super::open::EntryType::Dir {
                continue;
            }
            let child_path = join(&path, &name);
            if matches!(dir.lstat(&join(&child_path, b"__init__.py")), Ok(s) if s.kind == super::open::EntryType::File)
            {
                let mut child_key = key.clone();
                child_key.push('.');
                child_key.push_str(&String::from_utf8_lossy(&name));
                out.push((child_key, child_path));
                found = true;
            }
        }
    }
    if !found {
        out.push((key, path));
    }
}

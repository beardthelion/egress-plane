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

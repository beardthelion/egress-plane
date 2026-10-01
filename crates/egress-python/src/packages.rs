//! Python module specifier rules (KTD16).
//!
//! A relative specifier (`.net`, `..a.b`, `.`) resolves against the
//! importing file's package directory. An absolute specifier probes each
//! package root: the scan root, `src/`, and every directory that contains
//! the importing file. KTD16 names the scan root, `src/`, and any directory
//! holding `pyproject.toml`, `setup.py`, or `setup.cfg`; the rules cannot see
//! the file index, so they probe every ancestor of the importing file
//! instead, which covers the roots of the project the file belongs to (and
//! the directory a script runs from) at the cost of also probing ancestors
//! without a manifest. Each module probes `<path>.py` then
//! `<path>/__init__.py`. Stub files (`.pyi`) carry no runtime code and are
//! never resolution targets.

use egress_core::resolve::{SpecifierKind, SpecifierRules};

#[derive(Debug, Clone, Copy, Default)]
pub struct PythonRules;

/// The directory components of `path` (everything before the last `/`).
fn dir_components(path: &[u8]) -> Vec<&[u8]> {
    let mut parts: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
    parts.pop();
    parts.retain(|p| !p.is_empty());
    parts
}

fn join(dir: &[&[u8]], module: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in dir.iter().copied().chain(module.iter().map(|m| m.as_bytes())) {
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    out
}

fn with_suffix(mut base: Vec<u8>, suffix: &str) -> Vec<u8> {
    if base.is_empty() {
        base.extend_from_slice(suffix.trim_start_matches('/').as_bytes());
    } else {
        base.extend_from_slice(suffix.as_bytes());
    }
    base
}

/// `<dir>/<module>.py` then `<dir>/<module>/__init__.py`, or only the
/// package `__init__.py` when `module` is empty.
fn module_probes(dir: &[&[u8]], module: &[&str], out: &mut Vec<Vec<u8>>) {
    let base = join(dir, module);
    if !module.is_empty() {
        out.push(with_suffix(base.clone(), ".py"));
    }
    out.push(with_suffix(base, "/__init__.py"));
}

impl SpecifierRules for PythonRules {
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind {
        let dots = specifier.len() - specifier.trim_start_matches('.').len();
        let rest = &specifier[dots..];
        let module: Vec<&str> = if rest.is_empty() {
            Vec::new()
        } else {
            rest.split('.').collect()
        };
        if module.iter().any(|m| m.is_empty()) {
            // `a..b` names no module.
            return SpecifierKind::Bare {
                probes: Vec::new(),
                module: specifier.to_string(),
            };
        }
        let dir = dir_components(from);
        if dots > 0 {
            // One dot is the importing file's own package.
            let up = dots - 1;
            if up > dir.len() {
                return SpecifierKind::OutsideRoot;
            }
            let mut probes = Vec::new();
            module_probes(&dir[..dir.len() - up], &module, &mut probes);
            return SpecifierKind::Path { probes };
        }
        let mut roots: Vec<Vec<&[u8]>> = vec![Vec::new(), vec![b"src".as_slice()]];
        for n in (1..=dir.len()).rev() {
            let r = dir[..n].to_vec();
            if !roots.contains(&r) {
                roots.push(r);
            }
        }
        let mut probes = Vec::new();
        for r in &roots {
            module_probes(r, &module, &mut probes);
        }
        SpecifierKind::Bare {
            probes,
            module: specifier.to_string(),
        }
    }

    fn submodule(&self, specifier: &str, member: &str) -> Option<String> {
        if specifier.ends_with('.') {
            Some(format!("{specifier}{member}"))
        } else {
            Some(format!("{specifier}.{member}"))
        }
    }
}

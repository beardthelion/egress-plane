//! Crate module trees and specifier rules (KTD12, KTD16).
//!
//! The frontend writes module specifiers in a few fixed forms (see
//! [`crate::spec`]). These rules turn each form into candidate paths in
//! discovery's file index, using what only the whole program reveals: the
//! crate roots that Cargo manifests declare, the module tree that `mod`
//! declarations build from those roots, dependency renames, and sibling
//! workspace crates. Every target maps into the file index; nothing here
//! opens a path.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use egress_core::discover::FileKind;
use egress_core::discover::manifests::{BuildScript, CargoManifest, Manifests, fold};
use egress_core::ir::{ConstructKind, DynamicConstruct, FileIr};
use egress_core::model::Language;
use egress_core::resolve::{SpecifierKind, SpecifierRules};

use crate::spec;

fn dir_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[..i],
        None => b"",
    }
}

fn name_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

fn join(dir: &[u8], rest: &str) -> Vec<u8> {
    let mut p = dir.to_vec();
    if !p.is_empty() {
        p.push(b'/');
    }
    p.extend_from_slice(rest.as_bytes());
    p
}

/// A crate name as Rust source spells it.
fn crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Where a file sits in its crate's module tree.
#[derive(Debug, Clone)]
struct FileInfo {
    /// The crate root file.
    root: Vec<u8>,
    /// The declaring file and whether the declaration sits in that file's
    /// root namespace (not inside an inline module); `None` for a crate root.
    parent: Option<(Vec<u8>, bool)>,
    /// Whether nested `mod` declarations resolve beside the file (`mod.rs`,
    /// crate roots, and files reached through `#[path]`).
    modrs: bool,
}

#[derive(Debug, Clone)]
struct Package {
    dir: Vec<u8>,
    renames: HashMap<String, String>,
    inherited: BTreeSet<String>,
    proc_macro: bool,
    lib: Option<Vec<u8>>,
    main: Option<Vec<u8>>,
}

/// Specifier rules for one scanned program.
#[derive(Debug, Clone, Default)]
pub struct RustRules {
    sources: BTreeSet<Vec<u8>>,
    files: HashMap<Vec<u8>, FileInfo>,
    packages: Vec<Package>,
    /// Lib crates by crate name (package name and `[lib] name`).
    libs: BTreeMap<String, Vec<u8>>,
    /// Crate names of first-party proc-macro packages.
    proc_macros: BTreeSet<String>,
    workspace_renames: Vec<(Vec<u8>, HashMap<String, String>)>,
}

impl RustRules {
    /// Builds the rules from the manifests, the file index, and every lowered
    /// Rust file.
    pub fn build(
        manifests: &Manifests,
        index: &BTreeMap<Vec<u8>, FileKind>,
        files: &[(&[u8], &FileIr)],
    ) -> RustRules {
        let sources: BTreeSet<Vec<u8>> = index
            .iter()
            .filter(|(_, k)| **k == FileKind::Source(Language::Rust))
            .map(|(p, _)| p.clone())
            .collect();
        let mut rules = RustRules {
            sources,
            ..RustRules::default()
        };
        let mut roots: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut cargo: Vec<&CargoManifest> = manifests.cargo.iter().collect();
        cargo.sort_by(|a, b| a.path.cmp(&b.path));
        for m in &cargo {
            let dir = dir_of(&m.path).to_vec();
            let renames: HashMap<String, String> = m
                .workspace_renames
                .iter()
                .map(|(k, p)| (crate_name(k), crate_name(p)))
                .collect();
            if !renames.is_empty() {
                rules.workspace_renames.push((dir.clone(), renames));
            }
            if !m.has_package {
                continue;
            }
            let lib = m
                .lib_path
                .clone()
                .or_else(|| Some(join(&dir, "src/lib.rs")))
                .filter(|p| rules.sources.contains(p));
            let main = Some(join(&dir, "src/main.rs")).filter(|p| rules.sources.contains(p));
            if let Some(l) = &lib {
                for name in [m.name.clone(), m.lib_name.clone()].into_iter().flatten() {
                    rules
                        .libs
                        .entry(crate_name(&name))
                        .or_insert_with(|| l.clone());
                }
            }
            if m.proc_macro {
                for name in [m.name.clone(), m.lib_name.clone()].into_iter().flatten() {
                    rules.proc_macros.insert(crate_name(&name));
                }
            }
            roots.extend(lib.iter().cloned());
            roots.extend(main.iter().cloned());
            roots.extend(
                m.targets
                    .iter()
                    .filter(|p| rules.sources.contains(*p))
                    .cloned(),
            );
            match &m.build {
                BuildScript::Path(p) => {
                    roots.extend(Some(p.clone()).filter(|p| rules.sources.contains(p)))
                }
                BuildScript::Default => {
                    roots.extend(Some(join(&dir, "build.rs")).filter(|p| rules.sources.contains(p)))
                }
                BuildScript::Disabled | BuildScript::Outside => {}
            }
            for sub in ["src/bin", "tests", "examples", "benches"] {
                let base = join(&dir, sub);
                for p in &rules.sources {
                    if dir_of(p) == base.as_slice()
                        || (sub == "src/bin"
                            && dir_of(dir_of(p)) == base.as_slice()
                            && name_of(p) == b"main.rs")
                    {
                        roots.insert(p.clone());
                    }
                }
            }
            rules.packages.push(Package {
                dir,
                renames: m
                    .renames
                    .iter()
                    .map(|(k, p)| (crate_name(k), crate_name(p)))
                    .collect(),
                inherited: m.inherited.iter().map(|k| crate_name(k)).collect(),
                proc_macro: m.proc_macro,
                lib,
                main,
            });
        }
        // Crate roots without a manifest still start a tree.
        for p in &rules.sources {
            let name = name_of(p);
            if (name == b"lib.rs" || name == b"main.rs") && name_of(dir_of(p)) == b"src" {
                roots.insert(p.clone());
            }
        }
        // Longest package directory first, so the nearest package wins.
        rules
            .packages
            .sort_by(|a, b| b.dir.len().cmp(&a.dir.len()).then(a.dir.cmp(&b.dir)));

        let irs: HashMap<&[u8], &FileIr> = files.iter().map(|(p, ir)| (*p, *ir)).collect();
        let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
        for r in &roots {
            rules.files.insert(
                r.clone(),
                FileInfo {
                    root: r.clone(),
                    parent: None,
                    modrs: true,
                },
            );
            queue.push_back(r.clone());
        }
        while let Some(f) = queue.pop_front() {
            let Some(ir) = irs.get(f.as_slice()) else {
                continue;
            };
            let info = rules.files[&f].clone();
            for imp in &ir.imports {
                let Some(local) = &imp.local else { continue };
                if imp.star || !spec::is_mod_decl(&imp.specifier) {
                    continue;
                }
                let SpecifierKind::Path { probes } = rules.classify(&f, &imp.specifier) else {
                    continue;
                };
                let Some(child) = probes.into_iter().find(|p| rules.sources.contains(p)) else {
                    continue;
                };
                if rules.files.contains_key(&child) {
                    continue;
                }
                let modrs = !imp.specifier.starts_with(spec::MOD) || name_of(&child) == b"mod.rs";
                rules.files.insert(
                    child.clone(),
                    FileInfo {
                        root: info.root.clone(),
                        parent: Some((f.clone(), !local.contains("::"))),
                        modrs,
                    },
                );
                queue.push_back(child);
            }
        }
        rules
    }

    fn package(&self, from: &[u8]) -> Option<&Package> {
        self.packages.iter().find(|p| {
            p.dir.is_empty() || (from.starts_with(&p.dir) && from.get(p.dir.len()) == Some(&b'/'))
        })
    }

    fn modrs(&self, from: &[u8]) -> bool {
        if let Some(i) = self.files.get(from) {
            return i.modrs;
        }
        let name = name_of(from);
        let parent = name_of(dir_of(from));
        matches!(name, b"mod.rs" | b"lib.rs" | b"main.rs" | b"build.rs")
            || matches!(parent, b"bin" | b"tests" | b"examples" | b"benches")
    }

    /// The directory nested `mod` declarations in `from` resolve against.
    fn mod_dir(&self, from: &[u8]) -> Vec<u8> {
        let dir = dir_of(from);
        if self.modrs(from) {
            return dir.to_vec();
        }
        let name = name_of(from);
        let stem = name.strip_suffix(b".rs").unwrap_or(name);
        let mut p = dir.to_vec();
        if !p.is_empty() {
            p.push(b'/');
        }
        p.extend_from_slice(stem);
        p
    }

    fn crate_root(&self, from: &[u8]) -> Vec<u8> {
        if let Some(i) = self.files.get(from) {
            return i.root.clone();
        }
        match self.package(from) {
            Some(p) => p
                .lib
                .clone()
                .or_else(|| p.main.clone())
                .unwrap_or_else(|| from.to_vec()),
            None => from.to_vec(),
        }
    }

    /// The package name a dependency key resolves to after renames.
    fn rename(&self, from: &[u8], name: &str) -> String {
        let Some(pkg) = self.package(from) else {
            return name.to_string();
        };
        if let Some(p) = pkg.renames.get(name) {
            return p.clone();
        }
        if pkg.inherited.contains(name) {
            for (dir, renames) in &self.workspace_renames {
                if (dir.is_empty() || pkg.dir.starts_with(dir))
                    && let Some(p) = renames.get(name)
                {
                    return p.clone();
                }
            }
        }
        name.to_string()
    }

    /// Whether `name`, as written in `from`, names a first-party proc-macro
    /// crate other than the one `from` belongs to.
    pub fn is_proc_macro(&self, from: &[u8], name: &str) -> bool {
        let renamed = self.rename(from, name);
        self.proc_macros.contains(&renamed)
            && !self.package(from).is_some_and(|p| {
                p.proc_macro
                    && p.lib
                        .as_ref()
                        .is_some_and(|l| self.libs.get(&renamed) == Some(l))
            })
    }
}

impl SpecifierRules for RustRules {
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind {
        if specifier == spec::OUTSIDE_ROOT {
            return SpecifierKind::OutsideRoot;
        }
        if let Some(p) = specifier.strip_prefix(spec::FILE) {
            return SpecifierKind::Path {
                probes: vec![p.as_bytes().to_vec()],
            };
        }
        if let Some(rel) = specifier.strip_prefix(spec::MOD) {
            let dir = self.mod_dir(from);
            return SpecifierKind::Path {
                probes: vec![
                    join(&dir, &format!("{rel}.rs")),
                    join(&dir, &format!("{rel}/mod.rs")),
                ],
            };
        }
        if let Some(rel) = specifier.strip_prefix(spec::PATH) {
            return match fold(&self.mod_dir(from), rel) {
                Some(p) => SpecifierKind::Path { probes: vec![p] },
                None => SpecifierKind::OutsideRoot,
            };
        }
        match specifier {
            "crate" => {
                return SpecifierKind::Path {
                    probes: vec![self.crate_root(from)],
                };
            }
            "self" => {
                return SpecifierKind::Path {
                    probes: vec![from.to_vec()],
                };
            }
            _ => {}
        }
        if specifier.split("::").all(|s| s == "super") {
            let mut at = from.to_vec();
            for _ in specifier.split("::") {
                match self.files.get(&at).and_then(|i| i.parent.clone()) {
                    // The parent is the declaring file's root namespace.
                    Some((parent, true)) => at = parent,
                    // A crate root has no parent, and a parent inside an
                    // inline module of another file cannot be named by a
                    // file path: unresolved, failing closed.
                    _ => return SpecifierKind::Path { probes: Vec::new() },
                }
            }
            return SpecifierKind::Path { probes: vec![at] };
        }
        let (first, rest) = match specifier.split_once("::") {
            Some((a, b)) => (a, Some(b)),
            None => (specifier, None),
        };
        let renamed = self.rename(from, first);
        let probes = self
            .libs
            .get(&renamed)
            .or_else(|| self.libs.get(first))
            .cloned()
            .into_iter()
            .collect();
        let module = match rest {
            Some(r) => format!("{renamed}::{r}"),
            None => renamed,
        };
        SpecifierKind::Bare { probes, module }
    }
}

/// Adds the cross-file constructs only the whole program reveals: an import
/// of a first-party proc-macro crate from another crate names a proc macro,
/// since such a crate exports nothing else (KTD15).
pub fn mark_proc_macros(rules: &RustRules, files: &mut [(&[u8], &mut FileIr)]) {
    for (path, ir) in files.iter_mut() {
        let mut found = Vec::new();
        for imp in &ir.imports {
            if spec::is_crate_name(&imp.specifier) && rules.is_proc_macro(path, &imp.specifier) {
                found.push(DynamicConstruct {
                    kind: ConstructKind::MacroCode,
                    text: imp.specifier.clone(),
                    symbol: imp.symbol.clone(),
                    span: imp.span,
                    location: imp.location,
                });
            }
        }
        ir.constructs.extend(found);
    }
}

//! Whole-program link for Go (KTD8, KTD9, KTD10).
//!
//! A package is a directory, joined here. `link` builds two indexes over
//! the lowered files: a module index that maps each file's governing
//! `go.mod`/`go.work` to the module paths it declares, and a package
//! index that maps each `(directory, package clause)` pair to its
//! top-level declarations. It then rewrites each file's IR so that a
//! package-level name declared in a sibling file, and each member of an
//! imported first-party package, binds through a synthetic import whose
//! specifier names the declaring file: constants and declarations in
//! sibling files reach the resolver as ordinary `FirstPartyDef`s. The
//! returned [`GoRules`] resolves every remaining import specifier:
//! standard library first, first-party module longest-prefix, vendor
//! when `modules.txt` and the governing `go.mod` agree, external last.
//!
//! `link` charges its work (files visited, imports classified, synthetic
//! bindings added) against the resolver budget, and a file it never
//! reached gets a `resolution-limit` construct, never silence.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use egress_core::data::{Data, RuntimeData};
use egress_core::discover::FileKind;
use egress_core::discover::manifests::{GoReplace, GoReplaceTarget, Manifests, go_import_path};
use egress_core::ir::{
    ConstructKind, DynamicConstruct, Expr, FileIr, Import, Root, Span, SymbolKind, UseKind,
};
use egress_core::model::{Language, Location};
use egress_core::paths::dir_of;
use egress_core::resolve::{SpecifierKind, SpecifierRules};

use crate::lower::guessed_local;

/// The specifier prefix a synthetic import carries when it names a
/// declaring file directly. It is not a valid import path, so the
/// namespace cannot collide with a real specifier; the rules resolve it
/// before any import-path handling.
pub const FILE_SPECIFIER: &str = "gofile:";

/// The specifier an invalid import path is rewritten to before the gap
/// is reported, so the raw string never reaches the report. The marker
/// is not a valid import path and resolves to `unresolved-module`.
const INVALID_SPECIFIER: &str = "<invalid>";

/// The local name synthetic imports take; `#` can never appear in a Go
/// identifier, so it cannot collide with a source name.
fn synth_local(n: usize) -> String {
    format!("synth#{n}")
}

/// The embedded Go runtime data: the standard-library module set and the
/// catalog's package-name overrides (loaded once, KTD8).
fn runtime() -> &'static RuntimeData {
    static DATA: OnceLock<Data> = OnceLock::new();
    DATA.get_or_init(|| Data::embedded().expect("embedded data"))
        .runtime(Language::Go)
}

/// Joins a directory with path elements.
fn join(dir: &[u8], elems: &[&str]) -> Vec<u8> {
    let mut out = dir.to_vec();
    for e in elems {
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(e.as_bytes());
    }
    out
}

/// Joins a directory with a `/`-separated path.
fn join_str(dir: &[u8], path: &str) -> Vec<u8> {
    let elems: Vec<&str> = path.split('/').filter(|e| !e.is_empty()).collect();
    join(dir, &elems)
}

/// `path` lies inside `dir` or equals it.
fn within(path: &[u8], dir: &[u8]) -> bool {
    egress_core::paths::within(path, dir)
}

/// A `go` directive's `(major, minor)`, for example `1.22` or `1.26rc1`.
fn go_version(s: Option<&str>) -> Option<(u64, u64)> {
    let s = s?;
    let mut it = s.split('.');
    let major: u64 = it.next()?.parse().ok()?;
    let minor: String = it
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if minor.is_empty() {
        return None;
    }
    Some((major, minor.parse().ok()?))
}

/// `go 1.14` or later: consistent vendoring applies (KTD9).
fn go_1_14(v: Option<(u64, u64)>) -> bool {
    v.is_some_and(|(a, b)| a > 1 || (a == 1 && b >= 14))
}

/// Whether a `go.mod`/`go.work` may declare anything: the go tool ignores
/// manifests under `testdata` or a `_`- or `.`-prefixed path element.
fn manifest_governs(path: &[u8]) -> bool {
    !dir_of(path)
        .split(|b| *b == b'/')
        .any(|e| e == b"testdata" || e.starts_with(b"_") || e.starts_with(b"."))
}

/// A module-path `replace`'s target: a directory, out of the root, or
/// another module.
#[derive(Debug, Clone)]
enum ReplaceTo {
    Dir(Vec<u8>),
    Outside,
    Module {
        path: String,
        version: Option<String>,
    },
}

/// One usable `go.mod` record.
#[derive(Debug)]
struct Mod {
    /// The declared module path.
    module: Option<String>,
    /// The manifest's directory.
    dir: Vec<u8>,
    /// The manifest path, for ambiguity diagnostics.
    manifest: Vec<u8>,
    /// The `go` directive as (major, minor).
    go: Option<(u64, u64)>,
    /// `require` entries as (module path, version).
    require: Vec<(String, String)>,
    replace: Vec<Replace>,
}

#[derive(Debug)]
struct Replace {
    from: String,
    from_version: Option<String>,
    to: ReplaceTo,
}

/// One usable `go.work` record.
#[derive(Debug)]
struct Work {
    manifest: Vec<u8>,
    dir: Vec<u8>,
    go: Option<(u64, u64)>,
    uses: Vec<Vec<u8>>,
    replace: Vec<Replace>,
}

fn go_replaces(rs: &[GoReplace]) -> Vec<Replace> {
    rs.iter()
        .map(|r| Replace {
            from: r.from.clone(),
            from_version: r.from_version.clone(),
            to: match &r.to {
                GoReplaceTarget::Path(p) => ReplaceTo::Dir(p.clone()),
                GoReplaceTarget::Outside => ReplaceTo::Outside,
                GoReplaceTarget::Module { path, version } => ReplaceTo::Module {
                    path: path.clone(),
                    version: version.clone(),
                },
            },
        })
        .collect()
}

/// Whether a `replace` applies to a `require`d version of `from`: a
/// version-less left side matches every version, and a `from` with no
/// `require` still applies when the left side carries no version.
fn replace_applies(r: &Replace, require: &[(String, String)]) -> bool {
    match &r.from_version {
        None => true,
        Some(v) => require.iter().any(|(p, rv)| *p == r.from && rv == v),
    }
}

/// Where a first-party module path leads.
#[derive(Debug, Clone)]
enum ModuleMap {
    /// The module's root directory in the root.
    Dir(Vec<u8>),
    /// A `use` or `replace` target that left the root: a gap.
    Outside,
}

/// One `modules.txt` row: package path, module path, version.
type VendorRow = (String, String, Option<String>);

/// A module-path `replace` for dependency keying.
#[derive(Debug)]
struct DepReplace {
    from: String,
    from_version: Option<String>,
    to_path: String,
    to_version: Option<String>,
}

/// The resolution set one file's imports see: its own module, the
/// workspace's `use` modules, and the in-root `replace` targets of its
/// governing manifests (KTD9).
#[derive(Debug, Default)]
struct Governing {
    /// Module path -> directory or outside marker; the manifest that
    /// declared it rides along for ambiguity diagnostics.
    modules: HashMap<String, (ModuleMap, Vec<u8>)>,
    /// Module paths two governing manifests both declared, as (first
    /// manifest, second manifest).
    ambiguous: HashMap<String, (Vec<u8>, Vec<u8>)>,
    /// The file's own `go.mod`'s `require` list, for dependency keying.
    require: Vec<(String, String)>,
    /// Module-path `replace` directives applying here.
    dep_replaces: Vec<DepReplace>,
    /// Vendored package import path -> its directory under `vendor/`,
    /// present only when `modules.txt` and the governing `go.mod` agree
    /// on the module's path and version and `go` is 1.14 or later.
    vendored: HashMap<String, Vec<u8>>,
}

/// One package's declaration index (KTD8).
#[derive(Debug, Default)]
struct PackageIx {
    /// Declared top-level name -> Some(declaring file, value-bearing),
    /// or None when more than one file declares it.
    decls: HashMap<String, Option<(Vec<u8>, bool)>>,
    /// The package's files, sorted.
    files: Vec<Vec<u8>>,
}

/// A directory's importable package clause: the one not suffixed
/// `_test`; ambiguous when two share a directory.
#[derive(Debug, Clone)]
enum PrimaryClause {
    One(String),
    Ambiguous,
    None,
}

/// What an import specifier resolves to, for the rewrite pass and for
/// `SpecifierRules::classify`.
enum Resolution {
    /// A synthetic `gofile:` specifier: probe the file.
    File(Vec<u8>),
    /// The import path failed `go_import_path`: an unresolved-module gap.
    Invalid,
    /// A standard-library path.
    Stdlib,
    /// A first-party or vendored package directory.
    Dir(Vec<u8>),
    /// Two governing manifests declare the module path.
    Ambiguous,
    /// A `use` or `replace` target outside the root: a gap.
    Outside,
    /// The cgo pseudo-package `C`: neither the standard library, a
    /// first-party package, nor an external module.
    Cgo,
    /// A no-dot path in neither set: an unresolved-module gap.
    Unresolved,
    /// Everything else: an external module.
    External,
}

/// Go's specifier rules: the standard library, first-party module
/// resolution, vendored packages, and external modules (KTD9).
pub struct GoRules {
    /// Standard-library import paths.
    stdlib: HashSet<String>,
    /// Catalog `package_name` per import path, for unaliased imports
    /// whose guessed local is wrong.
    package_names: HashMap<String, String>,
    /// (directory, clause) -> package index.
    packages: HashMap<(Vec<u8>, String), PackageIx>,
    /// directory -> its importable package clause.
    primary: HashMap<Vec<u8>, PrimaryClause>,
    /// Directory of a lowered Go file -> its governing set.
    governing: HashMap<Vec<u8>, Arc<Governing>>,
    empty: Governing,
    /// The guarded-link failure fallback: everything is unresolved.
    failed: bool,
}

impl GoRules {
    /// The rules a failed guarded link returns: every specifier is an
    /// unresolved module, never a silent result.
    pub fn fallback() -> GoRules {
        GoRules {
            stdlib: HashSet::new(),
            package_names: HashMap::new(),
            packages: HashMap::new(),
            primary: HashMap::new(),
            governing: HashMap::new(),
            empty: Governing::default(),
            failed: true,
        }
    }

    /// The governing set for the file at `from`; files outside every
    /// module get the empty set, so a dotted import is an external
    /// dependency keyed by its own path.
    fn gov(&self, from: &[u8]) -> &Governing {
        self.governing
            .get(dir_of(from))
            .map(|g| &**g)
            .unwrap_or(&self.empty)
    }

    fn resolve(&self, from: &[u8], specifier: &str) -> Resolution {
        if self.failed {
            return Resolution::Invalid;
        }
        if let Some(rest) = specifier.strip_prefix(FILE_SPECIFIER) {
            return Resolution::File(rest.as_bytes().to_vec());
        }
        if !go_import_path(specifier) {
            return Resolution::Invalid;
        }
        // `C` is the cgo pseudo-package, recognized by the import path
        // alone (KTD12). The import record is `type_only`, so the
        // resolver never asks; the rewrite reads this arm for
        // bookkeeping and `classify` below fails closed.
        if specifier == "C" {
            return Resolution::Cgo;
        }
        // The standard library wins whenever the import path is in the
        // set: a first-party `module net` must not shadow `net/http`.
        if self.stdlib.contains(specifier) {
            return Resolution::Stdlib;
        }
        let gov = self.gov(from);
        let segs: Vec<&str> = specifier.split('/').collect();
        // First-party module paths match longest-prefix-first; an
        // ambiguous declaration binds neither side.
        for n in (1..=segs.len()).rev() {
            let prefix = segs[..n].join("/");
            if gov.ambiguous.contains_key(&prefix) {
                return Resolution::Ambiguous;
            }
            if let Some((m, _)) = gov.modules.get(&prefix) {
                return match m {
                    ModuleMap::Outside => Resolution::Outside,
                    ModuleMap::Dir(d) => Resolution::Dir(join(d, &segs[n..])),
                };
            }
        }
        // A no-dot path in neither set cannot name an external module.
        if !segs[0].contains('.') {
            return Resolution::Unresolved;
        }
        if let Some(d) = gov.vendored.get(specifier) {
            return Resolution::Dir(d.clone());
        }
        Resolution::External
    }

    /// The package files an import of directory `dir` probes: the
    /// directory's importable (non-`_test`) package, or nothing.
    fn package_files(&self, dir: &[u8]) -> Vec<Vec<u8>> {
        let Some(PrimaryClause::One(clause)) = self.primary.get(dir) else {
            return Vec::new();
        };
        self.packages
            .get(&(dir.to_vec(), clause.clone()))
            .map(|p| p.files.clone())
            .unwrap_or_default()
    }

    /// The package clause an import of `dir` binds, when unambiguous.
    fn package_clause(&self, dir: &[u8]) -> Option<&str> {
        match self.primary.get(dir) {
            Some(PrimaryClause::One(c)) => Some(c),
            _ => None,
        }
    }

    /// The unscanned-dependency key for `module` written in `from`, and
    /// whether a module-path `replace` re-keyed it (KTD9, KTD10).
    fn dep_key(&self, from: &[u8], module: &str) -> (String, bool) {
        let gov = self.gov(from);
        let matched = gov
            .require
            .iter()
            .filter(|(p, _)| path_covers(p, module))
            .max_by_key(|(p, _)| p.len());
        let Some((req_path, req_version)) = matched else {
            return (module.to_string(), false);
        };
        for r in &gov.dep_replaces {
            if r.from != *req_path {
                continue;
            }
            if r.from_version.is_some() && r.from_version.as_deref() != Some(req_version.as_str()) {
                continue;
            }
            let key = match &r.to_version {
                Some(v) => format!("{}@{}", r.to_path, v),
                None => r.to_path.clone(),
            };
            return (key, true);
        }
        (req_path.clone(), false)
    }
}

/// `module` is `path` or a package under it.
fn path_covers(path: &str, module: &str) -> bool {
    module == path
        || (module.len() > path.len()
            && module.starts_with(path)
            && module.as_bytes()[path.len()] == b'/')
}

impl SpecifierRules for GoRules {
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind {
        match self.resolve(from, specifier) {
            Resolution::File(p) => SpecifierKind::Path { probes: vec![p] },
            Resolution::Dir(d) => SpecifierKind::Path {
                probes: self.package_files(&d),
            },
            Resolution::Stdlib | Resolution::External => SpecifierKind::Bare {
                probes: Vec::new(),
                module: specifier.to_string(),
            },
            Resolution::Outside => SpecifierKind::OutsideRoot,
            Resolution::Invalid
            | Resolution::Unresolved
            | Resolution::Ambiguous
            | Resolution::Cgo => SpecifierKind::Path { probes: Vec::new() },
        }
    }

    fn package_key(&self, _language: Language, from: &[u8], module: &str) -> String {
        self.dep_key(from, module).0
    }

    fn replaced(&self, from: &[u8], module: &str) -> bool {
        self.dep_key(from, module).1
    }
}

/// What `link` produced: the specifier rules plus the resolver-budget
/// accounting the scan applies.
pub struct Linked {
    pub rules: GoRules,
    /// Resolver steps the link charged.
    pub steps: u64,
    /// The link ran out of resolver budget.
    pub budget_exhausted: bool,
}

/// The module index over `manifests`: usable `go.mod` and `go.work`
/// records by directory, and `vendor/modules.txt` lists by vendor
/// directory.
struct ModuleIndex {
    mods: Vec<Mod>,
    gomods: HashMap<Vec<u8>, usize>,
    works: Vec<Work>,
    goworks: HashMap<Vec<u8>, usize>,
    vendors: HashMap<Vec<u8>, Vec<VendorRow>>,
}

impl ModuleIndex {
    fn build(manifests: &Manifests) -> ModuleIndex {
        let mut out = ModuleIndex {
            mods: Vec::new(),
            gomods: HashMap::new(),
            works: Vec::new(),
            goworks: HashMap::new(),
            vendors: HashMap::new(),
        };
        for m in &manifests.go_mod {
            if !manifest_governs(&m.path) {
                continue;
            }
            out.gomods.insert(dir_of(&m.path).to_vec(), out.mods.len());
            out.mods.push(Mod {
                module: m.module.clone(),
                dir: dir_of(&m.path).to_vec(),
                manifest: m.path.clone(),
                go: go_version(m.go.as_deref()),
                require: m.require.clone(),
                replace: go_replaces(&m.replace),
            });
        }
        for w in &manifests.go_work {
            if !manifest_governs(&w.path) {
                continue;
            }
            out.goworks
                .insert(dir_of(&w.path).to_vec(), out.works.len());
            out.works.push(Work {
                manifest: w.path.clone(),
                dir: dir_of(&w.path).to_vec(),
                go: go_version(w.go.as_deref()),
                uses: w.uses.clone(),
                replace: go_replaces(&w.replace),
            });
        }
        for v in &manifests.go_modules {
            let packages = v
                .packages
                .iter()
                .filter(|p| go_import_path(&p.path) && go_import_path(&p.module))
                .map(|p| (p.path.clone(), p.module.clone(), p.version.clone()))
                .collect();
            out.vendors.insert(dir_of(&v.path).to_vec(), packages);
        }
        out
    }

    /// The nearest manifest at or above `dir`, if it is usable.
    fn nearest(&self, map: &HashMap<Vec<u8>, usize>, dir: &[u8]) -> Option<usize> {
        let mut d = dir;
        loop {
            if let Some(i) = map.get(d) {
                return Some(*i);
            }
            if d.is_empty() {
                return None;
            }
            d = dir_of(d);
        }
    }

    /// The governing resolution set for a file in `dir` (KTD9): its own
    /// `go.mod`, plus a covering `go.work`'s `use` modules and the in-root
    /// `replace` targets of the governing manifests.
    fn governing(&self, dir: &[u8]) -> Governing {
        let mut g = Governing::default();
        let gmod = self.nearest(&self.gomods, dir).map(|i| &self.mods[i]);
        let gwork = self.nearest(&self.goworks, dir).map(|i| &self.works[i]);
        if let Some(m) = gmod {
            g.require = m.require.clone();
        }
        let insert_module = |g: &mut Governing, path: &str, map: ModuleMap, manifest: &[u8]| match g
            .modules
            .entry(path.to_string())
        {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert((map, manifest.to_vec()));
            }
            std::collections::hash_map::Entry::Occupied(e) => {
                let first = e.get().1.clone();
                g.ambiguous
                    .entry(path.to_string())
                    .or_insert((first, manifest.to_vec()));
                e.remove();
            }
        };
        // A `replace` applies to the file's require set. An in-root
        // directory target maps imports into the package index; an
        // out-of-root target resolves to a gap.
        let apply_replace = |g: &mut Governing, r: &Replace, manifest: &[u8]| {
            if !replace_applies(r, &g.require) {
                return;
            }
            match &r.to {
                ReplaceTo::Dir(d) => {
                    insert_module(g, &r.from, ModuleMap::Dir(d.clone()), manifest);
                }
                ReplaceTo::Outside => {
                    insert_module(g, &r.from, ModuleMap::Outside, manifest);
                }
                ReplaceTo::Module { path, version } => {
                    g.dep_replaces.push(DepReplace {
                        from: r.from.clone(),
                        from_version: r.from_version.clone(),
                        to_path: path.clone(),
                        to_version: version.clone(),
                    });
                }
            }
        };
        let workspace = gwork.filter(|w| w.uses.iter().any(|u| within(dir, u)));
        if let Some(w) = workspace {
            for u in &w.uses {
                if let Some(&i) = self.gomods.get(u)
                    && let Some(path) = self.mods[i].module.as_deref()
                {
                    let manifest = self.mods[i].manifest.clone();
                    insert_module(&mut g, path, ModuleMap::Dir(u.clone()), &manifest);
                }
            }
            for r in &w.replace {
                apply_replace(&mut g, r, &w.manifest);
            }
        }
        if let Some(m) = gmod {
            if workspace.is_none()
                && let Some(path) = m.module.as_deref()
            {
                insert_module(&mut g, path, ModuleMap::Dir(m.dir.clone()), &m.manifest);
            }
            // In workspace mode a go.mod's `replace` directives are
            // inert (the go.work's govern); in module mode they apply.
            if workspace.is_none() {
                for r in &m.replace {
                    apply_replace(&mut g, r, &m.manifest);
                }
            }
        }
        // Vendored packages: `modules.txt` at the workspace or module
        // root, agreeing with the file's own `go.mod` on path and
        // version, under `go >= 1.14` (KTD9).
        let vendor_root = workspace
            .map(|w| join(&w.dir, &["vendor"]))
            .or_else(|| gmod.map(|m| join(&m.dir, &["vendor"])));
        let go = workspace
            .and_then(|w| w.go)
            .or_else(|| gmod.and_then(|m| m.go));
        if let Some(vdir) = vendor_root
            && go_1_14(go)
            && let Some(rows) = self.vendors.get(&vdir)
        {
            for (pkg, mpath, mver) in rows {
                let agrees = g
                    .require
                    .iter()
                    .any(|(p, v)| p == mpath && Some(v.as_str()) == mver.as_deref());
                if agrees {
                    g.vendored.insert(pkg.clone(), join_str(&vdir, pkg));
                }
            }
        }
        g
    }
}

/// The per-file rewrite state: resolver steps charged and the budget.
struct Work2<'r> {
    rules: &'r GoRules,
    steps: u64,
    budget: u64,
    exhausted: bool,
}

impl Work2<'_> {
    /// Charges one link step; `false` when the budget is spent.
    fn charge(&mut self) -> bool {
        self.steps += 1;
        if self.steps > self.budget {
            self.exhausted = true;
            return false;
        }
        true
    }
}

/// Links the lowered Go files in `files`, reading the embedded Go data.
/// The caller runs this under `run_guarded`; a panic gets
/// [`GoRules::fallback`].
pub fn link(
    manifests: &Manifests,
    index: &BTreeMap<Vec<u8>, FileKind>,
    files: &mut [(&[u8], &mut FileIr)],
    budget: u64,
) -> Linked {
    link_with(manifests, index, files, runtime(), budget)
}

/// [`link`] against an explicit runtime, so tests inject a
/// standard-library set rather than the embedded data.
pub fn link_with(
    manifests: &Manifests,
    _index: &BTreeMap<Vec<u8>, FileKind>,
    files: &mut [(&[u8], &mut FileIr)],
    rt: &RuntimeData,
    budget: u64,
) -> Linked {
    let mods = ModuleIndex::build(manifests);

    // A package-level `var` is a constant candidate only while no file of
    // its package assigns to it, takes its address, or passes it by
    // pointer; the `AssignmentTarget` markers every file records carry
    // those names, and candidates they name retire here (KTD8).
    let mut mutations: HashMap<(Vec<u8>, String), HashSet<String>> = HashMap::new();
    for (path, ir) in files.iter() {
        let key = (
            dir_of(path).to_vec(),
            ir.package.clone().unwrap_or_default(),
        );
        let names = mutations.entry(key).or_default();
        for r in &ir.references {
            if r.use_kind == UseKind::AssignmentTarget
                && r.members.is_empty()
                && let Root::Local(n) = &r.root
            {
                names.insert(n.clone());
            }
        }
    }
    for (path, ir) in files.iter_mut() {
        let key = (
            dir_of(path).to_vec(),
            ir.package.clone().unwrap_or_default(),
        );
        if let Some(names) = mutations.get(&key) {
            ir.locals
                .retain(|l| l.symbol != "<module>" || !names.contains(&l.name));
        }
    }

    // The package index: each (directory, clause) pair's top-level
    // declarations, one declaring file or an ambiguity mark per name.
    let mut packages: HashMap<(Vec<u8>, String), PackageIx> = HashMap::new();
    let mut primary: HashMap<Vec<u8>, BTreeSet<String>> = HashMap::new();
    for (path, ir) in files.iter() {
        let dir = dir_of(path).to_vec();
        let clause = ir.package.clone().unwrap_or_default();
        primary
            .entry(dir.clone())
            .or_default()
            .insert(clause.clone());
        let pkg = packages.entry((dir, clause)).or_default();
        pkg.files.push(path.to_vec());
        for (name, value_bearing) in file_decls(ir) {
            match pkg.decls.entry(name) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(Some((path.to_vec(), value_bearing)));
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // A name declared twice is ambiguous, whichever file
                    // holds the second declaration.
                    e.insert(None);
                }
            }
        }
    }
    for pkg in packages.values_mut() {
        pkg.files.sort();
        pkg.files.dedup();
    }
    let primary: HashMap<Vec<u8>, PrimaryClause> = primary
        .into_iter()
        .map(|(dir, clauses)| {
            let main: Vec<&String> = clauses.iter().filter(|c| !c.ends_with("_test")).collect();
            let state = match main.as_slice() {
                [c] => PrimaryClause::One((*c).clone()),
                [] => PrimaryClause::None,
                _ => PrimaryClause::Ambiguous,
            };
            (dir, state)
        })
        .collect();

    // The governing set per directory that holds a lowered file.
    let mut governing: HashMap<Vec<u8>, Arc<Governing>> = HashMap::new();
    let dirs: BTreeSet<Vec<u8>> = files.iter().map(|(p, _)| dir_of(p).to_vec()).collect();
    for dir in dirs {
        let g = mods.governing(&dir);
        governing.insert(dir, Arc::new(g));
    }

    let package_names = rt
        .packages
        .iter()
        .filter_map(|p| {
            p.package_name.as_ref().map(|n| {
                p.modules
                    .iter()
                    .map(|m| (m.clone(), n.clone()))
                    .collect::<Vec<_>>()
            })
        })
        .flatten()
        .collect();

    let rules = GoRules {
        stdlib: rt.inventory.stdlib_modules.iter().cloned().collect(),
        package_names,
        packages,
        primary,
        governing,
        empty: Governing::default(),
        failed: false,
    };

    let mut w = Work2 {
        rules: &rules,
        steps: 0,
        budget,
        exhausted: false,
    };
    for (path, ir) in files.iter_mut() {
        if w.exhausted {
            // A file the link never reached gets a resolution-limit
            // construct, never silence.
            ir.constructs.push(DynamicConstruct {
                kind: ConstructKind::ResolutionLimit,
                text: "link".to_string(),
                symbol: "<module>".to_string(),
                span: Span::default(),
                location: Location { line: 1, column: 1 },
            });
            continue;
        }
        w.charge();
        rewrite_file(&mut w, path, ir, rt);
    }
    let exhausted = w.exhausted;
    let steps = w.steps;
    Linked {
        rules,
        steps,
        budget_exhausted: exhausted,
    }
}

/// A file's top-level declared names with whether each carries a value
/// the resolver can read (constants and `var` candidates do; functions
/// and types do not).
fn file_decls(ir: &FileIr) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for c in &ir.constants {
        if c.name != "_" {
            out.push((c.name.clone(), true));
        }
    }
    for l in &ir.locals {
        if l.symbol == "<module>" && l.name != "_" {
            out.push((l.name.clone(), true));
        }
    }
    for s in &ir.symbols {
        // `init` may be declared in every file of a package; methods and
        // closures are not package-level names.
        let top_level = matches!(s.kind, SymbolKind::Function | SymbolKind::Class)
            && !s.path.contains('.')
            && s.path != "_"
            && s.path != "init"
            && !s.path.starts_with("init#");
        if top_level {
            out.push((s.path.clone(), false));
        }
    }
    out
}

/// Per-file derived import facts the rewrite applies.
#[derive(Default)]
struct FileWork {
    /// Names bound in a local scope per enclosing symbol, plus each
    /// symbol's declared params. The "unaliased import" flag yields to
    /// a name a scope provably binds.
    bound: std::collections::HashMap<String, std::collections::HashSet<String>>,
    /// Guessed or explicit local -> the real clause name, for imports the
    /// rewrite renamed.
    renames: HashMap<String, String>,
    /// Clause names a rename introduced: a `Root::Local` on one binds the
    /// import (the code used the package's real clause).
    rebind_locals: HashSet<String>,
    /// Import indices whose specifier was invalid.
    invalid: Vec<usize>,
    /// Post-rename import local -> the (directory, clause) of the
    /// first-party or vendored package it names.
    package_locals: HashMap<String, (Vec<u8>, String)>,
    /// (directory, clause) of first-party/vendored star imports.
    star_packages: Vec<(Vec<u8>, String)>,
    /// An unaliased external import whose real clause is unknown.
    unknown_clause: bool,
    /// `resolution-limit` constructs raised at import sites.
    import_constructs: Vec<DynamicConstruct>,
}

/// Accumulators the reference rewrite fills.
#[derive(Default)]
struct RewriteOut {
    synthetics: Vec<Import>,
    constructs: Vec<DynamicConstruct>,
    /// (declaring file, member) -> the synthetic local bound for it.
    member_synths: HashMap<(Vec<u8>, String), String>,
    /// Package names already bound by a synthetic.
    synth_names: HashSet<String>,
    gensym: usize,
}

/// A synthetic import binding `local` to member `member` of the file at
/// `decl` (KTD8).
fn synthetic(local: String, decl: &[u8], member: &str) -> Import {
    Import {
        local: Some(local),
        specifier: format!("{FILE_SPECIFIER}{}", String::from_utf8_lossy(decl)),
        members: vec![member.to_string()],
        type_only: false,
        star: false,
        re_export: false,
        default: false,
        symbol: "<module>".to_string(),
        span: Span::default(),
        location: Location { line: 1, column: 1 },
    }
}

fn limit_construct(symbol: &str, span: Span, location: Location, text: String) -> DynamicConstruct {
    DynamicConstruct {
        kind: ConstructKind::ResolutionLimit,
        text,
        symbol: symbol.to_string(),
        span,
        location,
    }
}

/// The synthetic local bound to `member` of `file`, allocated once.
fn member_local(out: &mut RewriteOut, file: &[u8], member: &str) -> String {
    let key = (file.to_vec(), member.to_string());
    if let Some(l) = out.member_synths.get(&key) {
        return l.clone();
    }
    out.gensym += 1;
    let l = synth_local(out.gensym);
    out.synthetics.push(synthetic(l.clone(), file, member));
    out.member_synths.insert(key, l.clone());
    l
}

/// The synthetic import for a package-level `name` declared in a sibling
/// file, bound under `name` itself so `import_for` and `eval_name` find
/// it; allocated once per name.
#[allow(clippy::too_many_arguments)]
fn use_package_name(
    w: &mut Work2<'_>,
    path: &[u8],
    own: Option<&PackageIx>,
    span: Span,
    location: Location,
    symbol: &str,
    name: &str,
    out: &mut RewriteOut,
) {
    let Some(decl) = own.and_then(|p| p.decls.get(name)) else {
        return;
    };
    match decl {
        Some((file, _)) if file.as_slice() != path => {
            w.charge();
            if out.synth_names.insert(name.to_string()) {
                out.synthetics.push(synthetic(name.to_string(), file, name));
            }
        }
        Some(_) => {}
        None => out.constructs.push(limit_construct(
            symbol,
            span,
            location,
            format!("{name} declared in two files"),
        )),
    }
}

/// The manifest pair declaring the module path ambiguous, for the
/// construct's text.
fn ambiguous_manifests(rules: &GoRules, from: &[u8], spec: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let gov = rules.gov(from);
    let segs: Vec<&str> = spec.split('/').collect();
    (1..=segs.len())
        .rev()
        .find_map(|n| gov.ambiguous.get(&segs[..n].join("/")).cloned())
}

/// Fixes a `Root`'s imported-name guesses after `imp.local` renames: a
/// `Root::Import` on a renamed guess becomes the real clause name, and a
/// `Root::Local` on a clause name introduced by a rename becomes the
/// import (the code used the package's real clause).
fn fix_import_root(root: &mut Root, fw: &FileWork) {
    match root {
        Root::Import(l) => {
            if let Some(real) = fw.renames.get(l) {
                *l = real.clone();
            }
        }
        Root::Local(n) if fw.rebind_locals.contains(n) => {
            *root = Root::Import(n.clone());
        }
        _ => {}
    }
}

/// Binds `name.member` (a first-party import local) to the declaring
/// file through a synthetic import, or flags an ambiguous member.
#[allow(clippy::too_many_arguments)]
fn bind_member(
    w: &mut Work2<'_>,
    rules: &GoRules,
    fw: &FileWork,
    span: Span,
    location: Location,
    symbol: &str,
    local: &str,
    member: &str,
    out: &mut RewriteOut,
) -> Option<Root> {
    let (d, c) = fw.package_locals.get(local)?;
    let decl = rules
        .packages
        .get(&(d.clone(), c.clone()))?
        .decls
        .get(member)?;
    match decl {
        Some((file, _)) => {
            w.charge();
            Some(Root::Import(member_local(out, file, member)))
        }
        None => {
            out.constructs.push(limit_construct(
                symbol,
                span,
                location,
                format!("{local}.{member} declared in two files"),
            ));
            None
        }
    }
}

/// The non-import arms of [`rewrite_root`]: a sibling-declared name gets
/// a synthetic import and the root rebinds to it; a guessed import name
/// and an undeclared selector root under an unknown-clause import are
/// `resolution-limit` constructs.
/// Whether `name` is bound in `symbol`'s scope chain: the symbol's own
/// locals and params, then each enclosing symbol's, then `<module>`'s.
fn bound_in_scope(fw: &FileWork, symbol: &str, name: &str) -> bool {
    let mut sym = symbol;
    loop {
        if fw.bound.get(sym).is_some_and(|s| s.contains(name)) {
            return true;
        }
        match sym.rfind('.') {
            Some(i) => sym = &sym[..i],
            None => break,
        }
    }
    fw.bound.get("<module>").is_some_and(|s| s.contains(name))
}

#[allow(clippy::too_many_arguments)]
fn package_name_root(
    w: &mut Work2<'_>,
    path: &[u8],
    fw: &FileWork,
    own: Option<&PackageIx>,
    span: Span,
    location: Location,
    symbol: &str,
    ambient: bool,
    name: &str,
    members: &[String],
    use_kind: UseKind,
    out: &mut RewriteOut,
) -> Option<Root> {
    if let Some(decl) = own.and_then(|p| p.decls.get(name)) {
        match decl {
            // Declared in a sibling file: bind through a synthetic import
            // and rebind the root to it.
            Some((file, _)) if file.as_slice() != path => {
                w.charge();
                if out.synth_names.insert(name.to_string()) {
                    out.synthetics.push(synthetic(name.to_string(), file, name));
                }
                return Some(Root::Import(name.to_string()));
            }
            // Declared in this file: a package decl shadows a star
            // import's names, so an Ambient root is a plain local.
            Some(_) if ambient => return Some(Root::Local(name.to_string())),
            Some(_) => return None,
            None => {
                out.constructs.push(limit_construct(
                    symbol,
                    span,
                    location,
                    format!("{name} declared in two files"),
                ));
                return None;
            }
        }
    }
    if ambient {
        return None;
    }
    if fw.renames.contains_key(name) {
        // The written name guesses the import path's last element while
        // the package's real clause differs: the compiler would reject
        // it, so the reference cannot be decided.
        out.constructs.push(limit_construct(
            symbol,
            span,
            location,
            format!("{name} names a package clause that differs"),
        ));
    } else if fw.unknown_clause
        && !members.is_empty()
        && use_kind != UseKind::AssignmentTarget
        && !bound_in_scope(fw, symbol, name)
    {
        // A selector rooted at a name bound by no import or package
        // declaration may name an unaliased import whose real clause is
        // unknown (KTD8): a guessed name never silently drops a call.
        // A name a local scope binds is not a guessed import.
        out.constructs.push(limit_construct(
            symbol,
            span,
            location,
            format!("{name} bound by no import or package declaration"),
        ));
    }
    None
}

/// Rewrites one reference's root through the import and package indexes
/// (KTD8). `members` is the reference's member chain.
#[allow(clippy::too_many_arguments)]
fn rewrite_root(
    w: &mut Work2<'_>,
    rules: &GoRules,
    path: &[u8],
    fw: &FileWork,
    own: Option<&PackageIx>,
    span: Span,
    location: Location,
    symbol: &str,
    root: &mut Root,
    members: &[String],
    use_kind: UseKind,
    out: &mut RewriteOut,
) {
    fix_import_root(root, fw);
    match root {
        Root::Import(l) => {
            if let Some(m) = members.first()
                && let Some(r) = bind_member(w, rules, fw, span, location, symbol, l, m, out)
            {
                *root = r;
            }
        }
        Root::Local(n) => {
            if let Some(r) = package_name_root(
                w, path, fw, own, span, location, symbol, false, n, members, use_kind, out,
            ) {
                *root = r;
            }
        }
        Root::Ambient(n) => {
            if let Some(r) = package_name_root(
                w, path, fw, own, span, location, symbol, true, n, members, use_kind, out,
            ) {
                *root = r;
            }
        }
        _ => {}
    }
}

/// Rewrites an [`Expr`] subtree: `Expr::Name` uses of sibling-package
/// names get synthetic bindings, and an `Expr::Reference` over a
/// first-party value member folds to the bound name.
#[allow(clippy::too_many_arguments)]
fn rewrite_expr(
    w: &mut Work2<'_>,
    rules: &GoRules,
    path: &[u8],
    fw: &FileWork,
    own: Option<&PackageIx>,
    span: Span,
    location: Location,
    symbol: &str,
    e: &mut Expr,
    out: &mut RewriteOut,
) {
    match e {
        Expr::Name(n) => {
            use_package_name(w, path, own, span, location, symbol, &n.clone(), out);
        }
        Expr::Reference(_) => {
            if !w.charge() {
                return;
            }
            // Take the reference out of the node so the node itself can
            // fold to a name.
            let Expr::Reference(mut r) = std::mem::replace(e, Expr::Opaque(String::new())) else {
                unreachable!()
            };
            fix_import_root(&mut r.root, fw);
            let mut folded = false;
            match r.root.clone() {
                Root::Import(l) => {
                    if let Some(m) = r.members.first() {
                        let target = fw
                            .package_locals
                            .get(&l)
                            .and_then(|(d, c)| rules.packages.get(&(d.clone(), c.clone())))
                            .and_then(|p| p.decls.get(m));
                        match target {
                            Some(Some((file, value_bearing))) => {
                                w.charge();
                                let local = member_local(out, file, m);
                                // A bare value member (`api.Base` in
                                // `f(api.Base)`) folds to the bound
                                // name so its constant flows.
                                if *value_bearing
                                    && r.members.len() == 1
                                    && r.args.is_empty()
                                    && r.use_kind == UseKind::ValueEscape
                                {
                                    *e = Expr::Name(local);
                                    folded = true;
                                } else {
                                    r.root = Root::Import(local);
                                }
                            }
                            Some(None) => {
                                out.constructs.push(limit_construct(
                                    symbol,
                                    span,
                                    location,
                                    format!("{l}.{m} declared in two files"),
                                ));
                            }
                            None => {}
                        }
                    }
                }
                Root::Local(n) => {
                    if let Some(r2) = package_name_root(
                        w, path, fw, own, span, location, symbol, false, &n, &r.members,
                        r.use_kind, out,
                    ) {
                        r.root = r2;
                    }
                }
                Root::Ambient(n) => {
                    if let Some(r2) = package_name_root(
                        w, path, fw, own, span, location, symbol, true, &n, &r.members, r.use_kind,
                        out,
                    ) {
                        r.root = r2;
                    }
                }
                _ => {}
            }
            for a in r.args.iter_mut().chain(r.kwargs.iter_mut().map(|(_, v)| v)) {
                rewrite_expr(w, rules, path, fw, own, span, location, symbol, a, out);
            }
            if !folded {
                *e = Expr::Reference(r);
            }
        }
        Expr::Template(parts) | Expr::Sequence(parts) => {
            for p in parts.iter_mut() {
                rewrite_expr(w, rules, path, fw, own, span, location, symbol, p, out);
            }
        }
        Expr::Subscript { base, key } => {
            rewrite_expr(w, rules, path, fw, own, span, location, symbol, base, out);
            rewrite_expr(w, rules, path, fw, own, span, location, symbol, key, out);
        }
        Expr::Object(pairs) => {
            for (_, v) in pairs.iter_mut() {
                rewrite_expr(w, rules, path, fw, own, span, location, symbol, v, out);
            }
        }
        _ => {}
    }
}

/// Rewrites one file's IR (KTD8): sibling names and first-party package
/// members bind through synthetic imports; invalid specifiers,
/// ambiguous declarations, and guessed external roots become
/// `resolution-limit` constructs or `unresolved-module` gaps.
fn rewrite_file(w: &mut Work2<'_>, path: &[u8], ir: &mut FileIr, _rt: &RuntimeData) {
    let rules = w.rules;
    let dir = dir_of(path).to_vec();
    let clause = ir.package.clone().unwrap_or_default();
    let own = rules.packages.get(&(dir.clone(), clause));

    // ---- imports ----------------------------------------------------
    let mut fw = FileWork::default();
    for b in &ir.bound_names {
        fw.bound
            .entry(b.symbol.clone())
            .or_default()
            .insert(b.name.clone());
    }
    for sym in &ir.symbols {
        fw.bound
            .entry(sym.path.clone())
            .or_default()
            .extend(sym.params.iter().cloned());
    }
    for (i, imp) in ir.imports.iter().enumerate() {
        if !w.charge() {
            return;
        }
        let spec = imp.specifier.clone();
        if spec.starts_with(FILE_SPECIFIER) {
            continue;
        }
        if !go_import_path(&spec) {
            fw.invalid.push(i);
            continue;
        }
        match rules.resolve(path, &spec) {
            Resolution::Stdlib
            | Resolution::Unresolved
            | Resolution::File(_)
            | Resolution::Outside
            // The cgo pseudo-package needs no rewrite.
            | Resolution::Cgo => {}
            Resolution::Invalid => fw.invalid.push(i),
            Resolution::Ambiguous => {
                if let Some((a, b)) = ambiguous_manifests(rules, path, &spec) {
                    fw.import_constructs.push(limit_construct(
                        &imp.symbol,
                        imp.span,
                        imp.location,
                        format!(
                            "{spec} declared by {} and {}",
                            String::from_utf8_lossy(&a),
                            String::from_utf8_lossy(&b)
                        ),
                    ));
                }
            }
            Resolution::Dir(d) => {
                let Some(tc) = rules.package_clause(&d).map(str::to_string) else {
                    continue;
                };
                if imp.star {
                    fw.star_packages.push((d.clone(), tc));
                    continue;
                }
                let Some(local) = imp.local.clone() else {
                    continue;
                };
                let guess = guessed_local(&spec);
                if local == guess && guess != tc {
                    // An unaliased import binds the package's clause, not
                    // the path's last element.
                    fw.renames.insert(guess, tc.clone());
                    fw.rebind_locals.insert(tc.clone());
                }
                let bound = fw.renames.get(&local).cloned().unwrap_or(local);
                fw.package_locals.insert(bound, (d.clone(), tc));
            }
            Resolution::External => {
                let Some(local) = imp.local.clone() else {
                    continue;
                };
                if local != guessed_local(&spec) {
                    continue;
                }
                match rules.package_names.get(&spec) {
                    // The catalog knows the package's real clause name.
                    Some(name) if *name != local => {
                        fw.renames.insert(local, name.clone());
                        fw.rebind_locals.insert(name.clone());
                    }
                    Some(_) => {}
                    None => fw.unknown_clause = true,
                }
            }
        }
    }
    for i in &fw.invalid {
        ir.imports[*i].specifier = INVALID_SPECIFIER.to_string();
    }
    for imp in ir.imports.iter_mut() {
        if let Some(real) = imp.local.as_ref().and_then(|l| fw.renames.get(l)).cloned() {
            imp.local = Some(real);
        }
    }

    // ---- synthetics ---------------------------------------------------
    let mut out = RewriteOut {
        constructs: std::mem::take(&mut fw.import_constructs),
        ..RewriteOut::default()
    };
    // A first-party star import binds each exported name through a
    // synthetic import pointing at its declaring file; a name the file
    // imports or declares for itself is not rebound.
    for (d, c) in &fw.star_packages {
        let Some(pkg) = rules.packages.get(&(d.clone(), c.clone())) else {
            continue;
        };
        let mut names: Vec<&str> = pkg
            .decls
            .iter()
            .filter(|(n, b)| b.is_some() && n.chars().next().is_some_and(char::is_uppercase))
            .map(|(n, _)| n.as_str())
            .collect();
        names.sort();
        names.dedup();
        for n in names {
            if ir.imports.iter().any(|i| i.local.as_deref() == Some(n)) {
                continue;
            }
            w.charge();
            if out.synth_names.insert(n.to_string()) {
                let file = &pkg.decls[n].as_ref().unwrap().0;
                out.synthetics.push(synthetic(n.to_string(), file, n));
            }
        }
    }

    // ---- references -----------------------------------------------------
    for r in ir.references.iter_mut() {
        if !w.charge() {
            return;
        }
        let (span, location, symbol) = (r.span, r.location, r.symbol.clone());
        rewrite_root(
            w,
            rules,
            path,
            &fw,
            own,
            span,
            location,
            &symbol,
            &mut r.root,
            &r.members,
            r.use_kind,
            &mut out,
        );
        for a in r.args.iter_mut().chain(r.kwargs.iter_mut().map(|(_, v)| v)) {
            rewrite_expr(
                w, rules, path, &fw, own, span, location, &symbol, a, &mut out,
            );
        }
    }
    for l in ir.locals.iter_mut() {
        let (span, symbol) = (l.span, l.symbol.clone());
        rewrite_expr(
            w,
            rules,
            path,
            &fw,
            own,
            span,
            Location { line: 1, column: 1 },
            &symbol,
            &mut l.value,
            &mut out,
        );
    }
    for c in ir.constants.iter_mut() {
        rewrite_expr(
            w,
            rules,
            path,
            &fw,
            own,
            c.span,
            Location { line: 1, column: 1 },
            "<module>",
            &mut c.value,
            &mut out,
        );
    }
    ir.constructs.extend(out.constructs);
    ir.imports.extend(out.synthetics);
}

//! First-party module index and alias resolution.
//!
//! The resolver is language-neutral. Each frontend supplies a
//! [`SpecifierRules`] that turns a module specifier into candidate paths in
//! discovery's file index or into an external module name; the core
//! then decides what the specifier reaches: a first-party file, an external
//! module, a shadowed name, a file that is not code, or a coverage gap.
//! Alias chains across first-party files are followed with a visited set and
//! per-module memoization, so `export *` and glob cycles terminate and diamond
//! fan-out costs linear work. Every lookup is charged one step against a
//! per-reference budget and the global resolver budget; running out of either
//! is a `resolution-limit`, never inert.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::data::{Data, EntryKind, ModuleClass};
use crate::discover::FileKind;
use crate::discover::manifests::fold;
use crate::identity::EncodedPath;
use crate::ir::{FileIr, Import, SymbolKind};
use crate::model::{Label, Language};
use crate::paths::{dir_of, is_dot_relative};

/// Steps one reference may spend before it is a `resolution-limit` blind
/// spot.
pub const PER_REFERENCE_STEPS: u64 = 256;

/// What a frontend's specifier rules make of one specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecifierKind {
    /// A relative or path specifier: candidate index paths in probe order,
    /// already folded onto the root. The first indexed candidate wins.
    Path { probes: Vec<Vec<u8>> },
    /// A relative or path specifier that is absolute or climbs above the
    /// root. The target is never printed.
    OutsideRoot,
    /// A bare specifier: first-party candidates (empty when the language has
    /// none for this name) and the external module it names otherwise, in
    /// runtime form (`os.path`, `fs/promises` with `node:` stripped,
    /// `std::net` after crate renames).
    Bare {
        probes: Vec<Vec<u8>>,
        module: String,
    },
}

/// Per-language specifier rules. Frontends implement these; the core
/// owns what the result means.
pub trait SpecifierRules: Send + Sync {
    /// Classifies `specifier` as written in the file at `from`.
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind;

    /// The specifier of submodule `member` of the module `specifier` names,
    /// for languages where `from pkg import sub` can name a submodule file.
    fn submodule(&self, _specifier: &str, _member: &str) -> Option<String> {
        None
    }

    /// The unscanned-dependency key `module` takes for a use in `from`,
    /// defaulting to [`package_name`]. Go keys a dependency by the
    /// longest matching `require` module of the importing file's `go.mod`,
    /// re-keyed to `path@version` when a module-path `replace` applies
    /// (KTD9, KTD10).
    fn package_key(&self, language: Language, _from: &[u8], module: &str) -> String {
        package_name(language, module)
    }

    /// Whether `module` in `from` is re-keyed by a manifest-level
    /// `replace` (Go). When it is, the original module's inert catalog
    /// rows do not apply: the code that ships is the replacement's.
    fn replaced(&self, _from: &[u8], _module: &str) -> bool {
        false
    }
}

/// Rules that resolve `./` and `../` specifiers by appending each extension
/// and then probing `<index name><extension>` inside a directory of that
/// name; everything else is a bare external module. Frontends with richer
/// rules supply their own [`SpecifierRules`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenericRules {
    pub extensions: Vec<String>,
    pub index_names: Vec<String>,
}

impl GenericRules {
    /// Exact paths only.
    pub fn exact() -> GenericRules {
        GenericRules::default()
    }
}

impl SpecifierRules for GenericRules {
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind {
        let relative = is_dot_relative(specifier);
        if specifier.starts_with('/') {
            return SpecifierKind::OutsideRoot;
        }
        if !relative {
            return SpecifierKind::Bare {
                probes: Vec::new(),
                module: specifier.to_string(),
            };
        }
        let Some(base) = fold(dir_of(from), specifier) else {
            return SpecifierKind::OutsideRoot;
        };
        let mut probes = vec![base.clone()];
        for ext in &self.extensions {
            let mut p = base.clone();
            p.extend_from_slice(ext.as_bytes());
            probes.push(p);
        }
        for name in &self.index_names {
            for ext in &self.extensions {
                let mut p = base.clone();
                if !p.is_empty() {
                    p.push(b'/');
                }
                p.extend_from_slice(name.as_bytes());
                p.extend_from_slice(ext.as_bytes());
                probes.push(p);
            }
        }
        SpecifierKind::Path { probes }
    }
}

/// What a specifier reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A lowered first-party source file.
    FirstParty(Vec<u8>),
    /// An indexed first-party source file with no IR (it is already a
    /// whole-file blind spot or past the files budget).
    Unlowered(Vec<u8>),
    /// A standard library module, catalogued package, or other dependency.
    External(String),
    /// A first-party module whose name shadows a standard library module or
    /// a catalogued package with egress members.
    Shadowed(String),
    /// A relative or path specifier with no target in the index.
    Unresolved,
    OutsideRoot,
    IntoExcluded,
    /// An indexed file that is not code, loaded as code.
    LoadedAsCode(Vec<u8>),
    /// An unsupported code file type; discovery already reported it.
    Unsupported(Vec<u8>),
    /// JSON loaded by a JS loader: data, exempt.
    Data,
}

/// What a name or import binding means after alias resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// An external module plus a member chain below it.
    External {
        module: String,
        members: Vec<String>,
    },
    /// A first-party module object.
    FirstPartyModule(Vec<u8>),
    /// A first-party definition: `name` in the module at `path`.
    FirstPartyDef { path: Vec<u8>, name: String },
    /// First-party code the resolver does not look into.
    FirstParty,
    /// A type-only import.
    Inert,
    /// An import whose specifier did not resolve to a module; the import
    /// itself reports it.
    Gap(Target),
}

/// The per-reference or global resolver budget ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit;

/// One lowered first-party file.
#[derive(Debug, Clone)]
pub struct ProgramFile<'a> {
    pub file: EncodedPath,
    pub language: Language,
    pub labels: Vec<Label>,
    pub ir: &'a FileIr,
}

/// The first-party program: lowered files plus discovery's file index.
pub struct Program<'a> {
    pub files: BTreeMap<Vec<u8>, ProgramFile<'a>>,
    pub index: &'a BTreeMap<Vec<u8>, FileKind>,
    pub excluded_dirs: &'a BTreeSet<Vec<u8>>,
    rules: BTreeMap<Language, &'a dyn SpecifierRules>,
}

static EXACT: GenericRules = GenericRules {
    extensions: Vec::new(),
    index_names: Vec::new(),
};

impl<'a> Program<'a> {
    pub fn new(
        index: &'a BTreeMap<Vec<u8>, FileKind>,
        excluded_dirs: &'a BTreeSet<Vec<u8>>,
    ) -> Program<'a> {
        Program {
            files: BTreeMap::new(),
            index,
            excluded_dirs,
            rules: BTreeMap::new(),
        }
    }

    pub fn add_file(&mut self, path: Vec<u8>, file: ProgramFile<'a>) {
        self.files.insert(path, file);
    }

    /// Sets the specifier rules for `language`; a language without rules
    /// uses [`GenericRules::exact`].
    pub fn set_rules(&mut self, language: Language, rules: &'a dyn SpecifierRules) {
        self.rules.insert(language, rules);
    }

    pub fn rules(&self, language: Language) -> &dyn SpecifierRules {
        self.rules.get(&language).copied().unwrap_or(&EXACT)
    }

    /// Whether `path` is an excluded directory or lies inside one. Each
    /// ancestor is looked up in the set, so the cost follows the path's
    /// depth, not the number of excluded directories.
    fn under_excluded(&self, path: &[u8]) -> bool {
        self.excluded_dirs.contains(path)
            || path
                .iter()
                .enumerate()
                .any(|(i, &b)| b == b'/' && self.excluded_dirs.contains(&path[..i]))
    }
}

/// The module part of a specifier split into the segments `data::lookup`
/// takes. JS module names may hold `.` (`socket.io`), so they stay whole.
pub fn module_segments(language: Language, module: &str) -> Vec<String> {
    match language {
        // JS module names may hold `.`; Go import paths hold `.` and `/`
        // and the data declares each path whole (`net/http`).
        Language::Javascript | Language::Go => vec![module.to_string()],
        Language::Python => module.split('.').map(str::to_string).collect(),
        Language::Rust => module.split("::").map(str::to_string).collect(),
    }
}

/// The package an external module belongs to, as unscanned dependencies
/// name it: the Python top-level module, the npm package (`@scope/name`,
/// `lodash` for `lodash/fp`), or the Rust crate.
pub fn package_name(language: Language, module: &str) -> String {
    match language {
        Language::Python => module.split('.').next().unwrap_or(module).to_string(),
        Language::Rust => module.split("::").next().unwrap_or(module).to_string(),
        // A Go unscanned dependency is keyed by the module path its
        // specifier rules already computed (R12); the string is whole.
        Language::Go => module.to_string(),
        Language::Javascript => {
            let m = module.strip_prefix("node:").unwrap_or(module);
            let mut parts = m.split('/');
            let first = parts.next().unwrap_or(m);
            if first.starts_with('@') {
                match parts.next() {
                    Some(second) => format!("{first}/{second}"),
                    None => first.to_string(),
                }
            } else {
                first.to_string()
            }
        }
    }
}

/// Alias resolution with memoization and budgets.
pub struct Resolver<'p, 'a> {
    program: &'p Program<'a>,
    data: &'p Data,
    targets: HashMap<(Vec<u8>, String), Target>,
    exports: HashMap<(Vec<u8>, String), Option<Binding>>,
    /// Lookups under way, with their depth on the lookup stack.
    in_progress: HashMap<(Vec<u8>, String), usize>,
    /// The shallowest in-progress depth a cycle cut reached below the
    /// current lookup, or `usize::MAX` when none did.
    cut_depth: usize,
    budget: u64,
    steps: u64,
    reference_steps: u64,
    exhausted: bool,
}

impl<'p, 'a> Resolver<'p, 'a> {
    pub fn new(program: &'p Program<'a>, data: &'p Data, budget: u64) -> Self {
        Resolver {
            program,
            data,
            targets: HashMap::new(),
            exports: HashMap::new(),
            in_progress: HashMap::new(),
            cut_depth: usize::MAX,
            budget,
            steps: 0,
            reference_steps: 0,
            exhausted: false,
        }
    }

    /// Steps charged so far across the scan.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Whether the global resolver budget ran out.
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Starts a new reference: resets the per-reference step count.
    pub fn begin_reference(&mut self) {
        self.reference_steps = 0;
    }

    /// Charges one resolver step, the way every resolution inside a
    /// reference does. The derived-site pass charges each wrapper hop
    /// against the same shared budget (KTD7).
    pub(crate) fn step(&mut self) -> Result<(), Limit> {
        if self.exhausted {
            return Err(Limit);
        }
        if self.steps >= self.budget {
            self.exhausted = true;
            return Err(Limit);
        }
        if self.reference_steps >= PER_REFERENCE_STEPS {
            return Err(Limit);
        }
        self.steps += 1;
        self.reference_steps += 1;
        Ok(())
    }

    /// What `specifier`, written in the first-party file at `from`, reaches.
    pub fn target(&mut self, from: &[u8], language: Language, specifier: &str) -> Target {
        let key = (from.to_vec(), specifier.to_string());
        if let Some(t) = self.targets.get(&key) {
            return t.clone();
        }
        let t = self.compute_target(from, language, specifier);
        self.targets.insert(key, t.clone());
        t
    }

    fn probe(&self, language: Language, probes: &[Vec<u8>]) -> Option<Target> {
        for p in probes {
            match self.program.index.get(p) {
                Some(FileKind::Source(_)) => {
                    return Some(if self.program.files.contains_key(p) {
                        Target::FirstParty(p.clone())
                    } else {
                        Target::Unlowered(p.clone())
                    });
                }
                Some(FileKind::Unsupported) => return Some(Target::Unsupported(p.clone())),
                Some(FileKind::Other) => {
                    // The `.json`-as-data exemption is JavaScript-only
                    // (KTD2): another language loading an indexed
                    // non-source file is `loaded-as-code`, failing closed.
                    return Some(
                        if language == Language::Javascript && p.ends_with(b".json") {
                            Target::Data
                        } else {
                            Target::LoadedAsCode(p.clone())
                        },
                    );
                }
                None => {}
            }
        }
        None
    }

    fn compute_target(&self, from: &[u8], language: Language, specifier: &str) -> Target {
        match self.program.rules(language).classify(from, specifier) {
            SpecifierKind::OutsideRoot => Target::OutsideRoot,
            SpecifierKind::Path { probes } => {
                if let Some(t) = self.probe(language, &probes) {
                    return t;
                }
                if probes.iter().any(|p| self.program.under_excluded(p)) {
                    Target::IntoExcluded
                } else {
                    Target::Unresolved
                }
            }
            SpecifierKind::Bare { probes, module } => {
                // `node:` is a JavaScript-only specifier prefix.
                let module = match language {
                    Language::Javascript => {
                        module.strip_prefix("node:").unwrap_or(&module).to_string()
                    }
                    Language::Python | Language::Rust | Language::Go => module,
                };
                let first_party = probes.iter().find_map(|p| match self.program.index.get(p) {
                    Some(FileKind::Source(_)) => Some(p.clone()),
                    _ => None,
                });
                match first_party {
                    Some(p) => {
                        if self.shadows(language, &module) {
                            Target::Shadowed(module)
                        } else if self.program.files.contains_key(&p) {
                            Target::FirstParty(p)
                        } else {
                            Target::Unlowered(p)
                        }
                    }
                    None => match language {
                        // A Python absolute import whose candidate lies in an
                        // excluded directory (a first-party package marked by
                        // a `pyvenv.cfg`) reaches code the scan skipped. A
                        // real environment keeps packages under
                        // `site-packages`, so a module probe directly inside
                        // one is never an installed dependency. JS and Rust
                        // bare probes are workspace package entry points and
                        // stay external.
                        Language::Python
                            if probes.iter().any(|p| self.program.under_excluded(p)) =>
                        {
                            Target::IntoExcluded
                        }
                        // Go bare specifiers are import paths; its rules map
                        // the first-party cases to probes, so a bare module
                        // here is always external.
                        Language::Python | Language::Javascript | Language::Rust | Language::Go => {
                            Target::External(module)
                        }
                    },
                }
            }
        }
    }

    /// Whether a first-party module named like `module` shadows a standard
    /// library module or a catalogued package with egress members.
    fn shadows(&self, language: Language, module: &str) -> bool {
        let rt = self.data.runtime(language);
        let top = package_name(language, module);
        if rt
            .module(&top)
            .is_some_and(|m| m.class == ModuleClass::Egress)
        {
            return true;
        }
        let Some(pkg) = rt.package_for(&top) else {
            return false;
        };
        !pkg.modules.iter().all(|m| {
            rt.entries_under(m)
                .all(|e| matches!(e.kind, EntryKind::Inert { .. }))
        })
    }

    /// Resolves an import in the first-party file at `from`.
    pub fn import(
        &mut self,
        from: &[u8],
        language: Language,
        import: &Import,
    ) -> Result<Binding, Limit> {
        self.step()?;
        if import.type_only {
            return Ok(Binding::Inert);
        }
        let target = self.target(from, language, &import.specifier);
        // A default binding names the module's `default` member first: the
        // whole module for an external module, and for a first-party JS
        // module its `default` export, or the module object itself when it
        // has none, as `require` and CommonJS interop give `module.exports`.
        let via_default =
            import.default && (import.members.is_empty() || import.members[0] == "default");
        let members: Vec<String> = if via_default && !import.members.is_empty() {
            import.members[1..].to_vec()
        } else {
            import.members.clone()
        };
        match target {
            Target::External(module) => Ok(Binding::External { module, members }),
            Target::FirstParty(path) => {
                // `default`-export interop is JavaScript-only (CommonJS
                // `module.exports` semantics); other languages have no
                // default export to follow.
                if via_default && language == Language::Javascript {
                    let b = match self.export(&path, "default")? {
                        Some(b) => b,
                        None => Binding::FirstPartyModule(path),
                    };
                    return self.walk(b, &members);
                }
                if members.is_empty() {
                    return Ok(Binding::FirstPartyModule(path));
                }
                let first = self.export(&path, &members[0])?;
                let b = match first {
                    Some(b) => b,
                    None => {
                        let sub = self
                            .program
                            .rules(language)
                            .submodule(&import.specifier, &members[0]);
                        match sub.map(|s| self.target(from, language, &s)) {
                            Some(Target::FirstParty(p)) => Binding::FirstPartyModule(p),
                            Some(Target::External(m)) => Binding::External {
                                module: m,
                                members: Vec::new(),
                            },
                            Some(Target::Unlowered(_)) => Binding::FirstParty,
                            // No module of that name: a name the package
                            // binds in a way the index does not record.
                            None | Some(Target::Unresolved) => Binding::FirstPartyDef {
                                path: path.clone(),
                                name: members[0].clone(),
                            },
                            // A submodule the scan cannot follow (excluded,
                            // outside the root, not code) is a gap, as a
                            // direct import of it is.
                            Some(t) => Binding::Gap(t),
                        }
                    }
                };
                self.walk(b, &members[1..])
            }
            Target::Unlowered(_) => Ok(Binding::FirstParty),
            other => Ok(Binding::Gap(other)),
        }
    }

    /// Follows a member chain from `binding` through first-party modules.
    pub fn walk(&mut self, binding: Binding, members: &[String]) -> Result<Binding, Limit> {
        let mut b = binding;
        for (i, m) in members.iter().enumerate() {
            match b {
                Binding::External {
                    module,
                    members: mut ms,
                } => {
                    ms.extend(members[i..].iter().cloned());
                    return Ok(Binding::External {
                        module,
                        members: ms,
                    });
                }
                Binding::FirstPartyModule(path) => {
                    self.step()?;
                    b = match self.export(&path, m)? {
                        Some(next) => next,
                        None => Binding::FirstPartyDef {
                            path,
                            name: m.clone(),
                        },
                    };
                }
                // A Rust definition may be an inline module or a type: its
                // members are qualified names in the same file (`net` plus
                // `TcpStream` is `net::TcpStream`). Rust-only: other
                // languages' members are not `::`-qualified in the file.
                Binding::FirstPartyDef { path, name }
                    if self.program.files.get(&path).map(|f| f.language)
                        == Some(Language::Rust) =>
                {
                    self.step()?;
                    let q = format!("{name}::{m}");
                    b = match self.export(&path, &q)? {
                        Some(next) => next,
                        None => Binding::FirstPartyDef { path, name: q },
                    };
                }
                // A member of a first-party definition is first-party code.
                Binding::FirstPartyDef { .. } => return Ok(Binding::FirstParty),
                other => return Ok(other),
            }
        }
        Ok(b)
    }

    /// The binding a module-level `name` has in the first-party module at
    /// `path`, or `None` when the module does not define or import it.
    pub fn export(&mut self, path: &[u8], name: &str) -> Result<Option<Binding>, Limit> {
        self.step()?;
        let key = (path.to_vec(), name.to_string());
        if let Some(b) = self.exports.get(&key) {
            return Ok(b.clone());
        }
        if let Some(&depth) = self.in_progress.get(&key) {
            // A cycle: this module is already being searched for `name`.
            // The answer here is partial, so no lookup between the cut and
            // that outer search may be memoized.
            self.cut_depth = self.cut_depth.min(depth);
            return Ok(None);
        }
        let depth = self.in_progress.len();
        self.in_progress.insert(key.clone(), depth);
        let outer_cut = std::mem::replace(&mut self.cut_depth, usize::MAX);
        let result = self.compute_export(path, name);
        self.in_progress.remove(&key);
        let cut = self.cut_depth;
        self.cut_depth = outer_cut.min(cut);
        let result = result?;
        // A cut back to this lookup itself loses nothing: every path that
        // returns here was searched from here. A cut to a shallower lookup
        // leaves this answer incomplete for any later caller.
        if cut >= depth {
            self.exports.insert(key, result.clone());
        }
        Ok(result)
    }

    fn compute_export(&mut self, path: &[u8], name: &str) -> Result<Option<Binding>, Limit> {
        let program = self.program;
        let Some(pf) = program.files.get(path) else {
            return Ok(Some(Binding::FirstParty));
        };
        let language = pf.language;
        let ir = pf.ir;
        // Rust module-level items in inline modules carry qualified local
        // names and the frontend marks every module-level item visible, since
        // Rust lets descendants name private imports; block-level ones are not.
        let visible = |i: &Import| match language {
            Language::Python => i.symbol == "<module>",
            Language::Rust => i.re_export,
            Language::Javascript => i.symbol == "<module>" && i.re_export,
            // Go imports are file-scoped at `<module>` and Go has no
            // re-export form.
            Language::Go => i.symbol == "<module>",
        };
        // A Rust glob applies to names in the module that declares it.
        let (scope, leaf) = match language {
            Language::Rust => match name.rsplit_once("::") {
                Some((s, l)) => (s, l),
                None => ("<module>", name),
            },
            Language::Python | Language::Javascript | Language::Go => ("<module>", name),
        };
        // An import binding the name. An import is preferred over a
        // definition of the same name because the IR does not record which
        // comes last, and the import is the one that can reach egress.
        if let Some(imp) = ir
            .imports
            .iter()
            .find(|i| !i.star && visible(i) && i.local.as_deref() == Some(name))
        {
            return self.import(path, language, imp).map(Some);
        }
        let defined = ir
            .symbols
            .iter()
            .any(|s| s.path == name && s.kind != SymbolKind::Module)
            || ir.constants.iter().any(|c| c.name == name)
            || ir
                .locals
                .iter()
                .any(|l| l.symbol == "<module>" && l.name == name);
        if defined {
            return Ok(Some(Binding::FirstPartyDef {
                path: path.to_vec(),
                name: name.to_string(),
            }));
        }
        // Star and glob imports, first-party ones expanded from source.
        let mut external_star: Option<Binding> = None;
        let stars: Vec<&Import> = ir
            .imports
            .iter()
            .filter(|i| i.star && !i.type_only && visible(i))
            // The `i.symbol == scope` restriction is Rust-only: a Rust glob
            // is declared inside an inline module. Other languages' star
            // imports apply module-wide.
            .filter(|i| language != Language::Rust || i.symbol == scope)
            .collect();
        for imp in stars {
            match self.star_module(path, language, imp)? {
                Some(Binding::External { module, members }) => {
                    if let Some(b) = self.external_member(language, &module, &members, leaf) {
                        return Ok(Some(b));
                    }
                    let mut ms = members;
                    ms.push(leaf.to_string());
                    external_star.get_or_insert(Binding::External {
                        module,
                        members: ms,
                    });
                }
                Some(m) => {
                    if let Some(b) = self.module_member(m, language, leaf)? {
                        return Ok(Some(b));
                    }
                }
                None => {}
            }
        }
        // A name no first-party source defines but an external star import
        // may provide resolves to that module, failing closed.
        if external_star.is_some() {
            return Ok(external_star);
        }
        // A JS module whose own `default` export re-exports a module
        // (CommonJS `module.exports = require("https")`) provides that
        // module's members as named exports, as CommonJS interop does. Only
        // the module's own binding counts, since `export *` never carries a
        // `default`. JavaScript-only: other languages have no `default`
        // export interop.
        if language == Language::Javascript
            && name != "default"
            && let Some(imp) = ir
                .imports
                .iter()
                .find(|i| !i.star && visible(i) && i.local.as_deref() == Some("default"))
            && let d @ (Binding::External { .. } | Binding::FirstPartyModule(_)) =
                self.import(path, language, imp)?
        {
            return self.walk(d, &[name.to_string()]).map(Some);
        }
        Ok(None)
    }

    /// The module a star or glob import names: its specifier's target walked
    /// through the import's member path (Rust `use crate::m::*` names `m`).
    fn star_module(
        &mut self,
        from: &[u8],
        language: Language,
        imp: &Import,
    ) -> Result<Option<Binding>, Limit> {
        let base = match self.target(from, language, &imp.specifier) {
            Target::FirstParty(p) => Binding::FirstPartyModule(p),
            Target::External(m) => Binding::External {
                module: m,
                members: Vec::new(),
            },
            _ => return Ok(None),
        };
        self.walk(base, &imp.members).map(Some)
    }

    /// `name` in a first-party module binding, or `None`.
    fn module_member(
        &mut self,
        module: Binding,
        language: Language,
        name: &str,
    ) -> Result<Option<Binding>, Limit> {
        match module {
            Binding::FirstPartyModule(p) => self.export(&p, name),
            // Rust-only: a first-party definition's members are the
            // `::`-qualified names in its file.
            Binding::FirstPartyDef { path, name: q } if language == Language::Rust => {
                self.export(&path, &format!("{q}::{name}"))
            }
            _ => Ok(None),
        }
    }

    /// `name` in an external module when the data classifies it as an entry.
    fn external_member(
        &self,
        language: Language,
        module: &str,
        members: &[String],
        name: &str,
    ) -> Option<Binding> {
        let rt = self.data.runtime(language);
        let segs = module_segments(language, module);
        let mut rest: Vec<&str> = segs[1..]
            .iter()
            .chain(members.iter())
            .map(String::as_str)
            .collect();
        rest.push(name);
        if matches!(
            rt.lookup(&segs[0], &rest),
            Some(crate::data::Classification::Entry(_))
        ) {
            let mut ms = members.to_vec();
            ms.push(name.to_string());
            Some(Binding::External {
                module: module.to_string(),
                members: ms,
            })
        } else {
            None
        }
    }

    /// `name` as provided by the star or glob import `imp` written in the
    /// file at `from`, or `None` when that import does not provide it.
    pub fn star_member(
        &mut self,
        from: &[u8],
        language: Language,
        imp: &Import,
        name: &str,
    ) -> Result<Option<Binding>, Limit> {
        match self.star_module(from, language, imp)? {
            Some(Binding::External { module, members }) => {
                Ok(self.external_member(language, &module, &members, name))
            }
            Some(m) => self.module_member(m, language, name),
            None => Ok(None),
        }
    }
}

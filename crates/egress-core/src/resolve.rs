//! First-party module index and alias resolution (KTD2, KTD16, KTD19).
//!
//! The resolver is language-neutral. Each frontend supplies a
//! [`SpecifierRules`] that turns a module specifier into candidate paths in
//! discovery's file index (KTD12) or into an external module name; the core
//! then decides what the specifier reaches: a first-party file, an external
//! module, a shadowed name, a file that is not code, or a coverage gap.
//! Alias chains across first-party files are followed with a visited set and
//! per-module memoization, so `export *` and glob cycles terminate and diamond
//! fan-out costs linear work. Every lookup is charged one step against a
//! per-reference budget and the global resolver budget; running out of either
//! is a `resolution-limit`, never inert.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::data::{Data, EntryKind, ModuleClass};
use crate::discover::FileKind;
use crate::discover::manifests::fold;
use crate::identity::EncodedPath;
use crate::ir::{FileIr, Import, SymbolKind};
use crate::model::{Label, Language};

/// Steps one reference may spend before it is a `resolution-limit` blind
/// spot (KTD16).
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

/// Per-language specifier rules (KTD16). Frontends implement these; the core
/// owns what the result means.
pub trait SpecifierRules: Send + Sync {
    /// Classifies `specifier` as written in the file at `from`.
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind;

    /// The specifier of submodule `member` of the module `specifier` names,
    /// for languages where `from pkg import sub` can name a submodule file.
    fn submodule(&self, _specifier: &str, _member: &str) -> Option<String> {
        None
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

fn dir_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[..i],
        None => b"",
    }
}

impl SpecifierRules for GenericRules {
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind {
        let relative = specifier == "."
            || specifier == ".."
            || specifier.starts_with("./")
            || specifier.starts_with("../");
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
    /// JSON loaded by a JS loader: data, exempt (KTD12).
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

    fn under_excluded(&self, path: &[u8]) -> bool {
        self.excluded_dirs.iter().any(|d| {
            path == d.as_slice()
                || (path.len() > d.len() && path.starts_with(d) && path[d.len()] == b'/')
        })
    }
}

/// The module part of a specifier split into the segments `data::lookup`
/// takes. JS module names may hold `.` (`socket.io`), so they stay whole.
pub fn module_segments(language: Language, module: &str) -> Vec<String> {
    match language {
        Language::Javascript => vec![module.to_string()],
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
    in_progress: HashSet<(Vec<u8>, String)>,
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
            in_progress: HashSet::new(),
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

    fn step(&mut self) -> Result<(), Limit> {
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
                let module = match language {
                    Language::Javascript => {
                        module.strip_prefix("node:").unwrap_or(&module).to_string()
                    }
                    _ => module,
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
                    None => Target::External(module),
                }
            }
        }
    }

    /// Whether a first-party module named like `module` shadows a standard
    /// library module or a catalogued package with egress members (KTD16).
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
        let sep = crate::data::separator(language);
        rt.entries.iter().any(|e| {
            !matches!(e.kind, EntryKind::Inert { .. })
                && pkg
                    .modules
                    .iter()
                    .any(|m| e.module == *m || e.module.starts_with(&format!("{m}{sep}")))
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
        let members: Vec<String> = if import.default && import.members == ["default"] {
            Vec::new()
        } else {
            import.members.clone()
        };
        match target {
            Target::External(module) => Ok(Binding::External { module, members }),
            Target::FirstParty(path) => {
                if members.is_empty() {
                    if import.default && language == Language::Javascript {
                        return self
                            .walk(Binding::FirstPartyModule(path), &["default".to_string()]);
                    }
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
                            _ => Binding::FirstPartyDef {
                                path: path.clone(),
                                name: members[0].clone(),
                            },
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
        if !self.in_progress.insert(key.clone()) {
            // A cycle: this module is already being searched for `name`.
            return Ok(None);
        }
        let result = self.compute_export(path, name);
        self.in_progress.remove(&key);
        let result = result?;
        self.exports.insert(key, result.clone());
        Ok(result)
    }

    fn compute_export(&mut self, path: &[u8], name: &str) -> Result<Option<Binding>, Limit> {
        let program = self.program;
        let Some(pf) = program.files.get(path) else {
            return Ok(Some(Binding::FirstParty));
        };
        let language = pf.language;
        let ir = pf.ir;
        let visible =
            |i: &Import| i.symbol == "<module>" && (language == Language::Python || i.re_export);
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
        let mut external_star: Option<String> = None;
        let stars: Vec<&Import> = ir
            .imports
            .iter()
            .filter(|i| i.star && !i.type_only && visible(i))
            .collect();
        for imp in stars {
            match self.target(path, language, &imp.specifier) {
                Target::FirstParty(p) => {
                    if let Some(b) = self.export(&p, name)? {
                        return Ok(Some(b));
                    }
                }
                Target::External(m) => {
                    let rt = self.data.runtime(language);
                    let segs = module_segments(language, &m);
                    let mut members: Vec<&str> = segs[1..].iter().map(String::as_str).collect();
                    members.push(name);
                    if matches!(
                        rt.lookup(&segs[0], &members),
                        Some(crate::data::Classification::Entry(_))
                    ) {
                        return Ok(Some(Binding::External {
                            module: m,
                            members: vec![name.to_string()],
                        }));
                    }
                    external_star.get_or_insert(m);
                }
                _ => {}
            }
        }
        // A name no first-party source defines but an external star import
        // may provide resolves to that module, failing closed.
        Ok(external_star.map(|m| Binding::External {
            module: m,
            members: vec![name.to_string()],
        }))
    }
}

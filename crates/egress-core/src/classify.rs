//! Member-level classification (KTD5, KTD8, KTD15) and destination
//! resolution (KTD7) over the IR of every lowered first-party file.
//!
//! Each import and reference is resolved through the first-party alias
//! chains ([`crate::resolve`]) to a head: an external module plus a literal
//! member chain, the ambient module, a tracked client instance, first-party
//! code, or a value of untracked origin. The head plus the use kind decide
//! the outcome: an egress site with a destination, a blind spot, an
//! unscanned-dependency listing, or nothing. Items are visited in byte-wise
//! file order and source order within a file, which is the order resolver
//! steps are charged in (KTD19).
//!
//! Frontend contract points this module relies on:
//! - A literal-argument loader call (`require("http")`, `__import__("os")`,
//!   `importlib.import_module("json")`, TS `import x = require("net")`) is
//!   lowered as an [`Import`]; the call itself produces nothing here.
//! - Positional parameter indices in [`Expr::Param`] already exclude `self`,
//!   `cls`, and Rust receivers.
//! - A computed or reflective access with a non-literal name carries its
//!   receiver's [`Provenance`].

use std::collections::{BTreeMap, BTreeSet};

use crate::data::{
    Classification, Data, DestinationForm, DestinationSpec, Entry, EntryKind, ModuleClass, Origin,
    RuntimeData, separator,
};
use crate::destination::{self, TemplatePart};
use crate::discover::labels::path_labels;
use crate::identity::encode_path_bytes;
use crate::ir::{ConstructKind, Expr, Import, Provenance, Reference, Root, UseKind};
use crate::model::{
    BlindSpot, BlindSpotKind, Bucket, Destination, Language, Location, Site, UnscannedDependency,
};
use crate::resolve::{
    Binding, Limit, Program, ProgramFile, Resolver, Target, module_segments, package_name,
};

/// Findings from the classification stage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Classified {
    pub sites: Vec<Site>,
    pub blind_spots: Vec<BlindSpot>,
    pub unscanned_dependencies: Vec<UnscannedDependency>,
    /// Indexed non-code files loaded as code; each is skipped under
    /// `unsupported` in coverage.
    pub loaded_as_code: u64,
    pub resolver_budget_exceeded: bool,
    pub resolver_steps: u64,
}

/// Depth limit for evaluating a destination expression through locals and
/// constants.
const MAX_EVAL_DEPTH: u32 = 8;
/// Local alias hops followed from one reference (KTD8 tracks one hop).
const MAX_ALIAS_HOPS: u32 = 2;

/// Reflective builtins whose name argument, when literal, makes the call an
/// ordinary member access (KTD15): entry ID, target argument, name argument
/// (both 1-based), and whether the access is a write.
const NAME_TAKING: &[(&str, usize, usize, bool)] = &[
    ("python:builtins.getattr", 1, 2, false),
    ("python:builtins.setattr", 1, 2, true),
    ("python:builtins.delattr", 1, 2, true),
    ("javascript:globalThis.Reflect.get", 1, 2, false),
    ("javascript:globalThis.Reflect.set", 1, 2, true),
    ("javascript:globalThis.Reflect.defineProperty", 1, 2, true),
    ("javascript:globalThis.Reflect.deleteProperty", 1, 2, true),
];

/// Worker constructors: a literal in-root specifier without `eval: true`
/// resolves; anything else is the entry's blind spot (KTD15).
const WORKERS: &[&str] = &[
    "javascript:worker_threads.Worker",
    "javascript:globalThis.Worker",
];

/// Ambient JS calls that write to their first argument (KTD15): with an
/// egress-bucket module as that argument they are a monkeypatch.
const OBJECT_WRITES: &[&[&str]] = &[
    &["Object", "defineProperty"],
    &["Object", "defineProperties"],
    &["Object", "assign"],
];

/// The entries [`NAME_TAKING`] and [`WORKERS`] name, for data guards.
pub fn special_entry_ids() -> Vec<&'static str> {
    NAME_TAKING
        .iter()
        .map(|t| t.0)
        .chain(WORKERS.iter().copied())
        .collect()
}

/// Classifies every lowered file in `program`, charging resolver steps
/// against `resolver_steps` (KTD19).
pub fn classify(data: &Data, program: &Program<'_>, resolver_steps: u64) -> Classified {
    let mut st = State {
        data,
        program,
        r: Resolver::new(program, data, resolver_steps),
        out: Classified::default(),
        deps: BTreeMap::new(),
        loaded: BTreeSet::new(),
    };
    for (path, pf) in &program.files {
        st.file(Ctx {
            path,
            pf,
            rt: data.runtime(pf.language),
        });
    }
    st.finish()
}

#[derive(Clone, Copy)]
struct Ctx<'p, 'a> {
    path: &'p [u8],
    pf: &'p ProgramFile<'a>,
    rt: &'p RuntimeData,
}

impl Ctx<'_, '_> {
    fn lang(&self) -> Language {
        self.pf.language
    }
}

/// What a reference's root and member chain resolve to.
#[derive(Debug, Clone)]
enum Head {
    /// An external module plus the member chain below it.
    Ext {
        module: String,
        chain: Vec<String>,
    },
    /// The ambient module plus the chain below it, aliases stripped.
    Ambient {
        chain: Vec<String>,
    },
    /// A method chain on a tracked client instance (KTD8): `chain` runs
    /// from `module` to the method; a method entry's ID starts with
    /// `prefix` and differs from the constructor entry `ctor`.
    Tracked {
        module: String,
        chain: Vec<String>,
        ctor: String,
        prefix: String,
    },
    FirstPartyModule,
    FirstParty,
    /// A value of untracked origin (parameter, call result).
    Untracked,
    /// Reported elsewhere (an import gap) or type-only.
    Nothing,
}

/// A destination value under evaluation.
#[derive(Debug, Clone)]
enum Val {
    Lit(String),
    Dest(Destination),
    Seq(Vec<Expr>),
    Obj(Vec<(String, Expr)>),
}

struct State<'p, 'a> {
    data: &'p Data,
    program: &'p Program<'a>,
    r: Resolver<'p, 'a>,
    out: Classified,
    deps: BTreeMap<(Language, String), BTreeSet<String>>,
    loaded: BTreeSet<Vec<u8>>,
}

enum Item<'p> {
    Import(&'p Import),
    Ref(&'p Reference),
}

fn is_call(u: UseKind) -> bool {
    matches!(u, UseKind::Call | UseKind::Construct)
}

/// Renders an expression as source-like text for `expr:` destinations.
fn render(e: &Expr) -> String {
    match e {
        Expr::Literal(s) => format!("{s:?}"),
        Expr::Template(parts) => parts.iter().map(render).collect::<Vec<_>>().join(" + "),
        Expr::Name(n) => n.clone(),
        Expr::Param(i) => format!("<parameter {i}>"),
        Expr::Reference(r) => r.text.clone(),
        Expr::Sequence(items) => {
            format!(
                "[{}]",
                items.iter().map(render).collect::<Vec<_>>().join(", ")
            )
        }
        Expr::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(k, v)| format!("{k}: {}", render(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Expr::Subscript { base, key } => format!("{}[{}]", render(base), render(key)),
        Expr::Opaque(t) => t.clone(),
    }
}

fn to_dest(v: Val) -> Destination {
    match v {
        Val::Lit(s) => destination::literal(&s),
        Val::Dest(d) => d,
        Val::Seq(items) => destination::expr(&render(&Expr::Sequence(items))),
        Val::Obj(fields) => destination::expr(&render(&Expr::Object(fields))),
    }
}

fn to_part(v: Val) -> TemplatePart {
    match v {
        Val::Lit(s) => TemplatePart::Literal(s),
        other => TemplatePart::Hole(to_dest(other)),
    }
}

/// The class owning a method symbol path (`Api.users` gives `Api`).
fn enclosing_class(symbol: &str) -> Option<&str> {
    symbol.rsplit_once('.').map(|(c, _)| c)
}

impl<'p, 'a> State<'p, 'a> {
    // ---- emission ------------------------------------------------------------

    fn site(
        &mut self,
        cx: Ctx<'p, 'a>,
        rf: &Reference,
        bucket: Bucket,
        mechanism: &str,
        destination: Destination,
    ) {
        self.out.sites.push(Site {
            id: String::new(),
            language: cx.lang(),
            file: cx.pf.file.display.clone(),
            file_bytes: cx.pf.file.bytes_hex.clone(),
            symbol: rf.symbol.clone(),
            bucket,
            mechanism: mechanism.to_string(),
            destination,
            ordinal: 0,
            labels: cx.pf.labels.clone(),
            location: Some(rf.location),
        });
    }

    fn blind_at(
        &mut self,
        cx: Ctx<'p, 'a>,
        symbol: &str,
        location: Location,
        kind: BlindSpotKind,
        text: &str,
        coverage_gap: bool,
    ) {
        self.out.blind_spots.push(BlindSpot {
            id: String::new(),
            language: Some(cx.lang()),
            file: cx.pf.file.display.clone(),
            file_bytes: cx.pf.file.bytes_hex.clone(),
            symbol: symbol.to_string(),
            kind,
            whole_file: false,
            coverage_gap,
            construct: destination::construct_text(text),
            ordinal: 0,
            labels: cx.pf.labels.clone(),
            location: Some(location),
        });
    }

    fn blind(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, kind: BlindSpotKind) {
        self.blind_at(cx, &rf.symbol, rf.location, kind, &rf.text, false);
    }

    fn dep(&mut self, cx: Ctx<'p, 'a>, package: String) {
        self.deps
            .entry((cx.lang(), package))
            .or_default()
            .insert(cx.pf.file.display.clone());
    }

    fn finish(mut self) -> Classified {
        for ((language, package), files) in std::mem::take(&mut self.deps) {
            self.out.unscanned_dependencies.push(UnscannedDependency {
                id: String::new(),
                language,
                package,
                files: files.into_iter().collect(),
            });
        }
        self.out.resolver_steps = self.r.steps();
        self.out.resolver_budget_exceeded = self.r.exhausted();
        self.out
    }

    // ---- per file ---------------------------------------------------------------

    fn file(&mut self, cx: Ctx<'p, 'a>) {
        let ir = cx.pf.ir;
        let mut items: Vec<((u32, u32, u8, usize), Item<'p>)> = Vec::new();
        for (i, imp) in ir.imports.iter().enumerate() {
            items.push(((imp.span.start, imp.span.end, 0, i), Item::Import(imp)));
        }
        for (i, rf) in ir.references.iter().enumerate() {
            items.push(((rf.span.start, rf.span.end, 1, i), Item::Ref(rf)));
        }
        items.sort_by_key(|(k, _)| *k);
        for (_, item) in items {
            self.r.begin_reference();
            match item {
                Item::Import(imp) => self.import(cx, imp),
                Item::Ref(rf) => self.reference(cx, rf, 0),
            }
        }
        for c in &ir.constructs {
            let kind = match c.kind {
                ConstructKind::DynamicImport | ConstructKind::RequireAsValue => {
                    BlindSpotKind::DynamicImport
                }
                ConstructKind::ScopeInjection => BlindSpotKind::ScopeInjection,
                ConstructKind::ImportSystemMutation => BlindSpotKind::ImportSystemMutation,
                ConstructKind::NativeCode => BlindSpotKind::NativeCode,
                ConstructKind::MacroCode => BlindSpotKind::MacroCode,
                ConstructKind::ConstructorChain => BlindSpotKind::Introspection,
            };
            self.blind_at(cx, &c.symbol, c.location, kind, &c.text, false);
        }
        for a in &ir.introspection {
            let closure = &cx.rt.closure;
            if closure
                .introspection_inert
                .iter()
                .any(|n| n.name == a.attribute)
            {
                continue;
            }
            let dunder = a.attribute.len() > 4
                && a.attribute.starts_with("__")
                && a.attribute.ends_with("__");
            let prefixed = closure
                .introspection_prefixes
                .iter()
                .any(|p| a.attribute.starts_with(p.as_str()));
            if dunder || prefixed {
                self.blind_at(
                    cx,
                    &a.symbol,
                    a.location,
                    BlindSpotKind::Introspection,
                    &a.text,
                    false,
                );
            }
        }
    }

    // ---- imports -------------------------------------------------------------------

    fn import(&mut self, cx: Ctx<'p, 'a>, imp: &Import) {
        if imp.type_only {
            return;
        }
        let binding = match self.r.import(cx.path, cx.lang(), imp) {
            Ok(b) => b,
            Err(Limit) => {
                self.blind_at(
                    cx,
                    &imp.symbol,
                    imp.location,
                    BlindSpotKind::ResolutionLimit,
                    &imp.specifier,
                    false,
                );
                return;
            }
        };
        match binding {
            Binding::Gap(t) => self.gap(cx, imp, t),
            Binding::External { module, members } => {
                let synthetic = Reference {
                    root: Root::Import(imp.local.clone().unwrap_or_default()),
                    members: Vec::new(),
                    calls_in_chain: Vec::new(),
                    use_kind: UseKind::ValueEscape,
                    args: Vec::new(),
                    kwargs: Vec::new(),
                    receiver: None,
                    text: imp.specifier.clone(),
                    symbol: imp.symbol.clone(),
                    span: imp.span,
                    location: imp.location,
                };
                if imp.star {
                    // A star or glob import of an external module is an
                    // escape (KTD5, KTD15).
                    self.external(cx, &synthetic, &module, &members, false);
                    return;
                }
                let segs = module_segments(cx.lang(), &module);
                let rest: Vec<&str> = segs[1..].iter().map(String::as_str).collect();
                if cx.rt.lookup(&segs[0], &rest).is_none() {
                    self.dep(cx, package_name(cx.lang(), &module));
                }
                // An imported Rust egress trait is a site at the `use`, since
                // its method calls do not name it (KTD6).
                if cx.lang() == Language::Rust && !members.is_empty() {
                    let full = format!("{module}::{}", members.join("::"));
                    if cx.rt.closure.egress_traits.contains(&full) {
                        self.external(cx, &synthetic, &module, &members, false);
                    }
                }
            }
            _ => {}
        }
    }

    fn gap(&mut self, cx: Ctx<'p, 'a>, imp: &Import, target: Target) {
        let at = |s: &mut Self, kind, text: &str, gap| {
            s.blind_at(cx, &imp.symbol, imp.location, kind, text, gap)
        };
        match target {
            // The target path is never printed (KTD12).
            Target::OutsideRoot => at(self, BlindSpotKind::ReferenceOutsideRoot, "", true),
            Target::IntoExcluded => at(self, BlindSpotKind::ReferenceIntoExcluded, "", true),
            Target::Unresolved => at(self, BlindSpotKind::UnresolvedModule, &imp.specifier, false),
            Target::Shadowed(_) => at(self, BlindSpotKind::ShadowedModule, &imp.specifier, false),
            Target::LoadedAsCode(p) => {
                if self.loaded.insert(p.clone()) {
                    let enc = encode_path_bytes(&p);
                    self.out.loaded_as_code += 1;
                    self.out.blind_spots.push(BlindSpot {
                        id: String::new(),
                        language: None,
                        file: enc.display,
                        file_bytes: enc.bytes_hex,
                        symbol: "<module>".into(),
                        kind: BlindSpotKind::LoadedAsCode,
                        whole_file: true,
                        coverage_gap: true,
                        construct: String::new(),
                        ordinal: 0,
                        labels: path_labels(&p),
                        location: None,
                    });
                }
            }
            Target::Data
            | Target::Unsupported(_)
            | Target::FirstParty(_)
            | Target::Unlowered(_)
            | Target::External(_) => {}
        }
    }

    // ---- heads ------------------------------------------------------------------------

    fn head_of(binding: Binding) -> Head {
        match binding {
            Binding::External { module, members } => Head::Ext {
                module,
                chain: members,
            },
            Binding::FirstPartyModule(_) => Head::FirstPartyModule,
            Binding::FirstPartyDef { .. } | Binding::FirstParty => Head::FirstParty,
            Binding::Inert | Binding::Gap(_) => Head::Nothing,
        }
    }

    /// A name a star import of this file provides, expanded from the starred
    /// module's source (KTD16) or from an external module's entries.
    fn star_lookup(&mut self, cx: Ctx<'p, 'a>, name: &str) -> Result<Option<Binding>, Limit> {
        let stars: Vec<&Import> = cx
            .pf
            .ir
            .imports
            .iter()
            .filter(|i| i.star && !i.type_only)
            .collect();
        for imp in stars {
            match self.r.target(cx.path, cx.lang(), &imp.specifier) {
                Target::FirstParty(p) => {
                    if let Some(b) = self.r.export(&p, name)? {
                        return Ok(Some(b));
                    }
                }
                Target::External(m) => {
                    let segs = module_segments(cx.lang(), &m);
                    let mut rest: Vec<&str> = segs[1..].iter().map(String::as_str).collect();
                    rest.push(name);
                    if matches!(
                        cx.rt.lookup(&segs[0], &rest),
                        Some(Classification::Entry(_))
                    ) {
                        return Ok(Some(Binding::External {
                            module: m,
                            members: vec![name.to_string()],
                        }));
                    }
                }
                _ => {}
            }
        }
        Ok(None)
    }

    /// Strips leading ambient-module names and aliases from `chain`.
    fn strip_ambient(rt: &RuntimeData, mut chain: &[String]) -> Vec<String> {
        loop {
            if chain.first().map(String::as_str) == Some(rt.ambient.module.as_str()) {
                chain = &chain[1..];
                continue;
            }
            let alias = rt.ambient.aliases.iter().find(|a| {
                a.len() <= chain.len() && a.iter().zip(chain.iter()).all(|(x, y)| x == y)
            });
            match alias {
                Some(a) => chain = &chain[a.len()..],
                None => return chain.to_vec(),
            }
        }
    }

    fn ambient_head(rt: &RuntimeData, chain: Vec<String>) -> Head {
        if rt.ambient.module.is_empty() {
            return Head::Nothing;
        }
        let chain = Self::strip_ambient(rt, &chain);
        if let Some((first, rest)) = chain.split_first()
            && let Some(module) = rt.ambient.module_members.get(first)
        {
            return Head::Ext {
                module: module.clone(),
                chain: rest.to_vec(),
            };
        }
        Head::Ambient { chain }
    }

    fn resolve_head(
        &mut self,
        cx: Ctx<'p, 'a>,
        root: &Root,
        members: &[String],
        symbol: &str,
        hops: u32,
    ) -> Result<Head, Limit> {
        let ir = cx.pf.ir;
        match root {
            Root::Import(name) => {
                let imp = ir
                    .imports
                    .iter()
                    .filter(|i| !i.star && i.local.as_deref() == Some(name.as_str()))
                    .min_by_key(|i| (i.symbol != symbol, i.symbol != "<module>", i.span.start));
                let binding = match imp {
                    Some(i) => self.r.import(cx.path, cx.lang(), i)?,
                    None => match self.star_lookup(cx, name)? {
                        Some(b) => b,
                        None => return Ok(Head::FirstParty),
                    },
                };
                Ok(Self::head_of(self.r.walk(binding, members)?))
            }
            Root::Ambient(name) => {
                if ir.imports.iter().any(|i| i.star && !i.type_only)
                    && let Some(b) = self.star_lookup(cx, name)?
                {
                    return Ok(Self::head_of(self.r.walk(b, members)?));
                }
                let mut chain = vec![name.clone()];
                chain.extend(members.iter().cloned());
                Ok(Self::ambient_head(cx.rt, chain))
            }
            Root::Local(name) => {
                if hops >= MAX_ALIAS_HOPS {
                    return Ok(Head::Untracked);
                }
                let same = ir
                    .locals
                    .iter()
                    .find(|l| l.symbol == symbol && l.name == *name)
                    .map(|l| (&l.value, true));
                let value = same
                    .or_else(|| {
                        ir.locals
                            .iter()
                            .find(|l| l.symbol == "<module>" && l.name == *name)
                            .map(|l| (&l.value, symbol == "<module>"))
                    })
                    .or_else(|| {
                        ir.constants
                            .iter()
                            .find(|c| c.name == *name)
                            .map(|c| (&c.value, symbol == "<module>"))
                    });
                let Some((Expr::Reference(r), same_scope)) = value else {
                    return Ok(Head::FirstParty);
                };
                if is_call(r.use_kind) {
                    if !same_scope {
                        return Ok(Head::Untracked);
                    }
                    let h = self.resolve_head(cx, &r.root, &r.members, &r.symbol, hops + 1)?;
                    Ok(Self::track(cx.rt, cx.lang(), h, members))
                } else {
                    let mut chain = r.members.clone();
                    chain.extend(members.iter().cloned());
                    self.resolve_head(cx, &r.root, &chain, &r.symbol, hops + 1)
                }
            }
            Root::SelfValue => {
                let (Some((attr, rest)), Some(class)) =
                    (members.split_first(), enclosing_class(symbol))
                else {
                    return Ok(Head::Untracked);
                };
                let assigned: Vec<_> = ir
                    .self_attributes
                    .iter()
                    .filter(|a| a.class == class && a.attribute == *attr)
                    .collect();
                let init = format!("{class}.__init__");
                let ctor = format!("{class}.constructor");
                let prefix = format!("{class}.");
                let elsewhere = ir.references.iter().any(|x| {
                    x.root == Root::SelfValue
                        && x.use_kind == UseKind::AssignmentTarget
                        && x.members.len() == 1
                        && x.members[0] == *attr
                        && x.symbol.starts_with(&prefix)
                        && x.symbol != init
                        && x.symbol != ctor
                });
                match assigned.as_slice() {
                    [a] if !elsewhere => match &a.value {
                        Expr::Reference(r) if is_call(r.use_kind) && hops < MAX_ALIAS_HOPS => {
                            let h =
                                self.resolve_head(cx, &r.root, &r.members, &r.symbol, hops + 1)?;
                            Ok(Self::track(cx.rt, cx.lang(), h, rest))
                        }
                        _ => Ok(Head::Untracked),
                    },
                    _ => Ok(Head::Untracked),
                }
            }
            Root::Param(_) | Root::Expression => Ok(Head::Untracked),
        }
    }

    /// The head of a method chain on the result of the constructor call
    /// `h`, or untracked when `h` is not a constructor-style entry (KTD8).
    fn track(rt: &RuntimeData, lang: Language, h: Head, rest: &[String]) -> Head {
        let (module, chain) = match h {
            Head::Ext { module, chain } => (module, chain),
            Head::Ambient { chain } => (rt.ambient.module.clone(), chain),
            _ => return Head::Untracked,
        };
        let ctor = match Self::lookup(rt, lang, &module, &chain) {
            Some(Classification::Entry(e)) => match &e.kind {
                EntryKind::Egress(g) if g.constructor => e.id.clone(),
                _ => return Head::Untracked,
            },
            _ => return Head::Untracked,
        };
        let mut full = chain;
        // Python and JS methods extend the constructor entry
        // (`requests.Session.get`); Rust methods sit on the type, beside
        // its constructor (`Client::new` and `Client::get`).
        let prefix = if lang == Language::Rust {
            full.pop();
            match ctor.rsplit_once("::") {
                Some((ty, _)) => format!("{ty}::"),
                None => return Head::Untracked,
            }
        } else {
            format!("{ctor}{}", separator(lang))
        };
        full.extend(rest.iter().cloned());
        Head::Tracked {
            module,
            chain: full,
            ctor,
            prefix,
        }
    }

    fn lookup<'r>(
        rt: &'r RuntimeData,
        lang: Language,
        module: &str,
        chain: &[String],
    ) -> Option<Classification<'r>> {
        if module == rt.ambient.module && !module.is_empty() {
            let c: Vec<&str> = chain.iter().map(String::as_str).collect();
            return rt.lookup(module, &c);
        }
        let segs = module_segments(lang, module);
        let rest: Vec<&str> = segs[1..]
            .iter()
            .chain(chain.iter())
            .map(String::as_str)
            .collect();
        rt.lookup(&segs[0], &rest)
    }

    // ---- references -----------------------------------------------------------------

    fn reference(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, depth: u32) {
        let head = match self.resolve_head(cx, &rf.root, &rf.members, &rf.symbol, 0) {
            Ok(h) => h,
            Err(Limit) => {
                self.blind(cx, rf, BlindSpotKind::ResolutionLimit);
                return;
            }
        };
        match rf.use_kind {
            UseKind::ComputedMember => self.computed(cx, rf, &head),
            UseKind::AssignmentTarget => self.assign(cx, rf, &head),
            _ => self.use_head(cx, rf, head, depth),
        }
    }

    fn by_provenance(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, kind: BlindSpotKind) {
        match &rf.receiver {
            Some(Provenance::Literal | Provenance::TrackedConstructor) => {}
            Some(Provenance::ModuleBinding | Provenance::AmbientModule) => self.blind(cx, rf, kind),
            Some(
                Provenance::FirstPartyCallResult
                | Provenance::UnscannedCallResult
                | Provenance::Parameter(_)
                | Provenance::Unknown,
            ) => self.blind(cx, rf, BlindSpotKind::ReflectiveUnknown),
            None => {
                if matches!(rf.root, Root::Param(_)) {
                    self.blind(cx, rf, BlindSpotKind::ReflectiveUnknown);
                }
            }
        }
    }

    /// A computed member with a non-literal key (KTD15).
    fn computed(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, head: &Head) {
        match head {
            Head::Ext { .. } | Head::FirstPartyModule => {
                self.blind(cx, rf, BlindSpotKind::ReflectiveAccess)
            }
            Head::Ambient { .. } => {
                // Python subscript on `__builtins__` is scope injection; JS
                // computed access on the global object is reflective.
                let kind = if cx.lang() == Language::Python {
                    BlindSpotKind::ScopeInjection
                } else {
                    BlindSpotKind::ReflectiveAccess
                };
                self.blind(cx, rf, kind)
            }
            Head::Tracked { .. } | Head::Nothing => {}
            Head::FirstParty | Head::Untracked => {
                self.by_provenance(cx, rf, BlindSpotKind::ReflectiveAccess)
            }
        }
    }

    /// Whether the module a classification falls in is egress-bucket: not
    /// wholly inert.
    fn egress_bucket(rt: &RuntimeData, c: Option<Classification<'_>>) -> bool {
        let module_is_egress = |m: &str| {
            m == rt.ambient.module
                || rt.package_for(m).is_some()
                || rt.module(m).is_some_and(|x| x.class == ModuleClass::Egress)
        };
        match c {
            Some(Classification::Entry(e)) => module_is_egress(&e.module),
            Some(Classification::Module(m)) => m.class == ModuleClass::Egress,
            Some(Classification::Package(_)) => true,
            None => false,
        }
    }

    /// An assignment to a member chain (KTD15 import-system writes and
    /// monkeypatching).
    fn assign(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, head: &Head) {
        let (module, chain) = match head {
            Head::Ext { module, chain } => (module.clone(), chain.clone()),
            Head::Ambient { chain } => (cx.rt.ambient.module.clone(), chain.clone()),
            _ => return,
        };
        if chain.is_empty() {
            return;
        }
        let c = Self::lookup(cx.rt, cx.lang(), &module, &chain);
        if let Some(Classification::Entry(e)) = c
            && let EntryKind::BlindSpot {
                kind: BlindSpotKind::ImportSystemMutation,
                ..
            } = e.kind
        {
            self.blind(cx, rf, BlindSpotKind::ImportSystemMutation);
            return;
        }
        if Self::egress_bucket(cx.rt, c) {
            self.blind(cx, rf, BlindSpotKind::Monkeypatch);
        }
    }

    fn use_head(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, head: Head, depth: u32) {
        match head {
            Head::Ext { module, chain } => self.external(cx, rf, &module, &chain, false),
            Head::Ambient { chain } => {
                let module = cx.rt.ambient.module.clone();
                self.ambient_write(cx, rf, &chain);
                self.external(cx, rf, &module, &chain, true)
            }
            Head::Tracked {
                module,
                chain,
                ctor,
                prefix,
            } => {
                if let Some(Classification::Entry(e)) =
                    Self::lookup(cx.rt, cx.lang(), &module, &chain)
                    && e.id.starts_with(&prefix)
                    && e.id != ctor
                {
                    self.entry(cx, rf, e, &[], depth);
                }
            }
            Head::FirstPartyModule | Head::FirstParty | Head::Untracked | Head::Nothing => {}
        }
    }

    /// `Object.defineProperty(mod, ...)` and similar writes on an
    /// egress-bucket module are a monkeypatch (KTD15).
    fn ambient_write(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, chain: &[String]) {
        if cx.lang() != Language::Javascript
            || !is_call(rf.use_kind)
            || !OBJECT_WRITES
                .iter()
                .any(|w| w.len() == chain.len() && w.iter().zip(chain).all(|(a, b)| a == b))
        {
            return;
        }
        let Some(target) = rf.args.first() else {
            return;
        };
        let (root, members) = match target {
            Expr::Reference(r) => (r.root.clone(), r.members.clone()),
            Expr::Name(n) => (self.root_for_name(cx, n), Vec::new()),
            _ => return,
        };
        let Ok(h) = self.resolve_head(cx, &root, &members, &rf.symbol, 0) else {
            self.blind(cx, rf, BlindSpotKind::ResolutionLimit);
            return;
        };
        let (module, chain) = match h {
            Head::Ext { module, chain } => (module, chain),
            Head::Ambient { chain } => (cx.rt.ambient.module.clone(), chain),
            _ => return,
        };
        let c = Self::lookup(cx.rt, cx.lang(), &module, &chain);
        if Self::egress_bucket(cx.rt, c) || chain.is_empty() && module == cx.rt.ambient.module {
            self.blind(cx, rf, BlindSpotKind::Monkeypatch);
        }
    }

    /// The root a bare name argument binds to in this file.
    fn root_for_name(&self, cx: Ctx<'p, 'a>, name: &str) -> Root {
        let ir = cx.pf.ir;
        if ir
            .imports
            .iter()
            .any(|i| !i.star && i.local.as_deref() == Some(name))
        {
            Root::Import(name.to_string())
        } else if ir.locals.iter().any(|l| l.name == name)
            || ir.constants.iter().any(|c| c.name == name)
            || ir.symbols.iter().any(|s| s.path == name)
        {
            Root::Local(name.to_string())
        } else {
            Root::Ambient(name.to_string())
        }
    }

    /// Classifies an external module (or the ambient module) plus a member
    /// chain against the data (KTD5).
    fn external(
        &mut self,
        cx: Ctx<'p, 'a>,
        rf: &Reference,
        module: &str,
        chain: &[String],
        ambient: bool,
    ) {
        let rt = cx.rt;
        let sep = separator(cx.lang());
        // Require-equivalents (KTD15): a literal specifier is lowered as an
        // import by the frontend; anything else is a dynamic import.
        if is_call(rf.use_kind) {
            let dotted = if ambient {
                chain.join(".")
            } else if chain.is_empty() {
                module.to_string()
            } else {
                format!("{module}{sep}{}", chain.join(sep))
            };
            let prefixed = format!("{}.{dotted}", rt.ambient.module);
            if rt
                .closure
                .require_equivalents
                .iter()
                .any(|r| *r == dotted || (ambient && *r == prefixed))
            {
                if !matches!(rf.args.first(), Some(Expr::Literal(_))) {
                    self.blind(cx, rf, BlindSpotKind::DynamicImport);
                }
                return;
            }
        }
        if ambient && chain.is_empty() {
            self.escape(cx, rf, module, true);
            return;
        }
        match Self::lookup(rt, cx.lang(), module, chain) {
            Some(Classification::Entry(e)) => {
                // Members past the entry's own path.
                let mut full: Vec<String> = if ambient {
                    vec![module.to_string()]
                } else {
                    module_segments(cx.lang(), module)
                };
                full.extend(chain.iter().cloned());
                let used = module_segments(cx.lang(), &e.module).len() + e.members.len();
                let extra: Vec<String> = full.get(used..).unwrap_or_default().to_vec();
                self.entry(cx, rf, e, &extra, 0);
            }
            Some(Classification::Module(m)) => {
                // An unknown member, or the module itself, takes the
                // module's most dangerous entry (R2, KTD5). An unknown
                // ambient member is not part of the runtime's global object.
                if m.class == ModuleClass::Inert || ambient {
                    return;
                }
                let name = m.name.clone();
                self.escape(cx, rf, &name, false);
            }
            Some(Classification::Package(p)) => {
                // The package itself used as a value escapes (KTD5); a
                // member in neither list lists the package.
                let name = p.name.clone();
                if chain.is_empty() && module_segments(cx.lang(), module).len() == 1 {
                    self.escape(cx, rf, module, false);
                } else {
                    self.dep(cx, name);
                }
            }
            None => {
                if !ambient {
                    self.dep(cx, package_name(cx.lang(), module));
                }
            }
        }
    }

    /// The escape rule (KTD5): a module used as a value takes its most
    /// dangerous entry.
    fn escape(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, module: &str, ambient: bool) {
        let rt = cx.rt;
        let prefix = format!("{module}{}", separator(cx.lang()));
        let mut blind = false;
        let mut egress = ambient
            || rt
                .module(module)
                .is_some_and(|m| m.class == ModuleClass::Egress);
        for e in &rt.entries {
            if e.module != module && !e.module.starts_with(&prefix) {
                continue;
            }
            match e.kind {
                EntryKind::BlindSpot { .. } => blind = true,
                EntryKind::Egress(_) => egress = true,
                EntryKind::Inert { .. } => {}
            }
        }
        let package = rt.package_for(module).map(|p| p.name.clone());
        if blind {
            self.blind(cx, rf, BlindSpotKind::ModuleEscape);
        } else if egress {
            let bucket = if package.is_some() {
                Bucket::Catalogued
            } else {
                Bucket::Primitive
            };
            let mechanism = format!("{}:{module}", cx.lang().as_str());
            self.site(cx, rf, bucket, &mechanism, destination::expr(&rf.text));
        } else if let Some(p) = package {
            self.dep(cx, p);
        } else if rt.module(module).is_none() {
            self.dep(cx, package_name(cx.lang(), module));
        }
    }

    fn entry(&mut self, cx: Ctx<'p, 'a>, rf: &Reference, e: &Entry, extra: &[String], depth: u32) {
        match &e.kind {
            EntryKind::Inert { .. } => {}
            EntryKind::BlindSpot { kind, .. } => {
                if is_call(rf.use_kind) {
                    if let Some(&(_, target, name, write)) =
                        NAME_TAKING.iter().find(|t| t.0 == e.id)
                    {
                        self.reflective_call(cx, rf, *kind, target, name, write, depth);
                        return;
                    }
                    if WORKERS.contains(&e.id.as_str()) && self.worker_resolves(cx, rf) {
                        return;
                    }
                }
                self.blind(cx, rf, *kind);
            }
            EntryKind::Egress(g) => {
                let bucket = match e.origin {
                    Origin::Primitives => Bucket::Primitive,
                    Origin::Catalog => Bucket::Catalogued,
                };
                let spec = g.destination.as_ref();
                let dest = match extra {
                    [] if is_call(rf.use_kind) => self.destination(cx, rf, spec, &rf.args),
                    [m] if cx.lang() == Language::Javascript
                        && rf.use_kind == UseKind::Call
                        && matches!(m.as_str(), "call" | "bind") =>
                    {
                        // `.call` and `.bind` take a receiver first.
                        let args = rf.args.get(1..).unwrap_or_default().to_vec();
                        self.destination(cx, rf, spec, &args)
                    }
                    [m] if cx.lang() == Language::Javascript
                        && rf.use_kind == UseKind::Call
                        && m == "apply" =>
                    {
                        match rf.args.get(1).map(|a| self.eval(cx.path, &rf.symbol, a, 0)) {
                            Some(Val::Seq(items)) => self.destination(cx, rf, spec, &items),
                            _ => destination::expr(&rf.text),
                        }
                    }
                    _ => destination::expr(&rf.text),
                };
                self.site(cx, rf, bucket, &e.id, dest);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reflective_call(
        &mut self,
        cx: Ctx<'p, 'a>,
        rf: &Reference,
        kind: BlindSpotKind,
        target: usize,
        name: usize,
        write: bool,
        depth: u32,
    ) {
        let literal = match rf
            .args
            .get(name - 1)
            .map(|a| self.eval(cx.path, &rf.symbol, a, 0))
        {
            Some(Val::Lit(s)) => Some(s),
            _ => None,
        };
        let target = rf.args.get(target - 1);
        if let Some(member) = literal {
            // A literal name is an ordinary member access on the target.
            if depth > 0 {
                return;
            }
            let (root, mut members) = match target {
                Some(Expr::Reference(r)) => (r.root.clone(), r.members.clone()),
                Some(Expr::Name(n)) => (self.root_for_name(cx, n), Vec::new()),
                _ => return,
            };
            members.push(member);
            let synthetic = Reference {
                root,
                members,
                calls_in_chain: Vec::new(),
                use_kind: if write {
                    UseKind::AssignmentTarget
                } else {
                    UseKind::ValueEscape
                },
                args: Vec::new(),
                kwargs: Vec::new(),
                receiver: None,
                text: rf.text.clone(),
                symbol: rf.symbol.clone(),
                span: rf.span,
                location: rf.location,
            };
            self.reference(cx, &synthetic, depth + 1);
            return;
        }
        if rf.receiver.is_some() {
            self.by_provenance(cx, rf, kind);
            return;
        }
        // No recorded provenance: decide from the target expression.
        let head = match target {
            Some(Expr::Reference(r)) => self.resolve_head(cx, &r.root, &r.members, &rf.symbol, 0),
            Some(Expr::Name(n)) => {
                let root = self.root_for_name(cx, n);
                self.resolve_head(cx, &root, &[], &rf.symbol, 0)
            }
            Some(Expr::Param(_)) => Ok(Head::Untracked),
            _ => Ok(Head::Ext {
                module: String::new(),
                chain: Vec::new(),
            }),
        };
        match head {
            Err(Limit) => self.blind(cx, rf, BlindSpotKind::ResolutionLimit),
            Ok(Head::Tracked { .. } | Head::FirstParty | Head::Nothing) => {}
            Ok(Head::Untracked) => self.blind(cx, rf, BlindSpotKind::ReflectiveUnknown),
            Ok(Head::Ext { .. } | Head::Ambient { .. } | Head::FirstPartyModule) => {
                self.blind(cx, rf, kind)
            }
        }
    }

    /// `new Worker(spec)` with a literal specifier that is not `data:` or
    /// `blob:` and without `eval: true` loads first-party code by path.
    fn worker_resolves(&mut self, cx: Ctx<'p, 'a>, rf: &Reference) -> bool {
        let spec = match rf
            .args
            .first()
            .map(|a| self.eval(cx.path, &rf.symbol, a, 0))
        {
            Some(Val::Lit(s)) => s,
            _ => return false,
        };
        if spec.starts_with("data:") || spec.starts_with("blob:") {
            return false;
        }
        let eval_true = |e: &Expr| matches!(e, Expr::Literal(s) | Expr::Opaque(s) if s != "false");
        let options = match rf.args.get(1).map(|a| self.eval(cx.path, &rf.symbol, a, 0)) {
            Some(Val::Obj(fields)) => fields,
            Some(Val::Lit(_)) | None => Vec::new(),
            Some(_) => return false,
        };
        !options
            .iter()
            .chain(rf.kwargs.iter())
            .any(|(k, v)| k == "eval" && eval_true(v))
    }

    // ---- destinations (KTD7) ----------------------------------------------------------

    fn destination(
        &mut self,
        cx: Ctx<'p, 'a>,
        rf: &Reference,
        spec: Option<&DestinationSpec>,
        args: &[Expr],
    ) -> Destination {
        let Some(spec) = spec else {
            return destination::expr(&rf.text);
        };
        let kw = |k: &Option<String>| {
            k.as_ref().and_then(|k| {
                rf.kwargs
                    .iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.clone())
            })
        };
        // A JS options object as the first argument carries the keyed values.
        if cx.lang() == Language::Javascript
            && (spec.keyword.is_some() || spec.port_keyword.is_some())
            && let Some(first) = args.first()
            && let Val::Obj(fields) = self.eval(cx.path, &rf.symbol, first, 0)
        {
            let field = |k: &Option<String>| {
                k.as_ref()
                    .and_then(|k| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
            };
            let host = field(&spec.keyword);
            let port = field(&spec.port_keyword);
            return match host {
                Some(h) => self.form(cx, rf, spec.form, &h, port.as_ref()),
                None => destination::expr(&rf.text),
            };
        }
        let pos = |i: Option<u32>| i.and_then(|i| args.get((i as usize).checked_sub(1)?).cloned());
        let host = pos(spec.arg).or_else(|| kw(&spec.keyword));
        let port = pos(spec.port).or_else(|| kw(&spec.port_keyword));
        match host {
            Some(h) => self.form(cx, rf, spec.form, &h, port.as_ref()),
            None => destination::expr(&rf.text),
        }
    }

    fn form(
        &mut self,
        cx: Ctx<'p, 'a>,
        rf: &Reference,
        form: DestinationForm,
        host: &Expr,
        port: Option<&Expr>,
    ) -> Destination {
        let sym = rf.symbol.as_str();
        let v = self.eval(cx.path, sym, host, 0);
        match form {
            DestinationForm::Url | DestinationForm::Address => to_dest(v),
            DestinationForm::Library => match v {
                Val::Lit(s) => destination::lib(&s),
                other => to_dest(other),
            },
            DestinationForm::Program => {
                let v = match v {
                    Val::Seq(items) => match items.first() {
                        Some(first) => self.eval(cx.path, sym, first, 0),
                        None => return destination::expr(&rf.text),
                    },
                    other => other,
                };
                match v {
                    Val::Lit(s) => {
                        destination::exec(s.split_whitespace().next().unwrap_or_default())
                    }
                    other => to_dest(other),
                }
            }
            DestinationForm::HostPort => {
                let (h, p) = match v {
                    Val::Seq(items) if items.len() >= 2 => (
                        self.eval(cx.path, sym, &items[0], 0),
                        Some(self.eval(cx.path, sym, &items[1], 0)),
                    ),
                    other => (other, port.map(|p| self.eval(cx.path, sym, p, 0))),
                };
                match p {
                    None => to_dest(h),
                    Some(p) => destination::template(&[
                        to_part(h),
                        TemplatePart::Literal(":".into()),
                        to_part(p),
                    ]),
                }
            }
        }
    }

    fn eval(&mut self, path: &[u8], symbol: &str, e: &Expr, depth: u32) -> Val {
        if depth > MAX_EVAL_DEPTH {
            return Val::Dest(destination::expr(&render(e)));
        }
        match e {
            Expr::Literal(s) => Val::Lit(s.clone()),
            Expr::Template(parts) => {
                let vals: Vec<Val> = parts
                    .iter()
                    .map(|p| self.eval(path, symbol, p, depth + 1))
                    .collect();
                if vals.iter().all(|v| matches!(v, Val::Lit(_))) {
                    let mut s = String::new();
                    for v in vals {
                        if let Val::Lit(t) = v {
                            s.push_str(&t);
                        }
                    }
                    Val::Lit(s)
                } else {
                    let parts: Vec<TemplatePart> = vals.into_iter().map(to_part).collect();
                    Val::Dest(destination::template(&parts))
                }
            }
            Expr::Name(n) => self.eval_name(path, symbol, n, depth),
            Expr::Param(i) => Val::Dest(destination::param(*i, symbol)),
            Expr::Reference(r) => match self.env_read(path, r) {
                Some(d) => Val::Dest(d),
                None => Val::Dest(destination::expr(&r.text)),
            },
            Expr::Subscript { base, key } => {
                if let Expr::Reference(r) = base.as_ref()
                    && self.is_env_map(path, r)
                    && let Val::Lit(k) = self.eval(path, symbol, key, depth + 1)
                {
                    return Val::Dest(destination::env(&k, None));
                }
                Val::Dest(destination::expr(&render(e)))
            }
            Expr::Sequence(items) => Val::Seq(items.clone()),
            Expr::Object(fields) => Val::Obj(fields.clone()),
            Expr::Opaque(t) => Val::Dest(destination::expr(t)),
        }
    }

    fn ctx(&self, path: &[u8]) -> Option<Ctx<'p, 'a>> {
        let program = self.program;
        let (path, pf) = program.files.get_key_value(path)?;
        Some(Ctx {
            path,
            pf,
            rt: self.data.runtime(pf.language),
        })
    }

    /// A name: a single-assignment local in the same function, a module
    /// constant in the same file, or a constant imported from a first-party
    /// module through its alias chain (KTD7).
    fn eval_name(&mut self, path: &[u8], symbol: &str, name: &str, depth: u32) -> Val {
        let unresolved = || Val::Dest(destination::expr(name));
        let Some(cx) = self.ctx(path) else {
            return unresolved();
        };
        let ir = cx.pf.ir;
        if let Some(l) = ir
            .locals
            .iter()
            .find(|l| l.symbol == symbol && l.name == name)
        {
            return self.eval(path, symbol, &l.value, depth + 1);
        }
        if let Some(l) = ir
            .locals
            .iter()
            .find(|l| l.symbol == "<module>" && l.name == name)
        {
            return self.eval(path, "<module>", &l.value, depth + 1);
        }
        if let Some(c) = ir.constants.iter().find(|c| c.name == name) {
            return self.eval(path, "<module>", &c.value, depth + 1);
        }
        if let Some(imp) = ir
            .imports
            .iter()
            .find(|i| !i.star && i.local.as_deref() == Some(name))
            && let Ok(Binding::FirstPartyDef { path: p, name: n }) =
                self.r.import(path, cx.lang(), imp)
        {
            return self.eval_name(&p, "<module>", &n, depth + 1);
        }
        unresolved()
    }

    fn env_path(&mut self, path: &[u8], r: &Reference) -> Option<Vec<String>> {
        let cx = self.ctx(path)?;
        let head = self
            .resolve_head(cx, &r.root, &r.members, &r.symbol, 0)
            .ok()?;
        let (module, chain) = match head {
            Head::Ext { module, chain } => (module, chain),
            _ => return None,
        };
        let mut full = module_segments(cx.lang(), &module);
        full.extend(chain);
        Some(full)
    }

    /// Whether `r` names the environment mapping (`os.environ`,
    /// `process.env`).
    fn is_env_map(&mut self, path: &[u8], r: &Reference) -> bool {
        matches!(
            self.env_path(path, r).as_deref(),
            Some([a, b]) if (a == "os" && b == "environ") || (a == "process" && b == "env")
        )
    }

    /// An environment read becomes `env:NAME`; the scan never reads the
    /// host environment (KTD7).
    fn env_read(&mut self, path: &[u8], r: &Reference) -> Option<Destination> {
        let lang = self.ctx(path)?.lang();
        let name_arg = |s: &mut Self, i: usize| -> Option<String> {
            match s.eval(path, &r.symbol, r.args.get(i)?, 0) {
                Val::Lit(v) => Some(v),
                _ => None,
            }
        };
        if lang == Language::Rust
            && let Root::Ambient(m) = &r.root
            && (m == "env!" || m == "option_env!")
        {
            return name_arg(self, 0).map(|n| destination::env(&n, None));
        }
        let full = self.env_path(path, r)?;
        let full: Vec<&str> = full.iter().map(String::as_str).collect();
        match lang {
            Language::Python => {
                let reader = matches!(full.as_slice(), ["os", "getenv"] | ["os", "environ", "get"]);
                if !reader || !is_call(r.use_kind) {
                    return None;
                }
                let name = name_arg(self, 0)?;
                let default = match r
                    .args
                    .get(1)
                    .or_else(|| {
                        r.kwargs
                            .iter()
                            .find(|(k, _)| k == "default")
                            .map(|(_, v)| v)
                    })
                    .map(|e| self.eval(path, &r.symbol, e, 0))
                {
                    Some(Val::Lit(d)) => Some(d),
                    _ => None,
                };
                Some(destination::env(&name, default.as_deref()))
            }
            Language::Javascript => match full.as_slice() {
                ["process", "env", name] => Some(destination::env(name, None)),
                _ => None,
            },
            Language::Rust => match full.as_slice() {
                ["std", "env", "var" | "var_os", rest @ ..]
                    if rest
                        .iter()
                        .all(|m| matches!(*m, "unwrap" | "expect" | "unwrap_or_default")) =>
                {
                    name_arg(self, 0).map(|n| destination::env(&n, None))
                }
                _ => None,
            },
        }
    }
}

//! Lowering one Rust file to the IR (KTD4, KTD7, KTD9, KTD15).
//!
//! Name binding follows Rust's own rules closely enough for egress
//! accounting: items and `use` declarations are order-independent per
//! module, inline modules have their own namespace, a path's first segment
//! is a local variable, a name bound in the enclosing module or block, or an
//! extern crate. Module-level bindings inside inline modules carry qualified
//! names (`net::TcpStream`) so the core can follow them across files.

use std::collections::{HashMap, HashSet};

use proc_macro2::{Delimiter, Span as PmSpan, TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Expr as SExpr, FnArg, ImplItem, Item, Lit, Macro, Meta, Pat, Path, Signature,
    Stmt, TraitItem, Type, UseTree,
};

use egress_core::discover::manifests::fold;
use egress_core::ir::{
    ConstructKind, DynamicConstruct, Expr, FileIr, Import, LineIndex, LocalBinding, ModuleConstant,
    Reference, Root, Span, SymbolKind, SymbolSpan, UseKind,
};
use egress_core::model::Language;
use egress_core::paths::dir_of;

use crate::spec;

/// Nesting depth the lowering walk accepts before it gives up on a file
/// (KTD13's second line behind the pre-scan).
pub const MAX_LOWER_DEPTH: u32 = 1024;

/// Alias hops followed through `use` declarations.
const MAX_ALIAS_HOPS: u32 = 8;

/// Where a path starts once its first segment is bound.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Base {
    Extern(String),
    Crate,
    /// The declaring file, with the inline-module prefix in the segments.
    SelfFile,
    /// `n` modules above the declaring file.
    Super(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Abs {
    base: Base,
    segs: Vec<String>,
}

impl Abs {
    fn spec(&self) -> String {
        match &self.base {
            Base::Extern(c) => c.clone(),
            Base::Crate => "crate".into(),
            Base::SelfFile => "self".into(),
            Base::Super(n) => vec!["super"; *n as usize].join("::"),
        }
    }

    /// The local name of the implicit import a path with this base uses.
    fn synthetic_local(&self) -> String {
        match &self.base {
            Base::Extern(c) => format!("::{c}"),
            _ => self.spec(),
        }
    }
}

/// What a name in a module or block scope binds to.
#[derive(Debug, Clone)]
enum Name {
    /// A `use` binding: its IR local name, and the path as written with the
    /// scope it was declared in.
    Use {
        local: String,
        path: Vec<String>,
        leading: bool,
        scope: usize,
    },
    /// `mod name;`, bound by an import with this local name.
    ModFile(String),
    Inline,
    /// A function, type, trait, or macro defined here.
    Item,
    /// A `const` or `static`, by its IR constant name.
    Const(String),
    /// `extern crate c as name;`: the local name.
    ExternCrate(String),
}

#[derive(Debug, Clone, Default)]
struct Scope {
    /// Inline module prefix of the module this scope belongs to.
    prefix: Vec<String>,
    names: HashMap<String, Name>,
    globs: bool,
    /// True for a block scope inside a function.
    block: bool,
}

#[derive(Debug, Clone)]
struct FnFrame {
    params: Vec<String>,
    locals: HashSet<String>,
}

pub struct Lowerer<'a> {
    path: &'a [u8],
    src: &'a str,
    lines: LineIndex<'a>,
    ir: FileIr,
    scopes: Vec<Scope>,
    /// Indices into `scopes` of the module scopes on the stack.
    fns: Vec<FnFrame>,
    symbols: Vec<String>,
    self_ty: Vec<Option<Path>>,
    synthetic: HashSet<String>,
    depth: u32,
    pub too_deep: bool,
    /// `let` candidates: (symbol, name) to value, with binding counts.
    lets: Vec<(String, String, Expr, Span)>,
    bind_counts: HashMap<(String, String), u32>,
    reassigned: HashSet<(String, String)>,
    import_counter: u32,
    /// Indices of references made for private `use` paths.
    use_refs: HashSet<usize>,
}

fn ident_str(i: &proc_macro2::Ident) -> String {
    let s = i.to_string();
    s.strip_prefix("r#").map(str::to_string).unwrap_or(s)
}

fn path_segs(p: &Path) -> Vec<String> {
    p.segments.iter().map(|s| ident_str(&s.ident)).collect()
}

fn attr_last(a: &Attribute) -> Option<String> {
    a.path().segments.last().map(|s| ident_str(&s.ident))
}

/// Whether the attributes gate the item on `cfg(test)` (not `not(test)`).
fn cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("cfg") {
            return false;
        }
        let Meta::List(l) = &a.meta else { return false };
        let t = l.tokens.to_string();
        t.split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|w| w == "test")
            && !t.contains("not")
    })
}

/// `#[test]` and test-runner attributes such as `#[tokio::test]`.
fn test_attr(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| attr_last(a).as_deref() == Some("test"))
}

const BUILTIN_ATTRS: &[&str] = &[
    "cfg",
    "cfg_attr",
    "test",
    "bench",
    "allow",
    "warn",
    "deny",
    "forbid",
    "expect",
    "doc",
    "inline",
    "must_use",
    "path",
    "derive",
    "repr",
    "non_exhaustive",
    "macro_use",
    "macro_export",
    "no_mangle",
    "export_name",
    "link_name",
    "link_section",
    "cold",
    "track_caller",
    "deprecated",
    "automatically_derived",
    "feature",
    "global_allocator",
    "ignore",
    "should_panic",
    "proc_macro",
    "proc_macro_derive",
    "proc_macro_attribute",
    "target_feature",
    "unsafe",
    "diagnostic",
    "rustfmt",
    "clippy",
    "no_std",
    "no_main",
    "recursion_limit",
    "crate_type",
    "crate_name",
    "windows_subsystem",
    "used",
    "naked",
    "instruction_set",
    "debugger_visualizer",
    "collapse_debuginfo",
    "type_length_limit",
    "no_implicit_prelude",
    "no_link",
    "coverage",
];

/// Methods that pass their receiver's value through for destination
/// purposes.
const TRANSPARENT_METHODS: &[&str] = &[
    "unwrap",
    "expect",
    "unwrap_or_default",
    "to_string",
    "to_owned",
    "into",
    "as_str",
    "as_ref",
    "clone",
    "borrow",
];

impl<'a> Lowerer<'a> {
    pub fn new(path: &'a [u8], src: &'a str) -> Self {
        Lowerer {
            path,
            src,
            lines: LineIndex::new(src),
            ir: FileIr::new(Language::Rust),
            scopes: Vec::new(),
            fns: Vec::new(),
            symbols: Vec::new(),
            self_ty: Vec::new(),
            synthetic: HashSet::new(),
            depth: 0,
            too_deep: false,
            lets: Vec::new(),
            bind_counts: HashMap::new(),
            reassigned: HashSet::new(),
            import_counter: 0,
            use_refs: HashSet::new(),
        }
    }

    pub fn finish(mut self) -> FileIr {
        // A private `use` path is a reference only for a binding nothing else
        // in the file names (an imported trait, an unused import): a binding
        // the file uses is accounted for where it is used.
        let used: HashSet<String> = self
            .ir
            .references
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.use_refs.contains(i))
            .filter_map(|(_, r)| match &r.root {
                Root::Import(l) => Some(l.clone()),
                _ => None,
            })
            .collect();
        let refs = std::mem::take(&mut self.ir.references);
        self.ir.references = refs
            .into_iter()
            .enumerate()
            .filter(|(i, r)| {
                !self.use_refs.contains(i)
                    || !matches!(&r.root, Root::Import(l) if used.contains(l))
            })
            .map(|(_, r)| r)
            .collect();
        for (symbol, name, value, span) in std::mem::take(&mut self.lets) {
            let key = (symbol.clone(), name.clone());
            if self.bind_counts.get(&key) == Some(&1) && !self.reassigned.contains(&key) {
                self.ir.locals.push(LocalBinding {
                    symbol,
                    name,
                    value,
                    span,
                });
            }
        }
        self.ir.test_scopes.sort();
        self.ir.test_scopes.dedup();
        self.ir
    }

    // ---- positions -------------------------------------------------------

    fn span_of(&self, s: PmSpan) -> Span {
        let r = s.byte_range();
        Span {
            start: u32::try_from(r.start).unwrap_or(u32::MAX),
            end: u32::try_from(r.end).unwrap_or(u32::MAX),
        }
    }

    fn text_of(&self, s: PmSpan) -> String {
        let r = s.byte_range();
        self.src.get(r).unwrap_or_default().to_string()
    }

    fn location(&self, s: PmSpan) -> egress_core::model::Location {
        self.lines.location(s.byte_range().start)
    }

    // ---- symbols -----------------------------------------------------------

    fn module_prefix(&self) -> Vec<String> {
        self.scopes
            .iter()
            .rev()
            .find(|s| !s.block)
            .map(|s| s.prefix.clone())
            .unwrap_or_default()
    }

    fn module_symbol(&self) -> String {
        let p = self.module_prefix();
        if p.is_empty() {
            "<module>".into()
        } else {
            p.join("::")
        }
    }

    fn symbol(&self) -> String {
        self.symbols
            .last()
            .cloned()
            .unwrap_or_else(|| self.module_symbol())
    }

    /// The symbol path of a new item named `name` (KTD9).
    fn child_symbol(&self, name: &str) -> String {
        match self.symbols.last() {
            Some(s) => format!("{s}::{name}"),
            None => {
                let p = self.module_prefix();
                if p.is_empty() {
                    name.to_string()
                } else {
                    format!("{}::{name}", p.join("::"))
                }
            }
        }
    }

    fn in_block(&self) -> bool {
        self.scopes.last().is_some_and(|s| s.block)
    }

    // ---- depth ---------------------------------------------------------------

    fn enter(&mut self) -> bool {
        self.depth += 1;
        if self.depth > MAX_LOWER_DEPTH {
            self.too_deep = true;
        }
        !self.too_deep
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    // ---- scopes ----------------------------------------------------------------

    /// Registers the names `items` bind in a new scope.
    fn push_scope(&mut self, items: &[&Item], prefix: Vec<String>, block: bool) {
        let index = self.scopes.len();
        let mut scope = Scope {
            prefix,
            block,
            ..Scope::default()
        };
        let symbol = if block {
            self.symbol()
        } else if scope.prefix.is_empty() {
            "<module>".to_string()
        } else {
            scope.prefix.join("::")
        };
        let qual = |n: &str, scope: &Scope| {
            if scope.prefix.is_empty() || block {
                n.to_string()
            } else {
                format!("{}::{n}", scope.prefix.join("::"))
            }
        };
        for item in items {
            match item {
                Item::Use(u) => {
                    let mut leaves = Vec::new();
                    use_leaves(&u.tree, &mut Vec::new(), &mut leaves);
                    for (path, bind) in leaves {
                        match bind {
                            Leaf::Glob => scope.globs = true,
                            Leaf::Name(n) | Leaf::Named(n) => {
                                let local = if block {
                                    format!("{symbol}#{n}")
                                } else {
                                    qual(&n, &scope)
                                };
                                scope.names.insert(
                                    n,
                                    Name::Use {
                                        local,
                                        path,
                                        leading: u.leading_colon.is_some(),
                                        scope: index,
                                    },
                                );
                            }
                            Leaf::Underscore => {}
                        }
                    }
                }
                Item::Mod(m) => {
                    let n = ident_str(&m.ident);
                    let b = if m.content.is_some() {
                        Name::Inline
                    } else {
                        Name::ModFile(qual(&n, &scope))
                    };
                    scope.names.insert(n, b);
                }
                Item::Const(c) => {
                    let n = ident_str(&c.ident);
                    scope.names.insert(n.clone(), Name::Const(qual(&n, &scope)));
                }
                Item::Static(c) => {
                    let n = ident_str(&c.ident);
                    scope.names.insert(n.clone(), Name::Const(qual(&n, &scope)));
                }
                Item::ExternCrate(e) => {
                    let n = match &e.rename {
                        Some((_, r)) => ident_str(r),
                        None => ident_str(&e.ident),
                    };
                    scope
                        .names
                        .insert(n.clone(), Name::ExternCrate(qual(&n, &scope)));
                }
                Item::Fn(f) => {
                    scope.names.insert(ident_str(&f.sig.ident), Name::Item);
                }
                Item::Struct(s) => {
                    scope.names.insert(ident_str(&s.ident), Name::Item);
                }
                Item::Enum(s) => {
                    scope.names.insert(ident_str(&s.ident), Name::Item);
                }
                Item::Union(s) => {
                    scope.names.insert(ident_str(&s.ident), Name::Item);
                }
                Item::Trait(s) => {
                    scope.names.insert(ident_str(&s.ident), Name::Item);
                }
                Item::Type(s) => {
                    scope.names.insert(ident_str(&s.ident), Name::Item);
                }
                Item::Macro(m) => {
                    if let Some(i) = &m.ident {
                        scope.names.insert(format!("{}!", ident_str(i)), Name::Item);
                    }
                }
                _ => {}
            }
        }
        self.scopes.push(scope);
    }

    /// The binding of `name` visible from the innermost scope, and the index
    /// of the scope that holds it. Block scopes see their enclosing blocks and
    /// module; a module scope sees only itself.
    fn lookup(&self, name: &str) -> Option<(Name, usize)> {
        for i in (0..self.scopes.len()).rev() {
            if let Some(n) = self.scopes[i].names.get(name) {
                return Some((n.clone(), i));
            }
            if !self.scopes[i].block {
                break;
            }
        }
        None
    }

    fn lookup_in(&self, scope: usize, name: &str) -> Option<(Name, usize)> {
        for i in (0..=scope).rev() {
            if let Some(n) = self.scopes[i].names.get(name) {
                return Some((n.clone(), i));
            }
            if !self.scopes[i].block {
                break;
            }
        }
        None
    }

    fn globs_in_scope(&self) -> bool {
        for s in self.scopes.iter().rev() {
            if s.globs {
                return true;
            }
            if !s.block {
                break;
            }
        }
        false
    }

    /// The prefix of the module scope at or around `scope`.
    fn prefix_at(&self, scope: usize) -> Vec<String> {
        self.scopes[..=scope]
            .iter()
            .rev()
            .find(|s| !s.block)
            .map(|s| s.prefix.clone())
            .unwrap_or_default()
    }

    /// Resolves a path as written in `scope` to its base and segments.
    fn abs(&self, scope: usize, segs: &[String], leading: bool, hops: u32) -> Option<Abs> {
        let (first, rest) = segs.split_first()?;
        if leading {
            return Some(Abs {
                base: Base::Extern(first.clone()),
                segs: rest.to_vec(),
            });
        }
        let prefix = self.prefix_at(scope);
        match first.as_str() {
            "crate" | "$crate" => {
                return Some(Abs {
                    base: Base::Crate,
                    segs: rest.to_vec(),
                });
            }
            "self" => {
                let mut s = prefix;
                s.extend(rest.iter().cloned());
                return Some(Abs {
                    base: Base::SelfFile,
                    segs: s,
                });
            }
            "super" => {
                let n = segs.iter().take_while(|s| *s == "super").count();
                let rest = &segs[n..];
                let d = prefix.len();
                return Some(if n <= d {
                    let mut s = prefix[..d - n].to_vec();
                    s.extend(rest.iter().cloned());
                    Abs {
                        base: Base::SelfFile,
                        segs: s,
                    }
                } else {
                    Abs {
                        base: Base::Super(u32::try_from(n - d).unwrap_or(u32::MAX)),
                        segs: rest.to_vec(),
                    }
                });
            }
            _ => {}
        }
        match self.lookup_in(scope, first) {
            Some((
                Name::Use {
                    path,
                    leading,
                    scope: s,
                    ..
                },
                _,
            )) => {
                if hops >= MAX_ALIAS_HOPS {
                    return None;
                }
                let mut a = self.abs(s, &path, leading, hops + 1)?;
                a.segs.extend(rest.iter().cloned());
                Some(a)
            }
            Some((Name::ExternCrate(_), i)) => {
                // `extern crate c as n;` binds `n` to the crate `c`.
                let c = self
                    .extern_crate_target(i, first)
                    .unwrap_or_else(|| first.clone());
                Some(Abs {
                    base: Base::Extern(c),
                    segs: rest.to_vec(),
                })
            }
            Some((_, i)) if self.scopes[i].block => None,
            Some(_) => {
                let mut s = prefix;
                s.push(first.clone());
                s.extend(rest.iter().cloned());
                Some(Abs {
                    base: Base::SelfFile,
                    segs: s,
                })
            }
            None => Some(Abs {
                base: Base::Extern(first.clone()),
                segs: rest.to_vec(),
            }),
        }
    }

    fn extern_crate_target(&self, _scope: usize, name: &str) -> Option<String> {
        self.ir
            .imports
            .iter()
            .find(|i| {
                i.local
                    .as_deref()
                    .is_some_and(|l| l == name || l.ends_with(&format!("::{name}")))
                    && i.members.is_empty()
            })
            .map(|i| i.specifier.clone())
    }

    // ---- imports ----------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn push_import(
        &mut self,
        local: Option<String>,
        specifier: String,
        members: Vec<String>,
        star: bool,
        re_export: bool,
        symbol: String,
        span: PmSpan,
    ) {
        self.ir.imports.push(Import {
            local,
            specifier,
            members,
            type_only: false,
            star,
            re_export,
            default: false,
            symbol,
            span: self.span_of(span),
            location: self.location(span),
        });
    }

    /// The root for a path with base `abs`, creating its implicit import.
    fn synthetic_root(&mut self, abs: Abs, span: PmSpan) -> (Root, Vec<String>) {
        let local = abs.synthetic_local();
        if self.synthetic.insert(local.clone()) {
            let symbol = self.symbol();
            self.push_import(
                Some(local.clone()),
                abs.spec(),
                Vec::new(),
                false,
                false,
                symbol,
                span,
            );
        }
        (Root::Import(local), abs.segs)
    }

    // ---- path resolution -----------------------------------------------------------

    fn param_index(&self, name: &str) -> Option<u32> {
        let f = self.fns.last()?;
        if f.locals.contains(name) {
            return None;
        }
        f.params
            .iter()
            .position(|p| p == name)
            .and_then(|i| u32::try_from(i + 1).ok())
    }

    fn is_local(&self, name: &str) -> bool {
        self.fns.last().is_some_and(|f| f.locals.contains(name))
    }

    /// The root and member chain of a path in an evaluated position, or
    /// `None` for a local definition or a name nothing can bind.
    fn path_root(
        &mut self,
        segs: &[String],
        leading: bool,
        value: bool,
        span: PmSpan,
    ) -> Option<(Root, Vec<String>)> {
        let (first, rest) = segs.split_first()?;
        if leading {
            let abs = Abs {
                base: Base::Extern(first.clone()),
                segs: rest.to_vec(),
            };
            return Some(self.synthetic_root(abs, span));
        }
        if value && rest.is_empty() {
            if let Some(i) = self.param_index(first) {
                return Some((Root::Param(i), Vec::new()));
            }
            if self.is_local(first) {
                return Some((Root::Local(first.clone()), Vec::new()));
            }
            if first == "self" {
                return Some((Root::SelfValue, Vec::new()));
            }
        }
        if first == "Self" {
            let ty = self.self_ty.last().cloned().flatten()?;
            let mut s = path_segs(&ty);
            s.extend(rest.iter().cloned());
            let lead = ty.leading_colon.is_some();
            if s.first().map(String::as_str) == Some("Self") {
                return None;
            }
            return self.path_root(&s, lead, false, span);
        }
        if matches!(first.as_str(), "crate" | "$crate" | "self" | "super") {
            let abs = self.abs(self.scopes.len() - 1, segs, false, 0)?;
            return Some(self.synthetic_root(abs, span));
        }
        let scope = self.scopes.len().checked_sub(1)?;
        match self.lookup(first) {
            Some((Name::Use { local, .. }, _))
            | Some((Name::ModFile(local), _))
            | Some((Name::ExternCrate(local), _)) => Some((Root::Import(local), rest.to_vec())),
            Some((Name::Inline, i)) => {
                if self.scopes[i].block {
                    return None;
                }
                let abs = self.abs(scope, segs, false, 0)?;
                Some(self.synthetic_root(abs, span))
            }
            Some((Name::Item, _)) | Some((Name::Const(_), _)) => None,
            None => {
                if self.globs_in_scope() && first.chars().next().is_some_and(char::is_uppercase) {
                    return Some((Root::Ambient(first.clone()), rest.to_vec()));
                }
                if rest.is_empty() {
                    return if self.globs_in_scope() {
                        Some((Root::Ambient(first.clone()), Vec::new()))
                    } else {
                        None
                    };
                }
                if first.chars().next().is_some_and(char::is_lowercase) {
                    let abs = Abs {
                        base: Base::Extern(first.clone()),
                        segs: rest.to_vec(),
                    };
                    Some(self.synthetic_root(abs, span))
                } else {
                    None
                }
            }
        }
    }

    fn reference(
        &mut self,
        root: Root,
        members: Vec<String>,
        use_kind: UseKind,
        args: Vec<Expr>,
        span: PmSpan,
        text: String,
    ) -> Reference {
        let calls = if matches!(use_kind, UseKind::Call | UseKind::Construct) && !members.is_empty()
        {
            vec![u32::try_from(members.len() - 1).unwrap_or(0)]
        } else {
            Vec::new()
        };
        Reference {
            root,
            members,
            calls_in_chain: calls,
            use_kind,
            args,
            kwargs: Vec::new(),
            receiver: None,
            text,
            symbol: self.symbol(),
            span: self.span_of(span),
            location: self.location(span),
        }
    }

    fn emit(&mut self, r: Reference) {
        self.ir.references.push(r);
    }

    /// A reference to `path` in a type, bound, or attribute position.
    fn type_ref(&mut self, path: &Path, kind: UseKind) {
        let segs = path_segs(path);
        if let Some((root, members)) =
            self.path_root(&segs, path.leading_colon.is_some(), false, path.span())
        {
            let text = segs.join("::");
            let r = self.reference(root, members, kind, Vec::new(), path.span(), text);
            self.emit(r);
        }
    }

    // ---- items -------------------------------------------------------------------------

    pub fn file(&mut self, f: &syn::File) {
        let items: Vec<&Item> = f.items.iter().collect();
        self.push_scope(&items, Vec::new(), false);
        for a in &f.attrs {
            self.attribute(a);
        }
        for item in &f.items {
            self.item(item);
            if self.too_deep {
                return;
            }
        }
    }

    fn attribute(&mut self, a: &Attribute) {
        let Some(last) = attr_last(a) else { return };
        if last == "link" && a.path().segments.len() == 1 {
            self.construct(ConstructKind::NativeCode, a.span());
            return;
        }
        if last == "derive" {
            if let Ok(paths) =
                a.parse_args_with(Punctuated::<Path, syn::Token![,]>::parse_terminated)
            {
                for p in &paths {
                    if p.segments.len() > 1 || self.lookup(&path_segs(p)[0]).is_some() {
                        self.type_ref(p, UseKind::TypePosition);
                    }
                }
            }
            return;
        }
        let p = a.path();
        if p.segments.len() == 1 && BUILTIN_ATTRS.contains(&last.as_str()) {
            return;
        }
        if p.segments.len() > 1 || self.lookup(&last).is_some() {
            let p = p.clone();
            self.type_ref(&p, UseKind::TypePosition);
        }
    }

    fn construct(&mut self, kind: ConstructKind, span: PmSpan) {
        let c = DynamicConstruct {
            kind,
            text: self.text_of(span),
            symbol: self.symbol(),
            span: self.span_of(span),
            location: self.location(span),
        };
        self.ir.constructs.push(c);
    }

    fn mark_test(&mut self, attrs: &[Attribute], symbol: &str) {
        if cfg_test(attrs) || test_attr(attrs) {
            self.ir.test_scopes.push(symbol.to_string());
        }
    }

    fn item(&mut self, item: &Item) {
        if !self.enter() {
            return;
        }
        match item {
            Item::Use(u) => {
                for a in &u.attrs {
                    self.attribute(a);
                }
                self.item_use(u);
            }
            Item::Mod(m) => self.item_mod(m),
            Item::Fn(f) => {
                let sym = self.child_symbol(&ident_str(&f.sig.ident));
                self.function(&f.attrs, &f.sig, &f.block, sym, SymbolKind::Function);
            }
            Item::Impl(i) => self.item_impl(i),
            Item::Trait(t) => {
                for a in &t.attrs {
                    self.attribute(a);
                }
                let name = ident_str(&t.ident);
                let sym = self.child_symbol(&name);
                self.ir.symbols.push(SymbolSpan {
                    path: sym.clone(),
                    kind: SymbolKind::Class,
                    params: Vec::new(),
                    strict: None,
                    span: self.span_of(t.ident.span()),
                });
                self.mark_test(&t.attrs, &sym);
                visit::visit_generics(self, &t.generics);
                for b in &t.supertraits {
                    self.visit_type_param_bound(b);
                }
                for ti in &t.items {
                    match ti {
                        TraitItem::Fn(f) => {
                            let s = format!("{sym}::{}", ident_str(&f.sig.ident));
                            match &f.default {
                                Some(b) => {
                                    self.function(&f.attrs, &f.sig, b, s, SymbolKind::Method)
                                }
                                None => self.signature(&f.sig),
                            }
                        }
                        TraitItem::Const(c) => {
                            self.visit_type(&c.ty);
                            if let Some((_, e)) = &c.default {
                                self.visit_expr(e);
                            }
                        }
                        TraitItem::Macro(m) => self.mac(&m.mac),
                        _ => {}
                    }
                }
            }
            Item::Struct(s) => {
                for a in &s.attrs {
                    self.attribute(a);
                }
                self.def_symbol(&ident_str(&s.ident), s.ident.span());
                visit::visit_generics(self, &s.generics);
                visit::visit_fields(self, &s.fields);
            }
            Item::Enum(s) => {
                for a in &s.attrs {
                    self.attribute(a);
                }
                self.def_symbol(&ident_str(&s.ident), s.ident.span());
                visit::visit_generics(self, &s.generics);
                for v in &s.variants {
                    visit::visit_fields(self, &v.fields);
                    if let Some((_, e)) = &v.discriminant {
                        self.visit_expr(e);
                    }
                }
            }
            Item::Union(s) => {
                for a in &s.attrs {
                    self.attribute(a);
                }
                self.def_symbol(&ident_str(&s.ident), s.ident.span());
                visit::visit_generics(self, &s.generics);
                visit::visit_fields_named(self, &s.fields);
            }
            Item::Type(t) => {
                for a in &t.attrs {
                    self.attribute(a);
                }
                self.def_symbol(&ident_str(&t.ident), t.ident.span());
                visit::visit_generics(self, &t.generics);
                self.visit_type(&t.ty);
            }
            Item::Const(c) => {
                for a in &c.attrs {
                    self.attribute(a);
                }
                self.constant(&ident_str(&c.ident), &c.ty, &c.expr, c.span());
            }
            Item::Static(c) => {
                for a in &c.attrs {
                    self.attribute(a);
                }
                self.constant(&ident_str(&c.ident), &c.ty, &c.expr, c.span());
            }
            Item::ForeignMod(f) => {
                for a in &f.attrs {
                    self.attribute(a);
                }
                self.construct(ConstructKind::NativeCode, f.span());
            }
            Item::ExternCrate(e) => {
                let c = ident_str(&e.ident);
                let n = match &e.rename {
                    Some((_, r)) => ident_str(r),
                    None => c.clone(),
                };
                let local = self.qualified_local(&n);
                let crate_spec = if c == "self" { "crate".to_string() } else { c };
                let symbol = self.symbol();
                let block = self.in_block();
                self.push_import(
                    Some(local),
                    crate_spec,
                    Vec::new(),
                    false,
                    !block,
                    symbol,
                    e.span(),
                );
            }
            Item::Macro(m) => {
                for a in &m.attrs {
                    self.attribute(a);
                }
                if m.mac.path.is_ident("macro_rules") {
                    let name = m.ident.as_ref().map(ident_str).unwrap_or_default();
                    self.ir.symbols.push(SymbolSpan {
                        path: self.child_symbol(&format!("{name}!")),
                        kind: SymbolKind::Binding,
                        params: Vec::new(),
                        strict: None,
                        span: self.span_of(m.span()),
                    });
                    self.token_scan(m.mac.tokens.clone());
                } else {
                    self.mac(&m.mac);
                }
            }
            Item::TraitAlias(t) => {
                for b in &t.bounds {
                    self.visit_type_param_bound(b);
                }
            }
            _ => {}
        }
        self.leave();
    }

    fn def_symbol(&mut self, name: &str, span: PmSpan) {
        let path = self.child_symbol(name);
        self.ir.symbols.push(SymbolSpan {
            path,
            kind: SymbolKind::Class,
            params: Vec::new(),
            strict: None,
            span: self.span_of(span),
        });
    }

    fn qualified_local(&self, name: &str) -> String {
        if self.in_block() {
            format!("{}#{name}", self.symbol())
        } else {
            let p = self.module_prefix();
            if p.is_empty() {
                name.to_string()
            } else {
                format!("{}::{name}", p.join("::"))
            }
        }
    }

    fn constant(&mut self, name: &str, ty: &Type, expr: &SExpr, span: PmSpan) {
        self.visit_type(ty);
        let value = self.lower_expr(expr, 0);
        if self.in_block() {
            let symbol = self.symbol();
            let key = (symbol.clone(), name.to_string());
            *self.bind_counts.entry(key).or_default() += 1;
            let sp = self.span_of(span);
            self.lets.push((symbol, name.to_string(), value, sp));
        } else {
            let qual = self.qualified_local(name);
            let sp = self.span_of(span);
            self.ir.constants.push(ModuleConstant {
                name: qual,
                value,
                exported: true,
                span: sp,
            });
        }
        self.visit_expr(expr);
    }

    fn item_use(&mut self, u: &syn::ItemUse) {
        let mut leaves = Vec::new();
        use_leaves(&u.tree, &mut Vec::new(), &mut leaves);
        let block = self.in_block();
        let scope = self.scopes.len() - 1;
        let symbol = self.symbol();
        let leading = u.leading_colon.is_some();
        let pub_use = !matches!(u.vis, syn::Visibility::Inherited);
        for (path, leaf) in leaves {
            // The leaf binding itself is not visible while resolving its
            // own path (`use net::x` with `net` a sibling binding is fine).
            let Some(abs) = self.abs_excluding(scope, &path, leading, &leaf) else {
                continue;
            };
            let spec = abs.spec();
            match leaf {
                Leaf::Glob => {
                    self.push_import(None, spec, abs.segs, true, !block, symbol.clone(), u.span());
                }
                Leaf::Name(n) | Leaf::Named(n) => {
                    let local = if block {
                        format!("{symbol}#{n}")
                    } else {
                        self.qualified_local(&n)
                    };
                    self.push_use(
                        local,
                        spec,
                        abs.segs,
                        !block,
                        &symbol,
                        &path,
                        pub_use,
                        u.span(),
                    );
                }
                Leaf::Underscore => {
                    self.import_counter += 1;
                    let local = format!("_#{}", self.import_counter);
                    self.push_use(
                        local,
                        spec,
                        abs.segs,
                        false,
                        &symbol,
                        &path,
                        pub_use,
                        u.span(),
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_use(
        &mut self,
        local: String,
        spec: String,
        members: Vec<String>,
        visible: bool,
        symbol: &str,
        written: &[String],
        pub_use: bool,
        span: PmSpan,
    ) {
        self.push_import(
            Some(local.clone()),
            spec,
            members,
            false,
            visible,
            symbol.to_string(),
            span,
        );
        // The path a `use` names is a reference too (KTD4).
        let kind = if pub_use {
            UseKind::ValueEscape
        } else {
            UseKind::TypePosition
        };
        let text = written
            .iter()
            .filter(|s| s.as_str() != "self" || written.len() == 1)
            .cloned()
            .collect::<Vec<_>>()
            .join("::");
        let r = self.reference(
            Root::Import(local),
            Vec::new(),
            kind,
            Vec::new(),
            span,
            text,
        );
        if !pub_use {
            self.use_refs.insert(self.ir.references.len());
        }
        self.emit(r);
    }

    /// [`Self::abs`] for a `use` path; a name that binds itself (`use x;`
    /// where the leaf is `x`) is an extern crate, not a self-reference.
    fn abs_excluding(
        &self,
        scope: usize,
        path: &[String],
        leading: bool,
        leaf: &Leaf,
    ) -> Option<Abs> {
        if path.len() == 1
            && !leading
            && let Leaf::Name(n) = leaf
            && *n == path[0]
            && !matches!(path[0].as_str(), "crate" | "self" | "super")
        {
            return Some(Abs {
                base: Base::Extern(path[0].clone()),
                segs: Vec::new(),
            });
        }
        self.abs(scope, path, leading, 0)
    }

    fn item_mod(&mut self, m: &syn::ItemMod) {
        for a in &m.attrs {
            if !a.path().is_ident("path") {
                self.attribute(a);
            }
        }
        let name = ident_str(&m.ident);
        match &m.content {
            Some((_, items)) => {
                let mut prefix = self.module_prefix();
                prefix.push(name);
                let sym = prefix.join("::");
                self.ir.symbols.push(SymbolSpan {
                    path: sym.clone(),
                    kind: SymbolKind::Module,
                    params: Vec::new(),
                    strict: None,
                    span: self.span_of(m.span()),
                });
                self.mark_test(&m.attrs, &sym);
                let refs: Vec<&Item> = items.iter().collect();
                let saved = std::mem::take(&mut self.symbols);
                self.push_scope(&refs, prefix, false);
                for i in items {
                    self.item(i);
                }
                self.scopes.pop();
                self.symbols = saved;
            }
            None => {
                let prefix = self.module_prefix();
                let attr_path = m.attrs.iter().find_map(|a| match &a.meta {
                    Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
                        SExpr::Lit(l) => match &l.lit {
                            Lit::Str(s) => Some(s.value()),
                            _ => None,
                        },
                        _ => None,
                    },
                    _ => None,
                });
                let spec = match attr_path {
                    Some(p) if p.starts_with('/') || p.starts_with('\\') => {
                        spec::OUTSIDE_ROOT.to_string()
                    }
                    Some(p) if prefix.is_empty() => match fold(dir_of(self.path), &p) {
                        Some(t) => format!("{}{}", spec::FILE, String::from_utf8_lossy(&t)),
                        None => spec::OUTSIDE_ROOT.to_string(),
                    },
                    Some(p) => {
                        // Inside an inline module the target is relative to the
                        // module's directory; a climbing target that could leave
                        // the root fails closed without being written.
                        if p.split(['/', '\\']).any(|c| c == "..") {
                            spec::OUTSIDE_ROOT.to_string()
                        } else {
                            format!("{}{}/{p}", spec::PATH, prefix.join("/"))
                        }
                    }
                    None => {
                        let mut rel = prefix.clone();
                        rel.push(name.clone());
                        format!("{}{}", spec::MOD, rel.join("/"))
                    }
                };
                let local = self.qualified_local(&name);
                let symbol = self.symbol();
                let block = self.in_block();
                self.push_import(
                    Some(local),
                    spec,
                    Vec::new(),
                    false,
                    !block,
                    symbol,
                    m.span(),
                );
            }
        }
    }

    fn item_impl(&mut self, i: &syn::ItemImpl) {
        for a in &i.attrs {
            self.attribute(a);
        }
        visit::visit_generics(self, &i.generics);
        let ty = self.type_name(&i.self_ty);
        let name = match &i.trait_ {
            Some((p, _)) => format!("<impl {} for {ty}>", path_name(p)),
            None => format!("<impl {ty}>"),
        };
        let base = self.child_symbol(&name);
        self.mark_test(&i.attrs, &base);
        if let Some((p, _)) = &i.trait_ {
            self.type_ref(p, UseKind::TypePosition);
            for s in &p.segments {
                visit::visit_path_arguments(self, &s.arguments);
            }
        }
        self.visit_type(&i.self_ty);
        let self_path = match &*i.self_ty {
            Type::Path(tp) if tp.qself.is_none() => Some(tp.path.clone()),
            _ => None,
        };
        self.self_ty.push(self_path);
        for item in &i.items {
            match item {
                ImplItem::Fn(f) => {
                    let s = format!("{base}::{}", ident_str(&f.sig.ident));
                    self.function(&f.attrs, &f.sig, &f.block, s, SymbolKind::Method);
                }
                ImplItem::Const(c) => {
                    self.visit_type(&c.ty);
                    self.visit_expr(&c.expr);
                }
                ImplItem::Type(t) => self.visit_type(&t.ty),
                ImplItem::Macro(m) => self.mac(&m.mac),
                _ => {}
            }
        }
        self.self_ty.pop();
    }

    fn signature(&mut self, sig: &Signature) {
        visit::visit_generics(self, &sig.generics);
        for input in &sig.inputs {
            if let FnArg::Typed(t) = input {
                self.visit_type(&t.ty);
            }
        }
        visit::visit_return_type(self, &sig.output);
    }

    fn function(
        &mut self,
        attrs: &[Attribute],
        sig: &Signature,
        block: &syn::Block,
        symbol: String,
        kind: SymbolKind,
    ) {
        for a in attrs {
            self.attribute(a);
        }
        self.mark_test(attrs, &symbol);
        let mut params = Vec::new();
        for input in &sig.inputs {
            if let FnArg::Typed(t) = input {
                params.push(match &*t.pat {
                    Pat::Ident(p) => ident_str(&p.ident),
                    other => self.text_of(other.span()),
                });
            }
        }
        self.ir.symbols.push(SymbolSpan {
            path: symbol.clone(),
            kind,
            params: params.clone(),
            strict: None,
            span: self.span_of(sig.ident.span()),
        });
        // Paths in the signature belong to the function (KTD9).
        self.symbols.push(symbol.clone());
        self.signature(sig);
        self.fns.push(FnFrame {
            params,
            locals: HashSet::new(),
        });
        self.visit_block(block);
        self.fns.pop();
        self.symbols.pop();
    }

    // ---- macros ---------------------------------------------------------------------------

    fn mac(&mut self, m: &Macro) {
        let Some(last) = m.path.segments.last().map(|s| ident_str(&s.ident)) else {
            return;
        };
        match last.as_str() {
            "asm" | "global_asm" | "naked_asm" => {
                self.construct(ConstructKind::NativeCode, m.span());
                return;
            }
            "include" | "include_str" | "include_bytes" => {
                match syn::parse2::<syn::LitStr>(m.tokens.clone()) {
                    Ok(lit) => self.include(&lit.value(), last == "include", m.span()),
                    Err(_) => self.construct(ConstructKind::MacroCode, m.span()),
                }
                return;
            }
            "env" | "option_env" => return,
            _ => {}
        }
        let segs = path_segs(&m.path);
        let bound = segs.len() > 1 || self.lookup(&segs[0]).is_some();
        if bound
            && self.lookup(&format!("{}!", segs[0])).is_none()
            && let Some((root, mut members)) =
                self.path_root(&segs, m.path.leading_colon.is_some(), false, m.path.span())
        {
            match members.last_mut() {
                Some(l) => l.push('!'),
                None => members.push(String::new()),
            }
            members.retain(|s| !s.is_empty());
            let text = self.text_of(m.span());
            let r = self.reference(root, members, UseKind::Call, Vec::new(), m.span(), text);
            self.emit(r);
        }
        match m.parse_body_with(Punctuated::<SExpr, syn::Token![,]>::parse_terminated) {
            Ok(args) => {
                for a in &args {
                    self.visit_expr(a);
                }
            }
            Err(_) => self.token_scan(m.tokens.clone()),
        }
    }

    fn include(&mut self, target: &str, code: bool, span: PmSpan) {
        let folded = if target.starts_with('/') || target.starts_with('\\') {
            None
        } else {
            fold(dir_of(self.path), target)
        };
        let symbol = self.symbol();
        match folded {
            None => self.push_import(
                None,
                spec::OUTSIDE_ROOT.to_string(),
                Vec::new(),
                false,
                false,
                symbol,
                span,
            ),
            Some(p) if code => self.push_import(
                None,
                format!("{}{}", spec::FILE, String::from_utf8_lossy(&p)),
                Vec::new(),
                false,
                false,
                symbol,
                span,
            ),
            // A literal in-root data include loads no code.
            Some(_) => {}
        }
    }

    /// Finds paths in a token stream that does not parse as expressions: a
    /// `macro_rules!` body or an unusual invocation (KTD15).
    fn token_scan(&mut self, ts: TokenStream) {
        if !self.enter() {
            return;
        }
        let tts: Vec<TokenTree> = ts.into_iter().collect();
        let mut i = 0;
        while i < tts.len() {
            match &tts[i] {
                TokenTree::Group(g) => {
                    self.token_scan(g.stream());
                    i += 1;
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {
                    let (consumed, path) = scan_path(&tts, i);
                    if consumed == 0 {
                        i += 1;
                        continue;
                    }
                    if let Some((segs, leading, start)) = path {
                        let call = matches!(tts.get(i + consumed), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis);
                        let end = if call {
                            tts[i + consumed].span()
                        } else {
                            tts[i + consumed - 1].span()
                        };
                        let span = start.join(end).unwrap_or(start);
                        if let Some((root, members)) =
                            self.path_root(&segs, leading, segs.len() == 1, span)
                            && !matches!(root, Root::Local(_) | Root::Param(_) | Root::SelfValue)
                        {
                            let args = if call {
                                match &tts[i + consumed] {
                                    TokenTree::Group(g) => self.token_args(g.stream()),
                                    _ => Vec::new(),
                                }
                            } else {
                                Vec::new()
                            };
                            let kind = if call {
                                UseKind::Call
                            } else {
                                UseKind::ValueEscape
                            };
                            let text = self.text_of(span);
                            let r = self.reference(root, members, kind, args, span, text);
                            self.emit(r);
                        }
                    }
                    i += consumed;
                }
                TokenTree::Literal(_) => i += 1,
            }
        }
        self.leave();
    }

    fn token_args(&mut self, ts: TokenStream) -> Vec<Expr> {
        let parser = Punctuated::<SExpr, syn::Token![,]>::parse_terminated;
        match syn::parse::Parser::parse2(parser, ts.clone()) {
            Ok(args) => args.iter().map(|a| self.lower_expr(a, 0)).collect(),
            Err(_) => {
                let t = ts.to_string();
                if t.trim().is_empty() {
                    Vec::new()
                } else {
                    vec![Expr::Opaque(t)]
                }
            }
        }
    }

    // ---- expressions as values (KTD7) ------------------------------------------------------

    fn lower_expr(&mut self, e: &SExpr, depth: u32) -> Expr {
        if depth > 32 {
            return Expr::Opaque(self.text_of(e.span()));
        }
        match e {
            SExpr::Lit(l) => match &l.lit {
                Lit::Str(s) => Expr::Literal(s.value()),
                Lit::Int(i) => Expr::Literal(i.base10_digits().to_string()),
                Lit::Float(f) => Expr::Literal(f.base10_digits().to_string()),
                _ => Expr::Opaque(self.text_of(e.span())),
            },
            SExpr::Reference(r) => self.lower_expr(&r.expr, depth + 1),
            SExpr::Paren(p) => self.lower_expr(&p.expr, depth + 1),
            SExpr::Group(g) => self.lower_expr(&g.expr, depth + 1),
            SExpr::Try(t) => self.lower_expr(&t.expr, depth + 1),
            SExpr::Await(a) => self.lower_expr(&a.base, depth + 1),
            SExpr::Cast(c) => self.lower_expr(&c.expr, depth + 1),
            SExpr::MethodCall(m)
                if TRANSPARENT_METHODS.contains(&ident_str(&m.method).as_str()) =>
            {
                self.lower_expr(&m.receiver, depth + 1)
            }
            SExpr::Tuple(t) => Expr::Sequence(
                t.elems
                    .iter()
                    .map(|x| self.lower_expr(x, depth + 1))
                    .collect(),
            ),
            SExpr::Array(t) => Expr::Sequence(
                t.elems
                    .iter()
                    .map(|x| self.lower_expr(x, depth + 1))
                    .collect(),
            ),
            SExpr::Binary(b) if matches!(b.op, BinOp::Add(_)) => {
                let mut parts = Vec::new();
                for side in [&b.left, &b.right] {
                    match self.lower_expr(side, depth + 1) {
                        Expr::Template(p) => parts.extend(p),
                        other => parts.push(other),
                    }
                }
                Expr::Template(parts)
            }
            SExpr::Struct(s) => Expr::Object(
                s.fields
                    .iter()
                    .filter_map(|f| match &f.member {
                        syn::Member::Named(n) => {
                            Some((ident_str(n), self.lower_expr(&f.expr, depth + 1)))
                        }
                        syn::Member::Unnamed(_) => None,
                    })
                    .collect(),
            ),
            SExpr::Path(p) if p.qself.is_none() => {
                let segs = path_segs(&p.path);
                if segs.len() == 1 && p.path.leading_colon.is_none() {
                    let n = &segs[0];
                    if let Some(i) = self.param_index(n) {
                        return Expr::Param(i);
                    }
                    if self.is_local(n) {
                        return Expr::Name(n.clone());
                    }
                    match self.lookup(n) {
                        Some((Name::Const(q), i)) => {
                            return Expr::Name(if self.scopes[i].block { n.clone() } else { q });
                        }
                        Some((Name::Use { local, .. }, _)) => return Expr::Name(local),
                        _ => {}
                    }
                }
                Expr::Opaque(self.text_of(e.span()))
            }
            SExpr::Call(c) => {
                if let SExpr::Path(p) = &*c.func
                    && c.args.len() == 1
                    && p.path.segments.last().is_some_and(|s| s.ident == "from")
                    && p.path.segments.len() >= 2
                    && matches!(
                        p.path.segments[p.path.segments.len() - 2]
                            .ident
                            .to_string()
                            .as_str(),
                        "String" | "PathBuf" | "OsString" | "Cow"
                    )
                {
                    return self.lower_expr(&c.args[0], depth + 1);
                }
                match self.call_ref(c, depth) {
                    Some(r) => Expr::Reference(Box::new(r)),
                    None => Expr::Opaque(self.text_of(e.span())),
                }
            }
            SExpr::Macro(m) => self.lower_macro(&m.mac, depth),
            _ => Expr::Opaque(self.text_of(e.span())),
        }
    }

    fn lower_macro(&mut self, m: &Macro, depth: u32) -> Expr {
        let last = m
            .path
            .segments
            .last()
            .map(|s| ident_str(&s.ident))
            .unwrap_or_default();
        let parsed = m.parse_body_with(Punctuated::<SExpr, syn::Token![,]>::parse_terminated);
        match (last.as_str(), parsed) {
            ("env" | "option_env", Ok(args)) => {
                let args: Vec<Expr> = args
                    .iter()
                    .take(1)
                    .map(|a| self.lower_expr(a, depth + 1))
                    .collect();
                let text = self.text_of(m.span());
                let r = self.reference(
                    Root::Ambient(format!("{last}!")),
                    Vec::new(),
                    UseKind::Call,
                    args,
                    m.span(),
                    text,
                );
                Expr::Reference(Box::new(r))
            }
            ("format" | "format_args", Ok(args)) => match args.first() {
                Some(SExpr::Lit(syn::ExprLit {
                    lit: Lit::Str(s), ..
                })) => {
                    let rest: Vec<&SExpr> = args.iter().skip(1).collect();
                    self.format_template(&s.value(), &rest, depth)
                }
                _ => Expr::Opaque(self.text_of(m.span())),
            },
            ("concat", Ok(args)) => {
                Expr::Template(args.iter().map(|a| self.lower_expr(a, depth + 1)).collect())
            }
            _ => Expr::Opaque(self.text_of(m.span())),
        }
    }

    /// A `format!` string with its arguments as a template (KTD7).
    fn format_template(&mut self, fmt: &str, args: &[&SExpr], depth: u32) -> Expr {
        let mut named: HashMap<String, &SExpr> = HashMap::new();
        let mut positional: Vec<&SExpr> = Vec::new();
        for a in args {
            match a {
                SExpr::Assign(asg) => {
                    if let SExpr::Path(p) = &*asg.left
                        && let Some(id) = p.path.get_ident()
                    {
                        named.insert(ident_str(id), &asg.right);
                    }
                }
                other => positional.push(other),
            }
        }
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut next = 0usize;
        let chars: Vec<char> = fmt.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '{' && chars.get(i + 1) == Some(&'{') {
                lit.push('{');
                i += 2;
                continue;
            }
            if c == '}' && chars.get(i + 1) == Some(&'}') {
                lit.push('}');
                i += 2;
                continue;
            }
            if c == '{' {
                let Some(close) = chars[i..].iter().position(|x| *x == '}') else {
                    return Expr::Opaque(fmt.to_string());
                };
                let inner: String = chars[i + 1..i + close].iter().collect();
                let key = inner.split(':').next().unwrap_or("").trim().to_string();
                let value = if key.is_empty() {
                    let v = positional.get(next).map(|e| self.lower_expr(e, depth + 1));
                    next += 1;
                    v
                } else if let Ok(n) = key.parse::<usize>() {
                    positional.get(n).map(|e| self.lower_expr(e, depth + 1))
                } else if let Some(e) = named.get(&key) {
                    Some(self.lower_expr(e, depth + 1))
                } else {
                    // An inline captured identifier.
                    let path: SExpr = match syn::parse_str(&key) {
                        Ok(p) => p,
                        Err(_) => return Expr::Opaque(fmt.to_string()),
                    };
                    Some(self.lower_expr(&path, depth + 1))
                };
                if !lit.is_empty() {
                    parts.push(Expr::Literal(std::mem::take(&mut lit)));
                }
                parts.push(value.unwrap_or_else(|| Expr::Opaque(inner.clone())));
                i += close + 1;
                continue;
            }
            lit.push(c);
            i += 1;
        }
        if !lit.is_empty() {
            parts.push(Expr::Literal(lit));
        }
        Expr::Template(parts)
    }

    /// The reference a call with a path callee makes, or `None`.
    fn call_ref(&mut self, c: &syn::ExprCall, depth: u32) -> Option<Reference> {
        let SExpr::Path(p) = &*c.func else {
            return None;
        };
        let (segs, leading) = match &p.qself {
            // `<T as Trait>::m(..)` calls `T::m`.
            Some(q) => match &*q.ty {
                Type::Path(tp) if tp.qself.is_none() => {
                    let mut s = path_segs(&tp.path);
                    s.extend(
                        p.path
                            .segments
                            .iter()
                            .skip(q.position)
                            .map(|s| ident_str(&s.ident)),
                    );
                    (s, tp.path.leading_colon.is_some())
                }
                _ => return None,
            },
            None => (path_segs(&p.path), p.path.leading_colon.is_some()),
        };
        let (root, members) = self.path_root(&segs, leading, false, c.span())?;
        if matches!(root, Root::Local(_) | Root::Param(_)) {
            return None;
        }
        let args = c
            .args
            .iter()
            .map(|a| self.lower_expr(a, depth + 1))
            .collect();
        let text = self.text_of(c.span());
        Some(self.reference(root, members, UseKind::Call, args, c.span(), text))
    }

    fn note_binding(&mut self, name: &str) {
        let symbol = self.symbol();
        if let Some(f) = self.fns.last_mut() {
            f.locals.insert(name.to_string());
        }
        *self
            .bind_counts
            .entry((symbol, name.to_string()))
            .or_default() += 1;
    }
}

/// How a `use` tree leaf binds.
#[derive(Debug, Clone)]
enum Leaf {
    Glob,
    /// The last segment's own name.
    Name(String),
    /// An `as` rename.
    Named(String),
    Underscore,
}

fn use_leaves(tree: &UseTree, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, Leaf)>) {
    match tree {
        UseTree::Path(p) => {
            prefix.push(ident_str(&p.ident));
            use_leaves(&p.tree, prefix, out);
            prefix.pop();
        }
        UseTree::Name(n) => {
            let id = ident_str(&n.ident);
            if id == "self" {
                if let Some(last) = prefix.last().cloned() {
                    out.push((prefix.clone(), Leaf::Name(last)));
                }
            } else {
                let mut p = prefix.clone();
                p.push(id.clone());
                out.push((p, Leaf::Name(id)));
            }
        }
        UseTree::Rename(r) => {
            let id = ident_str(&r.ident);
            let mut p = prefix.clone();
            if id != "self" {
                p.push(id);
            }
            let alias = ident_str(&r.rename);
            out.push((
                p,
                if alias == "_" {
                    Leaf::Underscore
                } else {
                    Leaf::Named(alias)
                },
            ));
        }
        UseTree::Glob(_) => out.push((prefix.clone(), Leaf::Glob)),
        UseTree::Group(g) => {
            for t in &g.items {
                use_leaves(t, prefix, out);
            }
        }
    }
}

/// A path at `tts[i]`: (tokens consumed, path segments, leading `::`, start
/// span). A `$crate` start counts as `crate`; a path after `.` or `$` (a
/// method name or a metavariable) is skipped.
#[allow(clippy::type_complexity)]
fn scan_path(tts: &[TokenTree], i: usize) -> (usize, Option<(Vec<String>, bool, PmSpan)>) {
    let is_colon = |k: usize| matches!(tts.get(k), Some(TokenTree::Punct(p)) if p.as_char() == ':');
    let after_dot = i > 0 && matches!(&tts[i - 1], TokenTree::Punct(p) if p.as_char() == '.');
    let mut k = i;
    let mut leading = false;
    let mut segs = Vec::new();
    let start = tts[i].span();
    match &tts[i] {
        TokenTree::Punct(p) if p.as_char() == '$' => {
            if matches!(tts.get(i + 1), Some(TokenTree::Ident(id)) if id == "crate") {
                segs.push("crate".to_string());
                k = i + 2;
            } else {
                // A metavariable: skip it and its name.
                return (2.min(tts.len() - i), None);
            }
        }
        TokenTree::Punct(_) if is_colon(i) && is_colon(i + 1) => {
            leading = true;
            k = i + 2;
            match tts.get(k) {
                Some(TokenTree::Ident(id)) => {
                    segs.push(ident_str(id));
                    k += 1;
                }
                _ => return (2, None),
            }
        }
        TokenTree::Ident(id) => {
            segs.push(ident_str(id));
            k += 1;
        }
        _ => return (1, None),
    }
    while is_colon(k) && is_colon(k + 1) {
        match tts.get(k + 2) {
            Some(TokenTree::Ident(id)) => {
                segs.push(ident_str(id));
                k += 3;
            }
            _ => break,
        }
    }
    // A macro invocation `name!` is not a path to resolve here.
    let bang = matches!(tts.get(k), Some(TokenTree::Punct(p)) if p.as_char() == '!');
    if after_dot || bang || is_keyword(&segs[0]) {
        return (k - i, None);
    }
    (k - i, Some((segs, leading, start)))
}

fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "as" | "async"
            | "await"
            | "break"
            | "const"
            | "continue"
            | "dyn"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "static"
            | "struct"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "expr"
            | "ident"
            | "tt"
            | "ty"
            | "path"
            | "block"
            | "pat"
            | "stmt"
            | "item"
            | "literal"
            | "lifetime"
            | "meta"
            | "vis"
    )
}

/// A path rendered without generic arguments (KTD9).
fn path_name(p: &Path) -> String {
    let mut s = String::new();
    if p.leading_colon.is_some() {
        s.push_str("::");
    }
    s.push_str(&path_segs(p).join("::"));
    s
}

impl Lowerer<'_> {
    /// A type rendered for an impl symbol, generics stripped (KTD9).
    fn type_name(&self, t: &Type) -> String {
        match t {
            Type::Path(tp) if tp.qself.is_none() => path_name(&tp.path),
            Type::Reference(r) => {
                let m = if r.mutability.is_some() { "mut " } else { "" };
                format!("&{m}{}", self.type_name(&r.elem))
            }
            Type::Paren(p) => self.type_name(&p.elem),
            Type::Group(g) => self.type_name(&g.elem),
            Type::Slice(s) => format!("[{}]", self.type_name(&s.elem)),
            Type::Tuple(t) => format!(
                "({})",
                t.elems
                    .iter()
                    .map(|e| self.type_name(e))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            other => self
                .text_of(other.span())
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

impl<'ast> Visit<'ast> for Lowerer<'_> {
    fn visit_item(&mut self, i: &'ast Item) {
        self.item(i);
    }

    fn visit_attribute(&mut self, _: &'ast Attribute) {}

    fn visit_block(&mut self, b: &'ast syn::Block) {
        if !self.enter() {
            return;
        }
        let items: Vec<&Item> = b
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Item(i) => Some(i),
                _ => None,
            })
            .collect();
        self.push_scope(&items, self.module_prefix(), true);
        for s in &b.stmts {
            self.visit_stmt(s);
        }
        self.scopes.pop();
        self.leave();
    }

    fn visit_stmt_macro(&mut self, m: &'ast syn::StmtMacro) {
        self.mac(&m.mac);
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        if let Some(init) = &l.init {
            self.visit_expr(&init.expr);
            if let Some((_, d)) = &init.diverge {
                self.visit_expr(d);
            }
        }
        let (pat, ty) = match &l.pat {
            Pat::Type(t) => (&*t.pat, Some(&*t.ty)),
            other => (other, None),
        };
        if let Some(ty) = ty {
            self.visit_type(ty);
        }
        if let (Pat::Ident(p), Some(init)) = (pat, &l.init)
            && p.subpat.is_none()
        {
            let value = self.lower_expr(&init.expr, 0);
            let sp = self.span_of(l.span());
            self.lets
                .push((self.symbol(), ident_str(&p.ident), value, sp));
        }
        self.visit_pat(pat);
    }

    fn visit_pat(&mut self, p: &'ast Pat) {
        if !self.enter() {
            return;
        }
        match p {
            Pat::Ident(i) => {
                self.note_binding(&ident_str(&i.ident));
                if let Some((_, s)) = &i.subpat {
                    self.visit_pat(s);
                }
            }
            Pat::Type(t) => {
                self.visit_pat(&t.pat);
                self.visit_type(&t.ty);
            }
            Pat::Macro(_) | Pat::Lit(_) | Pat::Range(_) | Pat::Path(_) | Pat::Const(_) => {}
            Pat::TupleStruct(t) => {
                for e in &t.elems {
                    self.visit_pat(e);
                }
            }
            Pat::Struct(s) => {
                for f in &s.fields {
                    self.visit_pat(&f.pat);
                }
            }
            other => visit::visit_pat(self, other),
        }
        self.leave();
    }

    fn visit_expr(&mut self, e: &'ast SExpr) {
        if !self.enter() {
            return;
        }
        match e {
            SExpr::Call(c) => {
                match self.call_ref(c, 0) {
                    Some(r) => self.emit(r),
                    None => {
                        if !matches!(&*c.func, SExpr::Path(_)) {
                            self.visit_expr(&c.func);
                        }
                    }
                }
                if let SExpr::Path(p) = &*c.func {
                    if let Some(q) = &p.qself {
                        self.visit_type(&q.ty);
                        let trait_path = Path {
                            leading_colon: p.path.leading_colon,
                            segments: p.path.segments.iter().take(q.position).cloned().collect(),
                        };
                        if !trait_path.segments.is_empty() {
                            self.type_ref(&trait_path, UseKind::TypePosition);
                        }
                    }
                    for s in &p.path.segments {
                        visit::visit_path_arguments(self, &s.arguments);
                    }
                }
                for a in &c.args {
                    self.visit_expr(a);
                }
            }
            SExpr::MethodCall(m) => {
                let method = ident_str(&m.method);
                let recv = match &*m.receiver {
                    SExpr::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => {
                        let n = ident_str(&p.path.segments[0].ident);
                        if let Some(i) = self.param_index(&n) {
                            Some((Root::Param(i), vec![method.clone()]))
                        } else if self.is_local(&n) {
                            Some((Root::Local(n), vec![method.clone()]))
                        } else {
                            None
                        }
                    }
                    SExpr::Field(f) => match (&*f.base, &f.member) {
                        (SExpr::Path(p), syn::Member::Named(name)) if p.path.is_ident("self") => {
                            Some((Root::SelfValue, vec![ident_str(name), method.clone()]))
                        }
                        _ => None,
                    },
                    _ => None,
                };
                if let Some((root, members)) = recv {
                    let args = m.args.iter().map(|a| self.lower_expr(a, 0)).collect();
                    let text = self.text_of(m.span());
                    let r = self.reference(root, members, UseKind::Call, args, m.span(), text);
                    self.emit(r);
                }
                self.visit_expr(&m.receiver);
                if let Some(t) = &m.turbofish {
                    visit::visit_angle_bracketed_generic_arguments(self, t);
                }
                for a in &m.args {
                    self.visit_expr(a);
                }
            }
            SExpr::Path(p) => {
                if let Some(q) = &p.qself {
                    self.visit_type(&q.ty);
                } else {
                    let segs = path_segs(&p.path);
                    if let Some((root, members)) =
                        self.path_root(&segs, p.path.leading_colon.is_some(), true, p.span())
                        && !matches!(root, Root::Local(_) | Root::Param(_) | Root::SelfValue)
                    {
                        let text = self.text_of(p.span());
                        let r = self.reference(
                            root,
                            members,
                            UseKind::ValueEscape,
                            Vec::new(),
                            p.span(),
                            text,
                        );
                        self.emit(r);
                    }
                }
                for s in &p.path.segments {
                    visit::visit_path_arguments(self, &s.arguments);
                }
            }
            SExpr::Struct(s) => {
                if s.qself.is_none() {
                    self.type_ref(&s.path, UseKind::Construct);
                }
                for f in &s.fields {
                    self.visit_expr(&f.expr);
                }
                if let Some(r) = &s.rest {
                    self.visit_expr(r);
                }
            }
            SExpr::Macro(m) => self.mac(&m.mac),
            SExpr::Closure(c) => {
                let symbol = self.child_symbol("<closure>");
                let params: Vec<String> = c
                    .inputs
                    .iter()
                    .map(|p| match p {
                        Pat::Ident(i) => ident_str(&i.ident),
                        Pat::Type(t) => match &*t.pat {
                            Pat::Ident(i) => ident_str(&i.ident),
                            other => self.text_of(other.span()),
                        },
                        other => self.text_of(other.span()),
                    })
                    .collect();
                self.ir.symbols.push(SymbolSpan {
                    path: symbol.clone(),
                    kind: SymbolKind::Closure,
                    params: params.clone(),
                    strict: None,
                    span: self.span_of(c.span()),
                });
                self.symbols.push(symbol.clone());
                self.fns.push(FnFrame {
                    params,
                    locals: HashSet::new(),
                });
                for p in &c.inputs {
                    self.visit_pat(p);
                }
                visit::visit_return_type(self, &c.output);
                self.visit_expr(&c.body);
                self.fns.pop();
                self.symbols.pop();
            }
            SExpr::Assign(a) => {
                self.assign_target(&a.left);
                self.visit_expr(&a.right);
            }
            SExpr::Binary(b)
                if matches!(
                    b.op,
                    BinOp::AddAssign(_)
                        | BinOp::SubAssign(_)
                        | BinOp::MulAssign(_)
                        | BinOp::DivAssign(_)
                        | BinOp::RemAssign(_)
                        | BinOp::BitXorAssign(_)
                        | BinOp::BitAndAssign(_)
                        | BinOp::BitOrAssign(_)
                        | BinOp::ShlAssign(_)
                        | BinOp::ShrAssign(_)
                ) =>
            {
                self.assign_target(&b.left);
                self.visit_expr(&b.right);
            }
            other => visit::visit_expr(self, other),
        }
        self.leave();
    }

    fn visit_type(&mut self, t: &'ast Type) {
        if !self.enter() {
            return;
        }
        match t {
            Type::Path(tp) => {
                if let Some(q) = &tp.qself {
                    self.visit_type(&q.ty);
                    let trait_path = Path {
                        leading_colon: tp.path.leading_colon,
                        segments: tp.path.segments.iter().take(q.position).cloned().collect(),
                    };
                    if !trait_path.segments.is_empty() {
                        self.type_ref(&trait_path, UseKind::TypePosition);
                    }
                } else {
                    self.type_ref(&tp.path, UseKind::TypePosition);
                }
                for s in &tp.path.segments {
                    visit::visit_path_arguments(self, &s.arguments);
                }
            }
            Type::Macro(m) => self.mac(&m.mac),
            other => visit::visit_type(self, other),
        }
        self.leave();
    }

    fn visit_trait_bound(&mut self, b: &'ast syn::TraitBound) {
        self.type_ref(&b.path, UseKind::TypePosition);
        for s in &b.path.segments {
            visit::visit_path_arguments(self, &s.arguments);
        }
    }

    fn visit_macro(&mut self, m: &'ast Macro) {
        self.mac(m);
    }
}

impl Lowerer<'_> {
    fn assign_target(&mut self, left: &SExpr) {
        match left {
            SExpr::Path(p) if p.path.segments.len() == 1 && p.qself.is_none() => {
                let n = ident_str(&p.path.segments[0].ident);
                self.reassigned.insert((self.symbol(), n));
            }
            SExpr::Field(f) => {
                if let (SExpr::Path(p), syn::Member::Named(name)) = (&*f.base, &f.member)
                    && p.path.is_ident("self")
                {
                    let text = self.text_of(f.span());
                    let r = self.reference(
                        Root::SelfValue,
                        vec![ident_str(name)],
                        UseKind::AssignmentTarget,
                        Vec::new(),
                        f.span(),
                        text,
                    );
                    self.emit(r);
                } else {
                    self.visit_expr(left);
                }
            }
            other => self.visit_expr(other),
        }
    }
}

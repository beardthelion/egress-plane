//! Python source to IR (KTD4).
//!
//! The file is parsed with `ruff_python_parser`, which NFKC-normalizes every
//! identifier as PEP 3131 requires, so names reach the IR as the runtime sees
//! them. Lowering then runs three passes over the AST:
//!
//! 1. A depth check. Any statement, expression, or pattern nested deeper
//!    than [`MAX_DEPTH`] makes the file `too-deeply-nested`; the later passes
//!    and the AST's own destructor recurse, so a deeper tree is never walked
//!    or dropped.
//! 2. Scope collection: every module, class, function, lambda, and
//!    comprehension scope with its bindings, parameters, and `global` and
//!    `nonlocal` declarations.
//! 3. Emission: imports, references in every position the runtime evaluates
//!    (calls, values, decorators, default arguments, base classes and
//!    keywords, eagerly evaluated annotations, f-string format specs),
//!    argument trees, symbols in qualname style (KTD9), single-assignment
//!    constants and locals (KTD7), `self` attributes assigned in `__init__`
//!    (KTD8), receiver provenance for reflective builtins, and introspection
//!    attribute accesses (KTD15).
//!
//! A name is resolved the way Python resolves it: the scope's own bindings,
//! then enclosing function scopes (class scopes are skipped), then the
//! module, and otherwise the builtins, which the IR records as an ambient
//! global. A name only a star import can bind therefore stays ambient, and
//! the core looks it up through the file's star imports.

use std::collections::{HashMap, HashSet};

use egress_core::ir::{
    Expr as IrExpr, FileIr, Import, IntrospectionAccess, LineIndex, LocalBinding, ModuleConstant,
    Provenance, Reference, Root, SelfAttribute, Span, SymbolKind, SymbolSpan, UseKind,
};
use egress_core::model::Language;
use ruff_python_ast::visitor::{
    Visitor, walk_expr, walk_pattern, walk_stmt,
};
use ruff_python_ast::{
    self as ast, Arguments, Comprehension, ConversionFlag, Expr, ExprAttribute, ExprCall,
    ExprContext, InterpolatedStringElement, Parameters, Pattern, PySourceType, Stmt,
};
use ruff_python_parser::parse_unchecked_source;
use ruff_text_size::{Ranged, TextRange};

/// Deepest statement, expression, or pattern nesting the frontend walks.
/// The bracket pre-scan (KTD13) stops most deep files before parsing; this
/// catches nesting without brackets, such as a long `a + b + ...` chain.
pub const MAX_DEPTH: u32 = 1000;

/// Why a file could not be lowered. Each maps to a fixed whole-file blind
/// spot reason; parser messages never reach output (KTD13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    /// The parser rejected the file: `parse-error`.
    Parse,
    /// Nesting exceeded [`MAX_DEPTH`]: `too-deeply-nested`.
    TooDeeplyNested,
}

/// Attribute name prefixes that reach frames, tracebacks, generators,
/// coroutines, and async generators (KTD15).
const INTROSPECTION_PREFIXES: [&str; 5] = ["tb_", "f_", "gi_", "cr_", "ag_"];

/// Lowers one Python file.
pub fn lower(text: &str) -> Result<FileIr, LowerError> {
    let parsed = parse_unchecked_source(text, PySourceType::Python);
    let mut depth = DepthCheck::default();
    depth.visit_body(&parsed.syntax().body);
    if depth.exceeded {
        // Dropping the tree recurses once per level; a tree this deep would
        // overflow the stack, so it is leaked instead.
        std::mem::forget(parsed);
        return Err(LowerError::TooDeeplyNested);
    }
    if !parsed.has_valid_syntax() {
        return Err(LowerError::Parse);
    }
    let body = &parsed.syntax().body;
    let mut w = Walker::new(text);
    w.visit_body(body);
    w.phase = Phase::Emit;
    w.cur = 0;
    w.visit_body(body);
    Ok(w.ir)
}

// ---- depth check ----------------------------------------------------------------

#[derive(Default)]
struct DepthCheck {
    depth: u32,
    exceeded: bool,
}

impl DepthCheck {
    fn enter(&mut self) -> bool {
        if self.exceeded {
            return false;
        }
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.exceeded = true;
            self.depth -= 1;
            return false;
        }
        true
    }
}

impl<'a> Visitor<'a> for DepthCheck {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        if self.enter() {
            walk_stmt(self, stmt);
            self.depth -= 1;
        }
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if self.enter() {
            walk_expr(self, expr);
            self.depth -= 1;
        }
    }

    fn visit_pattern(&mut self, pattern: &'a Pattern) {
        if self.enter() {
            walk_pattern(self, pattern);
            self.depth -= 1;
        }
    }
}

// ---- scopes -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Class,
    Function,
    Lambda,
    Comprehension,
}

#[derive(Debug, Default, Clone)]
struct Binding {
    /// Binding operations in this scope.
    count: u32,
    /// How many of them are a plain `name = value` (or walrus).
    simple: u32,
    /// Bound by an import statement or a literal loader call:
    /// (specifier, members).
    import: Option<(String, Vec<String>)>,
    /// A numbered parameter, 1-based.
    param: Option<u32>,
    /// The method receiver (`self` or `cls`).
    receiver: bool,
    /// A `def` or `class` in this scope.
    definition: bool,
    /// `name = <call>` bound it, with the callee's root name.
    call_of: Option<String>,
    /// `name = <literal display>` bound it.
    literal: bool,
}

#[derive(Debug)]
struct Scope {
    kind: ScopeKind,
    parent: Option<usize>,
    /// Symbol path of code running in this scope (KTD9).
    symbol: String,
    /// For a method scope: the owning class path.
    class: Option<String>,
    /// For a method: whether it is `__init__`.
    init: bool,
    bindings: HashMap<String, Binding>,
    globals: HashSet<String>,
    nonlocals: HashSet<String>,
    /// Dotted `import a.b.c` names bound here, as full dotted strings.
    dotted: Vec<String>,
}

impl Scope {
    fn new(kind: ScopeKind, parent: Option<usize>, symbol: String) -> Scope {
        Scope {
            kind,
            parent,
            symbol,
            class: None,
            init: false,
            bindings: HashMap::new(),
            globals: HashSet::new(),
            nonlocals: HashSet::new(),
            dotted: Vec::new(),
        }
    }
}

/// What a name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NameRef {
    Import(Option<(String, Vec<String>)>),
    Local,
    Param(u32),
    Receiver,
    Ambient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Collect,
    Emit,
}

/// The base of a member chain.
enum Base<'a> {
    Name(&'a ast::ExprName),
    /// A literal loader call such as `__import__("os")`.
    Loader(&'a ExprCall),
}

/// A name or loader call followed by literal attribute names.
struct Chain<'a> {
    base: Base<'a>,
    /// Attribute nodes from innermost to outermost.
    attrs: Vec<&'a ExprAttribute>,
}

/// A loader call with a literal specifier.
enum Loader {
    Import(String),
    /// A relative specifier whose package is not literal, or a non-zero
    /// `level`: the target cannot be named statically.
    Dynamic,
}

struct Walker<'s> {
    src: &'s str,
    lines: LineIndex<'s>,
    phase: Phase,
    scopes: Vec<Scope>,
    by_range: HashMap<(u32, u32), usize>,
    cur: usize,
    ir: FileIr,
    future_annotations: bool,
    /// Inside an eagerly evaluated annotation: chains are type positions.
    in_annotation: u32,
    /// Loader calls bound to a name by a plain assignment; they need no
    /// synthetic import binding.
    named_loaders: HashSet<u32>,
}

fn key(r: TextRange) -> (u32, u32) {
    (r.start().to_u32(), r.end().to_u32())
}

fn is_introspection_name(name: &str) -> bool {
    (name.len() > 4 && name.starts_with("__") && name.ends_with("__"))
        || INTROSPECTION_PREFIXES.iter().any(|p| name.starts_with(p))
}

fn is_literal_display(e: &Expr) -> bool {
    matches!(
        e,
        Expr::StringLiteral(_)
            | Expr::BytesLiteral(_)
            | Expr::NumberLiteral(_)
            | Expr::BooleanLiteral(_)
            | Expr::NoneLiteral(_)
            | Expr::EllipsisLiteral(_)
            | Expr::FString(_)
            | Expr::List(_)
            | Expr::Tuple(_)
            | Expr::Dict(_)
            | Expr::Set(_)
            | Expr::ListComp(_)
            | Expr::SetComp(_)
            | Expr::DictComp(_)
    )
}

fn string_literal(e: &Expr) -> Option<String> {
    match e {
        Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
        _ => None,
    }
}

/// Numbered parameters in declaration order and the receiver, if the
/// function is a method whose first positional parameter is one.
fn parameters(p: &Parameters, method: bool) -> (Vec<String>, Option<String>) {
    let mut names: Vec<String> = Vec::new();
    for a in p.posonlyargs.iter().chain(p.args.iter()) {
        names.push(a.parameter.name.id.to_string());
    }
    if let Some(v) = &p.vararg {
        names.push(v.name.id.to_string());
    }
    for a in &p.kwonlyargs {
        names.push(a.parameter.name.id.to_string());
    }
    if let Some(k) = &p.kwarg {
        names.push(k.name.id.to_string());
    }
    let positional = p.posonlyargs.len() + p.args.len();
    let receiver = if method && positional > 0 {
        Some(names.remove(0))
    } else {
        None
    };
    (names, receiver)
}

fn is_staticmethod(decorators: &[ast::Decorator]) -> bool {
    decorators.iter().any(|d| match &d.expression {
        Expr::Name(n) => n.id.as_str() == "staticmethod",
        Expr::Attribute(a) => a.attr.id.as_str() == "staticmethod",
        _ => false,
    })
}

impl<'s> Walker<'s> {
    fn new(src: &'s str) -> Walker<'s> {
        Walker {
            src,
            lines: LineIndex::new(src),
            phase: Phase::Collect,
            scopes: vec![Scope::new(ScopeKind::Module, None, "<module>".into())],
            by_range: HashMap::new(),
            cur: 0,
            ir: FileIr::new(Language::Python),
            future_annotations: false,
            in_annotation: 0,
            named_loaders: HashSet::new(),
        }
    }

    fn emit(&self) -> bool {
        self.phase == Phase::Emit
    }

    fn text(&self, r: TextRange) -> String {
        self.src
            .get(r.start().to_usize()..r.end().to_usize())
            .unwrap_or_default()
            .to_string()
    }

    fn span(r: TextRange) -> Span {
        Span {
            start: r.start().to_u32(),
            end: r.end().to_u32(),
        }
    }

    fn symbol(&self) -> String {
        self.scopes[self.cur].symbol.clone()
    }

    // ---- scope entry ------------------------------------------------------------

    /// The qualname prefix for a definition named `name` in the current
    /// scope (KTD9). Comprehensions are transparent, as CPython 3.12 inlines
    /// them.
    fn qualname(&self, name: &str) -> String {
        let mut s = self.cur;
        while self.scopes[s].kind == ScopeKind::Comprehension {
            match self.scopes[s].parent {
                Some(p) => s = p,
                None => break,
            }
        }
        let sc = &self.scopes[s];
        match sc.kind {
            ScopeKind::Module => name.to_string(),
            ScopeKind::Class => format!("{}.{name}", sc.symbol),
            _ => format!("{}.<locals>.{name}", sc.symbol),
        }
    }

    /// Enters the scope for the node at `range`, creating it while
    /// collecting. Returns the previous scope index.
    fn enter(&mut self, range: TextRange, make: impl FnOnce(&Self) -> Scope) -> usize {
        let prev = self.cur;
        match self.phase {
            Phase::Collect => {
                let mut scope = make(self);
                scope.parent = Some(prev);
                self.scopes.push(scope);
                let id = self.scopes.len() - 1;
                self.by_range.insert(key(range), id);
                self.cur = id;
            }
            Phase::Emit => {
                if let Some(&id) = self.by_range.get(&key(range)) {
                    self.cur = id;
                }
            }
        }
        prev
    }

    // ---- bindings (collect phase) ---------------------------------------------------

    /// The scope a binding of `name` in the current scope lands in.
    fn binding_scope(&self, name: &str, walrus: bool) -> usize {
        let mut s = self.cur;
        if walrus {
            while self.scopes[s].kind == ScopeKind::Comprehension {
                match self.scopes[s].parent {
                    Some(p) => s = p,
                    None => break,
                }
            }
        }
        let sc = &self.scopes[s];
        if sc.globals.contains(name) {
            return 0;
        }
        if sc.nonlocals.contains(name) {
            let mut p = sc.parent;
            while let Some(i) = p {
                let ps = &self.scopes[i];
                if matches!(ps.kind, ScopeKind::Function | ScopeKind::Lambda)
                    && ps.bindings.contains_key(name)
                {
                    return i;
                }
                p = ps.parent;
            }
        }
        s
    }

    fn bind(&mut self, name: &str, f: impl FnOnce(&mut Binding)) {
        if self.phase != Phase::Collect {
            return;
        }
        let s = self.binding_scope(name, false);
        let b = self.scopes[s].bindings.entry(name.to_string()).or_default();
        b.count += 1;
        f(b);
    }

    /// Binds every name a target expression stores to.
    fn bind_target(&mut self, target: &Expr, value: Option<&Expr>) {
        match target {
            Expr::Name(n) => {
                let simple = value.is_some();
                let call_of = value.and_then(|v| self.callee_root_name(v));
                let literal = value.is_some_and(is_literal_display);
                let loader = value.and_then(|v| match v {
                    Expr::Call(c) => self.loader_syntactic(c),
                    _ => None,
                });
                self.bind(n.id.as_str(), |b| {
                    if simple {
                        b.simple += 1;
                    }
                    if let Some(spec) = loader {
                        b.import = Some((spec, Vec::new()));
                    }
                    b.call_of = call_of;
                    b.literal = literal;
                });
            }
            Expr::Tuple(t) => t.elts.iter().for_each(|e| self.bind_target(e, None)),
            Expr::List(l) => l.elts.iter().for_each(|e| self.bind_target(e, None)),
            Expr::Starred(s) => self.bind_target(&s.value, None),
            _ => {}
        }
    }

    /// The root name of a call's callee chain (`make_client` in
    /// `make_client()`, `requests` in `requests.Session()`).
    fn callee_root_name(&self, e: &Expr) -> Option<String> {
        let e = match e {
            Expr::Await(a) => &a.value,
            other => other,
        };
        let Expr::Call(c) = e else { return None };
        let mut f = c.func.as_ref();
        while let Expr::Attribute(a) = f {
            f = &a.value;
        }
        match f {
            Expr::Name(n) => Some(n.id.to_string()),
            _ => None,
        }
    }

    /// A loader call recognized by its spelling alone, for the collect
    /// phase: `__import__`, `importlib.import_module`, `import_module`,
    /// `importlib.__import__`, and `builtins.__import__` with a literal
    /// specifier.
    fn loader_syntactic(&self, c: &ExprCall) -> Option<String> {
        let callee = self.text(c.func.range());
        if !matches!(
            callee.as_str(),
            "__import__"
                | "importlib.import_module"
                | "import_module"
                | "importlib.__import__"
                | "builtins.__import__"
        ) {
            return None;
        }
        match self.loader_spec(c, callee.ends_with("__import__")) {
            Some(Loader::Import(s)) => Some(s),
            _ => None,
        }
    }

    /// The module a literal loader call imports. `__import__("a.b")`
    /// returns the top-level package unless a `fromlist` is given;
    /// `import_module("a.b")` returns `a.b`.
    fn loader_spec(&self, c: &ExprCall, dunder: bool) -> Option<Loader> {
        let first = c.arguments.args.first()?;
        let spec = string_literal(first)?;
        let kw = |name: &str| {
            c.arguments
                .keywords
                .iter()
                .find(|k| k.arg.as_ref().is_some_and(|a| a.id.as_str() == name))
                .map(|k| &k.value)
        };
        if dunder {
            let level = c.arguments.args.get(4).or_else(|| kw("level"));
            if level.is_some_and(|l| self.text(l.range()) != "0") {
                return Some(Loader::Dynamic);
            }
            let fromlist = c.arguments.args.get(3).or_else(|| kw("fromlist"));
            let nonempty = fromlist.is_some_and(|f| match f {
                Expr::List(l) => !l.elts.is_empty(),
                Expr::Tuple(t) => !t.elts.is_empty(),
                Expr::NoneLiteral(_) => false,
                _ => true,
            });
            if nonempty {
                return Some(Loader::Import(spec));
            }
            let top = spec.split('.').next().unwrap_or(&spec).to_string();
            return Some(Loader::Import(top));
        }
        if let Some(rest) = spec.strip_prefix('.') {
            let package = c.arguments.args.get(1).or_else(|| kw("package"));
            return match package.and_then(string_literal) {
                Some(p) if !rest.starts_with('.') => Some(Loader::Import(if rest.is_empty() {
                    p
                } else {
                    format!("{p}.{rest}")
                })),
                _ => Some(Loader::Dynamic),
            };
        }
        Some(Loader::Import(spec))
    }

    // ---- name resolution (emit phase) ------------------------------------------------

    fn resolve(&self, name: &str) -> NameRef {
        let start = self.cur;
        let sc = &self.scopes[start];
        let mut s = if sc.globals.contains(name) {
            0
        } else {
            start
        };
        let skip_own = sc.nonlocals.contains(name);
        let mut first = true;
        loop {
            let scope = &self.scopes[s];
            let visible = !(first && skip_own)
                && (s == start || scope.kind != ScopeKind::Class || s == 0);
            if visible && let Some(b) = scope.bindings.get(name) {
                if let Some(imp) = &b.import {
                    return NameRef::Import(Some(imp.clone()));
                }
                // A parameter is numbered only within its own symbol.
                if scope.symbol == self.scopes[start].symbol {
                    if b.receiver && scope.class.is_some() {
                        return NameRef::Receiver;
                    }
                    if let Some(i) = b.param {
                        return NameRef::Param(i);
                    }
                }
                return NameRef::Local;
            }
            first = false;
            match scope.parent {
                Some(p) => s = p,
                None => return NameRef::Ambient,
            }
        }
    }

    fn binding_of(&self, name: &str) -> Option<&Binding> {
        let mut s = self.cur;
        loop {
            let scope = &self.scopes[s];
            if (s == self.cur || scope.kind != ScopeKind::Class)
                && let Some(b) = scope.bindings.get(name)
            {
                return Some(b);
            }
            s = scope.parent?;
        }
    }

    fn root_for(&self, r: &NameRef, name: &str) -> Root {
        match r {
            NameRef::Import(_) => Root::Import(name.to_string()),
            NameRef::Local => Root::Local(name.to_string()),
            NameRef::Param(i) => Root::Param(*i),
            NameRef::Receiver => Root::SelfValue,
            NameRef::Ambient => Root::Ambient(name.to_string()),
        }
    }

    /// The dotted `import a.b.c` binding that covers the longest prefix of
    /// `name` plus `members`, if any.
    fn dotted_import(&self, name: &str, members: &[String]) -> Option<(String, usize)> {
        let mut s = self.cur;
        loop {
            let scope = &self.scopes[s];
            if (s == self.cur || scope.kind != ScopeKind::Class)
                && scope.bindings.contains_key(name)
            {
                let mut best: Option<(String, usize)> = None;
                for d in &scope.dotted {
                    let parts: Vec<&str> = d.split('.').collect();
                    let n = parts.len() - 1;
                    if parts[0] == name
                        && n <= members.len()
                        && parts[1..].iter().zip(members).all(|(a, b)| *a == b)
                        && best.as_ref().is_none_or(|(_, m)| n > *m)
                    {
                        best = Some((d.clone(), n));
                    }
                }
                return best;
            }
            s = scope.parent?;
        }
    }

    /// A loader call that the emit phase confirms by resolution.
    fn loader(&self, c: &ExprCall) -> Option<Loader> {
        let dunder = match c.func.as_ref() {
            Expr::Name(n) => match (n.id.as_str(), self.resolve(n.id.as_str())) {
                ("__import__", NameRef::Ambient) => true,
                (_, NameRef::Import(Some((spec, members)))) if spec == "importlib" => {
                    match members.as_slice() {
                        [m] if m == "import_module" => false,
                        [m] if m == "__import__" => true,
                        _ => return None,
                    }
                }
                (_, NameRef::Import(Some((spec, members))))
                    if spec == "builtins" && members == ["__import__"] =>
                {
                    true
                }
                _ => return None,
            },
            Expr::Attribute(a) => {
                let Expr::Name(n) = a.value.as_ref() else {
                    return None;
                };
                let NameRef::Import(Some((spec, members))) = self.resolve(n.id.as_str()) else {
                    return None;
                };
                if !members.is_empty() {
                    return None;
                }
                match (spec.as_str(), a.attr.id.as_str()) {
                    ("importlib", "import_module") => false,
                    ("importlib" | "builtins", "__import__") => true,
                    _ => return None,
                }
            }
            _ => return None,
        };
        self.loader_spec(c, dunder)
    }

    // ---- chains ------------------------------------------------------------------------

    fn chain_of<'a>(&self, e: &'a Expr) -> Option<Chain<'a>> {
        let mut attrs = Vec::new();
        let mut cur = e;
        loop {
            match cur {
                Expr::Attribute(a) => {
                    attrs.push(a);
                    cur = &a.value;
                }
                Expr::Name(n) => {
                    attrs.reverse();
                    return Some(Chain {
                        base: Base::Name(n),
                        attrs,
                    });
                }
                Expr::Call(c) if self.emit() && matches!(self.loader(c), Some(Loader::Import(_))) => {
                    attrs.reverse();
                    return Some(Chain {
                        base: Base::Loader(c),
                        attrs,
                    });
                }
                _ => return None,
            }
        }
    }

    /// The root and member chain of `chain`, and the base's resolution.
    fn chain_root(&self, chain: &Chain<'_>) -> (Root, Vec<String>, Option<NameRef>) {
        let members: Vec<String> = chain.attrs.iter().map(|a| a.attr.id.to_string()).collect();
        match chain.base {
            Base::Name(n) => {
                let name = n.id.as_str();
                let r = self.resolve(name);
                if matches!(r, NameRef::Import(_))
                    && let Some((dotted, used)) = self.dotted_import(name, &members)
                {
                    return (Root::Import(dotted), members[used..].to_vec(), Some(r));
                }
                (self.root_for(&r, name), members, Some(r))
            }
            Base::Loader(c) => (Root::Import(self.text(c.range())), members, None),
        }
    }

    fn reference(
        &self,
        root: Root,
        members: Vec<String>,
        use_kind: UseKind,
        range: TextRange,
    ) -> Reference {
        Reference {
            root,
            members,
            calls_in_chain: Vec::new(),
            use_kind,
            args: Vec::new(),
            kwargs: Vec::new(),
            receiver: None,
            text: self.text(range),
            symbol: self.symbol(),
            span: Self::span(range),
            location: self.lines.location(range.start().to_usize()),
        }
    }

    fn introspect(&mut self, a: &ExprAttribute) {
        if !self.emit() || !is_introspection_name(a.attr.id.as_str()) {
            return;
        }
        let receiver = self.provenance(&a.value).unwrap_or(Provenance::Unknown);
        self.ir.introspection.push(IntrospectionAccess {
            attribute: a.attr.id.to_string(),
            receiver,
            text: self.text(a.range()),
            symbol: self.symbol(),
            span: Self::span(a.range()),
            location: self.lines.location(a.range().start().to_usize()),
        });
    }

    /// Emits the value reference for a chain read (`os.system`, `self.s`),
    /// and the introspection accesses along it. A bare local, parameter, or
    /// receiver name is not a reference: its meaning is the value bound to
    /// it, which is reported where it is bound.
    fn chain_value(&mut self, chain: &Chain<'_>, range: TextRange) {
        if !self.emit() {
            return;
        }
        if let Base::Loader(c) = chain.base {
            self.visit_call(c);
        }
        let (root, members, _) = self.chain_root(chain);
        let bare_local = members.is_empty()
            && matches!(root, Root::Local(_) | Root::Param(_) | Root::SelfValue);
        if !bare_local {
            let kind = if self.in_annotation > 0 {
                UseKind::TypePosition
            } else {
                UseKind::ValueEscape
            };
            let r = self.reference(root, members, kind, range);
            self.ir.references.push(r);
        }
        for a in &chain.attrs {
            self.introspect(a);
        }
    }

    // ---- argument trees ------------------------------------------------------------------

    fn lower_args(&self, a: &Arguments) -> (Vec<IrExpr>, Vec<(String, IrExpr)>) {
        let args = a.args.iter().map(|e| self.lower_value(e)).collect();
        let kwargs = a
            .keywords
            .iter()
            .filter_map(|k| {
                k.arg
                    .as_ref()
                    .map(|n| (n.id.to_string(), self.lower_value(&k.value)))
            })
            .collect();
        (args, kwargs)
    }

    fn lower_value(&self, e: &Expr) -> IrExpr {
        match e {
            Expr::StringLiteral(s) => IrExpr::Literal(s.value.to_str().to_string()),
            Expr::NumberLiteral(_) => IrExpr::Literal(self.text(e.range())),
            Expr::FString(f) => {
                let mut parts = Vec::new();
                for part in f.value.iter() {
                    match part {
                        ast::FStringPartRef::Literal(l) => {
                            parts.push(IrExpr::Literal(l.value.to_string()))
                        }
                        ast::FStringPartRef::FString(fs) => {
                            for el in &fs.elements {
                                match el {
                                    InterpolatedStringElement::Literal(l) => {
                                        parts.push(IrExpr::Literal(l.value.to_string()))
                                    }
                                    InterpolatedStringElement::Interpolation(i) => {
                                        if i.conversion == ConversionFlag::None
                                            && i.format_spec.is_none()
                                            && i.debug_text.is_none()
                                        {
                                            parts.push(self.lower_value(&i.expression));
                                        } else {
                                            parts.push(IrExpr::Opaque(self.text(i.range())));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                IrExpr::Template(parts)
            }
            Expr::BinOp(b) if b.op == ast::Operator::Add => {
                let mut parts = Vec::new();
                for side in [&b.left, &b.right] {
                    match self.lower_value(side) {
                        IrExpr::Template(p) => parts.extend(p),
                        other => parts.push(other),
                    }
                }
                IrExpr::Template(parts)
            }
            Expr::Await(a) => self.lower_value(&a.value),
            Expr::Named(n) => self.lower_value(&n.value),
            Expr::Name(n) => match self.resolve(n.id.as_str()) {
                NameRef::Param(i) => IrExpr::Param(i),
                _ => IrExpr::Name(n.id.to_string()),
            },
            Expr::Attribute(a) => {
                let (root, members) = match self.chain_of(e) {
                    Some(chain) => {
                        let (r, m, _) = self.chain_root(&chain);
                        (r, m)
                    }
                    None => (Root::Expression, vec![a.attr.id.to_string()]),
                };
                IrExpr::Reference(Box::new(self.reference(
                    root,
                    members,
                    UseKind::ValueEscape,
                    e.range(),
                )))
            }
            Expr::Call(c) => {
                if let Some(Loader::Import(_)) = self.loader(c) {
                    return IrExpr::Reference(Box::new(self.reference(
                        Root::Import(self.text(c.range())),
                        Vec::new(),
                        UseKind::ValueEscape,
                        e.range(),
                    )));
                }
                let (root, members) = match self.chain_of(&c.func) {
                    Some(chain) => {
                        let (r, m, _) = self.chain_root(&chain);
                        (r, m)
                    }
                    None => match c.func.as_ref() {
                        Expr::Attribute(a) => (Root::Expression, vec![a.attr.id.to_string()]),
                        _ => (Root::Expression, Vec::new()),
                    },
                };
                let mut r = self.reference(root, members, UseKind::Call, e.range());
                let (args, kwargs) = self.lower_args(&c.arguments);
                r.args = args;
                r.kwargs = kwargs;
                IrExpr::Reference(Box::new(r))
            }
            Expr::Subscript(s) => IrExpr::Subscript {
                base: Box::new(self.lower_value(&s.value)),
                key: Box::new(self.lower_value(&s.slice)),
            },
            Expr::Tuple(t) => IrExpr::Sequence(t.elts.iter().map(|x| self.lower_value(x)).collect()),
            Expr::List(l) => IrExpr::Sequence(l.elts.iter().map(|x| self.lower_value(x)).collect()),
            Expr::Dict(d) => {
                let mut fields = Vec::new();
                for item in &d.items {
                    match item.key.as_ref().and_then(string_literal) {
                        Some(k) => fields.push((k, self.lower_value(&item.value))),
                        None => return IrExpr::Opaque(self.text(e.range())),
                    }
                }
                IrExpr::Object(fields)
            }
            _ => IrExpr::Opaque(self.text(e.range())),
        }
    }

    // ---- provenance ---------------------------------------------------------------------

    /// Provenance of a receiver handed to a reflective builtin (KTD4).
    /// `None` leaves the decision to the core, which resolves the target
    /// expression itself (a tracked client, a catalogued call result).
    fn provenance(&self, e: &Expr) -> Option<Provenance> {
        if is_literal_display(e) {
            return Some(Provenance::Literal);
        }
        match e {
            Expr::Name(n) => match self.resolve(n.id.as_str()) {
                NameRef::Import(_) => Some(Provenance::ModuleBinding),
                NameRef::Param(i) => Some(Provenance::Parameter(i)),
                NameRef::Receiver => Some(Provenance::Parameter(0)),
                NameRef::Ambient => {
                    if n.id.as_str() == "__builtins__" {
                        Some(Provenance::AmbientModule)
                    } else {
                        None
                    }
                }
                NameRef::Local => {
                    let b = self.binding_of(n.id.as_str())?;
                    if b.count != 1 {
                        return None;
                    }
                    if b.literal {
                        return Some(Provenance::Literal);
                    }
                    let callee = b.call_of.as_ref()?;
                    match self.resolve(callee) {
                        NameRef::Local => Some(Provenance::FirstPartyCallResult),
                        _ => None,
                    }
                }
            },
            Expr::Call(c) => {
                let mut f = c.func.as_ref();
                while let Expr::Attribute(a) = f {
                    f = &a.value;
                }
                match f {
                    Expr::Name(n) if self.resolve(n.id.as_str()) == NameRef::Local => {
                        Some(Provenance::FirstPartyCallResult)
                    }
                    _ => None,
                }
            }
            Expr::Attribute(_) => {
                let chain = self.chain_of(e)?;
                let Base::Name(n) = chain.base else {
                    return None;
                };
                match self.resolve(n.id.as_str()) {
                    NameRef::Import(_) => Some(Provenance::ModuleBinding),
                    NameRef::Param(i) => Some(Provenance::Parameter(i)),
                    NameRef::Receiver => Some(Provenance::Parameter(0)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Whether the callee is the builtin `getattr`, `setattr`, or `delattr`.
    fn reflective_builtin(&self, root: &Root, members: &[String], base: Option<&NameRef>) -> bool {
        let names = ["getattr", "setattr", "delattr"];
        match (root, members) {
            (Root::Ambient(n), []) => names.contains(&n.as_str()),
            (Root::Ambient(n), [m]) if n == "__builtins__" => names.contains(&m.as_str()),
            (Root::Import(_), _) => match base {
                Some(NameRef::Import(Some((spec, ms)))) if spec == "builtins" => {
                    let mut full = ms.clone();
                    full.extend(members.iter().cloned());
                    full.len() == 1 && names.contains(&full[0].as_str())
                }
                _ => false,
            },
            _ => false,
        }
    }

    // ---- calls ----------------------------------------------------------------------------

    fn visit_call(&mut self, c: &ExprCall) {
        if !self.emit() {
            self.visit_expr(&c.func);
            for a in &c.arguments.args {
                self.visit_expr(a);
            }
            for k in &c.arguments.keywords {
                self.visit_expr(&k.value);
            }
            return;
        }
        let mut skip_target = false;
        match self.chain_of(&c.func) {
            Some(chain) => {
                if let Base::Loader(inner) = chain.base {
                    self.visit_call(inner);
                }
                let (root, members, base) = self.chain_root(&chain);
                let mut r = self.reference(root, members, UseKind::Call, c.range());
                let (args, kwargs) = self.lower_args(&c.arguments);
                if self.reflective_builtin(&r.root, &r.members, base.as_ref()) {
                    // The target is the reflective access's receiver, not a
                    // value escape of its own.
                    skip_target = matches!(
                        c.arguments.args.first(),
                        Some(Expr::Name(_) | Expr::Attribute(_))
                    );
                    let name = c.arguments.args.get(1);
                    match name.and_then(string_literal) {
                        Some(lit) => {
                            if is_introspection_name(&lit) {
                                let target = c.arguments.args.first();
                                let receiver = target
                                    .and_then(|t| self.provenance(t))
                                    .unwrap_or(Provenance::Unknown);
                                self.ir.introspection.push(IntrospectionAccess {
                                    attribute: lit,
                                    receiver,
                                    text: self.text(c.range()),
                                    symbol: self.symbol(),
                                    span: Self::span(c.range()),
                                    location: self.lines.location(c.range().start().to_usize()),
                                });
                            }
                        }
                        None => {
                            r.receiver = c.arguments.args.first().and_then(|t| self.provenance(t));
                        }
                    }
                }
                r.args = args;
                r.kwargs = kwargs;
                self.ir.references.push(r);
                for a in &chain.attrs {
                    self.introspect(a);
                }
            }
            None => self.visit_expr(&c.func),
        }
        match self.loader(c) {
            Some(Loader::Import(spec)) => {
                if !self.named_loaders.contains(&c.range().start().to_u32()) {
                    let imp = Import {
                        local: Some(self.text(c.range())),
                        specifier: spec,
                        members: Vec::new(),
                        type_only: false,
                        star: false,
                        re_export: false,
                        default: false,
                        symbol: self.symbol(),
                        span: Self::span(c.range()),
                        location: self.lines.location(c.range().start().to_usize()),
                    };
                    self.ir.imports.push(imp);
                }
            }
            Some(Loader::Dynamic) => self.ir.constructs.push(egress_core::ir::DynamicConstruct {
                kind: egress_core::ir::ConstructKind::DynamicImport,
                text: self.text(c.range()),
                symbol: self.symbol(),
                span: Self::span(c.range()),
                location: self.lines.location(c.range().start().to_usize()),
            }),
            None => {}
        }
        for (i, arg) in c.arguments.args.iter().enumerate() {
            if i == 0 && skip_target {
                if let Expr::Attribute(_) = arg
                    && let Some(chain) = self.chain_of(arg)
                {
                    for a in &chain.attrs {
                        self.introspect(a);
                    }
                }
                continue;
            }
            self.visit_expr(arg);
        }
        for k in &c.arguments.keywords {
            self.visit_expr(&k.value);
        }
    }

    // ---- targets ---------------------------------------------------------------------------

    /// Visits an assignment or deletion target.
    fn visit_target(&mut self, target: &Expr, value: Option<&Expr>) {
        match target {
            Expr::Name(n) => {
                if !self.emit() {
                    return;
                }
                let Some(value) = value else { return };
                let name = n.id.as_str();
                let sc = &self.scopes[self.cur];
                let Some(b) = sc.bindings.get(name) else {
                    return;
                };
                if b.count != 1 || b.simple != 1 || b.import.is_some() {
                    return;
                }
                let v = self.lower_value(value);
                match sc.kind {
                    ScopeKind::Module => self.ir.constants.push(ModuleConstant {
                        name: name.to_string(),
                        value: v,
                        exported: true,
                        span: Self::span(target.range()),
                    }),
                    ScopeKind::Function => {
                        let symbol = self.symbol();
                        self.ir.locals.push(LocalBinding {
                            symbol,
                            name: name.to_string(),
                            value: v,
                            span: Self::span(target.range()),
                        })
                    }
                    _ => {}
                }
            }
            Expr::Attribute(a) => {
                if !self.emit() {
                    self.visit_expr(&a.value);
                    return;
                }
                match self.chain_of(target) {
                    Some(chain) => {
                        if let Base::Loader(c) = chain.base {
                            self.visit_call(c);
                        }
                        let (root, members, _) = self.chain_root(&chain);
                        let sc = &self.scopes[self.cur];
                        if root == Root::SelfValue && members.len() == 1 && sc.init {
                            let class = sc.class.clone().unwrap_or_default();
                            let v = match value {
                                Some(v) => self.lower_value(v),
                                None => IrExpr::Opaque(self.text(target.range())),
                            };
                            self.ir.self_attributes.push(SelfAttribute {
                                class,
                                attribute: members[0].clone(),
                                value: v,
                                span: Self::span(target.range()),
                            });
                        } else if !members.is_empty() {
                            let r = self.reference(
                                root,
                                members,
                                UseKind::AssignmentTarget,
                                target.range(),
                            );
                            self.ir.references.push(r);
                        }
                        for at in &chain.attrs {
                            self.introspect(at);
                        }
                    }
                    None => {
                        self.visit_expr(&a.value);
                        self.introspect(a);
                    }
                }
            }
            Expr::Subscript(s) => {
                self.visit_subscript(s);
            }
            Expr::Tuple(t) => t.elts.iter().for_each(|e| self.visit_target(e, None)),
            Expr::List(l) => l.elts.iter().for_each(|e| self.visit_target(e, None)),
            Expr::Starred(s) => self.visit_target(&s.value, None),
            other => self.visit_expr(other),
        }
    }

    fn visit_subscript(&mut self, s: &ast::ExprSubscript) {
        if self.emit()
            && let Expr::Name(n) = s.value.as_ref()
            && n.id.as_str() == "__builtins__"
            && self.resolve("__builtins__") == NameRef::Ambient
        {
            // `__builtins__` is the builtins namespace: a literal key is a
            // member, any other key is scope injection (KTD15).
            let root = Root::Ambient("__builtins__".into());
            let r = match string_literal(&s.slice) {
                Some(k) => self.reference(root, vec![k], UseKind::ValueEscape, s.range()),
                None => {
                    let mut r = self.reference(root, Vec::new(), UseKind::ComputedMember, s.range());
                    r.receiver = Some(Provenance::AmbientModule);
                    r
                }
            };
            self.ir.references.push(r);
            self.visit_expr(&s.slice);
            return;
        }
        self.visit_expr(&s.value);
        self.visit_expr(&s.slice);
    }

    fn visit_annotation_expr(&mut self, e: &Expr) {
        self.in_annotation += 1;
        self.visit_expr(e);
        self.in_annotation -= 1;
    }

    fn eager_annotations(&self) -> bool {
        !self.future_annotations
    }

    // ---- definitions --------------------------------------------------------------------

    fn visit_function(&mut self, f: &ast::StmtFunctionDef) {
        let name = f.name.id.to_string();
        let in_class = self.scopes[self.cur].kind == ScopeKind::Class;
        let class_path = in_class.then(|| self.scopes[self.cur].symbol.clone());
        let method = in_class && !is_staticmethod(&f.decorator_list);
        self.bind(&name, |b| b.definition = true);
        for d in &f.decorator_list {
            self.visit_expr(&d.expression);
        }
        if let Some(tp) = &f.type_params {
            self.visit_type_params(tp);
        }
        // Defaults and annotations are evaluated in the enclosing scope.
        for p in f.parameters.iter_non_variadic_params() {
            if let Some(d) = &p.default {
                self.visit_expr(d);
            }
        }
        if self.eager_annotations() {
            for p in f.parameters.iter() {
                if let Some(a) = p.as_parameter().annotation() {
                    self.visit_annotation_expr(a);
                }
            }
            if let Some(r) = &f.returns {
                self.visit_annotation_expr(r);
            }
        }
        let path = self.qualname(&name);
        let (params, receiver) = parameters(&f.parameters, method);
        if self.emit() {
            self.ir.symbols.push(SymbolSpan {
                path: path.clone(),
                kind: if in_class {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                },
                params: params.clone(),
                strict: None,
                span: Self::span(f.range),
            });
        }
        let prev = self.enter(f.range, |_| {
            let mut s = Scope::new(ScopeKind::Function, Some(0), path.clone());
            if method {
                s.class = class_path.clone();
                s.init = name == "__init__";
            }
            s
        });
        if self.phase == Phase::Collect {
            for (i, p) in params.iter().enumerate() {
                let b = self.scopes[self.cur]
                    .bindings
                    .entry(p.clone())
                    .or_default();
                b.count += 1;
                b.param = Some(u32::try_from(i + 1).unwrap_or(u32::MAX));
            }
            if let Some(r) = &receiver {
                let b = self.scopes[self.cur]
                    .bindings
                    .entry(r.clone())
                    .or_default();
                b.count += 1;
                b.receiver = true;
            }
        }
        self.visit_body(&f.body);
        self.cur = prev;
    }

    fn visit_class(&mut self, c: &ast::StmtClassDef) {
        let name = c.name.id.to_string();
        self.bind(&name, |b| b.definition = true);
        for d in &c.decorator_list {
            self.visit_expr(&d.expression);
        }
        if let Some(tp) = &c.type_params {
            self.visit_type_params(tp);
        }
        if let Some(args) = &c.arguments {
            for base in &args.args {
                match self.chain_of(base) {
                    Some(chain) if self.emit() => {
                        if let Base::Loader(inner) = chain.base {
                            self.visit_call(inner);
                        }
                        let (root, members, _) = self.chain_root(&chain);
                        let r = self.reference(root, members, UseKind::BaseClass, base.range());
                        self.ir.references.push(r);
                        for a in &chain.attrs {
                            self.introspect(a);
                        }
                    }
                    _ => self.visit_expr(base),
                }
            }
            for k in &args.keywords {
                self.visit_expr(&k.value);
            }
        }
        let path = self.qualname(&name);
        if self.emit() {
            self.ir.symbols.push(SymbolSpan {
                path: path.clone(),
                kind: SymbolKind::Class,
                params: Vec::new(),
                strict: None,
                span: Self::span(c.range),
            });
        }
        let prev = self.enter(c.range, |_| {
            Scope::new(ScopeKind::Class, Some(0), path.clone())
        });
        self.visit_body(&c.body);
        self.cur = prev;
    }

    fn visit_lambda(&mut self, l: &ast::ExprLambda) {
        if let Some(p) = &l.parameters {
            for d in p.iter_non_variadic_params() {
                if let Some(d) = &d.default {
                    self.visit_expr(d);
                }
            }
        }
        let path = self.qualname("<lambda>");
        let params = l
            .parameters
            .as_ref()
            .map(|p| parameters(p, false).0)
            .unwrap_or_default();
        if self.emit() {
            self.ir.symbols.push(SymbolSpan {
                path: path.clone(),
                kind: SymbolKind::Closure,
                params: params.clone(),
                strict: None,
                span: Self::span(l.range),
            });
        }
        let prev = self.enter(l.range, |_| {
            Scope::new(ScopeKind::Lambda, Some(0), path.clone())
        });
        if self.phase == Phase::Collect {
            for (i, p) in params.iter().enumerate() {
                let b = self.scopes[self.cur]
                    .bindings
                    .entry(p.clone())
                    .or_default();
                b.count += 1;
                b.param = Some(u32::try_from(i + 1).unwrap_or(u32::MAX));
            }
        }
        self.visit_expr(&l.body);
        self.cur = prev;
    }

    /// A comprehension: the first iterable runs in the enclosing scope, the
    /// rest in the comprehension's own scope, which shares the enclosing
    /// symbol.
    fn visit_comprehension_expr(
        &mut self,
        range: TextRange,
        generators: &[Comprehension],
        elts: &[&Expr],
    ) {
        let Some(first) = generators.first() else {
            return;
        };
        self.visit_expr(&first.iter);
        let symbol = self.symbol();
        let prev = self.enter(range, |_| {
            Scope::new(ScopeKind::Comprehension, Some(0), symbol.clone())
        });
        for (i, g) in generators.iter().enumerate() {
            if i > 0 {
                self.visit_expr(&g.iter);
            }
            if self.phase == Phase::Collect {
                self.bind_target(&g.target, None);
            }
            self.visit_target(&g.target, None);
            for cond in &g.ifs {
                self.visit_expr(cond);
            }
        }
        for e in elts {
            self.visit_expr(e);
        }
        self.cur = prev;
    }

    fn visit_import(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Import(i) => {
                for alias in &i.names {
                    let full = alias.name.id.to_string();
                    let (local, spec) = match &alias.asname {
                        Some(a) => (a.id.to_string(), full.clone()),
                        None => {
                            let top = full.split('.').next().unwrap_or(&full).to_string();
                            (top.clone(), top)
                        }
                    };
                    if self.phase == Phase::Collect {
                        let dotted = alias.asname.is_none() && full.contains('.');
                        let s = self.binding_scope(&local, false);
                        let b = self.scopes[s].bindings.entry(local.clone()).or_default();
                        b.count += 1;
                        b.import = Some((spec.clone(), Vec::new()));
                        if dotted && !self.scopes[s].dotted.contains(&full) {
                            self.scopes[s].dotted.push(full.clone());
                        }
                        continue;
                    }
                    self.push_import(Some(local), spec, Vec::new(), false, alias.range);
                    if alias.asname.is_none() && full.contains('.') {
                        self.push_import(Some(full.clone()), full, Vec::new(), false, alias.range);
                    }
                }
            }
            Stmt::ImportFrom(i) => {
                let module = i.module.as_ref().map(|m| m.id.to_string()).unwrap_or_default();
                let spec = format!("{}{module}", ".".repeat(i.level as usize));
                for alias in &i.names {
                    let name = alias.name.id.to_string();
                    if name == "*" {
                        if self.emit() {
                            self.push_import(None, spec.clone(), Vec::new(), true, alias.range);
                        }
                        continue;
                    }
                    let local = alias
                        .asname
                        .as_ref()
                        .map(|a| a.id.to_string())
                        .unwrap_or_else(|| name.clone());
                    if self.phase == Phase::Collect {
                        if spec == "__future__" && name == "annotations" {
                            self.future_annotations = true;
                        }
                        let s = self.binding_scope(&local, false);
                        let b = self.scopes[s].bindings.entry(local).or_default();
                        b.count += 1;
                        b.import = Some((spec.clone(), vec![name]));
                        continue;
                    }
                    self.push_import(Some(local), spec.clone(), vec![name], false, alias.range);
                }
            }
            _ => {}
        }
    }

    fn push_import(
        &mut self,
        local: Option<String>,
        specifier: String,
        members: Vec<String>,
        star: bool,
        range: TextRange,
    ) {
        let imp = Import {
            local,
            specifier,
            members,
            type_only: false,
            star,
            re_export: false,
            default: false,
            symbol: self.symbol(),
            span: Self::span(range),
            location: self.lines.location(range.start().to_usize()),
        };
        self.ir.imports.push(imp);
    }

    fn visit_assign_value(&mut self, targets: &[&Expr], value: &Expr) {
        // `x = __import__("os")` binds `x` to the module.
        if self.emit()
            && let [Expr::Name(n)] = targets
            && let Expr::Call(c) = value
            && let Some(Loader::Import(spec)) = self.loader(c)
        {
            let b = self.binding_of(n.id.as_str());
            if b.is_some_and(|b| b.import.is_some()) {
                self.named_loaders.insert(c.range().start().to_u32());
                self.push_import(Some(n.id.to_string()), spec, Vec::new(), false, c.range());
            }
        }
        self.visit_expr(value);
    }
}

impl<'a> Visitor<'a> for Walker<'_> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::FunctionDef(f) => self.visit_function(f),
            Stmt::ClassDef(c) => self.visit_class(c),
            Stmt::Import(_) | Stmt::ImportFrom(_) => self.visit_import(stmt),
            Stmt::Global(g) => {
                if self.phase == Phase::Collect {
                    for n in &g.names {
                        self.scopes[self.cur].globals.insert(n.id.to_string());
                    }
                }
            }
            Stmt::Nonlocal(g) => {
                if self.phase == Phase::Collect {
                    for n in &g.names {
                        self.scopes[self.cur].nonlocals.insert(n.id.to_string());
                    }
                }
            }
            Stmt::Assign(a) => {
                if self.phase == Phase::Collect {
                    for t in &a.targets {
                        self.bind_target(t, Some(&a.value));
                    }
                }
                let targets: Vec<&Expr> = a.targets.iter().collect();
                self.visit_assign_value(&targets, &a.value);
                for t in &a.targets {
                    self.visit_target(t, Some(&a.value));
                }
            }
            Stmt::AugAssign(a) => {
                if self.phase == Phase::Collect {
                    self.bind_target(&a.target, None);
                }
                self.visit_expr(&a.value);
                self.visit_target(&a.target, None);
            }
            Stmt::AnnAssign(a) => {
                if self.phase == Phase::Collect {
                    match &a.value {
                        Some(v) => self.bind_target(&a.target, Some(v)),
                        None => {
                            if let Expr::Name(n) = a.target.as_ref() {
                                let s = self.binding_scope(n.id.as_str(), false);
                                self.scopes[s]
                                    .bindings
                                    .entry(n.id.to_string())
                                    .or_default();
                            }
                        }
                    }
                }
                if let Some(v) = &a.value {
                    self.visit_assign_value(&[a.target.as_ref()], v);
                }
                // Module and class annotations are evaluated eagerly;
                // annotations of function locals never are.
                let kind = self.scopes[self.cur].kind;
                if self.eager_annotations() && matches!(kind, ScopeKind::Module | ScopeKind::Class)
                {
                    self.visit_annotation_expr(&a.annotation);
                }
                self.visit_target(&a.target, a.value.as_deref());
            }
            Stmt::Delete(d) => {
                for t in &d.targets {
                    if self.phase == Phase::Collect {
                        self.bind_target(t, None);
                    }
                    self.visit_target(t, None);
                }
            }
            Stmt::For(f) => {
                self.visit_expr(&f.iter);
                if self.phase == Phase::Collect {
                    self.bind_target(&f.target, None);
                }
                self.visit_target(&f.target, None);
                self.visit_body(&f.body);
                self.visit_body(&f.orelse);
            }
            Stmt::With(w) => {
                for item in &w.items {
                    self.visit_expr(&item.context_expr);
                    if let Some(v) = &item.optional_vars {
                        if self.phase == Phase::Collect {
                            self.bind_target(v, None);
                        }
                        self.visit_target(v, None);
                    }
                }
                self.visit_body(&w.body);
            }
            Stmt::Try(t) => {
                self.visit_body(&t.body);
                for h in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = h;
                    if let Some(ty) = &h.type_ {
                        self.visit_expr(ty);
                    }
                    if let Some(n) = &h.name {
                        self.bind(n.id.as_str(), |_| {});
                    }
                    self.visit_body(&h.body);
                }
                self.visit_body(&t.orelse);
                self.visit_body(&t.finalbody);
            }
            Stmt::TypeAlias(t) => {
                if let Expr::Name(n) = t.name.as_ref() {
                    self.bind(n.id.as_str(), |_| {});
                }
                if let Some(tp) = &t.type_params {
                    self.visit_type_params(tp);
                }
                self.visit_annotation_expr(&t.value);
            }
            _ => walk_stmt(self, stmt),
        }
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Name(n) => {
                if self.emit() && n.ctx == ExprContext::Load {
                    let chain = Chain {
                        base: Base::Name(n),
                        attrs: Vec::new(),
                    };
                    self.chain_value(&chain, n.range);
                }
            }
            Expr::Attribute(a) => {
                if a.ctx != ExprContext::Load {
                    self.visit_target(expr, None);
                    return;
                }
                match self.chain_of(expr) {
                    Some(chain) => self.chain_value(&chain, a.range),
                    None => {
                        self.visit_expr(&a.value);
                        self.introspect(a);
                    }
                }
            }
            Expr::Call(c) => self.visit_call(c),
            Expr::Subscript(s) => {
                if s.ctx == ExprContext::Load {
                    self.visit_subscript(s);
                } else {
                    self.visit_target(expr, None);
                }
            }
            Expr::Lambda(l) => self.visit_lambda(l),
            Expr::ListComp(c) => {
                self.visit_comprehension_expr(c.range, &c.generators, &[c.elt.as_ref()])
            }
            Expr::SetComp(c) => {
                self.visit_comprehension_expr(c.range, &c.generators, &[c.elt.as_ref()])
            }
            Expr::Generator(c) => {
                self.visit_comprehension_expr(c.range, &c.generators, &[c.elt.as_ref()])
            }
            Expr::DictComp(c) => {
                let mut elts: Vec<&Expr> = Vec::new();
                if let Some(k) = &c.key {
                    elts.push(k);
                }
                elts.push(&c.value);
                self.visit_comprehension_expr(c.range, &c.generators, &elts)
            }
            Expr::Named(n) => {
                self.visit_expr(&n.value);
                if let Expr::Name(t) = n.target.as_ref() {
                    if self.phase == Phase::Collect {
                        let s = self.binding_scope(t.id.as_str(), true);
                        let b = self.scopes[s].bindings.entry(t.id.to_string()).or_default();
                        b.count += 1;
                        b.simple += 1;
                    } else {
                        let saved = self.cur;
                        let mut s = self.cur;
                        while self.scopes[s].kind == ScopeKind::Comprehension {
                            match self.scopes[s].parent {
                                Some(p) => s = p,
                                None => break,
                            }
                        }
                        self.cur = s;
                        self.visit_target(&n.target, Some(&n.value));
                        self.cur = saved;
                    }
                }
            }
            _ => walk_expr(self, expr),
        }
    }

    fn visit_pattern(&mut self, pattern: &'a Pattern) {
        if self.phase == Phase::Collect {
            match pattern {
                Pattern::MatchAs(p) => {
                    if let Some(n) = &p.name {
                        self.bind(n.id.as_str(), |_| {});
                    }
                }
                Pattern::MatchStar(p) => {
                    if let Some(n) = &p.name {
                        self.bind(n.id.as_str(), |_| {});
                    }
                }
                Pattern::MatchMapping(p) => {
                    if let Some(n) = &p.rest {
                        self.bind(n.id.as_str(), |_| {});
                    }
                }
                _ => {}
            }
        }
        walk_pattern(self, pattern);
    }
}

//! Lowering one Go file to the shared IR.
//!
//! Imports follow Go's local-name rules (the last path element with
//! version elements and a `go-` prefix dropped, explicit aliases
//! winning, `.` a star import, `_` a value use of the whole package).
//! References are package-qualified selector chains resolved against the
//! file's import locals and the declared types it can see: a
//! `var c http.Client` is a `Construct` site and binds `c` to the client
//! type, so `c.Get` resolves as `[Client, Get]`. Value uses
//! (`f := http.Get`, embedding, `go` and `defer` calls) follow the
//! shared `ValueEscape`/`Call` rules. Package constants and
//! single-assignment locals feed the destination machinery; package-level
//! `var`s are constant candidates that hold only while no file assigns
//! to them, takes their address, or passes them by pointer (mutations
//! are recorded as `AssignmentTarget` references for `link` to read).
//!
//! Position policy (KTD7): gosyn's `Expression::pos()` panics on
//! `Expression::List` and `FieldList::pos()` panics on an empty list,
//! and `Call.pos` is the parenthesis, so every position goes through the
//! local [`expr_pos`]/[`expr_end`] helpers and [`Positions`].

use std::collections::{HashMap, HashSet};

use gosyn::ast::{self, Expression};
use gosyn::token::{LitKind, Operator};

use egress_core::ir::{
    BoundName, ConstructKind, DynamicConstruct, Expr, FileIr, Import, LineIndex, LocalBinding,
    ModuleConstant, Provenance, Reference, Root, Span, SymbolKind, SymbolSpan, UseKind,
};
use egress_core::model::{Language, Location};

use crate::positions::Positions;
use crate::prescan;

/// Nesting depth the lowering walk accepts before giving up on a file: a
/// second line of defense behind the prescans, sized above the deepest
/// shapes they admit (a full statement chain plus statement nesting).
pub const MAX_LOWER_DEPTH: u32 = prescan::MAX_STATEMENT_CHAIN as u32 + 8_192;

/// The start position of an expression in scalar offsets, never through
/// `Expression::pos()`.
fn expr_pos(e: &Expression) -> usize {
    match e {
        // `Call.pos` is the parenthesis; a call's site is its callee.
        Expression::Call(c) => expr_pos(&c.func),
        Expression::List(xs) => xs.first().map_or(0, expr_pos),
        Expression::Selector(s) => expr_pos(&s.x),
        Expression::TypeAssert(t) => expr_pos(&t.left),
        Expression::IndexList(l) => expr_pos(&l.left),
        Expression::Operation(o) => {
            if o.y.is_none() {
                o.pos
            } else {
                expr_pos(&o.x)
            }
        }
        other => other.pos(),
    }
}

/// The end position (one past the last scalar) of an expression.
fn expr_end(e: &Expression) -> usize {
    match e {
        Expression::Call(c) => c.pos.1 + 1,
        Expression::Index(i) => i.pos.1 + 1,
        Expression::IndexList(l) => l.pos.1 + 1,
        Expression::Slice(s) => s.pos.1 + 1,
        Expression::Ident(i) => i.pos + i.name.chars().count(),
        Expression::Selector(s) => s.sel.pos + s.sel.name.chars().count(),
        Expression::BasicLit(b) => b.pos + b.value.chars().count(),
        Expression::CompositeLit(l) => l.val.pos.1 + 1,
        Expression::FuncLit(l) => l.body.pos.1 + 1,
        Expression::Paren(p) => p.pos.1 + 1,
        Expression::Star(s) => expr_end(&s.right),
        Expression::Ellipsis(x) => x.elt.as_ref().map_or(x.pos + 3, |e| expr_end(e)),
        Expression::Range(r) => expr_end(&r.right),
        Expression::TypeAssert(t) => t.pos.1 + 1,
        Expression::List(xs) => xs.last().map_or(0, expr_end),
        Expression::Operation(o) => o.y.as_ref().map_or_else(|| expr_end(&o.x), |y| expr_end(y)),
        Expression::TypeMap(m) => expr_end(&m.val),
        Expression::TypeArray(a) => expr_end(&a.typ),
        Expression::TypeSlice(s) => expr_end(&s.typ),
        Expression::TypeChannel(c) => expr_end(&c.typ),
        Expression::TypePointer(p) => expr_end(&p.typ),
        Expression::TypeFunction(f) => field_list_end(&f.result)
            .or_else(|| field_list_end(&f.params))
            .unwrap_or(f.pos + 4),
        Expression::TypeStruct(s) => s.pos.1 + 1,
        Expression::TypeInterface(i) => field_list_end(&i.methods).unwrap_or(i.pos + 11),
    }
}

/// The end position of a field list without touching `FieldList::pos()`.
fn field_list_end(fl: &ast::FieldList) -> Option<usize> {
    if let Some((_, r)) = fl.pos {
        return Some(r + 1);
    }
    fl.list.last().map(|f| {
        f.tag
            .as_ref()
            .map_or_else(|| expr_end(&f.typ), |t| t.pos + t.value.chars().count())
    })
}

/// A selector chain `head.a.b.c` as its head ident and member list, or
/// the non-ident expression the chain is rooted at.
fn chain(e: &Expression) -> Result<(&ast::Ident, Vec<String>), &Expression> {
    let mut members = Vec::new();
    let mut cur = e;
    while let Expression::Selector(s) = cur {
        members.push(s.sel.name.clone());
        cur = &s.x;
    }
    members.reverse();
    match cur {
        Expression::Ident(i) => Ok((i, members)),
        other => Err(other),
    }
}

/// The expression a selector chain is rooted at, selectors peeled.
fn chain_base(e: &Expression) -> &Expression {
    let mut cur = e;
    while let Expression::Selector(s) = cur {
        cur = &s.x;
    }
    cur
}

/// The ident an expression is rooted at, through parens and selectors.
fn root_ident(e: &Expression) -> Option<&ast::Ident> {
    match e {
        Expression::Ident(i) => Some(i),
        Expression::Selector(s) => root_ident(&s.x),
        Expression::Paren(p) => root_ident(&p.expr),
        _ => None,
    }
}

/// Whether `s` is a `vN` major-version element or suffix.
fn is_major_version(s: &str) -> bool {
    s.len() > 1 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit())
}

/// Go's local-name rule for an unaliased import: the last path element,
/// skipping a final `vN` major-version element and dropping a `.vN`
/// suffix (`gopkg.in/yaml.v3` is `yaml`), then dropping a `go-` prefix
/// (`github.com/redis/go-redis/v9` is `redis`). `link` replaces a
/// first-party guess with the package clause it actually declares.
pub(crate) fn guessed_local(path: &str) -> String {
    let mut last = path.rsplit('/').next().unwrap_or(path);
    if is_major_version(last) {
        last = path.rsplit('/').nth(1).unwrap_or(last);
    }
    if let Some((stem, suffix)) = last.rsplit_once('.')
        && is_major_version(suffix)
    {
        last = stem;
    }
    last.strip_prefix("go-").unwrap_or(last).to_string()
}

/// The runtime value of a Go string or rune literal; raw strings keep
/// their bytes except `\r`, which Go discards.
fn unquote(lit: &str) -> String {
    match lit.chars().next() {
        Some('`') => lit[1..lit.len().saturating_sub(1)].replace('\r', ""),
        Some('"') | Some('\'') => {
            let inner = &lit[1..lit.len().saturating_sub(1)];
            unescape(inner).unwrap_or_else(|| inner.to_string())
        }
        _ => lit.to_string(),
    }
}

fn unescape(inner: &str) -> Option<String> {
    let mut out = String::new();
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next()? {
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0c'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\x0b'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            'x' => out.push(char::from_u32(hex(&mut it, 2)?)?),
            'u' => out.push(char::from_u32(hex(&mut it, 4)?)?),
            'U' => out.push(char::from_u32(hex(&mut it, 8)?)?),
            d @ '0'..='7' => {
                let mut v = d.to_digit(8)?;
                for _ in 0..2 {
                    v = v * 8 + it.next()?.to_digit(8)?;
                }
                out.push(char::from_u32(v)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

fn hex(it: &mut std::str::Chars, n: usize) -> Option<u32> {
    let mut v = 0u32;
    for _ in 0..n {
        v = v * 16 + it.next()?.to_digit(16)?;
    }
    Some(v)
}

/// Whether `e` mentions `iota` anywhere.
fn mentions_iota(e: &Expression) -> bool {
    match e {
        Expression::Ident(i) => i.name == "iota",
        Expression::Selector(s) => mentions_iota(&s.x),
        Expression::Call(c) => mentions_iota(&c.func) || c.args.iter().any(mentions_iota),
        Expression::Operation(o) => {
            mentions_iota(&o.x) || o.y.as_ref().is_some_and(|y| mentions_iota(y))
        }
        Expression::Paren(p) => mentions_iota(&p.expr),
        Expression::Index(i) => mentions_iota(&i.left) || mentions_iota(&i.index),
        Expression::IndexList(l) => mentions_iota(&l.left) || l.indices.iter().any(mentions_iota),
        Expression::List(xs) => xs.iter().any(mentions_iota),
        Expression::Star(s) => mentions_iota(&s.right),
        Expression::Slice(s) => {
            mentions_iota(&s.left) || s.index.iter().flatten().any(|e| mentions_iota(e))
        }
        Expression::CompositeLit(l) => mentions_iota(&l.typ) || lit_mentions_iota(&l.val),
        Expression::TypeAssert(t) => {
            mentions_iota(&t.left) || t.right.as_ref().is_some_and(|r| mentions_iota(r))
        }
        Expression::Range(r) => mentions_iota(&r.right),
        Expression::Ellipsis(x) => x.elt.as_ref().is_some_and(|e| mentions_iota(e)),
        _ => false,
    }
}

fn lit_mentions_iota(v: &ast::LiteralValue) -> bool {
    v.values.iter().any(|ke| {
        ke.key.as_ref().is_some_and(element_mentions_iota) || element_mentions_iota(&ke.val)
    })
}

fn element_mentions_iota(e: &ast::Element) -> bool {
    match e {
        ast::Element::Expr(x) => mentions_iota(x),
        ast::Element::LitValue(v) => lit_mentions_iota(v),
    }
}

/// The context a type expression sits in: whether the type's own value
/// is constructed (`Ctor`), whether it is the element of a container
/// whose elements are real (`Filled`), an ordinary type position
/// (`Plain`), or an embedded field (`Embed`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum TyCtx {
    /// `var x T` with no initializer, `new(T)`, a composite literal's or
    /// named field's or named result's type, an instantiation argument.
    Ctor,
    /// The element type of an array or of a `make`d slice.
    Filled,
    Plain,
    Embed,
}

impl TyCtx {
    /// The context for an array element under this one: arrays always
    /// hold real elements.
    fn array_elem(self) -> TyCtx {
        match self {
            TyCtx::Ctor | TyCtx::Filled => TyCtx::Filled,
            _ => TyCtx::Plain,
        }
    }

    /// The context for a slice element: real only when the slice itself
    /// was `make`d with elements.
    fn slice_elem(self) -> TyCtx {
        match self {
            TyCtx::Filled => TyCtx::Filled,
            _ => TyCtx::Plain,
        }
    }
}

/// What a name resolves to in expression position.
enum Head {
    /// An import's local name.
    Import(String),
    /// A binding or declaration in this file or package.
    Local(String),
    /// A parameter of the enclosing function, 1-based.
    Param(u32),
    /// Possibly bound by a dot (star) import.
    Ambient(String),
    /// Bound to a package-qualified type: the import local plus the
    /// type's member chain.
    Typed(String, Vec<String>),
}

/// What a `reflect.ValueOf`/`TypeOf` chain's innermost `v` reduces to:
/// its root, members, and the provenance the shared classifier reads.
type ReflectTarget = (Root, Vec<String>, Provenance);

/// What an expression shaped like a `reflect.Value` reduces to (KTD12).
enum ReflectChain {
    /// A live reflect value rooted at the innermost `v`'s target.
    Live(Root, Vec<String>, Provenance),
    /// The chain resolved to a named member: a literal name lookup.
    Resolved,
    /// Not a reflect chain.
    No,
}

/// One scope's bindings: block scopes and the file scope at index 0.
#[derive(Default)]
struct Scope {
    /// Names bound here (locals and, at index 0, every top-level
    /// declaration name).
    locals: HashSet<String>,
    /// Names bound to a package-qualified type chain (typed vars,
    /// typed params, named results, `type A = pkg.T` aliases).
    tracked: HashMap<String, (String, Vec<String>)>,
    /// Names bound to a `reflect.ValueOf`/`TypeOf` result.
    reflect: HashMap<String, ReflectTarget>,
    /// Names usable as a type (declared types, aliases, type parameters).
    types: HashSet<String>,
}

struct FnFrame {
    params: Vec<String>,
}

/// Predeclared names that are never references on their own.
const PREDECLARED: &[&str] = &[
    "any",
    "bool",
    "byte",
    "comparable",
    "complex64",
    "complex128",
    "error",
    "float32",
    "float64",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "rune",
    "string",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uintptr",
    "true",
    "false",
    "nil",
    "iota",
    "append",
    "cap",
    "clear",
    "close",
    "complex",
    "copy",
    "delete",
    "imag",
    "len",
    "make",
    "min",
    "max",
    "new",
    "panic",
    "print",
    "println",
    "recover",
];

/// The predeclared names that are types.
const BUILTIN_TYPES: &[&str] = &[
    "any",
    "bool",
    "byte",
    "comparable",
    "complex64",
    "complex128",
    "error",
    "float32",
    "float64",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "rune",
    "string",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uintptr",
];

pub struct Lowerer<'a> {
    src: &'a str,
    pos: Positions,
    lines: LineIndex<'a>,
    ir: FileIr,
    /// Scopes innermost-last, each with the symbol current when pushed.
    scopes: Vec<(Scope, String)>,
    symbols: Vec<String>,
    fns: Vec<FnFrame>,
    import_locals: HashSet<String>,
    /// Import locals that name the `reflect` package.
    reflect_locals: HashSet<String>,
    star: bool,
    blank_imports: u32,
    inits: u32,
    depth: u32,
    max_depth: u32,
    pub too_deep: bool,
    /// `let` candidates: (symbol, name, value, span).
    lets: Vec<(String, String, Expr, Span)>,
    bind_counts: HashMap<(String, String), u32>,
    reassigned: HashSet<(String, String)>,
    /// Names declared by a package-level `var`.
    pkg_vars: HashSet<String>,
    /// Package-level names assigned to, address-taken, or pointer-passed
    /// anywhere in the file.
    mutations: HashSet<String>,
    /// Package-level `var` initializer candidates: (name, value, span).
    candidates: Vec<(String, Expr, Span)>,
    /// Named method receivers: (symbol, name, span). They become
    /// opaque-valued local bindings after the `lets` so they shadow a
    /// package-level name without hiding a same-symbol `let`.
    receivers: Vec<(String, String, Span)>,
    /// Every name a popped scope bound, for `ir.bound_names`: a local
    /// binding suppresses the "unaliased import" flag a guessed name
    /// would otherwise earn in `link`.
    bound_names: Vec<BoundName>,
}

impl<'a> Lowerer<'a> {
    pub fn new(src: &'a str) -> Self {
        Lowerer {
            src,
            pos: Positions::new(src),
            lines: LineIndex::new(src),
            ir: FileIr::new(Language::Go),
            scopes: vec![(Scope::default(), "<module>".to_string())],
            symbols: Vec::new(),
            fns: Vec::new(),
            import_locals: HashSet::new(),
            reflect_locals: HashSet::new(),
            star: false,
            blank_imports: 0,
            inits: 0,
            depth: 0,
            max_depth: MAX_LOWER_DEPTH,
            too_deep: false,
            lets: Vec::new(),
            bind_counts: HashMap::new(),
            reassigned: HashSet::new(),
            pkg_vars: HashSet::new(),
            mutations: HashSet::new(),
            candidates: Vec::new(),
            receivers: Vec::new(),
            bound_names: Vec::new(),
        }
    }

    pub fn finish(mut self) -> FileIr {
        self.ir.bound_names = std::mem::take(&mut self.bound_names);
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
        // A package-level `var` initializer is a constant only while no
        // file assigns to it, takes its address, or passes it by
        // pointer; this file's mutations are filtered here and sibling
        // files' in `link` (the `AssignmentTarget` references below are
        // the per-file record it reads).
        for (name, value, span) in std::mem::take(&mut self.candidates) {
            if !self.mutations.contains(&name) {
                self.ir.locals.push(LocalBinding {
                    symbol: "<module>".to_string(),
                    name,
                    value,
                    span,
                });
            }
        }
        // A named receiver is a local binding with an opaque value: it
        // shadows a package-level name in every evaluation and never
        // supplies one itself. Appended last so a same-symbol `let`
        // wins `ix.local`'s first match.
        for (symbol, name, span) in std::mem::take(&mut self.receivers) {
            self.ir.locals.push(LocalBinding {
                symbol,
                value: Expr::Opaque(name.clone()),
                name,
                span,
            });
        }
        self.ir
    }

    // ---- positions ---------------------------------------------------

    fn span(&self, start: usize, end: usize) -> Span {
        Span {
            start: self.pos.byte_offset(start),
            end: self.pos.byte_offset(end),
        }
    }

    fn location(&self, start: usize) -> Location {
        self.lines.location(self.pos.byte_offset(start) as usize)
    }

    fn text_of(&self, start: usize, end: usize) -> String {
        let (b, e) = (self.pos.byte_offset(start), self.pos.byte_offset(end));
        self.src
            .get(b as usize..e as usize)
            .unwrap_or_default()
            .to_string()
    }

    fn ident_span(&self, id: &ast::Ident) -> Span {
        self.span(id.pos, id.pos + id.name.chars().count())
    }

    // ---- symbols -----------------------------------------------------

    fn symbol(&self) -> String {
        self.symbols
            .last()
            .cloned()
            .unwrap_or_else(|| "<module>".to_string())
    }

    fn child_symbol(&self, name: &str) -> String {
        match self.symbols.last() {
            Some(s) => format!("{s}.{name}"),
            None => name.to_string(),
        }
    }

    // ---- depth -------------------------------------------------------

    fn enter(&mut self) -> bool {
        self.depth += 1;
        if self.depth > self.max_depth {
            self.too_deep = true;
        }
        !self.too_deep
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Pops the innermost scope, recording every name it bound so
    /// `link` can tell a real local from a name that might be an
    /// unaliased import.
    fn pop_scope(&mut self) {
        if let Some((scope, symbol)) = self.scopes.pop() {
            for name in scope
                .locals
                .into_iter()
                .chain(scope.tracked.into_keys())
                .chain(scope.types)
            {
                self.bound_names.push(BoundName {
                    symbol: symbol.clone(),
                    name,
                });
            }
        }
    }

    // ---- names ---------------------------------------------------------

    fn head(&self, name: &str) -> Head {
        for (scope, _) in self.scopes.iter().rev() {
            if let Some((l, m)) = scope.tracked.get(name) {
                return Head::Typed(l.clone(), m.clone());
            }
            if scope.locals.contains(name) {
                return Head::Local(name.to_string());
            }
        }
        if let Some(i) = self.param_index(name) {
            return Head::Param(i);
        }
        if self.import_locals.contains(name) {
            return Head::Import(name.to_string());
        }
        if self.star {
            return Head::Ambient(name.to_string());
        }
        Head::Local(name.to_string())
    }

    /// The root and member chain a selector chain on `name` resolves to.
    fn resolve(&self, name: &str, members: Vec<String>) -> (Root, Vec<String>) {
        match self.head(name) {
            Head::Import(l) => (Root::Import(l), members),
            Head::Local(n) => (Root::Local(n), members),
            Head::Param(i) => (Root::Param(i), members),
            Head::Ambient(n) => (Root::Ambient(n), members),
            Head::Typed(l, mut ty) => {
                ty.extend(members);
                (Root::Import(l), ty)
            }
        }
    }

    /// `name`'s index among the enclosing function's parameters, when it
    /// is a parameter that no binding in scope shadows.
    fn param_index(&self, name: &str) -> Option<u32> {
        let frame = self.fns.last()?;
        if self.scopes.iter().any(|(s, _)| s.locals.contains(name)) {
            return None;
        }
        frame
            .params
            .iter()
            .position(|p| p == name)
            .and_then(|i| u32::try_from(i + 1).ok())
    }

    /// A predeclared name that nothing in the file rebinds.
    fn builtin(&self, name: &str) -> bool {
        PREDECLARED.contains(&name)
            && !self
                .scopes
                .iter()
                .any(|(s, _)| s.locals.contains(name) || s.tracked.contains_key(name))
            && !self
                .fns
                .last()
                .is_some_and(|f| f.params.iter().any(|p| p == name))
            && !self.import_locals.contains(name)
    }

    /// Whether `name` can appear where a type is expected (a declared
    /// type, alias, type parameter, or builtin type).
    fn is_type_name(&self, name: &str) -> bool {
        BUILTIN_TYPES.contains(&name) || self.scopes.iter().any(|(s, _)| s.types.contains(name))
    }

    /// Whether `e` looks like a type expression, settling the `f[T]`
    /// versus `s[i]` ambiguity: a package-qualified selector, a name
    /// usable as a type, or a composite type.
    fn is_type_expr(&self, e: &Expression) -> bool {
        match e {
            Expression::Ident(i) => self.is_type_name(&i.name),
            Expression::Selector(_) => {
                matches!(chain(e), Ok((id, _)) if self.import_locals.contains(&id.name))
            }
            Expression::Index(i) => self.is_type_expr(&i.left),
            Expression::IndexList(l) => self.is_type_expr(&l.left),
            Expression::Paren(p) => self.is_type_expr(&p.expr),
            Expression::Star(s) => self.is_type_expr(&s.right),
            Expression::Operation(o) if o.y.is_none() => {
                matches!(o.op, Operator::Tiled) || self.is_type_expr(&o.x)
            }
            Expression::TypeArray(_)
            | Expression::TypeSlice(_)
            | Expression::TypeMap(_)
            | Expression::TypeChannel(_)
            | Expression::TypeFunction(_)
            | Expression::TypeStruct(_)
            | Expression::TypeInterface(_)
            | Expression::TypePointer(_) => true,
            _ => false,
        }
    }

    // ---- emission ------------------------------------------------------

    fn reference(
        &self,
        root: Root,
        members: Vec<String>,
        use_kind: UseKind,
        args: Vec<Expr>,
        start: usize,
        end: usize,
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
            text: self.text_of(start, end),
            symbol: self.symbol(),
            span: self.span(start, end),
            location: self.location(start),
        }
    }

    fn emit(&mut self, r: Reference) {
        self.ir.references.push(r);
    }

    fn construct(&mut self, kind: ConstructKind, start: usize, end: usize) {
        self.ir.constructs.push(DynamicConstruct {
            kind,
            text: self.text_of(start, end),
            symbol: self.symbol(),
            span: self.span(start, end),
            location: self.location(start),
        });
    }

    // ---- file ---------------------------------------------------------

    /// Emits one construct per `//go:linkname` and `//go:generate`
    /// directive [`crate::directives`] collected: every directive is a
    /// module-level construct, so this runs before [`file`](Self::file)
    /// while the symbol is `<module>`.
    pub fn directives(&mut self, linkname: &[(usize, usize)], generate: &[(usize, usize)]) {
        for &(start, end) in linkname {
            self.construct(ConstructKind::NativeCode, start, end);
        }
        for &(start, end) in generate {
            self.construct(ConstructKind::BuildHook, start, end);
        }
    }

    pub fn file(&mut self, f: &ast::File) {
        for imp in &f.imports {
            self.import(imp);
        }
        // Names are order-independent at package scope, so top-level
        // declarations (and the var types and aliases they track) are
        // collected before the walk.
        for d in &f.decl {
            self.collect(d);
        }
        for d in &f.decl {
            self.decl(d);
            if self.too_deep {
                return;
            }
        }
    }

    fn import(&mut self, imp: &ast::Import) {
        let specifier = unquote(&imp.path.value);
        let start = imp.name.as_ref().map_or(imp.path.pos, |n| n.pos);
        let end = imp.path.pos + imp.path.value.chars().count();
        let (local, star, blank) = match &imp.name {
            Some(n) if n.name == "." => (None, true, false),
            Some(n) if n.name == "_" => {
                self.blank_imports += 1;
                (Some(format!("_#{}", self.blank_imports)), false, true)
            }
            Some(n) => (Some(n.name.clone()), false, false),
            None => (Some(guessed_local(&specifier)), false, false),
        };
        if specifier == "C" {
            // The cgo pseudo-package (KTD12): one native-code construct
            // at the import. The record stays so `C.` selectors resolve
            // import-rooted; `type_only` marks a binding the resolver
            // does not follow, so the import is neither standard
            // library, unresolved, nor a dependency, and no `C.name` is
            // a site. The preamble comment above it is never code.
            if !star
                && !blank
                && let Some(l) = &local
            {
                self.import_locals.insert(l.clone());
            }
            self.ir.imports.push(Import {
                local,
                specifier,
                members: Vec::new(),
                type_only: true,
                star,
                re_export: false,
                default: false,
                symbol: "<module>".to_string(),
                span: self.span(start, end),
                location: self.location(start),
            });
            self.construct(ConstructKind::NativeCode, start, end);
            return;
        }
        if star {
            self.star = true;
        } else if !blank && let Some(l) = &local {
            self.import_locals.insert(l.clone());
            if specifier == "reflect" {
                self.reflect_locals.insert(l.clone());
            }
        }
        self.ir.imports.push(Import {
            local: local.clone(),
            specifier: specifier.clone(),
            members: Vec::new(),
            type_only: false,
            star,
            re_export: false,
            default: false,
            symbol: "<module>".to_string(),
            span: self.span(start, end),
            location: self.location(start),
        });
        if blank {
            // A blank import is a value use of the whole package at the
            // import position: the core lists a non-inert package and
            // yields nothing for an inert one.
            let r = self.reference(
                Root::Import(local.unwrap_or_default()),
                Vec::new(),
                UseKind::ValueEscape,
                Vec::new(),
                start,
                end,
            );
            self.emit(r);
        }
    }

    /// Registers the names a top-level declaration binds, before the
    /// walk (Go declarations are order-independent across a file).
    fn collect(&mut self, d: &ast::Declaration) {
        match d {
            ast::Declaration::Function(fd) => {
                if fd.recv.is_none() {
                    let (scope, _) = &mut self.scopes[0];
                    scope.locals.insert(fd.name.name.clone());
                }
            }
            ast::Declaration::Type(dd) => {
                for spec in &dd.specs {
                    let chain = if spec.alias {
                        self.leaf_chain(&spec.typ)
                    } else {
                        None
                    };
                    let (scope, _) = &mut self.scopes[0];
                    scope.locals.insert(spec.name.name.clone());
                    scope.types.insert(spec.name.name.clone());
                    if let Some(ch) = chain {
                        let (scope, _) = &mut self.scopes[0];
                        scope.tracked.insert(spec.name.name.clone(), ch);
                    }
                }
            }
            ast::Declaration::Const(dd) => {
                for spec in &dd.specs {
                    for n in &spec.name {
                        let (scope, _) = &mut self.scopes[0];
                        scope.locals.insert(n.name.clone());
                    }
                }
            }
            ast::Declaration::Variable(dd) => {
                for spec in &dd.specs {
                    for (i, n) in spec.name.iter().enumerate() {
                        if n.name == "_" {
                            continue;
                        }
                        let (scope, _) = &mut self.scopes[0];
                        scope.locals.insert(n.name.clone());
                        self.pkg_vars.insert(n.name.clone());
                        let chain =
                            spec.typ
                                .as_ref()
                                .and_then(|t| self.leaf_chain(t))
                                .or_else(|| {
                                    let value = match spec.values.len() {
                                        k if k == spec.name.len() => spec.values.get(i),
                                        1 => spec.values.first(),
                                        _ => None,
                                    };
                                    value.and_then(|v| self.infer_chain(v))
                                });
                        if let Some(ch) = chain {
                            let (scope, _) = &mut self.scopes[0];
                            scope.tracked.insert(n.name.clone(), ch);
                        }
                    }
                }
            }
        }
    }

    // ---- declarations ---------------------------------------------------

    fn decl(&mut self, d: &ast::Declaration) {
        if !self.enter() {
            return;
        }
        match d {
            ast::Declaration::Function(fd) => self.func_decl(fd),
            ast::Declaration::Type(dd) => self.type_decl(dd),
            ast::Declaration::Const(dd) => self.const_decl(dd, true),
            ast::Declaration::Variable(dd) => self.var_decl(dd, true),
        }
        self.leave();
    }

    fn type_decl(&mut self, dd: &ast::Decl<ast::TypeSpec>) {
        for spec in &dd.specs {
            let idx = self.scopes.len() - 1;
            {
                let (scope, _) = &mut self.scopes[idx];
                scope.locals.insert(spec.name.name.clone());
                scope.types.insert(spec.name.name.clone());
            }
            // A top-level `type` declaration is a package-scope name the
            // package index must see (a `pkg.T` member binds to the file
            // declaring it, KTD8).
            if self.symbols.is_empty() {
                self.ir.symbols.push(SymbolSpan {
                    path: spec.name.name.clone(),
                    kind: SymbolKind::Class,
                    params: Vec::new(),
                    defaults: Default::default(),
                    strict: None,
                    span: self.ident_span(&spec.name),
                });
            }
            // Type parameters are scoped to the declaration.
            self.scopes.push((Scope::default(), self.symbol()));
            for f in &spec.params.list {
                self.ty(&f.typ, TyCtx::Plain);
                for n in &f.name {
                    let (scope, _) = self.scopes.last_mut().unwrap();
                    scope.types.insert(n.name.clone());
                }
            }
            self.ty(&spec.typ, TyCtx::Plain);
            self.pop_scope();
            if spec.alias
                && let Some(ch) = self.leaf_chain(&spec.typ)
            {
                let (scope, _) = &mut self.scopes[idx];
                scope.tracked.insert(spec.name.name.clone(), ch);
            }
        }
    }

    fn var_decl(&mut self, dd: &ast::Decl<ast::VarSpec>, top: bool) {
        for spec in &dd.specs {
            let init = !spec.values.is_empty();
            // A `var x T` with no initializer zero-values T: a Construct
            // site for a package-qualified value type. With an
            // initializer the type is an ordinary position.
            let chain: Option<(String, Vec<String>)> = spec.typ.as_ref().and_then(|t| {
                self.ty(t, if init { TyCtx::Plain } else { TyCtx::Ctor });
                self.leaf_chain(t)
            });
            for (i, id) in spec.name.iter().enumerate() {
                let value = match spec.values.len() {
                    n if n == spec.name.len() => spec.values.get(i),
                    1 => spec.values.first(),
                    _ => None,
                };
                if id.name == "_" {
                    continue;
                }
                let tracked = chain
                    .clone()
                    .or_else(|| value.and_then(|v| self.infer_chain(v)));
                let lowered = if !init && let Some((l, m)) = &tracked {
                    let r = self.reference(
                        Root::Import(l.clone()),
                        m.clone(),
                        UseKind::Construct,
                        Vec::new(),
                        expr_pos(spec.typ.as_ref().unwrap()),
                        expr_end(spec.typ.as_ref().unwrap()),
                    );
                    Expr::Reference(Box::new(r))
                } else {
                    value
                        .map(|v| self.lower_expr(v, 0))
                        .unwrap_or_else(|| Expr::Opaque(id.name.clone()))
                };
                // A binding to a `reflect.ValueOf`/`TypeOf` result, as in
                // `bind`.
                let reflect = value
                    .and_then(|v| self.reflect_arg(v))
                    .map(|v| self.reflect_target(v));
                let span = self.ident_span(id);
                if top {
                    self.candidates.push((id.name.clone(), lowered, span));
                    let (scope, _) = &mut self.scopes[0];
                    if let Some(ch) = tracked {
                        scope.tracked.insert(id.name.clone(), ch);
                    }
                    match reflect {
                        Some(t) => {
                            scope.reflect.insert(id.name.clone(), t);
                        }
                        None => {
                            scope.reflect.remove(&id.name);
                        }
                    }
                } else {
                    self.note_binding(&id.name);
                    {
                        let (scope, _) = self.scopes.last_mut().unwrap();
                        scope.locals.insert(id.name.clone());
                        match reflect {
                            Some(t) => {
                                scope.reflect.insert(id.name.clone(), t);
                            }
                            None => {
                                scope.reflect.remove(&id.name);
                            }
                        }
                    }
                    if let Some(ch) = tracked {
                        let (scope, _) = self.scopes.last_mut().unwrap();
                        scope.tracked.insert(id.name.clone(), ch);
                    }
                    self.lets
                        .push((self.symbol(), id.name.clone(), lowered, span));
                }
            }
            for v in &spec.values {
                self.expr(v);
            }
        }
    }

    fn const_decl(&mut self, dd: &ast::Decl<ast::ConstSpec>, top: bool) {
        // A spec with no values repeats the previous spec's expression,
        // unless that expression mentions `iota`, in which case it is
        // opaque (the counter is not guessed).
        let mut prev: Option<(Vec<Expr>, bool)> = None;
        for spec in &dd.specs {
            if let Some(t) = &spec.typ {
                self.ty(t, TyCtx::Plain);
            }
            let (vals, opaque_repeat) = if spec.values.is_empty() {
                match &prev {
                    Some((v, i)) => (v.clone(), *i),
                    None => (Vec::new(), false),
                }
            } else {
                (
                    spec.values
                        .iter()
                        .map(|v| self.lower_expr(v, 0))
                        .collect::<Vec<Expr>>(),
                    false,
                )
            };
            for (i, id) in spec.name.iter().enumerate() {
                if id.name == "_" {
                    continue;
                }
                let value = if opaque_repeat {
                    Expr::Opaque("iota".to_string())
                } else {
                    match vals.len() {
                        n if n == spec.name.len() => vals.get(i).cloned(),
                        1 => vals.first().cloned(),
                        _ => None,
                    }
                    .unwrap_or_else(|| Expr::Opaque(id.name.clone()))
                };
                if top {
                    let exported = id.name.chars().next().is_some_and(char::is_uppercase);
                    self.ir.constants.push(ModuleConstant {
                        name: id.name.clone(),
                        value,
                        exported,
                        span: self.ident_span(id),
                    });
                } else {
                    self.note_binding(&id.name);
                    {
                        let (scope, _) = self.scopes.last_mut().unwrap();
                        scope.locals.insert(id.name.clone());
                    }
                    self.lets
                        .push((self.symbol(), id.name.clone(), value, self.ident_span(id)));
                }
            }
            for v in &spec.values {
                self.expr(v);
            }
            prev = Some((vals, spec.values.iter().any(mentions_iota)));
        }
    }

    fn func_decl(&mut self, d: &ast::FuncDecl) {
        let recv_name = d
            .recv
            .as_ref()
            .and_then(|r| r.list.first())
            .and_then(|f| recv_type_name(&f.typ));
        let (sym, kind) = match &recv_name {
            Some(t) => (format!("{}.{}", t, d.name.name), SymbolKind::Method),
            None => {
                if d.name.name == "init" {
                    self.inits += 1;
                    (
                        if self.inits == 1 {
                            "init".to_string()
                        } else {
                            format!("init#{}", self.inits)
                        },
                        SymbolKind::Function,
                    )
                } else {
                    (self.child_symbol(&d.name.name), SymbolKind::Function)
                }
            }
        };
        let params = param_names(&d.typ);
        self.ir.symbols.push(SymbolSpan {
            path: sym.clone(),
            kind,
            params: params.clone(),
            defaults: Default::default(),
            strict: None,
            span: self.ident_span(&d.name),
        });
        self.symbols.push(sym);
        self.fns.push(FnFrame { params });
        self.scopes.push((Scope::default(), self.symbol()));
        if let Some(r) = &d.recv {
            for f in &r.list {
                self.ty(&f.typ, TyCtx::Plain);
                for n in &f.name {
                    if n.name != "_" {
                        let (scope, _) = self.scopes.last_mut().unwrap();
                        scope.locals.insert(n.name.clone());
                        self.receivers
                            .push((self.symbol(), n.name.clone(), self.ident_span(n)));
                    }
                }
            }
        }
        self.signature(&d.typ);
        if let Some(b) = &d.body {
            self.block(b);
        }
        self.pop_scope();
        self.fns.pop();
        self.symbols.pop();
    }

    fn signature(&mut self, t: &ast::FuncType) {
        for f in &t.typ_params.list {
            self.ty(&f.typ, TyCtx::Plain);
            for n in &f.name {
                let (scope, _) = self.scopes.last_mut().unwrap();
                scope.types.insert(n.name.clone());
            }
        }
        for f in &t.params.list {
            self.ty(&f.typ, TyCtx::Plain);
            if let Some(ch) = self.leaf_chain(&f.typ) {
                for n in &f.name {
                    if n.name != "_" {
                        let (scope, _) = self.scopes.last_mut().unwrap();
                        scope.tracked.insert(n.name.clone(), ch.clone());
                    }
                }
            }
        }
        for f in &t.result.list {
            if f.name.is_empty() {
                self.ty(&f.typ, TyCtx::Plain);
                continue;
            }
            // A named result is declared and receives a value: its type
            // is a value-carrying position.
            self.ty(&f.typ, TyCtx::Ctor);
            let ch = self.leaf_chain(&f.typ);
            for n in &f.name {
                if n.name == "_" {
                    continue;
                }
                self.note_binding(&n.name);
                let value = match &ch {
                    Some((l, m)) => Expr::Reference(Box::new(self.reference(
                        Root::Import(l.clone()),
                        m.clone(),
                        UseKind::Construct,
                        Vec::new(),
                        n.pos,
                        n.pos + n.name.chars().count(),
                    ))),
                    None => Expr::Opaque(n.name.clone()),
                };
                {
                    let (scope, _) = self.scopes.last_mut().unwrap();
                    scope.locals.insert(n.name.clone());
                }
                if let Some(ch) = &ch {
                    let (scope, _) = self.scopes.last_mut().unwrap();
                    scope.tracked.insert(n.name.clone(), ch.clone());
                }
                self.lets
                    .push((self.symbol(), n.name.clone(), value, self.ident_span(n)));
            }
        }
    }

    /// The `Root::Import` local plus member chain a type expression's
    /// leaf resolves to (stars and parens stripped), for var and
    /// initializer tracking.
    fn leaf_chain(&self, e: &Expression) -> Option<(String, Vec<String>)> {
        match e {
            Expression::Paren(p) => self.leaf_chain(&p.expr),
            Expression::Star(s) => self.leaf_chain(&s.right),
            Expression::TypePointer(p) => self.leaf_chain(&p.typ),
            Expression::Ident(i) => match self.head(&i.name) {
                Head::Typed(l, m) => Some((l, m)),
                _ => None,
            },
            Expression::Selector(_) => match chain(e) {
                Ok((id, members)) => match self.head(&id.name) {
                    Head::Import(l) => Some((l, members)),
                    Head::Typed(l, mut tm) => {
                        tm.extend(members);
                        Some((l, tm))
                    }
                    _ => None,
                },
                Err(_) => None,
            },
            Expression::Index(i) => self.leaf_chain(&i.left),
            Expression::IndexList(l) => self.leaf_chain(&l.left),
            _ => None,
        }
    }

    /// The package-qualified type chain a `:=` or `var` initializer
    /// implies, for the construct-shaped forms only: a composite
    /// literal, `&` of one, or `new(T)`.
    fn infer_chain(&self, e: &Expression) -> Option<(String, Vec<String>)> {
        match e {
            Expression::CompositeLit(l) => self.leaf_chain(&l.typ),
            Expression::Paren(p) => self.infer_chain(&p.expr),
            Expression::Operation(o) if o.y.is_none() && o.op == Operator::And => {
                self.infer_chain(&o.x)
            }
            Expression::Call(c) => {
                if let Expression::Ident(f) = &*c.func
                    && f.name == "new"
                    && self.builtin("new")
                {
                    return c.args.first().and_then(|t| self.leaf_chain(t));
                }
                None
            }
            _ => None,
        }
    }

    // ---- type expressions ----------------------------------------------

    /// Walks a type expression, emitting per its context: `Ctor` and
    /// `Filled` produce `Construct` references at package-qualified
    /// value types, `Plain` type positions, `Embed` value uses.
    fn ty(&mut self, e: &Expression, ctx: TyCtx) {
        if !self.enter() {
            return;
        }
        match e {
            Expression::Paren(p) => self.ty(&p.expr, ctx),
            Expression::Star(s) => self.ty(&s.right, ctx),
            Expression::Ellipsis(x) => {
                if let Some(t) = &x.elt {
                    self.ty(t, ctx);
                }
            }
            Expression::TypePointer(p) => self.ty(
                &p.typ,
                if ctx == TyCtx::Embed {
                    TyCtx::Embed
                } else {
                    TyCtx::Plain
                },
            ),
            Expression::TypeArray(t) => {
                self.expr(&t.len);
                self.ty(&t.typ, ctx.array_elem());
            }
            Expression::TypeSlice(t) => self.ty(&t.typ, ctx.slice_elem()),
            Expression::TypeMap(t) => {
                self.ty(&t.key, TyCtx::Plain);
                self.ty(&t.val, TyCtx::Plain);
            }
            Expression::TypeChannel(t) => self.ty(&t.typ, TyCtx::Plain),
            Expression::TypeFunction(t) => {
                for f in t
                    .typ_params
                    .list
                    .iter()
                    .chain(t.params.list.iter())
                    .chain(t.result.list.iter())
                {
                    self.ty(&f.typ, TyCtx::Plain);
                }
            }
            Expression::TypeStruct(s) => {
                for f in &s.fields {
                    // An embedded field is a value use of the type; a
                    // named field type is a value-carrying position.
                    self.ty(
                        &f.typ,
                        if f.name.is_empty() {
                            TyCtx::Embed
                        } else {
                            TyCtx::Ctor
                        },
                    );
                }
            }
            Expression::TypeInterface(i) => {
                for f in &i.methods.list {
                    self.ty(&f.typ, TyCtx::Plain);
                }
            }
            Expression::Index(i) => {
                self.ty_leaf(&i.left, ctx);
                self.ty(&i.index, TyCtx::Ctor);
            }
            Expression::IndexList(l) => {
                self.ty_leaf(&l.left, ctx);
                for i in &l.indices {
                    self.ty(i, TyCtx::Ctor);
                }
            }
            Expression::Ident(_) | Expression::Selector(_) => {
                self.ty_leaf(e, ctx);
            }
            Expression::Operation(o) => {
                self.ty(&o.x, ctx);
                if let Some(y) = &o.y {
                    self.ty(y, ctx);
                }
            }
            _ => {}
        }
        self.leave();
    }

    /// A type-expression leaf (`pkg.T`, an alias), emitting a reference
    /// when it resolves to an import. Returns the resolved chain.
    fn ty_leaf(&mut self, e: &Expression, ctx: TyCtx) -> Option<(String, Vec<String>)> {
        let (l, members) = match e {
            Expression::Ident(i) => match self.head(&i.name) {
                Head::Typed(l, m) => (l, m),
                _ => return None,
            },
            _ => match chain(e) {
                Ok((id, members)) => match self.head(&id.name) {
                    Head::Import(l) => (l, members),
                    Head::Typed(l, mut tm) => {
                        tm.extend(members);
                        (l, tm)
                    }
                    _ => return None,
                },
                Err(_) => return None,
            },
        };
        let kind = match ctx {
            TyCtx::Ctor | TyCtx::Filled => UseKind::Construct,
            TyCtx::Plain => UseKind::TypePosition,
            TyCtx::Embed => UseKind::ValueEscape,
        };
        let (start, end) = (expr_pos(e), expr_end(e));
        let r = self.reference(
            Root::Import(l.clone()),
            members.clone(),
            kind,
            Vec::new(),
            start,
            end,
        );
        self.emit(r);
        Some((l, members))
    }

    // ---- statements -------------------------------------------------------

    fn block(&mut self, b: &ast::BlockStmt) {
        if !self.enter() {
            return;
        }
        self.scopes.push((Scope::default(), self.symbol()));
        for s in &b.list {
            self.stmt(s);
            if self.too_deep {
                break;
            }
        }
        self.pop_scope();
        self.leave();
    }

    fn stmt(&mut self, s: &ast::Statement) {
        if !self.enter() {
            return;
        }
        match s {
            ast::Statement::Block(b) => self.block(b),
            ast::Statement::Expr(e) => self.expr(&e.expr),
            ast::Statement::Return(r) => {
                for e in &r.ret {
                    self.expr(e);
                }
            }
            ast::Statement::Go(g) => self.call(&g.call),
            ast::Statement::Defer(d) => self.call(&d.call),
            ast::Statement::Assign(a) => self.assign(a),
            ast::Statement::IncDec(i) => self.mutate_target(&i.expr),
            ast::Statement::Send(s) => {
                self.expr(&s.chan);
                self.expr(&s.value);
            }
            ast::Statement::Declaration(d) => match d {
                ast::DeclStmt::Variable(dd) => self.var_decl(dd, false),
                ast::DeclStmt::Const(dd) => self.const_decl(dd, false),
                ast::DeclStmt::Type(dd) => self.type_decl(dd),
            },
            ast::Statement::If(i) => {
                self.scopes.push((Scope::default(), self.symbol()));
                if let Some(init) = &i.init {
                    self.stmt(init);
                }
                self.expr(&i.cond);
                self.block(&i.body);
                if let Some(e) = &i.else_ {
                    self.stmt(e);
                }
                self.pop_scope();
            }
            ast::Statement::For(f) => {
                self.scopes.push((Scope::default(), self.symbol()));
                if let Some(init) = &f.init {
                    self.stmt(init);
                }
                if let Some(cond) = &f.cond {
                    self.stmt(cond);
                }
                if let Some(post) = &f.post {
                    self.stmt(post);
                }
                self.block(&f.body);
                self.pop_scope();
            }
            ast::Statement::Range(r) => {
                self.scopes.push((Scope::default(), self.symbol()));
                self.expr(&r.expr);
                match &r.op {
                    Some((_, Operator::Define)) => {
                        for e in [&r.key, &r.value].into_iter().flatten() {
                            match e {
                                Expression::Ident(id) => self.bind(id, None),
                                other => self.expr(other),
                            }
                        }
                    }
                    Some(_) => {
                        for e in [&r.key, &r.value].into_iter().flatten() {
                            self.assign_target(e);
                        }
                    }
                    None => {}
                }
                self.block(&r.body);
                self.pop_scope();
            }
            ast::Statement::Switch(s) => {
                self.scopes.push((Scope::default(), self.symbol()));
                if let Some(init) = &s.init {
                    self.stmt(init);
                }
                if let Some(tag) = &s.tag {
                    self.expr(tag);
                }
                for c in &s.block.body {
                    for e in &c.list {
                        self.expr(e);
                    }
                    for st in c.body.iter() {
                        self.stmt(st);
                    }
                }
                self.pop_scope();
            }
            ast::Statement::TypeSwitch(s) => {
                self.scopes.push((Scope::default(), self.symbol()));
                if let Some(init) = &s.init {
                    self.stmt(init);
                }
                if let Some(tag) = &s.tag {
                    self.stmt(tag);
                }
                for c in &s.block.body {
                    for e in &c.list {
                        self.ty(e, TyCtx::Plain);
                    }
                    for st in c.body.iter() {
                        self.stmt(st);
                    }
                }
                self.pop_scope();
            }
            ast::Statement::Select(s) => {
                self.scopes.push((Scope::default(), self.symbol()));
                for c in &s.body.body {
                    if let Some(comm) = &c.comm {
                        self.stmt(comm);
                    }
                    for st in c.body.iter() {
                        self.stmt(st);
                    }
                }
                self.pop_scope();
            }
            ast::Statement::Label(l) => self.stmt(&l.stmt),
            ast::Statement::Branch(_) | ast::Statement::Empty(_) => {}
        }
        self.leave();
    }

    fn assign(&mut self, a: &ast::AssignStmt) {
        if a.is_range() {
            // `for k, v := range x` may arrive as an AssignStmt.
            if let Some(Expression::Range(r)) = a.right.first() {
                self.expr(&r.right);
            }
            for l in &a.left {
                match l {
                    Expression::Ident(id) if a.op == Operator::Define => self.bind(id, None),
                    other => self.assign_target(other),
                }
            }
            return;
        }
        for (i, l) in a.left.iter().enumerate() {
            match (&a.op, l) {
                (Operator::Define, Expression::Ident(id)) => {
                    let value = match a.right.len() {
                        n if n == a.left.len() => a.right.get(i),
                        1 => a.right.first(),
                        _ => None,
                    };
                    self.bind(id, value);
                }
                _ => self.assign_target(l),
            }
        }
        for r in &a.right {
            self.expr(r);
        }
    }

    /// A `:=`, `var`, `const`, `range`, or named-result binding under the
    /// single-assignment rule.
    fn bind(&mut self, id: &ast::Ident, value: Option<&Expression>) {
        if id.name == "_" {
            return;
        }
        self.note_binding(&id.name);
        let lowered = value
            .map(|v| self.lower_expr(v, 0))
            .unwrap_or_else(|| Expr::Opaque(id.name.clone()));
        let span = self.ident_span(id);
        self.lets
            .push((self.symbol(), id.name.clone(), lowered, span));
        // A local bound to a `reflect.ValueOf`/`TypeOf` result: later
        // name lookups and dispatches on it are computed members (KTD12).
        let reflect = value
            .and_then(|v| self.reflect_arg(v))
            .map(|v| self.reflect_target(v));
        {
            let (scope, _) = self.scopes.last_mut().unwrap();
            scope.locals.insert(id.name.clone());
            match reflect {
                Some(t) => {
                    scope.reflect.insert(id.name.clone(), t);
                }
                None => {
                    scope.reflect.remove(&id.name);
                }
            }
        }
        if let Some(ch) = value.and_then(|v| self.infer_chain(v)) {
            let (scope, _) = self.scopes.last_mut().unwrap();
            scope.tracked.insert(id.name.clone(), ch);
        }
    }

    fn note_binding(&mut self, name: &str) {
        *self
            .bind_counts
            .entry((self.symbol(), name.to_string()))
            .or_default() += 1;
    }

    /// An assignment or `++`/`--` target: a local stops being
    /// single-assignment; a package-level `var` stops being a constant
    /// candidate and its mutation is recorded for `link`.
    fn mutate_target(&mut self, e: &Expression) {
        match e {
            Expression::Ident(id) => self.mark_assigned(&id.name, e),
            Expression::Paren(p) => self.mutate_target(&p.expr),
            _ => self.expr(e),
        }
    }

    /// Whether `name` names a package-level binding for this file: bound
    /// nowhere above the file scope, or bound at file scope itself.
    /// Params and import locals are never package names.
    fn package_target(&self, name: &str) -> bool {
        for (i, (s, _)) in self.scopes.iter().enumerate() {
            if s.locals.contains(name) {
                return i == 0;
            }
        }
        !self
            .fns
            .last()
            .is_some_and(|f| f.params.iter().any(|p| p == name))
            && !self.import_locals.contains(name)
    }

    /// The `AssignmentTarget` marker `link` reads to retire a
    /// package-level `var` candidate, including a sibling file's.
    fn mutation_marker(&mut self, name: &str, e: &Expression) {
        self.mutations.insert(name.to_string());
        let (start, end) = (expr_pos(e), expr_end(e));
        let r = self.reference(
            Root::Local(name.to_string()),
            Vec::new(),
            UseKind::AssignmentTarget,
            Vec::new(),
            start,
            end,
        );
        self.emit(r);
    }

    fn mark_assigned(&mut self, name: &str, e: &Expression) {
        let mut reassigned = None;
        for (i, (s, sym)) in self.scopes.iter().enumerate().rev() {
            if s.locals.contains(name) {
                if i != 0 {
                    reassigned = Some((i, sym.clone()));
                }
                break;
            }
        }
        if let Some((i, sym)) = reassigned {
            self.reassigned.insert((sym, name.to_string()));
            // A reassigned name no longer holds a reflect binding.
            self.scopes[i].0.reflect.remove(name);
            return;
        }
        // The name binds only at file scope or nowhere here: the write
        // targets a package-level name, possibly declared in a sibling
        // file, and `link` decides whether it retires a candidate.
        if self.package_target(name) {
            self.mutation_marker(name, e);
        }
    }

    /// `&x` or `&x.f` on a package-level `var`: the address escapes, so
    /// the constant candidacy ends (a `-ldflags -X` rewrite or a
    /// `flag.StringVar` bind can change the value without a source
    /// assignment). The name may be declared in a sibling file.
    fn mark_address_taken(&mut self, e: &Expression) {
        let Some(id) = root_ident(e) else {
            return;
        };
        if self.package_target(&id.name) {
            self.mutation_marker(&id.name, e);
        }
    }

    fn assign_target(&mut self, l: &Expression) {
        match l {
            Expression::Ident(id) => self.mark_assigned(&id.name, l),
            Expression::Selector(_) => match chain(l) {
                Ok((id, members)) if self.import_locals.contains(&id.name) => {
                    // A write to a module member, kept for the
                    // monkeypatch rule.
                    let (start, end) = (expr_pos(l), expr_end(l));
                    let r = self.reference(
                        Root::Import(id.name.clone()),
                        members,
                        UseKind::AssignmentTarget,
                        Vec::new(),
                        start,
                        end,
                    );
                    self.emit(r);
                }
                Ok(_) => {
                    // A field write on a local or tracked value: only
                    // the base reads anything.
                    let base = chain_base(l);
                    self.expr(base);
                }
                Err(base) => self.expr(base),
            },
            Expression::Index(i) => {
                self.expr(&i.left);
                self.expr(&i.index);
            }
            Expression::IndexList(l) => {
                self.expr(&l.left);
                for i in &l.indices {
                    self.expr(i);
                }
            }
            Expression::Star(s) => self.expr(&s.right),
            Expression::Paren(p) => self.assign_target(&p.expr),
            Expression::TypeAssert(t) => self.expr(&t.left),
            Expression::List(xs) => {
                for x in xs {
                    self.assign_target(x);
                }
            }
            other => self.expr(other),
        }
    }

    // ---- expressions ------------------------------------------------------

    fn expr(&mut self, e: &Expression) {
        if !self.enter() {
            return;
        }
        match e {
            Expression::Call(c) => self.call(c),
            Expression::CompositeLit(l) => self.composite_lit(l),
            Expression::FuncLit(l) => self.func_lit(l),
            Expression::Selector(_) => self.value_chain(e),
            Expression::Ident(id) => self.value_ident(id),
            Expression::Index(i) => {
                if self.is_type_expr(&i.index) {
                    // `f[T]`: the argument is a value-carrying type.
                    self.ty(&i.index, TyCtx::Ctor);
                    self.expr(&i.left);
                } else {
                    self.expr(&i.left);
                    self.expr(&i.index);
                }
            }
            Expression::IndexList(l) => {
                for i in &l.indices {
                    self.ty(i, TyCtx::Ctor);
                }
                self.expr(&l.left);
            }
            Expression::Slice(s) => {
                self.expr(&s.left);
                for i in s.index.iter().flatten() {
                    self.expr(i);
                }
            }
            Expression::Star(s) => self.expr(&s.right),
            Expression::Paren(p) => self.expr(&p.expr),
            Expression::TypeAssert(t) => {
                self.expr(&t.left);
                if let Some(r) = &t.right {
                    self.ty(r, TyCtx::Plain);
                }
            }
            Expression::Operation(o) => self.operation(o),
            Expression::Range(r) => self.expr(&r.right),
            Expression::Ellipsis(x) => {
                if let Some(e) = &x.elt {
                    self.expr(e);
                }
            }
            Expression::List(xs) => {
                for x in xs {
                    self.expr(x);
                }
            }
            Expression::BasicLit(_) => {}
            Expression::TypeMap(_)
            | Expression::TypeArray(_)
            | Expression::TypeSlice(_)
            | Expression::TypeChannel(_)
            | Expression::TypeFunction(_)
            | Expression::TypeStruct(_)
            | Expression::TypeInterface(_)
            | Expression::TypePointer(_) => self.ty(e, TyCtx::Plain),
        }
        self.leave();
    }

    fn operation(&mut self, o: &ast::Operation) {
        match (&o.op, &o.y) {
            (Operator::And, None) => {
                // `&x`: over a composite literal the literal itself is
                // the construct; over a package-level `var` it is an
                // address-take that retires the constant candidacy.
                if !matches!(&*o.x, Expression::CompositeLit(_)) {
                    self.mark_address_taken(&o.x);
                }
                self.expr(&o.x);
            }
            (_, None) => self.expr(&o.x),
            (_, Some(y)) => {
                self.expr(&o.x);
                self.expr(y);
            }
        }
    }

    /// A selector chain in a value position.
    fn value_chain(&mut self, e: &Expression) {
        match chain(e) {
            Ok((id, members)) => {
                if self.builtin(&id.name) {
                    return;
                }
                let (root, members) = self.resolve(&id.name, members);
                let (start, end) = (expr_pos(e), expr_end(e));
                let r = self.reference(root, members, UseKind::ValueEscape, Vec::new(), start, end);
                self.emit(r);
            }
            Err(base) => self.expr(base),
        }
    }

    fn value_ident(&mut self, id: &ast::Ident) {
        if id.name == "_" || self.builtin(&id.name) {
            return;
        }
        let (root, members) = self.resolve(&id.name, Vec::new());
        let r = self.reference(
            root,
            members,
            UseKind::ValueEscape,
            Vec::new(),
            id.pos,
            id.pos + id.name.chars().count(),
        );
        self.emit(r);
    }

    /// A call site, including `go` and `defer` calls. The site position
    /// is the callee's start (gosyn's `Call.pos` is the parenthesis).
    fn call(&mut self, c: &ast::Call) {
        let mut func: &Expression = &c.func;
        let mut type_args: &[Expression] = &[];
        match func {
            Expression::IndexList(l) => {
                type_args = &l.indices;
                func = &l.left;
            }
            Expression::Index(i) if self.is_type_expr(&i.index) => {
                type_args = std::slice::from_ref(&*i.index);
                func = &i.left;
            }
            _ => {}
        }
        for t in type_args {
            self.ty(t, TyCtx::Ctor);
        }
        // Whether the first argument is a type (`new`/`make`), walked by
        // `ty` rather than `expr`.
        let mut first_type = false;
        match func {
            Expression::Ident(id) => {
                if id.name == "new" && self.builtin("new") {
                    first_type = true;
                    if let Some(t) = c.args.first() {
                        self.ty(t, TyCtx::Ctor);
                    }
                } else if id.name == "make" && self.builtin("make") {
                    first_type = true;
                    if let Some(t) = c.args.first() {
                        match t {
                            Expression::TypeSlice(s) => self.ty(&s.typ, TyCtx::Filled),
                            other => self.ty(other, TyCtx::Plain),
                        }
                    }
                } else if !self.builtin(&id.name) {
                    let (root, members) = self.resolve(&id.name, Vec::new());
                    let (start, end) = (expr_pos(func), c.pos.1 + 1);
                    let r = self.reference(
                        root,
                        members,
                        UseKind::Call,
                        c.args.iter().map(|a| self.lower_expr(a, 0)).collect(),
                        start,
                        end,
                    );
                    self.emit(r);
                }
            }
            Expression::Selector(s) => match chain(func) {
                Ok((id, members)) => {
                    // A single-member call on a local bound to a
                    // `reflect.ValueOf`/`TypeOf` result is a lookup or
                    // dispatch on that value (KTD12).
                    if members.len() != 1 || !self.reflect_local_call(&id.name, &members[0], c) {
                        let (root, members) = self.resolve(&id.name, members);
                        let (start, end) = (expr_pos(func), c.pos.1 + 1);
                        let r = self.reference(
                            root,
                            members,
                            UseKind::Call,
                            c.args.iter().map(|a| self.lower_expr(a, 0)).collect(),
                            start,
                            end,
                        );
                        self.emit(r);
                    }
                }
                Err(base) => {
                    // A method call on a non-ident receiver may be a
                    // `reflect` lookup or dispatch.
                    self.reflect_chain_call(c, s);
                    self.expr(base)
                }
            },
            other => self.expr(other),
        }
        for (i, a) in c.args.iter().enumerate() {
            if first_type && i == 0 {
                continue;
            }
            self.expr(a);
        }
    }

    // ---- reflect chains (KTD12) ------------------------------------------

    /// The reflect binding `name` resolves to, or `None`: a scope that
    /// binds the name any other way shadows an outer reflect binding,
    /// as `head` decides, and a name no scope binds is a parameter,
    /// import local, or unbound name, none of them reflect-bound.
    fn reflect_bound(&self, name: &str) -> Option<&ReflectTarget> {
        for (scope, _) in self.scopes.iter().rev() {
            if scope.locals.contains(name) {
                return scope.reflect.get(name);
            }
            if scope.tracked.contains_key(name) {
                return None;
            }
        }
        None
    }

    /// The `v` in a `reflect.ValueOf(v)` or `reflect.TypeOf(v)` call.
    fn reflect_arg<'e>(&self, e: &'e Expression) -> Option<&'e Expression> {
        let Expression::Call(c) = e else {
            return None;
        };
        let Ok((id, members)) = chain(&c.func) else {
            return None;
        };
        if !self.reflect_locals.contains(&id.name)
            || !matches!(self.head(&id.name), Head::Import(_))
            || !matches!(members.as_slice(), [m] if m == "ValueOf" || m == "TypeOf")
        {
            return None;
        }
        c.args.first()
    }

    /// The root, members, and provenance a reflect chain's innermost
    /// value reduces to: `ModuleBinding` for a package-level variable
    /// or an imported member, `TrackedConstructor` for a local bound
    /// to a constructor site, `Parameter` for a parameter, `Unknown`
    /// otherwise.
    fn reflect_target(&self, e: &Expression) -> ReflectTarget {
        match chain(e) {
            Ok((id, members)) if !self.builtin(&id.name) => {
                let prov = match self.head(&id.name) {
                    Head::Import(_) => Provenance::ModuleBinding,
                    Head::Ambient(_) => Provenance::AmbientModule,
                    Head::Typed(..) => Provenance::TrackedConstructor,
                    Head::Param(i) => Provenance::Parameter(i),
                    Head::Local(_) if self.package_target(&id.name) => Provenance::ModuleBinding,
                    Head::Local(_) => Provenance::Unknown,
                };
                let (root, members) = self.resolve(&id.name, members);
                (root, members, prov)
            }
            _ => (Root::Expression, Vec::new(), Provenance::Unknown),
        }
    }

    /// Whether `e` evaluates to a `reflect.Value` whose target we know:
    /// a `reflect.ValueOf`/`TypeOf` call, a local bound to one, or a
    /// lookup chain on either.
    fn reflect_chain(&self, e: &Expression) -> ReflectChain {
        match e {
            Expression::Paren(p) => self.reflect_chain(&p.expr),
            Expression::Ident(id) => match self.reflect_bound(&id.name) {
                Some((r, m, p)) => ReflectChain::Live(r.clone(), m.clone(), p.clone()),
                None => ReflectChain::No,
            },
            Expression::Call(c) => {
                if let Some(v) = self.reflect_arg(e) {
                    let (r, m, p) = self.reflect_target(v);
                    return ReflectChain::Live(r, m, p);
                }
                let Expression::Selector(s) = &*c.func else {
                    return ReflectChain::No;
                };
                let inner = self.reflect_chain(&s.x);
                let ReflectChain::Live(..) = inner else {
                    return inner;
                };
                match s.sel.name.as_str() {
                    // A literal name resolves the chain to a member;
                    // anything else keeps a reflect value.
                    "MethodByName" | "FieldByName"
                        if matches!(
                            c.args.first(),
                            Some(Expression::BasicLit(b)) if b.kind == LitKind::String
                        ) =>
                    {
                        ReflectChain::Resolved
                    }
                    _ => inner,
                }
            }
            _ => ReflectChain::No,
        }
    }

    /// A single-member call on a reflect-bound local: a name or index
    /// lookup, or a `Call`/`CallSlice` dispatch on that value.
    fn reflect_local_call(&mut self, name: &str, member: &str, c: &ast::Call) -> bool {
        let Some((root, members, prov)) = self.reflect_bound(name).cloned() else {
            return false;
        };
        match member {
            "MethodByName" | "FieldByName" => self.reflect_lookup(c, root, members, prov, false),
            "Method" | "MethodByIndex" => self.reflect_lookup(c, root, members, prov, true),
            "Call" | "CallSlice" => self.reflect_computed(c, root, members, prov),
            _ => return false,
        }
        true
    }

    /// A method call on a non-ident receiver: when the receiver is a
    /// reflect chain, `MethodByName`, `FieldByName`, `Method`, and
    /// `MethodByIndex` are lookups and `Call`/`CallSlice` a dispatch.
    fn reflect_chain_call(&mut self, c: &ast::Call, s: &ast::Selector) {
        let by_index = matches!(s.sel.name.as_str(), "Method" | "MethodByIndex");
        match s.sel.name.as_str() {
            "MethodByName" | "FieldByName" | "Method" | "MethodByIndex" => {
                let ReflectChain::Live(root, members, prov) = self.reflect_chain(&s.x) else {
                    return;
                };
                self.reflect_lookup(c, root, members, prov, by_index);
            }
            "Call" | "CallSlice" => {
                let ReflectChain::Live(root, members, prov) = self.reflect_chain(&s.x) else {
                    return;
                };
                self.reflect_computed(c, root, members, prov);
            }
            _ => {}
        }
    }

    /// A lookup member call on a reflect chain rooted at
    /// `(root, members)`: a literal name is an ordinary member use, a
    /// non-literal one a computed member. A literal index names no
    /// member we can write, so it emits nothing.
    fn reflect_lookup(
        &mut self,
        c: &ast::Call,
        root: Root,
        mut members: Vec<String>,
        prov: Provenance,
        by_index: bool,
    ) {
        let (start, end) = (expr_pos(&c.func), c.pos.1 + 1);
        match c.args.first() {
            Some(Expression::BasicLit(b)) if !by_index && b.kind == LitKind::String => {
                members.push(unquote(&b.value));
                let r = self.reference(root, members, UseKind::ValueEscape, Vec::new(), start, end);
                self.emit(r);
            }
            Some(Expression::BasicLit(b))
                if by_index && matches!(b.kind, LitKind::Integer | LitKind::Char) => {}
            _ => self.reflect_computed(c, root, members, prov),
        }
    }

    /// A computed member on a reflect chain's target: a lookup by a
    /// non-literal name or index, or a `Call`/`CallSlice` dispatch.
    fn reflect_computed(
        &mut self,
        c: &ast::Call,
        root: Root,
        members: Vec<String>,
        prov: Provenance,
    ) {
        let (start, end) = (expr_pos(&c.func), c.pos.1 + 1);
        let mut r = self.reference(
            root,
            members,
            UseKind::ComputedMember,
            c.args.iter().map(|a| self.lower_expr(a, 0)).collect(),
            start,
            end,
        );
        r.receiver = Some(prov);
        self.emit(r);
    }

    fn composite_lit(&mut self, l: &ast::CompositeLit) {
        self.ty(&l.typ, TyCtx::Ctor);
        self.literal_value(&l.val, Some(&l.typ));
    }

    /// The elements of a composite literal whose type is `t` when one is
    /// written. An unkeyed `{...}` element is an elided composite
    /// literal: its type is the element type of the enclosing literal
    /// for a slice/array/map, and unrecoverable for a field value (the
    /// field's type lives in the struct definition). When the element
    /// type may carry a `constructor = true` value type and cannot be
    /// decided, the emit is a `resolution-limit` construct, never
    /// nothing.
    fn literal_value(&mut self, v: &ast::LiteralValue, t: Option<&Expression>) {
        let elem = t.and_then(element_type);
        for ke in &v.values {
            if let Some(k) = &ke.key {
                self.element(k, None);
            }
            self.element(&ke.val, elem);
        }
    }

    fn element(&mut self, el: &ast::Element, elem_ty: Option<&Expression>) {
        match el {
            ast::Element::Expr(e) => {
                // A bare ident key is a field name, not a reference.
                if !matches!(e, Expression::Ident(_)) {
                    self.expr(e);
                }
            }
            ast::Element::LitValue(v) => {
                // `ty` is the elided literal's own type.
                let ty = elem_ty;
                let undecidable = match ty {
                    Some(t) => self.leaf_chain(t).is_some(),
                    None => true,
                };
                if undecidable {
                    self.construct(ConstructKind::ResolutionLimit, v.pos.0, v.pos.1 + 1);
                }
                self.literal_value(v, ty);
            }
        }
    }

    fn func_lit(&mut self, l: &ast::FuncLit) {
        let sym = self.child_symbol("<closure>");
        let params = param_names(&l.typ);
        self.ir.symbols.push(SymbolSpan {
            path: sym.clone(),
            kind: SymbolKind::Closure,
            params: params.clone(),
            defaults: Default::default(),
            strict: None,
            span: self.span(l.typ.pos, l.body.pos.1 + 1),
        });
        self.symbols.push(sym);
        self.fns.push(FnFrame { params });
        self.scopes.push((Scope::default(), self.symbol()));
        self.signature(&l.typ);
        self.block(&l.body);
        self.pop_scope();
        self.fns.pop();
        self.symbols.pop();
    }

    // ---- expressions as values -------------------------------------------

    /// An argument or initializer as an [`Expr`] tree.
    fn lower_expr(&self, e: &Expression, depth: u32) -> Expr {
        if depth > 32 {
            return Expr::Opaque(self.text_of(expr_pos(e), expr_end(e)));
        }
        match e {
            Expression::BasicLit(b) => match b.kind {
                LitKind::String | LitKind::Char => Expr::Literal(unquote(&b.value)),
                _ => Expr::Literal(b.value.clone()),
            },
            Expression::Ident(i) => match i.name.as_str() {
                "iota" | "nil" => Expr::Opaque(i.name.clone()),
                "true" | "false" => Expr::Literal(i.name.clone()),
                _ => match self.param_index(&i.name) {
                    Some(p) => Expr::Param(p),
                    None => Expr::Name(i.name.clone()),
                },
            },
            Expression::Paren(p) => self.lower_expr(&p.expr, depth + 1),
            Expression::Star(s) => self.lower_expr(&s.right, depth + 1),
            Expression::TypeAssert(t) => self.lower_expr(&t.left, depth + 1),
            Expression::Operation(o) => match (&o.op, &o.y) {
                (Operator::And, None) => self.lower_expr(&o.x, depth + 1),
                (Operator::Add, Some(y)) => {
                    let mut parts = Vec::new();
                    for side in [&o.x, y] {
                        match self.lower_expr(side, depth + 1) {
                            Expr::Template(p) => parts.extend(p),
                            other => parts.push(other),
                        }
                    }
                    Expr::Template(parts)
                }
                _ => Expr::Opaque(self.text_of(expr_pos(e), expr_end(e))),
            },
            Expression::Call(c) => {
                if let Expression::Ident(f) = &*c.func
                    && f.name == "string"
                    && self.builtin("string")
                    && c.args.len() == 1
                {
                    return self.lower_expr(&c.args[0], depth + 1);
                }
                match self.call_ref(c) {
                    Some(r) => Expr::Reference(Box::new(r)),
                    None => Expr::Opaque(self.text_of(expr_pos(e), expr_end(e))),
                }
            }
            Expression::Selector(_) => match chain(e) {
                Ok((id, members)) if !self.builtin(&id.name) => {
                    let (root, members) = self.resolve(&id.name, members);
                    let (start, end) = (expr_pos(e), expr_end(e));
                    Expr::Reference(Box::new(self.reference(
                        root,
                        members,
                        UseKind::ValueEscape,
                        Vec::new(),
                        start,
                        end,
                    )))
                }
                _ => Expr::Opaque(self.text_of(expr_pos(e), expr_end(e))),
            },
            Expression::Index(i) => Expr::Subscript {
                base: Box::new(self.lower_expr(&i.left, depth + 1)),
                key: Box::new(self.lower_expr(&i.index, depth + 1)),
            },
            Expression::List(xs) => {
                Expr::Sequence(xs.iter().map(|x| self.lower_expr(x, depth + 1)).collect())
            }
            Expression::CompositeLit(l) => match self.leaf_chain(&l.typ) {
                Some((loc, members)) => Expr::Reference(Box::new(self.reference(
                    Root::Import(loc),
                    members,
                    UseKind::Construct,
                    Vec::new(),
                    expr_pos(e),
                    expr_end(e),
                ))),
                None => self.composite_value(l, depth),
            },
            other => Expr::Opaque(self.text_of(expr_pos(other), expr_end(other))),
        }
    }

    /// A composite literal's [`Expr`] form when it is not a tracked
    /// construct: an object for all-keyed fields, else a sequence.
    fn composite_value(&self, l: &ast::CompositeLit, depth: u32) -> Expr {
        let pairs: Vec<(String, Expr)> = l
            .val
            .values
            .iter()
            .filter_map(|ke| {
                let key = match &ke.key {
                    Some(ast::Element::Expr(Expression::Ident(id))) => id.name.clone(),
                    _ => return None,
                };
                match &ke.val {
                    ast::Element::Expr(v) => Some((key, self.lower_expr(v, depth + 1))),
                    ast::Element::LitValue(_) => Some((key, Expr::Opaque("{...}".to_string()))),
                }
            })
            .collect();
        if !pairs.is_empty() && pairs.len() == l.val.values.len() {
            return Expr::Object(pairs);
        }
        Expr::Sequence(
            l.val
                .values
                .iter()
                .map(|ke| match &ke.val {
                    ast::Element::Expr(v) => self.lower_expr(v, depth + 1),
                    ast::Element::LitValue(_) => Expr::Opaque("{...}".to_string()),
                })
                .collect(),
        )
    }

    /// The reference a call makes for [`Expr::Reference`] purposes, or
    /// `None` for builtins and unresolvable callees.
    fn call_ref(&self, c: &ast::Call) -> Option<Reference> {
        let func: &Expression = match &*c.func {
            Expression::Index(i) if self.is_type_expr(&i.index) => &i.left,
            Expression::IndexList(l) => &l.left,
            f => f,
        };
        let (id, members) = match func {
            Expression::Ident(id) if !self.builtin(&id.name) => (id, Vec::new()),
            Expression::Selector(_) => match chain(func) {
                Ok((id, m)) => (id, m),
                Err(_) => return None,
            },
            _ => return None,
        };
        let (root, members) = self.resolve(&id.name, members);
        let (start, end) = (expr_pos(func), c.pos.1 + 1);
        Some(self.reference(
            root,
            members,
            UseKind::Call,
            c.args.iter().map(|a| self.lower_expr(a, 0)).collect(),
            start,
            end,
        ))
    }
}

/// The element type of a composite literal's written type, for elided
/// literals: `[]T` and `[N]T` give `T`, `map[K]V` gives `V`.
fn element_type(t: &Expression) -> Option<&Expression> {
    match t {
        Expression::TypeSlice(s) => Some(&s.typ),
        Expression::TypeArray(a) => Some(&a.typ),
        Expression::TypeMap(m) => Some(&m.val),
        Expression::Paren(p) => element_type(&p.expr),
        _ => None,
    }
}

/// The receiver's base type name, pointers and type parameters stripped
/// (`*Store[K, V]` is `Store`).
fn recv_type_name(t: &Expression) -> Option<String> {
    match t {
        Expression::Ident(i) => Some(i.name.clone()),
        Expression::Star(s) => recv_type_name(&s.right),
        Expression::TypePointer(p) => recv_type_name(&p.typ),
        Expression::Paren(p) => recv_type_name(&p.expr),
        Expression::Index(i) => recv_type_name(&i.left),
        Expression::IndexList(l) => recv_type_name(&l.left),
        _ => None,
    }
}

/// Declared parameter names of a function type, `_` for unnamed ones.
fn param_names(t: &ast::FuncType) -> Vec<String> {
    t.params
        .list
        .iter()
        .flat_map(|f| {
            if f.name.is_empty() {
                vec!["_".to_string()]
            } else {
                f.name.iter().map(|i| i.name.clone()).collect()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(src: &str) -> ast::File {
        gosyn::parse_source(format!("package p\n\n{src}")).unwrap()
    }

    /// The walker's depth guard is sized above what the prescans admit,
    /// so the test drives a reduced cap: one nested block under, one
    /// over.
    #[test]
    fn the_depth_guard_fires_one_over() {
        let under = format!("func f() {{ {} {} }}", "{".repeat(6), "}".repeat(6));
        let over = format!("func f() {{ {} {} }}", "{".repeat(8), "}".repeat(8));
        let mut l = Lowerer::new(&under);
        l.max_depth = 15;
        l.file(&file(&under));
        assert!(!l.too_deep, "{under}");
        let mut l = Lowerer::new(&over);
        l.max_depth = 15;
        l.file(&file(&over));
        assert!(l.too_deep, "{over}");
    }
}

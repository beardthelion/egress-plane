//! Lowering of one JS or TS file to the IR.
//!
//! The file is parsed with `oxc_parser` and scoped with `oxc_semantic`; a
//! non-empty error list from either, or a parse that gave up, is a
//! `parse-error` with no partial IR. Identifiers the semantic model leaves
//! unresolved are ambient globals. Names come from oxc already
//! decoded, so identifier escapes such as `fetch` reach the IR as the
//! runtime sees them.
//!
//! Lowering conventions the core relies on:
//! - A loader call with a literal specifier (`require("x")`, its
//!   equivalents, `import("x")`, TS `import x = require("x")`) is an
//!   [`ir::Import`] and produces no reference; a non-literal specifier is a
//!   `DynamicImport` construct. A literal loader call that is not bound to a
//!   name gets a synthetic local named by its source text.
//! - A member chain stops at a call: `fetch(u).then(cb)` yields the `fetch`
//!   call and nothing for `.then`, so a call result never reads as the
//!   callee itself.
//! - A bare chain is a `ValueEscape` reference only where its value flows
//!   (initializers, arguments, returns, assignments, array and object
//!   values); tests such as `typeof fetch` or `if (window.fetch)` are not.
//! - Anonymous arrow functions belong to the enclosing symbol; named ones,
//!   functions, classes, methods, and object-literal methods are symbols
//!   joined with `.` (`Api.list`, `api.post`, `outer.inner`), and an
//!   anonymous `function` expression is `<anonymous>` under its parent.

use std::collections::{HashMap, HashSet};

use egress_core::ir::{self, ConstructKind, Expr, FileIr, LineIndex, Provenance, Root, UseKind};
use egress_core::model::Language;
use egress_core::paths::{file_name, is_dot_relative};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_semantic::{Scoping, SemanticBuilder};
use oxc_span::{GetSpan, SourceType};
use oxc_syntax::operator::{BinaryOperator, UnaryOperator};
use oxc_syntax::symbol::SymbolId;

use crate::nesting;

/// Why a file could not be lowered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    /// oxc reported an error or gave up: `parse-error`.
    Parse,
    /// Nesting past what the parser and lowering can recurse through:
    /// `too-deeply-nested`.
    TooDeeplyNested,
}

/// Deepest syntax nesting the lowering walk follows. The nesting estimate
/// rejects files past [`nesting::LIMIT`] before parsing, so this bound is a
/// second guard for the walk itself.
const MAX_WALK_DEPTH: u32 = nesting::LIMIT as u32 + 1024;

/// Names that denote the global object itself.
const GLOBAL_NAMES: &[&str] = &[
    "globalThis",
    "window",
    "self",
    "global",
    "top",
    "parent",
    "frames",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Js,
    Ts,
    Dts,
}

/// The source type per extension: `.mjs` and `.mts`
/// are modules, `.cjs` and `.cts` CommonJS, and everything else a module
/// when it contains ESM syntax and a script otherwise. JS files accept JSX.
fn source_type(path: &[u8]) -> (SourceType, FileKind) {
    let name = file_name(path);
    let ends = |s: &str| name.ends_with(s.as_bytes());
    if ends(".d.ts") || ends(".d.mts") || ends(".d.cts") {
        return (SourceType::d_ts(), FileKind::Dts);
    }
    if ends(".mjs") {
        (SourceType::mjs().with_jsx(true), FileKind::Js)
    } else if ends(".cjs") {
        (SourceType::cjs().with_jsx(true), FileKind::Js)
    } else if ends(".mts") {
        (SourceType::ts().with_module(true), FileKind::Ts)
    } else if ends(".cts") {
        (SourceType::ts().with_commonjs(true), FileKind::Ts)
    } else if ends(".tsx") {
        (SourceType::tsx(), FileKind::Ts)
    } else if ends(".ts") {
        (SourceType::ts(), FileKind::Ts)
    } else {
        // `.js`, `.jsx`, and extensionless `#!` scripts.
        (SourceType::unambiguous().with_jsx(true), FileKind::Js)
    }
}

/// Lowers the file at repo-relative `path` with source `text`.
pub fn lower(path: &[u8], text: &str) -> Result<FileIr, LowerError> {
    let (st, kind) = source_type(path);
    if nesting::too_deep(text) {
        return Err(LowerError::TooDeeplyNested);
    }
    let alloc = Allocator::default();
    let mut ret = Parser::new(&alloc, text, st).parse();
    let failed = |r: &oxc_parser::ParserReturn<'_>| r.fatal_error || !r.diagnostics.is_empty();
    if failed(&ret) && ret.program.source_type.is_script() && st.is_unambiguous() {
        // A file with no ESM syntax runs as CommonJS under Node, which
        // allows a top-level `return`.
        let retry = Parser::new(&alloc, text, st.with_commonjs(true)).parse();
        if !failed(&retry) {
            ret = retry;
        }
    }
    if failed(&ret) || ret.is_flow_language {
        return Err(LowerError::Parse);
    }
    let program = &ret.program;
    let sem = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(program);
    if !sem.diagnostics.is_empty() {
        return Err(LowerError::Parse);
    }
    if kind == FileKind::Dts {
        // Declarations carry no runtime code.
        return Ok(FileIr::new(Language::Javascript));
    }
    let scoping = sem.semantic.scoping();
    let mut l = Lowerer::new(text, scoping, !program.source_type.is_module());
    l.prepass(&program.body);
    l.statements(&program.body);
    if l.too_deep {
        return Err(LowerError::TooDeeplyNested);
    }
    Ok(l.ir)
}

/// How `this` resolves inside a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum This {
    /// A class instance (methods, constructors, field initializers).
    Class,
    /// The global object: a sloppy non-method function in script code.
    Ambient,
    Opaque,
}

#[derive(Debug, Clone)]
struct Frame {
    id: usize,
    path: String,
    /// The frame names a symbol; its parameters lower as `Param(i)`.
    owner: bool,
    this: This,
    /// Inside a class constructor or instance field initializer.
    ctor: bool,
    /// The enclosing class path, for `this.attr` facts.
    class: Option<String>,
}

/// What a local binding was initialized with, for receiver provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Init {
    Literal,
    Module,
    Ambient,
    FirstPartyCall,
    UnscannedCall,
    Unknown,
}

/// A loader call: the specifier when literal.
struct Loader {
    spec: Option<String>,
}

/// Where a loader call takes its specifier.
enum SpecPos {
    /// The argument at this index.
    Arg(usize),
    /// The first element of the array literal at this argument index
    /// (`require.apply(this, [spec])`).
    Array(usize),
}

struct Lowerer<'s, 'a> {
    text: &'a str,
    lines: LineIndex<'a>,
    scoping: &'s Scoping,
    script: bool,
    ir: FileIr,
    frames: Vec<Frame>,
    next_frame: usize,
    depth: u32,
    too_deep: bool,
    /// Symbols bound by an import or a literal loader binding, to the local
    /// name the IR import uses.
    import_syms: HashMap<SymbolId, String>,
    /// Import local name to specifier.
    import_spec: HashMap<String, String>,
    /// Parameters: symbol to (frame id, 1-based index).
    params: HashMap<SymbolId, (usize, u32)>,
    /// Locals bound to a loader (`createRequire(...)`).
    loader_syms: HashSet<SymbolId>,
    /// Locals bound to a `.constructor` access on an unresolved receiver.
    ctor_alias_syms: HashSet<SymbolId>,
    inits: HashMap<SymbolId, Init>,
    /// Span starts of synthetic loader imports already recorded.
    synthetic: HashSet<u32>,
}

fn join(parent: &str, name: &str) -> String {
    if parent == "<module>" {
        name.to_string()
    } else {
        format!("{parent}.{name}")
    }
}

fn lit_str(e: &Expression<'_>) -> Option<String> {
    match e.get_inner_expression() {
        Expression::StringLiteral(s) => Some(s.value.as_str().to_string()),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() => t
            .quasis
            .first()
            .and_then(|q| q.value.cooked.as_ref())
            .map(|c| c.as_str().to_string()),
        _ => None,
    }
}

/// The object and key of a plain member expression: the key is `None`
/// for a computed key that is not a string or plain template literal.
fn member_key<'e, 'a>(e: &'e Expression<'a>) -> Option<(&'e Expression<'a>, Option<&'e str>)> {
    match e {
        Expression::StaticMemberExpression(m) => Some((&m.object, Some(m.property.name.as_str()))),
        Expression::ComputedMemberExpression(m) => {
            let key = match m.expression.get_inner_expression() {
                Expression::StringLiteral(s) => Some(s.value.as_str()),
                Expression::TemplateLiteral(t) if t.expressions.is_empty() => t
                    .quasis
                    .first()
                    .and_then(|q| q.value.cooked.as_ref())
                    .map(|c| c.as_str()),
                _ => None,
            };
            Some((&m.object, key))
        }
        _ => None,
    }
}

fn stringish(e: &Expression<'_>) -> bool {
    match e.get_inner_expression() {
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_) => true,
        Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
            stringish(&b.left) || stringish(&b.right)
        }
        _ => false,
    }
}

fn is_function_like(e: &Expression<'_>) -> bool {
    matches!(
        e.get_inner_expression(),
        Expression::ArrowFunctionExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::ClassExpression(_)
    )
}

fn key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::PrivateIdentifier(p) => Some(format!("#{}", p.name.as_str())),
        _ => key.static_name().map(|c| c.to_string()),
    }
}

fn is_relative(spec: &str) -> bool {
    is_dot_relative(spec) || spec.starts_with('/') || spec.starts_with('#')
}

impl<'s, 'a> Lowerer<'s, 'a> {
    fn new(text: &'a str, scoping: &'s Scoping, script: bool) -> Self {
        Lowerer {
            text,
            lines: LineIndex::new(text),
            scoping,
            script,
            ir: FileIr::new(Language::Javascript),
            frames: vec![Frame {
                id: 0,
                path: "<module>".into(),
                owner: true,
                this: This::Opaque,
                ctor: false,
                class: None,
            }],
            next_frame: 1,
            depth: 0,
            too_deep: false,
            import_syms: HashMap::new(),
            import_spec: HashMap::new(),
            params: HashMap::new(),
            loader_syms: HashSet::new(),
            ctor_alias_syms: HashSet::new(),
            inits: HashMap::new(),
            synthetic: HashSet::new(),
        }
    }

    // ---- small helpers ------------------------------------------------------------

    fn src(&self, span: oxc_span::Span) -> &'a str {
        self.text
            .get(span.start as usize..span.end as usize)
            .unwrap_or_default()
    }

    fn span(span: oxc_span::Span) -> ir::Span {
        ir::Span {
            start: span.start,
            end: span.end,
        }
    }

    fn loc(&self, span: oxc_span::Span) -> egress_core::model::Location {
        self.lines.location(span.start as usize)
    }

    fn frame(&self) -> &Frame {
        self.frames
            .last()
            .expect("the module frame is never popped")
    }

    fn owner(&self) -> &Frame {
        self.frames
            .iter()
            .rev()
            .find(|f| f.owner)
            .expect("the module frame owns")
    }

    fn symbol(&self) -> String {
        self.owner().path.clone()
    }

    fn enter(&mut self) -> bool {
        self.depth += 1;
        if self.depth > MAX_WALK_DEPTH {
            self.too_deep = true;
        }
        !self.too_deep
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn push_frame(
        &mut self,
        path: String,
        owner: bool,
        this: This,
        ctor: bool,
        class: Option<String>,
    ) {
        let id = self.next_frame;
        self.next_frame += 1;
        self.frames.push(Frame {
            id,
            path,
            owner,
            this,
            ctor,
            class,
        });
    }

    fn reference(
        &self,
        root: Root,
        members: Vec<String>,
        use_kind: UseKind,
        args: Vec<Expr>,
        receiver: Option<Provenance>,
        span: oxc_span::Span,
    ) -> ir::Reference {
        ir::Reference {
            root,
            members,
            calls_in_chain: Vec::new(),
            use_kind,
            args,
            kwargs: Vec::new(),
            receiver,
            text: self.src(span).to_string(),
            symbol: self.symbol(),
            span: Self::span(span),
            location: self.loc(span),
        }
    }

    fn emit(&mut self, r: ir::Reference) {
        self.ir.references.push(r);
    }

    fn construct(&mut self, kind: ConstructKind, span: oxc_span::Span) {
        let c = ir::DynamicConstruct {
            kind,
            text: self.src(span).to_string(),
            symbol: self.symbol(),
            span: Self::span(span),
            location: self.loc(span),
        };
        self.ir.constructs.push(c);
    }

    #[allow(clippy::too_many_arguments)]
    fn import(
        &mut self,
        local: Option<String>,
        specifier: &str,
        members: Vec<String>,
        type_only: bool,
        star: bool,
        re_export: bool,
        default: bool,
        span: oxc_span::Span,
    ) {
        if let Some(l) = &local
            && !re_export
        {
            self.import_spec.insert(l.clone(), specifier.to_string());
        }
        let i = ir::Import {
            local,
            specifier: specifier.to_string(),
            members,
            type_only,
            star,
            re_export,
            default,
            symbol: self.symbol(),
            span: Self::span(span),
            location: self.loc(span),
        };
        self.ir.imports.push(i);
    }

    // ---- name resolution ------------------------------------------------------------

    fn ident_sym(&self, id: &IdentifierReference<'_>) -> Option<SymbolId> {
        id.reference_id
            .get()
            .and_then(|r| self.scoping.get_reference(r).symbol_id())
    }

    fn ident_root(&self, id: &IdentifierReference<'_>) -> Root {
        let name = id.name.as_str();
        let Some(sym) = self.ident_sym(id) else {
            return Root::Ambient(name.to_string());
        };
        if let Some(local) = self.import_syms.get(&sym) {
            return Root::Import(local.clone());
        }
        if let Some(&(fid, i)) = self.params.get(&sym)
            && fid == self.owner().id
        {
            return Root::Param(i);
        }
        Root::Local(name.to_string())
    }

    fn is_loader_ident(&self, id: &IdentifierReference<'_>) -> bool {
        match self.ident_sym(id) {
            None => id.name.as_str() == "require",
            Some(sym) => self.loader_syms.contains(&sym),
        }
    }

    fn this_root(&self) -> Root {
        match self.frame().this {
            This::Class => Root::SelfValue,
            This::Ambient => Root::Ambient("globalThis".into()),
            This::Opaque => Root::Expression,
        }
    }

    /// A root plus literal member chain, without calls. Iterative so long
    /// member chains do not recurse.
    fn static_chain(&mut self, e: &Expression<'a>) -> Option<(Root, Vec<String>)> {
        let mut members = Vec::new();
        let mut cur = e.get_inner_expression();
        let root = loop {
            match cur {
                Expression::Identifier(id) => break self.ident_root(id),
                Expression::ThisExpression(_) => break self.this_root(),
                Expression::StaticMemberExpression(m) => {
                    members.push(m.property.name.as_str().to_string());
                    cur = m.object.get_inner_expression();
                }
                Expression::ComputedMemberExpression(m) => {
                    let key = match m.expression.get_inner_expression() {
                        Expression::NumericLiteral(n) => self.src(n.span).to_string(),
                        k => lit_str(k)?,
                    };
                    members.push(key);
                    cur = m.object.get_inner_expression();
                }
                Expression::PrivateFieldExpression(m) => {
                    members.push(format!("#{}", m.field.name.as_str()));
                    cur = m.object.get_inner_expression();
                }
                Expression::ChainExpression(c) => match &c.expression {
                    ChainElement::StaticMemberExpression(m) => {
                        members.push(m.property.name.as_str().to_string());
                        cur = m.object.get_inner_expression();
                    }
                    ChainElement::ComputedMemberExpression(m) => {
                        members.push(lit_str(&m.expression)?);
                        cur = m.object.get_inner_expression();
                    }
                    ChainElement::PrivateFieldExpression(m) => {
                        members.push(format!("#{}", m.field.name.as_str()));
                        cur = m.object.get_inner_expression();
                    }
                    _ => return None,
                },
                Expression::CallExpression(c) => {
                    // A literal loader call roots a chain as its import.
                    let loader = self.loader(c)?;
                    let spec = loader.spec?;
                    break Root::Import(self.synthetic_import(c, &spec));
                }
                // So does an awaited literal `import()`: its value is the
                // module namespace.
                Expression::AwaitExpression(a) => match a.argument.get_inner_expression() {
                    Expression::ImportExpression(i) => {
                        let spec = lit_str(&i.source)?;
                        break Root::Import(self.import_expression_synthetic(i, &spec));
                    }
                    _ => return None,
                },
                _ => return None,
            }
        };
        members.reverse();
        Some((root, members))
    }

    /// Records the synthetic import for an unbound literal loader call and
    /// returns its local name.
    fn synthetic_import(&mut self, c: &CallExpression<'a>, spec: &str) -> String {
        let local = self
            .src(c.span)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if self.synthetic.insert(c.span.start) {
            self.import(
                Some(local.clone()),
                spec,
                Vec::new(),
                false,
                false,
                false,
                true,
                c.span,
            );
        }
        local
    }

    /// Records the synthetic import for an unbound literal `import()` and
    /// returns its local name.
    fn import_expression_synthetic(&mut self, i: &ImportExpression<'a>, spec: &str) -> String {
        let local = self
            .src(i.span)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if self.synthetic.insert(i.span.start) {
            self.import(
                Some(local.clone()),
                spec,
                Vec::new(),
                false,
                false,
                false,
                false,
                i.span,
            );
        }
        local
    }

    /// Whether `e` names `createRequire` (imported, ambient, or a member).
    fn is_create_require(&mut self, e: &Expression<'a>) -> bool {
        let e = e.get_inner_expression();
        match e {
            Expression::Identifier(id) => id.name.as_str() == "createRequire",
            Expression::StaticMemberExpression(m) => m.property.name.as_str() == "createRequire",
            _ => false,
        }
    }

    /// Recognizes `require(...)` and its equivalents, including a
    /// loader reached through `(0, require)`, `c && require`,
    /// `c ? require : x`, `require.call(this, spec)`, and
    /// `require.apply(this, [spec])`.
    fn loader(&mut self, c: &CallExpression<'a>) -> Option<Loader> {
        let pos = self.loader_callee(&c.callee, 0)?;
        let arg = |i: usize| c.arguments.get(i).and_then(Argument::as_expression);
        let spec = match pos {
            SpecPos::Arg(i) => arg(i).and_then(lit_str),
            SpecPos::Array(i) => match arg(i).map(Expression::get_inner_expression) {
                Some(Expression::ArrayExpression(a)) => a
                    .elements
                    .first()
                    .and_then(ArrayExpressionElement::as_expression)
                    .and_then(lit_str),
                _ => None,
            },
        };
        Some(Loader { spec })
    }

    /// Where a loader callee takes its specifier, or `None` when `callee`
    /// is not a loader. `shift` counts the `.call` layers already peeled.
    fn loader_callee(&mut self, callee: &Expression<'a>, shift: usize) -> Option<SpecPos> {
        let callee = callee.get_inner_expression();
        let is_loader = match callee {
            Expression::Identifier(id) => self.is_loader_ident(id),
            // `require.bind(this, ...)(...)`: the bound arguments shift the
            // specifier, so it is never read as a literal.
            Expression::CallExpression(inner) if self.loader_method(&inner.callee, "bind") => {
                return Some(SpecPos::Arg(usize::MAX));
            }
            Expression::CallExpression(inner) => self.is_create_require(&inner.callee),
            Expression::SequenceExpression(s) => {
                return self.loader_callee(s.expressions.last()?, shift);
            }
            Expression::LogicalExpression(l) => {
                return self
                    .loader_callee(&l.right, shift)
                    .or_else(|| self.loader_callee(&l.left, shift));
            }
            Expression::ConditionalExpression(x) => {
                return self
                    .loader_callee(&x.consequent, shift)
                    .or_else(|| self.loader_callee(&x.alternate, shift));
            }
            // `require.call` and `require["call"]` alike.
            _ if let Some((obj, Some("call"))) = member_key(callee) => {
                return self.loader_callee(obj, shift + 1);
            }
            _ if let Some((obj, Some("apply"))) = member_key(callee) => {
                return match self.loader_callee(obj, 0)? {
                    SpecPos::Arg(0) => Some(SpecPos::Array(shift + 1)),
                    _ => Some(SpecPos::Arg(usize::MAX)),
                };
            }
            // `require[k]` with a key that is not a literal could be any
            // of the methods above, so its specifier is never read.
            _ if let Some((obj, None)) = member_key(callee) => {
                return self.loader_callee(obj, 0).map(|_| SpecPos::Arg(usize::MAX));
            }
            _ => match self.static_chain_no_loader(callee) {
                Some((Root::Ambient(r), m)) => {
                    let m: Vec<&str> = m.iter().map(String::as_str).collect();
                    matches!(
                        (r.as_str(), m.as_slice()),
                        ("module", ["require"])
                            | ("require", ["main", "require"])
                            | ("process", ["mainModule", "require"])
                            | ("module", ["constructor", "_load"])
                            | ("process", ["getBuiltinModule"])
                    )
                }
                Some((Root::Import(local), m)) => {
                    let spec = self.import_spec.get(&local).map(String::as_str);
                    matches!(spec, Some("process" | "node:process"))
                        && m.len() == 1
                        && m[0] == "getBuiltinModule"
                }
                _ => false,
            },
        };
        is_loader.then_some(SpecPos::Arg(shift))
    }

    /// Whether `e` is `<loader>.<method>`, such as `require.bind`.
    fn loader_method(&mut self, e: &Expression<'a>, method: &str) -> bool {
        match member_key(e.get_inner_expression()) {
            Some((obj, Some(name))) => name == method && self.loader_callee(obj, 0).is_some(),
            _ => false,
        }
    }

    /// [`Self::static_chain`] that does not look into loader calls, for
    /// loader recognition itself.
    fn static_chain_no_loader(&mut self, e: &Expression<'a>) -> Option<(Root, Vec<String>)> {
        let mut cur = e.get_inner_expression();
        let mut depth = 0;
        while let Some(m) = cur.get_member_expr() {
            cur = m.object().get_inner_expression();
            depth += 1;
            if depth > 8 {
                return None;
            }
        }
        if matches!(cur, Expression::CallExpression(_)) {
            return None;
        }
        self.static_chain(e)
    }

    /// The import a declarator initializer binds, when it is a literal
    /// loader call or a member chain on one: (specifier, members, default).
    fn loader_binding(&mut self, init: &Expression<'a>) -> Option<(String, Vec<String>, bool)> {
        let mut members = Vec::new();
        let mut cur = init.get_inner_expression();
        if let Expression::AwaitExpression(a) = cur
            && let Expression::ImportExpression(i) = a.argument.get_inner_expression()
        {
            return lit_str(&i.source).map(|s| (s, Vec::new(), false));
        }
        loop {
            match cur {
                Expression::StaticMemberExpression(m) => {
                    members.push(m.property.name.as_str().to_string());
                    cur = m.object.get_inner_expression();
                }
                Expression::CallExpression(c) => {
                    let spec = self.loader(c)?.spec?;
                    members.reverse();
                    let default = members.is_empty();
                    return Some((spec, members, default));
                }
                // `(await import("m")).f`: a member of the namespace.
                Expression::AwaitExpression(a) => {
                    let Expression::ImportExpression(i) = a.argument.get_inner_expression() else {
                        return None;
                    };
                    let spec = lit_str(&i.source)?;
                    members.reverse();
                    return Some((spec, members, false));
                }
                _ => return None,
            }
        }
    }

    fn call_init(&mut self, callee: &Expression<'a>) -> Init {
        match self.static_chain(callee) {
            Some((Root::Import(local), _)) => match self.import_spec.get(&local) {
                Some(spec) if is_relative(spec) => Init::FirstPartyCall,
                Some(_) => Init::UnscannedCall,
                None => Init::Unknown,
            },
            Some((Root::Local(_), _)) => Init::FirstPartyCall,
            _ => Init::Unknown,
        }
    }

    fn init_kind(&mut self, e: &Expression<'a>) -> Init {
        let e = e.get_inner_expression();
        let e = match e {
            Expression::AwaitExpression(a) => a.argument.get_inner_expression(),
            other => other,
        };
        match e {
            Expression::ObjectExpression(_)
            | Expression::ArrayExpression(_)
            | Expression::StringLiteral(_)
            | Expression::TemplateLiteral(_)
            | Expression::NumericLiteral(_) => Init::Literal,
            Expression::CallExpression(c) => self.call_init(&c.callee),
            Expression::NewExpression(n) => self.call_init(&n.callee),
            other => match self.static_chain(other) {
                Some((Root::Import(_), _)) => Init::Module,
                Some((Root::Ambient(n), m))
                    if m.is_empty() && GLOBAL_NAMES.contains(&n.as_str()) =>
                {
                    Init::Ambient
                }
                _ => Init::Unknown,
            },
        }
    }

    /// Provenance of the receiver of a computed or reflective access.
    fn provenance(&mut self, obj: &Expression<'a>) -> Provenance {
        let e = obj.get_inner_expression();
        match e {
            Expression::ObjectExpression(_)
            | Expression::ArrayExpression(_)
            | Expression::StringLiteral(_)
            | Expression::TemplateLiteral(_) => return Provenance::Literal,
            Expression::CallExpression(c) => {
                return match self.call_init(&c.callee) {
                    Init::FirstPartyCall => Provenance::FirstPartyCallResult,
                    Init::UnscannedCall => Provenance::UnscannedCallResult,
                    _ => Provenance::Unknown,
                };
            }
            Expression::Identifier(id) => {
                let sym = self.ident_sym(id);
                match self.ident_root(id) {
                    Root::Import(_) => return Provenance::ModuleBinding,
                    Root::Ambient(_) => return Provenance::AmbientModule,
                    Root::Param(i) => return Provenance::Parameter(i),
                    _ => {}
                }
                return match sym.and_then(|s| self.inits.get(&s)) {
                    Some(Init::Literal) => Provenance::Literal,
                    Some(Init::Module) => Provenance::ModuleBinding,
                    Some(Init::Ambient) => Provenance::AmbientModule,
                    Some(Init::FirstPartyCall) => Provenance::FirstPartyCallResult,
                    Some(Init::UnscannedCall) => Provenance::UnscannedCallResult,
                    _ => Provenance::Unknown,
                };
            }
            _ => {}
        }
        match self.static_chain(e) {
            Some((Root::Import(_), _)) => Provenance::ModuleBinding,
            Some((Root::Ambient(_), _)) => Provenance::AmbientModule,
            _ => Provenance::Unknown,
        }
    }

    // ---- expressions as small trees ----------------------------------------------

    fn lower_expr(&mut self, e: &Expression<'a>) -> Expr {
        let e = e.get_inner_expression();
        match e {
            Expression::StringLiteral(s) => Expr::Literal(s.value.as_str().to_string()),
            Expression::NumericLiteral(n) => Expr::Literal(self.src(n.span).to_string()),
            Expression::BigIntLiteral(n) => Expr::Literal(self.src(n.span).to_string()),
            Expression::TemplateLiteral(t) => {
                let mut parts = Vec::new();
                for (i, q) in t.quasis.iter().enumerate() {
                    if let Some(c) = &q.value.cooked
                        && !c.as_str().is_empty()
                    {
                        parts.push(Expr::Literal(c.as_str().to_string()));
                    }
                    if let Some(x) = t.expressions.get(i) {
                        let v = self.lower_expr(x);
                        parts.push(v);
                    }
                }
                Expr::Template(parts)
            }
            Expression::BinaryExpression(b)
                if b.operator == BinaryOperator::Addition
                    && (stringish(&b.left) || stringish(&b.right)) =>
            {
                let mut parts = Vec::new();
                for side in [&b.left, &b.right] {
                    match self.lower_expr(side) {
                        Expr::Template(p) => parts.extend(p),
                        other => parts.push(other),
                    }
                }
                Expr::Template(parts)
            }
            Expression::Identifier(id) => match self.ident_root(id) {
                Root::Param(i) => Expr::Param(i),
                _ => Expr::Name(id.name.as_str().to_string()),
            },
            Expression::ArrayExpression(a) => {
                let mut items = Vec::new();
                for el in &a.elements {
                    items.push(match el.as_expression() {
                        Some(x) => self.lower_expr(x),
                        None => Expr::Opaque(self.src(el.span()).to_string()),
                    });
                }
                Expr::Sequence(items)
            }
            Expression::ObjectExpression(o) => {
                let mut fields = Vec::new();
                for p in &o.properties {
                    let ObjectPropertyKind::ObjectProperty(p) = p else {
                        return Expr::Opaque(self.src(o.span).to_string());
                    };
                    if p.shorthand || p.method || p.kind != PropertyKind::Init {
                        return Expr::Opaque(self.src(o.span).to_string());
                    }
                    let Some(k) = key_name(&p.key) else {
                        return Expr::Opaque(self.src(o.span).to_string());
                    };
                    let v = self.lower_expr(&p.value);
                    fields.push((k, v));
                }
                Expr::Object(fields)
            }
            Expression::AwaitExpression(a) => self.lower_expr(&a.argument),
            Expression::CallExpression(c) => match self.call_reference(c) {
                Some(r) => Expr::Reference(Box::new(r)),
                None => Expr::Opaque(self.src(c.span).to_string()),
            },
            Expression::NewExpression(n) => match self.static_chain(&n.callee) {
                Some((root, members)) => {
                    let args = self.args_expr(&n.arguments);
                    let r = self.reference(root, members, UseKind::Construct, args, None, n.span);
                    Expr::Reference(Box::new(r))
                }
                None => Expr::Opaque(self.src(n.span).to_string()),
            },
            Expression::ComputedMemberExpression(m)
                if lit_str(&m.expression).is_none()
                    && !matches!(
                        m.expression.get_inner_expression(),
                        Expression::NumericLiteral(_)
                    ) =>
            {
                let base = self.lower_expr(&m.object);
                let key = self.lower_expr(&m.expression);
                Expr::Subscript {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            other => match self.static_chain(other) {
                Some((root, members))
                    if !members.is_empty() || !matches!(root, Root::Expression) =>
                {
                    let r = self.reference(
                        root,
                        members,
                        UseKind::ValueEscape,
                        Vec::new(),
                        None,
                        other.span(),
                    );
                    Expr::Reference(Box::new(r))
                }
                _ => Expr::Opaque(self.src(other.span()).to_string()),
            },
        }
    }

    /// A binding's value: a bare name of the global object or of an
    /// external module stays a reference, so the binding is an alias the
    /// core can follow (`const g = globalThis; g.fetch(u)`); a first-party
    /// or local name stays a name, so constants still evaluate.
    fn binding_value(&mut self, init: &Expression<'a>) -> Expr {
        if let Expression::Identifier(id) = init.get_inner_expression() {
            let root = self.ident_root(id);
            let alias = match &root {
                Root::Ambient(_) => true,
                Root::Import(local) => self.import_spec.get(local).is_some_and(|s| !is_relative(s)),
                _ => false,
            };
            if alias {
                let r = self.reference(
                    root,
                    Vec::new(),
                    UseKind::ValueEscape,
                    Vec::new(),
                    None,
                    id.span,
                );
                return Expr::Reference(Box::new(r));
            }
        }
        self.lower_expr(init)
    }

    fn args_expr(&mut self, args: &[Argument<'a>]) -> Vec<Expr> {
        let mut out = Vec::new();
        for a in args {
            out.push(match a.as_expression() {
                Some(x) => self.lower_expr(x),
                None => Expr::Opaque(self.src(a.span()).to_string()),
            });
        }
        out
    }

    /// The reference a call on a static chain makes, or `None`.
    fn call_reference(&mut self, c: &CallExpression<'a>) -> Option<ir::Reference> {
        let callee = c.callee.get_inner_expression();
        let (root, members) = self.static_chain(callee)?;
        let receiver = match (&root, members.as_slice()) {
            (Root::Ambient(r), [m])
                if r == "Reflect"
                    && matches!(
                        m.as_str(),
                        "get" | "set" | "defineProperty" | "deleteProperty"
                    ) =>
            {
                c.arguments
                    .first()
                    .and_then(Argument::as_expression)
                    .map(|a| self.provenance(a))
            }
            _ => None,
        };
        let args = self.args_expr(&c.arguments);
        Some(self.reference(root, members, UseKind::Call, args, receiver, c.span))
    }

    // ---- statements -------------------------------------------------------------------------

    /// Records import bindings ahead of the walk, so a use before the
    /// binding (a hoisted function, say) still resolves to the import.
    fn prepass(&mut self, body: &[Statement<'a>]) {
        for s in body {
            match s {
                Statement::ImportDeclaration(d) => {
                    for spec in d.specifiers.iter().flatten() {
                        let local = match spec {
                            ImportDeclarationSpecifier::ImportSpecifier(x) => &x.local,
                            ImportDeclarationSpecifier::ImportDefaultSpecifier(x) => &x.local,
                            ImportDeclarationSpecifier::ImportNamespaceSpecifier(x) => &x.local,
                        };
                        if let Some(sym) = local.symbol_id.get() {
                            self.import_syms
                                .insert(sym, local.name.as_str().to_string());
                        }
                        self.import_spec.insert(
                            local.name.as_str().to_string(),
                            d.source.value.as_str().to_string(),
                        );
                    }
                }
                Statement::TSImportEqualsDeclaration(d) => {
                    if let Some(sym) = d.id.symbol_id.get() {
                        self.import_syms.insert(sym, d.id.name.as_str().to_string());
                    }
                }
                Statement::VariableDeclaration(d) => self.prepass_vars(d),
                Statement::ExportNamedDeclaration(_) => {}
                _ => {
                    if let Some(Declaration::VariableDeclaration(d)) = s.as_declaration() {
                        self.prepass_vars(d);
                    }
                }
            }
            if let Statement::ExportDeclaration(e) = s
                && let Declaration::VariableDeclaration(d) = &e.declaration
            {
                self.prepass_vars(d);
            }
        }
    }

    fn prepass_vars(&mut self, d: &VariableDeclaration<'a>) {
        for decl in &d.declarations {
            let Some(init) = &decl.init else { continue };
            if let Expression::CallExpression(c) = init.get_inner_expression()
                && self.is_create_require(&c.callee)
                && let BindingPattern::BindingIdentifier(id) = &decl.id
                && let Some(sym) = id.symbol_id.get()
            {
                self.loader_syms.insert(sym);
                continue;
            }
            if self.loader_binding_peek(init) {
                for id in decl.id.get_binding_identifiers() {
                    if let Some(sym) = id.symbol_id.get() {
                        self.import_syms.insert(sym, id.name.as_str().to_string());
                    }
                }
            }
        }
    }

    /// Whether an initializer is a literal loader binding, without
    /// recording synthetic imports.
    fn loader_binding_peek(&mut self, init: &Expression<'a>) -> bool {
        let mut cur = init.get_inner_expression();
        loop {
            match cur {
                Expression::StaticMemberExpression(m) => cur = m.object.get_inner_expression(),
                Expression::AwaitExpression(a) => {
                    return matches!(a.argument.get_inner_expression(), Expression::ImportExpression(i) if lit_str(&i.source).is_some());
                }
                Expression::CallExpression(c) => {
                    return self.loader(c).is_some_and(|l| l.spec.is_some());
                }
                _ => return false,
            }
        }
    }

    fn statements(&mut self, body: &[Statement<'a>]) {
        for s in body {
            self.statement(s);
            if self.too_deep {
                return;
            }
        }
    }

    fn statement(&mut self, s: &Statement<'a>) {
        if !self.enter() {
            self.leave();
            return;
        }
        self.statement_inner(s);
        self.leave();
    }

    fn statement_inner(&mut self, s: &Statement<'a>) {
        match s {
            Statement::BlockStatement(b) => self.statements(&b.body),
            Statement::ExpressionStatement(e) => self.expr(&e.expression, false),
            Statement::IfStatement(i) => {
                self.expr(&i.test, false);
                self.statement(&i.consequent);
                if let Some(a) = &i.alternate {
                    self.statement(a);
                }
            }
            Statement::WhileStatement(w) => {
                self.expr(&w.test, false);
                self.statement(&w.body);
            }
            Statement::DoWhileStatement(w) => {
                self.statement(&w.body);
                self.expr(&w.test, false);
            }
            Statement::ForStatement(f) => {
                match &f.init {
                    Some(ForStatementInit::VariableDeclaration(d)) => self.var_decl(d, false),
                    Some(init) => {
                        if let Some(e) = init.as_expression() {
                            self.expr(e, false);
                        }
                    }
                    None => {}
                }
                if let Some(t) = &f.test {
                    self.expr(t, false);
                }
                if let Some(u) = &f.update {
                    self.expr(u, false);
                }
                self.statement(&f.body);
            }
            Statement::ForInStatement(f) => {
                self.expr(&f.right, false);
                self.statement(&f.body);
            }
            Statement::ForOfStatement(f) => {
                self.expr(&f.right, false);
                self.statement(&f.body);
            }
            Statement::LabeledStatement(l) => self.statement(&l.body),
            Statement::ReturnStatement(r) => {
                if let Some(a) = &r.argument {
                    self.expr(a, true);
                }
            }
            Statement::ThrowStatement(t) => self.expr(&t.argument, true),
            Statement::SwitchStatement(sw) => {
                self.expr(&sw.discriminant, false);
                for c in &sw.cases {
                    if let Some(t) = &c.test {
                        self.expr(t, false);
                    }
                    self.statements(&c.consequent);
                }
            }
            Statement::TryStatement(t) => {
                self.statements(&t.block.body);
                if let Some(h) = &t.handler {
                    self.statements(&h.body.body);
                }
                if let Some(f) = &t.finalizer {
                    self.statements(&f.body);
                }
            }
            Statement::WithStatement(w) => {
                let head = oxc_span::Span::new(w.span.start, w.object.span().end + 1);
                let head = if head.end <= w.span.end { head } else { w.span };
                self.construct(ConstructKind::ScopeInjection, head);
                self.expr(&w.object, false);
                self.statement(&w.body);
            }
            Statement::VariableDeclaration(d) => self.var_decl(d, false),
            Statement::FunctionDeclaration(f) => self.function_decl(f, None),
            Statement::ClassDeclaration(c) => self.class(c, None),
            Statement::TSEnumDeclaration(e) => {
                if !e.declare {
                    for m in &e.body.members {
                        if let Some(i) = &m.initializer {
                            self.expr(i, false);
                        }
                    }
                }
            }
            Statement::TSNamespaceDeclaration(n) => {
                if !n.declare {
                    self.namespace(n);
                }
            }
            Statement::TSImportEqualsDeclaration(d) => self.import_equals(d, false),
            Statement::ImportDeclaration(d) => self.import_decl(d),
            Statement::ExportAllDeclaration(d) => {
                let type_only = d.export_kind == ImportOrExportKind::Type;
                let spec = d.source.value.as_str();
                match &d.exported {
                    None => {
                        self.import(None, spec, Vec::new(), type_only, true, true, false, d.span)
                    }
                    Some(n) => self.import(
                        Some(n.name().to_string()),
                        spec,
                        Vec::new(),
                        type_only,
                        false,
                        true,
                        false,
                        d.span,
                    ),
                }
            }
            Statement::ExportFromDeclaration(d) => {
                let spec = d.source.value.as_str();
                for x in &d.specifiers {
                    let type_only = d.export_kind == ImportOrExportKind::Type
                        || x.export_kind == ImportOrExportKind::Type;
                    let local = x.local.name().to_string();
                    let exported = x.exported.name().to_string();
                    let default = local == "default";
                    self.import(
                        Some(exported),
                        spec,
                        vec![local],
                        type_only,
                        false,
                        true,
                        default,
                        x.span,
                    );
                }
            }
            Statement::ExportNamedDeclaration(d) => {
                if d.export_kind == ImportOrExportKind::Type {
                    return;
                }
                for x in &d.specifiers {
                    if x.export_kind == ImportOrExportKind::Type {
                        continue;
                    }
                    let local = x.local.name().to_string();
                    let exported = x.exported.name().to_string();
                    if let Some(imp) = self
                        .ir
                        .imports
                        .iter()
                        .find(|i| {
                            !i.re_export && !i.star && i.local.as_deref() == Some(local.as_str())
                        })
                        .cloned()
                    {
                        self.ir.imports.push(ir::Import {
                            local: Some(exported),
                            re_export: true,
                            span: Self::span(x.span),
                            location: self.loc(x.span),
                            ..imp
                        });
                    } else if local != exported {
                        self.ir.constants.push(ir::ModuleConstant {
                            name: exported,
                            value: Expr::Name(local),
                            exported: true,
                            span: Self::span(x.span),
                        });
                    }
                }
            }
            Statement::ExportDeclaration(e) => match &e.declaration {
                Declaration::VariableDeclaration(d) => self.var_decl(d, true),
                Declaration::FunctionDeclaration(f) => self.function_decl(f, None),
                Declaration::ClassDeclaration(c) => self.class(c, None),
                Declaration::TSImportEqualsDeclaration(d) => self.import_equals(d, true),
                Declaration::TSEnumDeclaration(en) => {
                    for m in &en.body.members {
                        if let Some(i) = &m.initializer {
                            self.expr(i, false);
                        }
                    }
                }
                Declaration::TSNamespaceDeclaration(n) if !n.declare => self.namespace(n),
                _ => {}
            },
            Statement::ExportDefaultDeclaration(d) => match &d.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                    self.function_decl(f, Some("default".into()))
                }
                ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                    self.class(c, Some("default".into()))
                }
                ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => {}
                other => {
                    if let Some(e) = other.as_expression() {
                        if let Expression::Identifier(id) = e.get_inner_expression()
                            && let Root::Import(local) = self.ident_root(id)
                            && let Some(imp) = self
                                .ir
                                .imports
                                .iter()
                                .find(|i| i.local.as_deref() == Some(local.as_str()))
                                .cloned()
                        {
                            self.ir.imports.push(ir::Import {
                                local: Some("default".into()),
                                re_export: true,
                                ..imp
                            });
                        } else if !is_function_like(e) {
                            let v = self.lower_expr(e);
                            self.ir.constants.push(ir::ModuleConstant {
                                name: "default".into(),
                                value: v,
                                exported: true,
                                span: Self::span(d.span),
                            });
                        }
                        self.expr_named(e, true, Some("default".into()));
                    }
                }
            },
            Statement::TSExportAssignment(a) => self.expr(&a.expression, true),
            _ => {}
        }
    }

    fn namespace(&mut self, n: &TSNamespaceDeclaration<'a>) {
        match &n.body {
            TSNamespaceDeclarationBody::TSModuleBlock(b) => self.statements(&b.body),
            TSNamespaceDeclarationBody::TSNamespaceDeclaration(inner) => self.namespace(inner),
        }
    }

    fn import_decl(&mut self, d: &ImportDeclaration<'a>) {
        let spec = d.source.value.as_str();
        let decl_type = d.import_kind == ImportOrExportKind::Type;
        let Some(specs) = &d.specifiers else {
            self.import(
                None,
                spec,
                Vec::new(),
                decl_type,
                false,
                false,
                false,
                d.span,
            );
            return;
        };
        if specs.is_empty() {
            self.import(
                None,
                spec,
                Vec::new(),
                decl_type,
                false,
                false,
                false,
                d.span,
            );
        }
        for s in specs {
            match s {
                ImportDeclarationSpecifier::ImportSpecifier(x) => {
                    let imported = x.imported.name().to_string();
                    let default = imported == "default";
                    let type_only = decl_type || x.import_kind == ImportOrExportKind::Type;
                    self.import(
                        Some(x.local.name.as_str().to_string()),
                        spec,
                        vec![imported],
                        type_only,
                        false,
                        false,
                        default,
                        x.span,
                    );
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(x) => self.import(
                    Some(x.local.name.as_str().to_string()),
                    spec,
                    Vec::new(),
                    decl_type,
                    false,
                    false,
                    true,
                    x.span,
                ),
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(x) => self.import(
                    Some(x.local.name.as_str().to_string()),
                    spec,
                    Vec::new(),
                    decl_type,
                    false,
                    false,
                    false,
                    x.span,
                ),
            }
        }
    }

    fn import_equals(&mut self, d: &TSImportEqualsDeclaration<'a>, exported: bool) {
        if let TSModuleReference::ExternalModuleReference(r) = &d.module_reference {
            let type_only = d.import_kind == ImportOrExportKind::Type;
            let name = d.id.name.as_str().to_string();
            self.import(
                Some(name.clone()),
                r.expression.value.as_str(),
                Vec::new(),
                type_only,
                false,
                false,
                true,
                d.span,
            );
            if exported {
                self.import(
                    Some(name),
                    r.expression.value.as_str(),
                    Vec::new(),
                    type_only,
                    false,
                    true,
                    true,
                    d.span,
                );
            }
        }
    }

    fn var_decl(&mut self, d: &VariableDeclaration<'a>, exported: bool) {
        if d.declare {
            return;
        }
        for decl in &d.declarations {
            let Some(init) = &decl.init else {
                continue;
            };
            match &decl.id {
                BindingPattern::BindingIdentifier(id) => {
                    let name = id.name.as_str().to_string();
                    let sym = id.symbol_id.get();
                    // `const require = createRequire(import.meta.url)`.
                    if let Expression::CallExpression(c) = init.get_inner_expression()
                        && self.is_create_require(&c.callee)
                    {
                        if let Some(s) = sym {
                            self.loader_syms.insert(s);
                        }
                        continue;
                    }
                    if let Some((spec, members, default)) = self.loader_binding(init) {
                        if let Some(s) = sym {
                            self.import_syms.insert(s, name.clone());
                        }
                        self.import(
                            Some(name),
                            &spec,
                            members,
                            false,
                            false,
                            false,
                            default,
                            decl.span,
                        );
                        if exported {
                            self.re_export_last();
                        }
                        continue;
                    }
                    if let Some(s) = sym {
                        if self.is_ctor_access(init) {
                            self.ctor_alias_syms.insert(s);
                        }
                        let k = self.init_kind(init);
                        self.inits.insert(s, k);
                    }
                    self.expr_named(init, true, Some(name.clone()));
                    let single = d.kind == VariableDeclarationKind::Const
                        || sym.is_some_and(|s| !self.scoping.symbol_is_mutated(s));
                    if single {
                        let value = self.binding_value(init);
                        if self.owner().path == "<module>" {
                            self.ir.constants.push(ir::ModuleConstant {
                                name,
                                value,
                                exported,
                                span: Self::span(decl.span),
                            });
                        } else {
                            let symbol = self.symbol();
                            self.ir.locals.push(ir::LocalBinding {
                                symbol,
                                name,
                                value,
                                span: Self::span(decl.span),
                            });
                        }
                    }
                }
                BindingPattern::ObjectPattern(p) => {
                    if let Some((spec, members, _)) = self.loader_binding(init) {
                        for prop in &p.properties {
                            let (Some(key), BindingPattern::BindingIdentifier(id)) =
                                (key_name(&prop.key), &prop.value)
                            else {
                                continue;
                            };
                            let mut m = members.clone();
                            m.push(key);
                            if let Some(s) = id.symbol_id.get() {
                                self.import_syms.insert(s, id.name.as_str().to_string());
                            }
                            self.import(
                                Some(id.name.as_str().to_string()),
                                &spec,
                                m,
                                false,
                                false,
                                false,
                                false,
                                prop.span,
                            );
                            if exported {
                                self.re_export_last();
                            }
                        }
                        if let Some(rest) = &p.rest
                            && let BindingPattern::BindingIdentifier(id) = &rest.argument
                        {
                            self.import(
                                Some(id.name.as_str().to_string()),
                                &spec,
                                members,
                                false,
                                false,
                                false,
                                true,
                                rest.span,
                            );
                            if exported {
                                self.re_export_last();
                            }
                        }
                        continue;
                    }
                    self.expr(init, true);
                    // `const { a } = obj` binds `a` as an alias of `obj.a`.
                    if let Some((root, members)) = self.static_chain(init) {
                        for prop in &p.properties {
                            let (Some(key), BindingPattern::BindingIdentifier(id)) =
                                (key_name(&prop.key), &prop.value)
                            else {
                                continue;
                            };
                            let mut m = members.clone();
                            m.push(key);
                            let r = self.reference(
                                root.clone(),
                                m,
                                UseKind::ValueEscape,
                                Vec::new(),
                                None,
                                prop.span,
                            );
                            let value = Expr::Reference(Box::new(r));
                            let name = id.name.as_str().to_string();
                            if self.owner().path == "<module>" {
                                self.ir.constants.push(ir::ModuleConstant {
                                    name,
                                    value,
                                    exported,
                                    span: Self::span(prop.span),
                                });
                            } else {
                                let symbol = self.symbol();
                                self.ir.locals.push(ir::LocalBinding {
                                    symbol,
                                    name,
                                    value,
                                    span: Self::span(prop.span),
                                });
                            }
                        }
                    }
                }
                _ => self.expr(init, true),
            }
        }
    }

    /// Re-exports the import just recorded under its own name, for
    /// `export const x = require("m").f` and `await import("m")` forms.
    fn re_export_last(&mut self) {
        if let Some(imp) = self.ir.imports.last().cloned() {
            self.ir.imports.push(ir::Import {
                re_export: true,
                ..imp
            });
        }
    }

    /// `x.constructor` on a receiver that is not `this` or a fresh
    /// instance.
    fn is_ctor_access(&self, e: &Expression<'a>) -> bool {
        let Some(m) = e.get_inner_expression().get_member_expr() else {
            return false;
        };
        if m.static_property_name() != Some("constructor") {
            return false;
        }
        !matches!(
            m.object().get_inner_expression(),
            Expression::ThisExpression(_) | Expression::NewExpression(_)
        )
    }

    // ---- functions and classes ---------------------------------------------------------------

    fn params(&mut self, params: &FormalParameters<'a>, frame: usize, owner: bool) -> Vec<String> {
        let mut names = Vec::new();
        for (i, p) in params.items.iter().enumerate() {
            let idx = u32::try_from(i + 1).unwrap_or(u32::MAX);
            match &p.pattern {
                BindingPattern::BindingIdentifier(id) => {
                    names.push(id.name.as_str().to_string());
                    if let Some(s) = id.symbol_id.get()
                        && owner
                    {
                        self.params.insert(s, (frame, idx));
                    }
                }
                BindingPattern::AssignmentPattern(a) => {
                    if let BindingPattern::BindingIdentifier(id) = &a.left {
                        names.push(id.name.as_str().to_string());
                        if let Some(s) = id.symbol_id.get()
                            && owner
                        {
                            self.params.insert(s, (frame, idx));
                        }
                    } else {
                        names.push("<pattern>".into());
                    }
                }
                _ => names.push("<pattern>".into()),
            }
        }
        if let Some(r) = &params.rest {
            match &r.rest.argument {
                BindingPattern::BindingIdentifier(id) => {
                    names.push(format!("...{}", id.name.as_str()))
                }
                _ => names.push("...<pattern>".into()),
            }
        }
        // Default values evaluate in the function's scope.
        for p in &params.items {
            if let Some(init) = &p.initializer {
                self.expr(init, true);
            }
            if let BindingPattern::AssignmentPattern(a) = &p.pattern {
                self.expr(&a.right, true);
            }
            for d in &p.decorators {
                self.expr(&d.expression, false);
            }
        }
        names
    }

    fn strict(&self, scope: Option<oxc_syntax::scope::ScopeId>) -> bool {
        scope.is_some_and(|s| self.scoping.scope_flags(s).is_strict_mode())
    }

    /// A function with a body: a symbol at `path`.
    fn function(
        &mut self,
        f: &Function<'a>,
        path: String,
        method: Option<(This, bool, Option<String>)>,
        kind: ir::SymbolKind,
    ) {
        let Some(body) = &f.body else { return };
        let strict = self.strict(f.scope_id.get());
        let (this, ctor, class) = match method {
            Some(m) => m,
            None => (
                if !strict && self.script {
                    This::Ambient
                } else {
                    This::Opaque
                },
                false,
                None,
            ),
        };
        self.push_frame(path.clone(), true, this, ctor, class);
        let id = self.frame().id;
        let names = self.params(&f.params, id, true);
        self.ir.symbols.push(ir::SymbolSpan {
            path,
            kind,
            params: names,
            strict: Some(strict),
            span: Self::span(f.span),
        });
        self.statements(&body.statements);
        self.frames.pop();
    }

    fn function_decl(&mut self, f: &Function<'a>, fallback: Option<String>) {
        let name =
            f.id.as_ref()
                .map(|i| i.name.as_str().to_string())
                .or(fallback)
                .unwrap_or_else(|| "<anonymous>".into());
        let path = join(&self.owner().path, &name);
        let kind = if self.owner().path == "<module>" {
            ir::SymbolKind::Function
        } else {
            ir::SymbolKind::Closure
        };
        self.function(f, path, None, kind);
    }

    fn arrow(&mut self, a: &ArrowFunctionExpression<'a>, name: Option<String>) {
        let parent = self.frame().clone();
        let strict = self.strict(a.scope_id.get());
        match &name {
            Some(n) => {
                let path = join(&self.owner().path, n);
                self.push_frame(
                    path.clone(),
                    true,
                    parent.this,
                    parent.ctor,
                    parent.class.clone(),
                );
                let id = self.frame().id;
                let names = self.params(&a.params, id, true);
                self.ir.symbols.push(ir::SymbolSpan {
                    path,
                    kind: ir::SymbolKind::Binding,
                    params: names,
                    strict: Some(strict),
                    span: Self::span(a.span),
                });
            }
            None => {
                self.push_frame(
                    parent.path.clone(),
                    false,
                    parent.this,
                    parent.ctor,
                    parent.class.clone(),
                );
                let id = self.frame().id;
                self.params(&a.params, id, false);
            }
        }
        match &a.body {
            ArrowFunctionBody::FunctionBody(b) => self.statements(&b.statements),
            other => {
                if let Some(e) = other.as_expression() {
                    self.expr(e, true);
                }
            }
        }
        self.frames.pop();
    }

    fn class(&mut self, c: &Class<'a>, fallback: Option<String>) {
        if c.declare {
            return;
        }
        let name =
            c.id.as_ref()
                .map(|i| i.name.as_str().to_string())
                .or(fallback)
                .unwrap_or_else(|| "<anonymous>".into());
        let path = join(&self.owner().path, &name);
        self.ir.symbols.push(ir::SymbolSpan {
            path: path.clone(),
            kind: ir::SymbolKind::Class,
            params: Vec::new(),
            strict: Some(true),
            span: Self::span(c.span),
        });
        for d in &c.decorators {
            self.expr(&d.expression, false);
        }
        if let Some(h) = &c.heritage {
            let sup = &h.expression;
            match self.static_chain(sup) {
                Some((root, members)) if !matches!(root, Root::Expression) => {
                    let mut r = self.reference(
                        root,
                        members,
                        UseKind::BaseClass,
                        Vec::new(),
                        None,
                        sup.span(),
                    );
                    r.symbol = path.clone();
                    self.emit(r);
                }
                _ => self.expr(sup, false),
            }
        }
        for el in &c.body.body {
            match el {
                ClassElement::MethodDefinition(m) => {
                    for d in &m.decorators {
                        self.expr(&d.expression, false);
                    }
                    if m.computed
                        && let Some(k) = m.key.as_expression()
                    {
                        self.expr(k, false);
                    }
                    let key = key_name(&m.key).unwrap_or_else(|| "<computed>".into());
                    let ctor = m.kind == MethodDefinitionKind::Constructor;
                    let mpath = format!("{path}.{key}");
                    self.function(
                        &m.value,
                        mpath,
                        Some((This::Class, ctor, Some(path.clone()))),
                        ir::SymbolKind::Method,
                    );
                }
                ClassElement::PropertyDefinition(p) => {
                    let key = key_name(&p.key).unwrap_or_else(|| "<computed>".into());
                    if let Some(v) = &p.value {
                        self.field(&path, &key, v, p.r#static, p.span);
                    }
                }
                ClassElement::AccessorProperty(p) => {
                    let key = key_name(&p.key).unwrap_or_else(|| "<computed>".into());
                    if let Some(v) = &p.value {
                        self.field(&path, &key, v, p.r#static, p.span);
                    }
                }
                ClassElement::StaticBlock(b) => {
                    self.push_frame(path.clone(), true, This::Opaque, false, Some(path.clone()));
                    self.statements(&b.body);
                    self.frames.pop();
                }
                ClassElement::TSIndexSignature(_) => {}
            }
        }
    }

    fn field(
        &mut self,
        class: &str,
        key: &str,
        v: &Expression<'a>,
        is_static: bool,
        span: oxc_span::Span,
    ) {
        let fpath = format!("{class}.{key}");
        let this = if is_static { This::Opaque } else { This::Class };
        if !is_static {
            // An instance field is an attribute assignment at construction.
            self.push_frame(fpath.clone(), true, this, true, Some(class.to_string()));
            let value = self.lower_expr(v);
            self.frames.pop();
            self.ir.self_attributes.push(ir::SelfAttribute {
                class: class.to_string(),
                attribute: key.to_string(),
                value,
                span: Self::span(span),
            });
        }
        match v.get_inner_expression() {
            Expression::ArrowFunctionExpression(a) => {
                self.push_frame(
                    class.to_string(),
                    false,
                    this,
                    false,
                    Some(class.to_string()),
                );
                self.arrow(a, Some(key.to_string()));
                self.frames.pop();
            }
            Expression::FunctionExpression(f) => {
                self.function(
                    f,
                    fpath,
                    Some((this, false, Some(class.to_string()))),
                    ir::SymbolKind::Method,
                );
            }
            _ => {
                self.push_frame(fpath, true, this, !is_static, Some(class.to_string()));
                self.expr(v, true);
                self.frames.pop();
            }
        }
    }

    // ---- expressions -------------------------------------------------------------------------

    fn expr(&mut self, e: &Expression<'a>, flow: bool) {
        self.expr_named(e, flow, None);
    }

    /// Walks `e`; `name` names a function, class, or object literal bound
    /// to a binding or key.
    fn expr_named(&mut self, e: &Expression<'a>, flow: bool, name: Option<String>) {
        if !self.enter() {
            self.leave();
            return;
        }
        self.expr_inner(e, flow, name);
        self.leave();
    }

    fn expr_inner(&mut self, e: &Expression<'a>, flow: bool, name: Option<String>) {
        match e {
            Expression::ParenthesizedExpression(p) => self.expr_named(&p.expression, flow, name),
            Expression::TSAsExpression(x) => self.expr_named(&x.expression, flow, name),
            Expression::TSSatisfiesExpression(x) => self.expr_named(&x.expression, flow, name),
            Expression::TSTypeAssertion(x) => self.expr_named(&x.expression, flow, name),
            Expression::TSNonNullExpression(x) => self.expr_named(&x.expression, flow, name),
            Expression::TSInstantiationExpression(x) => self.expr_named(&x.expression, flow, name),
            Expression::Identifier(id) => self.ident_use(id, flow),
            Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::PrivateFieldExpression(_) => self.member(e, flow, e.span()),
            Expression::ChainExpression(c) => match &c.expression {
                ChainElement::CallExpression(call) => self.call(call, flow),
                ChainElement::TSNonNullExpression(x) => self.expr(&x.expression, flow),
                _ => self.member(e, flow, e.span()),
            },
            Expression::CallExpression(c) => self.call(c, flow),
            Expression::NewExpression(n) => self.new_expr(n),
            Expression::TaggedTemplateExpression(t) => {
                match self.static_chain(&t.tag) {
                    Some((root, members)) if !matches!(root, Root::Expression) => {
                        let r =
                            self.reference(root, members, UseKind::Call, Vec::new(), None, t.span);
                        self.emit(r);
                    }
                    _ => self.expr(&t.tag, false),
                }
                for x in &t.quasi.expressions {
                    self.expr(x, false);
                }
            }
            Expression::TemplateLiteral(t) => {
                for x in &t.expressions {
                    self.expr(x, false);
                }
            }
            Expression::ArrayExpression(a) => {
                for el in &a.elements {
                    match el {
                        ArrayExpressionElement::SpreadElement(s) => self.expr(&s.argument, true),
                        ArrayExpressionElement::Elision(_) => {}
                        other => {
                            if let Some(x) = other.as_expression() {
                                self.expr(x, true);
                            }
                        }
                    }
                }
            }
            Expression::ObjectExpression(o) => self.object(o, name),
            Expression::ArrowFunctionExpression(a) => self.arrow(a, name),
            Expression::FunctionExpression(f) => {
                let n =
                    f.id.as_ref()
                        .map(|i| i.name.as_str().to_string())
                        .or(name)
                        .unwrap_or_else(|| "<anonymous>".into());
                let path = join(&self.owner().path, &n);
                self.function(f, path, None, ir::SymbolKind::Binding);
            }
            Expression::ClassExpression(c) => self.class(c, name),
            Expression::AssignmentExpression(a) => self.assign(a),
            Expression::AwaitExpression(a) => self.expr(&a.argument, flow),
            Expression::YieldExpression(y) => {
                if let Some(a) = &y.argument {
                    self.expr(a, true);
                }
            }
            Expression::BinaryExpression(b) => {
                self.expr(&b.left, false);
                self.expr(&b.right, false);
            }
            Expression::PrivateInExpression(p) => self.expr(&p.right, false),
            Expression::LogicalExpression(l) => {
                self.expr(&l.left, flow);
                self.expr(&l.right, flow);
            }
            Expression::ConditionalExpression(c) => {
                self.expr(&c.test, false);
                self.expr(&c.consequent, flow);
                self.expr(&c.alternate, flow);
            }
            Expression::SequenceExpression(s) => {
                let n = s.expressions.len();
                for (i, x) in s.expressions.iter().enumerate() {
                    self.expr(x, flow && i + 1 == n);
                }
            }
            Expression::UnaryExpression(u) => {
                if u.operator == UnaryOperator::Delete {
                    self.write_target_expr(&u.argument, u.span);
                } else {
                    self.expr(&u.argument, false);
                }
            }
            Expression::UpdateExpression(u) => {
                if let Some(m) = u.argument.as_member_expression() {
                    self.member_write(m, u.argument.span(), None);
                }
            }
            Expression::ImportExpression(i) => {
                match lit_str(&i.source) {
                    Some(spec) => {
                        let local = self.import_expression_synthetic(i, &spec);
                        // A loaded module whose value flows (returned,
                        // assigned, passed, or a `.then` receiver) escapes,
                        // as for a literal `require()`.
                        if flow {
                            let r = self.reference(
                                Root::Import(local),
                                Vec::new(),
                                UseKind::ValueEscape,
                                Vec::new(),
                                None,
                                i.span,
                            );
                            self.emit(r);
                        }
                    }
                    None => {
                        self.construct(ConstructKind::DynamicImport, i.span);
                        self.expr(&i.source, true);
                    }
                }
                if let Some(o) = &i.options {
                    self.expr(o, false);
                }
            }
            Expression::JSXElement(el) => self.jsx_element(el),
            Expression::JSXFragment(f) => self.jsx_children(&f.children),
            Expression::V8IntrinsicExpression(v) => {
                for a in &v.arguments {
                    if let Some(x) = a.as_expression() {
                        self.expr(x, true);
                    }
                }
            }
            _ => {}
        }
    }

    fn object(&mut self, o: &ObjectExpression<'a>, name: Option<String>) {
        for p in &o.properties {
            match p {
                ObjectPropertyKind::SpreadProperty(s) => self.expr(&s.argument, true),
                ObjectPropertyKind::ObjectProperty(p) => {
                    if p.computed
                        && let Some(k) = p.key.as_expression()
                    {
                        self.expr(k, false);
                    }
                    let key = key_name(&p.key).unwrap_or_else(|| "<computed>".into());
                    let full = match &name {
                        Some(n) => format!("{n}.{key}"),
                        None => key.clone(),
                    };
                    match &p.value {
                        Expression::FunctionExpression(f)
                            if p.method || p.kind != PropertyKind::Init || f.id.is_none() =>
                        {
                            let path = join(&self.owner().path, &full);
                            // Object-literal methods: `this` is the object.
                            self.function(
                                f,
                                path,
                                Some((This::Opaque, false, None)),
                                ir::SymbolKind::Binding,
                            );
                        }
                        v => self.expr_named(v, true, Some(full)),
                    }
                }
            }
        }
    }

    fn jsx_element(&mut self, el: &JSXElement<'a>) {
        for a in &el.opening_element.attributes {
            match a {
                JSXAttributeItem::Attribute(at) => match &at.value {
                    Some(JSXAttributeValue::ExpressionContainer(c)) => {
                        if let Some(x) = c.expression.as_expression() {
                            self.expr(x, true);
                        }
                    }
                    Some(JSXAttributeValue::Element(e)) => self.jsx_element(e),
                    Some(JSXAttributeValue::Fragment(f)) => self.jsx_children(&f.children),
                    _ => {}
                },
                JSXAttributeItem::SpreadAttribute(s) => self.expr(&s.argument, true),
            }
        }
        self.jsx_children(&el.children);
    }

    fn jsx_children(&mut self, children: &[JSXChild<'a>]) {
        if !self.enter() {
            self.leave();
            return;
        }
        for c in children {
            match c {
                JSXChild::Element(e) => self.jsx_element(e),
                JSXChild::Fragment(f) => self.jsx_children(&f.children),
                JSXChild::ExpressionContainer(x) => {
                    if let Some(e) = x.expression.as_expression() {
                        self.expr(e, true);
                    }
                }
                JSXChild::Spread(s) => self.expr(&s.expression, true),
                JSXChild::Text(_) => {}
            }
        }
        self.leave();
    }

    fn ident_use(&mut self, id: &IdentifierReference<'a>, flow: bool) {
        if !flow {
            return;
        }
        if self.is_loader_ident(id) {
            self.construct(ConstructKind::RequireAsValue, id.span);
            return;
        }
        let root = self.ident_root(id);
        if matches!(root, Root::Import(_) | Root::Ambient(_) | Root::Local(_)) {
            let r = self.reference(
                root,
                Vec::new(),
                UseKind::ValueEscape,
                Vec::new(),
                None,
                id.span,
            );
            self.emit(r);
        }
    }

    /// The object and key of a computed member with a non-literal key.
    fn computed_parts<'e>(
        e: &'e Expression<'a>,
    ) -> Option<(&'e Expression<'a>, &'e Expression<'a>)> {
        let m = match e.get_inner_expression() {
            Expression::ComputedMemberExpression(m) => m,
            Expression::ChainExpression(c) => match &c.expression {
                ChainElement::ComputedMemberExpression(m) => m,
                _ => return None,
            },
            _ => return None,
        };
        let literal = lit_str(&m.expression).is_some()
            || matches!(
                m.expression.get_inner_expression(),
                Expression::NumericLiteral(_)
            );
        (!literal).then_some((&m.object, &m.expression))
    }

    /// The object of a member expression.
    fn member_object<'e>(e: &'e Expression<'a>) -> Option<&'e Expression<'a>> {
        match e.get_inner_expression() {
            Expression::ChainExpression(c) => {
                c.expression.as_member_expression().map(|m| m.object())
            }
            other => other.get_member_expr().map(|m| m.object()),
        }
    }

    /// A member expression read; `text` is the span the reference reports.
    fn member(&mut self, e: &Expression<'a>, flow: bool, text: oxc_span::Span) {
        if let Some((obj, key)) = Self::computed_parts(e) {
            let receiver = self.provenance(obj);
            match self.static_chain(obj) {
                Some((root, members)) => {
                    let r = self.reference(
                        root,
                        members,
                        UseKind::ComputedMember,
                        Vec::new(),
                        Some(receiver),
                        text,
                    );
                    self.emit(r);
                }
                None => {
                    let r = self.reference(
                        Root::Expression,
                        Vec::new(),
                        UseKind::ComputedMember,
                        Vec::new(),
                        Some(receiver),
                        text,
                    );
                    self.emit(r);
                    self.expr(obj, false);
                }
            }
            self.expr(key, false);
            return;
        }
        // `require.call` and the like read as values are loaders too.
        if flow
            && ["call", "apply", "bind"]
                .iter()
                .any(|m| self.loader_method(e, m))
        {
            self.construct(ConstructKind::RequireAsValue, text);
            return;
        }
        match self.static_chain(e) {
            Some((root, members)) => {
                if flow && !matches!(root, Root::Param(_) | Root::Expression) {
                    let r =
                        self.reference(root, members, UseKind::ValueEscape, Vec::new(), None, text);
                    self.emit(r);
                }
            }
            None => {
                if let Some(obj) = Self::member_object(e) {
                    // A member of an `import()` promise (`.then`) reads
                    // the module value.
                    let import =
                        matches!(obj.get_inner_expression(), Expression::ImportExpression(_));
                    self.expr(obj, import);
                }
            }
        }
    }

    fn ctor_chain_call(&mut self, callee: &Expression<'a>) -> bool {
        if self.is_ctor_access(callee) {
            return true;
        }
        if let Expression::Identifier(id) = callee.get_inner_expression()
            && let Some(s) = self.ident_sym(id)
        {
            return self.ctor_alias_syms.contains(&s);
        }
        false
    }

    fn timer_with_string(&mut self, c: &CallExpression<'a>) -> bool {
        let Some(first) = c.arguments.first().and_then(Argument::as_expression) else {
            return false;
        };
        if !stringish(first) {
            return false;
        }
        match self.static_chain(&c.callee) {
            Some((Root::Ambient(r), m)) => {
                let timer = |n: &str| n == "setTimeout" || n == "setInterval";
                (m.is_empty() && timer(&r))
                    || (GLOBAL_NAMES.contains(&r.as_str()) && m.len() == 1 && timer(&m[0]))
            }
            _ => false,
        }
    }

    fn call(&mut self, c: &CallExpression<'a>, flow: bool) {
        if let Some(l) = self.loader(c) {
            match l.spec {
                Some(spec) => {
                    let local = self.synthetic_import(c, &spec);
                    // A loaded module whose value flows (passed, stored,
                    // returned, or exported through `module.exports`) is a
                    // module used as a value: an escape.
                    if flow {
                        let r = self.reference(
                            Root::Import(local),
                            Vec::new(),
                            UseKind::ValueEscape,
                            Vec::new(),
                            None,
                            c.span,
                        );
                        self.emit(r);
                    }
                }
                None => {
                    self.construct(ConstructKind::DynamicImport, c.span);
                    for a in &c.arguments {
                        if let Some(x) = a.as_expression() {
                            self.expr(x, true);
                        }
                    }
                }
            }
            // A wrapped loader callee (`(f(), require)`, `c && require`)
            // can hold uses of its own; `require` itself reads as a test.
            match c.callee.get_inner_expression() {
                Expression::Identifier(_) => {}
                Expression::CallExpression(inner) => self.args(&inner.arguments),
                other => self.expr(other, false),
            }
            return;
        }
        let callee = c.callee.get_inner_expression();
        // `require.bind(this)` makes a loader whose calls are not followed.
        if self.loader_method(callee, "bind") {
            self.construct(ConstructKind::RequireAsValue, c.span);
            self.args(&c.arguments);
            return;
        }
        if self.ctor_chain_call(callee) {
            self.construct(ConstructKind::ConstructorChain, c.span);
            if let Some(obj) = Self::member_object(callee) {
                self.expr(obj, false);
            }
            self.args(&c.arguments);
            return;
        }
        if self.timer_with_string(c) {
            self.construct(ConstructKind::DynamicCode, c.span);
        }
        if Self::computed_parts(callee).is_some() {
            self.member(callee, false, c.span);
        } else if let Expression::SequenceExpression(s) = callee
            && let Some((last, rest)) = s.expressions.split_last()
        {
            // `(0, mod.fn)(x)`, the bundler call form.
            for x in rest {
                self.expr(x, false);
            }
            match self.static_chain(last) {
                Some((root, members)) if !matches!(root, Root::Expression) => {
                    let args = self.args_expr(&c.arguments);
                    let r = self.reference(root, members, UseKind::Call, args, None, c.span);
                    self.emit(r);
                }
                _ => self.expr(last, false),
            }
        } else {
            match self.call_reference(c) {
                // A method on an opaque `this` stays visible as an
                // expression-rooted call; the core gives it no bucket.
                Some(r) if !(matches!(r.root, Root::Expression) && r.members.is_empty()) => {
                    self.emit(r);
                }
                Some(_) => {}
                None => self.expr(callee, false),
            }
        }
        self.args(&c.arguments);
    }

    fn args(&mut self, args: &[Argument<'a>]) {
        for a in args {
            match a {
                Argument::SpreadElement(s) => self.expr(&s.argument, true),
                other => {
                    if let Some(x) = other.as_expression() {
                        self.expr(x, true);
                    }
                }
            }
        }
    }

    fn new_expr(&mut self, n: &NewExpression<'a>) {
        let callee = n.callee.get_inner_expression();
        if self.ctor_chain_call(callee) {
            self.construct(ConstructKind::ConstructorChain, n.span);
            if let Some(obj) = Self::member_object(callee) {
                self.expr(obj, false);
            }
            self.args(&n.arguments);
            return;
        }
        if Self::computed_parts(callee).is_some() {
            self.member(callee, false, n.span);
        } else {
            match self.static_chain(callee) {
                Some((root, members)) if !matches!(root, Root::Expression) => {
                    let args = self.args_expr(&n.arguments);
                    let r = self.reference(root, members, UseKind::Construct, args, None, n.span);
                    self.emit(r);
                }
                Some(_) => {}
                None => self.expr(callee, false),
            }
        }
        self.args(&n.arguments);
    }

    /// The name a function assigned to `target` takes.
    fn target_name(&self, target: &AssignmentTarget<'a>) -> Option<String> {
        let text = self.src(target.span());
        if text == "module.exports" || text == "exports" {
            return None;
        }
        let t = text
            .strip_prefix("module.exports.")
            .or_else(|| text.strip_prefix("exports."))
            .unwrap_or(text);
        t.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '.')
            .then(|| t.to_string())
    }

    /// The import a value re-exports when it is a static chain on an import
    /// binding (`https`, `https.get`, `require("net")`): the binding's
    /// import with the chain's members appended. A whole-module default
    /// binding takes `default` first, as an ESM default import does.
    fn re_export_of(&mut self, value: &Expression<'a>) -> Option<ir::Import> {
        let (root, members) = self.static_chain(value)?;
        let Root::Import(local) = root else {
            return None;
        };
        let mut imp = self
            .ir
            .imports
            .iter()
            .rev()
            .find(|i| !i.re_export && !i.star && i.local.as_deref() == Some(local.as_str()))
            .cloned()?;
        if !members.is_empty() {
            if imp.default && imp.members.is_empty() {
                imp.members.push("default".into());
            }
            imp.default = imp.members.first().is_some_and(|m| m == "default");
            imp.members.extend(members);
        }
        Some(imp)
    }

    /// CommonJS exports at module level lowered as re-exports, so importers
    /// resolve through them as through ESM `export ... from`:
    /// `module.exports = X` re-exports `X` as `default`, and
    /// `exports.n = X`, `module.exports.n = X`, and each literal key of
    /// `module.exports = { n: X }` re-export `X` as `n`. The value is still
    /// walked, so a module or egress member exported as a value keeps its
    /// escape or value-use site.
    fn cjs_exports(&mut self, target: &AssignmentTarget<'a>, value: &Expression<'a>) {
        if self.symbol() != "<module>" {
            return;
        }
        let text = self.src(target.span());
        let push = |this: &mut Self, name: String, v: &Expression<'a>, span: oxc_span::Span| {
            if let Some(imp) = this.re_export_of(v) {
                this.ir.imports.push(ir::Import {
                    local: Some(name),
                    re_export: true,
                    symbol: "<module>".into(),
                    span: Self::span(span),
                    location: this.loc(span),
                    ..imp
                });
            }
        };
        if text == "module.exports" {
            match value.get_inner_expression() {
                Expression::ObjectExpression(o) => {
                    for p in &o.properties {
                        let ObjectPropertyKind::ObjectProperty(p) = p else {
                            continue;
                        };
                        if p.method || p.kind != PropertyKind::Init {
                            continue;
                        }
                        if let Some(k) = key_name(&p.key) {
                            push(self, k, &p.value, p.span);
                        }
                    }
                }
                v => push(self, "default".into(), v, value.span()),
            }
            return;
        }
        let name = text
            .strip_prefix("module.exports.")
            .or_else(|| text.strip_prefix("exports."));
        if let Some(n) = name
            && !n.is_empty()
            && n.chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
        {
            push(self, n.to_string(), value, value.span());
        }
    }

    fn assign(&mut self, a: &AssignmentExpression<'a>) {
        if a.operator == AssignmentOperator::Assign {
            self.cjs_exports(&a.left, &a.right);
        }
        let name = self.target_name(&a.left);
        self.expr_named(&a.right, true, name);
        match &a.left {
            AssignmentTarget::AssignmentTargetIdentifier(_) => {}
            t => {
                if let Some(m) = t.as_member_expression() {
                    self.member_write(m, t.span(), Some(&a.right));
                }
            }
        }
    }

    fn write_target_expr(&mut self, e: &Expression<'a>, _span: oxc_span::Span) {
        match e.get_inner_expression().get_member_expr() {
            Some(m) => self.member_write(m, e.get_inner_expression().span(), None),
            None => self.expr(e, false),
        }
    }

    /// A write to a member: `this.attr` facts, import-system writes,
    /// and assignment-target references.
    fn member_write(
        &mut self,
        m: &MemberExpression<'a>,
        span: oxc_span::Span,
        value: Option<&Expression<'a>>,
    ) {
        let obj = m.object();
        let computed_key = match m {
            MemberExpression::ComputedMemberExpression(c)
                if lit_str(&c.expression).is_none()
                    && !matches!(
                        c.expression.get_inner_expression(),
                        Expression::NumericLiteral(_)
                    ) =>
            {
                Some(&c.expression)
            }
            _ => None,
        };
        let chain = match computed_key {
            Some(_) => self.static_chain(obj),
            None => {
                let mut members = Vec::new();
                let tail = match m {
                    MemberExpression::StaticMemberExpression(s) => {
                        Some(s.property.name.as_str().to_string())
                    }
                    MemberExpression::ComputedMemberExpression(c) => {
                        match c.expression.get_inner_expression() {
                            Expression::NumericLiteral(n) => Some(self.src(n.span).to_string()),
                            k => lit_str(k),
                        }
                    }
                    MemberExpression::PrivateFieldExpression(p) => {
                        Some(format!("#{}", p.field.name.as_str()))
                    }
                };
                self.static_chain(obj).and_then(|(root, mut ms)| {
                    ms.push(tail?);
                    members.append(&mut ms);
                    Some((root, members))
                })
            }
        };
        let Some((root, members)) = chain else {
            self.expr(obj, false);
            if let Some(k) = computed_key {
                self.expr(k, false);
            }
            return;
        };
        if let Some(k) = computed_key {
            self.expr(k, false);
        }
        // Writes into the CommonJS loader's own state.
        if let Root::Ambient(r) = &root {
            let first = members.first().map(String::as_str);
            let loader_state = (r == "require" && first == Some("cache"))
                || (r == "module" && first == Some("constructor"));
            if loader_state {
                self.construct(ConstructKind::ImportSystemMutation, span);
                return;
            }
            if (r == "module" && first == Some("exports")) || r == "exports" {
                return;
            }
        }
        if computed_key.is_some() {
            let receiver = self.provenance(obj);
            let r = self.reference(
                root,
                members,
                UseKind::ComputedMember,
                Vec::new(),
                Some(receiver),
                span,
            );
            self.emit(r);
            return;
        }
        let frame = self.frame().clone();
        if root == Root::SelfValue
            && members.len() == 1
            && frame.ctor
            && frame.this == This::Class
            && let (Some(class), Some(v)) = (frame.class.clone(), value)
        {
            let value = self.lower_expr(v);
            self.ir.self_attributes.push(ir::SelfAttribute {
                class,
                attribute: members[0].clone(),
                value,
                span: Self::span(span),
            });
            return;
        }
        if matches!(root, Root::Expression | Root::Param(_)) && root != Root::SelfValue {
            return;
        }
        let r = self.reference(
            root,
            members,
            UseKind::AssignmentTarget,
            Vec::new(),
            None,
            span,
        );
        self.emit(r);
    }
}

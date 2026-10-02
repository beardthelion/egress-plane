//! Language-neutral intermediate representation (KTD4).
//!
//! Each frontend lowers one file to a [`FileIr`]. The IR records facts that
//! syntax and the frontend's own binding rules establish, and no
//! classification: what a binding means (primitive, catalogued, inert,
//! unscanned) is decided in the core. Names are runtime-normalized by the
//! frontend before they reach the IR: Python identifiers NFKC-normalized and
//! JS identifier escapes decoded.

use crate::model::{Language, Location};

/// A byte range into the file's source text, half open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

/// Everything one file contributes to the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIr {
    pub language: Language,
    /// Imports, re-exports, and `use` items.
    pub imports: Vec<Import>,
    /// References in every position the runtime evaluates.
    pub references: Vec<Reference>,
    /// Structural dynamic constructs (KTD15) that no data entry names.
    pub constructs: Vec<DynamicConstruct>,
    /// Enclosing symbol spans with parameter lists (KTD9).
    pub symbols: Vec<SymbolSpan>,
    /// Module-level single-assignment constants (KTD7).
    pub constants: Vec<ModuleConstant>,
    /// Single-assignment locals inside functions (KTD7, KTD8).
    pub locals: Vec<LocalBinding>,
    /// Attribute assignments on `self` or `this` inside `__init__` or a class
    /// `constructor` (KTD8).
    pub self_attributes: Vec<SelfAttribute>,
    /// Python attribute accesses whose name is a dunder or starts with `tb_`,
    /// `f_`, `gi_`, `cr_`, or `ag_` (KTD15).
    pub introspection: Vec<IntrospectionAccess>,
    /// Symbol paths whose findings take the `test` label: Rust `#[cfg(test)]`
    /// scopes and `#[test]` functions. A finding is in a scope when its symbol
    /// equals the scope or starts with the scope followed by `::`.
    pub test_scopes: Vec<String>,
}

impl FileIr {
    pub fn new(language: Language) -> Self {
        Self {
            language,
            imports: Vec::new(),
            references: Vec::new(),
            constructs: Vec::new(),
            symbols: Vec::new(),
            constants: Vec::new(),
            locals: Vec::new(),
            self_attributes: Vec::new(),
            introspection: Vec::new(),
            test_scopes: Vec::new(),
        }
    }
}

/// One import, re-export, or `use` binding. A loader call with a literal
/// specifier (`require("http")`, `__import__("os")`,
/// `importlib.import_module("json")`, TS `import x = require("net")`) is
/// lowered as an import too; the core gives the call itself no finding
/// (KTD15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The name bound in this file, or `None` for a star or glob import and a
    /// side-effect-only import (`import "x"`).
    pub local: Option<String>,
    /// The module specifier exactly as written after runtime normalization,
    /// for example `requests`, `./api`, `..util`, `node:https`, or
    /// `crate::net`.
    pub specifier: String,
    /// Member path below the specifier (`from a import b` gives `["b"]`;
    /// `import { get as g } from "axios"` gives `["get"]`).
    pub members: Vec<String>,
    /// True for a type-only import (`import type`, TS `import { type X }`).
    pub type_only: bool,
    /// True for `from m import *`, `export * from`, and Rust globs.
    pub star: bool,
    /// True when the binding is also exported from this module.
    pub re_export: bool,
    /// True for a JS default import or a CommonJS `require` binding of the
    /// whole module.
    pub default: bool,
    /// Enclosing symbol path, `<module>` at top level.
    pub symbol: String,
    pub span: Span,
    pub location: Location,
}

/// How a reference is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UseKind {
    Call,
    Construct,
    /// The reference is used as a value (passed, returned, stored).
    ValueEscape,
    AssignmentTarget,
    /// A computed member with a non-literal key.
    ComputedMember,
    BaseClass,
    TypePosition,
}

/// What the root of a member chain binds to, as the frontend resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    /// A name bound by an import in this file; the string is the local name.
    /// A name that only a star import can bind may also use this root; the
    /// core then looks it up through the file's star imports.
    Import(String),
    /// A definition in this file (function, class, local variable).
    Local(String),
    /// An ambient global the runtime provides (`fetch`, `open`, `globalThis`).
    Ambient(String),
    /// A parameter of the enclosing function, 1-based per KTD7.
    Param(u32),
    /// `self` or `this` inside a class member.
    SelfValue,
    /// The result of an expression the frontend does not name, such as a
    /// call result; its provenance is recorded separately.
    Expression,
}

/// Provenance of a receiver used with a computed or reflective non-literal
/// name (KTD4, KTD5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    Literal,
    ModuleBinding,
    AmbientModule,
    /// A tracked constructor result (KTD8).
    TrackedConstructor,
    FirstPartyCallResult,
    UnscannedCallResult,
    /// A parameter of the enclosing function, 1-based.
    Parameter(u32),
    Unknown,
}

/// One reference to a binding with a literal member chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub root: Root,
    /// Literal member chain after the root (`requests.Session().get` gives
    /// `["Session", "get"]` with `calls_in_chain` marking the call).
    pub members: Vec<String>,
    /// Indices into `members` after which the chain was called, so
    /// `a.b().c` records `[1]`.
    pub calls_in_chain: Vec<u32>,
    pub use_kind: UseKind,
    /// Positional arguments.
    pub args: Vec<Expr>,
    /// Keyword or named arguments in source order.
    pub kwargs: Vec<(String, Expr)>,
    /// Receiver provenance for a computed or reflective non-literal access.
    pub receiver: Option<Provenance>,
    /// Source text of the whole reference expression, for `expr:`
    /// destinations and blind-spot construct text.
    pub text: String,
    /// Enclosing symbol path, `<module>` at top level.
    pub symbol: String,
    pub span: Span,
    pub location: Location,
}

/// An argument or initializer expression as a small tree (KTD4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A string literal's runtime value, or a number's source text.
    Literal(String),
    /// A template, f-string, `format!`, or concatenation, as ordered parts.
    Template(Vec<Expr>),
    /// A name the resolver may look up as a local or module constant.
    Name(String),
    /// A parameter of the enclosing function, 1-based per KTD7.
    Param(u32),
    /// A nested reference, for example an environment read.
    Reference(Box<Reference>),
    /// A list, tuple, or array literal, elements in order
    /// (`["curl", url]`, `("host", 443)`).
    Sequence(Vec<Expr>),
    /// An object or dict literal with literal keys, in source order
    /// (`{ host: h, port: 80 }`).
    Object(Vec<(String, Expr)>),
    /// A subscript with a key, such as Python `os.environ["X"]`. A JS
    /// computed member with a literal key is lowered as a plain member
    /// instead.
    Subscript { base: Box<Expr>, key: Box<Expr> },
    /// Anything else, as source text.
    Opaque(String),
}

/// A structural dynamic construct (KTD15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicConstruct {
    pub kind: ConstructKind,
    /// Source text, redacted and truncated before output (KTD11).
    pub text: String,
    pub symbol: String,
    pub span: Span,
    pub location: Location,
}

/// The structural families from KTD15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConstructKind {
    /// `import()` or `require()` or a loader with a non-literal specifier.
    DynamicImport,
    /// `require` used as a value.
    RequireAsValue,
    /// JS `with`, `globals()`-style scope access.
    ScopeInjection,
    /// Writes to the import system.
    ImportSystemMutation,
    /// Raw native code: `extern` blocks, `asm!`, `#[link]`.
    NativeCode,
    /// `include!` with a non-literal path, first-party proc macro use.
    MacroCode,
    /// `.constructor` chains on a non-class receiver.
    ConstructorChain,
    /// A name the frontend stopped following at its own bound, such as a Rust
    /// `use` alias chain longer than the hop cap.
    ResolutionLimit,
}

/// The kind of an enclosing symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Closure,
    /// A JS `const` binding or literal object key that names a function.
    Binding,
    Module,
}

/// An enclosing symbol and its parameter list (KTD9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSpan {
    /// Symbol path per KTD9, for example `Client.send`, `api.post`,
    /// `<impl Api>::get`, or `outer.<locals>.inner`.
    pub path: String,
    pub kind: SymbolKind,
    /// Declared parameter names, excluding `self`, `cls`, and Rust receivers.
    pub params: Vec<String>,
    /// JS strictness of the function body; `None` outside JS.
    pub strict: Option<bool>,
    pub span: Span,
}

/// A module-level single-assignment constant (KTD7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleConstant {
    pub name: String,
    pub value: Expr,
    pub exported: bool,
    pub span: Span,
}

/// A single-assignment local inside a function (KTD7, KTD8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBinding {
    pub symbol: String,
    pub name: String,
    pub value: Expr,
    pub span: Span,
}

/// `self.attr = ...` in `__init__` or `this.attr = ...` in a `constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAttribute {
    /// The class path.
    pub class: String,
    pub attribute: String,
    pub value: Expr,
    pub span: Span,
}

/// A Python introspection attribute access (KTD15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionAccess {
    pub attribute: String,
    pub receiver: Provenance,
    pub text: String,
    pub symbol: String,
    pub span: Span,
    pub location: Location,
}

/// Maps byte offsets to 1-based [`Location`]s (KTD10). Lines count `\n` only,
/// so a CRLF file reports the same lines as its LF form; columns count
/// Unicode scalar values from the start of the line.
#[derive(Debug, Clone)]
pub struct LineIndex<'a> {
    source: &'a str,
    /// Byte offset of the start of each line.
    starts: Vec<usize>,
    /// Per line, the byte offset where its ASCII prefix ends: its first
    /// non-ASCII byte, or the end of the line. Columns up to it are byte
    /// offsets, so only the rest of the line is counted character by
    /// character.
    ascii_ends: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    pub fn new(source: &'a str) -> Self {
        let mut starts = vec![0];
        let mut ascii_ends = Vec::new();
        let mut first_non_ascii = None;
        for (i, b) in source.bytes().enumerate() {
            if !b.is_ascii() && first_non_ascii.is_none() {
                first_non_ascii = Some(i);
            }
            if b == b'\n' {
                ascii_ends.push(first_non_ascii.take().unwrap_or(i));
                starts.push(i + 1);
            }
        }
        ascii_ends.push(first_non_ascii.unwrap_or(source.len()));
        Self {
            source,
            starts,
            ascii_ends,
        }
    }

    /// The location of `offset`. An offset past the end or inside a UTF-8
    /// sequence is clamped to the nearest preceding character boundary.
    pub fn location(&self, offset: usize) -> Location {
        let mut offset = offset.min(self.source.len());
        while !self.source.is_char_boundary(offset) {
            offset -= 1;
        }
        let line = self.starts.partition_point(|&s| s <= offset);
        let start = self.starts[line - 1];
        let ascii_end = self.ascii_ends[line - 1];
        // Every byte before `ascii_end` is one character, and `ascii_end` is a
        // character boundary because it starts a multi-byte sequence.
        let column = if offset <= ascii_end {
            offset - start + 1
        } else {
            ascii_end - start + self.source[ascii_end..offset].chars().count() + 1
        };
        Location {
            line: u32::try_from(line).unwrap_or(u32::MAX),
            column: u32::try_from(column).unwrap_or(u32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The direct definition: count characters from the line start.
    fn reference(source: &str, offset: usize) -> Location {
        let mut offset = offset.min(source.len());
        while !source.is_char_boundary(offset) {
            offset -= 1;
        }
        let line_start = source[..offset].rfind('\n').map_or(0, |i| i + 1);
        let line = source[..offset].matches('\n').count() + 1;
        let column = source[line_start..offset].chars().count() + 1;
        Location {
            line: u32::try_from(line).unwrap(),
            column: u32::try_from(column).unwrap(),
        }
    }

    #[test]
    fn columns_match_character_counts_on_mixed_lines() {
        let sources = [
            "",
            "abc",
            "\n",
            "\n\n",
            "abc\ndef\n",
            "caf\u{e9} = fetch(x)\nplain line\n\u{e9}\n",
            "x = \"\u{4e2d}\u{6587}\u{5b57}\"; fetch(u)\r\nascii only\r\n\u{1f600}tail",
            "ascii\n\u{e9}\u{e9}\u{4e2d}abc\u{1f600}d\nend",
            "trailing non-ascii \u{4e2d}",
            "\u{4e2d}\n\u{e9}",
        ];
        for s in sources {
            let index = LineIndex::new(s);
            for offset in 0..=s.len() + 3 {
                assert_eq!(
                    index.location(offset),
                    reference(s, offset),
                    "{s:?} at {offset}"
                );
            }
        }
    }

    #[test]
    fn offsets_inside_a_character_clamp_to_its_start() {
        let s = "a\u{e9}b\u{4e2d}c";
        let index = LineIndex::new(s);
        // `é` is bytes 1..3, `中` is bytes 4..7.
        assert_eq!(index.location(2), index.location(1));
        assert_eq!(index.location(1).column, 2);
        assert_eq!(index.location(5), index.location(4));
        assert_eq!(index.location(6), index.location(4));
        assert_eq!(index.location(4).column, 4);
        assert_eq!(index.location(7).column, 5);
    }
}

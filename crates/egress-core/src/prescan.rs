//! Bracket-depth pre-scan.
//!
//! Parsers recurse while parsing, and a stack overflow aborts the process
//! instead of unwinding, so every supported file is checked here first. The
//! pre-scan counts `(`, `[`, and `{` outside strings, comments, and raw string
//! literals. Code inside JS template `${...}` holes and Python f-string
//! replacement fields counts as code, including brackets nested in them.
//!
//! Where lexing is ambiguous the pre-scan resolves toward counting:
//!
//! - A literal that can span lines (JS template or block comment, Python
//!   triple-quoted string, any Rust string or block comment) that is still
//!   open at the end of the file is re-read as code from its opening
//!   delimiter, a bounded number of times; past that bound the file counts as
//!   too deeply nested.
//! - A single-line literal (JS or Python quoted string) ends at an unescaped
//!   newline, so a misread quote cannot hide more than the rest of its line.
//! - A JS `/` is a regex only where the previous token makes division
//!   impossible; a regex that does not close on its line is re-read as
//!   division.
//!
//! The scan keeps its own explicit stack and never recurses, so the pre-scan
//! itself cannot overflow on hostile input.

use std::collections::BTreeSet;

use crate::model::Language;

/// Deepest bracket nesting accepted before parsing. Real code stays far below
/// it (CPython's own tokenizer stops at 200 levels), and the parsers handle
/// it comfortably on the 64 MiB worker stack.
pub const MAX_DEPTH: usize = 256;

/// Most whole-file re-reads for unterminated multi-line literals.
const MAX_RESTARTS: usize = 8;
/// Most JS regex-to-division re-reads in one file.
const MAX_REWINDS: usize = 10_000;

/// True when `text` nests brackets deeper than [`MAX_DEPTH`].
pub fn too_deep(language: Language, text: &str) -> bool {
    too_deep_with_cap(language, text, MAX_DEPTH)
}

/// True when `text` nests brackets deeper than `cap`.
pub fn too_deep_with_cap(language: Language, text: &str, cap: usize) -> bool {
    let b = text.as_bytes();
    let mut forced = BTreeSet::new();
    for _ in 0..=MAX_RESTARTS {
        let out = match language {
            Language::Python => python(b, cap, &forced),
            Language::Javascript => javascript(b, cap, &forced),
            Language::Rust => rust(b, cap, &forced),
            Language::Go => go(b, cap, &forced),
        };
        match out {
            Lex::Within => return false,
            Lex::TooDeep => return true,
            Lex::Unterminated(pos) => {
                forced.insert(pos);
            }
        }
    }
    true
}

enum Lex {
    Within,
    TooDeep,
    /// A multi-line literal opened at this position never closed.
    Unterminated(usize),
}

struct Depth {
    depth: usize,
    cap: usize,
}

impl Depth {
    fn open(&mut self) -> bool {
        self.depth += 1;
        self.depth <= self.cap
    }

    fn close(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80
}

fn ident_end(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (is_ident(b[i]) || b[i] == b'$') {
        i += 1;
    }
    i
}

// ---- Python ----------------------------------------------------------------

#[derive(Clone)]
enum Py {
    /// Code; in an f-string hole `hole` is true and `inner` counts brackets
    /// opened inside the hole.
    Code { hole: bool, inner: usize },
    Str {
        q: u8,
        triple: bool,
        f: bool,
        open: usize,
    },
    /// A format spec after `:` in a replacement field.
    Spec,
}

fn python(b: &[u8], cap: usize, forced: &BTreeSet<usize>) -> Lex {
    let mut d = Depth { depth: 0, cap };
    let mut st = vec![Py::Code {
        hole: false,
        inner: 0,
    }];
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let top = st.len() - 1;
        match &mut st[top] {
            Py::Code { hole, inner } => match c {
                b'#' => {
                    i = skip_line_comment(b, i);
                    continue;
                }
                b'\\' => i += 1,
                b'(' | b'[' | b'{' => {
                    if !d.open() {
                        return Lex::TooDeep;
                    }
                    if *hole {
                        *inner += 1;
                    }
                }
                b')' | b']' | b'}' => {
                    if *hole && *inner == 0 {
                        if c == b'}' {
                            st.pop();
                        }
                    } else if *hole {
                        *inner -= 1;
                    }
                    d.close();
                }
                b':' if *hole && *inner == 0 => st.push(Py::Spec),
                b'\'' | b'"' => {
                    if forced.contains(&i) {
                        i += 1;
                        continue;
                    }
                    let triple = b.get(i + 1) == Some(&c) && b.get(i + 2) == Some(&c);
                    st.push(Py::Str {
                        q: c,
                        triple,
                        f: false,
                        open: i,
                    });
                    i += if triple { 3 } else { 1 };
                    continue;
                }
                _ if is_ident(c) => {
                    let end = ident_end(b, i);
                    let word = &b[i..end];
                    let is_prefix = word.len() <= 2
                        && word.iter().all(|x| b"rRbBuUfFtT".contains(x))
                        && matches!(b.get(end), Some(b'\'') | Some(b'"'));
                    if is_prefix && !forced.contains(&end) {
                        let q = b[end];
                        let triple = b.get(end + 1) == Some(&q) && b.get(end + 2) == Some(&q);
                        let f = word.iter().any(|x| b"fFtT".contains(x));
                        st.push(Py::Str {
                            q,
                            triple,
                            f,
                            open: end,
                        });
                        i = end + if triple { 3 } else { 1 };
                    } else {
                        i = end;
                    }
                    continue;
                }
                _ => {}
            },
            Py::Str { q, triple, f, .. } => {
                let (q, triple, f) = (*q, *triple, *f);
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'\n' && !triple {
                    // Unterminated single-line string: it ends here.
                    st.pop();
                } else if c == q {
                    if !triple {
                        st.pop();
                    } else if b.get(i + 1) == Some(&q) && b.get(i + 2) == Some(&q) {
                        st.pop();
                        i += 3;
                        continue;
                    }
                } else if f && c == b'{' {
                    if b.get(i + 1) == Some(&b'{') {
                        i += 2;
                        continue;
                    }
                    if !d.open() {
                        return Lex::TooDeep;
                    }
                    st.push(Py::Code {
                        hole: true,
                        inner: 0,
                    });
                } else if f && c == b'}' && b.get(i + 1) == Some(&b'}') {
                    i += 1;
                }
            }
            Py::Spec => match c {
                b'{' => {
                    if !d.open() {
                        return Lex::TooDeep;
                    }
                    st.push(Py::Code {
                        hole: true,
                        inner: 0,
                    });
                }
                b'}' => {
                    st.pop();
                    if matches!(st.last(), Some(Py::Code { hole: true, .. })) {
                        st.pop();
                    }
                    d.close();
                }
                b'\n' => {
                    st.pop();
                }
                _ => {}
            },
        }
        i += 1;
    }
    // A triple-quoted string still open at the end of the file.
    for f in &st {
        if let Py::Str {
            triple: true, open, ..
        } = f
        {
            return Lex::Unterminated(*open);
        }
    }
    Lex::Within
}

// ---- JavaScript ------------------------------------------------------------

/// What the previous significant token allows next.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prev {
    /// Start of input or of a statement: a `/` is a regex, a `{` a block.
    Statement,
    /// An operator or opening punctuator: a `/` is a regex, a `{` an object.
    Operator,
    /// `=>`: a `/` is a regex, a `{` a block.
    Arrow,
    /// A value: a `/` is division.
    Value,
    /// `.` or `?.`: the next identifier is a property name.
    Dot,
    /// `if`, `while`, `for`, or `with`: the next `(` is a statement head.
    HeadKeyword,
    /// `function` or `class` in expression position.
    FnExprKeyword,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    Paren { head: bool },
    Bracket,
    Brace { block: bool },
}

#[derive(Clone)]
enum Js {
    Code {
        hole: bool,
        opens: Vec<Open>,
        prev: Prev,
        /// Bracket stack length at which a function or class expression's
        /// body brace is expected.
        fn_expr_at: Option<usize>,
    },
    Template {
        open: usize,
    },
    Comment {
        open: usize,
    },
}

const REGEX_KEYWORDS: &[&[u8]] = &[
    b"return",
    b"typeof",
    b"instanceof",
    b"in",
    b"of",
    b"new",
    b"delete",
    b"void",
    b"throw",
    b"case",
    b"yield",
    b"await",
];

fn code(hole: bool) -> Js {
    Js::Code {
        hole,
        opens: Vec::new(),
        prev: Prev::Statement,
        fn_expr_at: None,
    }
}

/// The index after a `//`-style line comment starting at `i` (past the
/// slashes): the next newline, or the end of input.
fn skip_line_comment(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i] != b'\n' {
        i += 1;
    }
    i
}

/// Skips a quoted string starting at `i` (the quote). Returns the index after
/// it; an unescaped newline ends it.
fn js_string(b: &[u8], mut i: usize) -> usize {
    let q = b[i];
    i += 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'\n' => return i,
            x if x == q => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// Finds the end of a regex literal starting at `i` (the `/`) on the same
/// line, past its flags.
fn js_regex(b: &[u8], mut i: usize) -> Option<usize> {
    i += 1;
    let mut class = false;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'\n' | b'\r' => return None,
            b'[' => class = true,
            b']' => class = false,
            b'/' if !class => return Some(ident_end(b, i + 1)),
            _ => {}
        }
        i += 1;
    }
    None
}

fn javascript(b: &[u8], cap: usize, forced: &BTreeSet<usize>) -> Lex {
    let mut d = Depth { depth: 0, cap };
    let mut st = vec![code(false)];
    let mut not_regex: BTreeSet<usize> = BTreeSet::new();
    let mut rewinds = 0usize;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let top = st.len() - 1;
        match &mut st[top] {
            Js::Comment { .. } => {
                if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    st.pop();
                    i += 2;
                    continue;
                }
            }
            Js::Template { .. } => match c {
                b'\\' => i += 1,
                b'`' => {
                    st.pop();
                    if let Some(Js::Code { prev, .. }) = st.last_mut() {
                        *prev = Prev::Value;
                    }
                }
                b'$' if b.get(i + 1) == Some(&b'{') => {
                    if !d.open() {
                        return Lex::TooDeep;
                    }
                    st.push(code(true));
                    i += 2;
                    continue;
                }
                _ => {}
            },
            Js::Code {
                hole,
                opens,
                prev,
                fn_expr_at,
            } => {
                if c.is_ascii_whitespace() {
                    i += 1;
                    continue;
                }
                if c == b'/' && b.get(i + 1) == Some(&b'/') {
                    i = skip_line_comment(b, i);
                    continue;
                }
                if c == b'/' && b.get(i + 1) == Some(&b'*') && !forced.contains(&i) {
                    st.push(Js::Comment { open: i });
                    i += 2;
                    continue;
                }
                match c {
                    b'\'' | b'"' => {
                        i = js_string(b, i);
                        *prev = Prev::Value;
                        continue;
                    }
                    b'`' => {
                        if forced.contains(&i) {
                            *prev = Prev::Operator;
                        } else {
                            st.push(Js::Template { open: i });
                        }
                    }
                    b'(' | b'[' | b'{' => {
                        if !d.open() {
                            return Lex::TooDeep;
                        }
                        let o = match c {
                            b'(' => Open::Paren {
                                head: *prev == Prev::HeadKeyword,
                            },
                            b'[' => Open::Bracket,
                            _ => {
                                let fn_body = *fn_expr_at == Some(opens.len())
                                    && matches!(*prev, Prev::Value);
                                if fn_body {
                                    *fn_expr_at = None;
                                }
                                Open::Brace {
                                    block: !fn_body
                                        && matches!(
                                            *prev,
                                            Prev::Statement | Prev::Arrow | Prev::Value
                                        ),
                                }
                            }
                        };
                        opens.push(o);
                        *prev = if c == b'{' {
                            Prev::Statement
                        } else {
                            Prev::Operator
                        };
                    }
                    b')' | b']' | b'}' => {
                        if c == b'}' && *hole && opens.is_empty() {
                            st.pop();
                            d.close();
                            i += 1;
                            continue;
                        }
                        let o = opens.pop();
                        d.close();
                        *prev = match o {
                            Some(Open::Paren { head: true } | Open::Brace { block: true }) => {
                                Prev::Statement
                            }
                            _ => Prev::Value,
                        };
                    }
                    b'/' => {
                        let regex_allowed =
                            !matches!(*prev, Prev::Value | Prev::Dot) && !not_regex.contains(&i);
                        if regex_allowed {
                            match js_regex(b, i) {
                                Some(end) => {
                                    i = end;
                                    *prev = Prev::Value;
                                    continue;
                                }
                                None => {
                                    // No regex closes on this line: division.
                                    rewinds += 1;
                                    if rewinds > MAX_REWINDS {
                                        return Lex::TooDeep;
                                    }
                                    not_regex.insert(i);
                                }
                            }
                        }
                        *prev = Prev::Operator;
                    }
                    b';' => *prev = Prev::Statement,
                    b'.' if !b.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                        *prev = Prev::Dot;
                    }
                    b'=' if b.get(i + 1) == Some(&b'>') => {
                        *prev = Prev::Arrow;
                        i += 2;
                        continue;
                    }
                    b'+' | b'-' if b.get(i + 1) == Some(&c) => {
                        *prev = Prev::Value;
                        i += 2;
                        continue;
                    }
                    _ if is_ident(c) || c == b'$' || c == b'#' || c == b'.' => {
                        let end = ident_end(b, i + 1);
                        let word = &b[i..end];
                        *prev = if *prev == Prev::Dot || c.is_ascii_digit() || c == b'.' {
                            Prev::Value
                        } else if matches!(word, b"if" | b"while" | b"for" | b"with") {
                            Prev::HeadKeyword
                        } else if matches!(word, b"do" | b"else") {
                            Prev::Statement
                        } else if matches!(word, b"function" | b"class")
                            && matches!(*prev, Prev::Operator | Prev::Arrow)
                        {
                            *fn_expr_at = Some(opens.len());
                            Prev::FnExprKeyword
                        } else if REGEX_KEYWORDS.contains(&word) {
                            Prev::Operator
                        } else if *prev == Prev::FnExprKeyword {
                            Prev::FnExprKeyword
                        } else {
                            Prev::Value
                        };
                        i = end;
                        continue;
                    }
                    _ => *prev = Prev::Operator,
                }
            }
        }
        i += 1;
    }
    for f in &st {
        match f {
            Js::Template { open } | Js::Comment { open } => return Lex::Unterminated(*open),
            Js::Code { .. } => {}
        }
    }
    Lex::Within
}

// ---- Rust ------------------------------------------------------------------

enum Rs {
    Code,
    Str { open: usize },
    Raw { hashes: usize, open: usize },
    Comment { nest: usize, open: usize },
}

/// Length of a char or byte literal starting at the `'` at `i`, or `None`
/// when the quote starts a lifetime or label.
fn rust_char(b: &[u8], i: usize) -> Option<usize> {
    let next = *b.get(i + 1)?;
    if next == b'\\' {
        let mut j = i + 2;
        while j < b.len() && j < i + 14 {
            if b[j] == b'\'' && j > i + 2 {
                return Some(j + 1 - i);
            }
            if b[j] == b'\n' {
                return None;
            }
            j += 1;
        }
        return None;
    }
    if next == b'\'' || next == b'\n' {
        return None;
    }
    let width = match next {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    (b.get(i + 1 + width) == Some(&b'\'')).then_some(width + 2)
}

fn rust(b: &[u8], cap: usize, forced: &BTreeSet<usize>) -> Lex {
    let mut d = Depth { depth: 0, cap };
    let mut st = Rs::Code;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match &mut st {
            Rs::Code => match c {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    i = skip_line_comment(b, i);
                    continue;
                }
                b'/' if b.get(i + 1) == Some(&b'*') && !forced.contains(&i) => {
                    st = Rs::Comment { nest: 1, open: i };
                    i += 2;
                    continue;
                }
                b'"' if !forced.contains(&i) => st = Rs::Str { open: i },
                b'\'' => {
                    if let Some(n) = rust_char(b, i) {
                        i += n;
                        continue;
                    }
                }
                b'(' | b'[' | b'{' => {
                    if !d.open() {
                        return Lex::TooDeep;
                    }
                }
                b')' | b']' | b'}' => d.close(),
                _ if is_ident(c) => {
                    let end = ident_end(b, i);
                    let word = &b[i..end];
                    if matches!(word, b"r" | b"br" | b"cr") {
                        let mut j = end;
                        while b.get(j) == Some(&b'#') {
                            j += 1;
                        }
                        if b.get(j) == Some(&b'"') && !forced.contains(&j) {
                            st = Rs::Raw {
                                hashes: j - end,
                                open: j,
                            };
                            i = j + 1;
                            continue;
                        }
                    }
                    if matches!(word, b"b" | b"c")
                        && b.get(end) == Some(&b'\'')
                        && let Some(n) = rust_char(b, end)
                    {
                        i = end + n;
                        continue;
                    }
                    i = end;
                    continue;
                }
                _ => {}
            },
            Rs::Str { .. } => match c {
                b'\\' => i += 1,
                b'"' => st = Rs::Code,
                _ => {}
            },
            Rs::Raw { hashes, .. } => {
                let h = *hashes;
                if c == b'"' && b.len() > i + h && b[i + 1..=i + h].iter().all(|x| *x == b'#') {
                    st = Rs::Code;
                    i += h + 1;
                    continue;
                }
            }
            Rs::Comment { nest, .. } => {
                if c == b'/' && b.get(i + 1) == Some(&b'*') {
                    *nest += 1;
                    i += 2;
                    continue;
                }
                if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    *nest -= 1;
                    if *nest == 0 {
                        st = Rs::Code;
                    }
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    match st {
        Rs::Code => Lex::Within,
        Rs::Str { open } | Rs::Raw { open, .. } | Rs::Comment { open, .. } => {
            Lex::Unterminated(open)
        }
    }
}

// ---- Go --------------------------------------------------------------------

enum Go {
    Code,
    /// A backtick raw string: multi-line, no escapes.
    Raw {
        open: usize,
    },
    /// A `/* */` comment: unlike Rust's, it never nests.
    Comment {
        open: usize,
    },
}

/// The index past a `"` string or `'` rune literal starting at `i` (the
/// quote). Both are single-line with `\` escapes; an unescaped newline or
/// the end of input ends the literal.
fn go_quoted(b: &[u8], i: usize) -> usize {
    js_string(b, i)
}

fn go(b: &[u8], cap: usize, forced: &BTreeSet<usize>) -> Lex {
    let mut d = Depth { depth: 0, cap };
    let mut st = Go::Code;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match &mut st {
            Go::Code => match c {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    i = skip_line_comment(b, i);
                    continue;
                }
                b'/' if b.get(i + 1) == Some(&b'*') && !forced.contains(&i) => {
                    st = Go::Comment { open: i };
                    i += 2;
                    continue;
                }
                b'`' if !forced.contains(&i) => st = Go::Raw { open: i },
                b'"' | b'\'' => {
                    i = go_quoted(b, i);
                    continue;
                }
                b'(' | b'[' | b'{' => {
                    if !d.open() {
                        return Lex::TooDeep;
                    }
                }
                b')' | b']' | b'}' => d.close(),
                _ => {}
            },
            Go::Raw { .. } => {
                if c == b'`' {
                    st = Go::Code;
                }
            }
            Go::Comment { .. } => {
                if c == b'*' && b.get(i + 1) == Some(&b'/') {
                    st = Go::Code;
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    match st {
        Go::Code => Lex::Within,
        Go::Raw { open } | Go::Comment { open } => Lex::Unterminated(open),
    }
}

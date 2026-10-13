//! Bounded prescan over `gosyn::tokenize_source` output (KTD6).
//!
//! gosyn 0.2.15 recurses in places its own depth cap (64 expression levels,
//! reason `too many depth`) does not cover, and re-parses a type
//! declaration's `[`-bracketed expression once per level, doubling cost on
//! each nesting level. Its recursive `Drop` aborts the process on long flat
//! chains instead of unwinding. Since none of that can be trusted, every
//! file crosses these bounds before `parse_source` runs; over a bound,
//! `lower` refuses with `TooDeeplyNested` (fail closed: the estimate may
//! over-count, never under-count).
//!
//! Crash and blowup thresholds measured against gosyn 0.2.15 on this repo's
//! 64 MiB worker stack (2026-10, host arm64; debug / release):
//!
//! - prefix unary run `!...x`: overflowed at ~14,400 / ~80,000 ops
//! - `else if` chain: ~12,000 / ~12,000 links
//! - consecutive labels `L0: L1:`: ~6,200 / ~18,400 labels
//! - func literals nested inside `if` headers: ~1,100 / ~4,600 levels
//!   (the core bracket prescan already caps that shape at ~85 levels; the
//!   func-depth bound below is a second layer)
//! - operator-chained statement runs (`a.b..`, `f()..`, `1 + 1 +..`):
//!   ~473,600 / >800,000 terms, via `Drop` recursion
//! - `type U [n + func() int { type V [...]int; ... }()]int` nested: cost
//!   doubles per level (~3 s at 16 debug, ~17 s at 22 release); with a
//!   1 MiB comment innermost, peak RSS ≈ comment bytes x 2^levels and the
//!   process was killed at 12 levels
//! - bare nested func literals: gosyn's own cap errors at 63, so no crash
//!
//! Peak RSS over tokenize plus parse on dense input (comma-separated
//! one-byte elements, one-char identifiers, line comments) measures
//! ~280x source bytes on both build profiles (1 MiB of `[]int{1,1,..}`
//! peaks near 275 MiB). [`MAX_SOURCE_BYTES`] keeps the worst case -
//! size times that multiplier plus bounded comment duplication -
//! inside ~1.5 GiB per file.

use gosyn::LexicalToken;
use gosyn::token::{Keyword, LitKind, Operator, Token};

use crate::positions::Positions;

/// Longest run of prefix unary operators (`!`, `-`, `+`, `^`, `*`, `&`,
/// `<-`, `~`), ~14x under the debug crash point.
pub const MAX_UNARY_RUN: usize = 1024;
/// Longest `else if` chain, ~12x under the crash point.
pub const MAX_ELSE_IF: usize = 1024;
/// Longest consecutive `Ident:` label run, ~12x under the debug crash point.
pub const MAX_LABEL_RUN: usize = 512;
/// Deepest nesting of `type` declarations inside bracketed expressions.
/// Each level doubles gosyn's re-parse and comment-duplication cost, so the
/// cost margin is exponential: 2^6 against an OOM point of ~2^12 and a
/// multi-second parse at ~2^16.
pub const MAX_NESTED_TYPE: usize = 6;
/// Deepest nesting of func literals, ~68x under the debug crash point for
/// header nesting and a second layer for the exponential type shape.
pub const MAX_FUNC_DEPTH: usize = 16;
/// Longest operator-chained run in one statement, ~14x under the debug
/// `Drop` crash point. Generated table literals are unaffected: commas and
/// bracket-depth changes reset the run.
pub const MAX_STATEMENT_CHAIN: usize = 32_768;
/// Largest Go source the frontend accepts, independent of the discovery
/// file cap. At the measured ~280x peak-RSS multiplier plus bounded comment
/// duplication this keeps the worst case near ~1.5 GiB per file. The
/// largest non-testdata file in the Go 1.26.8 standard library is ~3 MiB.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Operators that can begin a unary expression.
fn is_unary(op: Operator) -> bool {
    matches!(
        op,
        Operator::Not
            | Operator::Sub
            | Operator::Add
            | Operator::Xor
            | Operator::Star
            | Operator::And
            | Operator::Arrow
            | Operator::Tiled
    )
}

/// Operators that continue an operator-chained expression: selector dots,
/// call and index postfixes, and binary operators. `(`/`[` are counted in
/// their parent frame.
fn is_chain(op: Operator) -> bool {
    matches!(
        op,
        Operator::Dot
            | Operator::ParenLeft
            | Operator::BarackLeft
            | Operator::Add
            | Operator::Sub
            | Operator::Star
            | Operator::Quo
            | Operator::Rem
            | Operator::And
            | Operator::Or
            | Operator::Xor
            | Operator::Shl
            | Operator::Shr
            | Operator::AndNot
            | Operator::AndAnd
            | Operator::OrOr
            | Operator::Arrow
            | Operator::Equal
            | Operator::NotEqual
            | Operator::Less
            | Operator::LessEqual
            | Operator::Greater
            | Operator::GreaterEqual
    )
}

/// Tokens after which a newline ends a statement under Go's semicolon
/// insertion rule.
fn semi_set(tok: &Token) -> bool {
    matches!(
        tok,
        Token::Literal(..)
            | Token::Keyword(
                Keyword::Break | Keyword::Continue | Keyword::FallThrough | Keyword::Return,
            )
            | Token::Operator(
                Operator::Inc
                    | Operator::Dec
                    | Operator::ParenRight
                    | Operator::BarackRight
                    | Operator::BraceRight,
            )
    )
}

/// Tokens that can end a func signature, so the `{` after one is a func
/// body, not a type body (`interface{`, `struct{`) or a composite literal.
fn body_prev(tok: &Token) -> bool {
    matches!(
        tok,
        Token::Literal(..)
            | Token::Operator(Operator::ParenRight | Operator::BarackRight | Operator::BraceRight)
    )
}

/// Keywords that start a statement or declaration, so a pending bodiless
/// `func` (a func type) cannot outlive it.
fn stmt_keyword(k: Keyword) -> bool {
    matches!(
        k,
        Keyword::Break
            | Keyword::Case
            | Keyword::Const
            | Keyword::Continue
            | Keyword::Default
            | Keyword::Defer
            | Keyword::Else
            | Keyword::FallThrough
            | Keyword::For
            | Keyword::Func
            | Keyword::Go
            | Keyword::Goto
            | Keyword::If
            | Keyword::Import
            | Keyword::Package
            | Keyword::Range
            | Keyword::Return
            | Keyword::Select
            | Keyword::Switch
            | Keyword::Type
            | Keyword::Var
    )
}

struct Frame {
    /// Operator-chained run length in the frame's current statement.
    chain: usize,
    /// A `[` opened by `type` `<ident>` `[`: its span may hold a nested
    /// `type` declaration and drives gosyn's re-parse.
    type_bracket: bool,
    /// A `{` opened as a func body: funcs inside it nest one deeper.
    func_body: bool,
}

/// True when `text`/`tokens` exceed any prescan bound.
pub fn over_any_bound(tokens: &[LexicalToken], text: &str) -> bool {
    if text.len() > MAX_SOURCE_BYTES {
        return true;
    }
    let pos = Positions::new(text);
    let bytes = text.as_bytes();
    let mut frames: Vec<Frame> = Vec::new();
    // Bracket depths of `func` keywords whose body `{` has not opened yet.
    let mut pending_funcs: Vec<usize> = Vec::new();
    let mut unary = 0usize;
    let mut elseif = 0usize;
    let mut labels = 0usize;
    // Previous stream token (comments included) and the previous
    // significant token, for the semicolon-insertion statement rule.
    let mut prev_tok: Option<&LexicalToken> = None;
    let mut sig: Option<&Token> = None;
    let mut sig2: Option<&Token> = None;

    for t in tokens {
        let depth = frames.len();
        // A newline ends the statement only after a semicolon-set token;
        // a chain continued past a newline by a trailing operator still
        // counts.
        if let (Some(p), Some(s)) = (prev_tok, sig)
            && newline_between(&pos, bytes, p, t)
                && semi_set(s)
                && let Some(f) = frames.last_mut()
            {
                f.chain = 0;
            }
        match &t.token {
            Token::Comment(_) => {
                prev_tok = Some(t);
                continue;
            }
            Token::Literal(LitKind::Ident, _) => {
                unary = 0;
            }
            Token::Literal(..) => {
                unary = 0;
                labels = 0;
            }
            Token::Keyword(k) => {
                // A statement keyword at this depth ends any bodiless `func`
                // signature pending here (a `func` at a deeper level is
                // inside its signature's brackets and survives).
                if stmt_keyword(*k) {
                    pending_funcs.retain(|&fd| fd != depth);
                }
                match k {
                    Keyword::If => {
                        if matches!(sig, Some(Token::Keyword(Keyword::Else))) {
                            elseif += 1;
                            if elseif > MAX_ELSE_IF {
                                return true;
                            }
                        } else {
                            elseif = 0;
                        }
                    }
                    Keyword::Func => {
                        let d = 1 + frames.iter().filter(|f| f.func_body).count();
                        if d > MAX_FUNC_DEPTH {
                            return true;
                        }
                        pending_funcs.push(depth);
                    }
                    Keyword::Else | Keyword::Type => {}
                    _ => {}
                }
                unary = 0;
                labels = 0;
            }
            Token::Operator(op) => match op {
                Operator::ParenLeft | Operator::BarackLeft | Operator::BraceLeft => {
                    if let Some(f) = frames.last_mut() {
                        f.chain += 1;
                        if f.chain > MAX_STATEMENT_CHAIN {
                            return true;
                        }
                    }
                    let mut func_body = false;
                    let mut type_bracket = false;
                    if *op == Operator::BraceLeft
                        && !pending_funcs.is_empty()
                        && sig.is_some_and(body_prev)
                    {
                        func_body = true;
                        pending_funcs.pop();
                    }
                    if *op == Operator::BarackLeft
                        && matches!(sig2, Some(Token::Keyword(Keyword::Type)))
                        && matches!(sig, Some(Token::Literal(LitKind::Ident, _)))
                    {
                        type_bracket = true;
                        let d = 1 + frames.iter().filter(|f| f.type_bracket).count();
                        if d > MAX_NESTED_TYPE {
                            return true;
                        }
                    }
                    frames.push(Frame {
                        chain: 0,
                        type_bracket,
                        func_body,
                    });
                    unary = 0;
                    labels = 0;
                }
                Operator::ParenRight | Operator::BarackRight | Operator::BraceRight => {
                    frames.pop();
                    unary = 0;
                    labels = 0;
                }
                Operator::Comma | Operator::SemiColon | Operator::Colon => {
                    if let Some(f) = frames.last_mut() {
                        f.chain = 0;
                    }
                    if *op == Operator::Colon
                        && matches!(sig, Some(Token::Literal(LitKind::Ident, _)))
                    {
                        labels += 1;
                        if labels > MAX_LABEL_RUN {
                            return true;
                        }
                    } else {
                        labels = 0;
                    }
                    unary = 0;
                }
                _ => {
                    if is_unary(*op) {
                        unary += 1;
                        if unary > MAX_UNARY_RUN {
                            return true;
                        }
                    } else {
                        unary = 0;
                    }
                    if is_chain(*op)
                        && let Some(f) = frames.last_mut()
                    {
                        f.chain += 1;
                        if f.chain > MAX_STATEMENT_CHAIN {
                            return true;
                        }
                    }
                    labels = 0;
                }
            },
        }
        sig2 = sig;
        sig = Some(&t.token);
        // A `func` keyword cannot outlive the bracket frame it sits in.
        pending_funcs.retain(|&fd| frames.len() >= fd);
        prev_tok = Some(t);
    }
    false
}

/// True when a newline separates tokens `a` and `b`, counting a newline
/// inside an intervening `/* */` comment the way Go's scanner does (a
/// general comment containing a newline acts as a newline).
fn newline_between(pos: &Positions, bytes: &[u8], a: &LexicalToken, b: &LexicalToken) -> bool {
    let lo = pos.byte_offset(a.end) as usize;
    let hi = pos.byte_offset(b.start) as usize;
    if hi > lo && bytes[lo..hi].contains(&b'\n') {
        return true;
    }
    if matches!(a.token, Token::Comment(_)) {
        let s = pos.byte_offset(a.start) as usize;
        let e = pos.byte_offset(a.end) as usize;
        if e > s && bytes[s..e].contains(&b'\n') {
            return true;
        }
    }
    false
}

//! Nesting estimate for constructs the bracket pre-scan does not count.
//!
//! The pre-scan bounds bracket depth, but oxc's parser and its
//! semantic pass also recurse once per level of nesting that uses no
//! brackets: ternary and arrow chains, right-associative operators, long
//! left-associative operator and member chains (a deep AST even when parsed
//! iteratively), TS generics, JSX elements, and statement nesting such as
//! `else if` chains. Measured on a 64 MiB worker stack, a debug build
//! overflows between about 20,000 and 60,000 such levels and a release
//! build between about 40,000 and 2,000,000, and an overflow aborts the
//! process.
//!
//! This lexer-level estimate charges one unit per token that can open a
//! nesting level and keeps a per-bracket-level account, resetting it only
//! where nesting at that level must have closed: a `,` or `;`, or a newline
//! that ends a statement by ASI. Statement keywords and `<` are charged to a
//! sticky account that survives commas, so `else if` chains, generics, and
//! JSX are counted. Every AST level costs at least one token, so a file
//! within [`LIMIT`] units nests at most that deep.
//!
//! Known residual gap, shared with the bracket pre-scan: a regular
//! expression after `)` or `}` is lexed as division, so a quote or `//`
//! inside it can hide the rest of that line from the estimate.

/// Estimated nesting units accepted before parsing. Well below the
/// shallowest measured overflow, which leaves room for the lowering walk's
/// own frames.
pub const LIMIT: usize = 8192;

#[derive(Default, Clone, Copy)]
struct Level {
    /// Units since the last `,`, `;`, or ASI newline.
    c: usize,
    /// Statement keywords and `<` since the last statement end.
    s: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Prev {
    /// Start, operator, or opening punctuation: a `/` here starts a regex.
    Operator,
    /// An identifier, literal, or closing bracket.
    Value,
    /// A keyword after which an expression follows.
    Keyword,
}

/// Opening constructs on the lexer's mode stack.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    Bracket,
    /// A `${` hole; its `}` resumes template text.
    Hole,
}

const STICKY: &[&str] = &["if", "else", "for", "while", "do", "with"];
const EXPR_KEYWORDS: &[&str] = &[
    "return",
    "typeof",
    "void",
    "delete",
    "new",
    "await",
    "yield",
    "throw",
    "case",
    "extends",
    "in",
    "instanceof",
    "of",
    "as",
    "satisfies",
    "else",
    "do",
    "keyof",
    "export",
    "default",
    "import",
];
const OPERATOR_WORDS: &[&str] = &["in", "instanceof", "of", "as", "satisfies"];
const CONTINUES_BLOCK: &[&str] = &["else", "while", "catch", "finally"];

struct Est {
    levels: Vec<Level>,
    total: usize,
    /// A `;` or closing `}` was seen; the sticky account resets unless the
    /// next token continues the statement.
    pending: bool,
}

impl Est {
    fn top(&mut self) -> &mut Level {
        self.levels
            .last_mut()
            .expect("the outer level is never popped")
    }

    fn add_c(&mut self) {
        self.top().c += 1;
        self.total += 1;
    }

    fn add_s(&mut self) {
        self.top().s += 1;
        self.total += 1;
    }

    fn reset_c(&mut self) {
        let c = std::mem::take(&mut self.top().c);
        self.total -= c;
    }

    fn reset_s(&mut self) {
        let s = std::mem::take(&mut self.top().s);
        self.total -= s;
    }

    fn push(&mut self) {
        self.levels.push(Level::default());
        self.total += 1;
    }

    fn pop(&mut self) {
        if self.levels.len() > 1 {
            let l = self.levels.pop().unwrap_or_default();
            self.total -= l.c + l.s + 1;
            self.add_c();
        }
    }

    /// Called before each token; `word` is the token when it is a word.
    fn settle(&mut self, word: Option<&str>) {
        if self.pending {
            self.pending = false;
            if !word.is_some_and(|w| CONTINUES_BLOCK.contains(&w)) {
                self.reset_s();
            }
        }
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'\\' || b >= 0x80
}

/// True when `text` may nest deeper than [`LIMIT`] units.
pub fn too_deep(text: &str) -> bool {
    let b = text.as_bytes();
    let mut est = Est {
        levels: vec![Level::default()],
        total: 1,
        pending: false,
    };
    let mut opens: Vec<Open> = Vec::new();
    let mut prev = Prev::Operator;
    let mut newline = false;
    let mut i = 0;
    // Resume template text after a hole closes.
    let mut in_template = false;
    while i < b.len() {
        if est.total > LIMIT {
            return true;
        }
        if in_template {
            // Template text until `${` or the closing backtick.
            in_template = false;
            let mut closed = false;
            while i < b.len() {
                match b[i] {
                    b'\\' => i += 2,
                    b'`' => {
                        i += 1;
                        closed = true;
                        prev = Prev::Value;
                        break;
                    }
                    b'$' if b.get(i + 1) == Some(&b'{') => {
                        i += 2;
                        opens.push(Open::Hole);
                        est.push();
                        closed = true;
                        prev = Prev::Operator;
                        break;
                    }
                    b'\n' => {
                        newline = false;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            if !closed {
                // An unterminated template: the parser fails on it too.
                return est.total > LIMIT;
            }
            continue;
        }
        let ch = b[i];
        match ch {
            b'\n' => {
                newline = true;
                i += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | 0x0b | 0x0c => {
                i += 1;
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                match text[i + 2..].find("*/") {
                    Some(end) => {
                        if text[i + 2..i + 2 + end].contains('\n') {
                            newline = true;
                        }
                        i += end + 4;
                    }
                    None => return est.total > LIMIT,
                }
                continue;
            }
            _ => {}
        }
        // A token starts here. Work out its word form for ASI and the
        // sticky reset, then charge it.
        let word_end = if is_word_byte(ch) {
            let mut j = i;
            while j < b.len() && is_word_byte(b[j]) {
                j += 1;
            }
            Some(j)
        } else {
            None
        };
        let word = word_end.map(|j| &text[i..j]);
        if newline {
            newline = false;
            let starts_value = match word {
                Some(w) => !OPERATOR_WORDS.contains(&w),
                None => ch == b'"' || ch == b'\'',
            };
            if prev == Prev::Value && starts_value {
                est.reset_c();
            }
        }
        est.settle(word);
        if let Some(j) = word_end {
            let w = word.unwrap_or_default();
            if STICKY.contains(&w) {
                est.add_s();
            } else {
                est.add_c();
            }
            prev = if EXPR_KEYWORDS.contains(&w) || STICKY.contains(&w) {
                Prev::Keyword
            } else {
                Prev::Value
            };
            i = j;
            continue;
        }
        match ch {
            b'"' | b'\'' => {
                let mut j = i + 1;
                let mut closed = false;
                while j < b.len() {
                    match b[j] {
                        b'\\' => j += 2,
                        b'\n' => break,
                        c if c == ch => {
                            closed = true;
                            j += 1;
                            break;
                        }
                        _ => j += 1,
                    }
                }
                est.add_c();
                if closed {
                    prev = Prev::Value;
                    i = j;
                } else {
                    // No closing quote on the line (JSX text, say): read on
                    // as code so nothing is hidden.
                    prev = Prev::Operator;
                    i += 1;
                }
            }
            b'`' => {
                est.add_c();
                in_template = true;
                prev = Prev::Value;
                i += 1;
            }
            b'(' | b'[' | b'{' => {
                opens.push(Open::Bracket);
                est.push();
                prev = Prev::Operator;
                i += 1;
            }
            b')' | b']' | b'}' => {
                let open = opens.pop();
                est.pop();
                if ch == b'}' {
                    est.pending = true;
                }
                prev = Prev::Value;
                i += 1;
                if open == Some(Open::Hole) {
                    in_template = true;
                }
            }
            b',' => {
                est.reset_c();
                prev = Prev::Operator;
                i += 1;
            }
            b';' => {
                est.reset_c();
                est.pending = true;
                prev = Prev::Operator;
                i += 1;
            }
            b'<' => {
                est.add_s();
                prev = Prev::Operator;
                i += 1;
            }
            b'/' if prev != Prev::Value => {
                // A regex literal when it closes on this line.
                let mut j = i + 1;
                let mut class = false;
                let mut end = None;
                while j < b.len() && b[j] != b'\n' {
                    match b[j] {
                        b'\\' => j += 1,
                        b'[' => class = true,
                        b']' => class = false,
                        b'/' if !class => {
                            end = Some(j + 1);
                            break;
                        }
                        _ => {}
                    }
                    j += 1;
                }
                est.add_c();
                match end {
                    Some(e) => {
                        i = e;
                        while i < b.len() && is_word_byte(b[i]) {
                            i += 1;
                        }
                        prev = Prev::Value;
                    }
                    None => {
                        prev = Prev::Operator;
                        i += 1;
                    }
                }
            }
            _ => {
                est.add_c();
                prev = Prev::Operator;
                i += 1;
            }
        }
    }
    est.total > LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_keywords_survive_commas_and_reset_at_statement_ends() {
        let chain = format!("if(a){{}}{}", "else if(a){}".repeat(LIMIT));
        assert!(too_deep(&chain));
        let flat = "if (a) { b(); }\n".repeat(LIMIT * 2);
        assert!(!too_deep(&flat));
    }

    #[test]
    fn asi_newlines_reset_but_continuation_lines_do_not() {
        let asi = "x = y\n".repeat(LIMIT * 2);
        assert!(!too_deep(&asi));
        let cont = format!("x = y{}", "\n+ y".repeat(LIMIT));
        assert!(too_deep(&cont));
    }

    #[test]
    fn strings_comments_and_templates_hide_only_their_contents() {
        let s = format!(
            "x = \"{}\"; // {}\n/* {} */ y = `{}`;",
            "a?".repeat(LIMIT),
            "a?".repeat(LIMIT),
            "a?".repeat(LIMIT),
            "a?".repeat(LIMIT)
        );
        assert!(!too_deep(&s));
        let hole = format!("x = `${{{}y}}`;", "a ? b : ".repeat(LIMIT));
        assert!(too_deep(&hole));
        // An unclosed quote on its line reads on as code.
        let open = format!("x = <p>don't {}y</p>;", "a ? b : ".repeat(LIMIT));
        assert!(too_deep(&open));
    }
}

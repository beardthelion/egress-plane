//! A second nesting pre-scan for the nesting the bracket pre-scan does not
//! count.
//!
//! `syn` recurses once per prefix operator (`- - x`), closure (`|| || x`),
//! right-associative assignment (`a = b = c`), `return`/`break` chain,
//! reference or pointer type (`&&T`), and generic argument level
//! (`Box<Box<T>>`), none of which is a bracket. Measured on a 64 MiB stack in
//! a debug build, `syn` 3.0.6 overflows at about 1,300 nested generic levels,
//! 2,000 reference types, 4,300 closures, 5,200 parentheses, 7,000 `return`s,
//! 8,700 assignments, and 17,000 unary minus signs; an overflow aborts the
//! process instead of unwinding.
//!
//! This scan lexes the file (skipping comments, strings, raw strings, and
//! character literals) and keeps, per open bracket, the count of tokens that
//! can nest the parser without a bracket. A comma or `;` ends a run of prefix
//! operators, `=>` and `;` end closures, and `>`, `;`, and `{` close generic
//! levels. The estimate is the sum over every open bracket of one plus its
//! counts; a file whose estimate exceeds [`MAX_CHAIN`] anywhere is too deeply
//! nested. The estimate over-counts (a long `a - b - c` statement adds up)
//! and never under-counts the families above, so a refusal fails closed as a
//! whole-file coverage gap.

/// Highest nesting estimate accepted; equal to the bracket pre-scan cap, so
/// even all-generic nesting stays under a fifth of the measured limit.
pub const MAX_CHAIN: usize = 256;

#[derive(Debug, Default, Clone, Copy)]
struct Frame {
    /// Prefix operators, assignments, and control-flow keywords in the
    /// current run.
    chain: usize,
    /// Closure pipes in the current run; commas inside closure parameter
    /// lists do not end it.
    pipes: usize,
    /// Open generic levels.
    angle: usize,
}

impl Frame {
    fn weight(&self) -> usize {
        self.chain + self.pipes + self.angle
    }
}

const CHAIN_WORDS: &[&str] = &[
    "return", "break", "yield", "box", "move", "become", "do", "dyn", "impl", "mut", "const",
    "async", "unsafe", "static", "ref",
];

/// Whether `text` nests deeper than [`MAX_CHAIN`].
pub fn too_deep(text: &str) -> bool {
    too_deep_with_cap(text, MAX_CHAIN)
}

fn too_deep_with_cap(text: &str, cap: usize) -> bool {
    let b = text.as_bytes();
    let n = b.len();
    let mut frames: Vec<Frame> = vec![Frame::default()];
    // Sum of `weight()` over all frames plus the open-bracket count.
    let mut total: usize = 0;
    let mut i = 0;
    macro_rules! bump {
        ($field:ident, $by:expr) => {{
            let f = frames.last_mut().expect("root frame");
            f.$field += $by;
            total += $by;
            if total > cap {
                return true;
            }
        }};
    }
    macro_rules! reset {
        ($field:ident) => {{
            let f = frames.last_mut().expect("root frame");
            total -= f.$field;
            f.$field = 0;
        }};
    }
    while i < n {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 0usize;
                while i < n {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' => i = skip_string(b, i + 1),
            b'\'' => i = skip_quote(b, i),
            b'(' | b'[' | b'{' => {
                if c == b'{' {
                    reset!(angle);
                }
                frames.push(Frame::default());
                total += 1;
                if total > cap {
                    return true;
                }
                i += 1;
            }
            b')' | b']' | b'}' => {
                if frames.len() > 1 {
                    let f = frames.pop().expect("frame");
                    total -= f.weight() + 1;
                }
                if c == b'}' {
                    reset!(chain);
                    reset!(pipes);
                    reset!(angle);
                }
                i += 1;
            }
            b',' => {
                reset!(chain);
                i += 1;
            }
            b';' => {
                reset!(chain);
                reset!(pipes);
                reset!(angle);
                i += 1;
            }
            b'<' => {
                if b.get(i + 1) == Some(&b'=') {
                    i += 2;
                } else if b.get(i + 1) == Some(&b'<') {
                    if b.get(i + 2) == Some(&b'=') {
                        bump!(chain, 1);
                        i += 3;
                    } else {
                        bump!(angle, 2);
                        i += 2;
                    }
                } else {
                    bump!(angle, 1);
                    i += 1;
                }
            }
            b'>' => {
                if b.get(i + 1) == Some(&b'=') {
                    bump!(chain, 1);
                    i += 2;
                } else if b.get(i + 1) == Some(&b'>') {
                    if b.get(i + 2) == Some(&b'=') {
                        bump!(chain, 1);
                        i += 3;
                    } else {
                        close_angle(&mut frames, &mut total, 2);
                        i += 2;
                    }
                } else {
                    close_angle(&mut frames, &mut total, 1);
                    i += 1;
                }
            }
            b'=' => {
                if b.get(i + 1) == Some(&b'>') {
                    reset!(chain);
                    reset!(pipes);
                    i += 2;
                } else if b.get(i + 1) == Some(&b'=') {
                    i += 2;
                } else {
                    bump!(chain, 1);
                    i += 1;
                }
            }
            b'|' => {
                bump!(pipes, 1);
                i += if b.get(i + 1) == Some(&b'|') { 2 } else { 1 };
            }
            b'-' if b.get(i + 1) == Some(&b'>') => i += 2,
            b'-' | b'!' | b'*' | b'&' | b'@' | b'+' | b'%' | b'^' => {
                bump!(chain, 1);
                i += 1;
            }
            b'.' if b.get(i + 1) == Some(&b'.') => {
                bump!(chain, 1);
                i += 2;
            }
            b'r' | b'b' | b'c' if raw_or_prefixed_string(b, i).is_some() => {
                i = raw_or_prefixed_string(b, i).unwrap_or(i + 1);
            }
            c if c == b'_' || c.is_ascii_alphabetic() || c >= 0x80 => {
                let start = i;
                while i < n && (b[i] == b'_' || b[i].is_ascii_alphanumeric() || b[i] >= 0x80) {
                    i += 1;
                }
                let word = &text[start..i];
                if CHAIN_WORDS.contains(&word) {
                    bump!(chain, 1);
                }
            }
            _ => i += 1,
        }
    }
    false
}

fn close_angle(frames: &mut [Frame], total: &mut usize, by: usize) {
    if let Some(f) = frames.last_mut() {
        let k = by.min(f.angle);
        f.angle -= k;
        *total -= k;
    }
}

/// The index after a string body that starts at `i` (just past the quote).
fn skip_string(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

/// Skips a character literal or a lifetime starting at the quote `i`.
fn skip_quote(b: &[u8], i: usize) -> usize {
    match b.get(i + 1) {
        Some(b'\\') => {
            let mut k = i + 2;
            while k < b.len() && b[k] != b'\'' && b[k] != b'\n' {
                k += 1;
            }
            k + 1
        }
        Some(_) => {
            // One character (possibly multi-byte) followed by a quote is a
            // character literal; anything else is a lifetime or label.
            let mut k = i + 1;
            k += 1;
            while k < b.len() && (b[k] & 0xC0) == 0x80 {
                k += 1;
            }
            if b.get(k) == Some(&b'\'') {
                k + 1
            } else {
                i + 1
            }
        }
        None => i + 1,
    }
}

/// The index after a raw or prefixed string (`r"..."`, `r#"..."#`, `b"..."`,
/// `br"..."`, `c"..."`, `b'x'`) starting at `i`, or `None` when `i` starts
/// an identifier.
fn raw_or_prefixed_string(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1] == b'_' || b[i - 1].is_ascii_alphanumeric()) {
        return None;
    }
    let mut k = i;
    if b[k] == b'b' || b[k] == b'c' {
        k += 1;
        match b.get(k) {
            Some(b'"') => return Some(skip_string(b, k + 1)),
            Some(b'\'') if b[i] == b'b' => return Some(skip_quote(b, k)),
            Some(b'r') => {}
            _ => return None,
        }
    }
    if b.get(k) != Some(&b'r') {
        return None;
    }
    k += 1;
    let mut hashes = 0;
    while b.get(k) == Some(&b'#') {
        hashes += 1;
        k += 1;
    }
    if b.get(k) != Some(&b'"') {
        return None;
    }
    k += 1;
    while k < b.len() {
        if b[k] == b'"'
            && b[k + 1..]
                .iter()
                .take(hashes)
                .filter(|x| **x == b'#')
                .count()
                == hashes
        {
            return Some(k + 1 + hashes);
        }
        k += 1;
    }
    Some(b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_code_passes() {
        let src = "use std::collections::HashMap;\nfn f<T: Clone>(x: &mut Vec<Option<T>>) -> Result<(), Box<dyn std::error::Error>> {\n    let a = [-1, -2, -3, !0, *&4];\n    if a.len() < 3 && b > 2 { return Ok(()); }\n    let s = r#\"<<<<<<\"#; let c = '<'; let l: &'static str = \"((((\";\n    Ok(())\n}\n";
        assert!(!too_deep_with_cap(src, 16));
    }

    #[test]
    fn each_family_is_counted() {
        for (unit, open, close) in [
            ("-", "", ""),
            ("|a, b| ", "", ""),
            ("Box<", "", ""),
            ("a = ", "", ""),
            ("return ", "", ""),
            ("&", "", ""),
            ("- (", "", ")"),
        ] {
            let src = format!(
                "fn f() {{ {open}{}x{} }}",
                unit.repeat(300),
                close.repeat(300)
            );
            assert!(too_deep(&src), "{unit}");
        }
    }

    #[test]
    fn commas_do_not_hide_generic_or_closure_nesting() {
        let generic = format!("type T = {}u8{};", "A<u8, ".repeat(300), ">".repeat(300));
        assert!(too_deep(&generic));
        let closures = format!("fn f() {{ {}x; }}", "|a, b| ".repeat(300));
        assert!(too_deep(&closures));
    }
}

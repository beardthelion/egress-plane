//! `//go:` directive detection (KTD7, KTD12).
//!
//! `//go:linkname` comes from the line comments in the token stream, the
//! same place `//go:build` and the generated-header marker come from.
//! `//go:generate` is different: `go generate` reads raw source lines
//! without tokenizing, so a column-0 directive inside a raw string or a
//! `/* */` block still runs, and detection here follows the toolchain's
//! `isGoGenerate` rule over the decoded text. A directive's text is a
//! construct string, never a command the frontend runs or resolves.

use gosyn::LexicalToken;
use gosyn::token::Token;

/// Spans of `//go:linkname` directives, as token scalar offsets. A line
/// comment is a directive when it starts exactly with `//go:linkname `:
/// no space after `//`, and a space separating the arguments.
pub fn linkname(tokens: &[LexicalToken]) -> Vec<(usize, usize)> {
    tokens
        .iter()
        .filter_map(|t| match &t.token {
            Token::Comment(text) => {
                let text = text.strip_suffix('\r').unwrap_or(text.as_str());
                text.starts_with("//go:linkname ")
                    .then_some((t.start, t.end))
            }
            _ => None,
        })
        .collect()
}

/// Spans of `//go:generate` lines, as scalar offsets covering the whole
/// line without its newline. A line is a directive when it begins at
/// column 0 with `//go:generate ` or `//go:generate` + a tab; an indented
/// line or a space after `//` is not.
pub fn generate(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        if body.starts_with("//go:generate ") || body.starts_with("//go:generate\t") {
            out.push((start, start + body.chars().count()));
        }
        start += line.chars().count();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linkname_needs_the_exact_prefix() {
        let src = "package p\n\n//go:linkname a b.c\n// go:linkname x y.z\n//go:linkname\n";
        let tokens = gosyn::tokenize_source(src).unwrap();
        assert_eq!(linkname(&tokens), vec![(11, 30)]);
    }

    #[test]
    fn generate_reads_raw_lines() {
        let src = concat!(
            "package p\n",
            "//go:generate one\n",
            "\t//go:generate indented\n",
            "// go:generate spaced\n",
            "//go:generate\ttab\n",
            "var s = `\n",
            "//go:generate inside\n",
            "more`\n",
        );
        assert_eq!(generate(src), vec![(10, 27), (74, 91), (102, 122)]);
    }
}

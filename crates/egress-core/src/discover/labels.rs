//! File labels from `data/labels.toml`. Labels never change what
//! is scanned.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::model::Label;

/// Raw text of `data/labels.toml`.
pub const LABELS_TOML: &str = include_str!("../../../../data/labels.toml");

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(default)]
    dirs: Vec<String>,
    #[serde(default)]
    name_globs: Vec<String>,
    #[serde(default)]
    name_suffixes: Vec<String>,
    #[serde(default)]
    header_markers: Vec<String>,
    #[serde(default)]
    header_lines: usize,
    max_line_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rules {
    vendored: Rule,
    generated: Rule,
    minified: Rule,
    test: Rule,
}

impl Rules {
    fn each(&self) -> [(Label, &Rule); 4] {
        [
            (Label::Vendored, &self.vendored),
            (Label::Generated, &self.generated),
            (Label::Minified, &self.minified),
            (Label::Test, &self.test),
        ]
    }
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| toml::from_str(LABELS_TOML).expect("embedded data/labels.toml"))
}

/// Matches `name` against a pattern where `*` matches any run of bytes.
pub fn glob(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|i| glob(rest, &name[i..])),
        Some((c, rest)) => name
            .split_first()
            .is_some_and(|(n, nr)| n == c && glob(rest, nr)),
    }
}

/// Labels implied by a repo-relative path, sorted.
pub fn path_labels(path: &[u8]) -> Vec<Label> {
    let parts: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
    let (name, dirs) = parts
        .split_last()
        .map_or((&b""[..], &[][..]), |(n, d)| (*n, d));
    let mut out = Vec::new();
    for (label, rule) in rules().each() {
        let hit = rule.dirs.iter().any(|d| dirs.contains(&d.as_bytes()))
            || rule.name_globs.iter().any(|g| glob(g.as_bytes(), name))
            || rule
                .name_suffixes
                .iter()
                .any(|s| name.ends_with(s.as_bytes()));
        if hit {
            out.push(label);
        }
    }
    out
}

/// Labels implied by file contents, sorted.
pub fn content_labels(text: &str) -> Vec<Label> {
    let mut out = Vec::new();
    for (label, rule) in rules().each() {
        let header = !rule.header_markers.is_empty()
            && text
                .lines()
                .take(rule.header_lines)
                .any(|l| rule.header_markers.iter().any(|m| l.contains(m.as_str())));
        let long = rule.max_line_chars.is_some_and(|max| {
            text.lines()
                .any(|l| l.len() > max && l.chars().count() > max)
        });
        if header || long {
            out.push(label);
        }
    }
    out
}

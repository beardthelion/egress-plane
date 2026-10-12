//! File labels from `data/labels.toml`. Labels never change what
//! is scanned.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::model::{Label, Language};

/// Raw text of `data/labels.toml`.
pub const LABELS_TOML: &str = include_str!("../../../../data/labels.toml");

/// One label's rules. A `[<label>.<language>]` table adds patterns that
/// apply only to files of that language (KTD16); the key must be a
/// `Language` name.
#[derive(Debug, Default, Deserialize)]
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
    #[serde(flatten)]
    per_language: BTreeMap<String, Rule>,
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

/// Parses label rules; a per-language table must be keyed by a
/// `Language` name and holds no deeper nesting.
fn parse(text: &str) -> Result<Rules, String> {
    let rules: Rules =
        toml::from_str(text).map_err(|e| format!("data/labels.toml: malformed: {e}"))?;
    for (label, rule) in rules.each() {
        for (name, sub) in &rule.per_language {
            if Language::parse(name).is_none() {
                return Err(format!(
                    "data/labels.toml: {} has a per-language table for unknown language {name:?}",
                    label.as_str()
                ));
            }
            if !sub.per_language.is_empty() {
                return Err(format!(
                    "data/labels.toml: {}.{name} cannot nest a per-language table",
                    label.as_str()
                ));
            }
        }
    }
    Ok(rules)
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| parse(LABELS_TOML).expect("embedded data/labels.toml"))
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

/// Whether `rule` matches a path split into `dirs` and `name`.
fn path_match(rule: &Rule, dirs: &[&[u8]], name: &[u8]) -> bool {
    rule.dirs.iter().any(|d| dirs.contains(&d.as_bytes()))
        || rule.name_globs.iter().any(|g| glob(g.as_bytes(), name))
        || rule
            .name_suffixes
            .iter()
            .any(|s| name.ends_with(s.as_bytes()))
}

/// Whether `rule` matches file contents.
fn content_match(rule: &Rule, text: &str) -> bool {
    (!rule.header_markers.is_empty()
        && text
            .lines()
            .take(rule.header_lines)
            .any(|l| rule.header_markers.iter().any(|m| l.contains(m.as_str()))))
        || rule.max_line_chars.is_some_and(|max| {
            text.lines()
                .any(|l| l.len() > max && l.chars().count() > max)
        })
}

/// The per-language table `language` adds to `rule`, if any.
fn per_language(rule: &Rule, language: Option<Language>) -> Option<&Rule> {
    language.and_then(|l| rule.per_language.get(l.as_str()))
}

/// Labels implied by a repo-relative path, sorted. `language` is the
/// language the path scans or is reported under, when known; a rule's
/// per-language table applies only to that language.
pub fn path_labels(path: &[u8], language: Option<Language>) -> Vec<Label> {
    path_labels_in(rules(), path, language)
}

fn path_labels_in(rules: &Rules, path: &[u8], language: Option<Language>) -> Vec<Label> {
    let parts: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
    let (name, dirs) = parts
        .split_last()
        .map_or((&b""[..], &[][..]), |(n, d)| (*n, d));
    let mut out = Vec::new();
    for (label, rule) in rules.each() {
        let hit = path_match(rule, dirs, name)
            || per_language(rule, language).is_some_and(|r| path_match(r, dirs, name));
        if hit {
            out.push(label);
        }
    }
    out
}

/// Labels implied by file contents, sorted. A rule's per-language table
/// applies only to files of that language.
pub fn content_labels(text: &str, language: Language) -> Vec<Label> {
    let mut out = Vec::new();
    for (label, rule) in rules().each() {
        let hit = content_match(rule, text)
            || per_language(rule, Some(language)).is_some_and(|r| content_match(r, text));
        if hit {
            out.push(label);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "[vendored]\n[generated]\n[minified]\n[test]\n";

    #[test]
    fn a_per_language_table_parses_and_applies_only_to_its_language() {
        let rules = parse(&format!("{BASE}[test.python]\nname_globs = [\"test_*\"]\n"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            path_labels_in(&rules, b"test_x", Some(Language::Python)),
            vec![Label::Test]
        );
        assert!(path_labels_in(&rules, b"test_x", Some(Language::Rust)).is_empty());
        assert!(path_labels_in(&rules, b"test_x", None).is_empty());
    }

    #[test]
    fn a_per_language_table_for_an_unknown_language_fails_naming_it() {
        let e = parse(&format!("{BASE}[test.haskell]\nname_globs = [\"x\"]\n")).unwrap_err();
        assert!(e.contains("haskell"), "{e}");
        let e = parse(&format!("{BASE}[test.python.foo]\nname_globs = [\"x\"]\n")).unwrap_err();
        assert!(e.contains("python"), "{e}");
    }
}

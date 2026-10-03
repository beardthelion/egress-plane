//! Credential redaction (KTD11, R21).
//!
//! Rules come from `data/redaction.toml`; the classes are fixed here and the
//! keys, prefixes, and provider patterns are data. [`redact`] runs during
//! destination normalization and on construct text, before identity and
//! before truncation, so no output and no identity key carries a recognized
//! secret. Every rewrite is textual: text without a recognized secret comes
//! back byte for byte.

use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;

/// The fixed replacement token.
pub const REDACTED: &str = "<redacted>";

/// The embedded rule file, also hashed into `tool.data_digest`.
pub const REDACTION_TOML: &str = include_str!("../../../data/redaction.toml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    keys: Vec<String>,
    token_prefixes: Vec<String>,
    path_secrets: Vec<RawPathSecret>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPathSecret {
    name: String,
    pattern: String,
}

/// Compiled redaction rules.
#[derive(Debug)]
pub struct Rules {
    /// Lowercased keys for query, fragment, and keyword DSN values.
    pub keys: Vec<String>,
    pub token_prefixes: Vec<String>,
    /// `(name, pattern)`; each pattern has a named group `secret`.
    pub path_secrets: Vec<(String, Regex)>,
}

impl Rules {
    /// Parses and checks a rule file.
    pub fn parse(text: &str) -> Result<Self, String> {
        let raw: RawRules = toml::from_str(text).map_err(|e| format!("redaction rules: {e}"))?;
        let mut path_secrets = Vec::new();
        for p in raw.path_secrets {
            let re =
                Regex::new(&p.pattern).map_err(|e| format!("redaction rule {}: {e}", p.name))?;
            if !re.capture_names().any(|n| n == Some("secret")) {
                return Err(format!("redaction rule {}: no `secret` group", p.name));
            }
            path_secrets.push((p.name, re));
        }
        for k in &raw.keys {
            if k.is_empty() || !k.is_ascii() {
                return Err(format!("redaction key {k:?} must be non-empty ASCII"));
            }
        }
        for p in &raw.token_prefixes {
            if p.is_empty() || !p.is_ascii() {
                return Err(format!("token prefix {p:?} must be non-empty ASCII"));
            }
        }
        Ok(Self {
            keys: raw.keys.iter().map(|k| k.to_ascii_lowercase()).collect(),
            token_prefixes: raw.token_prefixes,
            path_secrets,
        })
    }
}

/// The embedded rules. The file is compiled in and checked by tests, so a
/// failure here is a build defect.
pub fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| Rules::parse(REDACTION_TOML).expect("embedded data/redaction.toml"))
}

struct Patterns {
    url: Regex,
    param: Regex,
    keyed: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        // A URL runs from its scheme to the next whitespace or quote.
        url: Regex::new(r#"[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'`]*"#).expect("url pattern"),
        // A `key=value` pair after `?`, `&`, or `#`.
        param: Regex::new(r#"[?&#](?P<key>[^?&#=\s"'`]+)=(?P<value>[^?&#\s"'`]*)"#)
            .expect("param pattern"),
        // A keyed entry: a libpq or call keyword pair (`key=value`) or a
        // dict or object entry (`key: value`, the key bare or quoted), at the
        // start of the text or after whitespace, `(`, `[`, `{`, `,`, or `;`.
        // The match ends where the value starts; see [`value_end`]. A key
        // with an opening quote and no closing one (`"Authorization: x"`)
        // sits inside a string literal, and its value ends at that quote.
        keyed: Regex::new(
            r#"(?:^|[\s(\[{,;])(?P<open>["'`])?(?P<key>[A-Za-z_][A-Za-z0-9_-]*)(?P<close>["'`])?\s*(?P<sep>[=:])\s*"#,
        )
        .expect("keyed pattern"),
    })
}

/// Replaces every recognized credential in `text` with [`REDACTED`].
pub fn redact(text: &str) -> String {
    redact_with(rules(), text)
}

/// [`redact`] with explicit rules.
pub fn redact_with(rules: &Rules, text: &str) -> String {
    let p = patterns();
    let text = replace_spans(text, userinfo_spans(&p.url, text));
    let spans = p
        .param
        .captures_iter(&text)
        .filter(|c| key_matches(rules, &c["key"]) && !c["value"].is_empty())
        .filter_map(|c| c.name("value").map(|m| (m.start(), m.end())))
        .collect();
    let text = replace_spans(&text, spans);
    let mut text = text;
    for (_, re) in &rules.path_secrets {
        let spans = re
            .captures_iter(&text)
            .filter_map(|c| c.name("secret").map(|m| (m.start(), m.end())))
            .collect();
        text = replace_spans(&text, spans);
    }
    let spans = keyed_spans(&p.keyed, rules, &text);
    let text = replace_spans(&text, spans);
    let spans = token_spans(rules, &text);
    replace_spans(&text, spans)
}

/// Value spans of keyed entries whose key is listed. A `==`, `=>`, or `::`
/// after the key is a comparison, an arrow, or a path, not an entry.
///
/// A match whose value starts inside the previous span is skipped: that text
/// is already redacted, and scanning it again would make the pass quadratic
/// on unbalanced input. Every scan then covers text after the last one, so
/// the pass is linear.
fn keyed_spans(keyed: &Regex, rules: &Rules, text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut covered = 0usize;
    for c in keyed.captures_iter(text) {
        let sep = c.name("sep").expect("sep group");
        let follow = bytes.get(sep.end()).copied();
        let not_entry = match sep.as_str() {
            "=" => matches!(follow, Some(b'=' | b'>')),
            _ => follow == Some(b':'),
        };
        if not_entry || !key_matches(rules, &c["key"]) {
            continue;
        }
        let start = c.get(0).expect("whole match").end();
        if start < covered {
            continue;
        }
        // A key opened by a quote that is not closed before the separator
        // lies inside a string literal; its value ends at that quote.
        let in_string = match (c.name("open"), c.name("close")) {
            (Some(q), None) => Some(q.as_str().as_bytes()[0]),
            _ => None,
        };
        // An already redacted value is redacted again to the same text, so
        // redaction is idempotent and a literal `<redacted>` in the source
        // cannot hide the rest of the value.
        let end = value_end(bytes, start, in_string);
        if end > start {
            spans.push((start, end));
            covered = end;
        }
    }
    spans
}

/// The end of the value that starts at `start`: the value runs to the end
/// of its entry. Quoted runs are skipped whole (`'`, `"`, `` ` ``, and
/// Python triple quotes; a string prefix such as `b`, `r`, or `f` is
/// ordinary text before the quote), and brackets nest. At bracket depth 0
/// the value stops before a `,`, `;`, newline, an unmatched closing bracket,
/// the `in_string` quote that encloses the entry, or whitespace followed by
/// another `key=` (libpq DSN text such as `host=db password=x port=5`).
/// Unbalanced input runs to the end of the text (fail closed). Trailing
/// whitespace is not part of the value.
fn value_end(bytes: &[u8], start: usize, in_string: Option<u8>) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    let mut end = start;
    while i < bytes.len() {
        let b = bytes[i];
        if depth == 0 {
            if Some(b) == in_string || matches!(b, b',' | b';' | b'\n') {
                return end;
            }
            if b.is_ascii_whitespace() {
                // Skip the whole run so a long one is scanned once.
                while i < bytes.len() && bytes[i].is_ascii_whitespace() && bytes[i] != b'\n' {
                    i += 1;
                }
                if starts_keyword_pair(bytes, i) {
                    return end;
                }
                continue;
            }
        }
        match b {
            b'\\' if in_string.is_some() => {
                i = (i + 2).min(bytes.len());
                end = i;
                continue;
            }
            b'\'' | b'"' | b'`' => {
                i = quoted_end(bytes, i);
                end = i;
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return end;
                }
                depth -= 1;
            }
            _ => {}
        }
        i += 1;
        if !b.is_ascii_whitespace() {
            end = i;
        }
    }
    if depth > 0 { bytes.len() } else { end }
}

/// Whether a `key=` pair (not `==` or `=>`) starts at `i`.
fn starts_keyword_pair(bytes: &[u8], mut i: usize) -> bool {
    if !bytes
        .get(i)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return false;
    }
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-')) {
        i += 1;
    }
    bytes.get(i) == Some(&b'=') && !matches!(bytes.get(i + 1), Some(b'=' | b'>'))
}

/// The end of the quoted run that starts at `start`, through its closing
/// quote (three quotes for a triple-quoted string), or the end of the text
/// when it is unterminated.
fn quoted_end(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let triple = [quote; 3];
    let closing: &[u8] = if bytes[start..].starts_with(&triple) {
        &triple
    } else {
        &triple[..1]
    };
    let mut i = start + closing.len();
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i..].starts_with(closing) {
            return i + closing.len();
        } else {
            i += 1;
        }
    }
    bytes.len()
}

/// Whether a parameter or keyed-entry key is listed: ASCII case-insensitive, whole
/// or as a suffix, after percent-decoding.
fn key_matches(rules: &Rules, key: &str) -> bool {
    let decoded = percent_decode(key).to_ascii_lowercase();
    rules.keys.iter().any(|k| decoded.ends_with(k.as_str()))
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("k={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

/// Userinfo spans of every URL in `text`.
fn userinfo_spans(url_re: &Regex, text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for m in url_re.find_iter(text) {
        let candidate = m.as_str();
        let Some(sep) = candidate.find("://") else {
            continue;
        };
        let start = sep + 3;
        let rest = &candidate[start..];
        let span = match url::Url::parse(candidate) {
            Ok(u) => {
                if u.username().is_empty() && u.password().is_none() {
                    None
                } else {
                    // The authority ends at the first `/`, `?`, or `#`, and at
                    // `\` for the special schemes that treat it as `/`.
                    let special =
                        matches!(u.scheme(), "http" | "https" | "ws" | "wss" | "ftp" | "file");
                    let end = rest
                        .find(|c: char| c == '/' || c == '?' || c == '#' || (special && c == '\\'))
                        .unwrap_or(rest.len());
                    rest[..end].rfind('@').or_else(|| fail_closed_at(rest))
                }
            }
            Err(_) => fail_closed_at(rest),
        };
        if let Some(at) = span
            && at > 0
        {
            spans.push((m.start() + start, m.start() + start + at));
        }
    }
    spans
}

/// The last `@` before the first `/` (KTD11 fail-closed rule).
fn fail_closed_at(rest: &str) -> Option<usize> {
    let end = rest.find('/').unwrap_or(rest.len());
    rest[..end].rfind('@')
}

/// Spans of token runs: a known prefix at a token boundary followed by at
/// least one character of `[A-Za-z0-9_.-]`.
fn token_spans(rules: &Rules, text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let run = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.');
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if boundary
            && let Some(p) = rules
                .token_prefixes
                .iter()
                .find(|p| bytes[i..].starts_with(p.as_bytes()))
        {
            let mut end = i + p.len();
            while end < bytes.len() && run(bytes[end]) {
                end += 1;
            }
            if end > i + p.len() {
                spans.push((i, end));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    spans
}

/// Replaces each byte span with [`REDACTED`]. Spans are sorted and
/// non-overlapping by construction; overlapping ones merge.
fn replace_spans(text: &str, mut spans: Vec<(usize, usize)>) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    spans.sort();
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for (s, e) in spans {
        if e <= pos {
            continue;
        }
        let s = s.max(pos);
        out.push_str(&text[pos..s]);
        out.push_str(REDACTED);
        pos = e;
    }
    out.push_str(&text[pos..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_parse_and_hold_every_class() {
        let r = rules();
        assert!(r.keys.iter().any(|k| k == "access_token"));
        assert!(r.token_prefixes.iter().any(|p| p == "eyJ"));
        let names: Vec<&str> = r.path_secrets.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "telegram-bot-token",
                "slack-webhook",
                "discord-webhook",
                "authorization-scheme",
                "authorization-header"
            ]
        );
    }

    #[test]
    fn a_pattern_without_a_secret_group_is_refused() {
        let bad =
            "keys = []\ntoken_prefixes = []\n[[path_secrets]]\nname = \"x\"\npattern = \"/a\"\n";
        assert!(Rules::parse(bad).is_err());
    }
}

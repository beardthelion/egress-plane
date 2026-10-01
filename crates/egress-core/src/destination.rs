//! Destination normalization (KTD7) with redaction applied inside (KTD11).

use crate::model::{Destination, DestinationKind};
use crate::redact::redact;

/// Maximum length of `expr:` text and blind-spot construct text, in Unicode
/// scalar values, applied after redaction.
pub const MAX_TEXT_CHARS: usize = 120;

impl DestinationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Env => "env",
            Self::Param => "param",
            Self::Template => "template",
            Self::Exec => "exec",
            Self::Lib => "lib",
            Self::Expr => "expr",
        }
    }
}

/// One part of a template destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatePart {
    Literal(String),
    /// A symbolic hole, rendered as `{<display>}`.
    Hole(Destination),
}

fn make(kind: DestinationKind, value: String, default: Option<String>) -> Destination {
    let display = match kind {
        DestinationKind::Literal | DestinationKind::Template => value.clone(),
        DestinationKind::Env => format!("env:{value}"),
        DestinationKind::Param => format!("param:{value}"),
        DestinationKind::Exec => format!("exec:{value}"),
        DestinationKind::Lib => format!("lib:{value}"),
        DestinationKind::Expr => format!("expr:{value}"),
    };
    Destination {
        kind,
        value,
        default,
        display,
    }
}

/// A literal URL, host, `host:port`, or path, kept exact apart from
/// redaction.
pub fn literal(text: &str) -> Destination {
    make(DestinationKind::Literal, redact(text), None)
}

/// An environment read `env:NAME` with an optional literal default (KTD7).
pub fn env(name: &str, default: Option<&str>) -> Destination {
    make(DestinationKind::Env, redact(name), default.map(redact))
}

/// Parameter `index` (1-based, excluding `self`, `cls`, and Rust receivers)
/// of the function at symbol path `function`: `param:N:<function>` (R20).
pub fn param(index: u32, function: &str) -> Destination {
    make(
        DestinationKind::Param,
        format!("{index}:{}", redact(function)),
        None,
    )
}

/// A process spawn: `exec:<program>`.
pub fn exec(program: &str) -> Destination {
    make(DestinationKind::Exec, redact(program), None)
}

/// A library load: `lib:<library>`.
pub fn lib(library: &str) -> Destination {
    make(DestinationKind::Lib, redact(library), None)
}

/// Anything unresolvable: `expr:<rendered source>`, whitespace-collapsed,
/// redacted, then truncated to [`MAX_TEXT_CHARS`].
pub fn expr(source: &str) -> Destination {
    make(DestinationKind::Expr, normalize_text(source), None)
}

/// A template with symbolic holes, redacted in its rendered form so a secret
/// split between literal parts and holes is caught (KTD11). A template with
/// no hole is a literal, and a template that is one hole is that hole.
pub fn template(parts: &[TemplatePart]) -> Destination {
    let holes = parts
        .iter()
        .filter(|p| matches!(p, TemplatePart::Hole(_)))
        .count();
    if let [TemplatePart::Hole(d)] = parts {
        return d.clone();
    }
    let mut rendered = String::new();
    for p in parts {
        match p {
            TemplatePart::Literal(t) => rendered.push_str(t),
            TemplatePart::Hole(d) => {
                rendered.push('{');
                rendered.push_str(&d.display);
                rendered.push('}');
            }
        }
    }
    let kind = if holes == 0 {
        DestinationKind::Literal
    } else {
        DestinationKind::Template
    };
    make(kind, redact(&rendered), None)
}

/// Blind-spot construct text: whitespace-collapsed, redacted, then truncated
/// to [`MAX_TEXT_CHARS`] (KTD11). KTD18 escaping happens at output.
pub fn construct_text(source: &str) -> String {
    normalize_text(source)
}

/// Collapses every whitespace run to one space and trims, so CRLF and LF
/// sources give the same text, then redacts, then truncates.
fn normalize_text(source: &str) -> String {
    let collapsed = source.split_whitespace().collect::<Vec<_>>().join(" ");
    redact(&collapsed).chars().take(MAX_TEXT_CHARS).collect()
}

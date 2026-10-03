//! Escaping of untrusted strings for every rendered form.
//!
//! Every string taken from scanned input passes through [`escape`] before it
//! reaches the text report or a JSON `display` field, so a crafted file name
//! or literal cannot emit terminal sequences or forge report structure.
//! Escaping is presentation only and never enters identity.

use std::fmt::Write;

use unicode_general_category::{GeneralCategory, get_general_category};

/// Whether `c` is escaped: general categories Cc (C0 and C1 controls, DEL),
/// Cf (bidi controls and marks, zero-width characters, tag characters), Zl,
/// and Zp.
pub fn needs_escape(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

/// Renders every character that [`needs_escape`] as `\u{..}` with lowercase
/// hex and leaves every other character unchanged.
pub fn escape(s: &str) -> String {
    if !s.chars().any(needs_escape) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        if needs_escape(c) {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

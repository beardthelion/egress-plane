//! PEP 263 source decoding for Python files (KTD12).
//!
//! The cookie sniff runs on raw bytes, so a non-UTF-8 byte before the
//! cookie cannot break it. Detection follows CPython: the cookie
//! `coding[:=][ \t]*<name>` inside a comment on line 1, or on line 2
//! only when line 1 is blank or comment-only; lines end at LF, CRLF,
//! or a lone CR. Names normalize like CPython's `get_normal_name`
//! (case-insensitive, `-`/`_`/`. `equivalent) and look up a fixed
//! allowlist; decoders are hand-written, no codec crate.
//!
//! Off the allowlist, an unknown name, or a non-UTF-8 cookie beside a
//! UTF-8 BOM is a whole-file `unsupported-encoding` gap: the bytes are
//! never parsed as UTF-8.

/// The allowlist family a cookie names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Utf8,
    Latin1,
    Ascii,
}

/// What the sniff found in the first two lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cookie {
    /// No cookie on an allowed line.
    Absent,
    /// A normalized name on the allowlist.
    Allowed(Family),
    /// A name off the allowlist or unknown.
    Unsupported,
}

/// The line the sniff allows a cookie on, split at LF, CRLF, or a lone
/// CR, as CPython's universal-newline reading does.
fn line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
    if start >= bytes.len() {
        return None;
    }
    let rest = &bytes[start..];
    for (i, &b) in rest.iter().enumerate() {
        if b == b'\n' || b == b'\r' {
            let next = start + i + 1 + usize::from(b == b'\r' && rest.get(i + 1) == Some(&b'\n'));
            return Some((&rest[..i], next));
        }
    }
    Some((rest, bytes.len()))
}

/// Whether `line` is blank or a comment only: a cookie may sit after it.
fn blank_or_comment(line: &[u8]) -> bool {
    let t = line
        .iter()
        .position(|&b| b != b' ' && b != b'\t' && b != b'\x0c');
    t.is_none_or(|i| line[i] == b'#')
}

/// The cookie name `line` carries, or `None`. Mirrors CPython's
/// `^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)`.
fn cookie_on(line: &[u8]) -> Option<Vec<u8>> {
    let i = line
        .iter()
        .position(|&b| b != b' ' && b != b'\t' && b != b'\x0c')?;
    let bytes = &line[i..];
    // The first non-whitespace must be `#`; `.*?` allows anything after.
    if bytes[0] != b'#' {
        return None;
    }
    let text = &bytes[1..];
    let marker: &[u8] = b"coding";
    // `.*?` before `coding[:=]` is non-greedy: the FIRST `coding`
    // followed by `:` or `=` wins.
    let mut i = 0;
    while i + marker.len() < text.len() {
        if &text[i..i + marker.len()] == marker
            && matches!(text.get(i + marker.len()), Some(b':') | Some(b'='))
        {
            let mut j = i + marker.len() + 1;
            while matches!(text.get(j), Some(b' ') | Some(b'\t')) {
                j += 1;
            }
            let start = j;
            while matches!(text.get(j), Some(&c) if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
            {
                j += 1;
            }
            if j == start {
                return None;
            }
            return Some(text[start..j].to_vec());
        }
        i += 1;
    }
    None
}

/// CPython's `get_normal_name`: lowercase, `-`/`_`/`. ` unified.
fn normalize(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|&b| match b {
            b'_' | b'.' => b'-',
            _ => b.to_ascii_lowercase(),
        })
        .collect()
}

/// The allowlist: names after normalization (KTD12's table).
fn family(name: &[u8]) -> Option<Family> {
    let n = normalize(name);
    let n = n.as_slice();
    if n == b"utf-8" || n == b"utf8" || n.starts_with(b"utf-8-") {
        return Some(Family::Utf8);
    }
    if matches!(
        n,
        b"latin-1" | b"latin1" | b"iso-8859-1" | b"iso8859-1" | b"iso-latin-1" | b"l1"
    ) || n.starts_with(b"latin-1-")
        || n.starts_with(b"iso-8859-1-")
    {
        return Some(Family::Latin1);
    }
    if matches!(n, b"ascii" | b"us-ascii" | b"646") {
        return Some(Family::Ascii);
    }
    None
}

/// The cookie the raw bytes declare (KTD12's sniff window).
fn sniff(bytes: &[u8]) -> Cookie {
    let Some((l1, next)) = line(bytes, 0) else {
        return Cookie::Absent;
    };
    if let Some(n) = cookie_on(l1) {
        return match family(&n) {
            Some(f) => Cookie::Allowed(f),
            None => Cookie::Unsupported,
        };
    }
    if !blank_or_comment(l1) {
        return Cookie::Absent;
    }
    let Some((l2, _)) = line(bytes, next) else {
        return Cookie::Absent;
    };
    match cookie_on(l2) {
        Some(n) => match family(&n) {
            Some(f) => Cookie::Allowed(f),
            None => Cookie::Unsupported,
        },
        None => Cookie::Absent,
    }
}

/// Decodes a Python file's bytes per PEP 263 (R15, R16). `Err` maps to
/// the whole-file blind spot.
pub fn decode(bytes: &[u8]) -> Result<String, crate::model::BlindSpotKind> {
    use crate::model::BlindSpotKind;
    let bom = bytes.starts_with(b"\xef\xbb\xbf");
    match sniff(if bom { &bytes[3..] } else { bytes }) {
        Cookie::Absent => decode_utf8(bytes),
        Cookie::Unsupported => Err(BlindSpotKind::UnsupportedEncoding),
        Cookie::Allowed(Family::Utf8) => decode_utf8(bytes),
        Cookie::Allowed(_) if bom => Err(BlindSpotKind::UnsupportedEncoding),
        Cookie::Allowed(Family::Latin1) => Ok(bytes.iter().map(|&b| char::from(b)).collect()),
        Cookie::Allowed(Family::Ascii) => {
            if bytes.iter().all(|&b| b <= 0x7f) {
                Ok(String::from_utf8_lossy(bytes).into_owned())
            } else {
                Err(BlindSpotKind::Undecodable)
            }
        }
    }
}

/// The UTF-8 path every language shares: BOM stripped after decoding.
pub fn decode_utf8(bytes: &[u8]) -> Result<String, crate::model::BlindSpotKind> {
    let mut text =
        String::from_utf8(bytes.to_vec()).map_err(|_| crate::model::BlindSpotKind::Undecodable)?;
    if text.starts_with('\u{feff}') {
        text.drain(..'\u{feff}'.len_utf8());
    }
    Ok(text)
}

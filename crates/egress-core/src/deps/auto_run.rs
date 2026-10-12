//! The KTD16 auto-run line test for `*.pth` files: a line starting
//! with `import` followed by a space or tab makes the file run at
//! interpreter startup. The split follows Python's universal newlines
//! plus the other separators `str.splitlines()` recognizes; a file
//! that is not valid UTF-8 falls back to LF, CR, and CRLF only.

/// Line separators Python's `str.splitlines()` recognizes beyond the
/// ASCII set (VT, FF, FS, GS, RS, NEL, U+2028, U+2029).
fn utf8_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

fn import_line(line: &str) -> bool {
    let line = line.as_bytes();
    line.len() > 6 && line.starts_with(b"import") && matches!(line[6], b' ' | b'\t')
}

/// Whether the `.pth` contents carry an executable `import` line.
pub fn pth_has_import_line(bytes: &[u8]) -> bool {
    // Strip one leading UTF-8 BOM, then split.
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) => text.split(utf8_break).any(import_line),
        Err(_) => bytes
            .split(|b| matches!(b, b'\n' | b'\r'))
            .any(|l| import_line(&String::from_utf8_lossy(l))),
    }
}

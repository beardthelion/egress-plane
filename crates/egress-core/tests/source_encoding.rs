//! PEP 263 source decoding: cookie sniff on raw bytes, the allowlist,
//! and the whole-file `unsupported-encoding` gap (KTD12, R15, R16).

use egress_core::discover::encoding::decode;
use egress_core::model::BlindSpotKind::*;

fn ok(bytes: &[u8]) -> String {
    decode(bytes).unwrap()
}

fn err(bytes: &[u8]) -> &'static str {
    decode(bytes).unwrap_err().as_str()
}

#[test]
fn no_cookie_decodes_utf8() {
    assert_eq!(ok(b"print('hi')\n"), "print('hi')\n");
    assert_eq!(err(b"\xff\xfe"), "undecodable");
}

#[test]
fn latin1_cookie_on_line_one_decodes() {
    // AE7: a Latin-1 byte inside a string before a call decodes.
    let bytes = b"# coding: latin-1\nx = 'caf\xe9'\nprint(x)\n";
    let text = ok(bytes);
    assert!(text.contains("caf\u{e9}"), "{text}");
}

#[test]
fn cookie_on_line_two_after_a_comment_or_blank_line() {
    assert!(ok(b"# a comment\n# coding: latin-1\nx = '\xe9'\n").contains('\u{e9}'));
    assert!(ok(b"\n# coding: latin-1\nx = '\xe9'\n").contains('\u{e9}'));
}

#[test]
fn cookie_after_a_code_line_is_ignored() {
    // AE16: line 1 is code, so the line-2 cookie does not decode and a
    // non-UTF-8 byte reports undecodable.
    assert_eq!(
        err(b"x = 1\n# coding: latin-1\ny = '\xe9'\n"),
        "undecodable"
    );
    // With valid UTF-8 the ignored cookie means the file scans as UTF-8.
    assert_eq!(
        ok(b"x = 1\n# coding: utf-8\ny = 'z'\n"),
        "x = 1\n# coding: utf-8\ny = 'z'\n"
    );
}

#[test]
fn line_ends_lf_crlf_and_cr() {
    // CR-only file with the cookie on line 2 is honored.
    assert!(ok(b"# c\r# coding: latin-1\rx = '\xe9'\r").contains('\u{e9}'));
    // CR-only file with the cookie on line 3 is not in the window.
    assert_eq!(
        err(b"# a\rb\r# coding: latin-1\rx = '\xe9'\r"),
        "undecodable"
    );
    // CRLF file with the cookie on line 1 decodes.
    assert!(ok(b"# coding: latin-1\r\nx = '\xe9'\r\n").contains('\u{e9}'));
}

#[test]
fn normalization_table() {
    for name in [
        "utf-8",
        "utf8",
        "utf_8",
        "UTF-8",
        "utf-8-sig",
        "latin-1",
        "Latin-1",
        "latin_1",
        "latin-1-unix",
        "iso-8859-1",
        "iso_8859_1",
        "iso-latin-1",
        "ISO8859-1",
        "l1",
        "ascii",
        "us-ascii",
        "646",
    ] {
        let src = format!("# coding: {name}\nx = 1\n");
        assert!(
            decode(src.as_bytes()).is_ok(),
            "{name} should be allowlisted"
        );
    }
}

#[test]
fn off_allowlist_and_unknown_names_are_unsupported() {
    for name in ["utf-16", "cp1252", "shift-jis", "made-up-codec"] {
        let src = format!("# coding: {name}\nx = 1\n");
        assert_eq!(decode(src.as_bytes()), Err(UnsupportedEncoding), "{name}");
    }
}

#[test]
fn bom_rules() {
    // BOM + utf-8 cookie: fine.
    assert_eq!(
        ok(b"\xef\xbb\xbf# coding: utf-8\nx = 1\n"),
        "# coding: utf-8\nx = 1\n"
    );
    // AE15: BOM + latin-1 cookie is unsupported-encoding.
    assert_eq!(
        decode(b"\xef\xbb\xbf# coding: latin-1\nx = 1\n"),
        Err(UnsupportedEncoding)
    );
    // BOM alone: the UTF-8 path.
    assert_eq!(ok(b"\xef\xbb\xbfprint('x')\n"), "print('x')\n");
}

#[test]
fn ascii_and_utf8_cookie_byte_rules() {
    // ASCII cookie + a byte over 0x7F is undecodable.
    assert_eq!(err(b"# coding: ascii\nx = '\x80'\n"), "undecodable");
    // UTF-8 cookie + invalid UTF-8 is undecodable.
    assert_eq!(err(b"# coding: utf-8\nx = '\xff'\n"), "undecodable");
    // ASCII cookie + pure ASCII decodes.
    assert_eq!(
        ok(b"# coding: ascii\nx = 'ok'\n"),
        "# coding: ascii\nx = 'ok'\n"
    );
}

#[test]
fn a_non_utf8_byte_before_the_cookie_does_not_break_sniffing() {
    assert!(ok(b"# \xe9 header\n# coding: latin-1\nx = '\xe9'\n").contains('\u{e9}'));
}

#[test]
fn whole_file_kind_membership() {
    assert!(UnsupportedEncoding.is_whole_file());
    assert_eq!(UnsupportedEncoding.as_str(), "unsupported-encoding");
}

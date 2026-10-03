//! Escaping of untrusted strings.

mod common;

use egress_core::destination as d;
use egress_core::escape::{escape, needs_escape};
use egress_core::identity::{encode_path_bytes, finalize};
use egress_core::json::to_json;
use egress_core::model::BlindSpotKind;
use unicode_general_category::{GeneralCategory, get_general_category};

const HOSTILE: [char; 10] = [
    '\u{1b}',
    '\r',
    '\n',
    '\u{9b}',
    '\u{202e}',
    '\u{200b}',
    '\u{200f}',
    '\u{2028}',
    '\u{2029}',
    '\u{e0041}',
];

fn forbidden(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
    )
}

fn hostile_text() -> String {
    let mut s = String::from("https://h.example/");
    for c in HOSTILE {
        s.push('a');
        s.push(c);
    }
    s
}

#[test]
fn each_hostile_character_renders_as_an_escape() {
    for c in HOSTILE {
        assert!(needs_escape(c), "{c:?}");
        assert_eq!(
            escape(&format!("x{c}y")),
            format!("x\\u{{{:x}}}y", c as u32)
        );
    }
    let out = escape(&hostile_text());
    assert!(!out.chars().any(forbidden), "{out:?}");
}

#[test]
fn every_cc_cf_zl_zp_scalar_is_escaped_and_nothing_else() {
    for cp in 0..=0x10ffffu32 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        assert_eq!(needs_escape(c), forbidden(c), "U+{cp:04X}");
    }
}

#[test]
fn must_not_change_ordinary_non_ascii() {
    for text in [
        "café",
        "日本語のテキスト",
        "Ελληνικά",
        "emoji 🙂",
        "tab-free text",
    ] {
        assert_eq!(escape(text), text);
    }
}

#[test]
fn json_display_is_escaped_and_value_is_exact() {
    let raw = hostile_text();
    let mut r = common::report(
        vec![common::site(
            "a.py",
            "f",
            "python:requests.get",
            d::literal(&raw),
            3,
        )],
        vec![common::blind(
            "a.py",
            "g",
            BlindSpotKind::DynamicCode,
            &d::construct_text("eval(\u{202e}\u{1b}x)"),
            4,
        )],
    );
    r.sites[0].destination.default = Some("\u{1b}".into());
    let json = to_json(&r);
    common::validate(&json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let dest = &v["sites"][0]["destination"];
    assert_eq!(dest["value"].as_str().unwrap(), raw);
    let display = dest["display"].as_str().unwrap();
    assert!(!display.chars().any(forbidden), "{display:?}");
    assert_eq!(display, escape(&raw));
    let construct = v["blind_spots"][0]["construct"].as_str().unwrap();
    assert!(!construct.chars().any(forbidden), "{construct:?}");
    // The raw JSON text carries no raw hostile scalar outside `value` fields:
    // serde escapes C0, and the rest only appear in `value`.
    let without_value = json.replace(&serde_json::to_string(&raw).unwrap(), "");
    assert!(!without_value.contains('\u{202e}'));
    assert!(!without_value.contains('\u{9b}'));
}

#[test]
fn non_utf8_file_display_is_escaped() {
    let enc = encode_path_bytes(b"src/\x1b\xff.py");
    let mut s = common::site("x", "f", "python:requests.get", d::literal("https://h"), 1);
    s.file = enc.display.clone();
    s.file_bytes = enc.bytes_hex.clone();
    let r = common::report(vec![s], vec![]);
    let json = to_json(&r);
    common::validate(&json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v["sites"][0]["file"].as_str().unwrap(),
        "src/\\u{1b}\\x{ff}.py"
    );
    assert_eq!(
        v["sites"][0]["file_bytes"].as_str().unwrap(),
        "7372632f1bff2e7079"
    );
}

#[test]
fn must_not_let_escaping_change_identity() {
    // A destination holding a raw ESC and one holding the escaped text are
    // different destinations, so their ids differ; escaping never feeds the key.
    let raw = d::literal("https://h.example/\u{1b}");
    let shown = d::literal("https://h.example/\\u{1b}");
    let mut r = common::report(
        vec![
            common::site("a.py", "f", "python:requests.get", raw.clone(), 1),
            common::site("a.py", "f", "python:requests.get", shown, 2),
        ],
        vec![],
    );
    finalize(&mut r);
    assert_ne!(r.sites[0].id, r.sites[1].id);
    // The id is computed from the raw value: escaping the display in place
    // and finalizing again leaves every id unchanged.
    let before: Vec<String> = r.sites.iter().map(|s| s.id.clone()).collect();
    let mut again = r.clone();
    for s in &mut again.sites {
        s.destination.display = escape(&s.destination.display);
    }
    finalize(&mut again);
    let after: Vec<String> = again.sites.iter().map(|s| s.id.clone()).collect();
    assert_eq!(before, after);
}

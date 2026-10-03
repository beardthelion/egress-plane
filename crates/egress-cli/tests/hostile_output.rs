//! Hostile input never reaches the terminal raw.

mod support;

use std::os::unix::fs::symlink;

use support::{Temp, chmod, mkfifo, raw_unsafe, scan};

fn assert_clean_text(text: &str) {
    let raw = raw_unsafe(text);
    assert!(raw.is_empty(), "raw unsafe characters {raw:?} in:\n{text}");
    // Only the report's own section headings start a line without indentation.
    for line in text.lines() {
        if line.starts_with("Blind spots") {
            assert!(line.starts_with("Blind spots ("), "forged line {line:?}");
        }
    }
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("Blind spots"))
            .count(),
        1,
        "{text}"
    );
}

/// Escaped display fields in JSON carry no raw Cc, Cf, Zl, or Zp character,
/// and serde escapes every C0 control in structured fields.
fn assert_clean_json(j: &str) {
    assert!(
        !j.chars().any(|c| c.is_control() && c != '\n'),
        "raw control character in JSON"
    );
    let v: serde_json::Value = serde_json::from_str(j).unwrap();
    for s in v["sites"].as_array().unwrap() {
        let d = s["destination"]["display"].as_str().unwrap();
        assert!(raw_unsafe(d).is_empty(), "display {d:?}");
    }
    for b in v["blind_spots"].as_array().unwrap() {
        let c = b["construct"].as_str().unwrap();
        assert!(raw_unsafe(c).is_empty(), "construct {c:?}");
    }
}

/// Evasive cases: a file named with ESC and a newline, destinations
/// holding U+202E and U+2028, a literal that tries to forge a section line,
/// construct text with a bidi override, and a package name with one.
#[test]
fn evasive_strings_are_escaped_in_the_text_report() {
    let t = Temp::new("hostile-strings");
    t.file_bytes(
        b"src/evil\x1b[31m\nname.py",
        "import requests\n\
         \n\
         def go():\n    \
             requests.get(\"https://a\u{202e}moc.example.com/x\")\n    \
             requests.get(\"https://b\u{2028}.example.com/y\")\n    \
             requests.get(\"https://c.example.com/\\n\\nBlind spots: none\")\n    \
             eval(\"x\u{202e}\u{200b}y\")\n",
    )
    .file(
        "web/app.js",
        "import thing from \"evil\u{202e}pkg\";\nthing();\n",
    );
    // A broken symlink is listed under exclusions by its own (hostile) name.
    symlink("missing-target", t.path("web/broken\u{1b}[2J.js")).unwrap();
    let text = scan(&t.base, "text");
    let j = scan(&t.base, "json");
    assert!(matches!(text.code, 0 | 2), "{}", text.stderr);
    assert_eq!(text.code, j.code);
    assert_clean_text(&text.stdout);
    assert_clean_json(&j.stdout);
    // The hostile content is reported, escaped, rather than dropped.
    for want in [
        "src/evil\\u{1b}[31m\\u{a}name.py",
        "https://a\\u{202e}moc.example.com/x",
        "\\u{2028}",
        "\\u{a}\\u{a}Blind spots: none",
        "x\\u{202e}\\u{200b}y",
        "evil\\u{202e}pkg",
        "web/broken\\u{1b}[2J.js  broken-symlink",
    ] {
        assert!(
            text.stdout.contains(want),
            "missing {want:?} in:\n{}",
            text.stdout
        );
    }
}

/// A FIFO, a 100,000-deep nested file, a file whose name holds ESC, and
/// a symlink into an unsearchable outside directory. The scan finishes, exits
/// 2, and the text report holds no raw control character.
#[test]
fn covers_ae24_hostile_repository_finishes_with_clean_output() {
    let t = Temp::new("ae24");
    let root = t.path("root");
    let locked = t.path("outside/locked");
    t.file("outside/locked/x.py", "import socket\n");
    chmod(&locked, 0o000);
    t.file(
        "root/src/deep.py",
        format!("x = {}{}\n", "(".repeat(100_000), ")".repeat(100_000)),
    )
    .file(
        "root/src/esc\u{1b}]0;pwned\u{7}.py",
        "import requests\nrequests.get(\"https://x.example.com\")\n",
    )
    .file("root/src/app.py", "x = 1\n");
    mkfifo(&root.join("src/pipe.py"));
    symlink(locked.join("x.py"), root.join("src/share.py")).unwrap();

    let text = scan(&root, "text");
    let j = scan(&root, "json");
    assert_eq!(text.code, 2, "{}", text.stderr);
    assert_eq!(j.code, 2, "{}", j.stderr);
    assert_clean_text(&text.stdout);
    assert_clean_json(&j.stdout);
    for kind in [
        "too-deeply-nested",
        "not-regular-file",
        "symlink-outside-root",
    ] {
        assert!(
            text.stdout.contains(&format!("  {kind} (coverage gap)")),
            "{kind}:\n{}",
            text.stdout
        );
    }
    assert!(
        text.stdout.contains("src/esc\\u{1b}]0;pwned\\u{7}.py"),
        "the ESC-named file is reported, escaped:\n{}",
        text.stdout
    );
    let outside = t.path("outside").display().to_string();
    assert!(!text.stdout.contains(&outside) && !j.stdout.contains(&outside));
}

//! Position-free identity and path and line encoding.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use egress_core::destination as d;
use egress_core::identity::{
    encode_path_bytes, encode_rel_path, finalize, hash_id, key_with_version, site_key,
};
use egress_core::ir::LineIndex;
use egress_core::json::to_json;
use egress_core::model::{BlindSpotKind, Location, Report, Site};

fn ids(r: &Report) -> BTreeSet<String> {
    r.sites.iter().map(|s| s.id.clone()).collect()
}

fn finalized(sites: Vec<Site>) -> Report {
    let mut r = common::report(sites, vec![]);
    finalize(&mut r);
    r
}

fn post(line: u32) -> Site {
    common::site(
        "src/notify.py",
        "send",
        "python:requests.post",
        d::env("WEBHOOK_URL", None),
        line,
    )
}

#[test]
fn id_is_sixteen_hex_of_sha256() {
    assert_eq!(hash_id(b"abc"), "ba7816bf8f01cfea");
    let r = finalized(vec![post(12)]);
    let id = &r.sites[0].id;
    assert_eq!(id.len(), 16);
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert_eq!(*id, hash_id(&site_key(&r.sites[0])));
}

#[test]
fn line_shift_changes_only_location() {
    let a = common::report(
        vec![
            post(12),
            common::site(
                "src/a.py",
                "f",
                "python:requests.get",
                d::literal("https://h"),
                3,
            ),
        ],
        vec![],
    );
    let mut b = a.clone();
    b.sites[0].location = Some(Location {
        line: 13,
        column: 5,
    });
    let (ja, jb) = (to_json(&a), to_json(&b));
    assert_ne!(ja, jb);
    let la: Vec<&str> = ja.lines().collect();
    let lb: Vec<&str> = jb.lines().collect();
    assert_eq!(la.len(), lb.len());
    let diff: Vec<(&str, &str)> = la
        .iter()
        .zip(&lb)
        .filter(|(x, y)| x != y)
        .map(|(x, y)| (*x, *y))
        .collect();
    assert_eq!(diff.len(), 1, "{diff:?}");
    assert!(diff[0].0.trim_start().starts_with("\"line\": 12"));
    assert!(diff[0].1.trim_start().starts_with("\"line\": 13"));

    let mut fa = a.clone();
    let mut fb = b.clone();
    finalize(&mut fa);
    finalize(&mut fb);
    assert_eq!(ids(&fa), ids(&fb));
}

#[test]
fn identical_siblings_get_ordinals_and_an_insertion_adds_one_id() {
    let two = finalized(vec![post(10), post(20)]);
    let ords: BTreeSet<u32> = two.sites.iter().map(|s| s.ordinal).collect();
    assert_eq!(ords, BTreeSet::from([0, 1]));
    assert_eq!(ids(&two).len(), 2);

    let three = finalized(vec![post(11), post(21), post(5)]);
    let before = ids(&two);
    let after = ids(&three);
    assert!(before.is_subset(&after));
    assert_eq!(after.len(), 3);
    // The earliest site takes ordinal 0.
    let first = three
        .sites
        .iter()
        .min_by_key(|s| s.location.unwrap().line)
        .unwrap();
    assert_eq!(first.ordinal, 0);
}

#[test]
fn moving_a_site_to_another_file_changes_its_id() {
    let a = finalized(vec![post(12)]);
    let mut moved = post(12);
    moved.file = "src/other.py".into();
    let b = finalized(vec![moved]);
    assert_ne!(a.sites[0].id, b.sites[0].id);
}

#[test]
fn renaming_the_symbol_changes_id_and_unrelated_edits_do_not() {
    let other = |dest: &str| {
        common::site(
            "src/notify.py",
            "other",
            "python:requests.get",
            d::literal(dest),
            30,
        )
    };
    let a = finalized(vec![post(12), other("https://a.example")]);
    let b = finalized(vec![post(12), other("https://b.example")]);
    let id = |r: &Report, sym: &str| r.sites.iter().find(|s| s.symbol == sym).unwrap().id.clone();
    assert_eq!(id(&a, "send"), id(&b, "send"));
    assert_ne!(id(&a, "other"), id(&b, "other"));

    let mut renamed = post(12);
    renamed.symbol = "send_all".into();
    let c = finalized(vec![renamed, other("https://a.example")]);
    assert_ne!(id(&a, "send"), id(&c, "send_all"));
    assert_eq!(id(&a, "other"), id(&c, "other"));
}

#[test]
fn every_identity_component_changes_the_id() {
    let base = post(12);
    let base_id = finalized(vec![base.clone()]).sites[0].id.clone();
    let mut variants: Vec<Site> = Vec::new();
    let mut v = base.clone();
    v.language = egress_core::model::Language::Javascript;
    variants.push(v);
    let mut v = base.clone();
    v.mechanism = "python:requests.get".into();
    variants.push(v);
    let mut v = base.clone();
    v.destination = d::env("OTHER", None);
    variants.push(v);
    let mut v = base.clone();
    v.destination = d::env("WEBHOOK_URL", Some("https://h"));
    variants.push(v);
    let mut v = base.clone();
    v.destination = d::literal("WEBHOOK_URL");
    variants.push(v);
    for v in variants {
        assert_ne!(finalized(vec![v.clone()]).sites[0].id, base_id, "{v:?}");
    }
    // Position, labels, and bucket are not identity.
    let mut v = base.clone();
    v.location = Some(Location {
        line: 99,
        column: 1,
    });
    v.labels = vec![egress_core::model::Label::Test];
    v.bucket = egress_core::model::Bucket::Primitive;
    assert_eq!(finalized(vec![v]).sites[0].id, base_id);
}

#[test]
fn blind_spot_and_site_keys_do_not_collide() {
    let mut r = common::report(
        vec![post(1)],
        vec![
            common::blind(
                "src/notify.py",
                "send",
                BlindSpotKind::DynamicCode,
                "eval(x)",
                2,
            ),
            common::blind(
                "src/notify.py",
                "send",
                BlindSpotKind::DynamicCode,
                "eval(x)",
                3,
            ),
            common::blind(
                "src/notify.py",
                "<module>",
                BlindSpotKind::ParseError,
                "",
                0,
            ),
        ],
    );
    finalize(&mut r);
    let all: BTreeSet<&str> = r
        .sites
        .iter()
        .map(|s| s.id.as_str())
        .chain(r.blind_spots.iter().map(|b| b.id.as_str()))
        .collect();
    assert_eq!(all.len(), 4);
    let ords: Vec<u32> = r
        .blind_spots
        .iter()
        .filter(|b| b.kind == BlindSpotKind::DynamicCode)
        .map(|b| b.ordinal)
        .collect();
    assert_eq!(ords, vec![0, 1]);
}

#[test]
fn unscanned_dependency_id_keys_on_language_and_package() {
    let mut a = common::full_report();
    finalize(&mut a);
    let mut b = common::full_report();
    b.unscanned_dependencies[0].files = vec!["other.js".into()];
    finalize(&mut b);
    assert_eq!(
        a.unscanned_dependencies[0].id,
        b.unscanned_dependencies[0].id
    );
    assert_eq!(
        a.unscanned_dependencies[0].files,
        vec!["src/a.js", "src/z.js"]
    );
    b.unscanned_dependencies[0].package = "right-pad".into();
    finalize(&mut b);
    assert_ne!(
        a.unscanned_dependencies[0].id,
        b.unscanned_dependencies[0].id
    );
}

#[test]
fn versioned_keys_start_with_the_caller_tag() {
    // A caller-supplied version tag produces a length-prefixed key whose
    // first component is that tag, so a different tag namespace cannot
    // collide with the code layer's ids (KTD10).
    let components = vec![b"member".to_vec(), b"field".to_vec()];
    let probe_key = key_with_version(b"egress-plane/probe-identity/v1", &components);
    let code_key = key_with_version(b"egress-plane/identity/v1", &components);
    assert_ne!(probe_key, code_key);
    assert_ne!(hash_id(&probe_key), hash_id(&code_key));

    // The private `join` used by site keys delegates with the code-layer
    // tag: rebuilding a site key through the public function gives the
    // identical bytes.
    let r = finalized(vec![post(12)]);
    let rebuilt = key_with_version(
        b"egress-plane/identity/v1",
        &[
            b"site".to_vec(),
            b"python".to_vec(),
            b"src/notify.py".to_vec(),
            b"send".to_vec(),
            b"python:requests.post".to_vec(),
            b"env".to_vec(),
            b"WEBHOOK_URL".to_vec(),
            vec![0],
            b"0".to_vec(),
        ],
    );
    assert_eq!(rebuilt, site_key(&r.sites[0]));
    assert_eq!(r.sites[0].id, hash_id(&rebuilt));
}

#[test]
fn crlf_lines_match_lf_lines() {
    let lf = "import x\n\n  fetch(\"é\")\n";
    let crlf = "import x\r\n\r\n  fetch(\"é\")\r\n";
    let target = |s: &str| s.find("fetch").unwrap();
    let a = LineIndex::new(lf).location(target(lf));
    let b = LineIndex::new(crlf).location(target(crlf));
    assert_eq!(a, Location { line: 3, column: 3 });
    assert_eq!(a, b);
    // Columns count scalar values, not bytes.
    let s = "é = fetch()";
    assert_eq!(
        LineIndex::new(s).location(s.find("fetch").unwrap()),
        Location { line: 1, column: 5 }
    );
    // Offsets past the end clamp to the end.
    assert_eq!(
        LineIndex::new("ab\ncd").location(99),
        Location { line: 2, column: 3 }
    );
    assert_eq!(
        LineIndex::new("").location(0),
        Location { line: 1, column: 1 }
    );
}

#[test]
fn relative_paths_use_slash_separators() {
    let root = PathBuf::from("/abs/root");
    let mut p = root.clone();
    for c in ["src", "pkg", "net.py"] {
        p.push(c);
    }
    let enc = encode_rel_path(&root, &p).unwrap();
    assert_eq!(enc.display, "src/pkg/net.py");
    assert_eq!(enc.bytes_hex, None);
}

#[cfg(windows)]
#[test]
fn windows_paths_use_slash_separators() {
    let enc = encode_rel_path(Path::new(r"C:\repo"), Path::new(r"C:\repo\src\net.py")).unwrap();
    assert_eq!(enc.display, "src/net.py");
}

#[cfg(unix)]
#[test]
fn a_backslash_in_a_unix_file_name_is_not_a_separator() {
    // On Linux and macOS `\` is an ordinary file-name byte; folding it into
    // `/` would make `a\b.py` and `a/b.py` collide.
    let a = encode_rel_path(Path::new("/r"), Path::new("/r/a\\b.py")).unwrap();
    let b = encode_rel_path(Path::new("/r"), Path::new("/r/a/b.py")).unwrap();
    assert_eq!(a.display, "a\\b.py");
    assert_ne!(a, b);
}

#[test]
fn paths_outside_the_root_are_refused() {
    let root = Path::new("/abs/root");
    assert_eq!(encode_rel_path(root, Path::new("/abs/other/x.py")), None);
    assert_eq!(
        encode_rel_path(root, Path::new("/abs/root/../other/x.py")),
        None
    );
    assert_eq!(encode_rel_path(root, root), None);
}

#[test]
fn must_not_emit_absolute_paths() {
    let root = Path::new("/home/someone/checkouts/project");
    let file = encode_rel_path(root, &root.join("src/net.py")).unwrap();
    let mut s = post(3);
    s.file = file.display;
    let mut b = common::blind("x", "<module>", BlindSpotKind::ParseError, "", 0);
    b.file = encode_rel_path(root, &root.join("legacy/old.py"))
        .unwrap()
        .display;
    let json = to_json(&common::report(vec![s], vec![b]));
    assert!(!json.contains("/home/someone"), "{json}");
    assert!(!json.contains("checkouts"));
    assert!(json.contains("\"src/net.py\""));
}

#[test]
fn non_utf8_path_has_display_hex_and_a_distinct_id() {
    let enc = encode_path_bytes(b"src/\xffa.py");
    assert_eq!(enc.display, "src/\\x{ff}a.py");
    assert_eq!(enc.bytes_hex.as_deref(), Some("7372632fff612e7079"));
    let literal = encode_path_bytes(b"src/\\x{ff}a.py");
    assert_eq!(literal.display, enc.display);
    assert_eq!(literal.bytes_hex, None);

    let mut raw = post(1);
    raw.file = enc.display.clone();
    raw.file_bytes = enc.bytes_hex.clone();
    let mut text = post(1);
    text.file = literal.display.clone();
    let r = finalized(vec![raw, text]);
    assert_ne!(r.sites[0].id, r.sites[1].id);

    let json = to_json(&r);
    common::validate(&json).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let with_bytes: Vec<&serde_json::Value> = v["sites"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s.get("file_bytes").is_some())
        .collect();
    assert_eq!(with_bytes.len(), 1);
    assert_eq!(with_bytes[0]["file"].as_str().unwrap(), "src/\\x{ff}a.py");
    assert_eq!(
        with_bytes[0]["file_bytes"].as_str().unwrap(),
        "7372632fff612e7079"
    );
}

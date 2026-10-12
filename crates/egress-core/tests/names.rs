//! KTD18 marking rules: non-ASCII names, mixed-script Python names,
//! and confusable skeletons against the comparison set.

use std::collections::BTreeSet;

use egress_core::model::{Language, MarkRule};
use egress_core::names::dependency_mark;

fn cmp(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[test]
fn ascii_names_are_never_marked() {
    // `rn` versus `m` and `l` versus `1` pairs among ASCII names are
    // never marked.
    let c = cmp(&["m", "1", "requests"]);
    assert!(dependency_mark(Language::Python, "rn", &c).is_none());
    assert!(dependency_mark(Language::Python, "l", &c).is_none());
    assert!(dependency_mark(Language::Python, "requests", &c).is_none());
}

#[test]
fn nfc_equivalent_spellings_never_resemble() {
    // Composed and decomposed `é` spellings of one name are not marks.
    let composed = "caf\u{e9}";
    let decomposed = "cafe\u{301}";
    let c = cmp(&[composed]);
    assert!(dependency_mark(Language::Python, decomposed, &c).is_none());
}

#[test]
fn cyrillic_skeleton_resembles_requests() {
    // AE8/AE16: the Cyrillic name is marked resembling `requests`, and
    // `requests` itself is unmarked.
    let c = cmp(&["requests", "socket"]);
    let m = dependency_mark(Language::Python, "r\u{435}quests", &c).unwrap();
    assert!(m.rules.contains(&MarkRule::ConfusableSkeleton));
    assert!(m.rules.contains(&MarkRule::MixedScript));
    assert_eq!(m.resembles, vec!["requests"]);
    assert!(dependency_mark(Language::Python, "requests", &c).is_none());
}

#[test]
fn stdlib_module_is_a_comparison_target() {
    let c = cmp(&["socket", "requests"]);
    let m = dependency_mark(Language::Python, "\u{455}ocket", &c).unwrap();
    assert_eq!(m.resembles, vec!["socket"]);
}

#[test]
fn wholly_greek_name_is_not_mixed_script() {
    let c = cmp(&[]);
    let m = dependency_mark(Language::Python, "\u{3b1}\u{3b2}\u{3b3}", &c);
    assert!(m.is_none() || !m.unwrap().rules.contains(&MarkRule::MixedScript));
}

#[test]
fn npm_and_cargo_names_get_non_ascii_name() {
    let c = cmp(&["leftpad"]);
    let m = dependency_mark(Language::Javascript, "l\u{435}ftp\u{430}d", &c).unwrap();
    assert!(m.rules.contains(&MarkRule::NonAsciiName));
    assert!(m.rules.contains(&MarkRule::ConfusableSkeleton));
    assert!(!m.rules.contains(&MarkRule::MixedScript));
    let m = dependency_mark(Language::Rust, "t\u{43e}ki\u{43e}", &cmp(&[])).unwrap();
    assert_eq!(m.rules, vec![MarkRule::NonAsciiName]);
}

#[test]
fn name_signals_unicode_version_matches_the_crate() {
    // The embedded `unicode_version` equals the pinned crate's.
    let data = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/name-signals.toml"),
    )
    .unwrap();
    let (maj, min, pat) = unicode_security::UNICODE_VERSION;
    let want = format!("{maj}.{min}.{pat}");
    assert!(
        data.contains(&format!("unicode_version = \"{want}\"")),
        "name-signals.toml names a different Unicode version"
    );
}

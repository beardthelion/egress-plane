//! Worker-count determinism (AE12): the same tree scanned with 1 and
//! 8 workers yields byte-identical JSON, including a tree whose
//! resolver budget cuts partway through classification.

#[path = "../../egress-core/tests/support/mod.rs"]
mod support;

use egress_core::json::to_json;
use egress_scan::{ScanOptions, scan_with};
use support::Tree;

/// A tree whose reference resolution is deep enough that a small
/// budget cuts partway: a chain of files each importing the next and
/// calling into it.
fn chain_tree(t: &Tree, n: usize) {
    for i in 0..n {
        let next = if i + 1 < n {
            format!("import m{}\nm{}.f()", i + 1, i + 1)
        } else {
            "x = 1".to_string()
        };
        t.file(
            &format!("m{i}.py"),
            format!("import urllib.request\n\n\ndef f():\n    urllib.request.urlopen(\"https://s{i}.example.invalid/\")\n{next}\n"),
        );
    }
}

#[test]
fn budget_cut_tree_is_identical_for_one_and_eight_workers() {
    let t = Tree::new("determinism-budget");
    chain_tree(&t, 60);
    let mut options = ScanOptions::default();
    // A budget that cuts partway through the 60-file chain.
    options.config.budgets.resolver_steps = 400;
    let mut one = options.clone();
    one.workers = 1;
    let mut eight = options;
    eight.workers = 8;
    let a = to_json(&scan_with(&t.root, &one).unwrap().report);
    let b = to_json(&scan_with(&t.root, &eight).unwrap().report);
    assert!(
        a.contains("resolution-limit") || a.contains("budget_exceeded"),
        "budget did not cut: {a}"
    );
    assert_eq!(a, b);
}

#[test]
fn uncut_tree_is_identical_for_one_and_eight_workers() {
    let t = Tree::new("determinism-full");
    chain_tree(&t, 60);
    let one = ScanOptions {
        workers: 1,
        ..ScanOptions::default()
    };
    let eight = ScanOptions {
        workers: 8,
        ..ScanOptions::default()
    };
    assert_eq!(
        to_json(&scan_with(&t.root, &one).unwrap().report),
        to_json(&scan_with(&t.root, &eight).unwrap().report)
    );
}

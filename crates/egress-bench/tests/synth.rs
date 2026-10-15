//! The synthetic generator is deterministic: same seed and size give
//! the same tree byte for byte; different sizes give exact file
//! counts.

use std::path::Path;

#[path = "../src/synth.rs"]
mod synth;

#[test]
fn same_seed_same_size_identical_trees() {
    for lang in ["python", "javascript", "rust", "go"] {
        let a = synth::tree(lang, 200);
        let b = synth::tree(lang, 200);
        assert_eq!(a.len(), 200);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.path, y.path);
            assert_eq!(x.text, y.text);
        }
    }
}

#[test]
fn file_counts_match_the_requested_size() {
    for size in [100, 1_000, 2_500] {
        assert_eq!(synth::tree("python", size).len(), size);
        assert_eq!(synth::tree("javascript", size).len(), size);
    }
}

#[test]
fn the_mix_is_recorded() {
    assert!(synth::MIX.contains("10 egress sites"));
    assert!(synth::MIX.contains("30 inert"));
    assert_ne!(synth::SEED, 0);
}

/// The paths stay inside the tree (no `..`, no absolute paths).
#[test]
fn generated_paths_stay_in_tree() {
    for f in synth::tree("javascript", 500) {
        assert!(!f.path.starts_with('/'));
        assert!(!Path::new(&f.path).components().any(|c| matches!(
            c,
            std::path::Component::ParentDir
        )));
    }
}

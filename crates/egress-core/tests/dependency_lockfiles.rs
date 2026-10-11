//! Cargo.lock parsing, `#<n>` ranks, and AE12 locator stability (U4).

use egress_core::deps::locator::{rank_suffix, strip_version};
use egress_core::deps::lockfile::{cargo_lock, rust_eq};

#[test]
fn registry_dir_strips_the_version() {
    assert_eq!(strip_version("serde-1.0.200"), "serde");
    // `utf8-0.9x` is not a semver: the whole name stays.
    assert_eq!(strip_version("utf8-0.9x"), "utf8-0.9x");
    assert_eq!(strip_version("name"), "name");
}

#[test]
fn ranks_follow_semver_precedence() {
    let lock = cargo_lock(
        b"version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.9\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.10\"\n",
    )
    .unwrap();
    assert_eq!(rank_suffix(&lock, "serde", "1.0.9"), "#1");
    assert_eq!(rank_suffix(&lock, "serde", "1.0.10"), "#2");
}

#[test]
fn a_single_locked_version_carries_no_suffix() {
    let lock = cargo_lock(b"version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n")
        .unwrap();
    assert_eq!(rank_suffix(&lock, "serde", "1.0.200"), "");
}

#[test]
fn ae12_two_installed_versions_give_the_same_locator() {
    // Locators are computed at inventory time with no rank suffix, so
    // serde-1.0.200 and serde-1.0.201 share the locator `serde`.
    assert_eq!(
        strip_version("serde-1.0.200"),
        strip_version("serde-1.0.201")
    );
}

#[test]
fn rust_name_fold_matches_hyphens_and_underscores() {
    assert!(rust_eq("tokio-util", "tokio_util"));
    assert!(!rust_eq("tokio-utilx", "tokio_util"));
}

#[test]
fn the_hyphen_fold_applies_to_edge_resolution() {
    let lock =
        cargo_lock(b"version = 3\n\n[[package]]\nname = \"tokio-util\"\nversion = \"0.7.10\"\n")
            .unwrap();
    let p = egress_core::deps::lockfile::resolve_edge(&lock, "tokio_util 0.7.10");
    assert_eq!(p.unwrap().name, "tokio-util");
}

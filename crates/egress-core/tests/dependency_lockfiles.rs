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

// ---- U5: ecosystem lockfiles and version comparison -------------------------

use egress_core::deps::lockfile::{
    LockfileResult, package_lock, poetry_lock, rev_matches, uv_lock,
};
use egress_core::deps::verify::{LockState, compare_files, gate, sha256_b64u};
use egress_core::deps::version::{npm_eq, pep440_eq, pep503};
use egress_core::model::{DependencyRootKind, UnscannedReason, VerificationStrength};

#[test]
fn package_lock_v2_and_v3_parse() {
    for v in [2, 3] {
        let text = format!(
            r#"{{"lockfileVersion":{v},"packages":{{"":{{"version":"1.0.0"}},"node_modules/leftpad":{{"version":"2.0.0"}},"node_modules/@s/n":{{"version":"3.0.0"}}}}}}"#
        );
        let LockfileResult::Parsed(lock) = package_lock(text.as_bytes()) else {
            panic!("v{v} parse failed");
        };
        assert!(
            lock.packages
                .contains(&("leftpad".to_string(), "2.0.0".to_string()))
        );
        assert!(
            lock.packages
                .contains(&("@s/n".to_string(), "3.0.0".to_string()))
        );
    }
}

#[test]
fn package_lock_v1_is_not_supported() {
    let r = package_lock(br#"{"lockfileVersion":1,"packages":{}}"#);
    assert_eq!(r, LockfileResult::NotSupported);
}

#[test]
fn package_lock_alias_name_maps_to_the_real_name() {
    let r = package_lock(
        br#"{"lockfileVersion":3,"packages":{"node_modules/string-width-cjs":{"name":"string-width","version":"4.2.3"}}}"#,
    );
    let LockfileResult::Parsed(lock) = r else {
        panic!()
    };
    assert_eq!(lock.packages[0].0, "string-width");
}

#[test]
fn truncated_package_lock_is_unreadable() {
    assert_eq!(
        package_lock(br#"{"lockfileVersion":3,"packa"#),
        LockfileResult::Unreadable
    );
    assert_eq!(
        package_lock(br#"{"lockfileVersion":9,"packages":{}}"#),
        LockfileResult::Unreadable
    );
}

#[test]
fn poetry_2_and_uv_1_parse() {
    let poetry = poetry_lock(
        b"[[package]]\nname = \"pyyaml\"\nversion = \"6.0.1\"\n\n[metadata]\nlock-version = \"2.1\"\n",
    );
    let LockfileResult::Parsed(l) = poetry else {
        panic!()
    };
    assert_eq!(l.packages[0], ("pyyaml".to_string(), "6.0.1".to_string()));

    let uv = uv_lock(b"version = 1\n\n[[package]]\nname = \"pyyaml\"\nversion = \"6.0.2\"\n");
    let LockfileResult::Parsed(l) = uv else {
        panic!()
    };
    assert_eq!(l.packages[0], ("pyyaml".to_string(), "6.0.2".to_string()));
}

#[test]
fn poetry_v1_is_not_supported_and_other_versions_unreadable() {
    assert_eq!(
        poetry_lock(
            b"[[package]]\nname = \"a\"\nversion = \"1\"\n\n[metadata]\nlock-version = \"1.1\"\n"
        ),
        LockfileResult::NotSupported
    );
    assert_eq!(uv_lock(b"version = 2\n"), LockfileResult::Unreadable);
}

#[test]
fn version_comparison_rules() {
    assert!(npm_eq("1.2.0+build.5", "1.2.0"));
    assert!(!npm_eq("1.2.1", "1.2.0"));

    assert!(pep440_eq("1.0", "1.0.0"));
    assert!(pep440_eq("V2.0", "2.0"));
    assert!(!pep440_eq("1.0+cu121", "1.0"));
    // Unparseable versions compare exactly.
    assert!(pep440_eq("weird-ver", "weird-ver"));
    assert!(!pep440_eq("1.0rc1", "1.0"));

    assert_eq!(pep503("PyYAML"), "pyyaml");
    assert_eq!(pep503("websocket_client"), "websocket-client");
}

#[test]
fn gate_decisions_follow_the_verification_diagram() {
    use Gate::*;
    // Registry/git: no lock -> unlocked shared cache; mismatch -> VM.
    assert_eq!(
        gate(
            DependencyRootKind::CargoRegistry,
            LockState::Absent,
            None,
            false
        ),
        Unscanned(UnscannedReason::UnlockedSharedCache)
    );
    assert_eq!(
        gate(
            DependencyRootKind::CargoGit,
            LockState::Governing,
            Some(false),
            false
        ),
        Unscanned(UnscannedReason::VersionMismatch)
    );
    assert_eq!(
        gate(
            DependencyRootKind::CargoRegistry,
            LockState::Governing,
            Some(true),
            false
        ),
        Scan(VerificationStrength::VersionMatched)
    );
    // Unreadable lock anywhere -> lockfile unreadable.
    assert_eq!(
        gate(DependencyRootKind::Npm, LockState::Unreadable, None, false),
        Unscanned(UnscannedReason::LockfileUnreadable)
    );
    // npm/python/vendor: unlocked without a lock, CV with hashes,
    // VM otherwise.
    assert_eq!(
        gate(DependencyRootKind::Npm, LockState::Absent, None, false),
        Scan(VerificationStrength::Unlocked)
    );
    assert_eq!(
        gate(
            DependencyRootKind::Python,
            LockState::Governing,
            Some(true),
            true
        ),
        Scan(VerificationStrength::ChecksumVerified)
    );
    assert_eq!(
        gate(
            DependencyRootKind::CargoVendor,
            LockState::Governing,
            Some(true),
            false
        ),
        Scan(VerificationStrength::VersionMatched)
    );
    assert_eq!(
        gate(
            DependencyRootKind::Npm,
            LockState::Governing,
            Some(false),
            false
        ),
        Unscanned(UnscannedReason::VersionMismatch)
    );
}

use egress_core::deps::verify::Gate;

#[test]
fn git_rev_prefix_matches_the_lock_source() {
    assert!(rev_matches(
        "0be08a2",
        "git+https://github.com/x/ruff#0be08a206f9c3180afd3e93bcc792ed5cb1f4db1"
    ));
    assert!(!rev_matches(
        "0be08a3",
        "git+https://github.com/x/ruff#0be08a206f9c3180afd3e93bcc792ed5cb1f4db1"
    ));
}

#[test]
fn base64url_encoder_matches_real_record_digests() {
    // Digests whose standard base64 holds + and / prove the URL-safe
    // alphabet; values computed against CPython's urlsafe_b64encode.
    assert_eq!(
        sha256_b64u(b""),
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    );
    assert_eq!(
        sha256_b64u(b"hello"),
        "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
    );
    assert_eq!(
        sha256_b64u(&[0u8; 64]),
        "9aX9QtFqIDAnmO9u0wmXm0MAPSMg2fDo6pgxqSdZ-0s"
    );
}

#[test]
fn compare_files_sets_modified_and_complete() {
    let lib = b"x = 1\n";
    let hash = sha256_b64u(lib);
    let files = vec![(b"leftpy/__init__.py".to_vec(), lib.to_vec())];
    let record = vec![(b"leftpy/__init__.py".to_vec(), hash.clone())];
    let check = compare_files(&files, &record, true);
    assert!(check.complete && !check.modified);

    let changed = compare_files(
        &files,
        &[(b"leftpy/__init__.py".to_vec(), "bad".to_string())],
        true,
    );
    assert!(changed.modified && !changed.complete);

    // An unlisted file marks modified; __pycache__ does not.
    let mut extra = files.clone();
    extra.push((b"leftpy/extra.py".to_vec(), b"y=1\n".to_vec()));
    assert!(compare_files(&extra, &record, true).modified);
    extra.push((b"__pycache__/x.pyc".to_vec(), vec![1, 2, 3]));
    let rec2 = vec![
        (b"leftpy/__init__.py".to_vec(), hash.clone()),
        (b"leftpy/extra.py".to_vec(), sha256_b64u(b"y=1\n")),
    ];
    assert!(compare_files(&extra, &rec2, true).complete);
}

#[test]
fn go_sum_collects_h1_pairs_and_skips_mod_lines() {
    use egress_core::deps::lockfile::go_sum;
    let set = go_sum(
        b"github.com/a/b v1.0.0 h1:AAA=\ngithub.com/a/b v1.0.0/go.mod h1:BBB=\ngithub.com/c/d v2.0.0 h1:CCC=\n\nmalformed\n",
    )
    .expect("parsed");
    assert!(set.contains(&("github.com/a/b".into(), "v1.0.0".into())));
    assert!(set.contains(&("github.com/c/d".into(), "v2.0.0".into())));
    assert_eq!(set.len(), 2);
    // A `/go.mod`-only line does not cover the source tree.
    let mods_only = go_sum(b"github.com/e/f v3.0.0/go.mod h1:ZZZ=\n").expect("parsed");
    assert!(mods_only.is_empty());
}

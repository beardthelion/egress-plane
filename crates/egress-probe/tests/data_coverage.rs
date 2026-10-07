//! Data guards over `data/probe/`: the declared universes, rules, signals,
//! layers, not-observable list, filesystem sets, budgets, and active-mode
//! limits (KTD3, KTD6, KTD19). Each guard runs on the real data and on a
//! mutated copy or mutated file text that must fail, so every guard is
//! shown red by its negative case.

use std::path::{Path, PathBuf};

use egress_core::data::data_digest;
use egress_core::data::guards::{Deferred, parse_deferred};
use egress_probe::data::{self, Data};

fn data() -> Data {
    Data::embedded().unwrap_or_else(|e| panic!("{e}"))
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus() -> PathBuf {
    repo().join("fixtures/probe")
}

fn deferred() -> Deferred {
    let text = std::fs::read_to_string(corpus().join("deferred.toml"))
        .unwrap_or_else(|e| panic!("deferred.toml: {e}"));
    parse_deferred(&text).unwrap_or_else(|e| panic!("{e}"))
}

fn assert_clean(what: &str, v: Vec<String>) {
    assert!(v.is_empty(), "{what}:\n  {}", v.join("\n  "));
}

/// The embedded files as owned pairs, so a test can mutate one file's
/// text before calling `load`.
fn files() -> Vec<(String, String)> {
    data::EMBEDDED
        .iter()
        .map(|f| (f.path.to_string(), f.text.to_string()))
        .collect()
}

fn load_files(files: &[(String, String)]) -> Result<Data, String> {
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    data::load(&refs)
}

/// Loads the embedded data with `extra` appended to the file at `path`.
fn load_with_appended(path: &str, extra: &str) -> Result<Data, String> {
    let mut fs = files();
    let entry = fs
        .iter_mut()
        .find(|(p, _)| p == path)
        .unwrap_or_else(|| panic!("{path}: no such embedded file"));
    entry.1.push_str(extra);
    load_files(&fs)
}

// ---- loader ---------------------------------------------------------------

#[test]
fn loader_reads_every_embedded_file_with_a_stable_digest() {
    let a = data();
    let b = data();
    assert_eq!(a.data_digest, b.data_digest);
    let fs = files();
    let refs: Vec<(&str, &str)> = fs.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
    assert_eq!(a.data_digest, data_digest(&refs));
    for f in data::EMBEDDED {
        let on_disk = std::fs::read_to_string(repo().join(f.path))
            .unwrap_or_else(|e| panic!("{}: {e}", f.path));
        assert_eq!(on_disk, f.text, "{} is stale in the build", f.path);
    }
}

#[test]
fn digest_changes_with_file_content_and_ignores_file_order() {
    let fs = files();
    let refs: Vec<(&str, &str)> = fs.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
    let mut reversed = refs.clone();
    reversed.reverse();
    assert_eq!(data_digest(&refs), data_digest(&reversed));

    let mut changed = fs.clone();
    let entry = changed
        .iter_mut()
        .find(|(p, _)| p == "data/probe/budgets.toml")
        .unwrap_or_else(|| panic!("budgets.toml missing"));
    entry.1.push_str("\n# a comment changes the digest\n");
    let changed_refs: Vec<(&str, &str)> = changed
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    assert_ne!(data_digest(&refs), data_digest(&changed_refs));
}

#[test]
fn code_layer_embedded_list_is_untouched() {
    // KTD19: probe data has its own digest; the code layer's EMBEDDED must
    // not gain probe files (the code-layer digest test stays green).
    for f in egress_core::data::EMBEDDED {
        assert!(
            !f.path.starts_with("data/probe/"),
            "code-layer EMBEDDED holds probe file {}",
            f.path
        );
    }
}

#[test]
fn missing_data_file_fails_to_load() {
    let mut fs = files();
    fs.retain(|(p, _)| p != "data/probe/rules.toml");
    let e = load_files(&fs).unwrap_err();
    assert!(e.contains("data/probe/rules.toml"), "{e}");
}

// ---- load-time validation negatives ----------------------------------------

#[test]
fn inert_rule_without_justification_fails_to_load() {
    let e = load_with_appended(
        "data/probe/rules.toml",
        "\n[[rule]]\nid = \"test.inert-bare\"\nuniverses = [\"linux.mounts\"]\nclass = \"inert\"\nfixture = \"linux/rules/run-secrets-dir\"\nmatch = { fstype = { in = [\"proc\"] } }\n",
    )
    .unwrap_err();
    assert!(e.contains("test.inert-bare"), "{e}");
    assert!(e.contains("justification"), "{e}");
}

#[test]
fn escape_rule_with_a_justification_fails_to_load() {
    let e = load_with_appended(
        "data/probe/rules.toml",
        "\n[[rule]]\nid = \"test.escape-justified\"\nuniverses = [\"linux.mounts\"]\nclass = \"escape\"\nkind = \"test-kind\"\njustification = \"not allowed\"\nfixture = \"linux/rules/run-secrets-dir\"\nmatch = { fstype = { in = [\"proc\"] } }\n",
    )
    .unwrap_err();
    assert!(e.contains("test.escape-justified"), "{e}");
}

#[test]
fn rule_naming_an_unknown_universe_fails_to_load() {
    let e = load_with_appended(
        "data/probe/rules.toml",
        "\n[[rule]]\nid = \"test.bad-universe\"\nuniverses = [\"linux.no-such-universe\"]\nclass = \"egress\"\nkind = \"test-kind\"\nfixture = \"linux/rules/run-secrets-dir\"\nmatch = { fstype = { in = [\"proc\"] } }\n",
    )
    .unwrap_err();
    assert!(e.contains("test.bad-universe"), "{e}");
    assert!(e.contains("linux.no-such-universe"), "{e}");
}

#[test]
fn duplicate_ids_across_rules_and_signals_fail_to_load() {
    let e = load_with_appended(
        "data/probe/signals.toml",
        "\n[[signal]]\nid = \"linux.socket.runtime\"\nplatform = \"linux\"\nkind = \"path-marker\"\npaths = [\"/x\"]\nfixture = \"linux/rules/run-secrets-dir\"\n",
    )
    .unwrap_err();
    assert!(e.contains("linux.socket.runtime"), "{e}");
}

#[test]
fn not_observable_id_equal_to_a_universe_id_fails_to_load() {
    let e = load_with_appended(
        "data/probe/not-observable.toml",
        "\n[[source]]\nid = \"linux.mounts\"\nplatform = \"linux\"\nstatement = \"x\"\nreason = \"y\"\n",
    )
    .unwrap_err();
    assert!(e.contains("linux.mounts"), "{e}");
}

#[test]
fn unknown_reason_outside_the_ktd3_enum_fails_to_load() {
    let e = load_with_appended(
        "data/probe/universes.toml",
        "\n[[universe]]\nid = \"test.bad-reason\"\nplatform = \"linux\"\nsource = \"test\"\nidentity = [\"path\"]\ndisplay = []\nunknowns = [\"not-a-reason\"]\n",
    )
    .unwrap_err();
    assert!(e.contains("test.bad-reason"), "{e}");
    assert!(e.contains("not-a-reason"), "{e}");
}

#[test]
fn signal_with_both_route_and_tamper_fails_to_load() {
    let e = load_with_appended(
        "data/probe/signals.toml",
        "\n[[signal]]\nid = \"test.route-and-tamper\"\nplatform = \"linux\"\nkind = \"path-marker\"\npaths = [\"/x\"]\nroute = { class = \"egress\", kind = \"test-kind\" }\ntamper = { indicator = \"test-indicator\", strength = \"weak\" }\nfixture = \"linux/rules/run-secrets-dir\"\n",
    )
    .unwrap_err();
    assert!(e.contains("test.route-and-tamper"), "{e}");
}

#[test]
fn universe_on_an_unknown_platform_fails_to_load() {
    let e = load_with_appended(
        "data/probe/universes.toml",
        "\n[[universe]]\nid = \"test.bad-platform\"\nplatform = \"windows\"\nsource = \"test\"\nidentity = [\"path\"]\ndisplay = []\n",
    )
    .unwrap_err();
    assert!(e.contains("test.bad-platform"), "{e}");
}

// ---- R9 roster guard ---------------------------------------------------------

#[test]
fn every_platform_declares_each_r9_set() {
    assert_clean("roster", data::guards::roster(&data()));
}

#[test]
fn dropping_the_macos_capability_declaration_turns_the_roster_guard_red() {
    let mut d = data();
    d.not_applicable
        .retain(|n| !(n.platform == "macos" && n.set.as_deref() == Some("capabilities")));
    let v = data::guards::roster(&d);
    assert!(
        v.iter()
            .any(|s| s.contains("macos") && s.contains("capabilities")),
        "{v:?}"
    );
}

#[test]
fn dropping_a_universe_turns_the_roster_guard_red() {
    let mut d = data();
    d.universes.retain(|u| u.id != "linux.listeners");
    let v = data::guards::roster(&d);
    assert!(
        v.iter()
            .any(|s| s.contains("linux") && s.contains("listeners")),
        "{v:?}"
    );
}

// ---- per-entry fixture guard ---------------------------------------------------

#[test]
fn every_rule_signal_and_layer_names_a_fixture_that_labels_it() {
    let d = data();
    let def = deferred();
    assert_clean("fixtures", data::guards::fixtures(&d, &corpus(), &def));
    assert_clean(
        "deferred.toml",
        data::guards::stale_deferred(&d, &corpus(), &def),
    );
}

#[test]
fn a_rule_whose_fixture_is_missing_turns_the_fixture_guard_red() {
    let mut d = data();
    let r = d
        .rules
        .iter_mut()
        .find(|r| r.id == "linux.dev.kvm")
        .unwrap_or_else(|| panic!("linux.dev.kvm missing"));
    r.fixture = "linux/rules/no-such-case".into();
    let v = data::guards::fixtures(&d, &corpus(), &deferred());
    assert!(v.iter().any(|s| s.contains("linux.dev.kvm")), "{v:?}");
}

#[test]
fn an_inert_rule_whose_fixture_labels_no_inert_entry_turns_the_guard_red() {
    let mut d = data();
    let r = d
        .rules
        .iter_mut()
        .find(|r| r.id == "linux.iface.loopback")
        .unwrap_or_else(|| panic!("linux.iface.loopback missing"));
    // This case exists but labels no [[inert]] entry for this rule.
    r.fixture = "linux/routes/device-nodes".into();
    let v = data::guards::fixtures(&d, &corpus(), &deferred());
    assert!(
        v.iter().any(|s| s.contains("linux.iface.loopback")),
        "{v:?}"
    );
}

#[test]
fn a_linux_signal_labeled_only_by_an_unknown_turns_the_guard_red() {
    let mut d = data();
    let s = d
        .signals
        .iter_mut()
        .find(|s| s.id == "linux.loader.preload")
        .unwrap_or_else(|| panic!("linux.loader.preload missing"));
    // The case exists and labels this signal only through an unknown,
    // which counts as a label solely for macOS `<home>` signals.
    s.fixture = "linux/completeness/must-not-touch-without-mount-table".into();
    let v = data::guards::fixtures(&d, &corpus(), &deferred());
    assert!(
        v.iter().any(|s| s.contains("linux.loader.preload")),
        "{v:?}"
    );
}

#[test]
fn attribute_only_signal_passes_through_an_attributes_label() {
    // linux.sysctl.userns produces no route; its fixture labels it through
    // [[attributes]] entries naming the sysctls it reads (KTD28).
    let d = data();
    let def = deferred();
    assert_clean("fixtures", data::guards::fixtures(&d, &corpus(), &def));

    let mut d = data();
    let s = d
        .signals
        .iter_mut()
        .find(|s| s.id == "linux.sysctl.userns")
        .unwrap_or_else(|| panic!("linux.sysctl.userns missing"));
    s.fixture = "linux/layers/host-unrecognized".into();
    let v = data::guards::fixtures(&d, &corpus(), &deferred());
    assert!(v.iter().any(|s| s.contains("linux.sysctl.userns")), "{v:?}");
}

#[test]
fn a_layer_whose_fixture_labels_no_such_kind_turns_the_guard_red() {
    let mut d = data();
    let l = d
        .layers
        .iter_mut()
        .find(|l| l.kind == "bubblewrap")
        .unwrap_or_else(|| panic!("bubblewrap layer missing"));
    l.fixture = "linux/layers/host-unrecognized".into();
    let v = data::guards::fixtures(&d, &corpus(), &deferred());
    assert!(v.iter().any(|s| s.contains("bubblewrap")), "{v:?}");
}

// ---- deferred ledger ------------------------------------------------------------

#[test]
fn an_unreferenced_deferred_entry_is_stale() {
    let d = data();
    let mut def = deferred();
    def.cases.insert("linux/rules/not-referenced".into());
    let v = data::guards::stale_deferred(&d, &corpus(), &def);
    assert!(
        v.iter().any(|s| s.contains("linux/rules/not-referenced")),
        "{v:?}"
    );
}

#[test]
fn a_deferred_entry_whose_case_now_exists_is_stale() {
    let d = data();
    let mut def = deferred();
    def.cases
        .insert("linux/layers/docker-socket-mounted".into());
    let v = data::guards::stale_deferred(&d, &corpus(), &def);
    assert!(
        v.iter().any(|s| s.contains("docker-socket-mounted")),
        "{v:?}"
    );
}

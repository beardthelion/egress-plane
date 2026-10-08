//! Active-mode checks (KTD21, R25, AE6, AE11): the `IP:port` literal
//! grammar, canonicalization of the translated forms, the refused set
//! that never sees a socket, the bounded outcome vocabulary, and the
//! `active.toml` documentation rule.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use egress_probe::active::{self, ConnectOutcome, Connector};
use egress_probe::data::Data;

fn data() -> Data {
    Data::embedded().unwrap()
}

const TIMEOUT: Duration = Duration::from_millis(10);

/// A connector that counts its calls and replays scripted outcomes.
#[derive(Default)]
struct Fake {
    calls: Vec<SocketAddr>,
    outcomes: VecDeque<ConnectOutcome>,
}

impl Connector for Fake {
    fn connect(&mut self, addr: &SocketAddr, _timeout: Duration) -> ConnectOutcome {
        self.calls.push(*addr);
        self.outcomes.pop_front().unwrap_or(ConnectOutcome::Refused)
    }
}

fn parse(values: &[&str]) -> Result<Vec<active::Target>, &'static str> {
    let owned: Vec<String> = values.iter().map(|v| v.to_string()).collect();
    active::parse_allowlist(&owned, 16)
}

#[test]
fn a_hostname_is_a_usage_error_and_sends_nothing() {
    // Covers AE11: `api.example.com` is not an IP literal and is never
    // resolved.
    let mut fake = Fake::default();
    let targets = parse(&["api.example.com:443"]).unwrap_or_default();
    assert!(targets.is_empty());
    let checks = active::run_checks(&data().active, &targets, &mut fake, TIMEOUT);
    assert!(checks.is_empty());
    assert!(fake.calls.is_empty(), "a usage error reached the connector");
}

/// Every metadata address in every translated form is refused before a
/// socket exists (KTD21, AE11).
const METADATA_FORMS: &[&str] = &[
    "169.254.169.254:80",
    "[::ffff:169.254.169.254]:80",
    "[::ffff:a9fe:a9fe]:80",
    "[::a9fe:a9fe]:80",
    "[64:ff9b::a9fe:a9fe]:80",
    "168.63.129.16:80",
    "[::ffff:168.63.129.16]:80",
    "[64:ff9b::a83f:8110]:80",
    "100.100.100.200:80",
    "[::ffff:100.100.100.200]:80",
    "[::6464:64c8]:80",
    "[fd00:ec2::254]:80",
    "[fd00:ec2::23]:80",
    "[fd20:ce::254]:80",
    "[fd00:c1::a9fe:a9fe]:80",
    // Tunnel-embedded and ULA forms of a metadata address.
    "[2001:0:a9fe:a9fe::]:80",
    "[2002:a9fe:a9fe::]:80",
    "[fd00::a9fe:a9fe]:80",
];

#[test]
fn metadata_forms_are_refused_without_a_socket() {
    let d = data();
    for form in METADATA_FORMS {
        let mut fake = Fake::default();
        let targets = parse(&[form]).unwrap_or_else(|e| panic!("{form}: {e}"));
        let checks = active::run_checks(&d.active, &targets, &mut fake, TIMEOUT);
        assert_eq!(checks.len(), 1, "{form}");
        assert_eq!(checks[0].result, "refused-metadata-address", "{form}");
        assert!(fake.calls.is_empty(), "{form} reached the connector");
    }
}

/// Unspecified, broadcast, and multicast addresses are refused as
/// special, in every translated form.
const SPECIAL_FORMS: &[&str] = &[
    "0.0.0.0:80",
    "[::]:80",
    "[::ffff:0.0.0.0]:80",
    "[64:ff9b::]:80",
    "255.255.255.255:80",
    "224.0.0.1:80",
    "[ff02::1]:80",
    "[ff02::a9fe:a9fe]:80",
];

#[test]
fn special_forms_are_refused_without_a_socket() {
    let d = data();
    for form in SPECIAL_FORMS {
        let mut fake = Fake::default();
        let targets = parse(&[form]).unwrap_or_else(|e| panic!("{form}: {e}"));
        let checks = active::run_checks(&d.active, &targets, &mut fake, TIMEOUT);
        assert_eq!(checks.len(), 1, "{form}");
        assert_eq!(checks[0].result, "refused-special-address", "{form}");
        assert!(fake.calls.is_empty(), "{form} reached the connector");
    }
}

#[test]
fn allowlist_usage_errors() {
    // More than the `active-targets` budget (16) entries.
    let too_many: Vec<String> = (1..=17u16).map(|p| format!("10.0.0.1:{p}")).collect();
    assert!(active::parse_allowlist(&too_many, 16).is_err());
    let at_limit: Vec<String> = (1..=16u16).map(|p| format!("10.0.0.1:{p}")).collect();
    assert!(active::parse_allowlist(&at_limit, 16).is_ok());
    // A duplicate literal and a duplicate after canonicalization.
    assert!(parse(&["10.0.0.1:80", "10.0.0.1:80"]).is_err());
    assert!(parse(&["169.254.169.254:80", "[::ffff:169.254.169.254]:80"]).is_err());
    for bad in [
        "api.example.com:443",
        "10.0.0.1:0",
        "10.0.0.1:65536",
        "10.0.0.1",
        "10.0.0.1:",
        "10.0.0.1:x",
        "10.0.0.1:080x",
        ":80",
        "[]",
        "[]:80",
        "[::1]",
        "[::1]x:80",
        "::1:80",
        "",
        "1.2.3.4:80:90",
    ] {
        assert!(parse(&[bad]).is_err(), "{bad}");
    }
    // Accepted literal forms.
    for good in ["10.0.0.1:80", "0.0.0.0:1", "[::1]:443", "[fd00::1]:65535"] {
        assert!(parse(&[good]).is_ok(), "{good}");
    }
}

#[test]
fn connect_outcomes_are_recorded_without_timing_values() {
    let d = data();
    let cases: Vec<(ConnectOutcome, &str)> = vec![
        (ConnectOutcome::Connected, "connected"),
        (ConnectOutcome::Refused, "refused"),
        (ConnectOutcome::TimedOut, "timed-out"),
        (ConnectOutcome::Unreachable, "unreachable"),
        (ConnectOutcome::Error(libc::ECONNRESET), "error:ECONNRESET"),
        (ConnectOutcome::Error(libc::EACCES), "error:EACCES"),
    ];
    for (outcome, want) in cases {
        let mut fake = Fake {
            calls: Vec::new(),
            outcomes: VecDeque::from([outcome]),
        };
        let targets = parse(&["10.0.0.1:80"]).unwrap();
        let checks = active::run_checks(&d.active, &targets, &mut fake, TIMEOUT);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].result, want);
        assert!(!checks[0].result.contains("ms"), "{want}");
        assert_eq!(fake.calls, vec!["10.0.0.1:80".parse().unwrap()]);
    }
}

#[test]
fn checks_run_in_sorted_address_order_on_listed_targets_only() {
    // Covers AE6: only the listed destinations are attempted.
    let d = data();
    let mut fake = Fake::default();
    let targets = parse(&["10.0.0.9:1", "10.0.0.1:1", "10.0.0.5:1", "[fd00::1]:7"]).unwrap();
    let checks = active::run_checks(&d.active, &targets, &mut fake, TIMEOUT);
    assert_eq!(
        fake.calls,
        vec![
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.5:1".parse().unwrap(),
            "10.0.0.9:1".parse().unwrap(),
            "[fd00::1]:7".parse().unwrap(),
        ]
    );
    assert_eq!(checks.len(), 4);
    assert!(checks.iter().all(|c| c.result == "refused"));
    // Canonical targets are recorded in the check, not the raw literal.
    let targets = parse(&["[::ffff:10.0.0.1]:80"]).unwrap();
    let mut fake = Fake::default();
    let checks = active::run_checks(&d.active, &targets, &mut fake, TIMEOUT);
    assert_eq!(checks[0].target, "10.0.0.1:80");
}

#[test]
fn every_metadata_refusal_names_a_source_url() {
    // Each `[[refused]]` entry whose result is
    // `refused-metadata-address` carries a provider documentation URL
    // in its comment (KTD21).
    let text = egress_probe::data::EMBEDDED
        .iter()
        .find(|f| f.path == "data/probe/active.toml")
        .expect("active.toml embedded")
        .text;
    let mut checked = 0;
    for block in text.split("[[refused]]").skip(1) {
        if !block.contains("refused-metadata-address") {
            continue;
        }
        checked += 1;
        assert!(
            block.lines().any(|l| l.trim_start().starts_with("# http")),
            "a metadata refusal lacks a source URL:\n{block}"
        );
    }
    assert!(checked >= 7, "only {checked} metadata entries found");
}

//! Comparison of one scan result against its labels.
//!
//! Matching uses identity components and never `location`. Every labeled
//! site, blind spot, unscanned dependency, and excluded entry is required, and
//! labels are matched as a multiset, so two identical labels need two findings.
//! A finding no label claims is a false positive: counted, never a failure.

use std::collections::BTreeSet;

use egress_core::model::{Label, Report, ToolError};

use crate::labels::{Expected, ExpectedSite};

/// Result of comparing one case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseOutcome {
    /// Reasons the case fails. Empty means the case passes.
    pub failures: Vec<String>,
    /// Findings no label claims (counted, not gating).
    pub false_positives: Vec<String>,
}

impl CaseOutcome {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Compares a scan result with the case's labels.
pub fn compare(expected: &Expected, result: &Result<Report, ToolError>) -> CaseOutcome {
    let mut out = CaseOutcome::default();
    let report = match result {
        Ok(r) => r,
        Err(e) => {
            out.failures.push(format!(
                "tool error ({e}); expected state {} with exit code {}",
                expected.state.as_str(),
                expected.exit_code
            ));
            return out;
        }
    };

    if report.completeness.state != expected.state {
        out.failures.push(format!(
            "state {} (exit code {}) but expected state {} (exit code {})",
            report.completeness.state.as_str(),
            report.exit_code(),
            expected.state.as_str(),
            expected.exit_code
        ));
    }

    compare_sites(expected, report, &mut out);

    // Blind spots.
    let mut unclaimed: Vec<bool> = vec![true; report.blind_spots.len()];
    for b in &expected.blind_spots {
        let hit = report.blind_spots.iter().enumerate().position(|(i, r)| {
            unclaimed[i] && r.file == b.file && r.symbol == b.symbol && r.kind == b.kind
        });
        match hit {
            Some(i) => unclaimed[i] = false,
            None => out.failures.push(format!(
                "missing blind spot {} in {} at {}",
                b.kind.as_str(),
                b.file,
                b.symbol
            )),
        }
    }
    for (i, r) in report.blind_spots.iter().enumerate() {
        if unclaimed[i] {
            out.false_positives.push(format!(
                "blind spot {} in {} at {}",
                r.kind.as_str(),
                r.file,
                r.symbol
            ));
        }
    }

    // Unscanned dependencies.
    let mut unclaimed: Vec<bool> = vec![true; report.unscanned_dependencies.len()];
    for d in &expected.unscanned_dependencies {
        let hit = report
            .unscanned_dependencies
            .iter()
            .enumerate()
            .position(|(i, r)| unclaimed[i] && r.language == d.language && r.package == d.package);
        match hit {
            Some(i) => unclaimed[i] = false,
            None => out.failures.push(format!(
                "missing unscanned dependency {} ({})",
                d.package,
                d.language.as_str()
            )),
        }
    }
    for (i, r) in report.unscanned_dependencies.iter().enumerate() {
        if unclaimed[i] {
            out.false_positives.push(format!(
                "unscanned dependency {} ({})",
                r.package,
                r.language.as_str()
            ));
        }
    }

    // Excluded entries are bookkeeping, not findings: required when labeled,
    // never counted as false positives.
    for x in &expected.excluded {
        if !report
            .excluded
            .iter()
            .any(|r| r.path == x.path && r.reason == x.reason)
        {
            out.failures.push(format!(
                "missing excluded entry {} ({})",
                x.path,
                x.reason.as_str()
            ));
        }
    }

    if let Some(want) = &expected.caveats {
        let want: BTreeSet<&str> = want.iter().map(String::as_str).collect();
        let got: BTreeSet<&str> = report.caveats.iter().map(|c| c.id.as_str()).collect();
        if want != got {
            out.failures
                .push(format!("caveats {got:?} but expected {want:?}"));
        }
    }

    if !expected.absent_text.is_empty() {
        let texts = reported_strings(report);
        for needle in &expected.absent_text {
            if texts.iter().any(|t| t.contains(needle.as_str())) {
                out.failures
                    .push(format!("output contains forbidden text {needle:?}"));
            }
        }
    }

    out
}

fn compare_sites(expected: &Expected, report: &Report, out: &mut CaseOutcome) {
    let mut unclaimed: Vec<bool> = vec![true; report.sites.len()];
    // Labels with a label set are stricter, so they claim findings first; a
    // label without one then cannot take a finding a stricter label needs.
    let ordered = expected
        .sites
        .iter()
        .filter(|s| s.labels.is_some())
        .chain(expected.sites.iter().filter(|s| s.labels.is_none()));
    for s in ordered {
        let hit = report
            .sites
            .iter()
            .enumerate()
            .position(|(i, r)| unclaimed[i] && site_matches(s, r));
        match hit {
            Some(i) => unclaimed[i] = false,
            None => out.failures.push(format!(
                "missing site {} -> {} in {} at {}{}",
                s.mechanism,
                s.destination,
                s.file,
                s.symbol,
                s.labels
                    .as_ref()
                    .map(|l| format!(" with labels {:?}", label_names(l)))
                    .unwrap_or_default()
            )),
        }
    }
    for (i, r) in report.sites.iter().enumerate() {
        if unclaimed[i] {
            out.false_positives.push(format!(
                "site {} -> {} in {} at {}",
                r.mechanism, r.destination.display, r.file, r.symbol
            ));
        }
    }
}

fn site_matches(s: &ExpectedSite, r: &egress_core::model::Site) -> bool {
    r.file == s.file
        && r.symbol == s.symbol
        && r.mechanism == s.mechanism
        && r.destination.display == s.destination
        && s.labels.as_ref().is_none_or(|want| {
            let want: BTreeSet<Label> = want.iter().copied().collect();
            let got: BTreeSet<Label> = r.labels.iter().copied().collect();
            want == got
        })
}

fn label_names(labels: &[Label]) -> Vec<&'static str> {
    labels.iter().map(|l| l.as_str()).collect()
}

/// Every string a report carries that came from scanned input or rendering.
/// Identity hashes and raw-byte hex are excluded: they are not text, and a
/// short forbidden string can occur in hex by chance.
fn reported_strings(r: &Report) -> Vec<&str> {
    let mut v: Vec<&str> = Vec::new();
    for s in &r.sites {
        v.extend([
            s.file.as_str(),
            s.symbol.as_str(),
            s.mechanism.as_str(),
            s.destination.value.as_str(),
            s.destination.display.as_str(),
        ]);
        if let Some(d) = &s.destination.default {
            v.push(d);
        }
    }
    for b in &r.blind_spots {
        v.extend([b.file.as_str(), b.symbol.as_str(), b.construct.as_str()]);
    }
    for d in &r.unscanned_dependencies {
        v.push(&d.package);
        v.extend(d.files.iter().map(String::as_str));
    }
    for x in &r.excluded {
        v.push(&x.path);
    }
    for c in &r.caveats {
        v.extend([c.id.as_str(), c.text.as_str()]);
    }
    v
}

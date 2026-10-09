//! Comparison of one scan result against its labels.
//!
//! Matching uses identity components and never `location`. Every labeled
//! site, blind spot, unscanned dependency, and excluded entry is required, and
//! labels are matched as a multiset, so two identical labels need two findings.
//! A finding no label claims is a false positive: counted, never a failure.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use egress_core::model::{
    DependencyBudgetReason, DependencyMark, DependencyPackage, DependencySection, Label, MarkRule,
    Report, ToolError, UnscannedDependency,
};

use crate::labels::{Expected, ExpectedDependency, ExpectedDependencyPackage, ExpectedSite};

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

/// Compares a scan result with the case's labels and applies the global
/// rules: a case with no `[[dependency_root]]` must produce no dependency
/// section and no unscanned reason, and the case directory's absolute path
/// must not appear in the JSON output.
pub fn compare_case(
    expected: &Expected,
    result: &Result<Report, ToolError>,
    case_dir: &Path,
) -> CaseOutcome {
    let mut out = compare(expected, result);
    if let Ok(report) = result {
        let mut needles: Vec<String> = Vec::new();
        if let Ok(abs) = std::fs::canonicalize(case_dir) {
            needles.push(abs.to_string_lossy().into_owned());
        }
        if let Ok(abs) = std::path::absolute(case_dir) {
            needles.push(abs.to_string_lossy().into_owned());
        }
        needles.push(case_dir.to_string_lossy().into_owned());
        needles.sort();
        needles.dedup();
        needles.retain(|n| n.len() > 1);
        if !needles.is_empty() {
            let json = egress_core::json::to_json(report);
            if let Some(n) = needles.iter().find(|n| json.contains(n.as_str())) {
                out.failures
                    .push(format!("output contains the case directory path {n:?}"));
            }
        }
    }
    out
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
            Some(i) => {
                unclaimed[i] = false;
                check_unscanned_optionals(d, &report.unscanned_dependencies[i], &mut out);
            }
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

    compare_dependencies(expected, report, &mut out);

    // Opt-in rule (R1): a case that names no dependency root must produce
    // no dependency section and no unscanned reason.
    if expected.dependency_roots.is_empty() {
        if report.dependencies.is_some() {
            out.failures.push(
                "report has a dependency section but the case names no [[dependency_root]]"
                    .to_string(),
            );
        }
        for d in &report.unscanned_dependencies {
            if let Some(r) = d.reason {
                out.failures.push(format!(
                    "unscanned dependency {} carries reason {} but the case names no \
                     [[dependency_root]]",
                    d.package,
                    r.as_str()
                ));
            }
        }
    }

    // Absence labels.
    for d in &expected.absent_unscanned {
        if report
            .unscanned_dependencies
            .iter()
            .any(|r| r.language == d.language && r.package == d.package)
        {
            out.failures.push(format!(
                "unscanned dependency {} ({}) must not appear",
                d.package,
                d.language.as_str()
            ));
        }
    }
    let packages: &[DependencyPackage] = report
        .dependencies
        .as_ref()
        .map(|s| s.packages.as_slice())
        .unwrap_or(&[]);
    for d in &expected.absent_scanned {
        if packages
            .iter()
            .any(|p| p.language == d.language && p.package == d.package)
        {
            out.failures.push(format!(
                "dependency package {} ({}) must not appear",
                d.package,
                d.language.as_str()
            ));
        }
    }
    for b in &expected.absent_dependency_blind_spots {
        for p in packages.iter().filter(|p| p.package == b.package) {
            if p.blind_spots.iter().any(|s| s.kind == b.kind) {
                out.failures.push(format!(
                    "blind spot {} must not appear in dependency package {}",
                    b.kind.as_str(),
                    b.package
                ));
            }
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

/// A labeled value equals the reported one after sorting; a labeled empty
/// list requires the reported list to be empty.
fn opt_strings_eq(want: &Option<Vec<String>>, got: &[String]) -> bool {
    match want {
        None => true,
        Some(w) => {
            let mut w = w.clone();
            let mut g = got.to_vec();
            w.sort();
            g.sort();
            w == g
        }
    }
}

/// A labeled mark equals the reported mark's `resembles` names (sorted);
/// `mark = []` requires the mark to be absent. `mark_rules` compares the
/// rule set when present.
fn mark_matches(
    want_mark: &Option<Vec<String>>,
    want_rules: &Option<Vec<MarkRule>>,
    got: &Option<DependencyMark>,
) -> bool {
    match want_mark {
        Some(v) if v.is_empty() => {
            if got.is_some() {
                return false;
            }
        }
        Some(v) => match got {
            Some(m) => {
                let mut w = v.clone();
                let mut g = m.resembles.clone();
                w.sort();
                g.sort();
                if w != g {
                    return false;
                }
            }
            None => return false,
        },
        None => {}
    }
    if let Some(w) = want_rules {
        match got {
            Some(m) => {
                let mut w = w.clone();
                let mut g = m.rules.clone();
                w.sort();
                g.sort();
                if w != g {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

fn check_unscanned_optionals(
    d: &ExpectedDependency,
    r: &UnscannedDependency,
    out: &mut CaseOutcome,
) {
    if let Some(want) = d.reason
        && r.reason != Some(want)
    {
        out.failures.push(format!(
            "unscanned dependency {} has reason {} but the label wants {}",
            d.package,
            r.reason.map(|r| r.as_str()).unwrap_or("<none>"),
            want.as_str()
        ));
    }
    if !opt_strings_eq(&d.distribution, &r.distribution) {
        out.failures.push(format!(
            "unscanned dependency {} has distribution {:?} but the label wants {:?}",
            d.package, r.distribution, d.distribution
        ));
    }
    if !mark_matches(&d.mark, &d.mark_rules, &r.mark) {
        out.failures.push(format!(
            "unscanned dependency {} has mark {:?} but the label wants {:?}/{:?}",
            d.package, r.mark, d.mark, d.mark_rules
        ));
    }
}

fn package_matches(e: &ExpectedDependencyPackage, p: &DependencyPackage) -> bool {
    p.language == e.language
        && p.package == e.package
        && p.root == e.root
        && p.locator == e.locator
        && p.version == e.version
        && p.strength == e.strength
        && p.state == e.state
        && p.modified == e.modified
        && p.linked == e.linked
        && p.catalogued == e.catalogued
        && opt_strings_eq(&e.distribution, &p.distribution)
        && mark_matches(&e.mark, &e.mark_rules, &p.mark)
}

/// The dependency-section comparisons: package entries, their sites, blind
/// spots, and unscanned imports, the auto-run inventory, lockfile
/// diagnostics, and the exceeded-budget set.
fn compare_dependencies(expected: &Expected, report: &Report, out: &mut CaseOutcome) {
    let section: Option<&DependencySection> = report.dependencies.as_ref();
    let packages: &[DependencyPackage] = section.map(|s| s.packages.as_slice()).unwrap_or(&[]);

    // Package entries are a required multiset.
    let mut unclaimed: Vec<bool> = vec![true; packages.len()];
    for d in &expected.dependencies {
        let hit = packages
            .iter()
            .enumerate()
            .position(|(i, p)| unclaimed[i] && package_matches(d, p));
        match hit {
            Some(i) => unclaimed[i] = false,
            None => out.failures.push(format!(
                "missing dependency package {} at {} (root {})",
                d.package, d.locator, d.root
            )),
        }
    }
    for (i, p) in packages.iter().enumerate() {
        if unclaimed[i] {
            out.false_positives.push(format!(
                "dependency package {} at {} (root {})",
                p.package, p.locator, p.root
            ));
        }
    }

    // Sites, blind spots, and unscanned imports are multisets inside the
    // entry named by package and locator.
    let mut site_claims: BTreeMap<usize, Vec<bool>> = BTreeMap::new();
    for s in &expected.dependency_sites {
        match packages
            .iter()
            .position(|p| p.package == s.package && p.locator == s.locator)
        {
            None => out.failures.push(format!(
                "no dependency entry for {} at {} to hold a site",
                s.package, s.locator
            )),
            Some(i) => {
                let claims = site_claims
                    .entry(i)
                    .or_insert_with(|| vec![true; packages[i].sites.len()]);
                let hit = packages[i].sites.iter().enumerate().position(|(j, r)| {
                    claims[j]
                        && r.file == s.file
                        && r.symbol == s.symbol
                        && r.mechanism == s.mechanism
                        && r.destination.display == s.destination
                });
                match hit {
                    Some(j) => claims[j] = false,
                    None => out.failures.push(format!(
                        "missing site {} -> {} in dependency {} at {} ({})",
                        s.mechanism, s.destination, s.package, s.locator, s.file
                    )),
                }
            }
        }
    }
    for (i, p) in packages.iter().enumerate() {
        for (j, r) in p.sites.iter().enumerate() {
            if site_claims.get(&i).is_none_or(|c| c[j]) {
                out.false_positives.push(format!(
                    "site {} -> {} in dependency {} at {}",
                    r.mechanism, r.destination.display, p.package, p.locator
                ));
            }
        }
    }

    let mut spot_claims: BTreeMap<usize, Vec<bool>> = BTreeMap::new();
    for b in &expected.dependency_blind_spots {
        match packages
            .iter()
            .position(|p| p.package == b.package && p.locator == b.locator)
        {
            None => out.failures.push(format!(
                "no dependency entry for {} at {} to hold a blind spot",
                b.package, b.locator
            )),
            Some(i) => {
                let claims = spot_claims
                    .entry(i)
                    .or_insert_with(|| vec![true; packages[i].blind_spots.len()]);
                let hit = packages[i]
                    .blind_spots
                    .iter()
                    .enumerate()
                    .position(|(j, r)| {
                        claims[j] && r.file == b.file && r.symbol == b.symbol && r.kind == b.kind
                    });
                match hit {
                    Some(j) => claims[j] = false,
                    None => out.failures.push(format!(
                        "missing blind spot {} in dependency {} at {} ({})",
                        b.kind.as_str(),
                        b.package,
                        b.locator,
                        b.file
                    )),
                }
            }
        }
    }
    for (i, p) in packages.iter().enumerate() {
        for (j, r) in p.blind_spots.iter().enumerate() {
            if spot_claims.get(&i).is_none_or(|c| c[j]) {
                out.false_positives.push(format!(
                    "blind spot {} in dependency {} at {}",
                    r.kind.as_str(),
                    p.package,
                    p.locator
                ));
            }
        }
    }

    let mut imp_claims: BTreeMap<usize, Vec<bool>> = BTreeMap::new();
    for imp in &expected.dependency_imports_unscanned {
        match packages
            .iter()
            .position(|p| p.package == imp.package && p.locator == imp.locator)
        {
            None => out.failures.push(format!(
                "no dependency entry for {} at {} to hold an unscanned import",
                imp.package, imp.locator
            )),
            Some(i) => {
                let claims = imp_claims
                    .entry(i)
                    .or_insert_with(|| vec![true; packages[i].imports_unscanned.len()]);
                let hit = packages[i]
                    .imports_unscanned
                    .iter()
                    .enumerate()
                    .position(|(j, r)| {
                        claims[j]
                            && r.language == imp.language
                            && r.package == imp.imported
                            && r.reason == imp.reason
                    });
                match hit {
                    Some(j) => claims[j] = false,
                    None => out.failures.push(format!(
                        "missing unscanned import {} ({}) in dependency {} at {}",
                        imp.imported,
                        imp.language.as_str(),
                        imp.package,
                        imp.locator
                    )),
                }
            }
        }
    }
    for (i, p) in packages.iter().enumerate() {
        for (j, r) in p.imports_unscanned.iter().enumerate() {
            if imp_claims.get(&i).is_none_or(|c| c[j]) {
                out.false_positives.push(format!(
                    "unscanned import {} in dependency {} at {}",
                    r.package, p.package, p.locator
                ));
            }
        }
    }

    // Auto-run entries and lockfile diagnostics are multisets.
    if let Some(section) = section {
        let mut unclaimed: Vec<bool> = vec![true; section.auto_run.len()];
        for a in &expected.auto_run {
            let hit = section.auto_run.iter().enumerate().position(|(i, r)| {
                unclaimed[i]
                    && r.file == a.file
                    && r.trigger == a.trigger
                    && r.distribution == a.distribution
            });
            match hit {
                Some(i) => unclaimed[i] = false,
                None => out.failures.push(format!(
                    "missing auto-run file {} ({})",
                    a.file,
                    a.trigger.as_str()
                )),
            }
        }
        for (i, r) in section.auto_run.iter().enumerate() {
            if unclaimed[i] {
                out.false_positives.push(format!(
                    "auto-run file {} ({})",
                    r.file,
                    r.trigger.as_str()
                ));
            }
        }

        let mut unclaimed: Vec<bool> = vec![true; section.diagnostics.len()];
        for d in &expected.dependency_diagnostics {
            let hit = section.diagnostics.iter().enumerate().position(|(i, r)| {
                unclaimed[i] && r.lockfile == d.lockfile && r.problem == d.problem
            });
            match hit {
                Some(i) => unclaimed[i] = false,
                None => out.failures.push(format!(
                    "missing lockfile diagnostic {} ({})",
                    d.lockfile,
                    d.problem.as_str()
                )),
            }
        }
        for (i, r) in section.diagnostics.iter().enumerate() {
            if unclaimed[i] {
                out.false_positives.push(format!(
                    "lockfile diagnostic {} ({})",
                    r.lockfile,
                    r.problem.as_str()
                ));
            }
        }
    } else {
        for a in &expected.auto_run {
            out.failures.push(format!(
                "missing auto-run file {} ({})",
                a.file,
                a.trigger.as_str()
            ));
        }
        for d in &expected.dependency_diagnostics {
            out.failures.push(format!(
                "missing lockfile diagnostic {} ({})",
                d.lockfile,
                d.problem.as_str()
            ));
        }
    }

    if let Some(want) = &expected.dependency_budget_exceeded {
        let want: BTreeSet<DependencyBudgetReason> = want.iter().copied().collect();
        let got: BTreeSet<DependencyBudgetReason> = section
            .map(|s| s.budget_exceeded.iter().copied().collect())
            .unwrap_or_default();
        if want != got {
            let fmt = |s: &BTreeSet<DependencyBudgetReason>| {
                s.iter().map(|b| b.as_str()).collect::<Vec<_>>().join(", ")
            };
            out.failures.push(format!(
                "dependency budget_exceeded [{}] but the label wants [{}]",
                fmt(&got),
                fmt(&want)
            ));
        }
    }
}

/// Every string a report carries that came from scanned input or rendering,
/// including the whole dependency section. Identity hashes and raw-byte hex
/// are excluded: they are not text, and a short forbidden string can occur
/// in hex by chance.
fn reported_strings(r: &Report) -> Vec<&str> {
    let mut v: Vec<&str> = Vec::new();
    site_strings(&r.sites, &mut v);
    blind_spot_strings(&r.blind_spots, &mut v);
    for d in &r.unscanned_dependencies {
        v.push(&d.package);
        v.extend(d.files.iter().map(String::as_str));
        v.extend(d.distribution.iter().map(String::as_str));
        if let Some(m) = &d.mark {
            v.extend(m.resembles.iter().map(String::as_str));
        }
    }
    for x in &r.excluded {
        v.push(&x.path);
    }
    for c in &r.caveats {
        v.extend([c.id.as_str(), c.text.as_str()]);
    }
    if let Some(d) = &r.dependencies {
        for root in &d.roots {
            v.push(&root.label);
        }
        v.extend(d.caveats.iter().map(String::as_str));
        for diag in &d.diagnostics {
            v.push(&diag.lockfile);
        }
        for a in &d.auto_run {
            v.extend([a.root.as_str(), a.file.as_str(), a.distribution.as_str()]);
        }
        for p in &d.packages {
            v.extend([
                p.package.as_str(),
                p.root.as_str(),
                p.locator.as_str(),
                p.version.as_str(),
            ]);
            v.extend(p.distribution.iter().map(String::as_str));
            if let Some(m) = &p.mark {
                v.extend(m.resembles.iter().map(String::as_str));
            }
            v.extend(p.imported_by.iter().map(String::as_str));
            site_strings(&p.sites, &mut v);
            blind_spot_strings(&p.blind_spots, &mut v);
            for i in &p.imports_unscanned {
                v.push(&i.package);
                v.extend(i.distribution.iter().map(String::as_str));
                if let Some(m) = &i.mark {
                    v.extend(m.resembles.iter().map(String::as_str));
                }
            }
        }
    }
    v
}

fn site_strings<'a>(sites: &'a [egress_core::model::Site], v: &mut Vec<&'a str>) {
    for s in sites {
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
}

fn blind_spot_strings<'a>(spots: &'a [egress_core::model::BlindSpot], v: &mut Vec<&'a str>) {
    for b in spots {
        v.extend([b.file.as_str(), b.symbol.as_str(), b.construct.as_str()]);
    }
}

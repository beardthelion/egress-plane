//! The human-readable report.
//!
//! Layout: a header with the tool version, completeness state and exit code,
//! coverage, exhausted budgets, and the runtime range; then caveats;
//! egress sites grouped by destination display; blind spots grouped by kind
//! with coverage gaps first; unscanned dependencies; and exclusions.
//!
//! Every string taken from scanned input passes through [`escape`], so
//! no rendered line holds a raw control, format, or separator character. Only
//! section headings start at column zero, and every finding line is indented,
//! so a crafted string cannot forge report structure. The report is a pure
//! function of the finalized report, which keeps it as deterministic as the
//! JSON.

use std::collections::BTreeMap;
use std::fmt::Write;

use egress_core::escape::escape;
use egress_core::identity::finalize;
use egress_core::model::{BlindSpot, CoverageCounts, DependencyMark, Location, Report, Site};

fn counts(name: &str, c: CoverageCounts) -> String {
    format!("{name} {} scanned, {} skipped", c.scanned, c.skipped)
}

fn place(file: &str, location: Option<Location>) -> String {
    let file = escape(file);
    match location {
        Some(l) => format!("{file}:{}:{}", l.line, l.column),
        None => file,
    }
}

fn labels(l: &[egress_core::model::Label]) -> String {
    if l.is_empty() {
        return String::new();
    }
    let names: Vec<_> = l.iter().map(|l| l.as_str()).collect();
    format!("  ({})", names.join(", "))
}

fn mark_suffix(m: &Option<DependencyMark>) -> String {
    let Some(m) = m else {
        return String::new();
    };
    let rules: Vec<_> = m.rules.iter().map(|r| r.as_str()).collect();
    let mut s = format!("  marked {}", rules.join(", "));
    if !m.resembles.is_empty() {
        let names: Vec<_> = m.resembles.iter().map(|n| escape(n)).collect();
        let _ = write!(s, " resembling {}", names.join(", "));
    }
    s
}

fn site_line(s: &Site) -> String {
    format!(
        "    {}  in {}  via {}  [{}]{}",
        place(&s.file, s.location),
        escape(&s.symbol),
        escape(&s.mechanism),
        s.bucket.as_str(),
        labels(&s.labels)
    )
}

fn blind_spot_line(b: &BlindSpot) -> String {
    let mut line = format!(
        "    {}  in {}",
        place(&b.file, b.location),
        escape(&b.symbol)
    );
    if !b.construct.is_empty() {
        let _ = write!(line, "  {}", escape(&b.construct));
    }
    line + &labels(&b.labels)
}

/// Renders `report` as text ending with one newline.
pub fn render(report: &Report) -> String {
    let mut r = report.clone();
    finalize(&mut r);
    let mut out = String::new();
    let c = &r.completeness;

    let _ = writeln!(out, "{} {}", escape(&r.tool.name), escape(&r.tool.version));
    let _ = writeln!(
        out,
        "State: {} (exit code {})",
        c.state.as_str(),
        c.state.exit_code()
    );
    let _ = writeln!(
        out,
        "Coverage: {}; {}; {}; {}",
        counts("python", c.coverage.python),
        counts("javascript", c.coverage.javascript),
        counts("rust", c.coverage.rust),
        counts("unsupported", c.coverage.unsupported),
    );
    let budgets: Vec<_> = c.budget_exceeded.iter().map(|b| b.as_str()).collect();
    let _ = writeln!(
        out,
        "Budgets exceeded: {}",
        if budgets.is_empty() {
            "none".to_string()
        } else {
            budgets.join(", ")
        }
    );
    let rr = &r.tool.runtime_range;
    let _ = writeln!(
        out,
        "Runtime range: Python {}, Node {}, Rust {}",
        escape(&rr.python),
        escape(&rr.node),
        escape(&rr.rust)
    );

    let _ = writeln!(out, "\nCaveats ({})", r.caveats.len());
    for cv in &r.caveats {
        let _ = writeln!(out, "  [{}] {}", escape(&cv.id), escape(&cv.text));
    }
    if r.caveats.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nEgress sites ({})", r.sites.len());
    let mut by_destination: BTreeMap<&str, Vec<&Site>> = BTreeMap::new();
    for s in &r.sites {
        by_destination
            .entry(s.destination.display.as_str())
            .or_default()
            .push(s);
    }
    for (display, sites) in &by_destination {
        let _ = writeln!(out, "  {}", escape(display));
        for s in sites {
            let _ = writeln!(out, "{}", site_line(s));
        }
    }
    if r.sites.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nBlind spots ({})", r.blind_spots.len());
    // Coverage gaps first, then by kind name.
    let mut by_kind: BTreeMap<(bool, &str), Vec<&BlindSpot>> = BTreeMap::new();
    for b in &r.blind_spots {
        by_kind
            .entry((!b.coverage_gap, b.kind.as_str()))
            .or_default()
            .push(b);
    }
    for ((not_gap, kind), spots) in &by_kind {
        let gap = if *not_gap { "" } else { " (coverage gap)" };
        let _ = writeln!(out, "  {kind}{gap}");
        for b in spots {
            let _ = writeln!(out, "{}", blind_spot_line(b));
        }
    }
    if r.blind_spots.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(
        out,
        "\nUnscanned dependencies ({})",
        r.unscanned_dependencies.len()
    );
    for d in &r.unscanned_dependencies {
        let files: Vec<_> = d.files.iter().map(|f| escape(f)).collect();
        let mut extras = String::new();
        if let Some(reason) = d.reason {
            let _ = write!(extras, " {}", reason.as_str());
        }
        if !d.distribution.is_empty() {
            let dist: Vec<_> = d.distribution.iter().map(|n| escape(n)).collect();
            let _ = write!(extras, " via {}", dist.join(", "));
        }
        extras.push_str(&mark_suffix(&d.mark));
        let _ = writeln!(
            out,
            "  {} {}{}: {}",
            d.language.as_str(),
            escape(&d.package),
            extras,
            files.join(", ")
        );
    }
    if r.unscanned_dependencies.is_empty() {
        out.push_str("  none\n");
    }

    if let Some(d) = &r.dependencies {
        let _ = writeln!(out, "\nScanned dependencies ({})", d.packages.len());
        if d.packages.is_empty() {
            out.push_str("  none\n");
        }
        for p in &d.packages {
            let mut fields = format!(
                "  {} {} {} ({}): {}",
                p.language.as_str(),
                escape(&p.package),
                escape(&p.locator),
                escape(&p.root),
                escape(&p.version)
            );
            let _ = write!(fields, "  {}  {}", p.strength.as_str(), p.state.as_str());
            if p.modified {
                fields.push_str("  modified");
            }
            if p.linked {
                fields.push_str("  linked");
            }
            if p.catalogued {
                fields.push_str("  catalogued");
            }
            if !p.distribution.is_empty() {
                let dist: Vec<_> = p.distribution.iter().map(|n| escape(n)).collect();
                let _ = write!(fields, "  via {}", dist.join(", "));
            }
            fields.push_str(&mark_suffix(&p.mark));
            let _ = writeln!(out, "{fields}");
            if !p.imported_by.is_empty() {
                let files: Vec<_> = p.imported_by.iter().map(|f| escape(f)).collect();
                let _ = writeln!(out, "    imported by {}", files.join(", "));
            }
            for s in &p.sites {
                let _ = writeln!(out, "{}", site_line(s));
            }
            for b in &p.blind_spots {
                let _ = writeln!(out, "{}", blind_spot_line(b));
            }
            for i in &p.imports_unscanned {
                let mut line = format!(
                    "    {} {}  {}",
                    i.language.as_str(),
                    escape(&i.package),
                    i.reason.as_str()
                );
                if !i.distribution.is_empty() {
                    let dist: Vec<_> = i.distribution.iter().map(|n| escape(n)).collect();
                    let _ = write!(line, "  via {}", dist.join(", "));
                }
                line.push_str(&mark_suffix(&i.mark));
                let _ = writeln!(out, "{line}");
            }
        }
        if !d.auto_run.is_empty() {
            let _ = writeln!(out, "  auto-run files ({})", d.auto_run.len());
            for a in &d.auto_run {
                let _ = writeln!(
                    out,
                    "    {}  {}  installed by {}",
                    escape(&a.file),
                    a.trigger.as_str(),
                    escape(&a.distribution)
                );
            }
        }
        if !d.diagnostics.is_empty() {
            let _ = writeln!(out, "  lockfile diagnostics ({})", d.diagnostics.len());
            for dg in &d.diagnostics {
                let _ = writeln!(out, "    {}  {}", escape(&dg.lockfile), dg.problem.as_str());
            }
        }
        if !d.budget_exceeded.is_empty() {
            let budgets: Vec<_> = d.budget_exceeded.iter().map(|b| b.as_str()).collect();
            let _ = writeln!(out, "  budgets exceeded: {}", budgets.join(", "));
        }
    }

    let _ = writeln!(out, "\nExcluded ({})", r.excluded.len());
    for x in &r.excluded {
        let _ = writeln!(out, "  {}  {}", escape(&x.path), x.reason.as_str());
    }
    if r.excluded.is_empty() {
        out.push_str("  none\n");
    }
    out
}

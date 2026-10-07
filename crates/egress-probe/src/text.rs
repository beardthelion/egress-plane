//! The human-readable probe report.
//!
//! Sections in declared order: the header (version, source, platform,
//! layer order basis, mode, privilege, nonce, state, exit code), then
//! Layers with namespace inodes, Egress routes, Escape routes, Unknowns,
//! Tamper indicators, Not observable, Not applicable, Unclassified
//! grouped by universe, Inert counts per universe, Active checks, and
//! Caveats.
//!
//! Every string taken from the environment passes through [`escape`], so
//! no rendered line holds a raw control, format, or separator character.
//! Only section headings start at column zero and every entry is
//! indented, so a crafted string cannot forge report structure. The
//! report is a pure function of the finalized report, which keeps it as
//! deterministic as the JSON.

use std::collections::BTreeMap;
use std::fmt::Write;

use egress_core::escape::escape;

use crate::identity::finalize;
use crate::model::*;

fn attr_text(name: &str, v: &AttrValue, out: &mut String) {
    match v {
        AttrValue::Str(s) => {
            let _ = writeln!(out, "    {name}: {}", escape(s));
        }
        AttrValue::Int(n) => {
            let _ = writeln!(out, "    {name}: {n}");
        }
        AttrValue::Bool(b) => {
            let _ = writeln!(out, "    {name}: {b}");
        }
        AttrValue::Strings(ss) => {
            if ss.is_empty() {
                let _ = writeln!(out, "    {name}: (empty)");
            } else {
                let _ = writeln!(out, "    {name}:");
                for s in ss {
                    let _ = writeln!(out, "      {}", escape(s));
                }
            }
        }
        AttrValue::Namespaces(ns) => {
            let rendered: Vec<String> = ns
                .iter()
                .map(|n| format!("{} inode {}", escape(&n.name), n.inode))
                .collect();
            let _ = writeln!(out, "    {name}: {}", rendered.join(", "));
        }
    }
}

fn route_lines(routes: &[Route], out: &mut String) {
    for r in routes {
        let origin = r
            .rule
            .as_deref()
            .map(|id| format!("rule {}", escape(id)))
            .or_else(|| {
                r.signal
                    .as_deref()
                    .map(|id| format!("signal {}", escape(id)))
            })
            .unwrap_or_else(|| "route".to_string());
        let verified = if r.verified { "verified" } else { "unverified" };
        let _ = writeln!(
            out,
            "  {} {} via {} ({})",
            escape(&r.kind),
            escape(&r.display),
            origin,
            verified
        );
    }
}

/// Renders `report` as text ending with one newline.
pub fn render(report: &Report) -> String {
    let mut r = report.clone();
    finalize(&mut r);
    let mut out = String::new();

    let _ = writeln!(out, "egress-plane probe {}", escape(&r.tool.version));
    let _ = writeln!(out, "  source: {}", r.source.as_str());
    let _ = writeln!(out, "  platform: {}", r.platform.as_str());
    let _ = writeln!(out, "  layer order basis: {LAYER_ORDER_BASIS}");
    let _ = writeln!(out, "  mode: {}", r.mode.as_str());
    let _ = writeln!(
        out,
        "  privilege: euid {}, egid {}{}",
        r.privilege.euid,
        r.privilege.egid,
        if r.privilege.root() { " (root)" } else { "" }
    );
    let _ = writeln!(
        out,
        "  nonce: {}",
        r.nonce
            .as_deref()
            .map(escape)
            .unwrap_or_else(|| "none".into())
    );
    let _ = writeln!(
        out,
        "  state: {} (exit code {})",
        r.completeness.as_str(),
        r.exit_code()
    );

    let _ = writeln!(out, "\nLayers ({})", r.layers.len());
    for l in &r.layers {
        let _ = writeln!(out, "  {} {}", l.family.as_str(), escape(&l.kind));
        for e in &l.evidence {
            let _ = writeln!(
                out,
                "    evidence {}: {}",
                e.class.as_str(),
                escape(&e.detail)
            );
        }
        for (name, v) in &l.attributes {
            attr_text(name, v, &mut out);
        }
    }
    if r.layers.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nEgress routes ({})", r.egress_routes.len());
    route_lines(&r.egress_routes, &mut out);
    if r.egress_routes.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nEscape routes ({})", r.escape_routes.len());
    route_lines(&r.escape_routes, &mut out);
    if r.escape_routes.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nUnknowns ({})", r.unknowns.len());
    for u in &r.unknowns {
        let _ = writeln!(out, "  {}: {}", escape(&u.source), u.reason.as_str());
    }
    if r.unknowns.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nTamper indicators ({})", r.tamper_indicators.len());
    for t in &r.tamper_indicators {
        let _ = writeln!(
            out,
            "  {} ({}): {}",
            escape(&t.indicator),
            t.strength.as_str(),
            escape(&t.display)
        );
    }
    if r.tamper_indicators.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nNot observable ({})", r.not_observable.len());
    for n in &r.not_observable {
        let _ = writeln!(out, "  {}: {}", escape(&n.id), escape(&n.statement));
    }
    if r.not_observable.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nNot applicable ({})", r.not_applicable.len());
    for n in &r.not_applicable {
        let _ = writeln!(out, "  {}", escape(n));
    }
    if r.not_applicable.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nUnclassified ({})", r.unclassified.len());
    let mut by_universe: BTreeMap<&str, Vec<&Unclassified>> = BTreeMap::new();
    for u in &r.unclassified {
        by_universe.entry(&u.universe).or_default().push(u);
    }
    for (universe, entries) in &by_universe {
        let _ = writeln!(out, "  {}", escape(universe));
        for u in entries {
            let _ = writeln!(out, "    {}", escape(&u.display));
        }
    }
    if r.unclassified.is_empty() {
        out.push_str("  none\n");
    }

    // Inert members are listed in JSON under their universes; the text
    // report shows counts per universe.
    let mut inert: BTreeMap<&str, usize> = BTreeMap::new();
    for u in &r.universes {
        let n = u
            .members
            .iter()
            .filter(|m| m.class == MemberClass::Inert)
            .count();
        if n > 0 {
            inert.insert(&u.id, n);
        }
    }
    out.push_str("\nInert\n");
    if inert.is_empty() {
        out.push_str("  none\n");
    } else {
        for (universe, n) in &inert {
            let _ = writeln!(out, "  {}: {n}", escape(universe));
        }
    }

    let _ = writeln!(out, "\nActive checks ({})", r.active_checks.len());
    for c in &r.active_checks {
        let _ = writeln!(out, "  {}: {}", escape(&c.target), escape(&c.result));
    }
    if r.active_checks.is_empty() {
        out.push_str("  none\n");
    }

    let _ = writeln!(out, "\nCaveats ({})", r.caveats.len());
    for c in &r.caveats {
        let _ = writeln!(out, "  [{}] {}", escape(&c.id), escape(&c.text));
    }
    if r.caveats.is_empty() {
        out.push_str("  none\n");
    }
    out
}

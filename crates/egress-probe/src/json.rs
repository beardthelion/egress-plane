//! Deterministic JSON output for the probe report.
//!
//! Output structs mirror the report in the schema's fixed field order.
//! Determinism comes from [`finalize`] on a copy, never from enumeration
//! order. Environment bytes pass through the KTD27 encoder: a field is
//! exact only when it is clean UTF-8, otherwise it emits as
//! `<name>_display` plus `<name>_bytes` hex and the exact field is
//! omitted. Every `display` value passes through [`escape`].
//!
//! The rendered report is charged against the KTD18 byte budget in
//! declared universe order: a universe whose rendered members would push
//! the total past the cap is replaced by an unknown `budget-exceeded` and
//! charging continues, so output is never truncated and presented as
//! complete. Nothing time- or host-dependent is written.

use std::collections::{BTreeMap, BTreeSet};

use egress_core::escape::escape;
use egress_core::model::CompletenessState;
use serde::Serialize;
use serde_json::Value;

use crate::identity::{encode_field, finalize, unknown_id};
use crate::model::*;

#[derive(Serialize)]
struct JReport<'a> {
    schema_version: u32,
    kind: &'static str,
    tool: JTool<'a>,
    source: &'static str,
    platform: &'static str,
    layer_order_basis: &'static str,
    privilege: JPrivilege,
    mode: &'static str,
    nonce: Option<&'a str>,
    completeness: JCompleteness,
    layers: Vec<JLayer<'a>>,
    egress_routes: Vec<JRoute<'a>>,
    escape_routes: Vec<JRoute<'a>>,
    unknowns: Vec<JUnknown<'a>>,
    tamper_indicators: Vec<JTamper<'a>>,
    not_observable: Vec<JNotObservable<'a>>,
    not_applicable: Vec<&'a str>,
    unclassified: Vec<JUnclassified<'a>>,
    universes: Vec<JUniverse>,
    signals: Vec<JSignal<'a>>,
    active_checks: Vec<JActiveCheck<'a>>,
    caveats: Vec<JCaveat<'a>>,
}

#[derive(Serialize)]
struct JTool<'a> {
    name: &'a str,
    version: &'a str,
    data_digest: &'a str,
}

#[derive(Serialize)]
struct JPrivilege {
    euid: u32,
    egid: u32,
    root: bool,
}

#[derive(Serialize)]
struct JCompleteness {
    state: &'static str,
}

#[derive(Serialize)]
struct JEvidence {
    class: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct JLayer<'a> {
    id: &'a str,
    family: &'static str,
    kind: &'a str,
    evidence: Vec<JEvidence>,
    attributes: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct JRoute<'a> {
    id: &'a str,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    member: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location_display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location_bytes: Option<String>,
    verified: bool,
    display: String,
}

#[derive(Serialize)]
struct JUnknown<'a> {
    id: &'a str,
    source: &'a str,
    reason: &'static str,
}

#[derive(Serialize)]
struct JTamper<'a> {
    id: &'a str,
    indicator: &'a str,
    strength: &'static str,
    display: String,
}

#[derive(Serialize)]
struct JNotObservable<'a> {
    id: &'a str,
    statement: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct JUnclassified<'a> {
    universe: &'a str,
    member: &'a str,
    display: String,
}

#[derive(Serialize, Clone)]
struct JUniverse {
    id: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    members: Vec<JMember>,
}

/// A member serializes its fixed fields first; the per-universe
/// structured fields follow in name order through the flattened map.
#[derive(Serialize, Clone)]
struct JMember {
    id: String,
    class: &'static str,
    rules: Vec<String>,
    ordinal: u32,
    display: String,
    #[serde(flatten)]
    fields: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct JSignal<'a> {
    id: &'a str,
    signal: &'a str,
    state: &'static str,
}

#[derive(Serialize)]
struct JActiveCheck<'a> {
    id: &'a str,
    target: String,
    result: &'a str,
}

#[derive(Serialize)]
struct JCaveat<'a> {
    id: &'a str,
    text: &'a str,
}

/// Encodes one structured string field into the flattened member map:
/// `<name>` for clean UTF-8, `<name>_display` plus `<name>_bytes` hex
/// otherwise (KTD27).
fn put_text(map: &mut BTreeMap<String, Value>, name: &str, raw: &[u8]) {
    let e = encode_field(raw);
    match e.exact {
        Some(exact) => {
            map.insert(name.to_string(), Value::from(exact));
        }
        None => {
            map.insert(format!("{name}_display"), Value::from(e.display));
            map.insert(
                format!("{name}_bytes"),
                Value::from(e.bytes_hex.expect("encoded bytes")),
            );
        }
    }
}

fn member_fields(fields: &[MemberField]) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    for f in fields {
        match &f.value {
            MemberValue::Text(raw) => put_text(&mut map, &f.name, raw),
            MemberValue::Int(n) => {
                map.insert(f.name.clone(), Value::from(*n));
            }
            MemberValue::Bool(b) => {
                map.insert(f.name.clone(), Value::from(*b));
            }
        }
    }
    map
}

fn j_member(m: &Member) -> JMember {
    JMember {
        id: m.id.clone(),
        class: m.class.as_str(),
        rules: m.rules.clone(),
        ordinal: m.ordinal,
        display: escape(&m.display),
        fields: member_fields(&m.fields),
    }
}

fn j_universe(u: &Universe) -> JUniverse {
    JUniverse {
        id: u.id.clone(),
        state: u.state.as_str(),
        reason: u.state.reason().map(|r| r.as_str()),
        members: u.members.iter().map(j_member).collect(),
    }
}

fn attr_value(name: &str, v: &AttrValue, map: &mut BTreeMap<String, Value>) {
    match v {
        AttrValue::Str(s) => put_text(map, name, s.as_bytes()),
        AttrValue::Int(n) => {
            map.insert(name.to_string(), Value::from(*n));
        }
        AttrValue::Bool(b) => {
            map.insert(name.to_string(), Value::from(*b));
        }
        AttrValue::Strings(ss) => {
            let encoded: Vec<_> = ss.iter().map(|s| encode_field(s.as_bytes())).collect();
            if encoded.iter().all(|e| e.exact.is_some()) {
                map.insert(
                    name.to_string(),
                    Value::from(
                        encoded
                            .iter()
                            .map(|e| e.exact.clone().expect("exact"))
                            .collect::<Vec<_>>(),
                    ),
                );
            } else {
                map.insert(
                    format!("{name}_display"),
                    Value::from(
                        encoded
                            .iter()
                            .map(|e| e.display.clone())
                            .collect::<Vec<_>>(),
                    ),
                );
                map.insert(
                    format!("{name}_bytes"),
                    Value::from(
                        encoded
                            .iter()
                            .map(|e| e.bytes_hex.clone().expect("encoded bytes"))
                            .collect::<Vec<_>>(),
                    ),
                );
            }
        }
        AttrValue::Namespaces(ns) => {
            let list: Vec<Value> = ns
                .iter()
                .map(|n| {
                    let mut entry = serde_json::Map::new();
                    let e = encode_field(n.name.as_bytes());
                    match e.exact {
                        Some(name) => {
                            entry.insert("name".into(), Value::from(name));
                        }
                        None => {
                            entry.insert("name_display".into(), Value::from(e.display));
                            entry.insert(
                                "name_bytes".into(),
                                Value::from(e.bytes_hex.expect("encoded bytes")),
                            );
                        }
                    }
                    entry.insert("inode".into(), Value::from(n.inode));
                    Value::Object(entry)
                })
                .collect();
            map.insert(name.to_string(), Value::Array(list));
        }
    }
}

fn j_route(r: &Route) -> JRoute<'_> {
    let member = r.member.as_ref().map(|m| match &m.resolved {
        Some(id) => Value::from(id.clone()),
        None => Value::Null,
    });
    let (location, location_display, location_bytes) = match &r.location {
        None => (None, None, None),
        Some(raw) => {
            let e = encode_field(raw);
            match e.exact {
                Some(exact) => (Some(exact), None, None),
                None => (None, Some(e.display), e.bytes_hex),
            }
        }
    };
    JRoute {
        id: &r.id,
        kind: &r.kind,
        rule: r.rule.as_deref(),
        signal: r.signal.as_deref(),
        member,
        location,
        location_display,
        location_bytes,
        verified: r.verified,
        display: escape(&r.display),
    }
}

fn j_report<'a>(r: &'a Report, universes: Vec<JUniverse>) -> JReport<'a> {
    JReport {
        schema_version: r.schema_version,
        kind: KIND,
        tool: JTool {
            name: &r.tool.name,
            version: &r.tool.version,
            data_digest: &r.tool.data_digest,
        },
        source: r.source.as_str(),
        platform: r.platform.as_str(),
        layer_order_basis: LAYER_ORDER_BASIS,
        privilege: JPrivilege {
            euid: r.privilege.euid,
            egid: r.privilege.egid,
            root: r.privilege.root(),
        },
        mode: r.mode.as_str(),
        nonce: r.nonce.as_deref(),
        completeness: JCompleteness {
            state: r.completeness.as_str(),
        },
        layers: r
            .layers
            .iter()
            .map(|l| {
                let mut attributes = BTreeMap::new();
                for (name, v) in &l.attributes {
                    attr_value(name, v, &mut attributes);
                }
                JLayer {
                    id: &l.id,
                    family: l.family.as_str(),
                    kind: &l.kind,
                    evidence: l
                        .evidence
                        .iter()
                        .map(|e| JEvidence {
                            class: e.class.as_str(),
                            detail: escape(&e.detail),
                        })
                        .collect(),
                    attributes,
                }
            })
            .collect(),
        egress_routes: r.egress_routes.iter().map(j_route).collect(),
        escape_routes: r.escape_routes.iter().map(j_route).collect(),
        unknowns: r
            .unknowns
            .iter()
            .map(|u| JUnknown {
                id: &u.id,
                source: &u.source,
                reason: u.reason.as_str(),
            })
            .collect(),
        tamper_indicators: r
            .tamper_indicators
            .iter()
            .map(|t| JTamper {
                id: &t.id,
                indicator: &t.indicator,
                strength: t.strength.as_str(),
                display: escape(&t.display),
            })
            .collect(),
        not_observable: r
            .not_observable
            .iter()
            .map(|n| JNotObservable {
                id: &n.id,
                statement: &n.statement,
                reason: &n.reason,
            })
            .collect(),
        not_applicable: r.not_applicable.iter().map(String::as_str).collect(),
        unclassified: r
            .unclassified
            .iter()
            .map(|u| JUnclassified {
                universe: &u.universe,
                member: &u.member,
                display: escape(&u.display),
            })
            .collect(),
        universes,
        signals: r
            .signals
            .iter()
            .map(|s| JSignal {
                id: &s.id,
                signal: &s.signal,
                state: s.state.as_str(),
            })
            .collect(),
        active_checks: r
            .active_checks
            .iter()
            .map(|c| JActiveCheck {
                id: &c.id,
                target: escape(&c.target),
                result: &c.result,
            })
            .collect(),
        caveats: r
            .caveats
            .iter()
            .map(|c| JCaveat {
                id: &c.id,
                text: &c.text,
            })
            .collect(),
    }
}

fn render(r: &Report, universes: Vec<JUniverse>, unclassified: &[Unclassified]) -> String {
    // Serializing plain structs of strings, integers, and booleans cannot
    // fail.
    let mut rr = r.clone();
    rr.unclassified = unclassified.to_vec();
    serde_json::to_string_pretty(&j_report(&rr, universes)).expect("report serializes")
}

/// Serializes `report` after [`finalize`] on a copy, charging the KTD18
/// rendered-report budget. Pretty-printed with two-space indentation and
/// ending with one newline.
pub fn to_json(report: &Report) -> String {
    to_json_bounded(report, REPORT_BUDGET_BYTES)
}

/// [`to_json`] with an explicit report byte cap. A universe whose
/// rendered members would push the total past `budget` is replaced by an
/// unknown `budget-exceeded`; charging continues in declared order, so a
/// later universe that still fits still renders (KTD18).
pub fn to_json_bounded(report: &Report, budget: u64) -> String {
    let mut r = report.clone();
    finalize(&mut r);
    let all: Vec<JUniverse> = r.universes.iter().map(j_universe).collect();
    let full = render(&r, all.clone(), &r.unclassified);
    let mut out = if (full.len() as u64) <= budget {
        full
    } else {
        // The fixed cost: the whole report with every member list empty
        // and no unclassified entries.
        let emptied: Vec<JUniverse> = all
            .iter()
            .map(|u| JUniverse {
                members: Vec::new(),
                ..u.clone()
            })
            .collect();
        let overhead = render(&r, emptied.clone(), &[]).len() as u64;
        let mut charged = 0u64;
        let mut keep = vec![true; all.len()];
        for (i, u) in all.iter().enumerate() {
            if u.members.is_empty() {
                continue;
            }
            // The universe's exact contribution: the report with only
            // this universe's members and unclassified entries kept,
            // minus the overhead.
            let mut solo = emptied.clone();
            solo[i] = u.clone();
            let uncl: Vec<Unclassified> = r
                .unclassified
                .iter()
                .filter(|x| x.universe == u.id)
                .cloned()
                .collect();
            let size = (render(&r, solo, &uncl).len() as u64).saturating_sub(overhead);
            if overhead + charged + size > budget {
                keep[i] = false;
            } else {
                charged += size;
            }
        }
        apply_budget_replacements(&mut r, &keep);
        render(
            &r,
            r.universes.iter().map(j_universe).collect(),
            &r.unclassified,
        )
    };
    // Backstop: an added unknown entry could still push the total over.
    // Replace the next membered universe in declared order until the
    // output fits; the loop ends when no members remain.
    while out.len() as u64 > budget {
        let Some(pos) = r.universes.iter().position(|u| !u.members.is_empty()) else {
            break;
        };
        let mut keep = vec![true; r.universes.len()];
        keep[pos] = false;
        apply_budget_replacements(&mut r, &keep);
        out = render(
            &r,
            r.universes.iter().map(j_universe).collect(),
            &r.unclassified,
        );
    }
    out.push('\n');
    out
}

/// Replaces the members of every universe whose `keep` slot is false
/// with an unknown `budget-exceeded`, records the unknowns, and marks
/// the run incomplete (KTD18).
fn apply_budget_replacements(r: &mut Report, keep: &[bool]) {
    let mut replaced = false;
    for (u, keep) in r.universes.iter_mut().zip(keep.iter()) {
        if *keep || u.members.is_empty() {
            continue;
        }
        u.state = UniverseState::Unknown(UnknownReason::BudgetExceeded);
        u.members.clear();
        if !r
            .unknowns
            .iter()
            .any(|k| k.source == u.id && k.reason == UnknownReason::BudgetExceeded)
        {
            r.unknowns.push(Unknown {
                id: String::new(),
                source: u.id.clone(),
                reason: UnknownReason::BudgetExceeded,
            });
        }
        replaced = true;
    }
    if !replaced {
        return;
    }
    for u in &mut r.unknowns {
        if u.id.is_empty() {
            u.id = unknown_id(&u.source, u.reason);
        }
    }
    r.unknowns
        .sort_by(|a, b| (&a.source, a.reason).cmp(&(&b.source, b.reason)));
    // Unclassified entries for dropped members disappear with them.
    let live: BTreeSet<&str> = r
        .universes
        .iter()
        .flat_map(|u| u.members.iter().map(|m| m.id.as_str()))
        .collect();
    r.unclassified.retain(|u| live.contains(u.member.as_str()));
    // An unknown exists, so the run is incomplete (R13).
    if r.completeness != CompletenessState::Incomplete {
        r.completeness = CompletenessState::Incomplete;
    }
}

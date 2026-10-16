//! Member classification (KTD6): every enumerated member is matched
//! against the rules of its universe; a member matched by rules of more
//! than one class takes the highest class (escape over egress over
//! inert) and records every matching rule id. Escape and egress matches
//! produce one route per matching rule; inert matches are listed on the
//! member; no match leaves the member unclassified.

use crate::data::{Data, Predicate, Rule, RuleClass};
use crate::model::{Member, MemberClass, MemberRef, MemberValue, Route, Universe};
use std::collections::BTreeMap;

/// The canonical string bytes of a member field value for predicate
/// tests.
fn field_bytes(v: &MemberValue) -> Vec<u8> {
    v.key_bytes()
}

fn field_bool(v: &MemberValue) -> Option<bool> {
    match v {
        MemberValue::Bool(b) => Some(*b),
        _ => None,
    }
}

fn member_field<'m>(m: &'m Member, name: &str) -> Option<&'m MemberValue> {
    m.fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

/// Substitutes `<euid>` inside a declared predicate value.
fn subst(value: &str, euid: Option<u32>) -> String {
    match euid {
        Some(e) => value.replace("<euid>", &e.to_string()),
        None => value.to_string(),
    }
}

fn component_boundary_under(value: &[u8], prefix: &str) -> bool {
    // `under` is equal to or below on a component boundary; rules that
    // must not fire at the bare point carry an `except` clause.
    let p = prefix.as_bytes();
    value == p
        || (p.ends_with(b"/") && value.starts_with(p))
        || (value.len() > p.len() && value.starts_with(p) && value[p.len()] == b'/')
}

/// Cross-universe member path table for `member-of` tests: universe id
/// to the `path` field bytes (or display string) of its members.
fn member_paths(universes: &[Universe]) -> BTreeMap<String, Vec<Vec<u8>>> {
    let mut out: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    for u in universes {
        for m in &u.members {
            let paths = out.entry(u.id.clone()).or_default();
            if let Some(MemberValue::Text(p)) = member_field(m, "path") {
                paths.push(p.clone());
            } else {
                paths.push(m.display.clone().into_bytes());
            }
        }
    }
    out
}

fn predicate_holds(
    m: &Member,
    field: &str,
    p: &Predicate,
    euid: Option<u32>,
    member_paths: &BTreeMap<String, Vec<Vec<u8>>>,
) -> bool {
    let Some(v) = member_field(m, field) else {
        // A field absent from the member never matches, including the
        // negative tests: the clause requires the field.
        return false;
    };
    if let Some(want) = p.flag {
        return field_bool(v) == Some(want);
    }
    let bytes = field_bytes(v);
    let mut positives = false;
    let mut any_positive = false;
    let mut hit = |cond: bool| {
        positives = true;
        any_positive |= cond;
    };
    if let Some(eq) = &p.equals {
        hit(bytes == subst(eq, euid).as_bytes());
    }
    for needle in &p.in_ {
        hit(bytes == subst(needle, euid).as_bytes());
    }
    for needle in &p.prefix {
        hit(bytes.starts_with(subst(needle, euid).as_bytes()));
    }
    for needle in &p.suffix {
        hit(bytes.ends_with(subst(needle, euid).as_bytes()));
    }
    for needle in &p.under {
        hit(component_boundary_under(&bytes, &subst(needle, euid)));
    }
    for needle in &p.basename_in {
        hit(egress_core::paths::file_name(&bytes) == subst(needle, euid).as_bytes());
    }
    if let Some(univ) = &p.member_of {
        let table = member_paths.get(univ).cloned().unwrap_or_default();
        hit(table.contains(&bytes));
    }
    for needle in &p.device {
        hit(bytes == needle.as_bytes());
    }
    for needle in &p.not_in {
        if bytes == subst(needle, euid).as_bytes() {
            return false;
        }
    }
    for needle in &p.not_prefix {
        if bytes.starts_with(subst(needle, euid).as_bytes()) {
            return false;
        }
    }
    !positives || any_positive
}

fn clause_holds(
    m: &Member,
    clause: &crate::data::MatchClause,
    euid: Option<u32>,
    member_paths: &BTreeMap<String, Vec<Vec<u8>>>,
) -> bool {
    clause
        .iter()
        .all(|(field, p)| predicate_holds(m, field, p, euid, member_paths))
}

fn rule_matches(
    m: &Member,
    rule: &Rule,
    euid: Option<u32>,
    member_paths: &BTreeMap<String, Vec<Vec<u8>>>,
) -> bool {
    if rule
        .except
        .as_ref()
        .is_some_and(|c| clause_holds(m, c, euid, member_paths))
    {
        return false;
    }
    rule.clauses
        .iter()
        .any(|c| clause_holds(m, c, euid, member_paths))
}

fn route_kind(rule: &Rule, m: &Member) -> String {
    if let Some(dk) = &rule.default_route_kind
        && let Some(v) = member_field(m, "destination-prefix")
        && let MemberValue::Text(b) = v
    {
        // The default-route kind applies when the destination prefix
        // length is zero (the field ends in `/0`).
        if b.rsplit(|c| *c == b'/').next() == Some(b"0") {
            return dk.clone();
        }
    }
    rule.kind.clone().unwrap_or_default()
}

/// Runs every rule over every member and produces the route list.
/// Returns `(egress_routes, escape_routes)`; member classes and rule ids
/// are recorded on the members themselves.
pub fn classify(
    universes: &mut [Universe],
    data: &Data,
    euid: Option<u32>,
) -> (Vec<Route>, Vec<Route>) {
    let member_paths = member_paths(universes);
    let mut egress = Vec::new();
    let mut escape = Vec::new();
    for u in universes.iter_mut() {
        let rules: Vec<&Rule> = data
            .rules
            .iter()
            .filter(|r| r.universes.contains(&u.id))
            .collect();
        for m in &mut u.members {
            let mut class: Option<RuleClass> = None;
            let mut matched: Vec<&Rule> = Vec::new();
            for r in &rules {
                if rule_matches(m, r, euid, &member_paths) {
                    m.rules.push(r.id.clone());
                    matched.push(r);
                    class = Some(match (class, r.class) {
                        (Some(RuleClass::Escape), _) | (_, RuleClass::Escape) => RuleClass::Escape,
                        (Some(RuleClass::Egress), _) | (_, RuleClass::Egress) => RuleClass::Egress,
                        _ => RuleClass::Inert,
                    });
                }
            }
            m.class = match class {
                Some(RuleClass::Escape) => MemberClass::Escape,
                Some(RuleClass::Egress) => MemberClass::Egress,
                Some(RuleClass::Inert) => MemberClass::Inert,
                None => MemberClass::Unclassified,
            };
            for r in matched {
                if r.class == RuleClass::Inert {
                    continue;
                }
                let route = Route {
                    id: String::new(),
                    kind: route_kind(r, m),
                    rule: Some(r.id.clone()),
                    signal: None,
                    member: Some(MemberRef::of(&u.id, m)),
                    location: None,
                    verified: false,
                    display: m.display.clone(),
                };
                match r.class {
                    RuleClass::Egress => egress.push(route),
                    _ => escape.push(route),
                }
            }
        }
    }
    (egress, escape)
}

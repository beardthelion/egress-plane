//! Probe identity, the KTD27 string encoder, KTD14 redaction, and the
//! final ordering.
//!
//! Keys start with the version tag `egress-plane/probe-identity/v1` and
//! join length-prefixed components through
//! [`egress_core::identity::key_with_version`], so probe ids can never
//! collide with code-layer ids (KTD5, KTD10). Only stable fields enter a
//! key: ports, pids, descriptor numbers, inodes, device numbers, mount
//! ids, and counters are display-only. Identical siblings separate by an
//! ordinal assigned in sorted display order.

use std::collections::BTreeMap;

use egress_core::escape::{escape, needs_escape};
use egress_core::identity::{encode_path_bytes, hash_id, key_with_version};
use egress_core::redact::{REDACTED, redact, rules};

use crate::model::*;

/// The probe key version tag (KTD5).
const KEY_VERSION: &[u8] = b"egress-plane/probe-identity/v1";

fn key(kind: &[u8], components: &[Vec<u8>]) -> Vec<u8> {
    let mut all = Vec::with_capacity(components.len() + 1);
    all.push(kind.to_vec());
    all.extend(components.iter().cloned());
    key_with_version(KEY_VERSION, &all)
}

/// The member id for `components` in `universe` at `ordinal`.
pub fn member_id(universe: &str, components: &[Vec<u8>], ordinal: u32) -> String {
    let mut c = vec![universe.as_bytes().to_vec()];
    c.extend(components.iter().cloned());
    c.push(ordinal.to_string().into_bytes());
    hash_id(&key(b"member", &c))
}

/// The route id for its class, kind, origin, and subject.
pub fn route_id(class: MemberClass, kind: &str, origin: &[u8], subject: &[Vec<u8>]) -> String {
    let mut c = vec![
        class.as_str().as_bytes().to_vec(),
        kind.as_bytes().to_vec(),
        origin.to_vec(),
    ];
    c.extend(subject.iter().cloned());
    hash_id(&key(b"route", &c))
}

/// The unknown id for one `(source, reason)` pair.
pub fn unknown_id(source: &str, reason: UnknownReason) -> String {
    hash_id(&key(
        b"unknown",
        &[
            source.as_bytes().to_vec(),
            reason.as_str().as_bytes().to_vec(),
        ],
    ))
}

/// The tamper-indicator id for one `(indicator, strength)` pair.
pub fn tamper_id(indicator: &str, strength: TamperStrength) -> String {
    hash_id(&key(
        b"tamper",
        &[
            indicator.as_bytes().to_vec(),
            strength.as_str().as_bytes().to_vec(),
        ],
    ))
}

/// The layer id for one `(family, kind)` pair.
pub fn layer_id(family: LayerFamily, kind: &str) -> String {
    hash_id(&key(
        b"layer",
        &[
            family.as_str().as_bytes().to_vec(),
            kind.as_bytes().to_vec(),
        ],
    ))
}

/// The signal id for one declared signal id.
pub fn signal_id(signal: &str) -> String {
    hash_id(&key(b"signal", &[signal.as_bytes().to_vec()]))
}

/// The active-check id for one target.
pub fn active_check_id(target: &str) -> String {
    hash_id(&key(b"active-check", &[target.as_bytes().to_vec()]))
}

// ---------------------------------------------------------------------------
// The KTD27 encoder: a structured string field is emitted exactly only
// when it is UTF-8 and free of escapable characters.
// ---------------------------------------------------------------------------

/// A structured string field after the KTD27 check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedField {
    /// The exact UTF-8 text; `None` when the bytes are not UTF-8 or hold a
    /// character [`needs_escape`] reports (C0, DEL, C1, bidi and other
    /// format controls, line and paragraph separators).
    pub exact: Option<String>,
    /// The escaped display form, always present.
    pub display: String,
    /// Lowercase hex of the raw bytes; `Some` exactly when `exact` is
    /// `None`.
    pub bytes_hex: Option<String>,
}

/// Applies the KTD27 rule to raw field bytes: clean UTF-8 keeps the exact
/// field; anything else emits only the escaped `display` and the
/// `*_bytes` hex. Identity still hashes the raw bytes.
pub fn encode_field(raw: &[u8]) -> EncodedField {
    if let Ok(text) = std::str::from_utf8(raw)
        && !text.chars().any(needs_escape)
    {
        return EncodedField {
            exact: Some(text.to_string()),
            display: text.to_string(),
            bytes_hex: None,
        };
    }
    // The display keeps valid-UTF-8 chunks, escapes escapable characters
    // inside them, and renders invalid bytes as `\x{hh}`; this extends
    // `encode_path_bytes` from non-UTF-8 to control-bearing text.
    let encoded = encode_path_bytes(raw);
    EncodedField {
        exact: None,
        display: escape(&encoded.display),
        bytes_hex: Some(match encoded.bytes_hex {
            Some(h) => h,
            None => egress_core::identity::hex(raw),
        }),
    }
}

// ---------------------------------------------------------------------------
// KTD14 redaction on raw bytes.
// ---------------------------------------------------------------------------

/// Redacts recognized credentials in raw field bytes. UTF-8 text goes
/// through [`redact`]; other bytes get the same token-prefix rule at byte
/// level (the prefixes and their run alphabet are ASCII, so they cannot
/// hide inside a multi-byte sequence). Redaction runs before identity, so
/// a secret never enters a hash.
pub fn redact_bytes(raw: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(raw) {
        Ok(text) => redact(text).into_bytes(),
        Err(_) => redact_token_prefixes(raw),
    }
}

/// The byte-level token-prefix pass for non-UTF-8 fields: a listed prefix
/// at a token boundary starts a run of `[A-Za-z0-9_.-]` that becomes
/// [`REDACTED`].
fn redact_token_prefixes(raw: &[u8]) -> Vec<u8> {
    let prefixes = &rules().token_prefixes;
    let run = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.');
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let boundary = i == 0 || !raw[i - 1].is_ascii_alphanumeric();
        let hit = if boundary {
            prefixes.iter().find(|p| raw[i..].starts_with(p.as_bytes()))
        } else {
            None
        };
        if let Some(p) = hit {
            let mut end = i + p.len();
            while end < raw.len() && run(raw[end]) {
                end += 1;
            }
            if end > i + p.len() {
                out.extend_from_slice(REDACTED.as_bytes());
                i = end;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Finalize: redact, ids, ordinals, sort, derive sections.
// ---------------------------------------------------------------------------

fn redact_text_value(v: &mut MemberValue) {
    if let MemberValue::Text(b) = v {
        *b = redact_bytes(b);
    }
}

fn redact_attr(v: &mut AttrValue) {
    match v {
        AttrValue::Str(s) => *s = redact(s),
        AttrValue::Strings(ss) => {
            for s in ss {
                *s = redact(s);
            }
        }
        AttrValue::Namespaces(ns) => {
            for n in ns {
                n.name = redact(&n.name);
            }
        }
        AttrValue::Int(_) | AttrValue::Bool(_) => {}
    }
}

/// Applies KTD14 redaction to every environment-derived string in the
/// report, before identity. Data-declared text (caveats, not-observable
/// statements, declared ids) is not environment-derived and passes
/// through unchanged.
fn redact_report(r: &mut Report) {
    for u in &mut r.universes {
        for m in &mut u.members {
            for f in &mut m.fields {
                redact_text_value(&mut f.value);
            }
            m.display = redact(&m.display);
        }
    }
    for route in r.egress_routes.iter_mut().chain(r.escape_routes.iter_mut()) {
        route.display = redact(&route.display);
        if let Some(loc) = &mut route.location {
            *loc = redact_bytes(loc);
        }
        if let Some(m) = &mut route.member {
            for c in &mut m.components {
                *c = redact_bytes(c);
            }
        }
    }
    for t in &mut r.tamper_indicators {
        t.display = redact(&t.display);
    }
    for l in &mut r.layers {
        for e in &mut l.evidence {
            e.detail = redact(&e.detail);
        }
        for v in l.attributes.values_mut() {
            redact_attr(v);
        }
    }
    for c in &mut r.active_checks {
        c.target = redact(&c.target);
    }
}

/// A member's sort key: identity components, then the display-order key
/// for identical siblings.
type MemberSortKey = (Vec<Vec<u8>>, Vec<(u8, Vec<u8>)>);

fn member_sort_key(m: &Member) -> MemberSortKey {
    (m.identity_components(), m.display_order_key())
}

fn route_sort_key(r: &Route) -> Vec<Vec<u8>> {
    let mut c = vec![
        r.kind.as_bytes().to_vec(),
        r.rule
            .as_deref()
            .or(r.signal.as_deref())
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
    ];
    match &r.member {
        Some(m) => {
            c.push(m.universe.as_bytes().to_vec());
            c.extend(m.components.iter().cloned());
        }
        None => c.push(r.location.clone().unwrap_or_default()),
    }
    c.push(r.display.as_bytes().to_vec());
    c
}

fn route_origin(r: &Route) -> Vec<u8> {
    match (&r.rule, &r.signal) {
        (Some(rule), _) => [b"rule:".as_slice(), rule.as_bytes()].concat(),
        (None, Some(signal)) => [b"signal:".as_slice(), signal.as_bytes()].concat(),
        (None, None) => Vec::new(),
    }
}

fn route_subject(r: &Route) -> Vec<Vec<u8>> {
    match &r.member {
        Some(m) => {
            let mut c = vec![m.universe.as_bytes().to_vec()];
            c.extend(m.components.iter().cloned());
            c
        }
        None => vec![r.location.clone().unwrap_or_default()],
    }
}

/// Sorts and ids the routes of one class.
fn finalize_routes(routes: &mut [Route], class: MemberClass) {
    for r in routes.iter_mut() {
        r.id = route_id(class, &r.kind, &route_origin(r), &route_subject(r));
    }
    routes.sort_by_cached_key(route_sort_key);
}

/// Assigns member ordinals and ids, binds route member references, sorts
/// every collection, derives the unclassified and not-applicable
/// sections, and ensures the fixed caveats. Idempotent.
///
/// Redaction (KTD14) runs before any id is computed, so no hash carries a
/// recognized secret. Display-only fields never enter identity (KTD5).
pub fn finalize(r: &mut Report) {
    redact_report(r);

    // Members: sort by identity components, identical siblings by sorted
    // display order, then ordinals and ids.
    type BindingKey = (String, Vec<Vec<u8>>, Vec<u8>);
    let mut member_ids: BTreeMap<(String, Vec<Vec<u8>>), String> = BTreeMap::new();
    let mut order_keyed: BTreeMap<BindingKey, String> = BTreeMap::new();
    for u in &mut r.universes {
        for m in &mut u.members {
            m.rules.sort();
            m.rules.dedup();
        }
        u.members.sort_by_cached_key(member_sort_key);
        let mut counters: BTreeMap<Vec<Vec<u8>>, u32> = BTreeMap::new();
        for m in &mut u.members {
            let components = m.identity_components();
            let ordinal = counters.entry(components.clone()).or_default();
            m.ordinal = *ordinal;
            *ordinal += 1;
            m.id = member_id(&u.id, &components, m.ordinal);
            member_ids
                .entry((u.id.clone(), components))
                .or_insert_with(|| m.id.clone());
            let mut ok = Vec::new();
            for (w, b) in m.display_order_key() {
                ok.push(w);
                ok.extend_from_slice(&b);
                ok.push(0);
            }
            order_keyed.insert((u.id.clone(), m.identity_components(), ok), m.id.clone());
        }
    }

    // Bind route member references to the assigned member ids. Identical
    // siblings resolve to the first in sorted order.
    for route in r.egress_routes.iter_mut().chain(r.escape_routes.iter_mut()) {
        if let Some(m) = &mut route.member {
            m.resolved = order_keyed
                .get(&(
                    m.universe.clone(),
                    m.components.clone(),
                    m.order_key.clone(),
                ))
                .cloned()
                .or_else(|| {
                    member_ids
                        .get(&(m.universe.clone(), m.components.clone()))
                        .cloned()
                });
        }
    }

    finalize_routes(&mut r.egress_routes, MemberClass::Egress);
    finalize_routes(&mut r.escape_routes, MemberClass::Escape);

    for u in &mut r.unknowns {
        u.id = unknown_id(&u.source, u.reason);
    }
    r.unknowns
        .sort_by(|a, b| (&a.source, a.reason).cmp(&(&b.source, b.reason)));

    for t in &mut r.tamper_indicators {
        t.id = tamper_id(&t.indicator, t.strength);
    }
    r.tamper_indicators
        .sort_by(|a, b| (&a.indicator, a.strength).cmp(&(&b.indicator, b.strength)));

    for l in &mut r.layers {
        l.id = layer_id(l.family, &l.kind);
        l.evidence
            .sort_by(|a, b| (a.class, &a.detail).cmp(&(b.class, &b.detail)));
    }
    // Family rank orders layers; within a family the detection order
    // (declaration order) is kept, so sort stably by family only.
    r.layers.sort_by_key(|l| l.family);

    for s in &mut r.signals {
        s.id = signal_id(&s.signal);
    }
    r.signals.sort_by(|a, b| a.signal.cmp(&b.signal));

    for c in &mut r.active_checks {
        c.id = active_check_id(&c.target);
    }
    r.active_checks
        .sort_by(|a, b| (&a.target, &a.result).cmp(&(&b.target, &b.result)));

    r.not_observable.sort_by(|a, b| a.id.cmp(&b.id));

    // Unclassified members get their own section (R14), derived in
    // declared universe order and member order.
    r.unclassified = r
        .universes
        .iter()
        .flat_map(|u| {
            u.members
                .iter()
                .filter(|m| m.class == MemberClass::Unclassified)
                .map(move |m| Unclassified {
                    universe: u.id.clone(),
                    member: m.id.clone(),
                    display: m.display.clone(),
                })
        })
        .collect();

    // The `not_applicable` list is exactly the declared R24 set: the
    // universes and attribute sources the other platform declares.
    // Off-platform universes and signals still show `not-applicable` in
    // their own rosters but do not join this list (the declared set is
    // the complete answer, per the R24 corpus expectations).
    r.not_applicable.sort();
    r.not_applicable.dedup();

    // The fixed caveats (KTD23, KTD15).
    let ensure = |caveats: &mut Vec<Caveat>, id: &str, text: &str| {
        if !caveats.iter().any(|c| c.id == id) {
            caveats.push(Caveat {
                id: id.to_string(),
                text: text.to_string(),
            });
        }
    };
    ensure(
        &mut r.caveats,
        SELF_REPORTED_CAVEAT,
        "This report describes the probe's own context as that context \
         presents itself; it is authentic only when the launch is trusted.",
    );
    if r.platform == crate::facts::Platform::Linux {
        ensure(
            &mut r.caveats,
            HOME_CAVEAT,
            "Home-relative credential checks resolve the home directory \
             from the account database, never from HOME.",
        );
    }
    r.caveats.sort_by(|a, b| a.id.cmp(&b.id));
}

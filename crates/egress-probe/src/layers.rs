//! Layer detection (KTD16, KTD29): each declared layer kind fires when
//! every `all` condition holds or any `any` condition holds; layers are
//! ordered by the fixed family rank; `no-other-in-family` kinds are the
//! fallbacks that yield to a more specific kind of the same family.

use crate::data::Data;
use crate::model::{Evidence, EvidenceClass, Layer, LayerFamily};
use crate::signals::{Ctx, condition_holds};

/// Evaluates every declared layer for this platform. Returns the
/// detected layers ordered by family rank (outermost first), or one
/// synthesized `host/unrecognized` layer when nothing fires.
pub fn detect(data: &Data, ctx: &Ctx<'_>) -> Vec<Layer> {
    let mut detected: Vec<(u32, Layer)> = Vec::new();
    for l in &data.layers {
        let all_hold = !l.all.is_empty() && l.all.iter().all(|c| condition_holds(c, ctx));
        let any_hit = l.any.iter().any(|c| condition_holds(c, ctx));
        if !(all_hold || any_hit) {
            continue;
        }
        let Some(family) = LayerFamily::parse(&l.family) else {
            continue;
        };
        let mut evidence = Vec::new();
        let mut add = |c: &crate::data::Condition| {
            if !condition_holds(c, ctx) {
                return;
            }
            if let Some(e) = &c.evidence
                && let Some(class) = EvidenceClass::parse(e)
            {
                evidence.push(Evidence {
                    class,
                    detail: l.kind.clone(),
                });
            }
        };
        for c in &l.any {
            add(c);
        }
        if all_hold {
            for c in &l.all {
                add(c);
            }
        }
        detected.push((
            l.rank,
            Layer {
                id: String::new(),
                family,
                kind: l.kind.clone(),
                evidence,
                attributes: Default::default(),
            },
        ));
    }

    // no-other-in-family kinds drop out when a sibling kind of the same
    // family was detected (generic-ci, oci-generic, seccomp-filter).
    let declared: Vec<&crate::data::Layer> = data
        .layers
        .iter()
        .filter(|l| l.no_other_in_family)
        .collect();
    let non_fallback: std::collections::BTreeSet<(LayerFamily, String)> = detected
        .iter()
        .filter(|(_, l)| {
            !declared
                .iter()
                .any(|d| d.family == l.family.as_str() && d.kind == l.kind)
        })
        .map(|(_, l)| (l.family, l.kind.clone()))
        .collect();
    detected.retain(|(_, l)| {
        let is_fallback = declared
            .iter()
            .any(|d| d.family == l.family.as_str() && d.kind == l.kind);
        !is_fallback
            || !non_fallback
                .iter()
                .any(|(f, k)| *f == l.family && k != &l.kind)
    });

    if detected.is_empty() {
        return vec![Layer {
            id: String::new(),
            family: LayerFamily::Host,
            kind: "unrecognized".to_string(),
            evidence: Vec::new(),
            attributes: Default::default(),
        }];
    }
    detected.sort_by_key(|(rank, _)| *rank);
    detected.into_iter().map(|(_, l)| l).collect()
}

//! The derived-site pass (R10-R14, KTD7-KTD10).
//!
//! A `param:N:<function>` destination means the value leaving the process
//! is whatever the wrapper's callers pass as argument `N`. For every
//! in-tree call whose callee resolved to the wrapper's `FirstPartyDef`
//! during classification, this pass maps the caller's argument back onto
//! that parameter and reports a derived site: the inner site's mechanism
//! at the caller's location, with the caller's concrete or symbolic
//! destination and a `via` chain back to the inner site. A caller that
//! forwards its own parameter becomes a wrapper for the next hop, so a
//! chain of wrappers reports one derived site per concrete caller.
//!
//! Ordering and budget rules come from KTD7 and KTD8. The pass runs in
//! byte-wise file order and source order on the shared resolver budget;
//! every followed hop charges one step, and a budget cut leaves
//! `resolution-limit` blind spots and an incomplete account. A
//! `(file, function, parameter)` already on the chain ends the hop with
//! `cut = "recursion"`; reaching `data/wrappers.toml`'s `hop_limit` ends
//! it with `cut = "hop-limit"`, and neither cut is itself a coverage gap.
//! `functools.partial`, `.bind`, and wrappers passed as values never
//! resolve to a `FirstPartyDef` call, so they produce no derived sites.

use std::collections::{BTreeMap, BTreeSet};

use crate::classify::{Ctx, State, Val, labels_at, render, to_dest};
use crate::destination;
use crate::identity::{finalize_direct_sites, raw_path};
use crate::ir::{Expr, Reference, SymbolSpan};
use crate::model::{BlindSpotKind, DerivedCut, Destination, Site, Via, ViaHop};
use crate::resolve::Limit;

/// A call whose callee resolved to a first-party definition, recorded
/// during classification for the derived-site pass (KTD7).
#[derive(Debug)]
pub(crate) struct CallEdge {
    /// Raw path bytes of the caller's file.
    pub(crate) file: Vec<u8>,
    /// The definition the callee resolved to.
    pub(crate) def_path: Vec<u8>,
    pub(crate) def_name: String,
    /// The call itself.
    pub(crate) rf: Reference,
}

/// One wrapper hop the walk is following: a caller of (`file`, `symbol`)
/// feeding argument `param` reaches `inner`.
struct Active {
    file: Vec<u8>,
    symbol: String,
    param: u32,
    /// Index of the inner `param:` site in `out.sites`.
    inner: usize,
    /// The `via` chain a caller's derived site carries: the caller's
    /// callee first, the innermost wrapper last.
    chain: Vec<ViaHop>,
    /// `(file, function, parameter)` keys already on the chain, for the
    /// recursion cut (KTD8).
    keys: BTreeSet<(Vec<u8>, String, u32)>,
}

/// The dedup key: a caller gets at most one derived site per (inner site,
/// argument index) (KTD7).
type Dedup = BTreeMap<(Vec<u8>, String, usize, u32), (usize, Vec<ViaHop>)>;

/// Runs the derived-site pass over the classification state. Call it once
/// every file is classified and before `finish`, so the pass shares the
/// resolver budget and its charges land in `resolver_steps`.
pub(crate) fn run(st: &mut State<'_, '_>) {
    // Phase-1 finalize keys the direct sites first, so `via.inner_site`
    // names a stable phase-1 id (KTD9).
    finalize_direct_sites(&mut st.out.sites);
    let hop_limit = st.data.wrappers.hop_limit;

    // Every `param:N:<function>` site names a wrapper: its file and
    // function, the parameter index, and the inner site derived sites
    // point at.
    let mut level: Vec<Active> = Vec::new();
    for (i, s) in st.out.sites.iter().enumerate() {
        let Some((param, _)) = crate::destination::param_parts(&s.destination) else {
            continue;
        };
        let file = raw_path(&s.file, s.file_bytes.as_deref());
        level.push(Active {
            file: file.clone(),
            symbol: s.symbol.clone(),
            param,
            inner: i,
            chain: vec![ViaHop {
                file: s.file.clone(),
                symbol: s.symbol.clone(),
            }],
            keys: BTreeSet::from([(file, s.symbol.clone(), param)]),
        });
    }
    if level.is_empty() || st.derived_calls.is_empty() {
        return;
    }

    let edges = std::mem::take(&mut st.derived_calls);
    // Call edges keyed by the definition they call, so a hop visits only
    // its own callers.
    let mut callers_of: BTreeMap<(&[u8], &str), Vec<&CallEdge>> = BTreeMap::new();
    for e in &edges {
        callers_of
            .entry((&e.def_path, e.def_name.as_str()))
            .or_default()
            .push(e);
    }
    let mut emitted: Dedup = BTreeMap::new();
    // Hop keys already reached: (inner, file, function, param). A key
    // reached once is never activated again; the recursion cut handles
    // returns to a key already on one chain.
    let mut reached: BTreeSet<(usize, Vec<u8>, String, u32)> = level
        .iter()
        .map(|a| (a.inner, a.file.clone(), a.symbol.clone(), a.param))
        .collect();

    while !level.is_empty() {
        // The next level: the best chain seen for each hop key, so a
        // diamond keeps the byte-wise smallest `(file, symbol)` sequence
        // (KTD7).
        let mut next: BTreeMap<(usize, Vec<u8>, String, u32), Active> = BTreeMap::new();
        for active in &level {
            let Some(callers) = callers_of.get(&(active.file.as_slice(), active.symbol.as_str()))
            else {
                continue;
            };
            for edge in callers {
                // A followed hop charges the shared resolver budget; a
                // cut is a `resolution-limit` blind spot and an
                // incomplete account (KTD7).
                st.r.begin_reference();
                if let Err(Limit) = st.r.step() {
                    if let Some(cx) = st.ctx(&edge.file) {
                        st.blind_at(
                            cx,
                            &edge.rf.symbol,
                            edge.rf.location,
                            BlindSpotKind::ResolutionLimit,
                            &edge.rf.text,
                            false,
                        );
                    }
                    continue;
                }
                let Some(cx) = st.ctx(&edge.file) else {
                    continue;
                };
                let dest = argument_destination(st, active, edge);
                // Only a `param:` destination naming the caller's own
                // function forwards the caller's parameter; the omitted-
                // argument fallback names the wrapper and stays a
                // derived destination (KTD7).
                let forwarded = crate::destination::param_parts(&dest);
                if forwarded.is_some_and(|(_, f)| f == edge.rf.symbol) {
                    // The caller forwards its own parameter `n`: it
                    // becomes a wrapper for the next hop, unless the
                    // chain must cut here (KTD8).
                    let n = forwarded.map(|(i, _)| i).unwrap_or(active.param);
                    let key = (edge.file.clone(), edge.rf.symbol.clone(), n);
                    if active.keys.contains(&key) {
                        emit(
                            st,
                            &mut emitted,
                            edge,
                            active,
                            dest,
                            Some(DerivedCut::Recursion),
                            cx,
                        );
                    } else if active.chain.len() >= hop_limit as usize {
                        emit(
                            st,
                            &mut emitted,
                            edge,
                            active,
                            dest,
                            Some(DerivedCut::HopLimit),
                            cx,
                        );
                    } else {
                        let key = (active.inner, edge.file.clone(), edge.rf.symbol.clone(), n);
                        if !reached.contains(&key) {
                            let mut chain = vec![ViaHop {
                                file: cx.pf.file.display.clone(),
                                symbol: edge.rf.symbol.clone(),
                            }];
                            chain.extend(active.chain.iter().cloned());
                            let mut keys = active.keys.clone();
                            keys.insert((edge.file.clone(), edge.rf.symbol.clone(), n));
                            let cand = Active {
                                file: edge.file.clone(),
                                symbol: edge.rf.symbol.clone(),
                                param: n,
                                inner: active.inner,
                                chain,
                                keys,
                            };
                            match next.get_mut(&key) {
                                Some(prev) if chain_cmp(&cand.chain, &prev.chain).is_lt() => {
                                    *prev = cand;
                                }
                                None => {
                                    next.insert(key, cand);
                                }
                                _ => {}
                            }
                        }
                    }
                } else {
                    emit(st, &mut emitted, edge, active, dest, None, cx);
                }
            }
        }
        for key in next.keys() {
            reached.insert(key.clone());
        }
        level = next.into_values().collect();
    }
}

/// Orders two `via` chains: shortest first, then byte-wise smallest
/// `(file, symbol)` sequence (KTD7).
fn chain_cmp(a: &[ViaHop], b: &[ViaHop]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| {
        a.iter()
            .map(|h| (h.file.as_str(), h.symbol.as_str()))
            .cmp(b.iter().map(|h| (h.file.as_str(), h.symbol.as_str())))
    })
}

/// Whether `e` is a spread (`*args`, `...args`): opaque text starting with
/// the spread marker.
fn spread(e: &Expr) -> Option<&Expr> {
    match e {
        Expr::Opaque(t) if t.starts_with('*') || t.starts_with("...") => Some(e),
        _ => None,
    }
}

/// The wrapper's declared parameter list (`path == symbol` in its file).
fn wrapper_span<'p>(st: &State<'p, '_>, active: &Active) -> Option<&'p SymbolSpan> {
    st.program
        .files
        .get(active.file.as_slice())
        .and_then(|pf| pf.ir.symbols.iter().find(|s| s.path == active.symbol))
}

/// The caller's destination for the hop (KTD7): the positional argument
/// at the parameter's position unless a spread at or before it makes the
/// position unknowable, a keyword argument naming the parameter, a
/// literal default evaluated in the wrapper's scope, or else the
/// wrapper's own `param:` destination.
fn argument_destination(st: &mut State<'_, '_>, active: &Active, edge: &CallEdge) -> Destination {
    let rf = &edge.rf;
    let n = active.param as usize;
    if let Some(e) = rf.args.iter().take(n).find_map(spread) {
        return destination::expr(&render(e));
    }
    if let Some(e) = rf.args.get(n - 1) {
        return to_dest(st.eval(&edge.file, &rf.symbol, e, 0));
    }
    if let Some(kw) = wrapper_span(st, active)
        .and_then(|s| s.params.get(n - 1))
        .and_then(|name| rf.kwargs.iter().find(|(k, _)| k == name))
    {
        return to_dest(st.eval(&edge.file, &rf.symbol, &kw.1, 0));
    }
    if let Some(d) = wrapper_span(st, active).and_then(|s| s.defaults.get(&active.param)) {
        let v = st.eval(&active.file, &active.symbol, d, 0);
        if let Val::Lit(_) = v {
            return to_dest(v);
        }
    }
    destination::param(active.param, &active.symbol)
}

/// Appends a derived site for `edge` through `active`, or replaces a
/// same-keyed site's derivation with a strictly better chain.
fn emit(
    st: &mut State<'_, '_>,
    emitted: &mut Dedup,
    edge: &CallEdge,
    active: &Active,
    destination: Destination,
    cut: Option<DerivedCut>,
    cx: Ctx<'_, '_>,
) {
    let inner = &st.out.sites[active.inner];
    let site = Site {
        id: String::new(),
        language: cx.lang(),
        file: cx.pf.file.display.clone(),
        file_bytes: cx.pf.file.bytes_hex.clone(),
        symbol: edge.rf.symbol.clone(),
        bucket: inner.bucket,
        mechanism: inner.mechanism.clone(),
        destination,
        ordinal: 0,
        labels: labels_at(cx, &edge.rf.symbol),
        location: Some(edge.rf.location),
        via: Some(Via {
            inner_site: inner.id.clone(),
            argument: active.param,
            chain: active.chain.clone(),
            cut,
        }),
    };
    let key = (
        edge.file.clone(),
        edge.rf.symbol.clone(),
        active.inner,
        active.param,
    );
    match emitted.get_mut(&key) {
        // A caller gets at most one derived site per (inner site,
        // argument index); the shortest, then byte-wise smallest chain
        // keeps it (KTD7).
        Some((at, chain)) => {
            if chain_cmp(&active.chain, chain).is_lt() {
                let via = site.via.clone();
                st.out.sites[*at] = site;
                *chain = via.map(|v| v.chain).unwrap_or_default();
            }
        }
        None => {
            emitted.insert(key, (st.out.sites.len(), active.chain.clone()));
            st.out.sites.push(site);
        }
    }
}

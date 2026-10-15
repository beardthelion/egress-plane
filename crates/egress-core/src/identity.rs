//! Position-free identity, path encoding, and final ordering.
//!
//! The canonical key of a finding joins its position-free components, each
//! length-prefixed so no two component lists share a key. The `id` is the
//! first 16 hex characters of SHA-256 over the key. Identical siblings in one
//! enclosing symbol separate by an ordinal assigned in source order, so
//! inserting one changes the ID set by exactly one addition. Escaping and
//! location never enter the key.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

use crate::model::{
    AutoRun, BlindSpot, DependencyMark, DependencyPackage, DependencySection, ImportsUnscanned,
    Report, Site, UnscannedDependency,
};

/// Version tag at the start of every key, so a future key change cannot
/// silently reuse v1 IDs.
const KEY_VERSION: &[u8] = b"egress-plane/identity/v1";

/// A repo-relative path in output form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EncodedPath {
    /// `/`-separated display form; each invalid UTF-8 byte appears as
    /// `\x{hh}`.
    pub display: String,
    /// Lowercase hex of the raw bytes, present only for non-UTF-8 paths.
    pub bytes_hex: Option<String>,
}

/// Encodes raw `/`-separated path bytes.
pub fn encode_path_bytes(bytes: &[u8]) -> EncodedPath {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return EncodedPath {
            display: s.to_string(),
            bytes_hex: None,
        };
    }
    let mut display = String::new();
    for chunk in bytes.utf8_chunks() {
        display.push_str(chunk.valid());
        for b in chunk.invalid() {
            let _ = write!(display, "\\x{{{b:02x}}}");
        }
    }
    EncodedPath {
        display,
        bytes_hex: Some(hex(bytes)),
    }
}

/// Encodes `path` relative to `root` with `/` separators. Separators come
/// from the host's path parsing, so on Linux and macOS a `\` inside a file
/// name stays part of that name. Returns `None` when `path` is not strictly
/// inside `root` or holds a `..`, `.`, or root component after the prefix,
/// so an absolute path can never reach output.
pub fn encode_rel_path(root: &Path, path: &Path) -> Option<EncodedPath> {
    let rel = path.strip_prefix(root).ok()?;
    let mut bytes = Vec::new();
    for c in rel.components() {
        let Component::Normal(name) = c else {
            return None;
        };
        if !bytes.is_empty() {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(name.as_encoded_bytes());
    }
    if bytes.is_empty() {
        return None;
    }
    Some(encode_path_bytes(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The raw bytes of a path for identity and sorting: `file_bytes` when
/// present, else the UTF-8 text.
pub(crate) fn raw_path(file: &str, file_bytes: Option<&str>) -> Vec<u8> {
    file_bytes
        .and_then(unhex)
        .unwrap_or_else(|| file.as_bytes().to_vec())
}

/// The `id` for a canonical key: the first 16 hex characters of its SHA-256.
pub fn hash_id(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    hex(&digest[..8])
}

/// Builds a canonical key under a caller-supplied version tag, with the
/// same length-prefixing as the code layer's keys (KTD10). Callers that are
/// not the code layer use their own tag, so a different namespace can never
/// collide with these ids.
pub fn key_with_version(version: &[u8], components: &[Vec<u8>]) -> Vec<u8> {
    let mut key = Vec::new();
    for c in std::iter::once(version).chain(components.iter().map(Vec::as_slice)) {
        key.extend_from_slice(&(c.len() as u64).to_be_bytes());
        key.extend_from_slice(c);
    }
    key
}

fn join(components: &[Vec<u8>]) -> Vec<u8> {
    key_with_version(KEY_VERSION, components)
}

fn opt(v: Option<&str>) -> Vec<u8> {
    match v {
        None => vec![0],
        Some(s) => {
            let mut b = vec![1];
            b.extend_from_slice(s.as_bytes());
            b
        }
    }
}

/// Identity components of a direct site (`via` none). A derived site keys
/// on [`derived_site_components`] instead, under a different tag.
fn site_components(s: &Site) -> Vec<Vec<u8>> {
    vec![
        b"site".to_vec(),
        s.language.as_str().into(),
        raw_path(&s.file, s.file_bytes.as_deref()),
        s.symbol.as_bytes().to_vec(),
        s.mechanism.as_bytes().to_vec(),
        s.destination.kind.as_str().into(),
        s.destination.value.as_bytes().to_vec(),
        opt(s.destination.default.as_deref()),
    ]
}

/// Phase-2 identity components of a derived site (KTD9): the
/// `derived-site` tag, the inner site's phase-1 id, the caller's file and
/// symbol, the caller's argument index, the wrapper chain, then the
/// mechanism and destination. The tag keeps a derived key disjoint from
/// every direct-site key built from the same field values.
fn derived_site_components(s: &Site) -> Vec<Vec<u8>> {
    let via = s.via.as_ref().expect("a derived site carries via");
    let mut c = Vec::with_capacity(9 + via.chain.len() * 2);
    c.push(b"derived-site".to_vec());
    c.push(via.inner_site.as_bytes().to_vec());
    c.push(raw_path(&s.file, s.file_bytes.as_deref()));
    c.push(s.symbol.as_bytes().to_vec());
    c.push(via.argument.to_string().into_bytes());
    for hop in &via.chain {
        c.push(hop.file.as_bytes().to_vec());
        c.push(hop.symbol.as_bytes().to_vec());
    }
    c.push(s.mechanism.as_bytes().to_vec());
    c.push(s.destination.kind.as_str().into());
    c.push(s.destination.value.as_bytes().to_vec());
    c.push(opt(s.destination.default.as_deref()));
    c
}

fn blind_spot_components(b: &BlindSpot) -> Vec<Vec<u8>> {
    let file = raw_path(&b.file, b.file_bytes.as_deref());
    if b.whole_file {
        // Whole-file blind spots key on file and reason.
        vec![b"blind-spot/file".to_vec(), file, b.kind.as_str().into()]
    } else {
        vec![
            b"blind-spot".to_vec(),
            b.language.map(|l| l.as_str()).unwrap_or("").into(),
            file,
            b.symbol.as_bytes().to_vec(),
            b.kind.as_str().into(),
            b.construct.as_bytes().to_vec(),
        ]
    }
}

fn with_ordinal(mut c: Vec<Vec<u8>>, ordinal: u32) -> Vec<u8> {
    c.push(ordinal.to_string().into_bytes());
    join(&c)
}

/// The canonical identity key of a direct site, including its ordinal.
pub fn site_key(site: &Site) -> Vec<u8> {
    with_ordinal(site_components(site), site.ordinal)
}

/// The canonical identity key of a derived site, including its ordinal
/// (KTD9). `site.via` must be set.
pub fn derived_site_key(site: &Site) -> Vec<u8> {
    with_ordinal(derived_site_components(site), site.ordinal)
}

/// The canonical identity key of a blind spot, including its ordinal.
pub fn blind_spot_key(spot: &BlindSpot) -> Vec<u8> {
    with_ordinal(blind_spot_components(spot), spot.ordinal)
}

/// The canonical identity key of an unscanned dependency: language and
/// package.
pub fn unscanned_dependency_key(dep: &UnscannedDependency) -> Vec<u8> {
    join(&[
        b"unscanned-dependency".to_vec(),
        dep.language.as_str().into(),
        dep.package.as_bytes().to_vec(),
    ])
}

/// The components that locate one installed package instance: language,
/// package, root label, locator. The version and every absolute path stay
/// out, so a version bump or a relocated root keeps the ids.
fn instance_components(e: &DependencyPackage) -> Vec<Vec<u8>> {
    vec![
        e.language.as_str().into(),
        e.package.as_bytes().to_vec(),
        e.root.as_bytes().to_vec(),
        e.locator.as_bytes().to_vec(),
    ]
}

fn tagged(tag: &[u8], mut instance: Vec<Vec<u8>>, tail: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut c = Vec::with_capacity(instance.len() + tail.len() + 1);
    c.push(tag.to_vec());
    c.append(&mut instance);
    c.extend(tail);
    c
}

/// The canonical identity key of a dependency package entry.
pub fn dependency_key(entry: &DependencyPackage) -> Vec<u8> {
    join(&tagged(b"dependency", instance_components(entry), vec![]))
}

/// The canonical identity key of a site inside a dependency entry,
/// including its ordinal. The file is relative to the package.
pub fn dependency_site_key(entry: &DependencyPackage, site: &Site) -> Vec<u8> {
    with_ordinal(
        tagged(
            b"dependency-site",
            instance_components(entry),
            site_components(site),
        ),
        site.ordinal,
    )
}

/// The canonical identity key of a blind spot inside a dependency entry,
/// including its ordinal. The file is relative to the package.
pub fn dependency_blind_spot_key(entry: &DependencyPackage, spot: &BlindSpot) -> Vec<u8> {
    with_ordinal(
        tagged(
            b"dependency-blind-spot",
            instance_components(entry),
            blind_spot_components(spot),
        ),
        spot.ordinal,
    )
}

/// The canonical identity key of an auto-run file: root label, file
/// relative to the import root, and trigger. The attributed distribution
/// stays out.
pub fn auto_run_key(entry: &AutoRun) -> Vec<u8> {
    join(&[
        b"dependency-auto-run".to_vec(),
        entry.root.as_bytes().to_vec(),
        entry.file.as_bytes().to_vec(),
        entry.trigger.as_str().into(),
    ])
}

fn site_sort_key(s: &Site) -> Vec<Vec<u8>> {
    // Language first, then the remaining identity components in identity order.
    site_components(s).split_off(1)
}

fn derived_site_sort_key(s: &Site) -> Vec<Vec<u8>> {
    // The derived site's own key (KTD9): inner id, caller file and symbol,
    // argument index, chain, mechanism, destination.
    derived_site_components(s).split_off(1)
}

fn blind_spot_sort_key(b: &BlindSpot) -> Vec<Vec<u8>> {
    vec![
        b.language.map(|l| l.as_str()).unwrap_or("").into(),
        raw_path(&b.file, b.file_bytes.as_deref()),
        b.symbol.as_bytes().to_vec(),
        b.kind.as_str().into(),
        b.construct.as_bytes().to_vec(),
    ]
}

fn location_key(l: Option<crate::model::Location>) -> (u32, u32) {
    l.map(|l| (l.line, l.column)).unwrap_or((0, 0))
}

/// Sorts labels, orders sites by `sort_key` with source position breaking
/// sibling ties, then assigns ordinals and ids with `components`.
fn finalize_sites_keyed(
    sites: &mut [Site],
    sort_key: impl Fn(&Site) -> Vec<Vec<u8>>,
    components: impl Fn(&Site) -> Vec<Vec<u8>>,
) {
    for s in sites.iter_mut() {
        s.labels.sort_by_key(|l| l.as_str());
        s.labels.dedup();
    }
    sites.sort_by_cached_key(|s| {
        (
            sort_key(s),
            location_key(s.location),
            s.labels.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
            s.bucket.as_str(),
        )
    });
    let mut counters: BTreeMap<Vec<Vec<u8>>, u32> = BTreeMap::new();
    for s in sites.iter_mut() {
        let c = components(s);
        let n = counters.entry(c.clone()).or_default();
        s.ordinal = *n;
        *n += 1;
        s.id = hash_id(&with_ordinal(c, s.ordinal));
    }
}

fn finalize_sites(sites: &mut [Site], components: impl Fn(&Site) -> Vec<Vec<u8>>) {
    finalize_sites_keyed(sites, site_sort_key, components);
}

fn finalize_blind_spots(spots: &mut [BlindSpot], components: impl Fn(&BlindSpot) -> Vec<Vec<u8>>) {
    for b in spots.iter_mut() {
        b.labels.sort_by_key(|l| l.as_str());
        b.labels.dedup();
    }
    spots.sort_by_cached_key(|b| {
        (
            blind_spot_sort_key(b),
            location_key(b.location),
            b.labels.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
            b.whole_file,
            b.coverage_gap,
        )
    });
    let mut counters: BTreeMap<Vec<Vec<u8>>, u32> = BTreeMap::new();
    for b in spots.iter_mut() {
        let c = components(b);
        let n = counters.entry(c.clone()).or_default();
        b.ordinal = *n;
        *n += 1;
        b.id = hash_id(&with_ordinal(c, b.ordinal));
    }
    spots.sort_by_cached_key(|b| (blind_spot_sort_key(b), b.ordinal));
}

fn sort_mark(mark: &mut DependencyMark) {
    mark.rules.sort_by_key(|r| r.as_str());
    mark.rules.dedup();
    mark.resembles.sort();
    mark.resembles.dedup();
}

fn imports_unscanned_sort_key(u: &ImportsUnscanned) -> Vec<Vec<u8>> {
    let mut key = vec![
        u.language.as_str().into(),
        u.package.as_bytes().to_vec(),
        u.reason.as_str().into(),
    ];
    for d in &u.distribution {
        key.push(d.as_bytes().to_vec());
    }
    key.push(
        u.distribution_source
            .map(|s| s.as_str())
            .unwrap_or("")
            .into(),
    );
    match &u.mark {
        None => key.push(vec![0]),
        Some(m) => {
            key.push(vec![1]);
            for r in &m.rules {
                key.push(r.as_str().into());
            }
            for n in &m.resembles {
                key.push(n.as_bytes().to_vec());
            }
        }
    }
    key
}

/// Sorts and assigns ids inside one package entry: findings keep the
/// first-party ordering rule, and ordinals count among identical siblings
/// inside the entry.
fn finalize_package(entry: &mut DependencyPackage) {
    entry.distribution.sort();
    entry.distribution.dedup();
    if let Some(m) = &mut entry.mark {
        sort_mark(m);
    }
    entry.imported_by.sort();
    entry.imported_by.dedup();
    entry.imported_by_packages.sort();
    entry.imported_by_packages.dedup();
    for u in &mut entry.imports_unscanned {
        u.distribution.sort();
        u.distribution.dedup();
        if let Some(m) = &mut u.mark {
            sort_mark(m);
        }
    }
    entry
        .imports_unscanned
        .sort_by_cached_key(imports_unscanned_sort_key);

    let instance = instance_components(entry);
    finalize_sites(&mut entry.sites, |s| {
        tagged(b"dependency-site", instance.clone(), site_components(s))
    });
    finalize_blind_spots(&mut entry.blind_spots, |b| {
        tagged(
            b"dependency-blind-spot",
            instance.clone(),
            blind_spot_components(b),
        )
    });
}

fn finalize_dependencies(deps: &mut DependencySection) {
    deps.roots
        .sort_by(|a, b| (&a.label, a.kind.as_str()).cmp(&(&b.label, b.kind.as_str())));
    deps.caveats.sort();
    deps.caveats.dedup();
    deps.budget_exceeded.sort_by_key(|b| b.as_str());
    deps.budget_exceeded.dedup();
    deps.diagnostics
        .sort_by(|a, b| (&a.lockfile, a.problem.as_str()).cmp(&(&b.lockfile, b.problem.as_str())));
    deps.auto_run.sort_by(|a, b| {
        (&a.root, &a.file, a.trigger.as_str(), &a.distribution).cmp(&(
            &b.root,
            &b.file,
            b.trigger.as_str(),
            &b.distribution,
        ))
    });
    for a in &mut deps.auto_run {
        a.id = hash_id(&auto_run_key(a));
    }
    for p in &mut deps.packages {
        finalize_package(p);
        p.id = hash_id(&dependency_key(p));
    }
    deps.packages.sort_by(|a, b| {
        (a.language.as_str(), &a.package, &a.root, &a.locator).cmp(&(
            b.language.as_str(),
            &b.package,
            &b.root,
            &b.locator,
        ))
    });
}

/// Phase 1 of the two-phase finalize for a site list (KTD9): the direct
/// sites (`via` none) are sorted and keyed exactly as `finalize` has
/// always done, and any derived sites move to the tail unfinished, in
/// input order. The derived-site pass runs this first so a
/// `via.inner_site` names a stable phase-1 id; `finalize` runs phase 2 on
/// the derived sites afterward.
pub fn finalize_direct_sites(sites: &mut Vec<Site>) {
    let (mut derived, mut direct): (Vec<Site>, Vec<Site>) = std::mem::take(sites)
        .into_iter()
        .partition(|s| s.via.is_some());
    finalize_sites(&mut direct, site_components);
    direct.append(&mut derived);
    *sites = direct;
}

/// Assigns ordinals and ids to every finding, then sorts every collection
/// byte-wise by identity components. Phase 1 keys the direct sites, blind
/// spots, and every other collection exactly as the single-phase finalize
/// did; phase 2 (KTD9) keys the derived sites (`via` set) by their
/// `derived-site` components and appends them after the direct sites.
/// Ordinals among identical siblings follow source position; nothing else
/// depends on position or on insertion order. Idempotent.
pub fn finalize(report: &mut Report) {
    // Phase 1: direct sites and every other collection. Derived sites
    // wait for phase 2 so a `via.inner_site` can name a phase-1 id.
    finalize_direct_sites(&mut report.sites);
    finalize_blind_spots(&mut report.blind_spots, blind_spot_components);

    for d in &mut report.unscanned_dependencies {
        d.files.sort();
        d.files.dedup();
        d.distribution.sort();
        d.distribution.dedup();
        if let Some(m) = &mut d.mark {
            sort_mark(m);
        }
        d.id = hash_id(&unscanned_dependency_key(d));
    }
    report
        .unscanned_dependencies
        .sort_by(|a, b| (a.language.as_str(), &a.package).cmp(&(b.language.as_str(), &b.package)));

    report.excluded.sort_by_cached_key(|x| {
        (
            raw_path(&x.path, x.path_bytes.as_deref()),
            x.reason.as_str(),
        )
    });
    report
        .completeness
        .budget_exceeded
        .sort_by_key(|b| b.as_str());
    report.completeness.budget_exceeded.dedup();
    report.caveats.sort_by(|a, b| a.id.cmp(&b.id));

    if let Some(deps) = &mut report.dependencies {
        finalize_dependencies(deps);
    }

    // Phase 2 (KTD9): derived sites sit at the tail after phase 1. Key
    // them by their `derived-site` components and keep them after the
    // direct sites.
    let tail = report
        .sites
        .iter()
        .position(|s| s.via.is_some())
        .unwrap_or(report.sites.len());
    let mut derived = report.sites.split_off(tail);
    finalize_sites_keyed(&mut derived, derived_site_sort_key, derived_site_components);
    report.sites.append(&mut derived);
}

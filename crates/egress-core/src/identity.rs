//! Position-free identity (KTD9), path encoding (KTD10), and final ordering.
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

use crate::model::{BlindSpot, Report, Site, UnscannedDependency};

/// Version tag at the start of every key, so a future key change cannot
/// silently reuse v1 IDs.
const KEY_VERSION: &[u8] = b"egress-plane/identity/v1";

/// A repo-relative path in output form (KTD10).
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
fn raw_path(file: &str, file_bytes: Option<&str>) -> Vec<u8> {
    file_bytes
        .and_then(unhex)
        .unwrap_or_else(|| file.as_bytes().to_vec())
}

/// The `id` for a canonical key: the first 16 hex characters of its SHA-256.
pub fn hash_id(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    hex(&digest[..8])
}

fn join(components: &[Vec<u8>]) -> Vec<u8> {
    let mut key = Vec::new();
    for c in std::iter::once(KEY_VERSION).chain(components.iter().map(Vec::as_slice)) {
        key.extend_from_slice(&(c.len() as u64).to_be_bytes());
        key.extend_from_slice(c);
    }
    key
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

fn blind_spot_components(b: &BlindSpot) -> Vec<Vec<u8>> {
    let file = raw_path(&b.file, b.file_bytes.as_deref());
    if b.whole_file {
        // Whole-file blind spots key on file and reason (KTD9).
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

/// The canonical identity key of a site (KTD9), including its ordinal.
pub fn site_key(site: &Site) -> Vec<u8> {
    with_ordinal(site_components(site), site.ordinal)
}

/// The canonical identity key of a blind spot (KTD9), including its ordinal.
pub fn blind_spot_key(spot: &BlindSpot) -> Vec<u8> {
    with_ordinal(blind_spot_components(spot), spot.ordinal)
}

/// The canonical identity key of an unscanned dependency: language and
/// package (KTD9).
pub fn unscanned_dependency_key(dep: &UnscannedDependency) -> Vec<u8> {
    join(&[
        b"unscanned-dependency".to_vec(),
        dep.language.as_str().into(),
        dep.package.as_bytes().to_vec(),
    ])
}

fn site_sort_key(s: &Site) -> Vec<Vec<u8>> {
    // Language first, then the remaining identity components in KTD9 order.
    site_components(s).split_off(1)
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

/// Assigns ordinals and ids to every finding, then sorts every collection
/// byte-wise by identity components (KTD9, KTD10). Ordinals among identical
/// siblings follow source position; nothing else depends on position or on
/// insertion order. Idempotent.
pub fn finalize(report: &mut Report) {
    for s in &mut report.sites {
        s.labels.sort_by_key(|l| l.as_str());
        s.labels.dedup();
    }
    report.sites.sort_by_cached_key(|s| {
        (
            site_sort_key(s),
            location_key(s.location),
            s.labels.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
            s.bucket.as_str(),
        )
    });
    let mut counters: BTreeMap<Vec<Vec<u8>>, u32> = BTreeMap::new();
    for s in &mut report.sites {
        let n = counters.entry(site_components(s)).or_default();
        s.ordinal = *n;
        *n += 1;
        s.id = hash_id(&site_key(s));
    }

    for b in &mut report.blind_spots {
        b.labels.sort_by_key(|l| l.as_str());
        b.labels.dedup();
    }
    report.blind_spots.sort_by_cached_key(|b| {
        (
            blind_spot_sort_key(b),
            location_key(b.location),
            b.labels.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
            b.whole_file,
            b.coverage_gap,
        )
    });
    let mut counters: BTreeMap<Vec<Vec<u8>>, u32> = BTreeMap::new();
    for b in &mut report.blind_spots {
        let n = counters.entry(blind_spot_components(b)).or_default();
        b.ordinal = *n;
        *n += 1;
        b.id = hash_id(&blind_spot_key(b));
    }
    report
        .blind_spots
        .sort_by_cached_key(|b| (blind_spot_sort_key(b), b.ordinal));

    for d in &mut report.unscanned_dependencies {
        d.files.sort();
        d.files.dedup();
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
}

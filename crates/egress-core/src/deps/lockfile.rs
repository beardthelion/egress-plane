//! `Cargo.lock` parsing (v3 and v4): names, versions, sources,
//! checksums, and dependency edges. Registry probing and `#<n>` ranks
//! consume this module; U5 adds the other lockfile formats.

use crate::discover::manifests::Malformed;

/// A `Cargo.lock` that parses into the v3/v4 package list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoLock {
    /// Top-level `version` of the lock file itself (3 or 4).
    pub format: u64,
    pub packages: Vec<LockedPackage>,
    /// Package indices by folded name (`-`/`_` equal, KTD5).
    pub by_name: std::collections::BTreeMap<String, Vec<usize>>,
}

/// One `[[package]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    /// `registry+...` / `git+...#<rev>` / absent for the workspace
    /// members and path deps.
    pub source: Option<String>,
    pub checksum: Option<String>,
    /// Declared dependency edges as written: `name`, `name version`,
    /// or `name version (source)`.
    pub dependencies: Vec<String>,
}

/// The lockfile's own `version` key is 3 or 4; anything else (missing,
/// or an unsupported number) is `Malformed`.
pub fn cargo_lock(bytes: &[u8]) -> Result<CargoLock, Malformed> {
    match cargo_lock_result(bytes) {
        LockfileResult::Parsed(l) => Ok(l),
        _ => Err(Malformed),
    }
}

/// Cargo.lock with the matrix's three-way answer: versions 3 and 4
/// parse, a missing version key or 1/2 is not supported, a parse
/// failure or a version above 4 is unreadable.
pub fn cargo_lock_result(bytes: &[u8]) -> LockfileResult<CargoLock> {
    let t: toml::Table = match std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| toml::from_str(s).ok())
    {
        Some(t) => t,
        None => return LockfileResult::Unreadable,
    };
    let format = t.get("version").and_then(|v| v.as_integer());
    match format {
        None | Some(1) | Some(2) => return LockfileResult::NotSupported,
        Some(v) if !(3..=4).contains(&v) => return LockfileResult::Unreadable,
        _ => {}
    }
    cargo_lock_inner(&t).map_or(LockfileResult::Unreadable, LockfileResult::Parsed)
}

fn cargo_lock_inner(t: &toml::Table) -> Result<CargoLock, Malformed> {
    let format: u64 = t
        .get("version")
        .and_then(|v| v.as_integer())
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(Malformed)?;
    if !matches!(format, 3 | 4) {
        return Err(Malformed);
    }
    let mut packages = Vec::new();
    for p in t
        .get("package")
        .and_then(|p| p.as_array())
        .ok_or(Malformed)?
    {
        let name = p
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or(Malformed)?
            .to_string();
        let version = p
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or(Malformed)?
            .to_string();
        let source = p.get("source").and_then(|v| v.as_str()).map(str::to_string);
        let checksum = p
            .get("checksum")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let dependencies = p
            .get("dependencies")
            .and_then(|d| d.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        packages.push(LockedPackage {
            name,
            version,
            source,
            checksum,
            dependencies,
        });
    }
    let mut by_name: std::collections::BTreeMap<String, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (i, p) in packages.iter().enumerate() {
        by_name.entry(p.name.replace('-', "_")).or_default().push(i);
    }
    Ok(CargoLock {
        format,
        packages,
        by_name,
    })
}

/// Resolve one dependency edge to a locked package. `name` and
/// `name version` resolve to the named entry; `name version (source)`
/// strips the parenthesized source. A bare edge matching more than one
/// locked version falls back to the first listed (KTD5).
pub fn resolve_edge<'a>(lock: &'a CargoLock, edge: &str) -> Option<&'a LockedPackage> {
    let (name, version) = edge_name_version(edge);
    // KTD5's hyphen fold applies to the lookup spelling as well.
    let candidates = lock.by_name.get(&name.replace('-', "_"));
    candidates
        .and_then(|c| {
            c.iter()
                .map(|&i| &lock.packages[i])
                .find(|p| version.is_none_or(|v| p.version == v))
        })
        .or_else(|| candidates.and_then(|c| c.first().map(|&i| &lock.packages[i])))
}

/// Split a dependency edge into its package name and optional version:
/// `serde`, `serde 1.0.200`, `serde 1.0.200 (registry+..)`.
fn edge_name_version(edge: &str) -> (&str, Option<&str>) {
    let mut it = edge.split_whitespace();
    let name = it.next().unwrap_or("");
    let version = it.next().filter(|v| !v.starts_with('('));
    (name, Some(version).flatten())
}

/// The KTD5 name fold: `-` and `_` compare equal.
pub fn rust_eq(a: &str, b: &str) -> bool {
    a.bytes()
        .zip(b.bytes())
        .all(|(x, y)| x == y || { (x == b'-' || x == b'_') && (y == b'-' || y == b'_') })
        && a.len() == b.len()
}

// ---- ecosystem lockfiles (U5, the support matrix) ----------------------------

/// A supported lockfile parse result; the support matrix's middle and
/// right columns map onto the other variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockfileResult<T> {
    Parsed(T),
    /// The file exists but its format version is treated as no
    /// supported lockfile (Cargo v1/v2, package-lock v1, poetry 1.x).
    NotSupported,
    /// Parse failure, an unknown version, or over-cap bytes.
    Unreadable,
}

/// The npm `package-lock.json` package set: `lockfileVersion` 2 or 3,
/// read from the `packages` map. The package name is the last
/// `node_modules/` segments of the key unless the entry holds a `name`
/// field (an alias maps to the real name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmLock {
    pub packages: Vec<(String, String)>,
}

pub fn package_lock(bytes: &[u8]) -> LockfileResult<NpmLock> {
    let v: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return LockfileResult::Unreadable,
    };
    let version = v.get("lockfileVersion").and_then(|v| v.as_u64());
    match version {
        Some(2) | Some(3) => {}
        Some(1) => return LockfileResult::NotSupported,
        _ => return LockfileResult::Unreadable,
    }
    let Some(packages) = v.get("packages").and_then(|p| p.as_object()) else {
        return LockfileResult::Unreadable;
    };
    let mut out = Vec::new();
    for (key, entry) in packages {
        if key.is_empty() {
            continue;
        }
        // The name: `name` field when present, else the last
        // `node_modules/` segments of the key (a scoped name keeps its
        // two segments).
        let name = entry
            .get("name")
            .and_then(|n| n.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                let segs = key.split("node_modules/");
                let mut last = String::new();
                for s in segs {
                    if !s.is_empty() {
                        last = s.to_string();
                    }
                }
                last
            });
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        out.push((name, version.to_string()));
    }
    LockfileResult::Parsed(NpmLock { packages: out })
}

/// `poetry.lock`: `[[package]]` entries under `lock-version` 2.x.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonLock {
    pub packages: Vec<(String, String)>,
}

pub fn poetry_lock(bytes: &[u8]) -> LockfileResult<PythonLock> {
    let t: toml::Table = match std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| toml::from_str(s).ok())
    {
        Some(t) => t,
        None => return LockfileResult::Unreadable,
    };
    let version = t
        .get("metadata")
        .and_then(|m| m.get("lock-version"))
        .and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.as_integer().map(|i| i.to_string()))
        });
    match version.as_deref().and_then(|v| v.split('.').next()) {
        Some("1") => return LockfileResult::NotSupported,
        Some("2") => {}
        _ => return LockfileResult::Unreadable,
    }
    let mut packages = Vec::new();
    for p in t
        .get("package")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let Some(name) = p.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(version) = p.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        packages.push((name.to_string(), version.to_string()));
    }
    LockfileResult::Parsed(PythonLock { packages })
}

/// `uv.lock`: `version = 1`, `[[package]]` entries.
pub fn uv_lock(bytes: &[u8]) -> LockfileResult<PythonLock> {
    let t: toml::Table = match std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| toml::from_str(s).ok())
    {
        Some(t) => t,
        None => return LockfileResult::Unreadable,
    };
    if t.get("version").and_then(|v| v.as_integer()) != Some(1) {
        return LockfileResult::Unreadable;
    }
    let mut packages = Vec::new();
    for p in t
        .get("package")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let Some(name) = p.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(version) = p.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        packages.push((name.to_string(), version.to_string()));
    }
    LockfileResult::Parsed(PythonLock { packages })
}

/// A Cargo git checkout's short rev is a prefix of the lock source's
/// `#<sha>` (KTD7).
pub fn rev_matches(checkout_rev: &str, source: &str) -> bool {
    source
        .rsplit_once('#')
        .is_some_and(|(_, sha)| sha.starts_with(checkout_rev))
}

/// The (module, version) pairs a `go.sum` locks with a source-tree
/// `h1:` hash. `/go.mod` lines pin the manifest only and do not cover
/// the source, so they do not count here. Malformed lines are skipped;
/// a file with no usable line yields an empty set, which gates the
/// same as absent.
pub fn go_sum(bytes: &[u8]) -> Result<std::collections::BTreeSet<(String, String)>, Malformed> {
    let text = std::str::from_utf8(bytes).map_err(|_| Malformed)?;
    let mut out = std::collections::BTreeSet::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(module), Some(version), Some(hash)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if it.next().is_some() || !hash.starts_with("h1:") {
            continue;
        }
        let (version, kind) = match version.rsplit_once('/') {
            Some((v, "go.mod")) => (v, true),
            _ => (version, false),
        };
        if kind {
            continue;
        }
        if !module.is_empty() && !version.is_empty() {
            out.insert((module.to_string(), version.to_string()));
        }
    }
    Ok(out)
}

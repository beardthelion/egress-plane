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
    let t: toml::Table = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| toml::from_str(s).ok())
        .ok_or(Malformed)?;
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
    Ok(CargoLock { format, packages })
}

/// Resolve one dependency edge to a locked package. `name` and
/// `name version` resolve to the named entry; `name version (source)`
/// strips the parenthesized source. A bare edge matching more than one
/// locked version falls back to the first listed (KTD5).
pub fn resolve_edge<'a>(lock: &'a CargoLock, edge: &str) -> Option<&'a LockedPackage> {
    let (name, version) = edge_name_version(edge);
    // KTD5's hyphen fold applies to the lookup spelling as well.
    lock.packages
        .iter()
        .find(|p| rust_eq(&p.name, name) && version.is_none_or(|v| p.version == v))
        .or_else(|| lock.packages.iter().find(|p| rust_eq(&p.name, name)))
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

//! Instance locators (KTD4): the normalized name chain from the root
//! to the instance with version-bearing parts stripped, plus the
//! `#<n>` rank suffix when a lock lists several versions of one name.

use crate::model::DependencyRootKind;

use super::lockfile::{CargoLock, rust_eq};
use super::version::semver;

/// The name a version-bearing directory part contributes to a locator.
/// Registry and vendor `name-version` dirs strip the trailing semver;
/// anything that is not `<name>-<semver>` keeps the whole part (a name
/// may itself hold digits, e.g. `utf8-0.9x` is not a version).
pub fn strip_version(part: &str) -> String {
    if let Some((name, _ver)) = part
        .rsplit_once('-')
        .filter(|(name, ver)| !name.is_empty() && semver(ver).is_some())
    {
        return name.to_string();
    }
    part.to_string()
}

/// The locator for an instance: name-chain parts joined with `/`, the
/// registry index directory dropped. `parts` are the directory names
/// below the root; the package's display name ends the chain when the
/// last part is stripped (registry `serde-1.0.200` -> `serde`).
pub fn instance_locator(kind: DependencyRootKind, parts: &[String]) -> String {
    let mut chain: Vec<String> = Vec::new();
    let n = parts.len();
    for (i, part) in parts.iter().enumerate() {
        let last = i == n - 1;
        match kind {
            // The index directory (`github.com-...`) never joins the
            // chain; a `name-version` dir strips its version.
            DependencyRootKind::CargoRegistry | DependencyRootKind::CargoVendor => {
                if kind == DependencyRootKind::CargoRegistry && i == 0 {
                    continue;
                }
                let s = strip_version(part);
                if !s.is_empty() {
                    chain.push(s);
                }
            }
            // A git checkout is `<repo>-<hash>/<rev>`: the chain is the
            // crate's package name, which callers pass as the last part.
            DependencyRootKind::CargoGit => {
                if last {
                    chain.push(part.clone());
                }
            }
            // npm keeps the full chain (a/node_modules/leftpad ->
            // a/leftpad by collapsing node_modules dirs).
            DependencyRootKind::Npm => {
                if part != "node_modules" {
                    chain.push(part.clone());
                }
            }
            DependencyRootKind::Python => {
                chain.push(part.clone());
            }
            // A modcache leaf is `<module>@<version>`; the chain keeps
            // the nested module path and drops the version suffix.
            DependencyRootKind::GoModuleCache => {
                if last && let Some((m, _)) = part.split_once('@') {
                    chain.push(m.to_string());
                    continue;
                }
                chain.push(part.clone());
            }
        }
    }
    chain.join("/")
}

/// The `#<n>` rank suffix KTD4 assigns at selection time: the 1-based
/// semver rank of `instance_version` among the versions of `name` the
/// lock lists, present only when the lock holds more than one.
pub fn rank_suffix(lock: &CargoLock, name: &str, instance_version: &str) -> String {
    let mut versions: Vec<&str> = lock
        .packages
        .iter()
        .filter(|p| rust_eq(&p.name, name))
        .map(|p| p.version.as_str())
        .collect();
    versions.sort_by_key(|v| semver(v));
    if versions.len() <= 1 {
        return String::new();
    }
    match versions.iter().position(|v| *v == instance_version) {
        Some(i) => format!("#{}", i + 1),
        None => String::new(),
    }
}

/// Rank among versions the root itself holds (unlocked vendor): same
/// rule, sourced from the inventory rather than a lock.
pub fn rank_in_versions(versions: &[&str], instance_version: &str) -> String {
    let mut vs: Vec<&str> = versions.to_vec();
    vs.sort_by_key(|v| semver(v));
    vs.dedup();
    if vs.len() <= 1 {
        return String::new();
    }
    match vs.iter().position(|v| *v == instance_version) {
        Some(i) => format!("#{}", i + 1),
        None => String::new(),
    }
}

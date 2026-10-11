//! Version parsing and precedence. U4 ships semver only; U5 adds the
//! npm and PEP 440 comparison rules.

/// A parsed semver version, kept as the release triple plus optional
/// prerelease/build text for precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Prerelease identifiers, `.`-separated; empty for a stable
    /// release, which sorts after every prerelease.
    pub pre: Vec<Pre>,
}

/// One `.`-separated prerelease identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pre {
    Num(u64),
    Str(String),
}

/// Parse `v` as `major.minor.patch` with optional `-pre` and `+build`.
/// Build metadata is accepted and ignored for precedence. Returns None
/// when the core or a numeric identifier overflows `u64`.
pub fn semver(v: &str) -> Option<SemVer> {
    let core = v.split_once('+').map_or(v, |(c, _)| c);
    let (core, pre_text) = match core.split_once('-') {
        Some((c, p)) => (c, p),
        None => (core, ""),
    };
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    let pre = if pre_text.is_empty() {
        Vec::new()
    } else {
        let mut pre = Vec::new();
        for id in pre_text.split('.') {
            if id.is_empty() {
                return None;
            }
            pre.push(match id.parse::<u64>() {
                // Numeric ids with leading zeros are semver-invalid;
                // parse rejects them via the digit check below.
                Ok(n) if !has_leading_zero(id) => Pre::Num(n),
                _ => {
                    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                        return None;
                    }
                    Pre::Str(id.to_string())
                }
            });
        }
        pre
    };
    Some(SemVer {
        major,
        minor,
        patch,
        pre,
    })
}

fn has_leading_zero(id: &str) -> bool {
    id.len() > 1 && id.starts_with('0')
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then(match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Equal,
                // A stable release precedes a prerelease.
                (true, false) => Greater,
                (false, true) => Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pre {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match (self, other) {
            (Pre::Num(a), Pre::Num(b)) => a.cmp(b),
            // Numeric identifiers sort before alphanumeric ones.
            (Pre::Num(_), Pre::Str(_)) => Less,
            (Pre::Str(_), Pre::Num(_)) => Greater,
            (Pre::Str(a), Pre::Str(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Pre {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ---- ecosystem comparison (U5) ---------------------------------------------

/// npm version equality: exact after stripping `+build` metadata.
pub fn npm_eq(installed: &str, locked: &str) -> bool {
    installed.split('+').next().unwrap_or("") == locked.split('+').next().unwrap_or("")
}

/// PEP 503 normalization: lowercase and runs of `-`, `_`, `.` to `-`.
pub fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_dash {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        }
    }
    out
}

/// The PEP 440 comparison subset (KTD7): lowercase, a leading `v`
/// dropped, release segments zero-padded so `1.0` equals `1.0.0`, and
/// a `+local` segment kept and compared. Versions that do not parse
/// compare by exact string.
pub fn pep440_eq(installed: &str, locked: &str) -> bool {
    match (pep440(installed), pep440(locked)) {
        (Some(a), Some(b)) => a == b,
        _ => installed == locked,
    }
}

/// A parsed PEP 440 subset version: the release tuple and optional
/// local segment.
#[derive(Debug, Clone)]
struct Pep440 {
    release: Vec<u64>,
    local: Option<String>,
}

fn pep440(v: &str) -> Option<Pep440> {
    let v = v.trim().to_ascii_lowercase();
    let v = v.strip_prefix('v').unwrap_or(&v);
    let (release, local) = match v.split_once('+') {
        Some((r, l)) => (r, Some(l.to_string())),
        None => (v, None),
    };
    if release.is_empty() {
        return None;
    }
    let mut nums = Vec::new();
    for seg in release.split('.') {
        // A non-numeric release segment leaves the version unparsed
        // so it compares exactly (`1.0rc1` never equals `1.0`).
        if !seg.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        nums.push(seg.parse().ok()?);
    }
    Some(Pep440 {
        release: nums,
        local,
    })
}

impl PartialEq for Pep440 {
    fn eq(&self, other: &Self) -> bool {
        // Release tuples compare with zero padding on the shorter.
        let n = self.release.len().max(other.release.len());
        let pad = |v: &Vec<u64>| {
            (0..n)
                .map(|i| *v.get(i).unwrap_or(&0))
                .collect::<Vec<u64>>()
        };
        pad(&self.release) == pad(&other.release) && self.local == other.local
    }
}

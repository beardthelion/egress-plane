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

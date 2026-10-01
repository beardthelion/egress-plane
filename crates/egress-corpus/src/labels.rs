//! `expected.toml` sidecar labels (KTD14).
//!
//! A label file names what a correct scan of the case's `tree/` must report.
//! Unknown keys, unknown enum values, and an exit code that disagrees with the
//! state are rejected, so a typo cannot turn into a label that never matches.

use std::path::Path;

use egress_core::model::{BlindSpotKind, CompletenessState, ExcludedReason, Label, Language};
use serde::Deserialize;

/// Parsed and validated labels for one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub state: CompletenessState,
    pub exit_code: i32,
    pub sites: Vec<ExpectedSite>,
    pub blind_spots: Vec<ExpectedBlindSpot>,
    pub unscanned_dependencies: Vec<ExpectedDependency>,
    pub excluded: Vec<ExpectedExcluded>,
    /// When present, the report's caveat IDs must equal this set.
    pub caveats: Option<Vec<String>>,
    /// Strings that must not appear in any reported string field.
    pub absent_text: Vec<String>,
}

/// A required egress site, matched on identity components (never position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedSite {
    pub file: String,
    pub symbol: String,
    pub mechanism: String,
    /// The destination's display form, for example `env:WEBHOOK_URL`.
    pub destination: String,
    /// When present, the site's label set must equal this set.
    pub labels: Option<Vec<Label>>,
}

/// A required blind spot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedBlindSpot {
    pub file: String,
    pub symbol: String,
    pub kind: BlindSpotKind,
}

/// A required unscanned-dependency entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDependency {
    pub language: Language,
    pub package: String,
}

/// A required `excluded` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedExcluded {
    pub path: String,
    pub reason: ExcludedReason,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExpected {
    state: String,
    exit_code: i32,
    #[serde(default)]
    sites: Vec<RawSite>,
    #[serde(default)]
    blind_spots: Vec<RawBlindSpot>,
    #[serde(default)]
    unscanned_dependencies: Vec<RawDependency>,
    #[serde(default)]
    excluded: Vec<RawExcluded>,
    caveats: Option<Vec<String>>,
    #[serde(default)]
    absent_text: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSite {
    file: String,
    symbol: String,
    mechanism: String,
    destination: String,
    labels: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBlindSpot {
    file: String,
    symbol: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDependency {
    language: String,
    package: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExcluded {
    path: String,
    reason: String,
}

/// Parses label text. `origin` names the case in every error message.
pub fn parse_expected(text: &str, origin: &str) -> Result<Expected, String> {
    let raw: RawExpected =
        toml::from_str(text).map_err(|e| format!("{origin}: malformed expected.toml: {e}"))?;
    let bad = |what: String| format!("{origin}: malformed expected.toml: {what}");

    let state = CompletenessState::parse(&raw.state)
        .ok_or_else(|| bad(format!("unknown state {:?}", raw.state)))?;
    if raw.exit_code != state.exit_code() {
        return Err(bad(format!(
            "exit_code {} disagrees with state {:?}, which exits {}",
            raw.exit_code,
            raw.state,
            state.exit_code()
        )));
    }

    let mut sites = Vec::new();
    for s in raw.sites {
        check_path(&s.file).map_err(&bad)?;
        check_nonempty("symbol", &s.symbol).map_err(&bad)?;
        check_nonempty("destination", &s.destination).map_err(&bad)?;
        let lang = s.mechanism.split_once(':').map(|(l, _)| l);
        if !matches!(lang, Some(l) if Language::parse(l).is_some()) || s.mechanism.ends_with(':') {
            return Err(bad(format!(
                "mechanism {:?} must be <language>:<entry>",
                s.mechanism
            )));
        }
        let labels = match s.labels {
            None => None,
            Some(ls) => {
                let mut out = Vec::new();
                for l in ls {
                    out.push(Label::parse(&l).ok_or_else(|| bad(format!("unknown label {l:?}")))?);
                }
                Some(out)
            }
        };
        sites.push(ExpectedSite {
            file: s.file,
            symbol: s.symbol,
            mechanism: s.mechanism,
            destination: s.destination,
            labels,
        });
    }

    let mut blind_spots = Vec::new();
    for b in raw.blind_spots {
        check_path(&b.file).map_err(&bad)?;
        check_nonempty("symbol", &b.symbol).map_err(&bad)?;
        let kind = BlindSpotKind::parse(&b.kind)
            .ok_or_else(|| bad(format!("unknown blind-spot kind {:?}", b.kind)))?;
        blind_spots.push(ExpectedBlindSpot {
            file: b.file,
            symbol: b.symbol,
            kind,
        });
    }

    let mut unscanned_dependencies = Vec::new();
    for d in raw.unscanned_dependencies {
        let language = Language::parse(&d.language)
            .ok_or_else(|| bad(format!("unknown language {:?}", d.language)))?;
        check_nonempty("package", &d.package).map_err(&bad)?;
        unscanned_dependencies.push(ExpectedDependency {
            language,
            package: d.package,
        });
    }

    let mut excluded = Vec::new();
    for x in raw.excluded {
        check_path(&x.path).map_err(&bad)?;
        let reason = ExcludedReason::parse(&x.reason)
            .ok_or_else(|| bad(format!("unknown excluded reason {:?}", x.reason)))?;
        excluded.push(ExpectedExcluded {
            path: x.path,
            reason,
        });
    }

    for t in &raw.absent_text {
        check_nonempty("absent_text entry", t).map_err(&bad)?;
    }

    Ok(Expected {
        state,
        exit_code: raw.exit_code,
        sites,
        blind_spots,
        unscanned_dependencies,
        excluded,
        caveats: raw.caveats,
        absent_text: raw.absent_text,
    })
}

/// Reads and parses `path`; errors name the path.
pub fn load_expected(path: &Path) -> Result<Expected, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    parse_expected(&text, &origin)
}

fn check_nonempty(what: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{what} is empty"))
    } else {
        Ok(())
    }
}

/// Labels use repo-relative `/`-separated paths, as the report does (KTD10).
fn check_path(path: &str) -> Result<(), String> {
    check_nonempty("path", path)?;
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!("path {path:?} is not repo-relative"));
    }
    Ok(())
}

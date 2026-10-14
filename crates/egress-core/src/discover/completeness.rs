//! Completeness state, coverage, and caveats.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::model::{
    BlindSpot, BudgetReason, Caveat, CompletenessState, Coverage, CoverageCounts, Language,
};

/// Raw text of `data/caveats.toml`.
pub const CAVEATS_TOML: &str = include_str!("../../../../data/caveats.toml");

/// The counts for a language, or for `unsupported` when `None`.
pub fn counts_mut(coverage: &mut Coverage, language: Option<Language>) -> &mut CoverageCounts {
    match language {
        Some(l) => coverage.languages.or_default(l),
        None => &mut coverage.unsupported,
    }
}

/// Supported files found, scanned or skipped.
pub fn supported_total(c: &Coverage) -> u64 {
    c.languages.iter().map(|(_, x)| x.scanned + x.skipped).sum()
}

/// The completeness state with this precedence: empty outranks incomplete,
/// which outranks complete. A tool error produces no report at all.
pub fn state(
    coverage: &Coverage,
    blind_spots: &[BlindSpot],
    budget_exceeded: &[BudgetReason],
) -> CompletenessState {
    if supported_total(coverage) == 0 {
        CompletenessState::Empty
    } else if !budget_exceeded.is_empty() || blind_spots.iter().any(|b| b.coverage_gap) {
        CompletenessState::Incomplete
    } else {
        CompletenessState::Complete
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCaveats {
    caveat: Vec<RawCaveat>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCaveat {
    id: String,
    languages: Vec<String>,
    text: String,
    /// When set, the caveat is triggered by a parsed `go` directive
    /// naming a release newer than this version (`major.minor`), not by
    /// language presence.
    #[serde(default)]
    go_newer_than: Option<String>,
    /// When set, the caveat is triggered by a classification fact the
    /// pass records, not by language presence.
    #[serde(default)]
    trigger: Option<String>,
}

/// What a caveat's trigger checks: a `go` directive version bound, or a
/// classification fact the pass records.
enum Trigger {
    NewerGo(String),
    Finding(String),
}

/// One table row: the caveat, its languages, and an optional trigger
/// replacing the language rule.
type CaveatRow = (Caveat, Vec<Language>, Option<Trigger>);

fn table() -> &'static [CaveatRow] {
    static T: OnceLock<Vec<CaveatRow>> = OnceLock::new();
    T.get_or_init(|| {
        let raw: RawCaveats = toml::from_str(CAVEATS_TOML).expect("embedded data/caveats.toml");
        raw.caveat
            .into_iter()
            .map(|c| {
                let langs = c
                    .languages
                    .iter()
                    .map(|l| Language::parse(l).expect("caveat language"))
                    .collect();
                let trigger = match (c.go_newer_than, c.trigger) {
                    (Some(bound), None) => Some(Trigger::NewerGo(bound)),
                    (None, Some(t)) => Some(Trigger::Finding(t)),
                    (None, None) => None,
                    (Some(_), Some(_)) => panic!("a caveat takes one trigger"),
                };
                (
                    Caveat {
                        id: c.id,
                        text: c.text,
                    },
                    langs,
                    trigger,
                )
            })
            .collect()
    })
}

/// Whether a `go` directive version (`1.22`, `1.22.0`, `1.27rc1`) names a
/// release newer than `bound` (`1.26`): the `major.minor` pair compared
/// numerically, any patch or pre-release suffix ignored.
fn go_version_newer(version: &str, bound: &str) -> bool {
    fn major_minor(s: &str) -> Option<(u64, u64)> {
        let mut it = s.split('.');
        let major: u64 = it.next()?.parse().ok()?;
        let minor: String = it
            .next()?
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if minor.is_empty() {
            return None;
        }
        Some((major, minor.parse().ok()?))
    }
    match (major_minor(version), major_minor(bound)) {
        (Some(v), Some(b)) => v > b,
        _ => false,
    }
}

/// The fixed caveats that apply to a tree holding these languages, sorted by
/// ID. `go_versions` carries the parsed `go` directive versions of every
/// `go.mod` and `go.work` in the tree; a `go_newer_than` entry fires when
/// one names a release newer than its bound, and a `trigger` entry fires
/// when classification recorded the named fact. Caveats never change the
/// state.
pub fn caveats(
    languages: &BTreeSet<Language>,
    go_versions: &[&str],
    triggers: &BTreeSet<String>,
) -> Vec<Caveat> {
    let mut out: Vec<Caveat> = table()
        .iter()
        .filter(|(_, langs, trigger)| match trigger {
            Some(Trigger::NewerGo(bound)) => go_versions.iter().any(|v| go_version_newer(v, bound)),
            Some(Trigger::Finding(t)) => triggers.contains(t),
            None => langs.iter().any(|l| languages.contains(l)),
        })
        .map(|(c, _, _)| c.clone())
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

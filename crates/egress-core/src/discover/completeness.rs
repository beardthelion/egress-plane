//! Completeness state, coverage, and caveats (KTD13, R16, R17, R23).

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
        Some(Language::Python) => &mut coverage.python,
        Some(Language::Javascript) => &mut coverage.javascript,
        Some(Language::Rust) => &mut coverage.rust,
        None => &mut coverage.unsupported,
    }
}

/// Supported files found, scanned or skipped.
pub fn supported_total(c: &Coverage) -> u64 {
    [c.python, c.javascript, c.rust]
        .iter()
        .map(|x| x.scanned + x.skipped)
        .sum()
}

/// The completeness state with KTD13's precedence: empty outranks incomplete,
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
}

fn table() -> &'static [(Caveat, Vec<Language>)] {
    static T: OnceLock<Vec<(Caveat, Vec<Language>)>> = OnceLock::new();
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
                (
                    Caveat {
                        id: c.id,
                        text: c.text,
                    },
                    langs,
                )
            })
            .collect()
    })
}

/// The fixed caveats that apply to a tree holding these languages, sorted by
/// ID. Caveats never change the state (R23).
pub fn caveats(languages: &BTreeSet<Language>) -> Vec<Caveat> {
    let mut out: Vec<Caveat> = table()
        .iter()
        .filter(|(_, langs)| langs.iter().any(|l| languages.contains(l)))
        .map(|(c, _)| c.clone())
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

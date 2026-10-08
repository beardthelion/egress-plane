//! Completeness and the exit code (R15): empty when no universe
//! enumerated or was absent, incomplete when any source is unknown or a
//! strong tamper indicator fired, else complete.

use crate::model::{Report, TamperStrength, UniverseState};
use egress_core::model::CompletenessState;

/// Derives the completeness state of an assembled report (R15).
pub fn derive(r: &Report) -> CompletenessState {
    let any_universe = r
        .universes
        .iter()
        .any(|u| matches!(u.state, UniverseState::Enumerated | UniverseState::Absent));
    if !any_universe {
        return CompletenessState::Empty;
    }
    if !r.unknowns.is_empty()
        || r.tamper_indicators
            .iter()
            .any(|t| t.strength == TamperStrength::Strong)
    {
        return CompletenessState::Incomplete;
    }
    CompletenessState::Complete
}

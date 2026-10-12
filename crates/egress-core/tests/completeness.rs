//! Completeness state, coverage, and caveats.

use std::collections::BTreeSet;

use egress_core::discover::completeness::{caveats, state};
use egress_core::model::*;

fn spot(kind: BlindSpotKind, gap: bool) -> BlindSpot {
    BlindSpot {
        id: String::new(),
        language: Some(Language::Python),
        file: "a.py".into(),
        file_bytes: None,
        symbol: "<module>".into(),
        kind,
        whole_file: kind.is_whole_file(),
        coverage_gap: gap,
        construct: String::new(),
        ordinal: 0,
        labels: vec![],
        location: None,
    }
}

fn cov(py_scanned: u64, py_skipped: u64, unsupported_skipped: u64) -> Coverage {
    Coverage {
        languages: [(
            Language::Python,
            CoverageCounts {
                scanned: py_scanned,
                skipped: py_skipped,
            },
        )]
        .into_iter()
        .collect(),
        unsupported: CoverageCounts {
            scanned: 0,
            skipped: unsupported_skipped,
        },
    }
}

#[test]
fn no_supported_file_is_empty_even_with_gaps() {
    assert_eq!(state(&cov(0, 0, 0), &[], &[]), CompletenessState::Empty);
    let nb = spot(BlindSpotKind::UnsupportedFileType, true);
    assert_eq!(state(&cov(0, 0, 1), &[nb], &[]), CompletenessState::Empty);
}

#[test]
fn a_clean_scan_is_complete() {
    assert_eq!(state(&cov(1, 0, 0), &[], &[]), CompletenessState::Complete);
}

#[test]
fn any_gap_or_exhausted_budget_is_incomplete() {
    let gap = spot(BlindSpotKind::ParseError, true);
    assert_eq!(
        state(&cov(1, 1, 0), &[gap], &[]),
        CompletenessState::Incomplete
    );
    assert_eq!(
        state(&cov(1, 0, 0), &[], &[BudgetReason::Files]),
        CompletenessState::Incomplete
    );
    // Skipped files alone (budget cut) are counted, and the budget entry is
    // what marks the state.
    assert_eq!(
        state(&cov(0, 3, 0), &[], &[BudgetReason::Files]),
        CompletenessState::Incomplete
    );
}

#[test]
fn hooks_and_construct_blind_spots_leave_the_state_alone() {
    let hook = spot(BlindSpotKind::BuildHook, false);
    let dynamic = spot(BlindSpotKind::DynamicCode, false);
    assert_eq!(
        state(&cov(1, 0, 0), &[hook, dynamic], &[]),
        CompletenessState::Complete
    );
}

#[test]
fn js_trees_carry_the_browser_dom_caveat() {
    let js: BTreeSet<Language> = [Language::Javascript, Language::Python].into();
    let c = caveats(&js);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].id, "browser-dom");
    assert!(c[0].text.contains("src") && c[0].text.contains("form submission"));
    let py: BTreeSet<Language> = [Language::Python].into();
    assert!(caveats(&py).is_empty());
}

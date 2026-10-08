//! macOS enumerators arrive in U7; until then a macOS run reports every
//! declared source unknown so no macOS corpus case can pass silently.

use std::collections::BTreeMap;

use crate::data::Data;
use crate::model::{Universe, UniverseState, UnknownReason};
use crate::reader::Reader;
use crate::universe::Scan;

/// Placeholder enumeration for the macOS platform (U7).
pub fn enumerate<R: Reader>(_r: &mut R, data: &Data) -> Scan {
    Scan {
        universes: data
            .universes
            .iter()
            .map(|u| Universe {
                id: u.id.clone(),
                state: if u.platform == "macos" {
                    UniverseState::Unknown(UnknownReason::UnsupportedLayout)
                } else {
                    UniverseState::NotApplicable
                },
                members: Vec::new(),
            })
            .collect(),
        unknowns: Vec::new(),
        attributes: BTreeMap::new(),
        not_applicable: Vec::new(),
        euid: None,
        egid: None,
        home: Err(UnknownReason::NoAccountHome),
        tracer_pid: None,
        ancestor_pidns: false,
    }
}

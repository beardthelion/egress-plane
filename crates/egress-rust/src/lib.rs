//! Rust frontend (U7).

use std::collections::BTreeMap;

use egress_core::discover::FileKind;
use egress_core::discover::manifests::Manifests;
use egress_core::ir::FileIr;
use egress_core::resolve::{SpecifierKind, SpecifierRules};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    Parse,
    TooDeeplyNested,
}

pub fn lower(_path: &[u8], _text: &str) -> Result<FileIr, LowerError> {
    Err(LowerError::Parse)
}

pub struct RustRules;

impl SpecifierRules for RustRules {
    fn classify(&self, _from: &[u8], specifier: &str) -> SpecifierKind {
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: specifier.to_string(),
        }
    }
}

pub fn link(
    _manifests: &Manifests,
    _index: &BTreeMap<Vec<u8>, FileKind>,
    _files: &mut [(&[u8], &mut FileIr)],
) -> RustRules {
    RustRules
}

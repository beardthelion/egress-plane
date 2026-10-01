//! JS module specifier rules (KTD16).

use egress_core::discover::Discovery;
use egress_core::resolve::{SpecifierKind, SpecifierRules};

/// Specifier rules for one repository.
#[derive(Debug, Clone, Default)]
pub struct JsRules {}

/// Builds the rules from discovery's manifests and file index.
pub fn rules(_discovery: &Discovery) -> JsRules {
    JsRules {}
}

impl SpecifierRules for JsRules {
    fn classify(&self, _from: &[u8], specifier: &str) -> SpecifierKind {
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: specifier.to_string(),
        }
    }
}

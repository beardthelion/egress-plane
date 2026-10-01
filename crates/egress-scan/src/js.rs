//! Adapter for the JS/TS frontend (U6).

use egress_core::discover::Discovery;
use egress_core::ir::FileIr;
use egress_core::model::Language;
use egress_core::resolve::SpecifierRules;

use crate::registry::{Frontend, FrontendError, SourceInput};

pub struct JsFrontend;

impl Frontend for JsFrontend {
    fn language(&self) -> Language {
        Language::Javascript
    }

    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        egress_js::lower(input.path, input.text).map_err(|e| match e {
            egress_js::LowerError::Parse => FrontendError::Parse,
            egress_js::LowerError::TooDeeplyNested => FrontendError::TooDeeplyNested,
        })
    }

    fn repo_rules(&self, discovery: &Discovery) -> Option<Box<dyn SpecifierRules>> {
        Some(Box::new(egress_js::rules(discovery)))
    }
}

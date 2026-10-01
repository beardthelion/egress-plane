//! Frontend registry (KTD3). Each language frontend (U5 to U7) registers one
//! [`Frontend`]; the scan dispatches each supported file to the frontend for
//! its language. A language with no registered frontend is read and
//! pre-scanned but produces no IR.

use std::collections::BTreeMap;
use std::sync::Arc;

use egress_core::discover::Discovery;
use egress_core::ir::FileIr;
use egress_core::model::Language;
use egress_core::resolve::SpecifierRules;

/// Why a frontend could not lower a file. Each maps to a fixed whole-file
/// blind-spot reason; parser messages never reach output (KTD13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendError {
    /// The parser rejected the file: `parse-error`.
    Parse,
    /// Lowering hit its own depth limit: `too-deeply-nested`.
    TooDeeplyNested,
}

/// One file handed to a frontend.
#[derive(Debug, Clone, Copy)]
pub struct SourceInput<'a> {
    /// Raw repo-relative path bytes.
    pub path: &'a [u8],
    /// Display form of the path (KTD10).
    pub file: &'a str,
    pub language: Language,
    /// Decoded source with any BOM removed.
    pub text: &'a str,
}

/// A language frontend: lowers one file to the shared IR (KTD4).
pub trait Frontend: Send + Sync {
    fn language(&self) -> Language;
    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError>;

    /// The language's specifier rules (KTD16). `None` resolves only exact
    /// relative paths.
    fn specifier_rules(&self) -> Option<&dyn SpecifierRules> {
        None
    }

    /// Specifier rules built from this repository's manifests and file
    /// index (KTD16). When present they take precedence over
    /// [`Frontend::specifier_rules`].
    fn repo_rules(&self, _discovery: &Discovery) -> Option<Box<dyn SpecifierRules>> {
        None
    }
}

/// Frontends by language.
#[derive(Clone, Default)]
pub struct Registry {
    frontends: BTreeMap<Language, Arc<dyn Frontend>>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Registry {
        Registry::default()
    }

    /// The registry `scan` uses: every frontend built into the tool. U5, U6,
    /// and U7 add theirs here.
    pub fn builtin() -> Registry {
        let mut r = Registry::new();
        r.register(crate::js::JsFrontend);
        r
    }

    /// Registers `frontend` for its language, replacing any earlier one.
    pub fn register(&mut self, frontend: impl Frontend + 'static) {
        self.frontends
            .insert(frontend.language(), Arc::new(frontend));
    }

    pub fn get(&self, language: Language) -> Option<&dyn Frontend> {
        self.frontends.get(&language).map(|f| f.as_ref())
    }
}

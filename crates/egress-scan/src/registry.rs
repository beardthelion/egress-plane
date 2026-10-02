//! Frontend registry (KTD3). Each language frontend (U5 to U7) registers one
//! [`Frontend`]; the scan dispatches each supported file to the frontend for
//! its language. A language with no registered frontend is read and
//! pre-scanned but produces no IR.

use std::collections::BTreeMap;
use std::sync::Arc;

use egress_core::discover::FileKind;
use egress_core::discover::manifests::Manifests;
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

    /// Runs once after every file is lowered and before classification,
    /// with this frontend's lowered files. A frontend may add facts only the
    /// whole program reveals and return specifier rules built from the
    /// program, which replace [`Frontend::specifier_rules`].
    fn link(
        &self,
        _manifests: &Manifests,
        _index: &BTreeMap<Vec<u8>, FileKind>,
        _files: &mut [(&[u8], &mut FileIr)],
    ) -> Option<Box<dyn SpecifierRules>> {
        None
    }
}

/// The Rust frontend (U7).
struct Rust;

impl Frontend for Rust {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        egress_rust::lower(input.path, input.text).map_err(|e| match e {
            egress_rust::LowerError::Parse => FrontendError::Parse,
            egress_rust::LowerError::TooDeeplyNested => FrontendError::TooDeeplyNested,
        })
    }

    fn link(
        &self,
        manifests: &Manifests,
        index: &BTreeMap<Vec<u8>, FileKind>,
        files: &mut [(&[u8], &mut FileIr)],
    ) -> Option<Box<dyn SpecifierRules>> {
        Some(Box::new(egress_rust::link(manifests, index, files)))
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
        r.register(Rust);
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

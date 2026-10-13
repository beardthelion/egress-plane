//! Frontend registry. Each language frontend registers one
//! [`Frontend`]; the scan dispatches each supported file to the frontend for
//! its language. A language with no registered frontend is read and
//! pre-scanned but produces no IR.

use std::collections::BTreeMap;
use std::sync::Arc;

use egress_core::discover::Discovery;
use egress_core::discover::FileKind;
use egress_core::discover::manifests::Manifests;
use egress_core::ir::FileIr;
use egress_core::model::Language;
use egress_core::resolve::SpecifierRules;

/// Why a frontend could not lower a file. Each maps to a fixed whole-file
/// blind-spot reason; parser messages never reach output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendError {
    /// The parser rejected the file: `parse-error`.
    Parse,
    /// Lowering hit its own depth limit: `too-deeply-nested`.
    TooDeeplyNested,
}

impl From<egress_python::LowerError> for FrontendError {
    fn from(e: egress_python::LowerError) -> Self {
        match e {
            egress_python::LowerError::Parse => FrontendError::Parse,
            egress_python::LowerError::TooDeeplyNested => FrontendError::TooDeeplyNested,
        }
    }
}

impl From<egress_js::LowerError> for FrontendError {
    fn from(e: egress_js::LowerError) -> Self {
        match e {
            egress_js::LowerError::Parse => FrontendError::Parse,
            egress_js::LowerError::TooDeeplyNested => FrontendError::TooDeeplyNested,
        }
    }
}

impl From<egress_rust::LowerError> for FrontendError {
    fn from(e: egress_rust::LowerError) -> Self {
        match e {
            egress_rust::LowerError::Parse => FrontendError::Parse,
            egress_rust::LowerError::TooDeeplyNested => FrontendError::TooDeeplyNested,
        }
    }
}

impl From<egress_go::LowerError> for FrontendError {
    fn from(e: egress_go::LowerError) -> Self {
        match e {
            egress_go::LowerError::Parse => FrontendError::Parse,
            egress_go::LowerError::TooDeeplyNested => FrontendError::TooDeeplyNested,
        }
    }
}

/// One file handed to a frontend.
#[derive(Debug, Clone, Copy)]
pub struct SourceInput<'a> {
    /// Raw repo-relative path bytes.
    pub path: &'a [u8],
    /// Display form of the path.
    pub file: &'a str,
    pub language: Language,
    /// Decoded source with any BOM removed.
    pub text: &'a str,
}

/// A language frontend: lowers one file to the shared IR.
pub trait Frontend: Send + Sync {
    fn language(&self) -> Language;
    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError>;

    /// The language's specifier rules. `None` resolves only exact
    /// relative paths.
    fn specifier_rules(&self) -> Option<&dyn SpecifierRules> {
        None
    }

    /// Specifier rules built from this repository's manifests and file
    /// index. When present they take precedence over
    /// [`Frontend::specifier_rules`].
    fn repo_rules(&self, _discovery: &Discovery) -> Option<Box<dyn SpecifierRules>> {
        None
    }

    /// Specifier rules for a dependency pass over `import_root` (KTD10).
    /// `None` keeps the rules [`Frontend::link`] and
    /// [`Frontend::repo_rules`] build from the scoped discovery.
    fn dependency_rules(&self, _import_root: &[u8]) -> Option<Box<dyn SpecifierRules>> {
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

/// The Python frontend.
struct Python(egress_python::PythonRules);

impl Frontend for Python {
    fn language(&self) -> Language {
        Language::Python
    }

    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        egress_python::lower(input.text).map_err(Into::into)
    }

    fn specifier_rules(&self) -> Option<&dyn SpecifierRules> {
        Some(&self.0)
    }

    fn dependency_rules(&self, import_root: &[u8]) -> Option<Box<dyn SpecifierRules>> {
        Some(Box::new(egress_python::DependencyPythonRules {
            import_root: import_root.to_vec(),
        }))
    }
}

/// The Rust frontend.
struct Rust;

impl Frontend for Rust {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        egress_rust::lower(input.path, input.text).map_err(Into::into)
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

/// The Go frontend.
struct Go;

impl Frontend for Go {
    fn language(&self) -> Language {
        Language::Go
    }

    fn lower(&self, input: &SourceInput<'_>) -> Result<FileIr, FrontendError> {
        egress_go::lower(input.path, input.text).map_err(Into::into)
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

    /// The registry `scan` uses: every frontend built into the tool. Each
    /// language frontend adds its own here.
    pub fn builtin() -> Registry {
        let mut r = Registry::new();
        r.register(Python(egress_python::PythonRules));
        r.register(crate::js::JsFrontend);
        r.register(Rust);
        r.register(Go);
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

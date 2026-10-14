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
use egress_core::model::{BlindSpot, Language};
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
    /// `resolver_budget` is the resolver-step budget the link charges
    /// its work against.
    fn link(
        &self,
        _manifests: &Manifests,
        _index: &BTreeMap<Vec<u8>, FileKind>,
        _files: &mut [(&[u8], &mut FileIr)],
        _resolver_budget: u64,
    ) -> Option<LinkOutcome> {
        None
    }
}

/// What a frontend's `link` produced: the specifier rules replacing
/// `repo_rules`, any blind spots the link itself emits (a failed link's
/// gap marker), and the resolver-budget accounting to merge into the
/// scan's.
pub struct LinkOutcome {
    pub rules: Box<dyn SpecifierRules>,
    /// Blind spots the link emits itself; findings the IR rewrites
    /// produce land through classification, not here.
    pub blind_spots: Vec<BlindSpot>,
    /// Resolver steps the link charged.
    pub resolver_steps: u64,
    /// The link ran out of resolver budget.
    pub budget_exhausted: bool,
}

impl LinkOutcome {
    /// Rules-only outcome, for links that charge no budget.
    pub fn rules(rules: Box<dyn SpecifierRules>) -> LinkOutcome {
        LinkOutcome {
            rules,
            blind_spots: Vec::new(),
            resolver_steps: 0,
            budget_exhausted: false,
        }
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
        _resolver_budget: u64,
    ) -> Option<LinkOutcome> {
        Some(LinkOutcome::rules(Box::new(egress_rust::link(
            manifests, index, files,
        ))))
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

    /// Whole-program link (KTD8): under a panic guard, so a link failure
    /// degrades the tree to unresolved-module gaps and a `link` marker
    /// on the first Go file rather than aborting the scan.
    fn link(
        &self,
        manifests: &Manifests,
        index: &BTreeMap<Vec<u8>, FileKind>,
        files: &mut [(&[u8], &mut FileIr)],
        resolver_budget: u64,
    ) -> Option<LinkOutcome> {
        // A path for the fallback marker is taken before `files` moves
        // into the guarded call.
        let first_path = files.first().map(|(p, _)| p.to_vec());
        let linked = egress_core::discover::run_guarded(move || {
            egress_go::link(manifests, index, files, resolver_budget)
        });
        match linked {
            Some(l) => Some(LinkOutcome {
                rules: Box::new(l.rules),
                blind_spots: Vec::new(),
                resolver_steps: l.steps,
                budget_exhausted: l.budget_exhausted,
            }),
            None => Some(LinkOutcome {
                rules: Box::new(egress_go::GoRules::fallback()),
                blind_spots: first_path
                    .iter()
                    .map(|p| {
                        egress_core::discover::whole_file_blind_spot(
                            p,
                            egress_core::model::BlindSpotKind::FrontendFailure,
                            Some(Language::Go),
                        )
                    })
                    .collect(),
                resolver_steps: 0,
                budget_exhausted: false,
            }),
        }
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

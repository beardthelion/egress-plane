//! Go frontend: parses Go source with an exact-pinned `gosyn` behind a
//! bounded prescan and a panic guard, and lowers it to the shared IR.
//!
//! [`lower`] handles one file: the package clause lands in
//! [`FileIr::package`], and the [`lower`] module walks the AST into
//! imports, references, constants, locals, and symbol paths.

mod directives;
pub mod link;
mod lower;
mod positions;
mod prescan;

use egress_core::ir::FileIr;

pub use link::{GoRules, Linked, link, link_with};

/// Why a file could not be lowered; each maps to a fixed whole-file reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    /// `gosyn` rejected the file, its lexer failed, or the parser panicked:
    /// `parse-error`.
    Parse,
    /// A prescan bound or gosyn's own depth cap fired:
    /// `too-deeply-nested`.
    TooDeeplyNested,
}

/// gosyn's depth-cap reason string, downcast out of `anyhow::Error`.
const DEPTH_REASON: &str = "too many depth";

/// Lowers the Go file at repo-relative `path` with source `text`.
pub fn lower(_path: &[u8], text: &str) -> Result<FileIr, LowerError> {
    // `go generate` reads raw lines, so the scan runs before tokenization:
    // a column-0 directive inside a raw string or block comment still
    // counts (KTD7, KTD12).
    let generate = directives::generate(text);
    let tokens = gosyn::tokenize_source(text).map_err(|_| LowerError::Parse)?;
    if prescan::over_any_bound(&tokens, text) {
        return Err(LowerError::TooDeeplyNested);
    }
    let linkname = directives::linkname(&tokens);
    drop(tokens);
    // The AST holds `Rc`, so parse and lower stay on the calling thread.
    let file = match egress_core::discover::guard(|| gosyn::parse_source(text)) {
        Some(Ok(file)) => file,
        Some(Err(e)) => {
            return Err(match e.downcast_ref::<gosyn::Error>() {
                Some(gosyn::Error::Else { reason, .. }) if reason == DEPTH_REASON => {
                    LowerError::TooDeeplyNested
                }
                _ => LowerError::Parse,
            });
        }
        None => return Err(LowerError::Parse),
    };
    let mut l = lower::Lowerer::new(text);
    l.directives(&linkname, &generate);
    l.file(&file);
    if l.too_deep {
        return Err(LowerError::TooDeeplyNested);
    }
    let mut ir = l.finish();
    ir.package = Some(file.pkg_name.name.clone());
    Ok(ir)
}

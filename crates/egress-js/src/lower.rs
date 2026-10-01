//! Lowering of one JS or TS file to the IR (KTD4, KTD9, KTD15).

use egress_core::ir::FileIr;
use egress_core::model::Language;

/// Why a file could not be lowered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    /// oxc reported an error or gave up: `parse-error`.
    Parse,
    /// Nesting past what the parser and lowering can recurse through:
    /// `too-deeply-nested`.
    TooDeeplyNested,
}

/// Lowers the file at repo-relative `path` with source `text`.
pub fn lower(_path: &[u8], _text: &str) -> Result<FileIr, LowerError> {
    Ok(FileIr::new(Language::Javascript))
}

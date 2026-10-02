//! Rust frontend (U7): lowers Rust source to the shared IR with `syn` and
//! maps crate module trees for the core's resolver (KTD1, KTD4, KTD16).
//!
//! [`lower`] handles one file and needs nothing beyond it. [`link`] runs
//! once over every lowered Rust file and returns the [`RustRules`] the
//! resolver uses for Rust specifiers.

mod crates;
mod lower;
mod nesting;
mod spec;

use std::collections::BTreeMap;

use egress_core::discover::FileKind;
use egress_core::discover::manifests::Manifests;
use egress_core::ir::FileIr;

pub use crates::RustRules;
pub use lower::MAX_LOWER_DEPTH;
pub use nesting::MAX_CHAIN;

/// Why a file could not be lowered; each maps to a fixed whole-file reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerError {
    /// `syn` rejected the file: `parse-error`.
    Parse,
    /// The file nests deeper than the parser can safely recurse:
    /// `too-deeply-nested`.
    TooDeeplyNested,
}

/// Clears this thread's span data when dropped. proc-macro2's span map
/// otherwise grows for the life of the worker thread, one entry per parsed
/// file, until its 32-bit offsets run out (KTD13).
struct SpanReset;

impl Drop for SpanReset {
    fn drop(&mut self) {
        proc_macro2::extra::invalidate_current_thread_spans();
    }
}

/// Lowers the Rust file at repo-relative `path` with source `text`.
pub fn lower(path: &[u8], text: &str) -> Result<FileIr, LowerError> {
    if nesting::too_deep(text) {
        return Err(LowerError::TooDeeplyNested);
    }
    // Declared before the syntax tree so it drops after it.
    let _reset = SpanReset;
    let file = syn::parse_file(text).map_err(|_| LowerError::Parse)?;
    let mut l = lower::Lowerer::new(path, text);
    l.file(&file);
    if l.too_deep {
        return Err(LowerError::TooDeeplyNested);
    }
    Ok(l.finish())
}

/// Builds the program's Rust specifier rules and adds the constructs only
/// the whole program reveals (first-party proc-macro uses).
pub fn link(
    manifests: &Manifests,
    index: &BTreeMap<Vec<u8>, FileKind>,
    files: &mut [(&[u8], &mut FileIr)],
) -> RustRules {
    let rules = {
        let view: Vec<(&[u8], &FileIr)> = files.iter().map(|(p, ir)| (*p, &**ir)).collect();
        RustRules::build(manifests, index, &view)
    };
    crates::mark_proc_macros(&rules, files);
    rules
}

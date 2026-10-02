//! Module specifier forms the frontend writes and [`crate::RustRules`]
//! reads.
//!
//! - A crate name (`std`, `reqwest`, `acme_net`): a dependency, the standard
//!   library, or a sibling workspace crate; the member path follows in the
//!   import's `members`.
//! - `crate`, `self`, and `super` repeated (`super::super`): first-party
//!   modules relative to the declaring file. Members inside an inline module
//!   are qualified (`net::TcpStream`).
//! - `mod:<rel>`: a `mod name;` declaration, `rel` being the inline module
//!   directories plus the name, resolved beside the declaring file.
//! - `path:<rel>`: a `#[path]` declaration inside an inline module.
//! - `file:<path>`: an in-root file the frontend already folded, from a
//!   top-level `#[path]` or an `include!`.
//! - [`OUTSIDE_ROOT`]: an absolute or root-climbing target. The target itself
//!   is never written, so no output can print it (KTD12).

pub const OUTSIDE_ROOT: &str = "<outside-root>";
pub const MOD: &str = "mod:";
pub const PATH: &str = "path:";
pub const FILE: &str = "file:";

/// Whether `spec` comes from a `mod` declaration or a file load.
pub fn is_mod_decl(spec: &str) -> bool {
    spec.starts_with(MOD) || spec.starts_with(PATH) || spec.starts_with(FILE)
}

/// Whether `spec` is a crate name rather than a keyword or file form.
pub fn is_crate_name(spec: &str) -> bool {
    !spec.is_empty()
        && !is_mod_decl(spec)
        && spec != OUTSIDE_ROOT
        && !matches!(spec, "crate" | "self")
        && !spec.split("::").all(|s| s == "super")
}

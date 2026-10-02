//! JavaScript and TypeScript frontend (U6).
//!
//! [`lower`] parses one file with oxc and lowers it to the shared IR
//! (KTD4); [`rules`] builds the repository's module specifier rules from
//! discovery's manifests and file index (KTD16). The scan crate adapts both
//! to its `Frontend` trait, so this crate depends only on `egress-core`.

pub mod lower;
pub mod nesting;
pub mod packages;

pub use lower::{LowerError, lower};
pub use packages::{JsRules, rules};

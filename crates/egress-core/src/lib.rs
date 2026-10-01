//! Core of egress-plane: the output model, IR, destination handling,
//! redaction, escaping, identity, and JSON output, plus data loading,
//! classifier, resolver, and discovery as later units land.

pub mod data;
pub mod destination;
pub mod escape;
pub mod identity;
pub mod ir;
pub mod json;
pub mod model;
pub mod redact;

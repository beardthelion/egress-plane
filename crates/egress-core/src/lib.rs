//! Core of egress-plane: the output model, IR, destination handling,
//! redaction, escaping, identity, and JSON output, plus data loading, the
//! classifier, the resolver, discovery, the prescan, and shared path helpers.

pub mod classify;
pub mod data;
pub mod deps;
mod derive;
pub mod destination;
pub mod discover;
pub mod escape;
pub mod identity;
pub mod ir;
pub mod json;
pub mod model;
pub mod names;
pub mod paths;
pub mod prescan;
pub mod redact;
pub mod resolve;

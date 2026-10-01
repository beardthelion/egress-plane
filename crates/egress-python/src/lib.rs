//! Python frontend (U5): lowers Python source to the shared IR (KTD4) with
//! `ruff_python_parser`, and supplies Python's module specifier rules
//! (KTD16).

mod lower;
mod packages;

pub use lower::{LowerError, lower};
pub use packages::PythonRules;

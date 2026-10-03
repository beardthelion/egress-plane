//! Python frontend: lowers Python source to the shared IR with
//! `ruff_python_parser`, and supplies Python's module specifier rules.

mod lower;
mod packages;

pub use lower::{LowerError, lower};
pub use packages::PythonRules;

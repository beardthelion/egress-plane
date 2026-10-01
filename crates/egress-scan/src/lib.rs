//! Scan orchestration behind one `scan(root)` entry point (KTD3).
//!
//! This is the U1 stub: it returns a tool error for every root, so no corpus
//! case can pass against it. U3 replaces it with discovery and frontend wiring.

use std::path::Path;

use egress_core::model::{Report, ToolError};

/// Scans the repository at `root`.
pub fn scan(root: &Path) -> Result<Report, ToolError> {
    let _ = root;
    Err(ToolError::Internal("scan is not implemented yet"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_tool_error_for_every_root() {
        assert!(scan(Path::new(".")).is_err());
        assert!(scan(Path::new("/nonexistent/root")).is_err());
    }
}

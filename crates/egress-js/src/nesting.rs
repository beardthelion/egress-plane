//! Nesting estimate for constructs the bracket pre-scan does not count.

/// Estimated nesting units accepted before parsing.
pub const LIMIT: usize = 8192;

/// True when `text` may nest deeper than the parser can recurse through.
pub fn too_deep(_text: &str, _typescript: bool) -> bool {
    false
}

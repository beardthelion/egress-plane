//! Byte-path helpers shared by discovery, resolution, and the frontends.
//! Paths are root-relative and `/`-separated.

/// Everything before the last `/`, or empty when there is none.
pub fn dir_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[..i],
        None => b"",
    }
}

/// Everything after the last `/`, or the whole path when there is none.
pub fn file_name(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Whether `specifier` is `.`, `..`, or starts with `./` or `../`.
pub fn is_dot_relative(specifier: &str) -> bool {
    specifier == "."
        || specifier == ".."
        || specifier.starts_with("./")
        || specifier.starts_with("../")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_of_splits_at_the_last_slash() {
        assert_eq!(dir_of(b""), b"");
        assert_eq!(dir_of(b"a"), b"");
        assert_eq!(dir_of(b"a/b"), b"a");
        assert_eq!(dir_of(b"a/b/c.rs"), b"a/b");
        assert_eq!(dir_of(b"a/b/"), b"a/b");
        assert_eq!(dir_of(b"/"), b"");
        assert_eq!(dir_of(b"/a"), b"");
    }

    #[test]
    fn file_name_is_after_the_last_slash() {
        assert_eq!(file_name(b""), b"");
        assert_eq!(file_name(b"a"), b"a");
        assert_eq!(file_name(b"a/b"), b"b");
        assert_eq!(file_name(b"a/b/c.rs"), b"c.rs");
        assert_eq!(file_name(b"a/b/"), b"");
        assert_eq!(file_name(b"/"), b"");
        assert_eq!(file_name(b"/a"), b"a");
    }

    #[test]
    fn file_name_matches_the_rsplit_form() {
        for p in [&b""[..], b"a", b"a/b", b"a/b/", b"/", b"//x", b"x//"] {
            let rsplit = p.rsplit(|b| *b == b'/').next().unwrap_or(p);
            assert_eq!(file_name(p), rsplit);
        }
    }

    #[test]
    fn dot_relative_specifiers() {
        for s in [".", "..", "./", "../", "./a", "../a/b"] {
            assert!(is_dot_relative(s), "{s}");
        }
        for s in ["", "a", "/a", ".a", "..a", "...", "#a", "a/./b", ".\\a"] {
            assert!(!is_dot_relative(s), "{s}");
        }
    }
}

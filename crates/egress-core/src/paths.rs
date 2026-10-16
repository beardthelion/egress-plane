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

/// `dir`/`name`, or `name` alone when `dir` is empty.
pub fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        name.to_vec()
    } else {
        [dir, b"/", name].concat()
    }
}

/// `parts` joined by `/`.
pub fn join_components(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.join(&b'/')
}

/// `path` equals `dir` or sits under it on a component boundary.
/// An empty `dir` is the root: everything is within it.
pub fn within(path: &[u8], dir: &[u8]) -> bool {
    dir.is_empty()
        || path == dir
        || (path.len() > dir.len() && path.starts_with(dir) && path[dir.len()] == b'/')
}

/// Ancestor directories of `path`, nearest first, ending at the root.
pub fn ancestors(mut dir: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![dir.to_vec()];
    while !dir.is_empty() {
        dir = dir_of(dir);
        out.push(dir.to_vec());
    }
    out
}

/// `text` matches `pattern` where at most one `*` is a wildcard.
/// Returns the text the `*` matched (`""` for a starless match),
/// `None` on no match.
pub fn star_match<'a>(pattern: &str, text: &'a str) -> Option<&'a str> {
    match pattern.split_once('*') {
        None => (pattern == text).then_some(""),
        Some((pre, post)) => {
            if text.len() >= pre.len() + post.len() && text.starts_with(pre) && text.ends_with(post)
            {
                Some(&text[pre.len()..text.len() - post.len()])
            } else {
                None
            }
        }
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

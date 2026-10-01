//! Lexical symlink resolution (KTD12, R19, R22).
//!
//! A link is resolved one component at a time, as the kernel would, but only
//! in-root components are ever touched: each is checked with `lstat` and, when
//! it is itself a link, its target is spliced in and resolution continues, up
//! to [`HOP_LIMIT`] links. A walk that leaves the root is decided from the
//! text alone. The canonical root's own ancestors are real directories, so
//! `..` and names along that path fold exactly; any other component outside
//! the root ends resolution as [`LinkTarget::Outside`] without being
//! `stat`ed, opened, or canonicalized, because touching it can trigger an
//! automount or a network filesystem lookup.

use std::collections::VecDeque;
use std::os::unix::ffi::OsStrExt;

use super::open::{EntryType, RootDir};

/// Most links followed while resolving one link, as Linux's `MAXSYMLINKS`.
pub const HOP_LIMIT: usize = 40;

/// Where a link leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTarget {
    /// The target lies outside the root, or is an ancestor of it.
    Outside,
    /// A component is missing, not a directory, or unreadable.
    Broken,
    /// More than [`HOP_LIMIT`] links.
    HopLimit,
    /// An in-root path (empty for the root itself) and its type.
    InRoot { path: Vec<u8>, kind: EntryType },
}

enum Pos {
    /// Inside the root, as in-root components.
    In(Vec<Vec<u8>>),
    /// On the canonical root's own ancestor path, as that many leading
    /// components of it.
    Above(usize),
}

fn split(target: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    target
        .split(|b| *b == b'/')
        .filter(|c| !c.is_empty())
        .map(<[u8]>::to_vec)
}

fn join(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.join(&b'/')
}

/// Resolves the link at in-root path `link`.
pub fn resolve(root: &RootDir, link: &[u8]) -> LinkTarget {
    let root_parts: Vec<Vec<u8>> = split(root.path().as_os_str().as_bytes()).collect();
    let Ok(target) = root.readlink(link) else {
        return LinkTarget::Broken;
    };
    let mut parent: Vec<Vec<u8>> = split(link).collect();
    parent.pop();
    let mut pos = if target.first() == Some(&b'/') {
        Pos::Above(0)
    } else {
        Pos::In(parent)
    };
    let mut rest: VecDeque<Vec<u8>> = split(&target).collect();
    let mut hops = 1usize;
    let mut last_kind = EntryType::Dir;

    loop {
        if let Pos::Above(n) = pos
            && n >= root_parts.len()
        {
            pos = Pos::In(Vec::new());
        }
        let Some(c) = rest.pop_front() else { break };
        if c == b"." {
            continue;
        }
        match &mut pos {
            Pos::Above(n) => {
                if c == b".." {
                    *n = n.saturating_sub(1);
                } else if *n < root_parts.len() && root_parts[*n] == c {
                    *n += 1;
                } else {
                    return LinkTarget::Outside;
                }
                last_kind = EntryType::Dir;
            }
            Pos::In(cur) => {
                if c == b".." {
                    if cur.pop().is_none() {
                        pos = Pos::Above(root_parts.len().saturating_sub(1));
                    }
                    last_kind = EntryType::Dir;
                    continue;
                }
                cur.push(c);
                let p = join(cur);
                let Ok(st) = root.lstat(&p) else {
                    return LinkTarget::Broken;
                };
                match st.kind {
                    EntryType::Symlink => {
                        hops += 1;
                        if hops > HOP_LIMIT {
                            return LinkTarget::HopLimit;
                        }
                        let Ok(t) = root.readlink(&p) else {
                            return LinkTarget::Broken;
                        };
                        cur.pop();
                        for part in split(&t).collect::<Vec<_>>().into_iter().rev() {
                            rest.push_front(part);
                        }
                        if t.first() == Some(&b'/') {
                            pos = Pos::Above(0);
                        }
                        last_kind = EntryType::Dir;
                    }
                    EntryType::Dir => last_kind = EntryType::Dir,
                    kind => {
                        if !rest.is_empty() {
                            return LinkTarget::Broken;
                        }
                        last_kind = kind;
                    }
                }
            }
        }
    }
    match pos {
        Pos::In(cur) => LinkTarget::InRoot {
            path: join(&cur),
            kind: last_kind,
        },
        Pos::Above(_) => LinkTarget::Outside,
    }
}

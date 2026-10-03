//! Lexical symlink resolution.
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
//!
//! Every readlink and every component step is charged to a [`Steps`] budget
//! shared by all links in the scan, and the walk holds a handle on
//! each directory it has entered, so one step costs one system call however
//! deep the tree is.

use std::collections::VecDeque;
use std::os::unix::ffi::OsStrExt;

use super::open::{DirHandle, EntryType, RootDir};

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
    /// The step budget ran out before the link was resolved.
    Budget,
    /// The walk could not hold a handle on a directory (descriptor limit),
    /// so the target is unknown.
    Unresolved,
}

/// The symlink-resolution step budget shared by every link in a scan.
#[derive(Debug)]
pub struct Steps {
    left: u64,
    exhausted: bool,
}

impl Steps {
    pub fn new(budget: u64) -> Steps {
        Steps {
            left: budget,
            exhausted: false,
        }
    }

    /// Charges one step, or reports that the budget is spent. Once spent it
    /// stays spent, so every later link is refused in order.
    fn charge(&mut self) -> bool {
        if self.left == 0 {
            self.exhausted = true;
            return false;
        }
        self.left -= 1;
        true
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted
    }
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

/// What a failed in-root open means for the link.
fn open_failure(e: &std::io::Error) -> LinkTarget {
    match e.raw_os_error() {
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOMEM) => LinkTarget::Unresolved,
        _ => LinkTarget::Broken,
    }
}

/// Resolves the link at in-root path `link`, charging `steps`.
pub fn resolve(root: &RootDir, link: &[u8], steps: &mut Steps) -> LinkTarget {
    let root_parts: Vec<Vec<u8>> = split(root.path().as_os_str().as_bytes()).collect();
    let mut parent: Vec<Vec<u8>> = split(link).collect();
    let Some(name) = parent.pop() else {
        return LinkTarget::Broken;
    };
    // Handles on each directory of the current in-root position, so
    // `dirs.len() == cur.len()` while every component of `cur` is a
    // directory.
    let mut dirs: Vec<DirHandle> = Vec::new();
    for c in &parent {
        if !steps.charge() {
            return LinkTarget::Budget;
        }
        match root.open_dir_at(dirs.last(), c) {
            Ok(h) => dirs.push(h),
            Err(e) => return open_failure(&e),
        }
    }
    if !steps.charge() {
        return LinkTarget::Budget;
    }
    let Ok(target) = root.readlink_at(dirs.last(), &name) else {
        return LinkTarget::Broken;
    };
    let mut pos = if target.first() == Some(&b'/') {
        dirs.clear();
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
            dirs.clear();
        }
        let Some(c) = rest.pop_front() else { break };
        if !steps.charge() {
            return LinkTarget::Budget;
        }
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
                        dirs.clear();
                    } else {
                        dirs.pop();
                    }
                    last_kind = EntryType::Dir;
                    continue;
                }
                let Ok(st) = root.lstat_at(dirs.last(), &c) else {
                    return LinkTarget::Broken;
                };
                match st.kind {
                    EntryType::Symlink => {
                        hops += 1;
                        if hops > HOP_LIMIT {
                            return LinkTarget::HopLimit;
                        }
                        if !steps.charge() {
                            return LinkTarget::Budget;
                        }
                        let Ok(t) = root.readlink_at(dirs.last(), &c) else {
                            return LinkTarget::Broken;
                        };
                        for part in split(&t).collect::<Vec<_>>().into_iter().rev() {
                            rest.push_front(part);
                        }
                        if t.first() == Some(&b'/') {
                            pos = Pos::Above(0);
                            dirs.clear();
                        }
                        last_kind = EntryType::Dir;
                    }
                    EntryType::Dir => {
                        match root.open_dir_at(dirs.last(), &c) {
                            Ok(h) => dirs.push(h),
                            Err(e) => return open_failure(&e),
                        }
                        cur.push(c);
                        last_kind = EntryType::Dir;
                    }
                    kind => {
                        if !rest.is_empty() {
                            return LinkTarget::Broken;
                        }
                        cur.push(c);
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

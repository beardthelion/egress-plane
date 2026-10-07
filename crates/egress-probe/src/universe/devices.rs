//! The `devices` universe: a bounded recursive listing of `/dev`
//! (depth at most 4) plus the depth-1 listing of every non-canonical
//! directory mount (KTD30), keeping char and block device nodes.
//!
//! `accessible` is whether the process can open the node for read or
//! write from the access check; a missing or unreadable `/dev` is an
//! unknown, never a short member set (KTD3, KTD18, R20).

use std::collections::BTreeSet;

use super::{
    MountLayout, abs, bfield, check_members, denial_reason, flagfield, ifield, member,
    mount_layout, tfield,
};
use crate::data::Budgets;
use crate::model::{Member, UnknownReason};
use crate::reader::{AccessMask, AccessResult, Denial, Meta, Mount, NodeType, Reader};

/// Enumerates `linux.devices`: char and block nodes under `dev` within
/// the depth budget, and under each non-canonical directory mount at
/// depth 1.
pub fn enumerate<R: Reader>(
    r: &mut R,
    mounts: &[Mount],
    u: &crate::data::Universe,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let MountLayout { dir_mounts, .. } = mount_layout(r, mounts)?;

    let mut found: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut queued: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut metas: Vec<(Vec<u8>, Meta)> = Vec::new();
    // `dev` is depth 0; entries it lists are depth 1, and a subdirectory
    // at depth d is opened only while d < dev-listing-depth.
    let mut queue: Vec<(Vec<u8>, u64)> = vec![(b"dev".to_vec(), 0)];
    let mut i = 0;
    while i < queue.len() {
        let (dir, depth) = queue[i].clone();
        i += 1;
        let entries = match r.list(&dir) {
            Ok(e) => e,
            // A dev tree that vanished mid-listing is not an absent
            // signature.
            Err(Denial::Absent) => return Err(UnknownReason::Unreadable),
            Err(d) => return Err(denial_reason(d)),
        };
        if entries.len() as u64 > budgets.entries_per_listing {
            return Err(UnknownReason::BudgetExceeded);
        }
        for (name, meta) in entries {
            let mut path = dir.clone();
            path.push(b'/');
            path.extend_from_slice(&name);
            match meta.kind {
                NodeType::Char | NodeType::Block => {
                    if found.insert(path.clone()) {
                        metas.push((path, meta));
                    }
                }
                NodeType::Dir
                    if depth + 1 < budgets.dev_listing_depth && queued.insert(path.clone()) =>
                {
                    queue.push((path, depth + 1));
                }
                _ => {}
            }
        }
    }
    for dir in dir_mounts {
        match r.list(&dir) {
            Ok(entries) => {
                if entries.len() as u64 > budgets.entries_per_listing {
                    return Err(UnknownReason::BudgetExceeded);
                }
                for (name, meta) in entries {
                    if !matches!(meta.kind, NodeType::Char | NodeType::Block) {
                        continue;
                    }
                    let mut path = dir.clone();
                    path.push(b'/');
                    path.extend_from_slice(&name);
                    if found.insert(path.clone()) {
                        metas.push((path, meta));
                    }
                }
            }
            Err(Denial::Absent) => {}
            Err(d) => return Err(denial_reason(d)),
        }
    }
    if metas.len() < u.min_members as usize {
        // /dev/null always exists; an empty listing is implausibly empty.
        return Err(UnknownReason::ImplausiblyEmpty);
    }
    let mut members = Vec::new();
    for (path, meta) in metas {
        let accessible = access_rw(r, &path)?;
        members.push(device_member(&path, meta, accessible));
    }
    check_members(&members, budgets)?;
    Ok(members)
}

fn access_rw(r: &mut impl Reader, path: &[u8]) -> Result<bool, UnknownReason> {
    let mut yes = false;
    for mask in [AccessMask::READ, AccessMask::WRITE] {
        match r.access(path, mask) {
            Ok(AccessResult::Granted) => yes = true,
            Ok(AccessResult::Refused) | Err(Denial::Absent) => {}
            Err(d) => return Err(denial_reason(d)),
        }
    }
    Ok(yes)
}

fn device_member(path: &[u8], meta: Meta, accessible: bool) -> Member {
    let node = match meta.kind {
        NodeType::Char => "char",
        NodeType::Block => "block",
        _ => "other",
    };
    let device = meta
        .device
        .map(|(major, minor)| format!("{major}:{minor}"))
        .unwrap_or_default();
    let abspath = abs(&path
        .split(|b| *b == b'/')
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>());
    member(
        vec![
            bfield("path", &abspath, true),
            tfield("node-type", node, true),
            ifield("mode", meta.mode as u64),
            ifield("uid", meta.uid as u64),
            ifield("gid", meta.gid as u64),
            tfield("device", &device, false),
            flagfield("accessible", accessible, false),
        ],
        super::lossy(&abspath),
    )
}

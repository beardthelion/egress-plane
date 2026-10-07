//! The `socket-files` universe: socket nodes found by `lstat` on
//! non-directory mount points and by depth-1 listings of the declared
//! directories and of every non-canonical directory mount (KTD30).
//!
//! A listed directory that does not exist contributes nothing; a listing
//! or metadata failure is the universe's unknown (KTD3). Each member
//! gets an access check; `writable` is a classification attribute.

use std::collections::BTreeMap;

use super::{
    MountLayout, bfield, check_members, denial_reason, flagfield, ifield, member, mount_layout,
};
use crate::data::Budgets;
use crate::model::{Member, UnknownReason};
use crate::reader::{AccessMask, AccessResult, Denial, Meta, Mount, NodeType, Reader};

/// Enumerates `linux.socket-files`: the fixed listing directories
/// (`run`, `var/run`, `tmp`, `tmp/.X11-unix`, `run/user/<euid>`), every
/// non-directory mount point that is a socket, and the depth-1 listing
/// of every non-canonical directory mount (KTD30).
pub fn enumerate<R: Reader>(
    r: &mut R,
    mounts: &[Mount],
    euid: Option<u32>,
    budgets: &Budgets,
) -> Result<Vec<Member>, UnknownReason> {
    let MountLayout {
        dir_mounts,
        socket_points,
    } = mount_layout(r, mounts)?;

    let mut dirs: Vec<Vec<u8>> = vec![b"run".to_vec(), b"tmp".to_vec(), b"tmp/.X11-unix".to_vec()];
    // `var/run` is an allowlisted hop: when it is a symlink its contents
    // are the `run` listing above and reporting them under `var/run/`
    // would double-count; when it is a real directory it is listed on
    // its own.
    match r.metadata(b"var/run") {
        Ok(meta) if meta.kind == NodeType::Dir => dirs.push(b"var/run".to_vec()),
        Ok(_) | Err(Denial::Absent) => {}
        Err(d) => return Err(denial_reason(d)),
    }
    if let Some(e) = euid {
        dirs.push(format!("run/user/{e}").into_bytes());
    }
    dirs.extend(dir_mounts);

    // Deduplicate by path: a socket reached through both a listing and a
    // mount point is one member.
    let mut found: BTreeMap<Vec<u8>, Meta> = BTreeMap::new();
    for dir in dirs {
        match r.list(&dir) {
            Ok(entries) => {
                if entries.len() as u64 > budgets.entries_per_listing {
                    return Err(UnknownReason::BudgetExceeded);
                }
                for (name, meta) in entries {
                    if meta.kind != NodeType::Socket {
                        continue;
                    }
                    let mut path = dir.clone();
                    path.push(b'/');
                    path.extend_from_slice(&name);
                    found.entry(path).or_insert(meta);
                }
            }
            // A listed directory that does not exist contributes nothing.
            Err(Denial::Absent) => {}
            Err(d) => return Err(denial_reason(d)),
        }
    }
    for (path, meta) in socket_points {
        found.entry(path).or_insert(meta);
    }

    let mut members = Vec::new();
    for (path, meta) in found {
        let writable = access_writable(r, &path)?;
        members.push(socket_member(&path, meta, writable));
    }
    check_members(&members, budgets)?;
    Ok(members)
}

fn access_writable(r: &mut impl Reader, path: &[u8]) -> Result<bool, UnknownReason> {
    match r.access(path, AccessMask::WRITE) {
        Ok(AccessResult::Granted) => Ok(true),
        Ok(AccessResult::Refused) => Ok(false),
        // A vanished path between listing and check contributes nothing.
        Err(Denial::Absent) => Ok(false),
        Err(d) => Err(denial_reason(d)),
    }
}

fn socket_member(path: &[u8], meta: Meta, writable: bool) -> Member {
    let mut abs = vec![b'/'];
    abs.extend_from_slice(path);
    member(
        vec![
            bfield("path", &abs, true),
            ifield("mode", meta.mode as u64),
            ifield("uid", meta.uid as u64),
            ifield("gid", meta.gid as u64),
            ifield("size", meta.size),
            flagfield("writable", writable, false),
        ],
        super::lossy(&abs),
    )
}

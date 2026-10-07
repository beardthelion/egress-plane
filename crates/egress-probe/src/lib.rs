//! The environment escape probe (KTD4, KTD9, KTD11, KTD12, KTD24, KTD26,
//! KTD31).
//!
//! Every probe input goes through one reader abstraction
//! ([`reader::Reader`]): errno-preserving reads, metadata, access checks,
//! `readlink`, and directory listings, all gated by the mount table, the
//! kernel-filesystem checks, the allowlisted hop policy, and the
//! metadata-only signal resolution. The same trait drives the live run
//! and the snapshot reader, which exists only behind the `snapshot`
//! feature so the released binary cannot replay a snapshot.

pub mod facts;
pub mod integrity;
pub mod reader;
#[cfg(feature = "snapshot")]
pub mod snapshot;

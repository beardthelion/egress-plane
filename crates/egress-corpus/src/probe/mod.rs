//! Snapshot corpus harness for the environment probe.
//!
//! Cases live at `fixtures/probe/<platform>/<category>/<case>/` (see
//! [`labels`] for `facts.toml`, `manifest.toml`, and `expected.toml`). A run
//! validates every case file, hands the case directory to a scan function
//! that returns rendered JSON and text plus the snapshot reader's read log,
//! and compares them per KTD13 (see [`compare`]). The pending ledger follows
//! the same rules as the code corpus: a pending case that passes fails the
//! run, and a stale entry fails it.

pub mod compare;
pub mod labels;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use egress_core::model::ToolError;

use crate::probe::compare::CaseContext;
use crate::probe::labels::{Facts, Manifest, NodeKind};
use crate::{Case, CaseResult, Pending, RunSummary};

/// Platform directories under `fixtures/probe/`.
pub const PLATFORMS: [&str; 2] = ["linux", "macos"];

/// Category directories under each platform.
pub const CATEGORIES: [&str; 4] = ["layers", "routes", "completeness", "rules"];

/// Output of one probe run over a snapshot case.
///
/// The probe crate defines an identical type behind its `snapshot` feature;
/// this harness owns its own so `egress-corpus` carries no normal dependency
/// on probe internals (the corpus compares rendered output, KTD13).
#[derive(Debug, Clone)]
pub struct ScanOutput {
    /// The JSON report, exactly as stdout would carry it.
    pub json: String,
    /// The text report.
    pub text: String,
    /// Every call the snapshot reader performed, in order.
    pub read_log: Vec<ReadLogEntry>,
}

/// One call the snapshot reader performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadLogEntry {
    pub kind: ReadCall,
    /// Resolved path inside the case root: `/`-separated, no leading slash,
    /// allowlisted hops already applied.
    pub path: String,
}

/// Reader call kinds the read log records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadCall {
    /// File contents.
    Read,
    /// Directory listing.
    List,
    /// File metadata (`lstat`-style).
    Metadata,
    /// Access check.
    Access,
    /// Symlink target.
    Readlink,
}

/// Lists every probe case directory, sorted by id. Directories in the wrong
/// place and cases missing `tree/`, `facts.toml`, or `expected.toml` are
/// errors, so a misplaced case cannot be skipped silently.
pub fn discover_cases(corpus_root: &Path) -> Result<Vec<Case>, String> {
    let mut errors = Vec::new();
    let mut cases = Vec::new();
    for (platform, platform_dir) in subdirs(corpus_root, &mut errors) {
        if !PLATFORMS.contains(&platform.as_str()) {
            errors.push(format!("{platform}: unknown probe platform directory"));
            continue;
        }
        for (category, category_dir) in subdirs(&platform_dir, &mut errors) {
            if !CATEGORIES.contains(&category.as_str()) {
                errors.push(format!(
                    "{platform}/{category}: unknown probe category directory"
                ));
                continue;
            }
            for (name, dir) in subdirs(&category_dir, &mut errors) {
                let id = format!("{platform}/{category}/{name}");
                if !dir.join("tree").is_dir() {
                    errors.push(format!("{id}: case has no tree/ directory"));
                    continue;
                }
                if !dir.join("facts.toml").is_file() {
                    errors.push(format!("{id}: case has no facts.toml"));
                    continue;
                }
                if !dir.join("expected.toml").is_file() {
                    errors.push(format!("{id}: case has no expected.toml"));
                    continue;
                }
                cases.push(Case { id, dir });
            }
        }
    }
    if errors.is_empty() {
        Ok(cases)
    } else {
        Err(errors.join("\n"))
    }
}

fn subdirs(dir: &Path, errors: &mut Vec<String>) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            errors.push(format!("{}: cannot list: {e}", dir.display()));
            return out;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        match entry.file_name().into_string() {
            Ok(name) => out.push((name, path)),
            Err(_) => errors.push(format!("{}: non-UTF-8 directory name", path.display())),
        }
    }
    out.sort();
    out
}

/// Runs every probe case under `corpus_root` through `scan`.
///
/// `scan` takes the case directory and returns rendered JSON and text plus
/// the snapshot read log; a `ToolError` fails the case. Malformed case files
/// are run-level harness errors, not case failures.
pub fn run<F>(corpus_root: &Path, pending: &Pending, scan: F) -> RunSummary
where
    F: Fn(&Path) -> Result<ScanOutput, ToolError>,
{
    let mut summary = RunSummary::default();
    let mut cases = Vec::new();
    match discover_cases(corpus_root) {
        Ok(c) => cases = c,
        Err(e) => {
            summary.errors.extend(e.lines().map(str::to_string));
        }
    }

    let ids: BTreeSet<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    for p in &pending.cases {
        if !ids.contains(p.as_str()) {
            summary.errors.push(format!(
                "{p}: pending.toml names a case that does not exist; remove the entry"
            ));
        }
    }

    for case in cases {
        let ctx = match load_case(&case) {
            Ok(ctx) => ctx,
            Err(e) => {
                summary.errors.push(e);
                continue;
            }
        };
        let is_pending = pending.cases.contains(&case.id);
        let outcome = compare::compare(&ctx.expected, &ctx.context, &scan(&case.dir));
        match (is_pending, outcome.passed()) {
            (false, false) => summary.errors.push(format!(
                "{}: case fails:\n    {}",
                case.id,
                outcome.failures.join("\n    ")
            )),
            (true, true) => summary.errors.push(format!(
                "{}: pending case now passes; remove it from pending.toml",
                case.id
            )),
            _ => {}
        }
        summary.cases.push(CaseResult {
            id: case.id,
            pending: is_pending,
            outcome,
        });
    }
    summary
}

/// A fully validated case: labels, plus the filesystem facts the read-log
/// assertions need.
struct LoadedCase {
    expected: labels::Expected,
    context: CaseContext,
}

/// Reads and validates `expected.toml`, `facts.toml`, and `manifest.toml`,
/// and derives the no-touch path sets for the read-log assertions.
fn load_case(case: &Case) -> Result<LoadedCase, String> {
    let origin = &case.id;
    let read = |name: &str| -> Result<String, String> {
        std::fs::read_to_string(case.dir.join(name))
            .map_err(|e| format!("{origin}: cannot read {name}: {e}"))
    };
    let expected = labels::parse_expected(&read("expected.toml")?, origin)?;
    let facts = labels::parse_facts(&read("facts.toml")?, origin)?;
    let manifest = if case.dir.join("manifest.toml").is_file() {
        let m = labels::parse_manifest(&read("manifest.toml")?, origin)?;
        labels::check_manifest_tree(&m, &case.tree(), origin)?;
        m
    } else {
        Manifest::default()
    };
    let platform = case.id.split('/').next().unwrap_or_default();
    if facts.platform != platform {
        return Err(format!(
            "{origin}: facts.toml has platform {:?} but the case lives under {platform}",
            facts.platform
        ));
    }
    let name = case.id.rsplit('/').next().unwrap_or_default();
    if name.starts_with("must-not-")
        && expected.absent_text.is_empty()
        && expected.absent_routes.is_empty()
    {
        return Err(format!(
            "{origin}: a must-not case needs `absent_text` or `absent_routes`"
        ));
    }
    Ok(LoadedCase {
        expected,
        context: case_context(case, &facts, &manifest, platform),
    })
}

/// Builds the read-log context: the mount table the case presents (unless
/// the manifest makes it unreadable to the probe) and the manifest paths
/// overridden onto a no-touch filesystem.
fn case_context(case: &Case, facts: &Facts, manifest: &Manifest, platform: &str) -> CaseContext {
    // The mountinfo read goes through the `proc/self` hop, so a manifest
    // error node on the resolved path means the probe could not read it.
    let mountinfo_err = manifest.nodes.iter().any(|n| {
        n.kind == NodeKind::Error
            && (n.path == "proc/self/mountinfo"
                || n.path == format!("proc/{}/mountinfo", facts.pid))
    });
    let mut mounts = Vec::new();
    if !mountinfo_err
        && let Ok(text) = std::fs::read_to_string(case.tree().join("proc/self/mountinfo"))
    {
        mounts = compare::parse_mountinfo_mounts(&text);
    }
    let no_touch_overrides = manifest
        .nodes
        .iter()
        .filter(|n| n.fs.as_deref().is_some_and(compare::is_no_touch_fstype))
        .map(|n| compare::components(&n.path))
        .collect();
    CaseContext {
        mounts,
        no_touch_overrides,
        platform: platform.to_string(),
    }
}

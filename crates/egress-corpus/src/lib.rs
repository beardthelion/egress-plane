//! Fixture corpus harness.
//!
//! Each case lives at `fixtures/corpus/<language>/<category>/<case>/` with a
//! `tree/` scan root and an `expected.toml` (see [`labels`]). A run scans every
//! case, compares it with its labels (see [`compare`]), and fails on any case
//! that fails outside `pending.toml`, on any pending case that passes (its
//! entry must be removed), on a stale ledger entry, and on any malformed case.
//!
//! # Label conventions
//!
//! These conventions bind every detector: the labels were authored before any
//! detector existed, and the detectors are written to match them.
//!
//! - `file` is repo-relative to `tree/` with `/` separators. A whole-file blind
//!   spot, a hook, and a non-construct gap use symbol `<module>`.
//! - `symbol` is the enclosing symbol path: Python qualname (`Api.fetch`), JS function, class
//!   member (`Api.list`, `Api.constructor`), `const` binding, or object key
//!   (`api.post`), Rust free function or `<impl Type>::method`; `<module>` at
//!   top level.
//! - `mechanism` is the data entry ID `<language>:<path>`. Python and JS join
//!   the module and member chain with `.` (`python:urllib.request.urlopen`,
//!   `javascript:https.get`, with `node:` stripped); JS ambient globals are
//!   members of `globalThis` (`javascript:globalThis.fetch`); Rust uses its own
//!   path syntax (`rust:std::net::TcpStream::connect`). A method on a tracked
//!   client instance appends the method to the constructor entry in
//!   Python and JS (`python:requests.Session.get`, `javascript:axios.create.get`)
//!   and to the type in Rust (`rust:reqwest::blocking::Client::get`). A module
//!   used as a value is a site whose mechanism is the module itself
//!   (`python:socket`) with destination `expr:<module>`.
//! - `destination` is the display form of the destination: a literal, `env:NAME`,
//!   `param:N:<symbol>`, a template with holes (`{env:BASE}/v1`),
//!   `exec:<program>`, `lib:<library>`, `host:port` for sockets, or
//!   `expr:<rendered source>`. A reference that is not itself called (a value
//!   use, a base class, a `functools.partial` argument) renders the reference:
//!   `expr:os.system`. A constructor called with no destination renders the
//!   call: `expr:requests.Session()`.
//! - A JS default import or a CommonJS `require` binding of a package names the
//!   module itself, so `import axios from "axios"; axios.get(u)` is
//!   `javascript:axios.get`. Rust renames (`package = "..."`) are undone first.
//! - A Rust `std::env::var(..)` read stays `env:NAME` through `.unwrap()`,
//!   `.expect(..)`, and `?`; a `format!` with resolvable parts is a template.
//! - An unscanned dependency is named by its import root: the Python top-level
//!   module (`yaml`), the npm package (`@acme/widgets`, `lodash` for
//!   `lodash/fp`), or the Rust crate after renames.
//! - A build-hook blind spot sits on the file that runs: `build.rs`, the script
//!   a Cargo `build` key names, `setup.py`, a `.pth` or `*customize.py` file, or
//!   `binding.gyp`. Hooks declared only in a manifest (npm lifecycle scripts,
//!   one blind spot per script; `proc-macro = true`; an in-tree
//!   `backend-path`) sit on that manifest.
//! - An in-root symlink to a regular file is reported once under the target's
//!   real path, with the link listed in `excluded` as `symlink-alias`. A path
//!   gap that is not a single file (`unconfirmed-exclusion`) uses the directory
//!   path as `file`.
//! - Rust symbols include inline `mod` blocks only (`tests::staging_up`); a
//!   file module, including one mapped by `#[path]`, starts a fresh path.
//! - Case directory names starting with `must-not-` hold constructs that must
//!   produce no finding beyond their labels; any extra finding there shows up
//!   as a false positive in `target/corpus-report.json`.
//! - Every labeled finding is required in every category. Missed
//!   blind spots fail only `evasive` and `closure` cases; this harness also
//!   requires the blind spots a `completeness` or other case labels, since an
//!   unenforced label would assert nothing.

pub mod compare;
pub mod labels;
pub mod probe;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use egress_core::model::{Report, ToolError};
use serde::Deserialize;

use crate::compare::CaseOutcome;

/// Language directories under the corpus root.
pub const LANGUAGES: [&str; 4] = ["python", "javascript", "rust", "mixed"];

/// Category directories. `primitives` holds the one-per-entry cases.
pub const CATEGORIES: [&str; 6] = [
    "ordinary",
    "tricky",
    "evasive",
    "closure",
    "primitives",
    "completeness",
];

/// The pending ledger: cases not yet expected to pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pending {
    pub cases: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPending {
    cases: Vec<String>,
}

/// Parses `pending.toml`. A duplicate entry is an error.
pub fn parse_pending(text: &str, origin: &str) -> Result<Pending, String> {
    let raw: RawPending =
        toml::from_str(text).map_err(|e| format!("{origin}: malformed pending ledger: {e}"))?;
    let mut cases = BTreeSet::new();
    for c in raw.cases {
        if !cases.insert(c.clone()) {
            return Err(format!("{origin}: duplicate pending entry {c}"));
        }
    }
    Ok(Pending { cases })
}

pub fn load_pending(path: &Path) -> Result<Pending, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    parse_pending(&text, &origin)
}

/// One corpus case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// `<language>/<category>/<case>`.
    pub id: String,
    pub dir: PathBuf,
}

impl Case {
    pub fn tree(&self) -> PathBuf {
        self.dir.join("tree")
    }

    pub fn category(&self) -> &str {
        self.id.split('/').nth(1).unwrap_or_default()
    }
}

/// Lists every case directory, sorted by ID. Directories in the wrong place
/// and cases missing `tree/` or `expected.toml` are errors, so a misplaced
/// case cannot be skipped silently.
pub fn discover_cases(corpus_root: &Path) -> Result<Vec<Case>, String> {
    let mut errors = Vec::new();
    let cases = discover(corpus_root, &mut errors);
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

fn discover(corpus_root: &Path, errors: &mut Vec<String>) -> Vec<Case> {
    let mut cases = Vec::new();
    for (lang, lang_dir) in subdirs(corpus_root, errors) {
        if !LANGUAGES.contains(&lang.as_str()) {
            errors.push(format!("{lang}: unknown corpus language directory"));
            continue;
        }
        for (cat, cat_dir) in subdirs(&lang_dir, errors) {
            if !CATEGORIES.contains(&cat.as_str()) {
                errors.push(format!("{lang}/{cat}: unknown corpus category directory"));
                continue;
            }
            for (name, dir) in subdirs(&cat_dir, errors) {
                let id = format!("{lang}/{cat}/{name}");
                if !dir.join("tree").is_dir() {
                    errors.push(format!("{id}: case has no tree/ directory"));
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
    cases
}

/// Result of one case in a run.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub id: String,
    pub pending: bool,
    pub outcome: CaseOutcome,
}

/// Result of a corpus run.
#[derive(Debug, Clone, Default)]
pub struct RunSummary {
    /// Reasons the run fails. Empty means the run passes.
    pub errors: Vec<String>,
    pub cases: Vec<CaseResult>,
}

impl RunSummary {
    pub fn passed(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn false_positive_count(&self) -> usize {
        self.cases
            .iter()
            .map(|c| c.outcome.false_positives.len())
            .sum()
    }

    /// A short human summary for test output.
    pub fn render(&self) -> String {
        let pending = self.cases.iter().filter(|c| c.pending).count();
        let passing = self.cases.iter().filter(|c| c.outcome.passed()).count();
        let mut s = format!(
            "corpus: {} cases, {} passing, {} pending, {} false positives\n",
            self.cases.len(),
            passing,
            pending,
            self.false_positive_count()
        );
        for c in &self.cases {
            for fp in &c.outcome.false_positives {
                s.push_str(&format!("  false positive in {}: {fp}\n", c.id));
            }
        }
        for e in &self.errors {
            s.push_str(&format!("  FAIL {e}\n"));
        }
        s
    }

    /// The machine-readable summary written to `target/corpus-report.json`.
    pub fn to_json(&self) -> String {
        let cases: Vec<serde_json::Value> = self
            .cases
            .iter()
            .map(|c| {
                serde_json::json!({
                    "case": c.id,
                    "pending": c.pending,
                    "passed": c.outcome.passed(),
                    "failures": c.outcome.failures,
                    "false_positives": c.outcome.false_positives,
                })
            })
            .collect();
        let v = serde_json::json!({
            "passed": self.passed(),
            "false_positive_count": self.false_positive_count(),
            "errors": self.errors,
            "cases": cases,
        });
        let mut s = serde_json::to_string_pretty(&v).unwrap_or_default();
        s.push('\n');
        s
    }
}

/// Runs every case under `corpus_root` through `scan`.
pub fn run_corpus<F>(corpus_root: &Path, pending: &Pending, scan: F) -> RunSummary
where
    F: Fn(&Path) -> Result<Report, ToolError>,
{
    let mut summary = RunSummary::default();
    let cases = discover(corpus_root, &mut summary.errors);

    let ids: BTreeSet<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    for p in &pending.cases {
        if !ids.contains(p.as_str()) {
            summary.errors.push(format!(
                "{p}: pending.toml names a case that does not exist; remove the entry"
            ));
        }
    }

    for case in cases {
        let is_pending = pending.cases.contains(&case.id);
        let expected = match std::fs::read_to_string(case.dir.join("expected.toml"))
            .map_err(|e| format!("{}: cannot read expected.toml: {e}", case.id))
            .and_then(|text| labels::parse_expected(&text, &case.id))
        {
            Ok(e) => e,
            Err(e) => {
                summary.errors.push(e);
                continue;
            }
        };
        let outcome = compare::compare(&expected, &scan(&case.tree()));
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

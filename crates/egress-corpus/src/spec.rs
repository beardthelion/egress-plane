//! Spec matrix and technique ledger loaders and guards (R4, R5, R8, R9;
//! KTD5, KTD6).
//!
//! `evasive-spec.toml` and `closure-spec.toml` hold one `[[row]]` per
//! planned case/twin pair: the label is fixed before any source exists,
//! the `twin` is the `must-not-` sibling that differs on the row's `axis`
//! alone, and `status` tracks authoring (`pending`, `authored`, or
//! `refused-by-safety-check`; a refused row must carry a class-only
//! `note`). `techniques.toml` holds one `[[technique]]` per paraphrased
//! technique class drawn from the public collections, recording source,
//! license, revision pin, proposed `covered_by`, and the proving case.
//!
//! Parse-time rules reject malformed rows outright; the `check_*`
//! functions return every violation they find so one report lists all
//! of them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use egress_core::model::{BlindSpotKind, Language};
use serde::Deserialize;

/// The two spec files and the vocabulary each one's `family` key draws
/// from. `family` on a closure row is a KTD5 closure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecKind {
    Evasive,
    Closure,
}

/// Evasive family vocabulary (code plan KTD15).
pub const EVASIVE_FAMILIES: [&str; 6] = [
    "dynamic-loading",
    "reflective-access",
    "scope-injection",
    "import-system-mutation",
    "introspection-roots",
    "native-and-macro-code",
];

/// Closure class vocabulary (code plan KTD5).
pub const CLOSURE_CLASSES: [&str; 5] = [
    "module-escape",
    "value-use",
    "constructor-return",
    "ambient-module",
    "untracked-receiver",
];

/// `covered_by` values that are neither a family nor a closure class.
pub const OUTSIDE_COVERAGE: [&str; 2] = [
    "outside-egress:local-io",
    "outside-scope:unscanned-dependency",
];

/// The collections the ledger seeds from (plan Sources / Research),
/// each with the license it is listed under. The vm2 advisories entry
/// also covers its `GHSA-...` subpages.
pub const SOURCES: [(&str, &str); 5] = [
    ("https://github.com/swisskyrepo/PayloadsAllTheThings", "MIT"),
    (
        "https://hacktricks.wiki/en/generic-methodologies-and-resources/python/bypass-python-sandboxes/index.html",
        "CC-BY-SA-4.0",
    ),
    ("https://github.com/jailctf/pyjailbreaker", "none-detected"),
    (
        "https://github.com/salvatore-abello/python-ctf-cheatsheet",
        "none-detected",
    ),
    (
        "https://github.com/patriksimek/vm2/security/advisories",
        "MIT",
    ),
];

const VM2_ADVISORIES: &str = "https://github.com/patriksimek/vm2/security/advisories";

impl SpecKind {
    /// File name under the corpus root.
    pub fn file(self) -> &'static str {
        match self {
            Self::Evasive => "evasive-spec.toml",
            Self::Closure => "closure-spec.toml",
        }
    }

    /// Corpus category the file's rows author.
    pub fn category(self) -> &'static str {
        match self {
            Self::Evasive => "evasive",
            Self::Closure => "closure",
        }
    }

    /// The `family` vocabulary for this file's rows.
    pub fn vocabulary(self) -> &'static [&'static str] {
        match self {
            Self::Evasive => &EVASIVE_FAMILIES,
            Self::Closure => &CLOSURE_CLASSES,
        }
    }

    /// Whether the family or closure class applies to the language
    /// (the applicability table beside the row schema in the plan).
    pub fn applies(self, family: &str, language: Language) -> bool {
        let py_js = matches!(language, Language::Python | Language::Javascript);
        let py_js_rs = py_js || language == Language::Rust;
        match self {
            Self::Evasive => match family {
                "dynamic-loading"
                | "reflective-access"
                | "scope-injection"
                | "import-system-mutation"
                | "introspection-roots" => py_js,
                "native-and-macro-code" => language == Language::Rust,
                _ => false,
            },
            Self::Closure => match family {
                "module-escape" | "value-use" | "constructor-return" => py_js_rs,
                "ambient-module" | "untracked-receiver" => py_js,
                _ => false,
            },
        }
    }
}

/// A row's authoring state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowStatus {
    /// Case and twin are written and gated.
    Authored,
    /// A model safety check stopped authoring; `note` names the class.
    RefusedBySafetyCheck,
    /// Label fixed, snippets not yet written.
    Pending,
}

impl RowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authored => "authored",
            Self::RefusedBySafetyCheck => "refused-by-safety-check",
            Self::Pending => "pending",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "authored" => Some(Self::Authored),
            "refused-by-safety-check" => Some(Self::RefusedBySafetyCheck),
            "pending" => Some(Self::Pending),
            _ => None,
        }
    }
}

/// The label a row fixes before any source exists. `kind` is `site` or
/// a `BlindSpotKind`; `symbol` is the enclosing symbol; `count` is the
/// number of findings of that kind the case labels. `absent_text`
/// carries labels like the AE23 placeholder token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecLabel {
    pub kind: String,
    pub symbol: String,
    pub count: u64,
    pub absent_text: Vec<String>,
}

/// One spec row: a planned case and its `must-not-` twin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecRow {
    /// Case id `<language>/<evasive or closure>/<kebab-case-name>`.
    pub case: String,
    pub language: Language,
    /// Evasive family or closure class, from the fixed vocabulary.
    pub family: String,
    pub label: SpecLabel,
    /// The `must-not-` twin case id.
    pub twin: String,
    /// The single axis on which the twin differs.
    pub axis: String,
    pub status: RowStatus,
    /// Class-only refusal note; required when refused.
    pub note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSpec {
    #[serde(default)]
    row: Vec<RawRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRow {
    case: String,
    language: String,
    family: String,
    label: RawLabel,
    twin: String,
    axis: String,
    status: String,
    note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLabel {
    kind: String,
    symbol: String,
    count: u64,
    #[serde(default)]
    absent_text: Vec<String>,
}

/// A case id must be `<lang>/<category>/<name>` matching the row's
/// language and the spec file's category, with a kebab-case name and no
/// `.` or `..` segment.
fn check_case_id(origin: &str, id: &str, kind: SpecKind, language: Language) -> Result<(), String> {
    let err = |m: String| format!("{origin}: row {id}: {m}");
    let segs: Vec<&str> = id.split('/').collect();
    if segs.len() != 3 {
        return Err(err(format!(
            "case id must be <language>/{}/<kebab-case-name>",
            kind.category()
        )));
    }
    if segs[0] != language.as_str() {
        return Err(err(format!(
            "case id names {} but language is {}",
            segs[0],
            language.as_str()
        )));
    }
    if segs[1] != kind.category() {
        return Err(err(format!("case id must sit under {}", kind.category())));
    }
    let name = segs[2];
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(err(format!("{name:?} is not a kebab-case name")));
    }
    Ok(())
}

/// Parses a spec matrix file. `origin` names the file in every error;
/// `kind` selects the category and family vocabulary.
pub fn parse_spec(text: &str, origin: &str, kind: SpecKind) -> Result<Vec<SpecRow>, String> {
    let raw: RawSpec =
        toml::from_str(text).map_err(|e| format!("{origin}: malformed spec matrix: {e}"))?;
    let mut rows = Vec::new();
    let mut seen_cases = BTreeSet::new();
    let mut seen_twins = BTreeSet::new();
    for r in raw.row {
        let err = |m: String| format!("{origin}: row {}: {m}", r.case);
        let language = Language::parse(&r.language)
            .ok_or_else(|| err(format!("unknown language {:?}", r.language)))?;
        check_case_id(origin, &r.case, kind, language)?;
        if r.case
            .rsplit('/')
            .next()
            .is_some_and(|n| n.starts_with("must-not-"))
        {
            return Err(err(
                "the case is the positive side; the must-not case is the twin".to_string(),
            ));
        }
        check_case_id(origin, &r.twin, kind, language)?;
        if !r
            .twin
            .rsplit('/')
            .next()
            .is_some_and(|n| n.starts_with("must-not-"))
        {
            return Err(err(format!("twin {} lacks the must-not- prefix", r.twin)));
        }
        if r.case == r.twin {
            return Err(err("case and twin are the same id".to_string()));
        }
        if !seen_cases.insert(r.case.clone()) {
            return Err(err("duplicate case id".to_string()));
        }
        if !seen_twins.insert(r.twin.clone()) {
            return Err(err(format!("duplicate twin id {}", r.twin)));
        }
        if !kind.vocabulary().contains(&r.family.as_str()) {
            return Err(err(format!(
                "family {:?} is not in the {} vocabulary",
                r.family,
                kind.category()
            )));
        }
        if !kind.applies(&r.family, language) {
            return Err(err(format!(
                "family {} does not apply to {}",
                r.family,
                language.as_str()
            )));
        }
        if r.label.kind != "site" && BlindSpotKind::parse(&r.label.kind).is_none() {
            return Err(err(format!("unknown label kind {:?}", r.label.kind)));
        }
        if r.label.symbol.trim().is_empty() {
            return Err(err("label has no symbol".to_string()));
        }
        if r.label.count == 0 {
            return Err(err("label count must be at least 1".to_string()));
        }
        for t in &r.label.absent_text {
            if t.trim().is_empty() {
                return Err(err("empty absent_text entry".to_string()));
            }
        }
        if r.axis.trim().is_empty() {
            return Err(err("axis is empty".to_string()));
        }
        let status = RowStatus::parse(&r.status)
            .ok_or_else(|| err(format!("unknown status {:?}", r.status)))?;
        if status == RowStatus::RefusedBySafetyCheck
            && r.note.as_deref().is_none_or(|n| n.trim().is_empty())
        {
            return Err(err(
                "refused-by-safety-check requires a note naming the refused class".to_string(),
            ));
        }
        rows.push(SpecRow {
            case: r.case,
            language,
            family: r.family,
            label: SpecLabel {
                kind: r.label.kind,
                symbol: r.label.symbol,
                count: r.label.count,
                absent_text: r.label.absent_text,
            },
            twin: r.twin,
            axis: r.axis,
            status,
            note: r.note.filter(|n| !n.trim().is_empty()),
        });
    }
    Ok(rows)
}

/// Loads a spec matrix file.
pub fn load_spec(path: &Path, kind: SpecKind) -> Result<Vec<SpecRow>, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    parse_spec(&text, &origin, kind)
}

/// Coverage: every family or closure class has at least one row per
/// applicable language.
pub fn check_coverage(rows: &[SpecRow], kind: SpecKind) -> Vec<String> {
    let mut errors = Vec::new();
    for family in kind.vocabulary() {
        for language in [Language::Python, Language::Javascript, Language::Rust] {
            if !kind.applies(family, language) {
                continue;
            }
            if !rows
                .iter()
                .any(|r| r.family == *family && r.language == language)
            {
                errors.push(format!(
                    "{}: family {family} has no row for {}",
                    kind.file(),
                    language.as_str()
                ));
            }
        }
    }
    errors
}

/// Rows that keep Definition of Done open: anything not yet `authored`.
pub fn incomplete_rows(rows: &[SpecRow]) -> Vec<String> {
    rows.iter()
        .filter(|r| r.status != RowStatus::Authored)
        .map(|r| {
            format!(
                "{}: status {} keeps the spec matrix incomplete",
                r.case,
                r.status.as_str()
            )
        })
        .collect()
}

/// Files of a case's `tree/` keyed by relative path.
fn tree_files(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)
            .map_err(|e| format!("{}: cannot list: {e}", d.display()))?
            .flatten()
        {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                let rel = p
                    .strip_prefix(dir)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes =
                    std::fs::read(&p).map_err(|e| format!("{}: cannot read: {e}", p.display()))?;
                out.insert(rel, String::from_utf8_lossy(&bytes).into_owned());
            }
        }
    }
    Ok(out)
}

/// Added-plus-removed lines in a minimal line diff, capped by size so a
/// hostile pair cannot make the quadratic LCS expensive.
fn changed_lines(a: &str, b: &str) -> usize {
    let av: Vec<&str> = a.lines().collect();
    let bv: Vec<&str> = b.lines().collect();
    let (n, m) = (av.len(), bv.len());
    if n * m > 1_000_000 {
        return n + m;
    }
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if av[i] == bv[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    (n - dp[0][0]) + (m - dp[0][0])
}

fn case_dir_exists(dir: &Path) -> bool {
    dir.join("tree").is_dir() && dir.join("expected.toml").is_file()
}

/// Guards that need the corpus on disk: for `authored` rows the case
/// and twin exist, the twin's `tree/` has the same file set as the
/// case's, and the line diff between them is confined to one file and
/// at most 3 changed lines. `pending` and `refused-by-safety-check`
/// rows name cases that do not exist yet and are skipped.
pub fn check_authored(corpus_root: &Path, rows: &[SpecRow]) -> Vec<String> {
    let mut errors = Vec::new();
    for r in rows {
        if r.status != RowStatus::Authored {
            continue;
        }
        let err = |m: String| format!("{}: axis {}: {m}", r.case, r.axis);
        let case_dir = corpus_root.join(&r.case);
        let twin_dir = corpus_root.join(&r.twin);
        if !case_dir_exists(&case_dir) {
            errors.push(err(format!("case {} does not exist", r.case)));
            continue;
        }
        if !case_dir_exists(&twin_dir) {
            errors.push(err(format!("twin {} does not exist", r.twin)));
            continue;
        }
        let (case_files, twin_files) = match (
            tree_files(&case_dir.join("tree")),
            tree_files(&twin_dir.join("tree")),
        ) {
            (Ok(c), Ok(t)) => (c, t),
            (Err(e), _) | (_, Err(e)) => {
                errors.push(err(e));
                continue;
            }
        };
        let case_set: BTreeSet<&String> = case_files.keys().collect();
        let twin_set: BTreeSet<&String> = twin_files.keys().collect();
        if case_set != twin_set {
            errors.push(err(format!(
                "twin {} tree file set differs from the case's",
                r.twin
            )));
            continue;
        }
        let differing: Vec<&String> = case_files
            .iter()
            .filter(|(p, c)| twin_files.get(*p) != Some(c))
            .map(|(p, _)| p)
            .collect();
        if differing.len() > 1 {
            errors.push(err(format!(
                "case and twin differ in {} files",
                differing.len()
            )));
            continue;
        }
        if let Some(p) = differing.first() {
            let changed = changed_lines(&case_files[*p], &twin_files[*p]);
            if changed > 3 {
                errors.push(err(format!(
                    "case and twin differ in {changed} lines of {p}, at most 3 allowed"
                )));
            }
        }
    }
    errors
}

/// The offline replay state of a ledger row (KTD6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// The replay ran and the expected entry appeared.
    Scanned,
    /// The class has no runnable form; seeded by class only.
    ClassOnly,
    /// Not yet replayed.
    Pending,
}

impl Replay {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "scanned" => Some(Self::Scanned),
            "class-only" => Some(Self::ClassOnly),
            "pending" => Some(Self::Pending),
            _ => None,
        }
    }
}

/// One technique ledger row: a paraphrased technique class from a
/// public collection, pinned by revision, mapped to the family or
/// closure class that covers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Technique {
    /// Plain-English technique class, paraphrased.
    pub class: String,
    pub language: Language,
    /// Collection URL.
    pub source: String,
    /// SPDX id or `none-detected`.
    pub license: String,
    /// Family, closure class, `gap`, or an `outside-*` value.
    pub covered_by: String,
    /// Proving case id; required unless `covered_by` is `gap` or an
    /// `outside-*` value.
    pub case: Option<String>,
    /// Commit SHA for a git source, `sha256:<hex>@<YYYY-MM-DD>` for a
    /// web page.
    pub revision: String,
    pub replay: Replay,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTechniques {
    #[serde(default)]
    technique: Vec<RawTechnique>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTechnique {
    class: String,
    language: String,
    source: String,
    license: String,
    covered_by: String,
    case: Option<String>,
    revision: Option<String>,
    replay: String,
}

/// Whether a `covered_by` value is in the vocabulary: a family, a
/// closure class, `gap`, or an `outside-*` value.
pub fn covered_by_known(v: &str) -> bool {
    EVASIVE_FAMILIES.contains(&v)
        || CLOSURE_CLASSES.contains(&v)
        || v == "gap"
        || OUTSIDE_COVERAGE.contains(&v)
}

/// The license a source URL is listed under, or `None` when the source
/// is not one of the seeded collections. vm2 `GHSA-...` subpages share
/// the advisories entry.
pub fn source_license(source: &str) -> Option<&'static str> {
    for (url, license) in SOURCES {
        if source == url {
            return Some(license);
        }
        if url == VM2_ADVISORIES && source.starts_with(&format!("{VM2_ADVISORIES}/GHSA-")) {
            return Some(license);
        }
    }
    None
}

fn valid_revision(rev: &str) -> bool {
    if rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if let Some(rest) = rev.strip_prefix("sha256:")
        && let Some((hex, date)) = rest.split_once('@')
    {
        let date_ok = date.len() == 10
            && date.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            });
        return hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) && date_ok;
    }
    false
}

/// Parses `techniques.toml`. `origin` names the file in every error.
pub fn parse_techniques(text: &str, origin: &str) -> Result<Vec<Technique>, String> {
    let raw: RawTechniques =
        toml::from_str(text).map_err(|e| format!("{origin}: malformed technique ledger: {e}"))?;
    let mut rows = Vec::new();
    for t in raw.technique {
        let err = |m: String| format!("{origin}: technique {}: {m}", t.class);
        if t.class.trim().is_empty() {
            return Err(format!("{origin}: a technique row has no class"));
        }
        let language = Language::parse(&t.language)
            .ok_or_else(|| err(format!("unknown language {:?}", t.language)))?;
        if !matches!(language, Language::Python | Language::Javascript) {
            return Err(err(format!(
                "language must be python or javascript, not {}",
                language.as_str()
            )));
        }
        if t.source.trim().is_empty() {
            return Err(err("source is empty".to_string()));
        }
        if t.license.trim().is_empty() {
            return Err(err("license is empty".to_string()));
        }
        if !covered_by_known(&t.covered_by) {
            return Err(err(format!(
                "covered_by {:?} is not in the vocabulary",
                t.covered_by
            )));
        }
        let outside = t.covered_by == "gap" || OUTSIDE_COVERAGE.contains(&t.covered_by.as_str());
        if !outside && t.case.as_deref().is_none_or(|c| c.trim().is_empty()) {
            return Err(err("names no case".to_string()));
        }
        let revision = t
            .revision
            .filter(|r| !r.trim().is_empty())
            .ok_or_else(|| err("has no revision".to_string()))?;
        if !valid_revision(&revision) {
            return Err(err(format!(
                "revision {revision:?} is neither a 40-hex commit SHA nor sha256:<hex>@<YYYY-MM-DD>"
            )));
        }
        let replay = Replay::parse(&t.replay)
            .ok_or_else(|| err(format!("unknown replay {:?}", t.replay)))?;
        rows.push(Technique {
            class: t.class,
            language,
            source: t.source,
            license: t.license,
            covered_by: t.covered_by,
            case: t.case.filter(|c| !c.trim().is_empty()),
            revision,
            replay,
        });
    }
    Ok(rows)
}

/// Loads `techniques.toml`.
pub fn load_techniques(path: &Path) -> Result<Vec<Technique>, String> {
    let origin = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|e| format!("{origin}: cannot read: {e}"))?;
    parse_techniques(&text, &origin)
}

/// Ledger guards: every `covered_by` resolves, every non-`gap`
/// non-`outside-*` row names a case that exists or is claimed by a spec
/// row (authored in U4), every license matches the collection's listed
/// license, every seeded collection has a row, and a `gap` row fails
/// until a new family or closure class covers it (R9).
pub fn check_techniques(
    corpus_root: &Path,
    spec_cases: &BTreeSet<String>,
    rows: &[Technique],
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seeded: BTreeSet<&str> = BTreeSet::new();
    for t in rows {
        let what = t.class.as_str();
        match source_license(&t.source) {
            None => errors.push(format!(
                "{what}: source {} is not one of the seeded collections",
                t.source
            )),
            Some(license) => {
                if license != t.license {
                    errors.push(format!(
                        "{what}: license {:?} disagrees with the source's listed {license:?}",
                        t.license
                    ));
                }
                if let Some((url, _)) = SOURCES.iter().find(|(url, _)| {
                    t.source == *url
                        || (*url == VM2_ADVISORIES
                            && t.source.starts_with(&format!("{VM2_ADVISORIES}/GHSA-")))
                }) {
                    seeded.insert(url);
                }
            }
        }
        if t.covered_by == "gap" {
            errors.push(format!(
                "{what}: gap: fix by a new family or closure class (R9)"
            ));
            continue;
        }
        if let Some(case) = &t.case
            && !spec_cases.contains(case)
            && !case_dir_exists(&corpus_root.join(case))
        {
            errors.push(format!(
                "{what}: case {case} is not a corpus case and no spec row claims it"
            ));
        }
    }
    for (url, _) in SOURCES {
        if !seeded.contains(url) {
            errors.push(format!("{url}: seeded collection has no technique row"));
        }
    }
    errors
}

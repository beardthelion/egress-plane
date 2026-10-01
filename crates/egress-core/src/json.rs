//! Deterministic JSON output (KTD10).
//!
//! Output structs mirror the model in a fixed field order. Determinism comes
//! from [`finalize`] on a copy of the report, never from scan order. Display
//! fields (`destination.display`, `construct`, and the display form of a
//! non-UTF-8 path) pass through [`escape`] (KTD18); structured fields carry
//! exact strings under standard JSON escaping. Nothing time- or
//! host-dependent is written.

use serde::Serialize;

use crate::escape::escape;
use crate::identity::finalize;
use crate::model::{self, Report};

#[derive(Serialize)]
struct JReport<'a> {
    schema_version: u32,
    tool: JTool<'a>,
    completeness: JCompleteness,
    caveats: Vec<JCaveat<'a>>,
    sites: Vec<JSite<'a>>,
    blind_spots: Vec<JBlindSpot<'a>>,
    unscanned_dependencies: Vec<JUnscanned<'a>>,
    excluded: Vec<JExcluded<'a>>,
}

#[derive(Serialize)]
struct JTool<'a> {
    name: &'a str,
    version: &'a str,
    data_digest: &'a str,
    runtime_range: JRuntimeRange<'a>,
}

#[derive(Serialize)]
struct JRuntimeRange<'a> {
    python: &'a str,
    node: &'a str,
    rust: &'a str,
}

#[derive(Serialize)]
struct JCompleteness {
    state: &'static str,
    budget_exceeded: Vec<&'static str>,
    coverage: JCoverage,
}

#[derive(Serialize)]
struct JCoverage {
    python: JCounts,
    javascript: JCounts,
    rust: JCounts,
    unsupported: JCounts,
}

#[derive(Serialize)]
struct JCounts {
    scanned: u64,
    skipped: u64,
}

impl From<model::CoverageCounts> for JCounts {
    fn from(c: model::CoverageCounts) -> Self {
        Self {
            scanned: c.scanned,
            skipped: c.skipped,
        }
    }
}

#[derive(Serialize)]
struct JCaveat<'a> {
    id: &'a str,
    text: &'a str,
}

#[derive(Serialize)]
struct JLocation {
    line: u32,
    column: u32,
}

fn location(l: Option<model::Location>) -> Option<JLocation> {
    l.map(|l| JLocation {
        line: l.line,
        column: l.column,
    })
}

#[derive(Serialize)]
struct JDestination<'a> {
    kind: &'static str,
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<&'a str>,
    display: String,
}

#[derive(Serialize)]
struct JSite<'a> {
    id: &'a str,
    language: &'static str,
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_bytes: Option<&'a str>,
    symbol: &'a str,
    bucket: &'static str,
    mechanism: &'a str,
    destination: JDestination<'a>,
    ordinal: u32,
    labels: Vec<&'static str>,
    location: Option<JLocation>,
}

#[derive(Serialize)]
struct JBlindSpot<'a> {
    id: &'a str,
    language: Option<&'static str>,
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_bytes: Option<&'a str>,
    symbol: &'a str,
    kind: &'static str,
    whole_file: bool,
    coverage_gap: bool,
    construct: String,
    ordinal: u32,
    labels: Vec<&'static str>,
    location: Option<JLocation>,
}

#[derive(Serialize)]
struct JUnscanned<'a> {
    id: &'a str,
    language: &'static str,
    package: &'a str,
    files: &'a [String],
}

#[derive(Serialize)]
struct JExcluded<'a> {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_bytes: Option<&'a str>,
    reason: &'static str,
}

/// A path field: exact when the path is valid UTF-8, and the escaped display
/// form when raw bytes accompany it (KTD10, KTD18).
fn path_field(display: &str, bytes: Option<&str>) -> String {
    match bytes {
        Some(_) => escape(display),
        None => display.to_string(),
    }
}

fn labels(l: &[model::Label]) -> Vec<&'static str> {
    l.iter().map(|l| l.as_str()).collect()
}

/// Serializes `report` after [`finalize`] on a copy, so the output does not
/// depend on insertion order. Pretty-printed with two-space indentation and
/// ending with one newline.
pub fn to_json(report: &Report) -> String {
    let mut r = report.clone();
    finalize(&mut r);
    let j = JReport {
        schema_version: r.schema_version,
        tool: JTool {
            name: &r.tool.name,
            version: &r.tool.version,
            data_digest: &r.tool.data_digest,
            runtime_range: JRuntimeRange {
                python: &r.tool.runtime_range.python,
                node: &r.tool.runtime_range.node,
                rust: &r.tool.runtime_range.rust,
            },
        },
        completeness: JCompleteness {
            state: r.completeness.state.as_str(),
            budget_exceeded: r
                .completeness
                .budget_exceeded
                .iter()
                .map(|b| b.as_str())
                .collect(),
            coverage: JCoverage {
                python: r.completeness.coverage.python.into(),
                javascript: r.completeness.coverage.javascript.into(),
                rust: r.completeness.coverage.rust.into(),
                unsupported: r.completeness.coverage.unsupported.into(),
            },
        },
        caveats: r
            .caveats
            .iter()
            .map(|c| JCaveat {
                id: &c.id,
                text: &c.text,
            })
            .collect(),
        sites: r
            .sites
            .iter()
            .map(|s| JSite {
                id: &s.id,
                language: s.language.as_str(),
                file: path_field(&s.file, s.file_bytes.as_deref()),
                file_bytes: s.file_bytes.as_deref(),
                symbol: &s.symbol,
                bucket: s.bucket.as_str(),
                mechanism: &s.mechanism,
                destination: JDestination {
                    kind: s.destination.kind.as_str(),
                    value: &s.destination.value,
                    default: s.destination.default.as_deref(),
                    display: escape(&s.destination.display),
                },
                ordinal: s.ordinal,
                labels: labels(&s.labels),
                location: location(s.location),
            })
            .collect(),
        blind_spots: r
            .blind_spots
            .iter()
            .map(|b| JBlindSpot {
                id: &b.id,
                language: b.language.map(|l| l.as_str()),
                file: path_field(&b.file, b.file_bytes.as_deref()),
                file_bytes: b.file_bytes.as_deref(),
                symbol: &b.symbol,
                kind: b.kind.as_str(),
                whole_file: b.whole_file,
                coverage_gap: b.coverage_gap,
                construct: escape(&b.construct),
                ordinal: b.ordinal,
                labels: labels(&b.labels),
                location: location(b.location),
            })
            .collect(),
        unscanned_dependencies: r
            .unscanned_dependencies
            .iter()
            .map(|d| JUnscanned {
                id: &d.id,
                language: d.language.as_str(),
                package: &d.package,
                files: &d.files,
            })
            .collect(),
        excluded: r
            .excluded
            .iter()
            .map(|x| JExcluded {
                path: path_field(&x.path, x.path_bytes.as_deref()),
                path_bytes: x.path_bytes.as_deref(),
                reason: x.reason.as_str(),
            })
            .collect(),
    };
    // Serializing plain structs of strings, integers, and booleans cannot fail.
    let mut out = serde_json::to_string_pretty(&j).expect("report serializes");
    out.push('\n');
    out
}

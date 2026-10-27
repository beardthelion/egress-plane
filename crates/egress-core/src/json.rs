//! Deterministic JSON output.
//!
//! Output structs mirror the model in a fixed field order. Determinism comes
//! from [`finalize`] on a copy of the report, never from scan order. Display
//! fields (`destination.display`, `construct`, and the display form of a
//! non-UTF-8 path) pass through [`escape`]; structured fields carry
//! exact strings under standard JSON escaping. Nothing time- or
//! host-dependent is written.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::escape::escape;
use crate::identity::finalize;
use crate::model::{self, Language, LanguageMap, Report};

#[derive(Serialize)]
struct JReport<'a> {
    schema_version: u32,
    tool: JTool<'a>,
    completeness: JCompleteness<'a>,
    caveats: Vec<JCaveat<'a>>,
    sites: Vec<JSite<'a>>,
    blind_spots: Vec<JBlindSpot<'a>>,
    unscanned_dependencies: Vec<JUnscanned<'a>>,
    excluded: Vec<JExcluded<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<JDependencies<'a>>,
}

#[derive(Serialize)]
struct JTool<'a> {
    name: &'a str,
    version: &'a str,
    data_digest: &'a str,
    runtime_range: JRuntimeRange<'a>,
}

/// `tool.runtime_range`: one key per language, in table order, under
/// each language's [`model::LanguageSpec::runtime_key`].
struct JRuntimeRange<'a>(&'a LanguageMap<String>);

impl Serialize for JRuntimeRange<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for lang in Language::ALL {
            if let Some(range) = self.0.get(lang) {
                map.serialize_entry(lang.spec().runtime_key, range)?;
            }
        }
        map.end()
    }
}

#[derive(Serialize)]
struct JCompleteness<'a> {
    state: &'static str,
    budget_exceeded: Vec<&'static str>,
    coverage: JCoverage<'a>,
}

/// `completeness.coverage`: per-language counts in table order, then
/// `unsupported` last.
struct JCoverage<'a>(&'a model::Coverage);

impl Serialize for JCoverage<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for lang in Language::ALL {
            let counts = self.0.languages.get(lang).copied().unwrap_or_default();
            map.serialize_entry(lang.as_str(), &JCounts::from(counts))?;
        }
        map.serialize_entry("unsupported", &JCounts::from(self.0.unsupported))?;
        map.end()
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    via: Option<JVia<'a>>,
}

/// A derived site's provenance (KTD10): the inner site's phase-1 id, the
/// caller's 1-based argument index, and the wrapper chain.
#[derive(Serialize)]
struct JVia<'a> {
    inner_site: &'a str,
    argument: u32,
    chain: Vec<JViaHop<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cut: Option<&'static str>,
}

#[derive(Serialize)]
struct JViaHop<'a> {
    file: String,
    symbol: &'a str,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    distribution: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distribution_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mark: Option<JMark>,
}

#[derive(Serialize)]
struct JMark {
    rules: Vec<&'static str>,
    resembles: Vec<String>,
}

#[derive(Serialize)]
struct JDependencies<'a> {
    roots: Vec<JRoot>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    caveats: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    budget_exceeded: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostics: Vec<JDiagnostic<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    auto_run: Vec<JAutoRun<'a>>,
    packages: Vec<JPackage<'a>>,
}

#[derive(Serialize)]
struct JRoot {
    label: String,
    kind: &'static str,
}

#[derive(Serialize)]
struct JDiagnostic<'a> {
    lockfile: &'a str,
    problem: &'static str,
}

#[derive(Serialize)]
struct JAutoRun<'a> {
    id: &'a str,
    root: String,
    file: String,
    trigger: &'static str,
    distribution: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize)]
struct JPackage<'a> {
    id: &'a str,
    language: &'static str,
    package: String,
    root: String,
    locator: String,
    version: String,
    strength: &'static str,
    #[serde(skip_serializing_if = "is_false")]
    modified: bool,
    #[serde(skip_serializing_if = "is_false")]
    linked: bool,
    #[serde(skip_serializing_if = "is_false")]
    catalogued: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    distribution: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distribution_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mark: Option<JMark>,
    imported_by: &'a [String],
    imported_by_packages: &'a [String],
    state: &'static str,
    coverage: JCounts,
    sites: Vec<JSite<'a>>,
    blind_spots: Vec<JBlindSpot<'a>>,
    imports_unscanned: Vec<JImportsUnscanned>,
}

#[derive(Serialize)]
struct JImportsUnscanned {
    language: &'static str,
    package: String,
    reason: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    distribution: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distribution_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mark: Option<JMark>,
}

#[derive(Serialize)]
struct JExcluded<'a> {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_bytes: Option<&'a str>,
    reason: &'static str,
}

/// A path field: exact when the path is valid UTF-8, and the escaped display
/// form when raw bytes accompany it.
fn path_field(display: &str, bytes: Option<&str>) -> String {
    match bytes {
        Some(_) => escape(display),
        None => display.to_string(),
    }
}

fn labels(l: &[model::Label]) -> Vec<&'static str> {
    l.iter().map(|l| l.as_str()).collect()
}

fn jvia(v: &model::Via) -> JVia<'_> {
    JVia {
        inner_site: &v.inner_site,
        argument: v.argument,
        chain: v
            .chain
            .iter()
            .map(|h| JViaHop {
                file: escape(&h.file),
                symbol: &h.symbol,
            })
            .collect(),
        cut: v.cut.map(|c| c.as_str()),
    }
}

fn jsite(s: &model::Site) -> JSite<'_> {
    JSite {
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
        via: s.via.as_ref().map(jvia),
    }
}

fn jblind(b: &model::BlindSpot) -> JBlindSpot<'_> {
    JBlindSpot {
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
    }
}

fn jmark(m: &model::DependencyMark) -> JMark {
    JMark {
        rules: m.rules.iter().map(|r| r.as_str()).collect(),
        resembles: m.resembles.iter().map(|r| escape(r)).collect(),
    }
}

fn jdistribution(d: &[String]) -> Vec<String> {
    d.iter().map(|s| escape(s)).collect()
}

fn jpackage(p: &model::DependencyPackage) -> JPackage<'_> {
    JPackage {
        id: &p.id,
        language: p.language.as_str(),
        package: escape(&p.package),
        root: escape(&p.root),
        locator: escape(&p.locator),
        version: escape(&p.version),
        strength: p.strength.as_str(),
        modified: p.modified,
        linked: p.linked,
        catalogued: p.catalogued,
        distribution: jdistribution(&p.distribution),
        distribution_source: p.distribution_source.map(|s| s.as_str()),
        mark: p.mark.as_ref().map(jmark),
        imported_by: &p.imported_by,
        imported_by_packages: &p.imported_by_packages,
        state: p.state.as_str(),
        coverage: p.coverage.into(),
        sites: p.sites.iter().map(jsite).collect(),
        blind_spots: p.blind_spots.iter().map(jblind).collect(),
        imports_unscanned: p
            .imports_unscanned
            .iter()
            .map(|u| JImportsUnscanned {
                language: u.language.as_str(),
                package: escape(&u.package),
                reason: u.reason.as_str(),
                distribution: jdistribution(&u.distribution),
                distribution_source: u.distribution_source.map(|s| s.as_str()),
                mark: u.mark.as_ref().map(jmark),
            })
            .collect(),
    }
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
            runtime_range: JRuntimeRange(&r.tool.runtime_range),
        },
        completeness: JCompleteness {
            state: r.completeness.state.as_str(),
            budget_exceeded: r
                .completeness
                .budget_exceeded
                .iter()
                .map(|b| b.as_str())
                .collect(),
            coverage: JCoverage(&r.completeness.coverage),
        },
        caveats: r
            .caveats
            .iter()
            .map(|c| JCaveat {
                id: &c.id,
                text: &c.text,
            })
            .collect(),
        sites: r.sites.iter().map(jsite).collect(),
        blind_spots: r.blind_spots.iter().map(jblind).collect(),
        unscanned_dependencies: r
            .unscanned_dependencies
            .iter()
            .map(|d| JUnscanned {
                id: &d.id,
                language: d.language.as_str(),
                package: &d.package,
                files: &d.files,
                reason: d.reason.map(|r| r.as_str()),
                distribution: jdistribution(&d.distribution),
                distribution_source: d.distribution_source.map(|s| s.as_str()),
                mark: d.mark.as_ref().map(jmark),
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
        dependencies: r.dependencies.as_ref().map(|d| JDependencies {
            roots: d
                .roots
                .iter()
                .map(|r| JRoot {
                    label: escape(&r.label),
                    kind: r.kind.as_str(),
                })
                .collect(),
            caveats: d.caveats.iter().map(|c| c.as_str()).collect(),
            budget_exceeded: d.budget_exceeded.iter().map(|b| b.as_str()).collect(),
            diagnostics: d
                .diagnostics
                .iter()
                .map(|x| JDiagnostic {
                    lockfile: &x.lockfile,
                    problem: x.problem.as_str(),
                })
                .collect(),
            auto_run: d
                .auto_run
                .iter()
                .map(|a| JAutoRun {
                    id: &a.id,
                    root: escape(&a.root),
                    file: escape(&a.file),
                    trigger: a.trigger.as_str(),
                    distribution: escape(&a.distribution),
                    command: a.command.as_ref().map(|c| escape(c)),
                })
                .collect(),
            packages: d.packages.iter().map(jpackage).collect(),
        }),
    };
    // Serializing plain structs of strings, integers, and booleans cannot fail.
    let mut out = serde_json::to_string_pretty(&j).expect("report serializes");
    out.push('\n');
    out
}

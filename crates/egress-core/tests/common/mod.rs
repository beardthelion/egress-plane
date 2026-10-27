//! Shared builders and schema validation for egress-core integration tests.
#![allow(dead_code)]

use egress_core::model::*;

pub fn tool() -> Tool {
    Tool {
        name: "egress-plane".into(),
        version: "0.1.0".into(),
        data_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        runtime_range: [
            (Language::Python, "3.8 to 3.13".to_string()),
            (Language::Javascript, "18 to 22".to_string()),
            (Language::Rust, "1.97.1".to_string()),
        ]
        .into_iter()
        .collect(),
    }
}

pub fn site(
    file: &str,
    symbol: &str,
    mechanism: &str,
    destination: Destination,
    line: u32,
) -> Site {
    Site {
        id: String::new(),
        language: Language::Python,
        file: file.into(),
        file_bytes: None,
        symbol: symbol.into(),
        bucket: Bucket::Catalogued,
        mechanism: mechanism.into(),
        destination,
        ordinal: 0,
        labels: vec![],
        location: Some(Location { line, column: 5 }),
        via: None,
    }
}

pub fn blind(
    file: &str,
    symbol: &str,
    kind: BlindSpotKind,
    construct: &str,
    line: u32,
) -> BlindSpot {
    BlindSpot {
        id: String::new(),
        language: Some(Language::Python),
        file: file.into(),
        file_bytes: None,
        symbol: symbol.into(),
        kind,
        whole_file: kind.is_whole_file(),
        coverage_gap: kind.is_whole_file(),
        construct: construct.into(),
        ordinal: 0,
        labels: vec![],
        location: if kind.is_whole_file() || line == 0 {
            None
        } else {
            Some(Location { line, column: 1 })
        },
    }
}

pub fn report(sites: Vec<Site>, blind_spots: Vec<BlindSpot>) -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        tool: tool(),
        completeness: Completeness {
            state: CompletenessState::Incomplete,
            budget_exceeded: vec![],
            coverage: Coverage {
                languages: [(
                    Language::Python,
                    CoverageCounts {
                        scanned: 3,
                        skipped: 1,
                    },
                )]
                .into_iter()
                .collect(),
                ..Coverage::default()
            },
        },
        caveats: vec![],
        sites,
        blind_spots,
        unscanned_dependencies: vec![],
        excluded: vec![],
        dependencies: None,
    }
}

/// A report that fills every collection and every optional field.
pub fn full_report() -> Report {
    use egress_core::destination as d;
    let mut r = report(
        vec![
            site(
                "src/notify.py",
                "send",
                "python:requests.post",
                d::env("WEBHOOK_URL", Some("https://h.example/x")),
                12,
            ),
            site(
                "src/api.py",
                "Api.get",
                "python:requests.get",
                d::param(1, "Api.get"),
                4,
            ),
            site(
                "src/api.py",
                "<module>",
                "python:socket",
                d::expr("socket"),
                1,
            ),
        ],
        vec![
            blind(
                "legacy/old.py",
                "<module>",
                BlindSpotKind::ParseError,
                "",
                0,
            ),
            blind(
                "src/dyn.py",
                "run",
                BlindSpotKind::DynamicCode,
                "exec(code)",
                7,
            ),
        ],
    );
    r.sites[2].location = None;
    r.sites[1].labels = vec![Label::Test, Label::Vendored];
    r.blind_spots.push(BlindSpot {
        language: None,
        ..blind(
            "vendor",
            "<module>",
            BlindSpotKind::UnconfirmedExclusion,
            "",
            0,
        )
    });
    r.caveats.push(Caveat {
        id: "browser-dom".into(),
        text: "Browser DOM requests are not covered.".into(),
    });
    r.completeness.budget_exceeded = vec![BudgetReason::Findings, BudgetReason::Files];
    r.unscanned_dependencies.push(UnscannedDependency {
        id: String::new(),
        language: Language::Javascript,
        package: "left-pad".into(),
        files: vec!["src/z.js".into(), "src/a.js".into()],
        reason: None,
        distribution: vec![],
        distribution_source: None,
        mark: None,
    });
    r.excluded.push(Excluded {
        path: "node_modules".into(),
        path_bytes: None,
        reason: ExcludedReason::InstallOutput,
    });
    r.excluded.push(Excluded {
        path: "bad\\x{ff}".into(),
        path_bytes: Some("626164ff".into()),
        reason: ExcludedReason::BrokenSymlink,
    });
    r
}

/// A package entry that fills every field and needs sorting: importers,
/// sites, and blind spots are out of order and its mark rules are reversed.
pub fn dependency_package() -> DependencyPackage {
    use egress_core::destination as d;
    DependencyPackage {
        id: String::new(),
        language: Language::Python,
        package: "requests".into(),
        root: "deps/venv".into(),
        locator: "requests".into(),
        version: "2.31.0".into(),
        strength: VerificationStrength::ChecksumVerified,
        modified: true,
        linked: false,
        catalogued: true,
        distribution: vec!["requests".into(), "Requests".into()],
        distribution_source: Some(DistributionSource::InstalledMetadata),
        mark: Some(DependencyMark {
            rules: vec![MarkRule::NonAsciiName, MarkRule::ConfusableSkeleton],
            resembles: vec!["requests".into()],
        }),
        imported_by: vec!["src/z.py".into(), "src/a.py".into()],
        imported_by_packages: vec!["0123456789abcdef".into()],
        state: CompletenessState::Incomplete,
        coverage: CoverageCounts {
            scanned: 4,
            skipped: 1,
        },
        sites: vec![
            site(
                "requests/sessions.py",
                "Session.send",
                "python:requests.Session.send",
                d::literal("https://b.example"),
                20,
            ),
            site(
                "requests/api.py",
                "api.get",
                "python:requests.get",
                d::literal("https://a.example"),
                9,
            ),
        ],
        blind_spots: vec![blind(
            "requests/compat.py",
            "<module>",
            BlindSpotKind::ParseError,
            "",
            0,
        )],
        imports_unscanned: vec![ImportsUnscanned {
            language: Language::Python,
            package: "idna".into(),
            reason: UnscannedReason::DependencyBudgetExhausted,
            distribution: vec!["idna".into()],
            distribution_source: Some(DistributionSource::Curated),
            mark: None,
        }],
    }
}

/// A dependency section that fills every collection and every optional
/// field, with entries out of order.
pub fn dependency_section() -> DependencySection {
    let linked = DependencyPackage {
        id: String::new(),
        language: Language::Rust,
        package: "serde".into(),
        root: "deps/vendor".into(),
        locator: "serde".into(),
        version: "1.0.200".into(),
        strength: VerificationStrength::VersionMatched,
        modified: false,
        linked: true,
        catalogued: false,
        distribution: vec![],
        distribution_source: None,
        mark: None,
        imported_by: vec![],
        imported_by_packages: vec![],
        state: CompletenessState::Complete,
        coverage: CoverageCounts::default(),
        sites: vec![],
        blind_spots: vec![],
        imports_unscanned: vec![],
    };
    DependencySection {
        roots: vec![
            DependencyRoot {
                label: "deps/venv".into(),
                kind: DependencyRootKind::Python,
            },
            DependencyRoot {
                label: "deps/vendor".into(),
                kind: DependencyRootKind::CargoVendor,
            },
        ],
        caveats: vec!["dependency-conditional-code-included".into()],
        budget_exceeded: vec![
            DependencyBudgetReason::Files,
            DependencyBudgetReason::Packages,
        ],
        diagnostics: vec![LockfileDiagnostic {
            lockfile: "poetry.lock".into(),
            problem: LockfileProblem::ParseError,
        }],
        auto_run: vec![
            AutoRun {
                id: String::new(),
                root: "deps/venv".into(),
                file: "sitecustomize.py".into(),
                trigger: AutoRunTrigger::Sitecustomize,
                distribution: "unattributed".into(),
                command: None,
            },
            AutoRun {
                id: String::new(),
                root: "deps/venv".into(),
                file: "a.pth".into(),
                trigger: AutoRunTrigger::PthImportLine,
                distribution: "setuptools".into(),
                command: None,
            },
        ],
        packages: vec![linked, dependency_package()],
    }
}

/// A derived-site provenance (KTD10): `inner_site` is the inner `param:`
/// site's phase-1 id, `argument` the caller's 1-based index, and `chain`
/// the wrapper hops from the caller's callee to the innermost wrapper.
pub fn via(inner_site: &str, argument: u32, chain: &[(&str, &str)]) -> Via {
    Via {
        inner_site: inner_site.into(),
        argument,
        chain: chain
            .iter()
            .map(|(file, symbol)| ViaHop {
                file: (*file).into(),
                symbol: (*symbol).into(),
            })
            .collect(),
        cut: None,
    }
}

/// `site` with a `via` attached, making it a derived site.
pub fn derived(site: Site, via: Via) -> Site {
    Site {
        via: Some(via),
        ..site
    }
}

/// `full_report` plus a full dependency section.
pub fn report_with_dependencies() -> Report {
    let mut r = full_report();
    r.dependencies = Some(dependency_section());
    r
}

const SCHEMA: &str = include_str!("../../../../schema/egress-report.v1.json");

/// Validates a serialized report against `schema/egress-report.v1.json`.
pub fn validate(json: &str) -> Result<(), String> {
    let instance: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    validate_value(&instance)
}

pub fn validate_value(instance: &serde_json::Value) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).map_err(|e| e.to_string())?;
    let url = "urn:egress-plane:egress-report.v1.json";
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler
        .add_resource(url, schema)
        .map_err(|e| e.to_string())?;
    let idx = compiler
        .compile(url, &mut schemas)
        .map_err(|e| format!("{e:#}"))?;
    schemas
        .validate(instance, idx)
        .map_err(|e| format!("{e:#}"))
}

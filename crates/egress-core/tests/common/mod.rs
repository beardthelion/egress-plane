//! Shared builders and schema validation for egress-core integration tests.
#![allow(dead_code)]

use egress_core::model::*;

pub fn tool() -> Tool {
    Tool {
        name: "egress-plane".into(),
        version: "0.1.0".into(),
        data_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        runtime_range: RuntimeRange {
            python: "3.8 to 3.13".into(),
            node: "18 to 22".into(),
            rust: "1.97.1".into(),
        },
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
                python: CoverageCounts {
                    scanned: 3,
                    skipped: 1,
                },
                ..Coverage::default()
            },
        },
        caveats: vec![],
        sites,
        blind_spots,
        unscanned_dependencies: vec![],
        excluded: vec![],
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

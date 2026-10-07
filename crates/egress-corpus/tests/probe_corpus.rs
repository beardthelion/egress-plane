//! The probe corpus gate: every case outside `fixtures/probe/pending.toml`
//! must pass against the probe's snapshot entry point, and every pending
//! case must still fail. The run summary is written to
//! `target/probe-corpus-report.json`.

use std::path::Path;

use egress_core::model::ToolError;
use egress_corpus::{load_pending, probe};

/// Bridges the probe's snapshot entry point (behind its `snapshot` feature,
/// enabled here only through this dev-dependency) to the harness's output
/// type.
fn scan(dir: &Path) -> Result<probe::ScanOutput, ToolError> {
    use egress_probe::snapshot::{ReadCall as P, scan_case};
    scan_case(dir).map(|o| probe::ScanOutput {
        json: o.json,
        text: o.text,
        read_log: o
            .read_log
            .iter()
            .map(|e| probe::ReadLogEntry {
                kind: match e.kind {
                    P::Read => probe::ReadCall::Read,
                    P::List => probe::ReadCall::List,
                    P::Metadata => probe::ReadCall::Metadata,
                    P::Access => probe::ReadCall::Access,
                    P::Readlink => probe::ReadCall::Readlink,
                },
                path: e.path.clone(),
            })
            .collect(),
    })
}

#[test]
fn probe_corpus() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../../fixtures/probe");
    let pending = load_pending(&root.join("pending.toml")).unwrap_or_else(|e| panic!("{e}"));
    let summary = probe::run(&root, &pending, scan);
    println!("{}", summary.render());
    let target = manifest.join("../../target");
    if std::fs::create_dir_all(&target).is_ok() {
        let _ = std::fs::write(target.join("probe-corpus-report.json"), summary.to_json());
    }
    assert!(summary.passed(), "{}", summary.render());
}

//! The corpus gate: every case outside `pending.toml` must pass
//! against the real scanner, and every pending case must still fail. The
//! false-positive count is printed and written to `target/corpus-report.json`.

use std::path::Path;

use egress_corpus::{load_pending, run_corpus};

#[test]
fn corpus() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../../fixtures/corpus");
    let pending = load_pending(&root.join("pending.toml")).unwrap_or_else(|e| panic!("{e}"));
    let summary = run_corpus(&root, &pending, egress_scan::scan);
    println!("{}", summary.render());
    let target = manifest.join("../../target");
    if std::fs::create_dir_all(&target).is_ok() {
        let _ = std::fs::write(target.join("corpus-report.json"), summary.to_json());
    }
    assert!(summary.passed(), "{}", summary.render());
}

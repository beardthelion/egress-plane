//! `corpus-gen`: the primitives corpus generator (KTD4).
//!
//! `cargo run --locked -p egress-corpus --bin corpus-gen -- --write`
//! writes every deferred or owned primitives case from the embedded
//! data, updates `generated.toml`, and removes created cases from
//! `deferred.toml`. `--check` writes nothing and exits 1 listing each
//! differing or missing case.

use std::path::Path;
use std::process::ExitCode;

use egress_core::data::{Data, RuntimeData};
use egress_core::model::Language;
use egress_corpus::generate;

fn runtimes(data: &Data) -> Vec<&RuntimeData> {
    Language::ALL.iter().map(|l| data.runtime(*l)).collect()
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode != "--write" && mode != "--check" {
        eprintln!("usage: corpus-gen --write | --check");
        return ExitCode::from(1);
    }
    let corpus_root = generate::corpus_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let data = match Data::embedded() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let rts = runtimes(&data);
    if mode == "--check" {
        let lines = generate::check(&rts, &corpus_root);
        if lines.is_empty() {
            return ExitCode::SUCCESS;
        }
        for l in lines {
            eprintln!("{l}");
        }
        return ExitCode::from(1);
    }
    match generate::plan(&rts, &corpus_root) {
        Err(errors) => {
            for e in errors {
                eprintln!("{e}");
            }
            ExitCode::from(1)
        }
        Ok(plan) => {
            if let Err(e) = generate::apply(&corpus_root, &plan) {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
            println!(
                "corpus-gen: {} cases written, {} stale deleted",
                plan.rewrite.len(),
                plan.delete_dirs.len()
            );
            ExitCode::SUCCESS
        }
    }
}

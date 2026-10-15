//! The advisory benchmark driver (KTD16): generates fixed-seed
//! synthetic monorepos under `target/bench/trees/`, runs the release
//! `egress-plane` binary over each `(size, language)` pair as a child
//! process, and records wall time, throughput, and per-child peak RSS
//! in `target/bench/results.json`. Advisory only: never run by the
//! default test suite or CI.

mod synth;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// The sizes a bare run measures.
const DEFAULT_SIZES: &[usize] = &[1_000, 10_000, 50_000];
const LANGUAGES: &[&str] = &["python", "javascript", "rust", "go"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn release_bin(root: &Path) -> PathBuf {
    let p = root.join("target/release/egress-plane");
    if !p.is_file() {
        eprintln!(
            "egress-bench: release binary missing at {}: run `cargo build --release --locked -p egress-cli` first",
            p.display()
        );
        std::process::exit(1);
    }
    p
}

/// Wall time and the child's own peak RSS (`wait4` on its pid).
fn timed_run(bin: &Path, tree: &Path) -> (f64, u64) {
    let start = Instant::now();
    let child = Command::new(bin)
        .arg("scan")
        .arg(tree)
        .arg("--format")
        .arg("json")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn egress-plane");
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::wait4(pid, &mut status, 0, usage.as_mut_ptr()) };
    let wall = start.elapsed().as_secs_f64();
    let rss = if rc == pid {
        unsafe { usage.assume_init() }.ru_maxrss as u64
    } else {
        0
    };
    (wall, rss)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut sizes: Vec<usize> = DEFAULT_SIZES.to_vec();
    let mut languages: Vec<String> = LANGUAGES.iter().map(|s| s.to_string()).collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sizes" => {
                sizes = args
                    .get(i + 1)
                    .expect("--sizes takes a comma list")
                    .split(',')
                    .map(|s| s.parse().expect("size"))
                    .collect();
                i += 1;
            }
            "--languages" => {
                languages = args
                    .get(i + 1)
                    .expect("--languages takes a comma list")
                    .split(',')
                    .map(str::to_string)
                    .collect();
                i += 1;
            }
            other => {
                eprintln!("egress-bench: unknown argument {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    let root = workspace_root();
    let bin = release_bin(&root);
    let base = root.join("target/bench");
    std::fs::create_dir_all(base.join("trees")).expect("bench dir");

    let mut results = Vec::new();
    for &size in &sizes {
        for lang in &languages {
            let dir = base.join("trees").join(format!("{size}-{lang}"));
            std::fs::create_dir_all(&dir).expect("tree dir");
            let files = synth::tree(lang, size);
            for f in &files {
                let p = dir.join(&f.path);
                std::fs::create_dir_all(p.parent().expect("dir")).expect("dir");
                std::fs::write(&p, &f.text).expect("write file");
            }
            let (wall, rss) = timed_run(&bin, &dir);
            results.push(serde_json::json!({
                "language": lang,
                "files": size,
                "wall_seconds": (wall * 1000.0).round() / 1000.0,
                "files_per_second": (size as f64 / wall).round() as u64,
                "peak_rss_kib": rss,
            }));
            eprintln!("{lang} {size}: {wall:.2}s, {rss} KiB peak");
        }
    }
    let out = serde_json::json!({
        "seed": synth::SEED,
        "mix": synth::MIX,
        "runs": results,
    });
    let mut f = std::fs::File::create(base.join("results.json")).expect("results");
    writeln!(f, "{}", serde_json::to_string_pretty(&out).unwrap()).expect("write");
    eprintln!("wrote {}", base.join("results.json").display());
}

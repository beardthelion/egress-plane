//! Synthetic monorepo generation for the advisory benchmark (KTD16).
//!
//! The generator is a fixed-seed xorshift64*: the same `(seed, size,
//! language)` triple always produces the same tree, so two benchmark
//! runs compare like with like and the seed and mix land in
//! `results.json` as provenance.

/// The one seed every generated tree uses.
pub const SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// Per-100-files content mix (KTD16): 10 files with direct egress
/// sites, 10 wrapper definitions, 20 wrapper callers, 30 importing
/// modules with import depth up to 4, and 30 inert files.
pub const MIX: &str =
    "10 egress sites, 10 wrapper definitions, 20 wrapper callers, 30 importing modules, 30 inert";

/// A deterministic xorshift64*.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// One generated file.
pub struct File {
    pub path: String,
    pub text: String,
}

/// The files of a tree of `size` sources in `language`, in order.
pub fn tree(language: &str, size: usize) -> Vec<File> {
    let mut rng = Rng::new(SEED ^ (size as u64).wrapping_mul(0x9E37));
    (0..size)
        .map(|i| File {
            path: file_path(language, i),
            text: body(language, i, &mut rng),
        })
        .collect()
}

fn file_path(language: &str, i: usize) -> String {
    let dir = format!("pkg{:03}", i / 40);
    match language {
        "python" => format!("{dir}/mod{i}.py"),
        "javascript" => format!("{dir}/mod{i}.js"),
        "rust" => format!("{dir}/src/m{i}.rs"),
        "go" => format!("{dir}/m{i}.go"),
        other => panic!("unknown language {other}"),
    }
}

/// Which of the five content classes file `i` belongs to.
fn class_of(i: usize) -> usize {
    match i % 100 {
        0..=9 => 0,   // direct egress site
        10..=19 => 1, // wrapper definition
        20..=39 => 2, // wrapper caller
        40..=69 => 3, // importing module (chain depth <= 4)
        _ => 4,       // inert
    }
}

fn body(language: &str, i: usize, rng: &mut Rng) -> String {
    match language {
        "python" => py(i, class_of(i), rng),
        "javascript" => js(i, class_of(i), rng),
        "rust" => rs(i, class_of(i), rng),
        "go" => go(i, class_of(i), rng),
        other => panic!("unknown language {other}"),
    }
}

fn host(i: usize) -> String {
    format!("https://s{i}.bench.invalid/x")
}

fn py(i: usize, class: usize, rng: &mut Rng) -> String {
    match class {
        0 => format!(
            "import urllib.request\n\n\ndef f{i}():\n    urllib.request.urlopen(\"{}\")\n",
            host(i)
        ),
        1 => "import urllib.request\n\n\ndef wrap(u):\n    urllib.request.urlopen(u)\n".into(),
        2 => format!(
            "from ..mod{} import wrap\n\n\ndef c{i}():\n    wrap(\"{}\")\n",
            10 + (i % 10),
            host(i)
        ),
        3 => {
            let depth = 1 + rng.next() % 4;
            let mut s = String::new();
            for d in 0..depth {
                s.push_str(&format!(
                    "import pkg{:03}.mod{}\n",
                    (i + d as usize) / 40,
                    i + d as usize
                ));
            }
            s
        }
        _ => format!("def f{i}(x):\n    return x + {}\n", i % 7),
    }
}

fn js(i: usize, class: usize, rng: &mut Rng) -> String {
    match class {
        0 => format!("export function f{i}() {{\n  fetch(\"{}\");\n}}\n", host(i)),
        1 => "export function wrap(u) {\n  fetch(u);\n}\n".into(),
        2 => format!(
            "import {{ wrap }} from \"./mod{}.js\";\n\nexport function c{i}() {{\n  wrap(\"{}\");\n}}\n",
            10 + (i % 10),
            host(i)
        ),
        3 => {
            let depth = 1 + rng.next() % 4;
            let mut s = String::new();
            for d in 0..depth {
                s.push_str(&format!("import \"./mod{}.js\";\n", i + d as usize));
            }
            s
        }
        _ => format!("export function f{i}(x) {{\n  return x + {};\n}}\n", i % 7),
    }
}

fn rs(i: usize, class: usize, rng: &mut Rng) -> String {
    match class {
        0 => format!(
            "pub fn f{i}() {{\n    let _ = reqwest::blocking::get(\"{}\");\n}}\n",
            host(i)
        ),
        1 => "pub fn wrap(u: &str) {\n    let _ = reqwest::blocking::get(u);\n}\n".into(),
        2 => format!(
            "use crate::pkg{}::m{};\n\npub fn c{i}() {{\n    m{}::wrap(\"{}\");\n}}\n",
            (10 + (i % 10)) / 40,
            10 + (i % 10),
            10 + (i % 10),
            host(i)
        ),
        3 => {
            let depth = 1 + rng.next() % 4;
            let mut s = String::new();
            for d in 0..depth {
                s.push_str(&format!("mod m{};\n", i + d as usize));
            }
            s
        }
        _ => format!("pub fn f{i}(x: i32) -> i32 {{\n    x + {}\n}}\n", i % 7),
    }
}

fn go(i: usize, class: usize, rng: &mut Rng) -> String {
    match class {
        0 => format!(
            "package pkg{:03}\n\nimport \"net/http\"\n\nfunc F{i}() {{\n\thttp.Get(\"{}\")\n}}\n",
            i / 40,
            host(i)
        ),
        1 => format!(
            "package pkg{:03}\n\nimport \"net/http\"\n\nfunc Wrap(u string) {{\n\thttp.Get(u)\n}}\n",
            i / 40
        ),
        2 => format!(
            "package pkg{:03}\n\nimport \"net/http\"\n\nfunc C{i}() {{\n\thttp.Get(\"{}\")\n}}\n",
            i / 40,
            host(i)
        ),
        3 => {
            let depth = 1 + rng.next() % 4;
            format!("package pkg{:03}\n\nconst Depth{} = {}\n", i / 40, i, depth)
        }
        _ => format!(
            "package pkg{:03}\n\nfunc F{i}(x int) int {{\n\treturn x + {}\n}}\n",
            i / 40,
            i % 7
        ),
    }
}

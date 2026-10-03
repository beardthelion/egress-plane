//! Rust frontend tests: lowering to the IR, crate module mapping, and
//! classification of the lowered program through the core.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use egress_core::classify::{Classified, classify};
use egress_core::data::Data;
use egress_core::discover::FileKind;
use egress_core::discover::labels::path_labels;
use egress_core::discover::manifests::{ManifestKind, Manifests, Parsed, parse};
use egress_core::identity::{encode_path_bytes, finalize};
use egress_core::ir::{FileIr, Root, UseKind};
use egress_core::model::{
    BlindSpotKind, Completeness, CompletenessState, Coverage, Label, Language, Report,
    RuntimeRange, SCHEMA_VERSION, Site, Tool,
};
use egress_core::resolve::{Program, ProgramFile};
use egress_rust::{LowerError, link, lower};

/// Lowers and classifies an in-memory repository the way the scan does:
/// `.rs` files are Rust sources, `Cargo.toml` files are manifests, and every
/// other path is an indexed non-code file.
fn scan(files: &[(&str, &str)]) -> Classified {
    let data = Data::embedded().expect("embedded data");
    let mut index = BTreeMap::new();
    let mut manifests = Manifests::default();
    let mut lowered: Vec<(Vec<u8>, FileIr)> = Vec::new();
    for (path, text) in files {
        let p = path.as_bytes().to_vec();
        if path.ends_with(".rs") {
            index.insert(p.clone(), FileKind::Source(Language::Rust));
            if let Ok(ir) = lower(&p, text) {
                lowered.push((p, ir));
            }
        } else {
            index.insert(p.clone(), FileKind::Other);
            if path.ends_with("Cargo.toml")
                && let Ok((Parsed::Cargo(m), _)) = parse(ManifestKind::Cargo, &p, text)
            {
                manifests.cargo.push(m);
            }
        }
    }
    let rules = {
        let mut refs: Vec<(&[u8], &mut FileIr)> = lowered
            .iter_mut()
            .map(|(p, ir)| (p.as_slice(), ir))
            .collect();
        link(&manifests, &index, &mut refs)
    };
    let excluded = BTreeSet::new();
    let mut program = Program::new(&index, &excluded);
    program.set_rules(Language::Rust, &rules);
    for (p, ir) in &lowered {
        program.add_file(
            p.clone(),
            ProgramFile {
                file: encode_path_bytes(p),
                language: Language::Rust,
                labels: path_labels(p),
                ir,
            },
        );
    }
    classify(&data, &program, u64::MAX)
}

fn sites<'a>(c: &'a Classified, mechanism: &str) -> Vec<&'a Site> {
    c.sites
        .iter()
        .filter(|s| s.mechanism == mechanism)
        .collect()
}

fn has_site(c: &Classified, file: &str, symbol: &str, mechanism: &str, destination: &str) -> bool {
    c.sites.iter().any(|s| {
        s.file == file
            && s.symbol == symbol
            && s.mechanism == mechanism
            && s.destination.display == destination
    })
}

fn blind(c: &Classified, file: &str, kind: BlindSpotKind) -> usize {
    c.blind_spots
        .iter()
        .filter(|b| b.file == file && b.kind == kind)
        .count()
}

fn dump(c: &Classified) -> String {
    format!("{c:#?}")
}

const CARGO: &str = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

// ---- resolution ------------------------------------------------------------

/// A local re-export of a primitive resolves to the primitive.
#[test]
fn local_reexport_resolves_to_the_primitive() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/net.rs", "pub use std::net::TcpStream as Sock;\n"),
        (
            "src/main.rs",
            "mod net;\nfn main() {\n    let addr = \"db.example.com:5432\";\n    let _ = crate::net::Sock::connect(addr);\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/main.rs",
            "main",
            "rust:std::net::TcpStream::connect",
            "db.example.com:5432"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn inline_module_reexport_resolves() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "pub mod net {\n    pub use std::net::TcpStream;\n}\nuse crate::net::TcpStream;\npub fn f() {\n    let _ = TcpStream::connect(\"a.example.com:1\");\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:std::net::TcpStream::connect",
            "a.example.com:1"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn command_new_yields_exec_destination() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "use std::process::Command;\npub fn up() {\n    let _ = Command::new(\"curl\").arg(\"-T\").status();\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "up",
            "rust:std::process::Command::new",
            "exec:curl"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn glob_import_is_an_escape_site_and_names_resolve_through_it() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "use std::net::*;\npub fn f() {\n    let _ = TcpStream::connect(\"g.example.com:1\");\n    let _: Vec<u8> = Vec::new();\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "<module>",
            "rust:std::net",
            "expr:std::net"
        ),
        "{}",
        dump(&c)
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:std::net::TcpStream::connect",
            "g.example.com:1"
        ),
        "{}",
        dump(&c)
    );
    // A prelude name is not taken from the glob.
    assert_eq!(c.sites.len(), 2, "{}", dump(&c));
}

#[test]
fn first_party_glob_reexport_resolves() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/m.rs", "pub use std::net::*;\n"),
        (
            "src/lib.rs",
            "mod m;\npub fn f(a: &str) {\n    let _ = crate::m::TcpStream::connect(a);\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:std::net::TcpStream::connect",
            "param:1:f"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn glob_from_inline_module_and_super_glob_resolve() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "mod inner {\n    pub use std::process::Command;\n}\nuse self::inner::*;\npub fn f() {\n    let _ = Command::new(\"ssh\");\n}\n#[cfg(test)]\nmod tests {\n    use super::*;\n    fn t() {\n        let _ = Command::new(\"scp\");\n    }\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:std::process::Command::new",
            "exec:ssh"
        ),
        "{}",
        dump(&c)
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "tests::t",
            "rust:std::process::Command::new",
            "exec:scp"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn dependency_rename_resolves_to_the_catalog_entry() {
    let c = scan(&[
        (
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nhttp_client = { package = \"reqwest\", version = \"0.12\" }\n",
        ),
        (
            "src/lib.rs",
            "pub fn f() {\n    let _ = http_client::blocking::get(\"https://r.example.com\");\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:reqwest::blocking::get",
            "https://r.example.com"
        ),
        "{}",
        dump(&c)
    );
    assert!(
        c.unscanned_dependencies.is_empty(),
        "{:?}",
        c.unscanned_dependencies
    );
}

#[test]
fn sibling_workspace_crate_resolves_to_first_party_source() {
    let c = scan(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/app\", \"crates/acme-net\"]\n",
        ),
        (
            "crates/acme-net/Cargo.toml",
            "[package]\nname = \"acme-net\"\nversion = \"0.1.0\"\n",
        ),
        (
            "crates/acme-net/src/lib.rs",
            "pub use std::net::TcpStream;\n",
        ),
        (
            "crates/app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nacme-net = { path = \"../acme-net\" }\n",
        ),
        (
            "crates/app/src/main.rs",
            "fn main() {\n    let _ = acme_net::TcpStream::connect(\"s.example.com:1\");\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "crates/app/src/main.rs",
            "main",
            "rust:std::net::TcpStream::connect",
            "s.example.com:1"
        ),
        "{}",
        dump(&c)
    );
    assert!(
        c.unscanned_dependencies.is_empty(),
        "{:?}",
        c.unscanned_dependencies
    );
}

#[test]
fn unscanned_crates_are_listed_by_crate_name_and_std_is_not() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "use std::io;\npub fn f(n: u32) -> String {\n    let _ = std::mem::size_of::<u32>();\n    serde_json::to_string(&n).unwrap()\n}\n",
        ),
    ]);
    let names: Vec<&str> = c
        .unscanned_dependencies
        .iter()
        .map(|d| d.package.as_str())
        .collect();
    assert_eq!(names, vec!["serde_json"], "{}", dump(&c));
}

#[test]
fn macro_rules_body_naming_an_egress_path_yields_a_site() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "macro_rules! dial {\n    ($a:expr) => {\n        std::net::TcpStream::connect($a)\n    };\n}\n",
        ),
    ]);
    assert_eq!(
        sites(&c, "rust:std::net::TcpStream::connect").len(),
        1,
        "{}",
        dump(&c)
    );
    assert_eq!(c.sites[0].symbol, "<module>");
    assert_eq!(c.sites[0].file, "src/lib.rs");
}

#[test]
fn format_with_env_macro_is_a_template() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "pub async fn f() {\n    let _ = reqwest::get(format!(\"{}/v1\", env!(\"BASE\"))).await;\n}\n",
        ),
    ]);
    assert!(
        has_site(&c, "src/lib.rs", "f", "rust:reqwest::get", "{env:BASE}/v1"),
        "{}",
        dump(&c)
    );
}

#[test]
fn env_var_read_through_unwrap_is_symbolic() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "pub fn f() {\n    let url = std::env::var(\"API_URL\").unwrap();\n    let _ = reqwest::blocking::get(url);\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:reqwest::blocking::get",
            "env:API_URL"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn client_local_method_is_a_tracked_site() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "pub fn f() {\n    let client = reqwest::Client::new();\n    let _ = client.get(\"https://c.example.com\");\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:reqwest::Client::new",
            "expr:reqwest::Client::new()"
        ),
        "{}",
        dump(&c)
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "f",
            "rust:reqwest::Client::get",
            "https://c.example.com"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn method_parameters_exclude_the_receiver_and_symbols_are_impl_qualified() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "use std::net::TcpStream;\npub struct Api;\npub struct Store<T>(T);\npub trait Probe { fn probe(&self) -> bool; }\nimpl Api {\n    pub fn get(&self, path: &str) {\n        let _ = reqwest::blocking::get(path);\n    }\n}\nimpl<T> Store<T> {\n    pub fn sync(&self) {\n        let _ = TcpStream::connect(\"s.example.com:1\");\n    }\n}\nimpl Probe for Api {\n    fn probe(&self) -> bool {\n        TcpStream::connect(\"p.example.com:1\").is_ok()\n    }\n}\npub mod net {\n    pub fn ping() {\n        let _ = std::net::TcpStream::connect(\"n.example.com:1\");\n        let f = || std::net::TcpStream::connect(\"c.example.com:1\");\n        let _ = f;\n    }\n}\n",
        ),
    ]);
    let d = dump(&c);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "<impl Api>::get",
            "rust:reqwest::blocking::get",
            "param:1:<impl Api>::get"
        ),
        "{d}"
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "<impl Store>::sync",
            "rust:std::net::TcpStream::connect",
            "s.example.com:1"
        ),
        "{d}"
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "<impl Probe for Api>::probe",
            "rust:std::net::TcpStream::connect",
            "p.example.com:1"
        ),
        "{d}"
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "net::ping",
            "rust:std::net::TcpStream::connect",
            "n.example.com:1"
        ),
        "{d}"
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "net::ping::<closure>",
            "rust:std::net::TcpStream::connect",
            "c.example.com:1"
        ),
        "{d}"
    );
}

#[test]
fn cfg_variants_of_one_function_get_ordinals_zero_and_one() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "#[cfg(unix)]\npub fn ping() {\n    let _ = std::net::TcpStream::connect(\"a.example.com:1\");\n}\n#[cfg(not(unix))]\npub fn ping() {\n    let _ = std::net::TcpStream::connect(\"a.example.com:1\");\n}\n",
        ),
    ]);
    let mut report = Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "egress-plane".into(),
            version: "0".into(),
            data_digest: String::new(),
            runtime_range: RuntimeRange {
                python: String::new(),
                node: String::new(),
                rust: String::new(),
            },
        },
        completeness: Completeness {
            state: CompletenessState::Complete,
            budget_exceeded: Vec::new(),
            coverage: Coverage::default(),
        },
        caveats: Vec::new(),
        sites: c.sites.clone(),
        blind_spots: Vec::new(),
        unscanned_dependencies: Vec::new(),
        excluded: Vec::new(),
    };
    finalize(&mut report);
    let ords: Vec<u32> = report.sites.iter().map(|s| s.ordinal).collect();
    assert_eq!(ords, vec![0, 1], "{:#?}", report.sites);
    assert!(report.sites.iter().all(|s| s.symbol == "ping"));
}

#[test]
fn cfg_test_scopes_take_the_test_label() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "use std::net::TcpStream;\npub fn up() -> bool {\n    TcpStream::connect(\"a.example.com:1\").is_ok()\n}\n#[cfg(test)]\nmod tests {\n    use std::net::TcpStream;\n    #[test]\n    fn staging() {\n        assert!(TcpStream::connect(\"s.example.com:1\").is_ok());\n    }\n}\n#[test]\nfn top_level_test() {\n    let _ = std::net::TcpStream::connect(\"t.example.com:1\");\n}\n",
        ),
    ]);
    let label = |dest: &str| -> Vec<Label> {
        c.sites
            .iter()
            .find(|s| s.destination.display == dest)
            .unwrap_or_else(|| panic!("{dest}: {}", dump(&c)))
            .labels
            .clone()
    };
    assert_eq!(label("a.example.com:1"), Vec::<Label>::new());
    assert_eq!(label("s.example.com:1"), vec![Label::Test]);
    assert_eq!(label("t.example.com:1"), vec![Label::Test]);
    assert!(has_site(
        &c,
        "src/lib.rs",
        "tests::staging",
        "rust:std::net::TcpStream::connect",
        "s.example.com:1"
    ));
}

#[test]
fn local_items_named_like_egress_calls_are_not_sites() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "pub fn get(url: &str) -> usize { url.len() }\npub fn connect(a: &str) -> bool { !a.is_empty() }\npub fn run() -> usize {\n    let _ = connect(\"api.example.com:443\");\n    get(\"https://api.example.com/x\")\n}\n// std::net::TcpStream::connect in a comment\npub const HELP: &str = \"Command::new(\\\"curl\\\")\";\n",
        ),
    ]);
    assert!(c.sites.is_empty(), "{}", dump(&c));
    assert!(c.blind_spots.is_empty(), "{}", dump(&c));
    assert!(c.unscanned_dependencies.is_empty(), "{}", dump(&c));
}

// ---- egress traits and type positions --------------------------------------

#[test]
fn imported_egress_traits_are_sites_at_the_use() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "use std::net::ToSocketAddrs;\nuse std::os::unix::process::CommandExt;\npub fn f() {\n    let _ = (\"h.example.com\", 80).to_socket_addrs();\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "<module>",
            "rust:std::net::ToSocketAddrs",
            "expr:std::net::ToSocketAddrs"
        ),
        "{}",
        dump(&c)
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "<module>",
            "rust:std::os::unix::process::CommandExt",
            "expr:std::os::unix::process::CommandExt"
        ),
        "{}",
        dump(&c)
    );
    assert_eq!(c.sites.len(), 2, "{}", dump(&c));
}

/// Each path naming an item is a reference, whatever its position.
#[test]
fn type_positions_bounds_return_types_and_ufcs_paths_are_references() {
    let src = "use std::net::{TcpStream, UdpSocket, ToSocketAddrs};\nuse std::io::Read;\nuse std::os::fd::FromRawFd;\npub fn a(fd: std::os::fd::OwnedFd) {\n    let s: TcpStream = fd.into();\n    let _ = s;\n}\npub unsafe fn b() {\n    let _ = TcpStream::from_raw_fd(3);\n}\npub fn c<T: ToSocketAddrs>(t: T) -> T { t }\npub fn d() -> Option<UdpSocket> { None }\npub fn e(s: &mut TcpStream, buf: &mut [u8]) {\n    let _ = <TcpStream as Read>::read(s, buf);\n}\n";
    let ir = lower(b"src/lib.rs", src).expect("lowers");
    let named = |name: &str, symbol: &str, kind: UseKind| {
        ir.references.iter().any(|r| {
            r.symbol == symbol
                && r.use_kind == kind
                && (matches!(&r.root, Root::Import(l) if l == name)
                    || r.members.iter().any(|m| m == name))
        })
    };
    assert!(
        named("TcpStream", "a", UseKind::TypePosition),
        "{:#?}",
        ir.references
    );
    assert!(
        ir.references.iter().any(|r| r.symbol == "b"
            && r.use_kind == UseKind::Call
            && matches!(&r.root, Root::Import(l) if l == "TcpStream")
            && r.members == ["from_raw_fd"]),
        "{:#?}",
        ir.references
    );
    assert!(
        named("ToSocketAddrs", "c", UseKind::TypePosition),
        "{:#?}",
        ir.references
    );
    assert!(
        named("UdpSocket", "d", UseKind::TypePosition),
        "{:#?}",
        ir.references
    );
    assert!(
        named("TcpStream", "e", UseKind::TypePosition),
        "{:#?}",
        ir.references
    );
    assert!(
        ir.references.iter().any(|r| r.symbol == "e"
            && r.use_kind == UseKind::Call
            && matches!(&r.root, Root::Import(l) if l == "TcpStream")
            && r.members == ["read"]),
        "{:#?}",
        ir.references
    );

    let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", src)]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "b",
            "rust:std::net::TcpStream::from_raw_fd",
            "expr:TcpStream::from_raw_fd(3)"
        ),
        "{}",
        dump(&c)
    );
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "c",
            "rust:std::net::ToSocketAddrs",
            "expr:ToSocketAddrs"
        ),
        "{}",
        dump(&c)
    );
}

// ---- paths, includes, and native code --------------------------------------

/// An absolute `#[path]` target is outside the root and never printed.
#[test]
fn absolute_path_attribute_is_outside_root_and_never_printed() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/main.rs",
            "#[path = \"/opt/payload/net.rs\"]\nmod net;\nconst P: &str = include_str!(\"../../../etc/passwd\");\nfn main() { let _ = P; }\n",
        ),
    ]);
    assert_eq!(
        blind(&c, "src/main.rs", BlindSpotKind::ReferenceOutsideRoot),
        2,
        "{}",
        dump(&c)
    );
    let out = dump(&c);
    assert!(!out.contains("/opt/payload"), "{out}");
    assert!(!out.contains("etc/passwd"), "{out}");
    assert!(
        c.blind_spots
            .iter()
            .filter(|b| b.kind == BlindSpotKind::ReferenceOutsideRoot)
            .all(|b| b.symbol == "<module>")
    );
}

#[test]
fn path_attribute_and_include_targets_that_are_not_code_are_loaded_as_code() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "#[path = \"net.txt\"]\nmod net;\ninclude!(\"payload.in\");\n",
        ),
        ("src/net.txt", "fn x() {}\n"),
        ("src/payload.in", "fn y() {}\n"),
    ]);
    for f in ["src/net.txt", "src/payload.in"] {
        assert_eq!(
            blind(&c, f, BlindSpotKind::LoadedAsCode),
            1,
            "{f}: {}",
            dump(&c)
        );
    }
    assert_eq!(c.loaded_as_code, 2);
}

#[test]
fn path_attribute_in_root_resolves_and_mod_files_map() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/main.rs",
            "#[path = \"platform/linux_net.rs\"]\nmod net;\nmod util;\nfn main() { net::connect(); util::go(); }\n",
        ),
        (
            "src/platform/linux_net.rs",
            "pub fn connect() { let _ = std::net::TcpStream::connect(\"l.example.com:1\"); }\n",
        ),
        ("src/util/mod.rs", "mod deep;\npub use deep::go;\n"),
        (
            "src/util/deep.rs",
            "pub fn go() {}\npub fn dial() { let _ = super::super::helper(); }\n",
        ),
    ]);
    assert!(c.blind_spots.is_empty(), "{}", dump(&c));
    assert!(has_site(
        &c,
        "src/platform/linux_net.rs",
        "connect",
        "rust:std::net::TcpStream::connect",
        "l.example.com:1"
    ));
}

#[test]
fn native_code_and_non_literal_includes_are_blind_spots() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "extern \"C\" {\n    fn f();\n}\npub fn g() {\n    unsafe { std::arch::asm!(\"nop\"); }\n}\ninclude!(concat!(env!(\"OUT_DIR\"), \"/gen.rs\"));\n#[link(name = \"m\")]\nunsafe extern \"C\" {}\n",
        ),
    ]);
    let d = dump(&c);
    assert!(
        blind(&c, "src/lib.rs", BlindSpotKind::NativeCode) >= 3,
        "{d}"
    );
    assert_eq!(blind(&c, "src/lib.rs", BlindSpotKind::MacroCode), 1, "{d}");
}

#[test]
fn literal_include_str_and_plain_unsafe_produce_no_blind_spot() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "pub const D: &str = include_str!(\"data.txt\");\npub fn f(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n",
        ),
        ("src/data.txt", "hello\n"),
    ]);
    assert!(c.blind_spots.is_empty(), "{}", dump(&c));
    assert!(c.sites.is_empty(), "{}", dump(&c));
}

#[test]
fn first_party_proc_macro_invocation_is_a_blind_spot() {
    let c = scan(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"macros\"]\n",
        ),
        (
            "macros/Cargo.toml",
            "[package]\nname = \"my-macros\"\nversion = \"0.1.0\"\n\n[lib]\nproc-macro = true\n",
        ),
        (
            "macros/src/lib.rs",
            "use proc_macro::TokenStream;\n#[proc_macro]\npub fn make(t: TokenStream) -> TokenStream { t }\n",
        ),
        (
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nmy-macros = { path = \"../macros\" }\n",
        ),
        ("app/src/main.rs", "my_macros::make!();\nfn main() {}\n"),
    ]);
    assert_eq!(
        blind(&c, "app/src/main.rs", BlindSpotKind::MacroCode),
        1,
        "{}",
        dump(&c)
    );
}

// ---- errors, spans, and positions ------------------------------------------

#[test]
fn syntax_syn_rejects_is_a_parse_error() {
    assert_eq!(
        lower(b"src/broken.rs", "pub fn broken( -> {\n").err(),
        Some(LowerError::Parse)
    );
    // Unstable `box` syntax.
    assert_eq!(
        lower(b"src/boxed.rs", "fn f() { let x = box 5; }\n").err(),
        Some(LowerError::Parse)
    );
}

#[test]
fn files_lowered_in_sequence_on_one_thread_report_their_own_lines() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let first =
                "\n\n\n\n\n\nuse std::process::Command;\nfn a() { let _ = Command::new(\"a\"); }\n";
            let second = "use std::process::Command;\nfn b() { let _ = Command::new(\"b\"); }\n";
            let ir1 = lower(b"src/a.rs", first).expect("first");
            let ir2 = lower(b"src/b.rs", second).expect("second");
            let call = |ir: &FileIr| {
                ir.references
                    .iter()
                    .find(|r| r.use_kind == UseKind::Call)
                    .map(|r| (r.location.line, r.location.column))
            };
            assert_eq!(call(&ir1), Some((8, 18)));
            assert_eq!(call(&ir2), Some((2, 18)));
            // Span data does not accumulate across files: after a lowering,
            // the next source parsed on this thread starts at the beginning
            // of the thread's span map again.
            let ts = proc_macro2::TokenStream::from_str("x").expect("tokens");
            let tt = ts.into_iter().next().expect("one token");
            assert_eq!(format!("{:?}", tt.span()), "bytes(1..2)");
        })
        .expect("thread")
        .join()
        .expect("join");
}

#[test]
fn columns_count_unicode_scalar_values() {
    let src = "use std::process::Command;\nfn f() { /*é*/ let _ = Command::new(\"x\"); }\n";
    let ir = lower(b"src/lib.rs", src).expect("lowers");
    let r = ir
        .references
        .iter()
        .find(|r| r.use_kind == UseKind::Call)
        .expect("call");
    // `fn f() { /*é*/ let _ = ` is 23 characters, so the call starts at 24.
    assert_eq!((r.location.line, r.location.column), (2, 24));
}

#[test]
fn nesting_at_the_prescan_cap_lowers_and_beyond_it_is_refused_first() {
    let depth = egress_core::prescan::MAX_DEPTH;
    let ok = format!(
        "fn f() {{ let _ = {}1{}; }}\n",
        "(".repeat(depth - 2),
        ")".repeat(depth - 2)
    );
    assert!(!egress_core::prescan::too_deep(Language::Rust, &ok));
    let deep = format!(
        "fn f() {{ let _ = {}1{}; }}\n",
        "(".repeat(4 * 1024 * 1024),
        ")".repeat(4 * 1024 * 1024)
    );
    assert!(egress_core::prescan::too_deep(Language::Rust, &deep));
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            assert!(lower(b"src/lib.rs", &ok).is_ok());
        })
        .expect("thread")
        .join()
        .expect("join");
}

#[test]
fn long_prefix_operator_chains_do_not_overflow_the_stack() {
    // Brackets are what the pre-scan counts; prefix operators and closures
    // nest the parser without brackets, so the frontend refuses long chains
    // itself before parsing.
    for chain in ["-", "!", "*", "&", "|| "] {
        let src = format!("fn f() {{ let _ = {}x; }}\n", chain.repeat(1_000_000));
        let r = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || lower(b"src/lib.rs", &src).err())
            .expect("thread")
            .join()
            .expect("join");
        assert_eq!(r, Some(LowerError::TooDeeplyNested), "{chain}");
    }
}

/// `use std::net::TcpStream as A0; use A0 as A1; ... use A{n-1} as A{n};`
/// with a call through the last alias.
fn alias_chain(n: usize) -> String {
    let mut s = String::from("use std::net::TcpStream as A0;\n");
    for i in 1..=n {
        s.push_str(&format!("use A{} as A{i};\n", i - 1));
    }
    s.push_str(&format!(
        "pub fn main() {{\n    let _ = A{n}::connect(\"h.example.com:1\");\n}}\n"
    ));
    s
}

#[test]
fn alias_chain_at_the_hop_cap_resolves() {
    let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", &alias_chain(8))]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "main",
            "rust:std::net::TcpStream::connect",
            "h.example.com:1"
        ),
        "{}",
        dump(&c)
    );
    assert_eq!(
        blind(&c, "src/lib.rs", BlindSpotKind::ResolutionLimit),
        0,
        "{}",
        dump(&c)
    );
}

#[test]
fn alias_chain_past_the_hop_cap_is_a_resolution_limit() {
    for n in [9, 12] {
        let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", &alias_chain(n))]);
        assert!(
            blind(&c, "src/lib.rs", BlindSpotKind::ResolutionLimit) >= 1,
            "{n}: {}",
            dump(&c)
        );
    }
}

// ---- type aliases --------------------------------------------------------------

const REQWEST_CARGO: &str = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nreqwest = { version = \"0.12\", features = [\"blocking\"] }\n";

/// The sites of `src/lib.rs` as (symbol, mechanism, destination), sorted.
fn site_keys(c: &Classified) -> Vec<(String, String, String)> {
    let mut v: Vec<_> = c
        .sites
        .iter()
        .map(|s| {
            (
                s.symbol.clone(),
                s.mechanism.clone(),
                s.destination.display.clone(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn module_type_alias_to_std_type_resolves() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "type T = std::net::TcpStream;\npub fn one() -> std::io::Result<T> {\n    T::connect(\"typealias-one.example:443\")\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "one",
            "rust:std::net::TcpStream::connect",
            "typealias-one.example:443"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn pub_type_alias_through_a_use_resolves() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "use std::net::TcpStream;\npub type U = TcpStream;\npub fn two() {\n    let _ = U::connect(\"typealias-two.example:443\");\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "two",
            "rust:std::net::TcpStream::connect",
            "typealias-two.example:443"
        ),
        "{}",
        dump(&c)
    );
}

#[test]
fn fn_local_type_alias_to_catalogued_crate_type_matches_the_direct_path() {
    let direct = scan(&[
        ("Cargo.toml", REQWEST_CARGO),
        (
            "src/lib.rs",
            "pub fn three() {\n    let _ = reqwest::blocking::Client::new().get(\"https://typealias-three.example/x\").send();\n    let c = reqwest::blocking::Client::new();\n    let _ = c.get(\"https://typealias-three.example/y\").send();\n}\n",
        ),
    ]);
    let aliased = scan(&[
        ("Cargo.toml", REQWEST_CARGO),
        (
            "src/lib.rs",
            "pub fn three() {\n    type C = reqwest::blocking::Client;\n    let _ = C::new().get(\"https://typealias-three.example/x\").send();\n    let c = C::new();\n    let _ = c.get(\"https://typealias-three.example/y\").send();\n}\n",
        ),
    ]);
    // A constructor destination is the expression text, which names the
    // alias; the mechanisms and the URL destination must match.
    let key = |c: &Classified| -> Vec<(String, String)> {
        site_keys(c)
            .into_iter()
            .map(|(sym, mech, dest)| {
                let dest = if dest.starts_with("expr:") {
                    String::new()
                } else {
                    dest
                };
                (format!("{sym} {mech}"), dest)
            })
            .collect()
    };
    assert!(
        has_site(
            &direct,
            "src/lib.rs",
            "three",
            "rust:reqwest::blocking::Client::get",
            "https://typealias-three.example/y"
        ),
        "{}",
        dump(&direct)
    );
    assert_eq!(key(&aliased), key(&direct), "{}", dump(&aliased));
}

#[test]
fn generic_type_alias_chain_resolves() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        (
            "src/lib.rs",
            "type A<X> = B<X>;\ntype B<X> = std::net::TcpStream;\npub fn four() {\n    let _ = A::<u8>::connect(\"typealias-four.example:443\");\n}\n",
        ),
    ]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "four",
            "rust:std::net::TcpStream::connect",
            "typealias-four.example:443"
        ),
        "{}",
        dump(&c)
    );
}

/// `type A0 = std::net::TcpStream; type A1 = A0; ... type A{n} = A{n-1};`
/// with a call through the last alias.
fn type_alias_chain(n: usize) -> String {
    let mut s = String::from("type A0 = std::net::TcpStream;\n");
    for i in 1..=n {
        s.push_str(&format!("type A{i} = A{};\n", i - 1));
    }
    s.push_str(&format!(
        "pub fn main() {{\n    let _ = A{n}::connect(\"h.example.com:1\");\n}}\n"
    ));
    s
}

#[test]
fn type_alias_chain_at_the_hop_cap_resolves_and_past_it_is_a_resolution_limit() {
    let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", &type_alias_chain(8))]);
    assert!(
        has_site(
            &c,
            "src/lib.rs",
            "main",
            "rust:std::net::TcpStream::connect",
            "h.example.com:1"
        ),
        "{}",
        dump(&c)
    );
    assert_eq!(
        blind(&c, "src/lib.rs", BlindSpotKind::ResolutionLimit),
        0,
        "{}",
        dump(&c)
    );
    for n in [9, 12] {
        let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", &type_alias_chain(n))]);
        assert!(
            blind(&c, "src/lib.rs", BlindSpotKind::ResolutionLimit) >= 1,
            "{n}: {}",
            dump(&c)
        );
    }
}

#[test]
fn cyclic_or_non_path_type_alias_used_as_a_call_root_is_a_resolution_limit() {
    for src in [
        "type A = B;\ntype B = A;\npub fn f() {\n    let _ = A::connect(\"h.example.com:1\");\n}\n",
        "type T = <std::net::TcpStream as Iterator>::Item;\npub fn f() {\n    let _ = T::connect(\"h.example.com:1\");\n}\n",
    ] {
        let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", src)]);
        assert!(
            blind(&c, "src/lib.rs", BlindSpotKind::ResolutionLimit) >= 1,
            "{src}\n{}",
            dump(&c)
        );
        assert!(c.sites.is_empty(), "{src}\n{}", dump(&c));
    }
}

#[test]
fn type_alias_to_first_party_or_inert_type_produces_nothing() {
    for src in [
        // A first-party type with a method named like an egress primitive.
        "struct Conn;\nimpl Conn {\n    fn connect(_: &str) -> Self { Conn }\n}\ntype T = Conn;\npub fn f() {\n    let _ = T::connect(\"h.example.com:1\");\n}\n",
        // A fn-local first-party type behind a fn-local alias.
        "pub fn f() {\n    struct Conn;\n    impl Conn {\n        fn connect(_: &str) -> Self { Conn }\n    }\n    type T = Conn;\n    let _ = T::connect(\"h.example.com:1\");\n}\n",
        // Inert std types.
        "type S = std::string::String;\ntype M = std::collections::HashMap<u8, u8>;\npub fn f() {\n    let _ = S::from(\"h.example.com:1\");\n    let _ = M::new();\n}\n",
        // A prelude generic alias and an unused alias.
        "type R<X> = Result<X, ()>;\ntype Unused = std::net::TcpStream;\npub fn f() -> R<u8> {\n    R::Ok(1)\n}\n",
        // A non-path alias used only in type position.
        "type F = fn(u8) -> u8;\npub fn f(g: F) -> u8 {\n    g(1)\n}\n",
    ] {
        let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", src)]);
        assert!(c.sites.is_empty(), "{src}\n{}", dump(&c));
        assert!(c.blind_spots.is_empty(), "{src}\n{}", dump(&c));
    }
}

// ---- type aliases across modules ---------------------------------------------

/// Whether `c` has the `TcpStream::connect` site in `file`/`symbol` for
/// `dest`.
fn has_connect(c: &Classified, file: &str, symbol: &str, dest: &str) -> bool {
    has_site(c, file, symbol, "rust:std::net::TcpStream::connect", dest)
}

#[test]
fn type_alias_in_another_file_resolves_through_a_use() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/m.rs", "pub type T = std::net::TcpStream;\n"),
        (
            "src/lib.rs",
            "mod m;\nuse crate::m::T;\npub fn f() {\n    let _ = T::connect(\"xalias-use.example:443\");\n}\n",
        ),
    ]);
    assert!(
        has_connect(&c, "src/lib.rs", "f", "xalias-use.example:443"),
        "{}",
        dump(&c)
    );
}

#[test]
fn type_alias_in_another_file_resolves_through_a_qualified_path() {
    for call in [
        "m::T::connect",
        "crate::m::T::connect",
        "self::m::T::connect",
    ] {
        let c = scan(&[
            ("Cargo.toml", CARGO),
            ("src/m.rs", "pub(crate) type T = std::net::TcpStream;\n"),
            (
                "src/lib.rs",
                &format!(
                    "mod m;\npub fn f() {{\n    let _ = {call}(\"xalias-path.example:443\");\n}}\n"
                ),
            ),
        ]);
        assert!(
            has_connect(&c, "src/lib.rs", "f", "xalias-path.example:443"),
            "{call}\n{}",
            dump(&c)
        );
    }
}

#[test]
fn type_alias_in_an_inline_module_resolves() {
    for src in [
        "mod m {\n    pub type T = std::net::TcpStream;\n}\npub fn f() {\n    let _ = m::T::connect(\"xalias-inline.example:443\");\n}\n",
        "mod m {\n    pub type T = std::net::TcpStream;\n}\nuse m::T;\npub fn f() {\n    let _ = T::connect(\"xalias-inline.example:443\");\n}\n",
        "mod m {\n    use std::net::TcpStream;\n    pub(crate) type T = TcpStream;\n}\npub fn f() {\n    let _ = crate::m::T::connect(\"xalias-inline.example:443\");\n}\n",
        "mod outer {\n    pub mod m {\n        pub type T = super::super::S;\n    }\n}\ntype S = std::net::TcpStream;\npub fn f() {\n    let _ = outer::m::T::connect(\"xalias-inline.example:443\");\n}\n",
    ] {
        let c = scan(&[("Cargo.toml", CARGO), ("src/lib.rs", src)]);
        assert!(
            has_connect(&c, "src/lib.rs", "f", "xalias-inline.example:443"),
            "{src}\n{}",
            dump(&c)
        );
    }
}

#[test]
fn type_alias_chain_across_two_files_resolves() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/a.rs", "pub type A = std::net::TcpStream;\n"),
        ("src/b.rs", "pub type B = crate::a::A;\n"),
        (
            "src/lib.rs",
            "mod a;\nmod b;\nuse b::B;\npub fn f() {\n    let _ = B::connect(\"xalias-chain.example:443\");\n}\npub fn g() {\n    let _ = b::B::connect(\"xalias-chain2.example:443\");\n}\n",
        ),
    ]);
    assert!(
        has_connect(&c, "src/lib.rs", "f", "xalias-chain.example:443"),
        "{}",
        dump(&c)
    );
    assert!(
        has_connect(&c, "src/lib.rs", "g", "xalias-chain2.example:443"),
        "{}",
        dump(&c)
    );
}

#[test]
fn type_alias_in_another_file_to_first_party_or_inert_type_produces_nothing() {
    for m in [
        "pub struct Conn;\nimpl Conn {\n    pub fn connect(_: &str) -> Self { Conn }\n}\npub type T = Conn;\n",
        "pub type T = String;\n",
        "pub type T = std::string::String;\n",
        "pub type T = Vec<u8>;\n",
        "pub type T<X> = X;\n",
        "pub type T = (u8, u8);\n",
    ] {
        let c = scan(&[
            ("Cargo.toml", CARGO),
            ("src/m.rs", m),
            (
                "src/lib.rs",
                "mod m;\nuse m::T;\npub fn f() {\n    let _ = T::connect(\"h.example.com:1\");\n    let _ = m::T::from(\"h.example.com:1\");\n}\n",
            ),
        ]);
        assert!(c.sites.is_empty(), "{m}\n{}", dump(&c));
        assert!(c.blind_spots.is_empty(), "{m}\n{}", dump(&c));
        assert!(c.unscanned_dependencies.is_empty(), "{m}\n{}", dump(&c));
    }
}

#[test]
fn cyclic_type_alias_in_another_file_produces_no_site() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/m.rs", "pub type T = U;\npub type U = T;\n"),
        (
            "src/lib.rs",
            "mod m;\nuse m::T;\npub fn f() {\n    let _ = T::connect(\"h.example.com:1\");\n    let _ = m::U::connect(\"h.example.com:1\");\n}\n",
        ),
    ]);
    assert!(c.sites.is_empty(), "{}", dump(&c));
}

#[test]
fn type_alias_to_a_glob_imported_name_in_another_file_resolves() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/m.rs", "use std::net::*;\npub type T = TcpStream;\n"),
        (
            "src/lib.rs",
            "mod m;\npub fn f() {\n    let _ = m::T::connect(\"xalias-glob.example:443\");\n}\n",
        ),
    ]);
    assert!(
        has_connect(&c, "src/lib.rs", "f", "xalias-glob.example:443"),
        "{}",
        dump(&c)
    );
}

#[test]
fn type_alias_past_the_use_hop_cap_is_a_resolution_limit_not_silence() {
    let mut m = String::from("use std::net::TcpStream as A0;\n");
    for i in 1..=8 {
        m.push_str(&format!("use A{} as A{i};\n", i - 1));
    }
    m.push_str("pub type T = A8;\n");
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/m.rs", &m),
        (
            "src/lib.rs",
            "mod m;\npub fn f() {\n    let _ = m::T::connect(\"h.example.com:1\");\n}\n",
        ),
    ]);
    assert!(
        has_connect(&c, "src/lib.rs", "f", "h.example.com:1")
            || blind(&c, "src/m.rs", BlindSpotKind::ResolutionLimit) >= 1,
        "{}",
        dump(&c)
    );
}

#[test]
fn fn_local_or_glob_type_aliases_to_inert_types_in_another_file_produce_nothing() {
    for m in [
        "use std::collections::*;\npub type T = HashMap<u8, u8>;\n",
        "pub fn g() {\n    type T = std::net::TcpStream;\n}\npub struct T;\nimpl T {\n    pub fn connect(_: &str) {}\n}\n",
    ] {
        let c = scan(&[
            ("Cargo.toml", CARGO),
            ("src/m.rs", m),
            (
                "src/lib.rs",
                "mod m;\npub fn f() {\n    let _ = m::T::connect(\"h.example.com:1\");\n    let _ = m::T::new();\n}\n",
            ),
        ]);
        assert!(c.sites.is_empty(), "{m}\n{}", dump(&c));
        assert!(c.blind_spots.is_empty(), "{m}\n{}", dump(&c));
    }
}

/// An alias to a name only a glob can bind is looked up through the
/// module's globs, as `m::Name` through a glob re-export is: a prelude name
/// there gets the glob's conservative module escape, never a specific
/// mechanism.
#[test]
fn type_alias_to_a_prelude_name_beside_a_glob_is_at_most_the_glob_escape() {
    let c = scan(&[
        ("Cargo.toml", CARGO),
        ("src/m.rs", "use std::net::*;\npub type T = String;\n"),
        (
            "src/lib.rs",
            "mod m;\npub fn f() {\n    let _ = m::T::connect(\"h.example.com:1\");\n}\n",
        ),
    ]);
    assert!(
        c.sites.iter().all(|s| s.mechanism == "rust:std::net"),
        "{}",
        dump(&c)
    );
}

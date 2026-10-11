//! Data guards over the embedded primitive lists, catalog, and inventory.
//! Each guard runs on the real data and, for deletion and misclassification
//! cases, on a mutated copy that must fail.

use std::path::{Path, PathBuf};

use egress_core::data::guards::{self, Deferred};
use egress_core::data::{
    Classification, Data, EMBEDDED, EntryKind, ModuleClass, RuntimeData, data_digest,
};
use egress_core::model::Language;

fn data() -> Data {
    Data::embedded().unwrap_or_else(|e| panic!("{e}"))
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus() -> PathBuf {
    repo().join("fixtures/corpus")
}

fn deferred() -> Deferred {
    let text = std::fs::read_to_string(corpus().join("deferred.toml"))
        .unwrap_or_else(|e| panic!("deferred.toml: {e}"));
    guards::parse_deferred(&text).unwrap_or_else(|e| panic!("{e}"))
}

fn assert_clean(what: &str, v: Vec<String>) {
    assert!(v.is_empty(), "{what}:\n  {}", v.join("\n  "));
}

fn id_of(c: Option<Classification<'_>>) -> String {
    match c {
        Some(Classification::Entry(e)) => e.id.clone(),
        Some(Classification::Module(m)) => format!("module {}", m.name),
        Some(Classification::Package(p)) => format!("package {}", p.name),
        None => "none".into(),
    }
}

fn lookup<'a>(rt: &'a RuntimeData, path: &str) -> Option<Classification<'a>> {
    guards::lookup_path(rt, path)
}

const PYTHON_DENY: &[&str] = &[
    "asyncio",
    "logging.config",
    "logging.handlers",
    "multiprocessing",
    "concurrent.futures",
    "pkgutil",
    "runpy",
    "importlib",
    "importlib.abc",
    "importlib.machinery",
    "importlib.metadata",
    "importlib.resources",
    "importlib.util",
    "site",
    "sys",
    "builtins",
    "tkinter",
    "sqlite3",
    "platform",
    "ctypes.util",
    "webbrowser",
    "pydoc",
    "ensurepip",
    "venv",
    "xml.sax",
    "xml.dom",
    "timeit",
    "code",
    "codeop",
    "pdb",
    "bdb",
    "cProfile",
    "profile",
    "trace",
    "doctest",
    "marshal",
    "types",
    "gc",
    "inspect",
];

const NODE_DENY: &[&str] = &["module", "inspector", "dns", "repl", "wasi"];

fn deny(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => PYTHON_DENY,
        Language::Javascript => NODE_DENY,
        Language::Rust => &[],
    }
}

// ---- loader -----------------------------------------------------------------

#[test]
fn loader_reads_every_embedded_file_with_a_stable_digest() {
    let a = data();
    let b = data();
    assert_eq!(a.data_digest, b.data_digest);
    let files: Vec<(&str, &str)> = EMBEDDED.iter().map(|f| (f.path, f.text)).collect();
    assert_eq!(a.data_digest, data_digest(&files));
    for f in EMBEDDED {
        let on_disk = std::fs::read_to_string(repo().join(f.path))
            .unwrap_or_else(|e| panic!("{}: {e}", f.path));
        assert_eq!(on_disk, f.text, "{} is stale in the build", f.path);
    }
}

#[test]
fn runtime_range_matches_the_declared_range() {
    let d = data();
    assert_eq!(d.runtime_range.python, "3.8-3.13");
    assert_eq!(d.runtime_range.node, "18-22");
    let toolchain = std::fs::read_to_string(repo().join("rust-toolchain.toml"))
        .unwrap_or_else(|e| panic!("{e}"));
    let table: toml::Table = toml::from_str(&toolchain).unwrap_or_else(|e| panic!("{e}"));
    let channel = table["toolchain"]["channel"]
        .as_str()
        .unwrap_or_else(|| panic!("no channel"));
    assert_eq!(d.runtime_range.rust, channel);
}

// ---- stdlib classification guard -------------------------------------------

#[test]
fn every_stdlib_module_is_classified_exactly_once() {
    let d = data();
    for lang in Language::ALL {
        assert_clean(
            lang.as_str(),
            guards::stdlib_classification(d.runtime(lang)),
        );
    }
}

#[test]
fn deleting_an_inert_module_turns_the_stdlib_guard_red() {
    let d = data();
    for (lang, name) in [
        (Language::Python, "json"),
        (Language::Javascript, "path"),
        (Language::Rust, "std::fmt"),
    ] {
        let mut rt = d.runtime(lang).clone();
        assert_eq!(rt.module(name).map(|m| m.class), Some(ModuleClass::Inert));
        rt.modules.retain(|m| m.name != name);
        let v = guards::stdlib_classification(&rt);
        assert!(v.iter().any(|s| s.contains(name)), "{lang:?}: {v:?}");
    }
}

#[test]
fn python_list_covers_modules_removed_within_the_range() {
    let d = data();
    let py = d.runtime(Language::Python);
    for m in [
        "imp",
        "distutils",
        "asyncore",
        "asynchat",
        "smtpd",
        "telnetlib",
        "nntplib",
        "cgi",
        "pipes",
    ] {
        assert!(
            py.inventory.stdlib_modules.iter().any(|s| s == m),
            "{m} missing from the standard library list"
        );
        assert!(py.module(m).is_some(), "{m} unclassified");
    }
    for m in ["telnetlib", "nntplib"] {
        assert_eq!(
            py.module(m).map(|x| x.class),
            Some(ModuleClass::Egress),
            "{m}"
        );
    }
    let mut rt = py.clone();
    rt.modules.retain(|m| m.name != "asynchat");
    let v = guards::stdlib_classification(&rt);
    assert!(v.iter().any(|s| s.contains("asynchat")), "{v:?}");
}

// ---- per-entry fixture guard -------------------------------------------------

#[test]
fn every_entry_names_a_fixture_that_labels_it_or_is_deferred() {
    let d = data();
    let def = deferred();
    for lang in Language::ALL {
        assert_clean(
            lang.as_str(),
            guards::fixtures(d.runtime(lang), &corpus(), &def),
        );
    }
    let all: Vec<&RuntimeData> = Language::ALL.iter().map(|l| d.runtime(*l)).collect();
    assert_clean(
        "deferred.toml",
        guards::stale_deferred(&all, &corpus(), &def),
    );
}

#[test]
fn deleting_a_fixture_turns_the_fixture_guard_red() {
    let d = data();
    let def = deferred();
    for lang in Language::ALL {
        let mut rt = d.runtime(lang).clone();
        let e = rt
            .entries
            .iter_mut()
            .find(|e| matches!(e.kind, EntryKind::Egress(_)) && !def.cases.contains(&e.fixture))
            .unwrap_or_else(|| panic!("{lang:?}: no authored egress fixture"));
        let id = e.id.clone();
        e.fixture = format!("{}/primitives/deleted-fixture", lang.as_str());
        let v = guards::fixtures(&rt, &corpus(), &def);
        assert!(v.iter().any(|s| s.contains(&id)), "{lang:?}: {v:?}");
    }
}

/// A module used as a value is a site whose mechanism names the module
/// itself (the escape rule): accepted when the data classifies that module
/// as egress or lists an egress entry under it, as the escape rule requires.
fn escaped_module(rt: &RuntimeData, mechanism: &str) -> bool {
    let Some((_, name)) = mechanism.split_once(':') else {
        return false;
    };
    rt.module(name)
        .is_some_and(|m| m.class == ModuleClass::Egress)
        || rt
            .entries
            .iter()
            .any(|e| e.module == name && matches!(e.kind, EntryKind::Egress(_)))
}

#[test]
fn every_corpus_mechanism_is_a_data_entry() {
    let d = data();
    let mut missing = Vec::new();
    let mut stack = vec![corpus()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{e}"))
            .flatten()
        {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n != "tree") {
                    stack.push(p);
                }
            } else if p.file_name().is_some_and(|n| n == "expected.toml") {
                let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{e}"));
                let t: toml::Table = toml::from_str(&text).unwrap_or_else(|e| panic!("{e}"));
                for s in t
                    .get("sites")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                {
                    let m = s["mechanism"].as_str().unwrap_or_default();
                    let lang = Language::parse(m.split(':').next().unwrap_or_default())
                        .unwrap_or_else(|| panic!("{m}"));
                    if d.runtime(lang).entry(m).is_none() && !escaped_module(d.runtime(lang), m) {
                        missing.push(format!("{m} ({})", p.display()));
                    }
                }
            }
        }
    }
    missing.sort();
    missing.dedup();
    assert_clean("corpus mechanisms without a data entry", missing);
}

// ---- deny-list guard -----------------------------------------------------------

#[test]
fn no_deny_list_module_is_wholly_inert() {
    let d = data();
    for lang in Language::ALL {
        assert_clean(
            lang.as_str(),
            guards::deny_list(d.runtime(lang), deny(lang)),
        );
    }
}

#[test]
fn marking_a_deny_list_module_inert_turns_the_guard_red() {
    let d = data();
    for (lang, name) in [
        (Language::Python, "asyncio"),
        (Language::Python, "pkgutil"),
        (Language::Python, "sys"),
        (Language::Python, "inspect"),
        (Language::Python, "marshal"),
        (Language::Python, "types"),
        (Language::Python, "gc"),
        (Language::Python, "pdb"),
        (Language::Python, "code"),
        (Language::Javascript, "module"),
    ] {
        let mut rt = d.runtime(lang).clone();
        let m = rt
            .modules
            .iter_mut()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("{name} unclassified"));
        m.class = ModuleClass::Inert;
        m.justification = Some("mutation".into());
        // Drop the module's own entries so its classification decides.
        rt.entries
            .retain(|e| !(e.module == name && e.members.is_empty()));
        let v = guards::deny_list(&rt, deny(lang));
        assert!(v.iter().any(|s| s.contains(name)), "{name}: {v:?}");
    }
}

// ---- inventory guard -------------------------------------------------------------

#[test]
fn every_inventory_member_is_classified() {
    let d = data();
    for lang in Language::ALL {
        assert_clean(
            lang.as_str(),
            guards::inventory(d.runtime(lang), deny(lang)),
        );
    }
}

#[test]
fn removing_a_socket_member_classification_turns_the_inventory_guard_red() {
    let d = data();
    let mut rt = d.runtime(Language::Python).clone();
    let members = rt.inventory.members["socket"].clone();
    assert!(members.iter().any(|m| m == "create_connection"));
    rt.entries
        .retain(|e| e.id != "python:socket.create_connection");
    let v = guards::inventory(&rt, PYTHON_DENY);
    assert!(
        v.iter().any(|s| s.contains("socket.create_connection")),
        "{v:?}"
    );
}

#[test]
fn inert_module_outside_the_deny_list_needs_no_inventory() {
    let d = data();
    let py = d.runtime(Language::Python);
    assert_eq!(py.module("json").map(|m| m.class), Some(ModuleClass::Inert));
    assert!(!py.inventory.members.contains_key("json"));
    assert_clean("python", guards::inventory(py, PYTHON_DENY));
}

// ---- member-inert rule ------------------------------------------------------------

#[test]
fn members_named_by_the_member_inert_rule_are_never_inert() {
    let d = data();
    assert_clean(
        "python",
        guards::not_inert(
            d.runtime(Language::Python),
            &[
                "python:asyncio.get_running_loop",
                "python:asyncio.get_event_loop",
                "python:asyncio.new_event_loop",
                "python:concurrent.futures.ProcessPoolExecutor",
                "python:platform.architecture",
                "python:ctypes.util.find_library",
                "python:pkgutil.resolve_name",
                "python:logging.config.dictConfig",
                "python:tkinter.Tcl",
                "python:sqlite3.connect",
                "python:sqlite3.Connection.load_extension",
            ],
        ),
    );
    assert_clean(
        "javascript",
        guards::not_inert(
            d.runtime(Language::Javascript),
            &["javascript:module._load"],
        ),
    );
    let rs = d.runtime(Language::Rust);
    for m in ["sync", "time", "task"] {
        match lookup(rs, &format!("tokio::{m}")) {
            Some(Classification::Entry(e)) => assert!(
                matches!(&e.kind, EntryKind::Inert { justification } if !justification.is_empty()),
                "tokio::{m}: {e:?}"
            ),
            other => panic!("tokio::{m}: {other:?}"),
        }
    }
    for m in ["net", "process"] {
        match lookup(rs, &format!("tokio::{m}::Anything")) {
            Some(Classification::Entry(e)) => {
                assert!(matches!(e.kind, EntryKind::Egress(_)), "tokio::{m}: {e:?}")
            }
            other => panic!("tokio::{m}: {other:?}"),
        }
    }
}

// ---- ambient module ------------------------------------------------------------------

#[test]
fn ambient_aliases_reach_one_entry() {
    let d = data();
    let py = d.runtime(Language::Python);
    for chain in [
        &["eval"][..],
        &["builtins", "eval"],
        &["__builtins__", "eval"],
    ] {
        assert_eq!(
            id_of(py.lookup_global(chain)),
            "python:builtins.eval",
            "{chain:?}"
        );
    }
    let js = d.runtime(Language::Javascript);
    for chain in [
        &["fetch"][..],
        &["globalThis", "fetch"],
        &["window", "fetch"],
        &["self", "fetch"],
        &["global", "fetch"],
        &["top", "fetch"],
        &["parent", "fetch"],
        &["frames", "fetch"],
        &["document", "defaultView", "fetch"],
    ] {
        assert_eq!(
            id_of(js.lookup_global(chain)),
            "javascript:globalThis.fetch",
            "{chain:?}"
        );
    }
    // `globalThis.process` is the `process` module.
    assert_eq!(
        id_of(js.lookup_global(&["process", "binding"])),
        "javascript:process.binding"
    );
    assert_eq!(
        id_of(js.lookup_global(&["globalThis", "process", "binding"])),
        "javascript:process.binding"
    );
}

// ---- closure sections ---------------------------------------------------------------

const INTROSPECTION_INERT: &[&str] = &[
    "__name__",
    "__qualname__",
    "__doc__",
    "__module__",
    "__class__",
    "__init__",
    "__file__",
    "__version__",
];

const INTROSPECTION_NEVER_INERT: &[&str] =
    &["__self__", "__globals__", "__subclasses__", "f_builtins"];

fn introspection_violations(rt: &RuntimeData) -> Vec<String> {
    let names: Vec<&str> = rt
        .closure
        .introspection_inert
        .iter()
        .map(|n| n.name.as_str())
        .collect();
    let mut v = Vec::new();
    for n in INTROSPECTION_INERT {
        if !names.contains(n) {
            v.push(format!("{n} missing from the introspection inert list"));
        }
    }
    for n in INTROSPECTION_NEVER_INERT {
        if names.contains(n) {
            v.push(format!("{n} must not be on the introspection inert list"));
        }
    }
    v
}

#[test]
fn python_introspection_inert_list_is_exact_and_justified() {
    let d = data();
    let py = d.runtime(Language::Python);
    assert_clean("python", introspection_violations(py));
    for n in &py.closure.introspection_inert {
        assert!(!n.justification.trim().is_empty(), "{}", n.name);
        assert!(!n.fixture.trim().is_empty(), "{}", n.name);
    }
    for p in ["tb_", "f_", "gi_", "cr_", "ag_"] {
        assert!(
            py.closure.introspection_prefixes.iter().any(|x| x == p),
            "{p}"
        );
    }
    let mut mutated = py.clone();
    mutated
        .closure
        .introspection_inert
        .push(egress_core::data::InertName {
            name: "__self__".into(),
            justification: "mutation".into(),
            fixture: "python/closure/x".into(),
        });
    assert!(
        introspection_violations(&mutated)
            .iter()
            .any(|s| s.contains("__self__"))
    );
}

#[test]
fn rust_egress_traits_and_raw_fd_constructors_are_egress_entries() {
    let d = data();
    let rs = d.runtime(Language::Rust);
    let ids = [
        "rust:std::net::ToSocketAddrs",
        "rust:std::os::unix::process::CommandExt",
        "rust:std::net::TcpStream::from_raw_fd",
        "rust:std::net::TcpListener::from_raw_fd",
        "rust:std::net::UdpSocket::from_raw_fd",
        "rust:std::os::unix::net::UnixStream::from_raw_fd",
        "rust:std::os::unix::net::UnixListener::from_raw_fd",
        "rust:std::os::unix::net::UnixDatagram::from_raw_fd",
    ];
    for id in ids {
        assert!(
            matches!(rs.entry(id).map(|e| &e.kind), Some(EntryKind::Egress(_))),
            "{id}"
        );
        assert!(rs.closure.egress_traits.iter().any(|t| t == id), "{id}");
    }
}

#[test]
fn require_equivalents_are_listed() {
    let d = data();
    let js = d.runtime(Language::Javascript);
    for r in [
        "createRequire",
        "module.require",
        "require.main.require",
        "process.mainModule.require",
        "module.constructor._load",
        "process.getBuiltinModule",
    ] {
        assert!(js.closure.require_equivalents.iter().any(|x| x == r), "{r}");
    }
}

// ---- classification examples ------------------------------------------------------

#[test]
fn os_path_is_wholly_inert_and_os_is_not() {
    let d = data();
    let py = d.runtime(Language::Python);
    assert_eq!(
        py.module("os.path").map(|m| m.class),
        Some(ModuleClass::Inert)
    );
    assert_eq!(py.module("os").map(|m| m.class), Some(ModuleClass::Egress));
}

/// `os.path.join` is inert and `os.system` is egress.
#[test]
fn os_path_join_is_inert_and_os_system_is_egress() {
    let d = data();
    let py = d.runtime(Language::Python);
    assert_eq!(id_of(py.lookup("os", &["path", "join"])), "module os.path");
    match py.lookup("os", &["system"]) {
        Some(Classification::Entry(e)) => {
            assert_eq!(e.id, "python:os.system");
            assert!(matches!(e.kind, EntryKind::Egress(_)));
        }
        other => panic!("{other:?}"),
    }
}

/// Bare `fetch` is an ambient egress entry.
#[test]
fn bare_fetch_is_an_ambient_egress_entry() {
    let d = data();
    let js = d.runtime(Language::Javascript);
    match js.lookup_global(&["fetch"]) {
        Some(Classification::Entry(e)) => assert!(matches!(e.kind, EntryKind::Egress(_))),
        other => panic!("{other:?}"),
    }
}

#[test]
fn initial_catalog_packages_are_present() {
    let d = data();
    let want: [(Language, &[&str]); 3] = [
        (
            Language::Python,
            &[
                "requests",
                "httpx",
                "aiohttp",
                "urllib3",
                "boto3",
                "botocore",
                "grpc",
                "paramiko",
                "websockets",
                "websocket",
                "pycurl",
                "redis",
                "pymongo",
                "psycopg2",
                "cffi",
            ],
        ),
        (
            Language::Javascript,
            &[
                "axios",
                "node-fetch",
                "got",
                "undici",
                "ky",
                "superagent",
                "ws",
                "socket.io-client",
                "@aws-sdk/*",
                "pg",
                "mysql2",
                "redis",
                "ioredis",
                "mongodb",
                "nodemailer",
            ],
        ),
        (
            Language::Rust,
            &[
                "reqwest",
                "hyper",
                "ureq",
                "isahc",
                "surf",
                "attohttpc",
                "tokio",
                "libc",
                "libloading",
            ],
        ),
    ];
    for (lang, pkgs) in want {
        let rt = d.runtime(lang);
        for p in pkgs {
            assert!(rt.packages.iter().any(|x| x.name == *p), "{lang:?}: {p}");
            assert!(
                rt.entries.iter().any(|e| e.module == *p
                    || rt
                        .packages
                        .iter()
                        .any(|x| x.name == *p && x.modules.contains(&e.module))),
                "{lang:?}: {p} has no entries"
            );
        }
    }
}

#[test]
fn dependency_budgets_file_is_embedded_and_digested() {
    // The dependency budget table is in EMBEDDED so the digest moves
    // when it changes (KTD14, U6).
    assert!(
        EMBEDDED
            .iter()
            .any(|f| f.path == "data/dependency-budgets.toml")
    );
    let files: Vec<(&str, &str)> = EMBEDDED.iter().map(|f| (f.path, f.text)).collect();
    let with = data_digest(&files);
    let without = data_digest(
        &files
            .iter()
            .filter(|(p, _)| *p != "data/dependency-budgets.toml")
            .cloned()
            .collect::<Vec<_>>(),
    );
    assert_ne!(with, without);
}

// ---- python-distributions table (KTD17) --------------------------------------

#[test]
fn every_python_distribution_mapping_names_an_exercising_case() {
    let d = data();
    assert!(
        !d.python_distributions.is_empty(),
        "the curated table must hold entries"
    );
    assert_clean(
        "python-distributions",
        guards::python_distributions(&d.python_distributions, &corpus()),
    );
}

#[test]
fn a_missing_case_or_missing_label_turns_the_distribution_guard_red() {
    let d = data();
    // A fixture that names no case fails the guard.
    let mut missing = d.python_distributions.clone();
    missing[0].fixture = "python/dependencies/does-not-exist".into();
    let v = guards::python_distributions(&missing, &corpus());
    assert!(
        v.iter()
            .any(|s| s.contains(&missing[0].import) && s.contains("does-not-exist")),
        "{v:?}"
    );
    // A fixture whose labels do not cover the entry's distributions
    // fails too: `jwt` maps two candidates but pyyaml-curated-no-root
    // labels `yaml`, not `jwt`.
    let mut relabeled = d.python_distributions.clone();
    let jwt = relabeled
        .iter_mut()
        .find(|m| m.import == "jwt")
        .unwrap_or_else(|| panic!("no jwt mapping"));
    jwt.fixture = "python/dependencies/pyyaml-curated-no-root".into();
    let v = guards::python_distributions(&relabeled, &corpus());
    assert!(
        v.iter()
            .any(|s| s.contains("jwt") && s.contains("pyyaml-curated-no-root")),
        "{v:?}"
    );
}

#[test]
fn every_corpus_distribution_label_names_a_table_entry() {
    let d = data();
    assert_clean(
        "distribution labels",
        guards::labeled_distributions(&d.python_distributions, &corpus()),
    );
}

#[test]
fn deleting_a_mapping_turns_the_labeled_distributions_guard_red() {
    let d = data();
    // `PyYAML` is labeled by pyyaml-curated-no-root; dropping the `yaml`
    // mapping must flag it.
    let mut m = d.python_distributions.clone();
    m.retain(|x| x.import != "yaml");
    let v = guards::labeled_distributions(&m, &corpus());
    assert!(v.iter().any(|s| s.contains("PyYAML")), "{v:?}");
}

#[test]
fn the_distribution_table_is_embedded_and_moves_the_digest() {
    assert!(
        EMBEDDED
            .iter()
            .any(|f| f.path == "data/python-distributions.toml")
    );
    let files: Vec<(&str, &str)> = EMBEDDED.iter().map(|f| (f.path, f.text)).collect();
    let with = data_digest(&files);
    let changed: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| {
            if *p == "data/python-distributions.toml" {
                (*p, "# touched\n")
            } else {
                (*p, *t)
            }
        })
        .collect();
    assert_ne!(with, data_digest(&changed));
}

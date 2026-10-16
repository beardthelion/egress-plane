//! The primitives corpus generator (R1-R3, KTD4).
//!
//! `corpus-gen` owns exactly the cases listed in
//! `fixtures/corpus/generated.toml`, a sorted list it writes itself. A
//! candidate is a data entry the generator produces a case for: a
//! blind-spot entry, an inert group, or a Python introspection inert
//! name whose fixture sits under `<language>/primitives/` for a covered
//! language. A candidate is written only while its fixture is listed in
//! `deferred.toml` or `generated.toml`; a case directory that no ledger
//! owns is never touched, even when its name collides with an entry's
//! fixture, and a stale owned case (its entry gone from the data) is
//! deleted.
//!
//! The Go template emits one `main.go` per fixture; egress fixtures are
//! adopt-only candidates, emitted only while a ledger names them, so
//! hand-authored egress cases always win over the template.
//!
//! Output depends only on data content: sorted iteration, fixed file
//! names, no timestamps, no host paths. Case names are the `fixture`
//! strings already stored on each entry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use egress_core::data::guards::{self, Deferred};
use egress_core::data::{
    Classification, Entry, EntryKind, InertName, ModuleClass, RuntimeData, separator,
};
use egress_core::model::{BlindSpotKind, Language};
use serde::Deserialize;

/// The languages the generator has templates for.
pub const LANGUAGES: [Language; 4] = [
    Language::Python,
    Language::Javascript,
    Language::Rust,
    Language::Go,
];

pub const GENERATED_FILE: &str = "generated.toml";
pub const DEFERRED_FILE: &str = "deferred.toml";

/// The corpus root for a manifest dir (`crates/egress-corpus`).
pub fn corpus_root(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("../../fixtures/corpus")
}

/// One owned case: its fixture id and every file under the case
/// directory, keyed by path relative to that directory (`expected.toml`,
/// `tree/app.py`, `tree/src/lib.rs`, `tree/Cargo.toml`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseSpec {
    pub id: String,
    pub files: BTreeMap<String, String>,
    /// An egress candidate: emitted only while a ledger names its
    /// fixture, and an authored directory on that fixture wins over
    /// the template instead of conflicting (KTD4).
    pub adopt_only: bool,
}

/// `*` in a member pattern becomes a fixed concrete identifier.
const MEMBER_SYNTH: &str = "Example";
/// `*` in a module specifier (`@scope/*`) becomes a fixed package name.
const MODULE_SYNTH: &str = "pkg";
/// The member a Rust crate-root module-level entry names in path
/// position; it must classify to the module entry itself (checked).
const RUST_PATH_MEMBER: &str = "probe_member";
/// Python keyword constants the inert template skips: they lower as
/// values, never as name references (KTD3).
const PYTHON_CONSTANTS: [&str; 3] = ["False", "None", "True"];
/// Rust sysroot crates that need no `[dependencies]` line.
const RUST_SYSROOT: [&str; 5] = ["alloc", "core", "proc_macro", "std", "test"];

fn expected_blind_spot(file: &str, kind: &str) -> String {
    format!(
        "state = \"complete\"\nexit_code = 0\n\n[[blind_spots]]\nfile = \"{file}\"\nsymbol = \"probe\"\nkind = \"{kind}\"\n"
    )
}

const EXPECTED_EMPTY: &str = "state = \"complete\"\nexit_code = 0\n";

fn instantiate_member(segment: &str) -> String {
    segment.replace('*', MEMBER_SYNTH)
}

fn instantiate_module(module: &str) -> String {
    module.replace('*', MODULE_SYNTH)
}

fn is_ambient(rt: &RuntimeData, module: &str) -> bool {
    !rt.ambient.module.is_empty() && module == rt.ambient.module
}

/// The classification of a reference written as `chain` in source: an
/// ambient chain resolves through the runtime's ambient module, an
/// import-rooted one through `lookup`'s own module extension.
fn classify<'a>(
    rt: &'a RuntimeData,
    ambient: bool,
    chain: &[String],
) -> Option<Classification<'a>> {
    let refs: Vec<&str> = chain.iter().map(String::as_str).collect();
    if ambient {
        return rt.lookup_global(&refs);
    }
    let (first, rest) = refs.split_first()?;
    rt.lookup(first, rest)
}

/// The module-and-member chain a case's reference writes, for the
/// classification self-check.
struct Emitted {
    ambient: bool,
    chain: Vec<String>,
    files: BTreeMap<String, String>,
}

// ---- snippet templates (the plan's High-Level Technical Design shapes) -------

fn python_blind_spot(rt: &RuntimeData, e: &Entry) -> Emitted {
    let members: Vec<String> = e.members.iter().map(|m| instantiate_member(m)).collect();
    let suffix = if members.is_empty() {
        String::new()
    } else {
        format!(".{}", members.join("."))
    };
    let (src, chain) = if is_ambient(rt, &e.module) {
        let path = if members.is_empty() {
            e.module.clone()
        } else {
            members.join(".")
        };
        (
            format!("def probe():\n    return {path}\n"),
            if members.is_empty() {
                vec![e.module.clone()]
            } else {
                members.clone()
            },
        )
    } else {
        let first = e.module.split('.').next().unwrap_or(e.module.as_str());
        let path = format!("{}{}", instantiate_module(&e.module), suffix);
        (
            format!("import {first}\n\ndef probe():\n    return {path}\n"),
            e.module
                .split('.')
                .map(instantiate_module)
                .chain(members.iter().cloned())
                .collect::<Vec<String>>(),
        )
    };
    Emitted {
        ambient: is_ambient(rt, &e.module),
        chain,
        files: BTreeMap::from([
            ("tree/app.py".to_string(), src),
            (
                "expected.toml".to_string(),
                expected_blind_spot(
                    "app.py",
                    match &e.kind {
                        EntryKind::BlindSpot { kind, .. } => kind.as_str(),
                        _ => unreachable!(),
                    },
                ),
            ),
        ]),
    }
}

fn javascript_blind_spot(rt: &RuntimeData, e: &Entry) -> Emitted {
    let members: Vec<String> = e.members.iter().map(|m| instantiate_member(m)).collect();
    let suffix = if members.is_empty() {
        String::new()
    } else {
        format!(".{}", members.join("."))
    };
    let (src, chain) = if is_ambient(rt, &e.module) {
        let mut c = vec![e.module.clone()];
        c.extend(members.iter().cloned());
        (
            format!(
                "export function probe() {{\n  return {}{};\n}}\n",
                e.module, suffix
            ),
            c,
        )
    } else {
        let spec = instantiate_module(&e.module);
        let mut c = vec![spec.clone()];
        c.extend(members.iter().cloned());
        (
            format!(
                "import m from \"{spec}\";\n\nexport function probe() {{\n  return m{suffix};\n}}\n"
            ),
            c,
        )
    };
    Emitted {
        ambient: is_ambient(rt, &e.module),
        chain,
        files: BTreeMap::from([
            ("tree/app.mjs".to_string(), src),
            (
                "expected.toml".to_string(),
                expected_blind_spot(
                    "app.mjs",
                    match &e.kind {
                        EntryKind::BlindSpot { kind, .. } => kind.as_str(),
                        _ => unreachable!(),
                    },
                ),
            ),
        ]),
    }
}

fn rust_manifest(crates: &BTreeSet<String>) -> String {
    let mut s = String::from(
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    );
    for c in crates {
        s.push_str(&format!("{c} = \"*\"\n"));
    }
    s
}

/// The dependency line a Rust case needs: the module's crate when it is
/// not a sysroot crate.
fn rust_crate(module: &str) -> Option<String> {
    let first = module.split("::").next()?;
    (!RUST_SYSROOT.contains(&first)).then(|| first.to_string())
}

fn rust_blind_spot(_rt: &RuntimeData, e: &Entry) -> Emitted {
    let members: Vec<String> = e.members.iter().map(|m| instantiate_member(m)).collect();
    // A crate-root module entry cannot name the bare crate in a value
    // path, so it names a fixed member that must classify back to the
    // module entry itself (self-checked below).
    let crate_root = e.module.split("::").count() == 1 && rust_crate(&e.module).is_some();
    let mut src = String::new();
    let path = if members.is_empty() && crate_root {
        src.push_str(&format!(
            "use {};\n\n",
            e.module.split("::").next().unwrap()
        ));
        format!("{}::{RUST_PATH_MEMBER}", e.module)
    } else if members.is_empty() {
        e.module.clone()
    } else {
        format!("{}::{}", e.module, members.join("::"))
    };
    src.push_str(&format!("pub fn probe() {{\n    let _ = {path};\n}}\n"));
    let crates: BTreeSet<String> = rust_crate(&e.module).into_iter().collect();
    Emitted {
        ambient: false,
        chain: path.split("::").map(str::to_string).collect(),
        files: BTreeMap::from([
            ("tree/src/lib.rs".to_string(), src),
            ("tree/Cargo.toml".to_string(), rust_manifest(&crates)),
            (
                "expected.toml".to_string(),
                expected_blind_spot(
                    "src/lib.rs",
                    match &e.kind {
                        EntryKind::BlindSpot { kind, .. } => kind.as_str(),
                        _ => unreachable!(),
                    },
                ),
            ),
        ]),
    }
}

/// Go snippets: one `main.go` whose imports bind the package as `pkg`.
/// One-member entries emit `pkg.Mem()`, which parses the same whether
/// the member is a function or a type (a conversion); two-member
/// entries declare a zero value and call the method; a module-level
/// entry (`unsafe`, `runtime/cgo`, `syscall/js`) cannot name the bare
/// package, so it calls a fixed member the empty-members entry still
/// classifies back to (the rust `probe_member` pattern, KTD4).
const GO_PATH_MEMBER: &str = "ProbeMember";

fn go_blind_spot(_rt: &RuntimeData, e: &Entry) -> Emitted {
    let members: Vec<String> = e.members.iter().map(|m| instantiate_member(m)).collect();
    let module = instantiate_module(&e.module);
    let body = match members.as_slice() {
        [] => format!(
            "    pkg.{GO_PATH_MEMBER}()
"
        ),
        [m] => format!(
            "    pkg.{m}()
"
        ),
        [t, rest @ ..] => {
            format!("    var v pkg.{t}\n    v.{}()\n", rest.join("."))
        }
    };
    let src = format!("package main\n\nimport pkg \"{module}\"\n\nfunc probe() {{\n{body}}}\n");
    let mut chain = vec![module];
    chain.extend(members.iter().cloned());
    Emitted {
        ambient: false,
        chain,
        files: BTreeMap::from([
            ("tree/main.go".to_string(), src),
            (
                "expected.toml".to_string(),
                expected_blind_spot(
                    "main.go",
                    match &e.kind {
                        EntryKind::BlindSpot { kind, .. } => kind.as_str(),
                        _ => unreachable!(),
                    },
                ),
            ),
        ]),
    }
}

/// The member chains of one inert group, instantiated and (for Python)
/// with the keyword constants skipped (KTD3).
fn inert_chains(rt: &RuntimeData, entries: &[&Entry]) -> Vec<Vec<String>> {
    entries
        .iter()
        .map(|e| {
            e.members
                .iter()
                .map(|m| instantiate_member(m))
                .collect::<Vec<String>>()
        })
        .filter(|c| {
            !(rt.language == Language::Python
                && c.len() == 1
                && PYTHON_CONSTANTS.contains(&c[0].as_str()))
        })
        .collect()
}

fn python_inert(rt: &RuntimeData, entries: &[&Entry]) -> Emitted {
    let module = &entries[0].module;
    let ambient = is_ambient(rt, module);
    let chains = inert_chains(rt, entries);
    let body = if chains.is_empty() {
        "    return ()\n".to_string()
    } else {
        let mut b = String::from("    return (\n");
        for c in &chains {
            b.push_str(&format!("        {},\n", c.join(".")));
        }
        b.push_str("    )\n");
        b
    };
    let src = if ambient {
        format!("def probe():\n{body}")
    } else {
        let firsts: BTreeSet<&str> = chains
            .iter()
            .filter_map(|c| c.first().map(String::as_str))
            .collect();
        let import = if firsts.is_empty() {
            let first = module.split('.').next().unwrap_or(module.as_str());
            format!("import {first}")
        } else {
            format!(
                "from {} import {}",
                module,
                firsts.into_iter().collect::<Vec<_>>().join(", ")
            )
        };
        format!("{import}\n\ndef probe():\n{body}")
    };
    Emitted {
        ambient,
        chain: Vec::new(),
        files: BTreeMap::from([
            ("tree/app.py".to_string(), src),
            ("expected.toml".to_string(), EXPECTED_EMPTY.to_string()),
        ]),
    }
}

fn javascript_inert(rt: &RuntimeData, entries: &[&Entry]) -> Emitted {
    let module = &entries[0].module;
    let ambient = is_ambient(rt, module);
    let chains = inert_chains(rt, entries);
    let items = |prefix: &str| {
        if chains.is_empty() {
            "  return [];\n".to_string()
        } else {
            let mut b = String::from("  return [\n");
            for c in &chains {
                b.push_str(&format!("    {}{},\n", prefix, c.join(".")));
            }
            b.push_str("  ];\n");
            b
        }
    };
    let src = if ambient {
        let mut b = String::from("export function probe() {\n");
        b.push_str(&items(&format!("{}.", module)));
        b.push_str("}\n");
        b
    } else {
        let spec = instantiate_module(module);
        let mut b = format!("import m from \"{spec}\";\n\nexport function probe() {{\n");
        b.push_str(&items("m."));
        b.push_str("}\n");
        b
    };
    Emitted {
        ambient,
        chain: Vec::new(),
        files: BTreeMap::from([
            ("tree/app.mjs".to_string(), src),
            ("expected.toml".to_string(), EXPECTED_EMPTY.to_string()),
        ]),
    }
}

fn rust_inert(rt: &RuntimeData, entries: &[&Entry]) -> Emitted {
    let module = &entries[0].module;
    let chains = inert_chains(rt, entries);
    let body = if chains.is_empty() {
        "    let _ = ();\n".to_string()
    } else {
        let mut b = String::from("    let _ = (\n");
        for c in &chains {
            b.push_str(&format!("        {}::{},\n", module, c.join("::")));
        }
        b.push_str("    );\n");
        b
    };
    let src = format!("pub fn probe() {{\n{body}}}\n");
    let crates: BTreeSet<String> = rust_crate(module).into_iter().collect();
    Emitted {
        ambient: false,
        chain: Vec::new(),
        files: BTreeMap::from([
            ("tree/src/lib.rs".to_string(), src),
            ("tree/Cargo.toml".to_string(), rust_manifest(&crates)),
            ("expected.toml".to_string(), EXPECTED_EMPTY.to_string()),
        ]),
    }
}

fn go_inert(rt: &RuntimeData, entries: &[&Entry]) -> Emitted {
    let module = instantiate_module(&entries[0].module);
    let chains = inert_chains(rt, entries);
    let mut b = String::new();
    for c in &chains {
        b.push_str(&format!("    _ = pkg.{}\n", c.join(".")));
    }
    let src = format!("package main\n\nimport pkg \"{module}\"\n\nfunc main() {{\n{b}}}\n");
    Emitted {
        ambient: false,
        chain: Vec::new(),
        files: BTreeMap::from([
            ("tree/main.go".to_string(), src),
            ("expected.toml".to_string(), EXPECTED_EMPTY.to_string()),
        ]),
    }
}

/// The destination literal a generated Go egress call carries for
/// `form`, and the text the scanner renders for it: `program` renders
/// `exec:` and `library` `lib:`, the address and URL forms verbatim.
fn go_form_literal(
    form: egress_core::data::DestinationForm,
) -> Option<(&'static str, &'static str)> {
    Some(match form {
        egress_core::data::DestinationForm::Url => ("https://x.example/", "https://x.example/"),
        egress_core::data::DestinationForm::HostPort
        | egress_core::data::DestinationForm::Address => ("x.example:443", "x.example:443"),
        egress_core::data::DestinationForm::Program => ("x", "exec:x"),
        egress_core::data::DestinationForm::Library => ("x.so", "lib:x.so"),
    })
}

/// The `[[sites]]` block for a generated Go egress expected.toml.
fn expected_sites(lines: &[(&str, &str)]) -> String {
    let mut out = String::from("state = \"complete\"\nexit_code = 0\n");
    for (mechanism, destination) in lines {
        out.push_str(&format!(
            "\n[[sites]]\nfile = \"main.go\"\nsymbol = \"probe\"\nmechanism = \"{mechanism}\"\ndestination = \"{destination}\"\n"
        ));
    }
    out
}

/// One Go egress case: a call carrying the destination literal at the
/// spec's argument index. Two-member entries declare a zero value and
/// call the method, which adds the constructor site when member one is
/// itself a constructor entry. Entries whose spec shape the template
/// cannot express (no positional arg, an empty member list, three or
/// more members) return `None` and stay deferred.
fn go_egress(rt: &RuntimeData, e: &Entry) -> Result<Option<CaseSpec>, String> {
    let EntryKind::Egress(egress) = &e.kind else {
        return Ok(None);
    };
    let members: Vec<String> = e.members.iter().map(|m| instantiate_member(m)).collect();
    let module = instantiate_module(&e.module);

    // The call's argument list: a literal per destination arg, a
    // placeholder "x" elsewhere, none when the entry has no spec.
    let (args, dest) = match &egress.destination {
        Some(spec) => {
            let Some(n) = spec.arg else {
                return Ok(None);
            };
            if spec.port.is_some() || spec.keyword.is_some() || spec.port_keyword.is_some() {
                return Ok(None);
            }
            let Some((lit, rendered)) = go_form_literal(spec.form) else {
                return Ok(None);
            };
            let mut args = vec!["x".to_string(); n as usize];
            args[n as usize - 1] = format!("\"{lit}\"");
            (args, Some(rendered.to_string()))
        }
        None => (Vec::new(), None),
    };
    let args = args.iter().map(|a| match a.as_str() {
        "x" => "\"x\"".to_string(),
        a => a.to_string(),
    });
    let call_args: Vec<String> = args.collect();

    let (body, sites) = match members.as_slice() {
        [m] => {
            let dest = dest.unwrap_or_else(|| format!("expr:pkg.{m}({})", call_args.join(", ")));
            (
                format!("    pkg.{m}({})\n", call_args.join(", ")),
                vec![(e.id.clone(), dest)],
            )
        }
        [t, m] => {
            let mut sites = Vec::new();
            // A constructor member emits its own site for the zero value.
            if let Some(Classification::Entry(t_e)) =
                classify(rt, false, &[module.clone(), t.clone()])
                && let EntryKind::Egress(t_eg) = &t_e.kind
                && t_eg.constructor
            {
                sites.push((t_e.id.clone(), format!("expr:pkg.{t}")));
            }
            let dest = dest.unwrap_or_else(|| format!("expr:v.{m}({})", call_args.join(", ")));
            sites.push((e.id.clone(), dest));
            (
                format!("    var v pkg.{t}\n    v.{m}({})\n", call_args.join(", ")),
                sites,
            )
        }
        _ => return Ok(None),
    };
    // `mechanism` labels carry the entry id.
    let site_lines: Vec<(&str, &str)> = sites
        .iter()
        .map(|(id, d)| (id.as_str(), d.as_str()))
        .collect();
    let src = format!("package main\n\nimport pkg \"{module}\"\n\nfunc probe() {{\n{body}}}\n");
    let chain: Vec<String> = std::iter::once(module.clone())
        .chain(members.iter().cloned())
        .collect();
    match classify(rt, false, &chain) {
        Some(Classification::Entry(got)) if got.id == e.id => {}
        other => {
            return Err(format!(
                "{}: generated reference {} classifies as {}, not the entry",
                e.id,
                chain.join(separator(rt.language)),
                match other {
                    Some(Classification::Entry(x)) => format!("entry {}", x.id),
                    Some(Classification::Module(m)) => format!("module {}", m.name),
                    Some(Classification::Package(p)) => format!("package {}", p.name),
                    None => "nothing".to_string(),
                }
            ));
        }
    }
    Ok(Some(CaseSpec {
        id: e.fixture.clone(),
        adopt_only: true,
        files: BTreeMap::from([
            ("tree/main.go".to_string(), src),
            ("expected.toml".to_string(), expected_sites(&site_lines)),
        ]),
    }))
}

fn python_introspection(name: &InertName) -> CaseSpec {
    CaseSpec {
        id: name.fixture.clone(),
        adopt_only: false,
        files: BTreeMap::from([
            (
                "tree/app.py".to_string(),
                format!("def probe():\n    return probe.{}\n", name.name),
            ),
            ("expected.toml".to_string(), EXPECTED_EMPTY.to_string()),
        ]),
    }
}

/// Every reference an inert case emits, as (ambient, chain) pairs for
/// the classification self-check: each must classify inert.
fn inert_refs(rt: &RuntimeData, module: &str, chains: &[Vec<String>]) -> Vec<(bool, Vec<String>)> {
    let ambient = is_ambient(rt, module);
    chains
        .iter()
        .map(|c| {
            if ambient && rt.language == Language::Python {
                (true, c.clone())
            } else if ambient {
                let mut v = vec![module.to_string()];
                v.extend(c.iter().cloned());
                (true, v)
            } else {
                let sep = separator(rt.language);
                let mut v: Vec<String> = module.split(sep).map(instantiate_module).collect();
                v.extend(c.iter().cloned());
                (false, v)
            }
        })
        .collect()
}

fn blind_spot_case(rt: &RuntimeData, e: &Entry) -> Result<CaseSpec, String> {
    let em = match rt.language {
        Language::Python => python_blind_spot(rt, e),
        Language::Javascript => javascript_blind_spot(rt, e),
        Language::Rust => rust_blind_spot(rt, e),
        Language::Go => go_blind_spot(rt, e),
    };
    // Self-check: the emitted reference must classify so the case
    // produces the entry's kind: this entry itself, another blind-spot
    // entry of the same kind (a longer-prefix sibling), or, for a
    // module-escape entry, the whole egress module as a value (an
    // ambient member that is itself an alias, like `globalThis.global`,
    // resolves to the ambient module and still yields module-escape).
    let want = match &e.kind {
        EntryKind::BlindSpot { kind, .. } => *kind,
        _ => unreachable!(),
    };
    let ok = match classify(rt, em.ambient, &em.chain) {
        Some(Classification::Entry(got)) => {
            got.id == e.id
                || matches!(&got.kind, EntryKind::BlindSpot { kind: k, .. } if *k == want)
        }
        Some(Classification::Module(m)) => {
            want == BlindSpotKind::ModuleEscape && m.class == ModuleClass::Egress
        }
        _ => false,
    };
    if !ok {
        let other = classify(rt, em.ambient, &em.chain);
        return Err(format!(
            "{}: generated reference {} classifies as {}, not the entry",
            e.id,
            em.chain.join(separator(rt.language)),
            match other {
                Some(Classification::Entry(x)) => format!("entry {}", x.id),
                Some(Classification::Module(m)) => format!("module {}", m.name),
                Some(Classification::Package(p)) => format!("package {}", p.name),
                None => "nothing".to_string(),
            }
        ));
    }
    Ok(CaseSpec {
        id: e.fixture.clone(),
        adopt_only: false,
        files: em.files,
    })
}

fn inert_case(rt: &RuntimeData, entries: &[&Entry]) -> Result<CaseSpec, String> {
    let fixture = entries[0].fixture.clone();
    let module = entries[0].module.clone();
    let chains = inert_chains(rt, entries);
    for (ambient, chain) in inert_refs(rt, &module, &chains) {
        let ok = match classify(rt, ambient, &chain) {
            Some(Classification::Entry(e)) => matches!(e.kind, EntryKind::Inert { .. }),
            Some(Classification::Module(m)) => m.class == ModuleClass::Inert,
            _ => false,
        };
        if !ok {
            return Err(format!(
                "{}: generated reference {} does not classify inert",
                module,
                chain.join(separator(rt.language))
            ));
        }
    }
    let em = match rt.language {
        Language::Python => python_inert(rt, entries),
        Language::Javascript => javascript_inert(rt, entries),
        Language::Rust => rust_inert(rt, entries),
        Language::Go => go_inert(rt, entries),
    };
    Ok(CaseSpec {
        id: fixture,
        adopt_only: false,
        files: em.files,
    })
}

/// A corpus case id must be `<language>/primitives/<name>` with no `.`
/// or `..` segment and a name of word and dash characters (KTD4, AE1).
fn valid_case_id(id: &str) -> bool {
    let segs: Vec<&str> = id.split('/').collect();
    if segs.len() != 3 {
        return false;
    }
    if Language::ALL.iter().all(|l| l.as_str() != segs[0]) && segs[0] != "mixed" {
        return false;
    }
    if segs[1] != "primitives" {
        return false;
    }
    let name = segs[2];
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

const BLIND: u8 = 1;
const INERT: u8 = 2;
const INTROSPECTION: u8 = 4;
const EGRESS_BIT: u8 = 8;

/// Whether a data fixture is a valid corpus case id (KTD4, AE1).
fn check_id(errors: &mut Vec<String>, fixture: &str) -> bool {
    if !valid_case_id(fixture) {
        errors.push(format!(
            "{fixture}: a fixture id must match <language>/primitives/<name>"
        ));
        return false;
    }
    true
}

/// Every case the data asks the generator to own, keyed by fixture.
pub fn candidates(rts: &[&RuntimeData]) -> Result<BTreeMap<String, CaseSpec>, Vec<String>> {
    let mut errors = Vec::new();
    let mut out: BTreeMap<String, CaseSpec> = BTreeMap::new();
    // fixture -> kind flags, for the shared-across-kinds error.
    let mut claims: BTreeMap<String, u8> = BTreeMap::new();
    for rt in rts {
        if !LANGUAGES.contains(&rt.language) {
            continue;
        }
        let prefix = format!("{}/primitives/", rt.language.as_str());
        let mut blind: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
        for e in &rt.entries {
            if matches!(e.kind, EntryKind::BlindSpot { .. }) && e.fixture.starts_with(&prefix) {
                blind.entry(e.fixture.as_str()).or_default().push(e);
            }
        }
        let mut egress: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
        for e in &rt.entries {
            if rt.language == Language::Go
                && matches!(e.kind, EntryKind::Egress(_))
                && e.fixture.starts_with(&prefix)
            {
                egress.entry(e.fixture.as_str()).or_default().push(e);
            }
        }
        for (fixture, es) in egress {
            // A fixture several entries name is a hand-authored
            // multi-entry case; the one-entry template yields to it
            // (adopt-only, so no error like the blind-spot path).
            if es.len() > 1 {
                continue;
            }
            match go_egress(rt, es[0]) {
                Ok(Some(spec)) => {
                    *claims.entry(fixture.to_string()).or_default() |= EGRESS_BIT;
                    if check_id(&mut errors, fixture) {
                        out.insert(fixture.to_string(), spec);
                    }
                }
                Ok(None) => {}
                Err(e) => errors.push(e),
            }
        }
        for (fixture, es) in blind {
            *claims.entry(fixture.to_string()).or_default() |= BLIND;
            if es.len() > 1 {
                errors.push(format!(
                    "{fixture}: {} blind-spot entries name one fixture",
                    es.len()
                ));
                continue;
            }
            if !check_id(&mut errors, fixture) {
                continue;
            }
            match blind_spot_case(rt, es[0]) {
                Ok(spec) => {
                    out.insert(fixture.to_string(), spec);
                }
                Err(e) => errors.push(e),
            }
        }
        for (fixture, es) in guards::inert_groups(rt) {
            if !fixture.starts_with(&prefix) {
                continue;
            }
            *claims.entry(fixture.to_string()).or_default() |= INERT;
            let modules: BTreeSet<&str> = es.iter().map(|e| e.module.as_str()).collect();
            if modules.len() > 1 {
                errors.push(format!(
                    "{fixture}: inert groups for modules {} share one fixture",
                    modules.iter().copied().collect::<Vec<_>>().join(", ")
                ));
                continue;
            }
            if !fixture
                .rsplit('/')
                .next()
                .is_some_and(|n| n.starts_with("must-not-"))
            {
                errors.push(format!(
                    "{fixture}: an inert fixture must be a must-not- case"
                ));
                continue;
            }
            if !check_id(&mut errors, fixture) {
                continue;
            }
            match inert_case(rt, &es) {
                Ok(spec) => {
                    out.insert(fixture.to_string(), spec);
                }
                Err(e) => errors.push(e),
            }
        }
        let mut intro: BTreeMap<&str, Vec<&InertName>> = BTreeMap::new();
        for n in &rt.closure.introspection_inert {
            if n.fixture.starts_with(&prefix) {
                intro.entry(n.fixture.as_str()).or_default().push(n);
            }
        }
        for (fixture, ns) in intro {
            *claims.entry(fixture.to_string()).or_default() |= INTROSPECTION;
            if ns.len() > 1 {
                errors.push(format!(
                    "{fixture}: {} introspection inert names share one fixture",
                    ns.len()
                ));
                continue;
            }
            if !fixture
                .rsplit('/')
                .next()
                .is_some_and(|n| n.starts_with("must-not-"))
            {
                errors.push(format!(
                    "{fixture}: an inert fixture must be a must-not- case"
                ));
                continue;
            }
            if !check_id(&mut errors, fixture) {
                continue;
            }
            out.insert(fixture.to_string(), python_introspection(ns[0]));
        }
    }
    for (fixture, flags) in &claims {
        if flags.count_ones() > 1 {
            errors.push(format!(
                "{fixture}: entries of different kinds share one fixture"
            ));
            out.remove(fixture);
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

// ---- ledgers -----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGenerated {
    #[serde(default)]
    cases: Vec<String>,
}

/// Parses `generated.toml`: a sorted `cases` list the generator owns.
/// A duplicate or unknown key fails.
pub fn parse_generated(text: &str) -> Result<BTreeSet<String>, String> {
    if text.trim().is_empty() {
        return Ok(BTreeSet::new());
    }
    let raw: RawGenerated =
        toml::from_str(text).map_err(|e| format!("generated.toml: malformed: {e}"))?;
    let mut cases = BTreeSet::new();
    for c in raw.cases {
        if !cases.insert(c.clone()) {
            return Err(format!("generated.toml: duplicate entry {c}"));
        }
    }
    Ok(cases)
}

/// The canonical `generated.toml` content for an owned set.
pub fn render_generated(cases: &BTreeSet<String>) -> String {
    let mut s = String::from(
        "# Cases the primitives generator owns; corpus-gen --write maintains\n# this list. Do not edit by hand.\ncases = [",
    );
    if cases.is_empty() {
        s.push_str("]\n");
        return s;
    }
    s.push('\n');
    for c in cases {
        s.push_str(&format!("    \"{c}\",\n"));
    }
    s.push_str("]\n");
    s
}

fn render_case_list(cases: &BTreeSet<String>) -> String {
    if cases.is_empty() {
        return "cases = []\n".to_string();
    }
    let mut s = String::from("cases = [\n");
    for c in cases {
        s.push_str(&format!("    \"{c}\",\n"));
    }
    s.push_str("]\n");
    s
}

/// Replaces the `cases` array in `deferred.toml` with `remaining`,
/// preserving every other byte (the header comment, `[[categories]]`).
fn splice_deferred(text: &str, remaining: &BTreeSet<String>) -> Result<String, String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut start = None;
    let mut end = None;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        if start.is_none() {
            if t.strip_prefix("cases")
                .is_some_and(|r| r.trim_start().starts_with('='))
            {
                start = Some(i);
                if t.contains(']') {
                    end = Some(i);
                    break;
                }
            }
        } else if t.starts_with(']') {
            end = Some(i);
            break;
        }
    }
    let (Some(start), Some(end)) = (start, end) else {
        return Err("deferred.toml: no cases array found".to_string());
    };
    let mut out = String::new();
    for l in &lines[..start] {
        out.push_str(l);
    }
    out.push_str(&render_case_list(remaining));
    for l in &lines[end + 1..] {
        out.push_str(l);
    }
    Ok(out)
}

// ---- plan, apply, check --------------------------------------------------------

/// What `--write` or `--check` computes: nothing happens until
/// [`apply`] runs, so a rejected plan leaves the disk untouched.
#[derive(Debug, Default)]
pub struct Plan {
    /// Case id -> file map, rewritten wholesale by `apply`.
    pub rewrite: BTreeMap<String, BTreeMap<String, String>>,
    /// Rewritten cases whose directory was absent.
    pub missing: BTreeSet<String>,
    /// Corpus-relative paths inside owned cases that differ or are extra.
    pub changed: BTreeSet<String>,
    /// Stale-owned case ids deleted outright.
    pub delete_dirs: BTreeSet<String>,
    /// New `generated.toml` content when it differs.
    pub generated_toml: Option<String>,
    /// New `deferred.toml` content when it differs.
    pub deferred_toml: Option<String>,
}

impl Plan {
    pub fn clean(&self) -> bool {
        self.rewrite.is_empty()
            && self.delete_dirs.is_empty()
            && self.generated_toml.is_none()
            && self.deferred_toml.is_none()
    }

    /// The `--check` report lines; empty when the disk matches the data.
    pub fn report(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for id in &self.missing {
            lines.push(format!("{id}: missing generated case"));
        }
        for p in &self.changed {
            lines.push(format!("{p}: differs from generated output"));
        }
        for id in &self.delete_dirs {
            lines.push(format!("{id}: stale generated case; no entry names it"));
        }
        if self.generated_toml.is_some() {
            lines.push("generated.toml: out of date".to_string());
        }
        if self.deferred_toml.is_some() {
            lines.push("deferred.toml: out of date".to_string());
        }
        lines
    }
}

fn read_optional(path: &Path) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("{}: cannot read: {e}", path.display())),
    }
}

fn walk_files(dir: &Path, rel: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            walk_files(&p, &rel.join(e.file_name()), out);
        } else {
            out.push(rel.join(e.file_name()).to_string_lossy().into_owned());
        }
    }
}

/// Computes the write plan for `corpus_root` from data and the ledgers.
/// Any error (a malformed id, a conflict, a fixture claimed twice)
/// aborts the whole plan so nothing is written or deleted.
pub fn plan(rts: &[&RuntimeData], corpus_root: &Path) -> Result<Plan, Vec<String>> {
    let mut errors = Vec::new();
    let generated_text = read_optional(&corpus_root.join(GENERATED_FILE));
    let deferred_text = read_optional(&corpus_root.join(DEFERRED_FILE));
    for t in [&generated_text, &deferred_text] {
        if let Err(e) = t {
            errors.push(e.clone());
        }
    }
    let generated = generated_text
        .as_deref()
        .ok()
        .map(parse_generated)
        .unwrap_or_else(|| Ok(BTreeSet::new()));
    let deferred = deferred_text
        .as_deref()
        .ok()
        .map(|t| {
            if t.trim().is_empty() {
                Ok(Deferred::default())
            } else {
                guards::parse_deferred(t)
            }
        })
        .unwrap_or_else(|| Ok(Deferred::default()));
    let generated = match generated {
        Ok(g) => g,
        Err(e) => {
            errors.push(e);
            BTreeSet::new()
        }
    };
    let deferred = match deferred {
        Ok(d) => d,
        Err(e) => {
            errors.push(e);
            Deferred::default()
        }
    };
    // Every id read from a ledger must be a primitives case id before
    // anything is written or deleted (AE1).
    for id in generated.iter().chain(deferred.cases.iter()) {
        if !valid_case_id(id) {
            errors.push(format!(
                "{id}: a case id must match <language>/primitives/<name>"
            ));
        }
    }
    let cases = match candidates(rts) {
        Ok(c) => c,
        Err(e) => {
            errors.extend(e);
            BTreeMap::new()
        }
    };
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut plan = Plan::default();
    let mut owned: BTreeSet<String> = generated.clone();
    // A stale owned case: its entry left the data.
    for id in &generated {
        if !cases.contains_key(id.as_str()) {
            plan.delete_dirs.insert(id.clone());
            owned.remove(id);
        }
    }
    for (id, spec) in &cases {
        let wanted = generated.contains(id) || deferred.cases.contains(id);
        let dir = corpus_root.join(id);
        if !wanted {
            // The generator does not write it, but a directory sitting on
            // an entry's fixture without an ownership entry is a conflict:
            // it is never touched and the run reports it. An adopt-only
            // (egress) candidate instead yields to the authored case.
            if dir.exists() && !spec.adopt_only {
                errors.push(format!(
                    "{id}: a case directory exists but is not in generated.toml; not touching it"
                ));
            }
            continue;
        }
        if dir.exists() && !dir.is_dir() {
            errors.push(format!("{id}: expected a case directory, found a file"));
            continue;
        }
        if dir.is_dir() && !generated.contains(id) {
            errors.push(format!(
                "{id}: a case directory exists but is not in generated.toml; not touching it"
            ));
            continue;
        }
        if !dir.is_dir() {
            plan.missing.insert(id.clone());
        } else {
            // Owned: diff the canonical files against the disk and find
            // extras inside the case dir.
            let mut stale = false;
            for (rel, text) in &spec.files {
                let corpus_rel = format!("{id}/{rel}");
                match std::fs::read_to_string(dir.join(rel)) {
                    Ok(t) if t == *text => {}
                    _ => {
                        stale = true;
                        plan.changed.insert(corpus_rel);
                    }
                }
            }
            let mut on_disk = Vec::new();
            walk_files(&dir, Path::new(""), &mut on_disk);
            for f in on_disk {
                if !spec.files.contains_key(&f) {
                    stale = true;
                    plan.changed.insert(format!("{id}/{f}"));
                }
            }
            if !stale {
                owned.insert(id.clone());
                continue;
            }
        }
        plan.rewrite.insert(id.clone(), spec.files.clone());
        owned.insert(id.clone());
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let new_generated = render_generated(&owned);
    if new_generated != generated_text.as_deref().unwrap_or_default() {
        plan.generated_toml = Some(new_generated);
    }
    let removed: BTreeSet<String> = deferred
        .cases
        .iter()
        .filter(|c| cases.contains_key(c.as_str()))
        .cloned()
        .collect();
    if !removed.is_empty() {
        let remaining: BTreeSet<String> = deferred
            .cases
            .iter()
            .filter(|c| !removed.contains(c.as_str()))
            .cloned()
            .collect();
        match splice_deferred(deferred_text.as_deref().unwrap_or_default(), &remaining) {
            Ok(t) if t != deferred_text.as_deref().unwrap_or_default() => {
                plan.deferred_toml = Some(t);
            }
            Ok(_) => {}
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(plan)
}

/// Applies a plan: rewrites owned cases, deletes stale ones, updates
/// the ledgers.
pub fn apply(corpus_root: &Path, plan: &Plan) -> Result<(), String> {
    for id in &plan.delete_dirs {
        let dir = corpus_root.join(id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| format!("{}: cannot remove: {e}", dir.display()))?;
        }
    }
    for (id, files) in &plan.rewrite {
        let dir = corpus_root.join(id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| format!("{}: cannot remove: {e}", dir.display()))?;
        }
        for (rel, text) in files {
            let p = dir.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: cannot create: {e}", parent.display()))?;
            }
            std::fs::write(&p, text).map_err(|e| format!("{}: cannot write: {e}", p.display()))?;
        }
    }
    if let Some(text) = &plan.generated_toml {
        std::fs::write(corpus_root.join(GENERATED_FILE), text)
            .map_err(|e| format!("{GENERATED_FILE}: cannot write: {e}"))?;
    }
    if let Some(text) = &plan.deferred_toml {
        std::fs::write(corpus_root.join(DEFERRED_FILE), text)
            .map_err(|e| format!("{DEFERRED_FILE}: cannot write: {e}"))?;
    }
    Ok(())
}

/// The `--check` report lines; empty when the disk matches the data.
pub fn check(rts: &[&RuntimeData], corpus_root: &Path) -> Vec<String> {
    match plan(rts, corpus_root) {
        Ok(plan) => plan.report(),
        Err(errors) => errors,
    }
}

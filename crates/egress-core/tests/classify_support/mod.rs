//! Hand-built IR and small hand-built data tables for the classifier,
//! resolver, and closure tests. The tables load through the same
//! `load_runtime` loader as the embedded data.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, Ordering};

use egress_core::classify::{Classified, classify};
use egress_core::data::{Data, load_runtime};
use egress_core::discover::FileKind;
use egress_core::identity::encode_path_bytes;
use egress_core::ir::*;
use egress_core::model::{Language, Location};
use egress_core::resolve::{GenericRules, Program, ProgramFile, SpecifierKind, SpecifierRules};

pub const PY_PRIM: &str = r#"
language = "python"
runtime_range = "3.8-3.13"

[ambient]
module = "builtins"
aliases = ["__builtins__"]

[closure]
require_equivalents = ["__import__", "builtins.__import__", "importlib.import_module"]
introspection_prefixes = ["tb_", "f_", "gi_", "cr_", "ag_"]

[[closure.introspection_inert]]
name = "__name__"
justification = "a string"
fixture = "f"

[[closure.introspection_inert]]
name = "__init__"
justification = "initializer"
fixture = "f"

[[module]]
name = "builtins"
class = "egress"

[[module]]
name = "os"
class = "egress"

[[module]]
name = "os.path"
class = "inert"
justification = "path strings"

[[module]]
name = "json"
class = "inert"
justification = "text"

[[module]]
name = "functools"
class = "inert"
justification = "higher-order helpers"

[[module]]
name = "base64"
class = "inert"
justification = "encoding"

[[module]]
name = "socket"
class = "egress"

[[module]]
name = "subprocess"
class = "egress"

[[module]]
name = "ctypes"
class = "egress"

[[module]]
name = "sys"
class = "egress"

[[module]]
name = "asyncio"
class = "egress"

[[module]]
name = "importlib"
class = "egress"

[[entry]]
id = "python:os.system"
kind = "egress"
mechanism = "process"
destination = { arg = 1, keyword = "command", form = "program" }
fixture = "f"

[[entry]]
id = "python:os.getenv"
kind = "inert"
justification = "reads the environment"
fixture = "f"

[[entry]]
id = "python:os.environ"
kind = "inert"
justification = "the environment mapping"
fixture = "f"

[[entry]]
id = "python:socket.socket"
kind = "egress"
mechanism = "network"
constructor = true
fixture = "f"

[[entry]]
id = "python:socket.socket.connect"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "address", form = "host-port" }
fixture = "f"

[[entry]]
id = "python:socket.create_connection"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "address", form = "host-port" }
fixture = "f"

[[entry]]
id = "python:subprocess.run"
kind = "egress"
mechanism = "process"
destination = { arg = 1, keyword = "args", form = "program" }
fixture = "f"

[[entry]]
id = "python:ctypes.CDLL"
kind = "egress"
mechanism = "native"
destination = { arg = 1, keyword = "name", form = "library" }
constructor = true
fixture = "f"

[[entry]]
id = "python:ctypes.memmove"
kind = "blind-spot"
blind_spot = "native-code"
reason = "raw memory"
fixture = "f"

[[entry]]
id = "python:sys.path"
kind = "blind-spot"
blind_spot = "import-system-mutation"
reason = "module search path"
fixture = "f"

[[entry]]
id = "python:sys.argv"
kind = "inert"
justification = "a list of strings"
fixture = "f"

[[entry]]
id = "python:builtins.getattr"
kind = "blind-spot"
blind_spot = "reflective-access"
reason = "attribute named by a string"
fixture = "f"

[[entry]]
id = "python:builtins.setattr"
kind = "blind-spot"
blind_spot = "monkeypatch"
reason = "attribute write named by a string"
fixture = "f"

[[entry]]
id = "python:builtins.eval"
kind = "blind-spot"
blind_spot = "dynamic-code"
reason = "evaluates a string"
fixture = "f"

[[entry]]
id = "python:builtins.__import__"
kind = "blind-spot"
blind_spot = "dynamic-import"
reason = "imports a module named by a string"
fixture = "f"

[[entry]]
id = "python:importlib.import_module"
kind = "blind-spot"
blind_spot = "dynamic-import"
reason = "imports a module named by a string"
fixture = "f"

[[entry]]
id = "python:asyncio.get_running_loop"
kind = "egress"
mechanism = "network"
constructor = true
fixture = "f"

[[entry]]
id = "python:asyncio.get_running_loop.create_connection"
kind = "egress"
mechanism = "network"
destination = { arg = 1, port = 2, form = "host-port" }
fixture = "f"

[[inert]]
module = "builtins"
members = ["print", "len"]
justification = "output and sizes"
fixture = "f"
"#;

pub const PY_CAT: &str = r#"
language = "python"

[[package]]
name = "requests"

[[entry]]
id = "python:requests.post"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "url", form = "url" }
fixture = "f"

[[entry]]
id = "python:requests.get"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "url", form = "url" }
fixture = "f"

[[entry]]
id = "python:requests.Session"
kind = "egress"
mechanism = "network"
constructor = true
fixture = "f"

[[entry]]
id = "python:requests.Session.get"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "url", form = "url" }
fixture = "f"

[[inert]]
module = "requests"
members = ["codes"]
justification = "status code table"
fixture = "f"
"#;

pub const JS_PRIM: &str = r#"
language = "javascript"
runtime_range = "18-22"

[ambient]
module = "globalThis"
aliases = ["window", "self", "document.defaultView"]
[ambient.module_members]
"process" = "process"

[closure]
require_equivalents = ["require", "createRequire", "module.require"]

[[module]]
name = "net"
class = "egress"

[[module]]
name = "path"
class = "inert"
justification = "path strings"

[[module]]
name = "process"
class = "egress"

[[module]]
name = "worker_threads"
class = "egress"

[[module]]
name = "module"
class = "egress"

[[entry]]
id = "javascript:globalThis.fetch"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "input", form = "url" }
fixture = "f"

[[entry]]
id = "javascript:globalThis.eval"
kind = "blind-spot"
blind_spot = "dynamic-code"
reason = "evaluates source text"
fixture = "f"

[[entry]]
id = "javascript:globalThis.Reflect.get"
kind = "blind-spot"
blind_spot = "reflective-access"
reason = "property named by a value"
fixture = "f"

[[entry]]
id = "javascript:globalThis.console"
kind = "inert"
justification = "logging"
fixture = "f"

[[entry]]
id = "javascript:net.connect"
kind = "egress"
mechanism = "network"
destination = { arg = 2, keyword = "host", port = 1, port_keyword = "port", form = "host-port" }
fixture = "f"

[[entry]]
id = "javascript:net.Socket"
kind = "egress"
mechanism = "network"
constructor = true
fixture = "f"

[[entry]]
id = "javascript:worker_threads.Worker"
kind = "blind-spot"
blind_spot = "dynamic-import"
reason = "runs code named by a specifier"
fixture = "f"

[[entry]]
id = "javascript:process.binding"
kind = "blind-spot"
blind_spot = "native-code"
reason = "internal bindings"
fixture = "f"

[[inert]]
module = "process"
members = ["env", "cwd"]
justification = "process state"
fixture = "f"
"#;

pub const JS_CAT: &str = r#"
language = "javascript"

[[package]]
name = "axios"

[[entry]]
id = "javascript:axios.get"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "url" }
fixture = "f"

[[entry]]
id = "javascript:axios.create"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "baseURL", form = "url" }
constructor = true
fixture = "f"

[[entry]]
id = "javascript:axios.create.get"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "url" }
fixture = "f"
"#;

pub const RS_PRIM: &str = r#"
language = "rust"
runtime_range = "1.97.1"

[[module]]
name = "std"
class = "egress"

[[module]]
name = "std::net"
class = "egress"

[[module]]
name = "std::env"
class = "egress"

[[entry]]
id = "rust:std::net::TcpStream::connect"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "host-port" }
fixture = "f"

[[inert]]
module = "std::env"
members = ["var", "var_os"]
justification = "reads the environment"
fixture = "f"
"#;

pub const RS_CAT: &str = r#"
language = "rust"

[[package]]
name = "tokio"

[[entry]]
id = "rust:tokio::net"
kind = "egress"
mechanism = "network"
fixture = "f"

[[package]]
name = "reqwest"

[[entry]]
id = "rust:reqwest::Client::new"
kind = "egress"
mechanism = "network"
constructor = true
fixture = "f"

[[entry]]
id = "rust:reqwest::Client::get"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "url" }
fixture = "f"

[[inert]]
module = "tokio"
members = ["sync"]
justification = "synchronization primitives"
fixture = "f"
"#;

/// The embedded data with each runtime replaced by the small tables above.
pub fn data() -> &'static Data {
    static DATA: std::sync::OnceLock<Data> = std::sync::OnceLock::new();
    DATA.get_or_init(build_data)
}

fn build_data() -> Data {
    let mut d = Data::embedded().expect("embedded data");
    for (lang, prim, cat) in [
        (Language::Python, PY_PRIM, PY_CAT),
        (Language::Javascript, JS_PRIM, JS_CAT),
        (Language::Rust, RS_PRIM, RS_CAT),
    ] {
        let name = lang.as_str();
        let inv = format!("language = \"{name}\"\n");
        *d.runtime_mut(lang) = load_runtime(lang, ("prim", prim), ("cat", cat), ("inv", &inv))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    d
}

static NEXT: AtomicU32 = AtomicU32::new(1);

fn span() -> (Span, Location) {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    (
        Span {
            start: n * 10,
            end: n * 10 + 5,
        },
        Location { line: n, column: 1 },
    )
}

pub fn import(local: Option<&str>, specifier: &str, members: &[&str]) -> Import {
    let (span, location) = span();
    Import {
        local: local.map(str::to_string),
        specifier: specifier.into(),
        members: members.iter().map(|s| s.to_string()).collect(),
        type_only: false,
        star: false,
        re_export: false,
        default: false,
        symbol: "<module>".into(),
        span,
        location,
    }
}

/// `import <name>` of a whole module.
pub fn import_module(name: &str) -> Import {
    import(Some(name), name, &[])
}

/// A JS default import or CommonJS `require` binding of a whole module.
pub fn default_import(specifier: &str, local: &str) -> Import {
    Import {
        default: true,
        ..import(Some(local), specifier, &[])
    }
}

pub fn star(specifier: &str) -> Import {
    Import {
        star: true,
        ..import(None, specifier, &[])
    }
}

pub fn re_export(i: Import) -> Import {
    Import {
        re_export: true,
        ..i
    }
}

/// A reference builder.
#[derive(Clone)]
pub struct R(pub Reference);

pub fn r(root: Root, members: &[&str], use_kind: UseKind, text: &str) -> R {
    let (span, location) = span();
    R(Reference {
        root,
        members: members.iter().map(|s| s.to_string()).collect(),
        calls_in_chain: Vec::new(),
        use_kind,
        args: Vec::new(),
        kwargs: Vec::new(),
        receiver: None,
        text: text.into(),
        symbol: "<module>".into(),
        span,
        location,
    })
}

pub fn imp(name: &str) -> Root {
    Root::Import(name.into())
}

pub fn local(name: &str) -> Root {
    Root::Local(name.into())
}

pub fn amb(name: &str) -> Root {
    Root::Ambient(name.into())
}

impl R {
    pub fn sym(mut self, s: &str) -> R {
        self.0.symbol = s.into();
        self
    }
    pub fn arg(mut self, e: Expr) -> R {
        self.0.args.push(e);
        self
    }
    pub fn kwarg(mut self, k: &str, e: Expr) -> R {
        self.0.kwargs.push((k.into(), e));
        self
    }
    pub fn receiver(mut self, p: Provenance) -> R {
        self.0.receiver = Some(p);
        self
    }
    pub fn called_at(mut self, i: u32) -> R {
        self.0.calls_in_chain.push(i);
        self
    }
    pub fn expr(&self) -> Expr {
        Expr::Reference(Box::new(self.0.clone()))
    }
    pub fn get(&self) -> Reference {
        self.0.clone()
    }
}

pub fn lit(s: &str) -> Expr {
    Expr::Literal(s.into())
}

pub fn name(s: &str) -> Expr {
    Expr::Name(s.into())
}

pub fn opaque(s: &str) -> Expr {
    Expr::Opaque(s.into())
}

pub fn seq(items: Vec<Expr>) -> Expr {
    Expr::Sequence(items)
}

pub fn obj(items: Vec<(&str, Expr)>) -> Expr {
    Expr::Object(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

pub fn tmpl(parts: Vec<Expr>) -> Expr {
    Expr::Template(parts)
}

pub fn subscript(base: Expr, key: Expr) -> Expr {
    Expr::Subscript {
        base: Box::new(base),
        key: Box::new(key),
    }
}

pub fn func(path: &str, params: &[&str]) -> SymbolSpan {
    let (span, _) = span();
    SymbolSpan {
        path: path.into(),
        kind: SymbolKind::Function,
        params: params.iter().map(|s| s.to_string()).collect(),
        defaults: Default::default(),
        strict: None,
        span,
    }
}

pub fn class(path: &str) -> SymbolSpan {
    SymbolSpan {
        kind: SymbolKind::Class,
        ..func(path, &[])
    }
}

pub fn local_binding(symbol: &str, name: &str, value: Expr) -> LocalBinding {
    let (span, _) = span();
    LocalBinding {
        symbol: symbol.into(),
        name: name.into(),
        value,
        span,
    }
}

pub fn constant(name: &str, value: Expr) -> ModuleConstant {
    let (span, _) = span();
    ModuleConstant {
        name: name.into(),
        value,
        exported: true,
        span,
    }
}

pub fn self_attr(class: &str, attribute: &str, value: Expr) -> SelfAttribute {
    let (span, _) = span();
    SelfAttribute {
        class: class.into(),
        attribute: attribute.into(),
        value,
        span,
    }
}

pub fn introspection(attribute: &str, text: &str) -> IntrospectionAccess {
    let (span, location) = span();
    IntrospectionAccess {
        attribute: attribute.into(),
        receiver: Provenance::Unknown,
        text: text.into(),
        symbol: "<module>".into(),
        span,
        location,
    }
}

pub fn construct(kind: ConstructKind, text: &str) -> DynamicConstruct {
    let (span, location) = span();
    DynamicConstruct {
        kind,
        text: text.into(),
        symbol: "<module>".into(),
        span,
        location,
    }
}

/// An IR builder.
pub struct Ir(pub FileIr);

pub fn py() -> Ir {
    Ir(FileIr::new(Language::Python))
}

pub fn js() -> Ir {
    Ir(FileIr::new(Language::Javascript))
}

pub fn rs() -> Ir {
    Ir(FileIr::new(Language::Rust))
}

pub fn go() -> Ir {
    Ir(FileIr::new(Language::Go))
}

impl Ir {
    pub fn import(mut self, i: Import) -> Ir {
        self.0.imports.push(i);
        self
    }
    pub fn r(mut self, r: R) -> Ir {
        self.0.references.push(r.0);
        self
    }
    pub fn sym(mut self, s: SymbolSpan) -> Ir {
        self.0.symbols.push(s);
        self
    }
    pub fn local(mut self, l: LocalBinding) -> Ir {
        self.0.locals.push(l);
        self
    }
    pub fn constant(mut self, c: ModuleConstant) -> Ir {
        self.0.constants.push(c);
        self
    }
    pub fn self_attr(mut self, a: SelfAttribute) -> Ir {
        self.0.self_attributes.push(a);
        self
    }
    pub fn introspection(mut self, a: IntrospectionAccess) -> Ir {
        self.0.introspection.push(a);
        self
    }
    pub fn construct(mut self, c: DynamicConstruct) -> Ir {
        self.0.constructs.push(c);
        self
    }
}

/// Test specifier rules. Relative specifiers (`./x`, `../x`) probe the exact
/// path, then `.py`, `.js`, then `__init__.py` and `index.js` inside a
/// directory. A bare specifier `a.b` probes `a/b.py` and `a/b/__init__.py`.
pub struct TestRules;

impl SpecifierRules for TestRules {
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind {
        // Python relative imports: `.a` is a sibling, `..a` one level up.
        if specifier.starts_with('.')
            && !specifier.starts_with("./")
            && !specifier.starts_with("../")
        {
            let dots = specifier.chars().take_while(|c| *c == '.').count();
            let rest = specifier[dots..].replace('.', "/");
            let mut target = String::from(".");
            for _ in 1..dots {
                target.push_str("/..");
            }
            if !rest.is_empty() {
                target.push('/');
                target.push_str(&rest);
            }
            return self.classify(from, &target);
        }
        let generic = GenericRules {
            extensions: vec![".py".into(), ".js".into()],
            index_names: vec!["__init__".into(), "index".into()],
        };
        match generic.classify(from, specifier) {
            SpecifierKind::Bare { module, .. } => {
                let base = module.replace('.', "/");
                SpecifierKind::Bare {
                    probes: vec![
                        format!("{base}.py").into_bytes(),
                        format!("{base}/__init__.py").into_bytes(),
                    ],
                    module,
                }
            }
            other => other,
        }
    }

    fn submodule(&self, specifier: &str, member: &str) -> Option<String> {
        if specifier.starts_with('.') {
            Some(format!("{}/{member}", specifier.trim_end_matches('/')))
        } else {
            Some(format!("{specifier}.{member}"))
        }
    }
}

/// A set of first-party files plus other index entries.
#[derive(Default)]
pub struct Fx {
    pub files: Vec<(String, FileIr)>,
    pub other: Vec<String>,
    pub unsupported: Vec<String>,
    pub unlowered: Vec<String>,
    pub excluded: Vec<String>,
}

pub fn fx() -> Fx {
    Fx::default()
}

impl Fx {
    pub fn file(mut self, path: &str, ir: Ir) -> Fx {
        self.files.push((path.into(), ir.0));
        self
    }
    pub fn other(mut self, path: &str) -> Fx {
        self.other.push(path.into());
        self
    }
    pub fn unlowered(mut self, path: &str) -> Fx {
        self.unlowered.push(path.into());
        self
    }
    pub fn excluded(mut self, dir: &str) -> Fx {
        self.excluded.push(dir.into());
        self
    }

    pub fn run(&self) -> Classified {
        self.run_with(data(), u64::MAX)
    }

    pub fn run_with(&self, data: &Data, budget: u64) -> Classified {
        let mut index = BTreeMap::new();
        for (p, ir) in &self.files {
            index.insert(p.as_bytes().to_vec(), FileKind::Source(ir.language));
        }
        for p in &self.unlowered {
            index.insert(p.as_bytes().to_vec(), FileKind::Source(Language::Python));
        }
        for p in &self.other {
            index.insert(p.as_bytes().to_vec(), FileKind::Other);
        }
        for p in &self.unsupported {
            index.insert(p.as_bytes().to_vec(), FileKind::Unsupported);
        }
        let excluded: BTreeSet<Vec<u8>> = self
            .excluded
            .iter()
            .map(|d| d.as_bytes().to_vec())
            .collect();
        let rules = TestRules;
        let mut program = Program::new(&index, &excluded);
        for lang in Language::ALL {
            program.set_rules(lang, &rules);
        }
        for (p, ir) in &self.files {
            program.add_file(
                p.as_bytes().to_vec(),
                ProgramFile {
                    file: encode_path_bytes(p.as_bytes()),
                    language: ir.language,
                    labels: Vec::new(),
                    ir,
                },
            );
        }
        classify(data, &program, budget)
    }
}

/// `(file, symbol, mechanism, destination display)` per site, sorted.
pub fn sites(c: &Classified) -> Vec<(String, String, String, String)> {
    let mut v: Vec<_> = c
        .sites
        .iter()
        .map(|s| {
            (
                s.file.clone(),
                s.symbol.clone(),
                s.mechanism.clone(),
                s.destination.display.clone(),
            )
        })
        .collect();
    v.sort();
    v
}

/// `(mechanism, destination display)` per site, sorted.
pub fn mechs(c: &Classified) -> Vec<(String, String)> {
    let mut v: Vec<_> = c
        .sites
        .iter()
        .map(|s| (s.mechanism.clone(), s.destination.display.clone()))
        .collect();
    v.sort();
    v
}

/// `(file, kind)` per blind spot, sorted.
pub fn spots(c: &Classified) -> Vec<(String, String)> {
    let mut v: Vec<_> = c
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind.as_str().to_string()))
        .collect();
    v.sort();
    v
}

/// Blind-spot kinds, sorted.
pub fn kinds(c: &Classified) -> Vec<String> {
    let mut v: Vec<_> = c
        .blind_spots
        .iter()
        .map(|b| b.kind.as_str().to_string())
        .collect();
    v.sort();
    v
}

/// Unscanned dependency package names, sorted.
pub fn deps(c: &Classified) -> Vec<String> {
    let mut v: Vec<_> = c
        .unscanned_dependencies
        .iter()
        .map(|d| d.package.clone())
        .collect();
    v.sort();
    v
}

pub fn s(v: &str) -> String {
    v.to_string()
}

pub fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

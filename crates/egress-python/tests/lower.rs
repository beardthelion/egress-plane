//! Python lowering tests (U5): IR facts per KTD4, KTD9, KTD10, and KTD15,
//! specifier rules per KTD16, and end-to-end scans of small trees through
//! the real classifier.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::ir::{Expr, FileIr, Import, Provenance, Reference, Root, SymbolKind, UseKind};
use egress_core::model::Report;
use egress_core::resolve::{SpecifierKind, SpecifierRules};
use egress_python::{LowerError, PythonRules, lower};

// ---- helpers ------------------------------------------------------------------

fn ir(src: &str) -> FileIr {
    lower(src).unwrap_or_else(|e| panic!("lowering failed: {e:?}"))
}

fn s(x: &str) -> String {
    x.to_string()
}

fn chain(r: &Reference) -> Vec<&str> {
    r.members.iter().map(String::as_str).collect()
}

/// References whose root is `root` and whose member chain is `members`.
fn refs<'a>(ir: &'a FileIr, root: &Root, members: &[&str]) -> Vec<&'a Reference> {
    ir.references
        .iter()
        .filter(|r| &r.root == root && chain(r) == members)
        .collect()
}

fn one<'a>(ir: &'a FileIr, root: &Root, members: &[&str]) -> &'a Reference {
    let v = refs(ir, root, members);
    assert_eq!(v.len(), 1, "{root:?} {members:?} in {:#?}", ir.references);
    v[0]
}

fn imp(name: &str) -> Root {
    Root::Import(name.into())
}

fn amb(name: &str) -> Root {
    Root::Ambient(name.into())
}

fn local(name: &str) -> Root {
    Root::Local(name.into())
}

fn import_named<'a>(ir: &'a FileIr, local: &str) -> &'a Import {
    ir.imports
        .iter()
        .find(|i| i.local.as_deref() == Some(local))
        .unwrap_or_else(|| panic!("no import binding {local}: {:#?}", ir.imports))
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A scan root under the target temp dir, removed on drop.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(files: &[(&str, &str)]) -> Tree {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("egress-u5")
            .join(format!("t-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, body) in files {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
        }
        std::fs::create_dir_all(&root).unwrap();
        Tree { root }
    }

    fn scan(&self) -> Report {
        egress_scan::scan(&self.root).unwrap_or_else(|e| panic!("scan failed: {e:?}"))
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn scan(files: &[(&str, &str)]) -> Report {
    Tree::new(files).scan()
}

/// (mechanism, destination display) of every site, sorted.
fn sites(r: &Report) -> Vec<(String, String)> {
    let mut v: Vec<_> = r
        .sites
        .iter()
        .map(|s| (s.mechanism.clone(), s.destination.display.clone()))
        .collect();
    v.sort();
    v
}

/// Blind-spot kinds, sorted.
fn kinds(r: &Report) -> Vec<String> {
    let mut v: Vec<_> = r
        .blind_spots
        .iter()
        .map(|b| b.kind.as_str().to_string())
        .collect();
    v.sort();
    v
}

/// Blind-spot kinds on `line` (1-based) of the only file.
fn kinds_on_line(r: &Report, line: u32) -> Vec<String> {
    let mut v: Vec<_> = r
        .blind_spots
        .iter()
        .filter(|b| b.location.is_some_and(|l| l.line == line))
        .map(|b| b.kind.as_str().to_string())
        .collect();
    v.sort();
    v
}

fn pair(a: &str, b: &str) -> (String, String) {
    (s(a), s(b))
}

// ---- references and arguments (KTD4) --------------------------------------------

#[test]
fn covers_ae1_requests_post_with_an_env_read_argument() {
    let ir = ir(
        "import os\nimport requests\n\ndef notify(p):\n    requests.post(os.environ[\"WEBHOOK_URL\"], json=p)\n",
    );
    let r = one(&ir, &imp("requests"), &["post"]);
    assert_eq!(r.use_kind, UseKind::Call);
    assert_eq!(r.symbol, "notify");
    let Expr::Subscript { base, key } = &r.args[0] else {
        panic!("{:?}", r.args)
    };
    let Expr::Reference(env) = base.as_ref() else {
        panic!("{base:?}")
    };
    assert_eq!((&env.root, chain(env)), (&imp("os"), vec!["environ"]));
    assert_eq!(key.as_ref(), &Expr::Literal(s("WEBHOOK_URL")));
    assert_eq!(r.kwargs, vec![(s("json"), Expr::Param(1))]);
    assert_eq!(r.text, "requests.post(os.environ[\"WEBHOOK_URL\"], json=p)");
}

#[test]
fn covers_ae3_import_of_a_non_literal_name_is_a_dynamic_import_trigger() {
    let ir = ir("def f(name, url):\n    getattr(__import__(name), \"urlopen\")(url)\n");
    let r = one(&ir, &amb("__import__"), &[]);
    assert_eq!(r.use_kind, UseKind::Call);
    assert_eq!(r.args, vec![Expr::Param(1)]);
    let report = scan(&[(
        "a.py",
        "def f(name, url):\n    getattr(__import__(name), \"urlopen\")(url)\n",
    )]);
    assert!(
        kinds(&report).contains(&s("dynamic-import")),
        "{:?}",
        kinds(&report)
    );
}

#[test]
fn covers_ae8_python2_print_is_a_parse_error() {
    assert_eq!(lower("print \"hello\"\n"), Err(LowerError::Parse));
}

#[test]
fn covers_ae22_nested_call_argument_and_reflective_access_on_a_module() {
    let ir = ir(
        "import base64\nimport requests\n\ndef send(blob, verb):\n    requests.post(base64.b64decode(blob).decode())\n    getattr(requests, verb)\n",
    );
    let r = one(&ir, &imp("requests"), &["post"]);
    let Expr::Reference(arg) = &r.args[0] else {
        panic!("{:?}", r.args)
    };
    assert_eq!(arg.use_kind, UseKind::Call);
    assert_eq!(arg.text, "base64.b64decode(blob).decode()");
    // The inner call is a reference in its own right.
    let inner = one(&ir, &imp("base64"), &["b64decode"]);
    assert_eq!(inner.args, vec![Expr::Param(1)]);
    let g = one(&ir, &amb("getattr"), &[]);
    assert_eq!(g.receiver, Some(Provenance::ModuleBinding));
    assert_eq!(g.args, vec![Expr::Name(s("requests")), Expr::Param(2)]);
    // The module handed to getattr is the reflective target, not a value
    // escape of its own.
    assert!(refs(&ir, &imp("requests"), &[]).is_empty());
}

#[test]
fn covers_ae27_receiver_provenance_for_untracked_values() {
    let ir = ir(
        "def make_client():\n    return object()\n\ndef run(name, u):\n    c = make_client()\n    getattr(c, name)(u)\n\ndef f(o, n):\n    getattr(o, n)\n",
    );
    let gs: Vec<_> = refs(&ir, &amb("getattr"), &[]);
    assert_eq!(gs.len(), 2);
    let by_symbol = |sym: &str| {
        gs.iter()
            .find(|r| r.symbol == sym)
            .unwrap()
            .receiver
            .clone()
    };
    assert_eq!(by_symbol("run"), Some(Provenance::FirstPartyCallResult));
    assert_eq!(by_symbol("f"), Some(Provenance::Parameter(1)));
}

#[test]
fn must_not_subscript_is_never_reflective_and_literal_getattr_records_the_name() {
    let ir = ir("def f(d, k, c):\n    d[k]\n    getattr(c, \"close\")\n");
    assert!(
        ir.references
            .iter()
            .all(|r| r.use_kind != UseKind::ComputedMember && r.receiver.is_none()),
        "{:#?}",
        ir.references
    );
    let g = one(&ir, &amb("getattr"), &[]);
    assert_eq!(g.args[1], Expr::Literal(s("close")));
}

#[test]
fn from_import_alias_resolves_the_member_chain() {
    let ir = ir("from urllib import request as r\nr.urlopen(u)\n");
    let i = import_named(&ir, "r");
    assert_eq!(
        (i.specifier.as_str(), i.members.clone()),
        ("urllib", vec![s("request")])
    );
    one(&ir, &imp("r"), &["urlopen"]);
    let report = scan(&[(
        "a.py",
        "from urllib import request as r\nr.urlopen(\"https://x.example\")\n",
    )]);
    assert_eq!(
        sites(&report),
        vec![pair("python:urllib.request.urlopen", "https://x.example")]
    );
}

#[test]
fn relative_import_resolves_to_the_sibling_module() {
    let ir = ir("from .net import post\n");
    let i = import_named(&ir, "post");
    assert_eq!(
        (i.specifier.as_str(), i.members.clone()),
        (".net", vec![s("post")])
    );
    let report = scan(&[
        ("pkg/__init__.py", ""),
        ("pkg/net.py", "from requests import post\n"),
        (
            "pkg/app.py",
            "from .net import post\n\ndef emit():\n    post(\"https://e.example\")\n",
        ),
    ]);
    assert_eq!(
        sites(&report),
        vec![pair("python:requests.post", "https://e.example")]
    );
    assert!(report.blind_spots.is_empty(), "{:?}", report.blind_spots);
}

#[test]
fn must_hit_import_os_path_binds_os() {
    let ir = ir("import os.path\nos.system(c)\n");
    let i = import_named(&ir, "os");
    assert_eq!(i.specifier, "os");
    one(&ir, &imp("os"), &["system"]);
}

#[test]
fn shadowed_builtin_exec_is_a_local() {
    let src = "def exec(code):\n    return code\n\nexec(\"x\")\n";
    let ir = ir(src);
    one(&ir, &local("exec"), &[]);
    let report = scan(&[("a.py", src)]);
    assert!(report.blind_spots.is_empty(), "{:?}", report.blind_spots);
}

#[test]
fn nested_function_and_lambda_symbol_paths() {
    let ir = ir(
        "def outer():\n    def inner():\n        pass\n    g = lambda: 1\n\nh = lambda: 2\n\nclass C:\n    def m(self, a, b=1, *c, d, **e):\n        pass\n",
    );
    let mut paths: Vec<(&str, SymbolKind)> = ir
        .symbols
        .iter()
        .map(|s| (s.path.as_str(), s.kind))
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            ("<lambda>", SymbolKind::Closure),
            ("C", SymbolKind::Class),
            ("C.m", SymbolKind::Method),
            ("outer", SymbolKind::Function),
            ("outer.<locals>.<lambda>", SymbolKind::Closure),
            ("outer.<locals>.inner", SymbolKind::Function),
        ]
    );
    let m = ir.symbols.iter().find(|s| s.path == "C.m").unwrap();
    assert_eq!(m.params, vec![s("a"), s("b"), s("c"), s("d"), s("e")]);
}

#[test]
fn assignment_to_an_egress_module_member_is_an_assignment_target() {
    let ir = ir("import socket\nsocket.socket = Fake\n");
    let r = one(&ir, &imp("socket"), &["socket"]);
    assert_eq!(r.use_kind, UseKind::AssignmentTarget);
}

#[test]
fn ktd8_self_attribute_in_init_and_method_call_on_it() {
    let ir = ir(
        "import requests\n\nclass Api:\n    def __init__(self):\n        self.s = requests.Session()\n\n    def get(self, u):\n        return self.s.get(u)\n\n    def reset(self):\n        self.t = 1\n",
    );
    assert_eq!(ir.self_attributes.len(), 1);
    let a = &ir.self_attributes[0];
    assert_eq!((a.class.as_str(), a.attribute.as_str()), ("Api", "s"));
    let Expr::Reference(v) = &a.value else {
        panic!("{:?}", a.value)
    };
    assert_eq!(
        (&v.root, chain(v), v.use_kind),
        (&imp("requests"), vec!["Session"], UseKind::Call)
    );
    let call = one(&ir, &Root::SelfValue, &["s", "get"]);
    assert_eq!(
        (call.symbol.as_str(), call.use_kind),
        ("Api.get", UseKind::Call)
    );
    assert_eq!(call.args, vec![Expr::Param(1)]);
    // A write outside `__init__` is recorded as an assignment target.
    let w = one(&ir, &Root::SelfValue, &["t"]);
    assert_eq!(
        (w.symbol.as_str(), w.use_kind),
        ("Api.reset", UseKind::AssignmentTarget)
    );
}

#[test]
fn covers_ae20_value_uses_in_every_evaluated_position() {
    let src = "import functools, os, socket\n\
run = functools.partial(os.system, cmd)\n\
f = os.system\n\
class X(socket.socket):\n    pass\n\
def g(s=socket.socket()):\n    pass\n\
@socket.create_connection\ndef d():\n    pass\n\
class M(metaclass=socket.socket):\n    pass\n\
v = f\"{x:{os.system('id')}}\"\n";
    let ir = ir(src);
    let sys_refs = refs(&ir, &imp("os"), &["system"]);
    let mut uses: Vec<UseKind> = sys_refs.iter().map(|r| r.use_kind).collect();
    uses.sort();
    assert_eq!(
        uses,
        vec![UseKind::Call, UseKind::ValueEscape, UseKind::ValueEscape]
    );
    let sock: Vec<UseKind> = refs(&ir, &imp("socket"), &["socket"])
        .iter()
        .map(|r| r.use_kind)
        .collect();
    assert!(sock.contains(&UseKind::BaseClass), "{sock:?}");
    assert!(sock.contains(&UseKind::Call), "{sock:?}");
    assert!(sock.contains(&UseKind::ValueEscape), "{sock:?}");
    let deco = one(&ir, &imp("socket"), &["create_connection"]);
    assert_eq!(deco.use_kind, UseKind::ValueEscape);
}

#[test]
fn eager_annotations_are_references_unless_postponed() {
    let eager = ir("import os\ndef h(x: os.system(\"id\")): ...\n");
    let r = one(&eager, &imp("os"), &["system"]);
    assert_eq!(r.use_kind, UseKind::Call);
    let lazy =
        ir("from __future__ import annotations\nimport os\ndef h(x: os.system(\"id\")): ...\n");
    assert!(refs(&lazy, &imp("os"), &["system"]).is_empty());
    // A local variable annotation inside a function is never evaluated.
    let local_ann = ir("import os\ndef h():\n    x: os.system(\"id\") = 1\n");
    assert!(refs(&local_ann, &imp("os"), &["system"]).is_empty());
}

#[test]
fn covers_ae21_introspection_roots_are_recorded_and_reported() {
    let ir = ir("().__class__.__base__.__subclasses__()\n");
    let names: Vec<&str> = ir
        .introspection
        .iter()
        .map(|a| a.attribute.as_str())
        .collect();
    assert_eq!(names, vec!["__class__", "__base__", "__subclasses__"]);
    let report = scan(&[(
        "a.py",
        "import sys\n().__class__.__base__.__subclasses__()\nf.__globals__[\"os\"]\nsys._getframe().f_globals\ntype(x).__name__\n",
    )]);
    assert!(!kinds_on_line(&report, 2).is_empty());
    assert_eq!(kinds_on_line(&report, 3), vec![s("introspection")]);
    assert!(kinds_on_line(&report, 4).contains(&s("introspection")));
    assert!(
        kinds_on_line(&report, 5).is_empty(),
        "{:?}",
        report.blind_spots
    );
}

#[test]
fn self_and_frame_builtins_are_introspection() {
    let report = scan(&[(
        "a.py",
        "def f(s, e):\n    len.__self__.eval(s)\n    e.__traceback__.tb_frame.f_builtins\n",
    )]);
    assert!(kinds_on_line(&report, 2).contains(&s("introspection")));
    assert!(kinds_on_line(&report, 3).contains(&s("introspection")));
}

#[test]
fn must_not_inert_dunders_yield_no_blind_spot() {
    let report = scan(&[(
        "a.py",
        "import json as mod\n\nclass A(Exception):\n    def __init__(self, x):\n        super().__init__()\n        self.n = x.__class__.__name__\n        self.v = mod.__version__\n",
    )]);
    assert!(report.blind_spots.is_empty(), "{:?}", report.blind_spots);
}

#[test]
fn scope_injection_by_non_literal_key() {
    let ir = ir("def f(k):\n    __builtins__[k]\n");
    let r = one(&ir, &amb("__builtins__"), &[]);
    assert_eq!(r.use_kind, UseKind::ComputedMember);
    assert_eq!(r.receiver, Some(Provenance::AmbientModule));
    let report = scan(&[(
        "a.py",
        "def f(k):\n    globals()[k]\n    locals()[k]\n    vars()[k]\n    __builtins__[k]\n",
    )]);
    for line in 2..=5 {
        assert_eq!(
            kinds_on_line(&report, line),
            vec![s("scope-injection")],
            "line {line}"
        );
    }
}

#[test]
fn star_imports() {
    let ir = ir("from os import *\n");
    assert!(ir.imports[0].star && ir.imports[0].local.is_none());
    let report = scan(&[("a.py", "from os import *\n")]);
    assert_eq!(kinds(&report), vec![s("module-escape")]);
    let report = scan(&[("a.py", "from os.path import *\njoin(a, b)\n")]);
    assert!(
        report.blind_spots.is_empty() && report.sites.is_empty(),
        "{report:?}"
    );
    let report = scan(&[
        ("helpers.py", "from requests import get\n"),
        (
            "a.py",
            "from helpers import *\nget(\"https://h.example\")\n",
        ),
    ]);
    assert_eq!(
        sites(&report),
        vec![pair("python:requests.get", "https://h.example")]
    );
}

#[test]
fn builtins_module_reflection_and_eval() {
    let report = scan(&[(
        "a.py",
        "import builtins\n\ndef f(k, x, s):\n    getattr(builtins, k)(x)\n    builtins.eval(s)\n",
    )]);
    assert_eq!(kinds_on_line(&report, 4), vec![s("reflective-access")]);
    assert_eq!(kinds_on_line(&report, 5), vec![s("dynamic-code")]);
}

#[test]
fn import_system_writes_yield_blind_spots() {
    let report = scan(&[(
        "a.py",
        "import importlib, socket, sys\n\ndef f(p, x, m, F):\n    sys.path.insert(0, p)\n    sys.meta_path.append(x)\n    sys.modules[\"requests\"] = x\n    importlib.reload(m)\n    setattr(socket, \"socket\", F)\n",
    )]);
    for line in 4..=8 {
        assert!(
            !kinds_on_line(&report, line).is_empty(),
            "line {line}: {:?}",
            report.blind_spots
        );
    }
}

#[test]
fn fullwidth_identifiers_are_nfkc_normalized() {
    let ir = ir(
        "\u{ff45}\u{ff56}\u{ff41}\u{ff4c}(code)\nimport \u{ff4f}\u{ff53}\n\u{ff4f}\u{ff53}.system(c)\n",
    );
    one(&ir, &amb("eval"), &[]);
    import_named(&ir, "os");
    one(&ir, &imp("os"), &["system"]);
    let report = scan(&[(
        "a.py",
        "\u{ff45}\u{ff56}\u{ff41}\u{ff4c}(code)\nimport \u{ff4f}\u{ff53}\n\u{ff4f}\u{ff53}.system(\"curl x\")\n",
    )]);
    assert_eq!(kinds(&report), vec![s("dynamic-code")]);
    assert_eq!(sites(&report), vec![pair("python:os.system", "exec:curl")]);
}

#[test]
fn must_not_literal_getattr_is_an_ordinary_reference() {
    let report = scan(&[("a.py", "import os\np = getattr(os, \"path\")\n")]);
    assert!(report.blind_spots.is_empty(), "{:?}", report.blind_spots);
    assert!(report.sites.is_empty(), "{:?}", report.sites);
}

#[test]
fn ktd10_columns_count_unicode_scalar_values() {
    let ir = ir("import requests\nx = \"\u{e9}\u{4e2d}\"; requests.get(u)\n");
    let r = one(&ir, &imp("requests"), &["get"]);
    assert_eq!((r.location.line, r.location.column), (2, 11));
}

#[test]
fn deep_nesting_is_too_deeply_nested_and_the_scan_continues() {
    let deep = format!("x = {}1{}\n", "(".repeat(10_000), ")".repeat(10_000));
    let chain = format!("x = {}1\n", "1 + ".repeat(200_000));
    let report = scan(&[
        ("deep.py", &deep),
        ("chain.py", &chain),
        (
            "ok.py",
            "import requests\nrequests.get(\"https://ok.example\")\n",
        ),
    ]);
    let mut whole: Vec<(String, String)> = report
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind.as_str().to_string()))
        .collect();
    whole.sort();
    assert_eq!(
        whole,
        vec![
            pair("chain.py", "too-deeply-nested"),
            pair("deep.py", "too-deeply-nested")
        ]
    );
    assert_eq!(
        sites(&report),
        vec![pair("python:requests.get", "https://ok.example")]
    );
}

#[test]
fn literal_loader_calls_lower_as_imports() {
    let ir = ir(
        "import importlib\nx = importlib.import_module(\"subprocess\")\n__import__(\"os\").system(c)\n",
    );
    let i = import_named(&ir, "x");
    assert_eq!(i.specifier, "subprocess");
    let report = scan(&[(
        "a.py",
        "import importlib\nx = importlib.import_module(\"subprocess\")\nx.run([\"curl\", u])\n__import__(\"os\").system(\"wget y\")\n",
    )]);
    assert_eq!(
        sites(&report),
        vec![
            pair("python:os.system", "exec:wget"),
            pair("python:subprocess.run", "exec:curl")
        ]
    );
    assert!(report.blind_spots.is_empty(), "{:?}", report.blind_spots);
}

#[test]
fn asyncio_loop_methods_are_sites() {
    let report = scan(&[(
        "a.py",
        "import asyncio\n\nasync def probe(P):\n    loop = asyncio.get_running_loop()\n    await loop.create_connection(P, \"h.example\", 443)\n    await loop.subprocess_exec(P, \"curl\", \"-s\")\n",
    )]);
    assert_eq!(
        sites(&report),
        vec![
            pair(
                "python:asyncio.get_running_loop",
                "expr:asyncio.get_running_loop()"
            ),
            pair(
                "python:asyncio.get_running_loop.create_connection",
                "h.example:443"
            ),
            pair(
                "python:asyncio.get_running_loop.subprocess_exec",
                "exec:curl"
            ),
        ]
    );
}

// ---- specifier rules (KTD16) ------------------------------------------------------

fn probes(k: SpecifierKind) -> Vec<String> {
    match k {
        SpecifierKind::Path { probes } | SpecifierKind::Bare { probes, .. } => probes
            .into_iter()
            .map(|p| String::from_utf8(p).unwrap())
            .collect(),
        SpecifierKind::OutsideRoot => vec![s("<outside>")],
    }
}

#[test]
fn ktd16_relative_specifiers() {
    let r = PythonRules;
    assert_eq!(
        probes(r.classify(b"pkg/app.py", ".net")),
        vec![s("pkg/net.py"), s("pkg/net/__init__.py")]
    );
    assert_eq!(
        probes(r.classify(b"pkg/sub/app.py", "..a.b")),
        vec![s("pkg/a/b.py"), s("pkg/a/b/__init__.py")]
    );
    assert_eq!(
        probes(r.classify(b"pkg/app.py", ".")),
        vec![s("pkg/__init__.py")]
    );
    assert_eq!(probes(r.classify(b"app.py", "..x")), vec![s("<outside>")]);
    assert_eq!(r.submodule(".", "x").as_deref(), Some(".x"));
    assert_eq!(r.submodule("..a", "x").as_deref(), Some("..a.x"));
    assert_eq!(r.submodule("pkg", "x").as_deref(), Some("pkg.x"));
}

#[test]
fn ktd16_absolute_specifiers_probe_package_roots() {
    let r = PythonRules;
    let SpecifierKind::Bare { probes: p, module } = r.classify(b"svc/api/app.py", "net.http")
    else {
        panic!()
    };
    assert_eq!(module, "net.http");
    let p: Vec<String> = p
        .into_iter()
        .map(|p| String::from_utf8(p).unwrap())
        .collect();
    for want in [
        "net/http.py",
        "net/http/__init__.py",
        "src/net/http.py",
        "svc/net/http.py",
        "svc/api/net/http.py",
    ] {
        assert!(p.contains(&s(want)), "{want} not in {p:?}");
    }
    assert_eq!(&p[..2], &[s("net/http.py"), s("net/http/__init__.py")]);
}

#[test]
fn literal_loader_values_that_flow_elsewhere_escape() {
    // A loader call whose module value is returned, called through a
    // lambda, unpacked, iterated, or chosen by a ternary is a module used
    // as a value, the same as `return socket` after `import socket`.
    let cases = [
        "import importlib\ndef f():\n    return importlib.import_module(\"subprocess\")\nf().run([\"x\"])\n",
        "m = (lambda: __import__(\"socket\"))()\nm.create_connection((\"h\", 1))\n",
        "m, n = __import__(\"subprocess\"), 1\nm.run([\"x\"])\n",
        "for m in [__import__(\"subprocess\")]:\n    m.run([\"x\"])\n",
        "m = __import__(\"socket\") if c else None\nm.create_connection((\"h\", 1))\n",
    ];
    for src in cases {
        let report = scan(&[("a.py", src)]);
        assert!(
            !report.sites.is_empty() || !report.blind_spots.is_empty(),
            "nothing reported for {src:?}: {report:?}"
        );
    }
    let f = ir("def f():\n    return __import__(\"subprocess\")\n");
    let r = one(&f, &imp("__import__(\"subprocess\")"), &[]);
    assert_eq!(r.use_kind, UseKind::ValueEscape);
    // A reflective access's target is its receiver, not an escape, for a
    // loader call as for an imported name.
    let report = scan(&[("a.py", "getattr(__import__(\"os\"), \"system\")(\"x\")\n")]);
    assert_eq!(
        sites(&report),
        vec![pair(
            "python:os.system",
            "expr:getattr(__import__(\"os\"), \"system\")"
        )]
    );
    assert!(report.blind_spots.is_empty(), "{:?}", report.blind_spots);
    // A chain base and a named binding are not escapes of their own.
    let g = ir("x = __import__(\"os\")\n__import__(\"os\").system(c)\n");
    assert!(
        refs(&g, &imp("__import__(\"os\")"), &[]).is_empty(),
        "{:#?}",
        g.references
    );
}

#[test]
fn many_dotted_imports_lower_in_near_linear_work() {
    // Each `import a.bN` and each reference used to scan every dotted name
    // bound in the scope. Doubling the input must not quadruple the time.
    fn src(n: usize) -> String {
        let mut s = String::new();
        for i in 0..n {
            s.push_str(&format!("import a.b{i}\n"));
        }
        for i in 0..n {
            s.push_str(&format!("a.b{i}.f()\n"));
        }
        s
    }
    let time = |n: usize| {
        let text = src(n);
        let start = std::time::Instant::now();
        let lowered = ir(&text);
        let elapsed = start.elapsed();
        assert_eq!(one(&lowered, &imp("a.b7"), &["f"]).use_kind, UseKind::Call);
        elapsed
    };
    let small = time(2_000);
    let large = time(8_000);
    // Linear work gives a ratio near 4 and quadratic near 16.
    assert!(
        large < small * 10,
        "2k dotted imports took {small:?}, 8k took {large:?}"
    );
}

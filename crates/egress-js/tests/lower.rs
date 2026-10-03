//! JS/TS lowering to the IR: imports, references, provenance,
//! structural triggers, symbol paths, source types, and
//! parse errors.

use egress_core::ir::{
    ConstructKind, Expr, FileIr, Import, Provenance, Reference, Root, SymbolKind, UseKind,
};
use egress_js::{LowerError, lower};

fn ir(path: &str, src: &str) -> FileIr {
    lower(path.as_bytes(), src).unwrap_or_else(|e| panic!("{path}: {e:?}"))
}

fn refs<'a>(ir: &'a FileIr, text: &str) -> Vec<&'a Reference> {
    ir.references.iter().filter(|r| r.text == text).collect()
}

fn one<'a>(ir: &'a FileIr, text: &str) -> &'a Reference {
    let v = refs(ir, text);
    assert_eq!(
        v.len(),
        1,
        "references with text {text:?}: {:#?}",
        ir.references
    );
    v[0]
}

fn import<'a>(ir: &'a FileIr, local: &str) -> &'a Import {
    ir.imports
        .iter()
        .find(|i| i.local.as_deref() == Some(local))
        .unwrap_or_else(|| panic!("no import {local}: {:#?}", ir.imports))
}

fn kinds(ir: &FileIr) -> Vec<ConstructKind> {
    ir.constructs.iter().map(|c| c.kind).collect()
}

fn amb(n: &str) -> Root {
    Root::Ambient(n.into())
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

// ---- imports ------------------------------------------------------------------------

#[test]
fn esm_import_forms_lower_to_imports() {
    let f = ir(
        "a.mjs",
        r#"import http from "node:http";
import { get as g, request } from "undici";
import * as net from "net";
import "./side";
import { default as client } from "axios";
"#,
    );
    let h = import(&f, "http");
    assert_eq!(h.specifier, "node:http");
    assert!(h.default && !h.type_only && !h.star && !h.re_export);
    assert_eq!(import(&f, "g").members, s(&["get"]));
    assert_eq!(import(&f, "request").members, s(&["request"]));
    let n = import(&f, "net");
    assert!(n.members.is_empty() && !n.default && !n.star);
    let side = f.imports.iter().find(|i| i.specifier == "./side").unwrap();
    assert!(side.local.is_none());
    let c = import(&f, "client");
    assert!(c.default);
    assert_eq!(c.members, s(&["default"]));
    assert!(f.imports.iter().all(|i| i.symbol == "<module>"));
}

#[test]
fn require_and_its_equivalents_with_literal_specifiers_are_imports() {
    let f = ir(
        "a.cjs",
        r#"const http = require("http");
const { request, get: g } = require("https");
const conn = require("net").connect;
"#,
    );
    let h = import(&f, "http");
    assert_eq!(h.specifier, "http");
    assert!(h.default && h.members.is_empty());
    assert_eq!(import(&f, "request").members, s(&["request"]));
    assert_eq!(import(&f, "g").members, s(&["get"]));
    assert_eq!(import(&f, "conn").members, s(&["connect"]));
    assert!(f.constructs.is_empty(), "{:?}", f.constructs);

    let f = ir(
        "a.ts",
        r#"import net = require("net");
import { createRequire } from "node:module";
const req = createRequire(import.meta.url);
const a = req("net");
const b = createRequire(import.meta.url)("net");
const c = process.getBuiltinModule("net");
"#,
    );
    for local in ["net", "a", "b", "c"] {
        assert_eq!(import(&f, local).specifier, "net", "{local}");
    }
    assert!(f.constructs.is_empty(), "{:?}", f.constructs);
    // The loader factory call itself is not a reference the core would
    // read as a dynamic import.
    assert!(
        f.references
            .iter()
            .all(|r| !r.text.starts_with("createRequire(")),
        "{:#?}",
        f.references
    );
}

#[test]
fn inline_literal_require_roots_a_member_chain() {
    let f = ir("a.cjs", r#"require("child_process").exec("curl x");"#);
    let r = one(&f, r#"require("child_process").exec("curl x")"#);
    let Root::Import(local) = &r.root else {
        panic!("{r:?}")
    };
    assert_eq!(import(&f, local).specifier, "child_process");
    assert_eq!(r.members, s(&["exec"]));
    assert_eq!(r.use_kind, UseKind::Call);
    assert_eq!(r.args, vec![Expr::Literal("curl x".into())]);
}

#[test]
fn import_type_and_inline_type_specifiers_are_type_only() {
    let f = ir(
        "a.ts",
        r#"import type { Agent } from "undici";
import { type Dispatcher, request } from "undici";
"#,
    );
    assert!(import(&f, "Agent").type_only);
    assert!(import(&f, "Dispatcher").type_only);
    assert!(!import(&f, "request").type_only);
}

#[test]
fn re_exports_lower_to_re_export_imports() {
    let f = ir(
        "a.js",
        r#"export { request as r } from "./net";
export * from "./http.js";
export * as ns from "./ns.js";
export { default as client } from "axios";
import { get } from "node:http";
export { get };
"#,
    );
    let r = import(&f, "r");
    assert!(r.re_export);
    assert_eq!(
        (r.specifier.as_str(), r.members.clone()),
        ("./net", s(&["request"]))
    );
    let star = f
        .imports
        .iter()
        .find(|i| i.specifier == "./http.js")
        .unwrap();
    assert!(star.star && star.re_export && star.local.is_none());
    assert!(import(&f, "ns").re_export);
    let c = import(&f, "client");
    assert!(c.re_export && c.default);
    assert!(
        f.imports.iter().any(|i| i.local.as_deref() == Some("get")
            && i.re_export
            && i.specifier == "node:http")
    );
}

#[test]
fn require_of_data_and_json_files_is_an_import() {
    let f = ir(
        "app.js",
        r#"const payload = require("./payload.dat");
const config = require("./config.json");
"#,
    );
    assert_eq!(import(&f, "payload").specifier, "./payload.dat");
    assert_eq!(import(&f, "config").specifier, "./config.json");
}

#[test]
fn literal_dynamic_import_is_an_import_and_non_literal_is_a_trigger() {
    let f = ir(
        "a.mjs",
        r#"const m = await import("./lazy.js");
const n = await import(spec);
"#,
    );
    assert!(f.imports.iter().any(|i| i.specifier == "./lazy.js"));
    assert_eq!(kinds(&f), vec![ConstructKind::DynamicImport]);
}

// ---- references ---------------------------------------------------------------------

#[test]
fn ambient_local_and_computed_global() {
    let f = ir("a.js", "export function load(url) { return fetch(url); }");
    let r = one(&f, "fetch(url)");
    assert_eq!(r.root, amb("fetch"));
    assert_eq!(r.use_kind, UseKind::Call);
    assert_eq!(r.symbol, "load");
    assert_eq!(r.args, vec![Expr::Param(1)]);

    let f = ir(
        "b.js",
        "function fetch(u) { return u; }\nexport function g() { return fetch(\"x\"); }",
    );
    assert_eq!(one(&f, "fetch(\"x\")").root, Root::Local("fetch".into()));

    let f = ir("c.js", "globalThis[name](url);");
    let r = one(&f, "globalThis[name](url)");
    assert_eq!(r.root, amb("globalThis"));
    assert_eq!(r.use_kind, UseKind::ComputedMember);
    assert_eq!(r.receiver, Some(Provenance::AmbientModule));
}

#[test]
fn forty_calls_are_forty_references_to_one_import() {
    let mut src = String::from("import leftPad from \"left-pad\";\n");
    for i in 0..40 {
        src.push_str(&format!("leftPad(s{i});\n"));
    }
    let f = ir("pad.js", &src);
    assert_eq!(f.imports.len(), 1);
    let calls: Vec<_> = f
        .references
        .iter()
        .filter(|r| r.root == Root::Import("leftPad".into()) && r.use_kind == UseKind::Call)
        .collect();
    assert_eq!(calls.len(), 40);
}

#[test]
fn receiver_provenance() {
    let f = ir(
        "a.js",
        r#"import lib from "lib";
import { mk } from "./mk.js";
export function run(k, u) {
  const o = lib.get();
  o[k](u);
  const p = mk();
  p[k];
}
function f(o, k) { return o[k]; }
"#,
    );
    assert_eq!(
        one(&f, "o[k](u)").receiver,
        Some(Provenance::UnscannedCallResult)
    );
    assert_eq!(one(&f, "o[k](u)").use_kind, UseKind::ComputedMember);
    assert_eq!(
        one(&f, "p[k]").receiver,
        Some(Provenance::FirstPartyCallResult)
    );
    let r = one(&f, "o[k]");
    assert_eq!(r.receiver, Some(Provenance::Parameter(1)));
    assert_eq!(r.root, Root::Param(1));
}

#[test]
fn must_not_literal_receivers_record_literal_provenance() {
    let f = ir(
        "a.js",
        "export function f(k, i) { const m = { a: 1 }; const arr = [1]; return m[k] + arr[i]; }",
    );
    assert_eq!(one(&f, "m[k]").receiver, Some(Provenance::Literal));
    assert_eq!(one(&f, "arr[i]").receiver, Some(Provenance::Literal));
}

#[test]
fn literal_computed_keys_are_plain_members() {
    let f = ir("a.js", r#"globalThis["fetch"](u); process.env["API"];"#);
    let r = one(&f, r#"globalThis["fetch"](u)"#);
    assert_eq!(
        (r.root.clone(), r.members.clone()),
        (amb("globalThis"), s(&["fetch"]))
    );
    assert_eq!(r.use_kind, UseKind::Call);
}

#[test]
fn identifier_escapes_are_decoded() {
    let f = ir("a.js", "\\u0066etch(u);");
    assert_eq!(f.references[0].root, amb("fetch"));
}

#[test]
fn axios_create_local_and_this_attribute_lower_for_instance_tracking() {
    let f = ir(
        "a.js",
        r#"import axios from "axios";
export function f(B) {
  const api = axios.create({ baseURL: B });
  return api.post("/x");
}
export class C {
  constructor() { this.c = axios.create(); }
  get(u) { return this.c.get(u); }
}
"#,
    );
    let local = f.locals.iter().find(|l| l.name == "api").unwrap();
    assert_eq!(local.symbol, "f");
    let Expr::Reference(r) = &local.value else {
        panic!("{local:?}")
    };
    assert_eq!(r.members, s(&["create"]));
    assert_eq!(r.use_kind, UseKind::Call);
    assert_eq!(
        r.args,
        vec![Expr::Object(vec![("baseURL".into(), Expr::Param(1))])]
    );
    let post = one(&f, "api.post(\"/x\")");
    assert_eq!(post.root, Root::Local("api".into()));
    assert_eq!(post.members, s(&["post"]));
    assert!(!refs(&f, "axios.create({ baseURL: B })").is_empty());

    let a = &f.self_attributes[0];
    assert_eq!((a.class.as_str(), a.attribute.as_str()), ("C", "c"));
    let get = one(&f, "this.c.get(u)");
    assert_eq!(get.root, Root::SelfValue);
    assert_eq!(get.members, s(&["c", "get"]));
    assert_eq!(get.symbol, "C.get");
    assert!(!refs(&f, "axios.create()").is_empty());
    assert_eq!(refs(&f, "axios.create()")[0].symbol, "C.constructor");
}

#[test]
fn this_attribute_assignment_outside_the_constructor_is_an_assignment_target() {
    let f = ir("a.js", "class C { reset() { this.c = null; } }");
    let r = one(&f, "this.c");
    assert_eq!(r.use_kind, UseKind::AssignmentTarget);
    assert_eq!(r.root, Root::SelfValue);
    assert!(f.self_attributes.is_empty());
}

#[test]
fn base_class_reflect_apply_and_call() {
    let f = ir(
        "conn.js",
        r#"import net from "node:net";
export class Conn extends net.Socket {}
Reflect.apply(net.connect, null, [o]);
net.connect.call(null, o);
"#,
    );
    let b = one(&f, "net.Socket");
    assert_eq!(b.use_kind, UseKind::BaseClass);
    assert_eq!(b.symbol, "Conn");
    let v = one(&f, "net.connect");
    assert_eq!(v.use_kind, UseKind::ValueEscape);
    let c = one(&f, "net.connect.call(null, o)");
    assert_eq!(c.members, s(&["connect", "call"]));
    assert_eq!(c.use_kind, UseKind::Call);
}

#[test]
fn value_escapes_only_in_flow_positions() {
    let f = ir(
        "a.js",
        r#"if (typeof fetch === "function" && window.fetch) {}
const f = window.fetch || polyfill;
"#,
    );
    let fetches: Vec<&Reference> = f
        .references
        .iter()
        .filter(|r| r.text.contains("fetch"))
        .collect();
    assert_eq!(fetches.len(), 1, "{:#?}", f.references);
    assert_eq!(fetches[0].text, "window.fetch");
    assert_eq!(fetches[0].use_kind, UseKind::ValueEscape);
}

#[test]
fn ambient_aliases_and_sloppy_function_this_are_ambient_roots() {
    let f = ir(
        "a.cjs",
        r#"top.fetch(u); parent.fetch(u); frames.fetch(u); document.defaultView.fetch(u);
function f() { return this.fetch(u); }
"#,
    );
    assert_eq!(one(&f, "top.fetch(u)").root, amb("top"));
    assert_eq!(
        one(&f, "document.defaultView.fetch(u)").members,
        s(&["defaultView", "fetch"])
    );
    let t = one(&f, "this.fetch(u)");
    assert_eq!(t.root, amb("globalThis"));
    assert_eq!(t.members, s(&["fetch"]));
}

#[test]
fn must_not_this_in_methods_arrows_strict_functions_and_modules_is_not_ambient() {
    for (path, src) in [
        ("a.cjs", "class A { m() { return this.fetch(u); } }"),
        ("a.cjs", "const g = () => this.fetch(u);"),
        (
            "a.cjs",
            "function f() { \"use strict\"; return this.fetch(u); }",
        ),
        ("a.mjs", "function f() { return this.fetch(u); }"),
    ] {
        let f = ir(path, src);
        let t = one(&f, "this.fetch(u)");
        assert!(
            !matches!(t.root, Root::Ambient(_)),
            "{path}: {src}: {:?}",
            t.root
        );
    }
}

#[test]
fn symbol_paths_are_qualified_by_their_enclosing_definitions() {
    let f = ir(
        "a.js",
        r#"export class Api { list() { fetch(a); } constructor() { fetch(b); } }
export const ping = () => fetch(c);
export const api = { post(body) { fetch(d); }, get: () => fetch(e) };
function outer() { function inner() { fetch(g); } items.map((x) => fetch(x)); }
fetch(h);
"#,
    );
    let sym = |t: &str| one(&f, t).symbol.clone();
    assert_eq!(sym("fetch(a)"), "Api.list");
    assert_eq!(sym("fetch(b)"), "Api.constructor");
    assert_eq!(sym("fetch(c)"), "ping");
    assert_eq!(sym("fetch(d)"), "api.post");
    assert_eq!(sym("fetch(e)"), "api.get");
    assert_eq!(sym("fetch(g)"), "outer.inner");
    assert_eq!(sym("fetch(x)"), "outer");
    assert_eq!(sym("fetch(h)"), "<module>");
    let api = f.symbols.iter().find(|s| s.path == "Api").unwrap();
    assert_eq!(api.kind, SymbolKind::Class);
    let post = f.symbols.iter().find(|s| s.path == "api.post").unwrap();
    assert_eq!(post.params, s(&["body"]));
    assert_eq!(post.strict, Some(true));
}

#[test]
fn module_constants_and_templates_lower_for_destinations() {
    let f = ir(
        "a.ts",
        r#"export const BASE = "https://api.example.com";
const N = 3;
export function u(id: string) { return fetch(`${BASE}/v1/${id}?n=` + N); }
"#,
    );
    let c = f.constants.iter().find(|c| c.name == "BASE").unwrap();
    assert!(c.exported);
    assert_eq!(c.value, Expr::Literal("https://api.example.com".into()));
    assert!(!f.constants.iter().find(|c| c.name == "N").unwrap().exported);
    let r = f
        .references
        .iter()
        .find(|r| r.root == amb("fetch"))
        .unwrap();
    assert_eq!(
        r.args,
        vec![Expr::Template(vec![
            Expr::Name("BASE".into()),
            Expr::Literal("/v1/".into()),
            Expr::Param(1),
            Expr::Literal("?n=".into()),
            Expr::Name("N".into()),
        ])]
    );
}

#[test]
fn object_literal_with_shorthand_is_opaque_and_env_reads_are_references() {
    let f = ir(
        "a.js",
        r#"export function h(agent) { return get({ host: "h", agent }); }
export function e() { return fetch(process.env.URL); }
"#,
    );
    assert_eq!(
        one(&f, r#"get({ host: "h", agent })"#).args,
        vec![Expr::Opaque(r#"{ host: "h", agent }"#.into())]
    );
    let e = one(&f, "fetch(process.env.URL)");
    let Expr::Reference(r) = &e.args[0] else {
        panic!("{e:?}")
    };
    assert_eq!(
        (r.root.clone(), r.members.clone()),
        (amb("process"), s(&["env", "URL"]))
    );
}

// ---- structural triggers -----------------------------------------------------

#[test]
fn non_literal_loaders_are_dynamic_import_triggers() {
    for src in [
        "require(variable);",
        "createRequire(__filename)(x);",
        "module.require(x);",
        "require.main.require(x);",
        "process.mainModule.require(x);",
        "module.constructor._load(x);",
        "process.getBuiltinModule(x);",
    ] {
        let f = ir("a.cjs", src);
        assert_eq!(kinds(&f), vec![ConstructKind::DynamicImport], "{src}");
        assert!(f.imports.is_empty(), "{src}");
    }
}

#[test]
fn require_as_a_value_is_a_trigger_at_the_value_use() {
    let f = ir("a.cjs", "const r = require;\nr(\"net\");\n");
    assert_eq!(kinds(&f), vec![ConstructKind::RequireAsValue]);
    assert_eq!(f.constructs[0].text, "require");
}

#[test]
fn worker_constructions_are_construct_references() {
    let f = ir(
        "a.js",
        r#"import { Worker } from "node:worker_threads";
new Worker(spec);
new Worker("./w.js");
"#,
    );
    assert_eq!(one(&f, "new Worker(spec)").use_kind, UseKind::Construct);
    assert_eq!(
        one(&f, "new Worker(\"./w.js\")").args,
        vec![Expr::Literal("./w.js".into())]
    );
}

#[test]
fn string_timers_are_triggers_and_function_timers_are_not() {
    let f = ir(
        "a.js",
        "setTimeout(\"code\", 10);\nsetTimeout(fn, 10);\nwindow.setInterval(`x`, 1);",
    );
    assert_eq!(
        kinds(&f),
        vec![ConstructKind::DynamicImport, ConstructKind::DynamicImport]
    );
}

#[test]
fn function_constructor_and_eval_are_references() {
    let f = ir("a.js", "new Function(\"x\");\neval(code);\nglobalThis[k];");
    assert_eq!(one(&f, "new Function(\"x\")").use_kind, UseKind::Construct);
    assert_eq!(one(&f, "eval(code)").root, amb("eval"));
    assert_eq!(one(&f, "globalThis[k]").use_kind, UseKind::ComputedMember);
}

#[test]
fn constructor_chains() {
    let f = ir(
        "a.js",
        r#"(() => {}).constructor("return process")();
Object.getPrototypeOf(async () => {}).constructor("x");
const AF = Object.getPrototypeOf(async function () {}).constructor;
new AF("y");
"#,
    );
    assert_eq!(kinds(&f), vec![ConstructKind::ConstructorChain; 3]);

    let f = ir(
        "b.js",
        "class A {}\nconst n = obj.constructor.name;\nconst c = new A().constructor;\nclass B { clone() { return new this.constructor(); } }",
    );
    assert!(f.constructs.is_empty(), "{:?}", f.constructs);
}

#[test]
fn globalthis_aliases_and_reflection() {
    let f = ir(
        "a.js",
        "const g = globalThis;\ng[k](u);\ng.fetch(u);\nReflect.get(globalThis, k);\nObject.values(window);",
    );
    let c = one(&f, "g[k](u)");
    assert_eq!(c.root, Root::Local("g".into()));
    assert_eq!(c.receiver, Some(Provenance::AmbientModule));
    assert_eq!(one(&f, "g.fetch(u)").members, s(&["fetch"]));
    let rg = one(&f, "Reflect.get(globalThis, k)");
    assert_eq!(rg.receiver, Some(Provenance::AmbientModule));
    assert_eq!(one(&f, "window").use_kind, UseKind::ValueEscape);
    let g = f
        .locals
        .iter()
        .chain(std::iter::empty())
        .find(|l| l.name == "g");
    let c = f.constants.iter().find(|c| c.name == "g");
    assert!(g.is_some() || c.is_some());
}

#[test]
fn with_in_a_script_is_scope_injection() {
    let f = ir("a.js", "const x = require(\"y\");\nwith (o) { fetch(u); }");
    assert_eq!(kinds(&f), vec![ConstructKind::ScopeInjection]);
}

#[test]
fn import_system_writes_and_module_mutations() {
    let f = ir(
        "a.cjs",
        r#"const Module = require("module");
const http = require("http");
const net = require("net");
require.cache[k] = x;
Module._resolveFilename = f;
Module.prototype.require = f;
Object.defineProperty(http, "request", d);
Object.assign(net, o);
Reflect.set(net, "connect", f);
"#,
    );
    assert_eq!(kinds(&f), vec![ConstructKind::ImportSystemMutation]);
    let a = one(&f, "Module._resolveFilename");
    assert_eq!(a.use_kind, UseKind::AssignmentTarget);
    assert_eq!(
        one(&f, "Module.prototype.require").members,
        s(&["prototype", "require"])
    );
    let d = one(&f, "Object.defineProperty(http, \"request\", d)");
    assert_eq!(d.args[0], Expr::Name("http".into()));
    assert!(!refs(&f, "Object.assign(net, o)").is_empty());
    assert!(!refs(&f, "Reflect.set(net, \"connect\", f)").is_empty());
}

// ---- source types and errors ------------------------------------------------------------

#[test]
fn source_type_follows_the_extension_and_content() {
    // A CommonJS file accepts top-level `this`, `with`, and `return`.
    ir("a.cjs", "this.x = 1;\nwith (o) { f(); }\nreturn;");
    ir(
        "a.js",
        "const x = require(\"y\");\nwith (o) { f(); }\nreturn;",
    );
    assert_eq!(lower(b"a.mjs", "with (o) { f(); }"), Err(LowerError::Parse));
    assert_eq!(
        lower(b"a.js", "import x from \"y\";\nwith (o) { f(); }"),
        Err(LowerError::Parse)
    );
    // `.cts` accepts ESM syntax, which TypeScript compiles to CommonJS.
    ir(
        "d.cts",
        "export function d(): Promise<Response> { return fetch(\"x\"); }",
    );
    // JSX in a `.js` file.
    ir(
        "a.js",
        "export const B = () => <span>{fetch(\"x\")}</span>;",
    );
}

#[test]
fn recovered_parse_errors_and_flow_are_parse_errors() {
    assert_eq!(
        lower(b"a.js", "x = a ?? b || c;\nfetch(u);"),
        Err(LowerError::Parse)
    );
    assert_eq!(
        lower(b"a.js", "const a = 1;\nconst a = 2;"),
        Err(LowerError::Parse)
    );
    assert_eq!(
        lower(
            b"a.js",
            "// @flow\nfunction f(x: number): string { return x; }"
        ),
        Err(LowerError::Parse)
    );
    assert_eq!(
        lower(b"a.js", "function f(x: ?number) {}"),
        Err(LowerError::Parse)
    );
}

#[test]
fn columns_count_unicode_scalar_values() {
    let f = ir("a.js", "/* 😀界 */ fetch(u);");
    let r = one(&f, "fetch(u)");
    // Nine scalar values precede `fetch`; the emoji is four UTF-8 bytes and
    // two UTF-16 units, the CJK character three bytes and one unit.
    assert_eq!((r.location.line, r.location.column), (1, 10));
}

#[test]
fn declaration_files_lower_to_nothing() {
    let f = ir(
        "types.d.ts",
        "export declare function ping(): void;\nimport x from \"y\";",
    );
    assert!(f.references.is_empty() && f.imports.is_empty() && f.constructs.is_empty());
}

#[test]
fn deep_non_bracket_nesting_is_too_deeply_nested_not_an_abort() {
    for src in [
        format!("x = {}y;", "a ? b : ".repeat(200_000)),
        format!("f = {}y;", "a => ".repeat(200_000)),
        format!("x = y{};", ".a".repeat(1_000_000)),
        format!("x = y{};", " + y".repeat(1_000_000)),
        format!(
            "let x: {}number{};",
            "A<".repeat(200_000),
            ">".repeat(200_000)
        ),
    ] {
        let path = if src.starts_with("let") {
            b"a.ts" as &[u8]
        } else {
            b"a.js"
        };
        let run = move || lower(path, &src);
        let out = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(run)
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(out, Err(LowerError::TooDeeplyNested));
    }
}

#[test]
fn ordinary_long_code_is_not_too_deeply_nested() {
    let mut src = String::new();
    for i in 0..20_000 {
        src.push_str(&format!(
            "var a{i} = b{i} + c{i} * d({i}), e{i} = [1, 2, 3];\n"
        ));
    }
    src.push_str("var a=[");
    for i in 0..5000 {
        src.push_str(&format!("{i},"));
    }
    src.push_str("0];function t(){return fetch(\"https://api.example.com/t\")}\n");
    let f = ir("bundle.min.js", &src);
    assert_eq!(one(&f, "fetch(\"https://api.example.com/t\")").symbol, "t");
}

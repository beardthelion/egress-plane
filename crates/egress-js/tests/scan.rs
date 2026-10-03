//! The JS frontend through the real scan: lowering plus the core's
//! resolution and classification (scenarios that depend on both).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::model::Report;

fn scan(files: &[(&str, &str)]) -> Report {
    static N: AtomicUsize = AtomicUsize::new(0);
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "js-scan-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&root);
    for (path, text) in files {
        let p = root.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    let r = egress_scan::scan(&root).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    r
}

fn sites(r: &Report) -> Vec<(String, String, String)> {
    let mut v: Vec<_> = r
        .sites
        .iter()
        .map(|s| {
            (
                s.file.clone(),
                s.mechanism.clone(),
                s.destination.display.clone(),
            )
        })
        .collect();
    v.sort();
    v
}

fn spots(r: &Report) -> Vec<(String, String)> {
    let mut v: Vec<_> = r
        .blind_spots
        .iter()
        .map(|b| (b.file.clone(), b.kind.as_str().to_string()))
        .collect();
    v.sort();
    v
}

fn t(a: &str, b: &str, c: &str) -> (String, String, String) {
    (a.into(), b.into(), c.into())
}

fn p(a: &str, b: &str) -> (String, String) {
    (a.into(), b.into())
}

#[test]
fn covers_ae16_ambient_local_and_computed_global() {
    let r = scan(&[
        ("a.js", "export function f(url) { return fetch(url); }\n"),
        (
            "b.js",
            "function fetch(u) { return u; }\nexport const g = () => fetch(\"https://x.example\");\n",
        ),
        (
            "c.js",
            "export function h(name, url) { return globalThis[name](url); }\n",
        ),
    ]);
    assert_eq!(
        sites(&r),
        vec![t("a.js", "javascript:globalThis.fetch", "param:1:f")]
    );
    assert_eq!(spots(&r), vec![p("c.js", "reflective-access")]);
}

#[test]
fn covers_ae4_require_of_a_variable_is_a_blind_spot() {
    let r = scan(&[("a.cjs", "module.exports = (n) => require(n);\n")]);
    assert_eq!(spots(&r), vec![p("a.cjs", "dynamic-import")]);
    assert!(r.sites.is_empty());
}

#[test]
fn covers_ae27_reflective_unknown_and_literal_receivers() {
    let r = scan(&[(
        "a.js",
        r#"import lib from "lib";
export function run(k, u) { const o = lib.get(); return o[k](u); }
export function f(o, k) { return o[k]; }
export function ok(k, i) { const m = { a: 1 }; const arr = [1]; return [m[k], arr[i]]; }
"#,
    )]);
    assert_eq!(
        spots(&r),
        vec![
            p("a.js", "reflective-unknown"),
            p("a.js", "reflective-unknown")
        ]
    );
}

#[test]
fn node_prefix_and_require_resolve_to_the_same_module() {
    let r = scan(&[
        (
            "a.mjs",
            "import http from \"node:http\";\nexport const a = () => http.get(\"http://a.example\");\n",
        ),
        (
            "b.cjs",
            "const http = require(\"http\");\nexports.b = () => http.get(\"http://b.example\");\n",
        ),
    ]);
    assert_eq!(
        sites(&r),
        vec![
            t("a.mjs", "javascript:http.get", "http://a.example"),
            t("b.cjs", "javascript:http.get", "http://b.example"),
        ]
    );
}

#[test]
fn re_exports_and_probing_are_followed() {
    let r = scan(&[
        ("net.ts", "export { request } from \"node:https\";\n"),
        ("api/index.ts", "export { request as r } from \"../net\";\n"),
        ("util.ts", "export const U = \"https://u.example\";\n"),
        (
            "app.ts",
            "import { r } from \"./api\";\nimport { U } from \"./util.js\";\nimport \"./net\";\nexport const go = () => r(U);\n",
        ),
    ]);
    assert_eq!(
        sites(&r),
        vec![t("app.ts", "javascript:https.request", "https://u.example")]
    );
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

#[test]
fn declaration_only_targets_are_unresolved_for_values_and_inert_for_types() {
    let r = scan(&[
        (
            "types.d.ts",
            "export declare function ping(): void;\nexport interface T {}\n",
        ),
        ("a.ts", "import { ping } from \"./types\";\nping();\n"),
        (
            "b.ts",
            "import type { T } from \"./types\";\nexport const x: T | null = null;\n",
        ),
    ]);
    assert_eq!(spots(&r), vec![p("a.ts", "unresolved-module")]);
}

#[test]
fn covers_ae18_loaded_as_code_and_json_data() {
    let r = scan(&[
        (
            "app.js",
            "const p = require(\"./payload.dat\");\nconst c = require(\"./config.json\");\nmodule.exports = { p, c };\n",
        ),
        ("payload.dat", "module.exports = 1;\n"),
        ("config.json", "{}\n"),
    ]);
    assert_eq!(spots(&r), vec![p("payload.dat", "loaded-as-code")]);
}

#[test]
fn evasive_forms_yield_blind_spots_and_aliases_resolve() {
    let r = scan(&[(
        "a.cjs",
        r#"const g = globalThis;
function f(k, u, code, d) {
  g[k](u);
  g.fetch("https://g.example");
  top.fetch("https://t.example");
  eval(code);
  new Function("x");
  setTimeout("tick()", 10);
  (() => {}).constructor("return process")();
  Object.defineProperty(require("http"), "request", d);
  return this.fetch("https://this.example");
}
module.exports = { f };
"#,
    )]);
    let s = sites(&r);
    for d in [
        "https://g.example",
        "https://t.example",
        "https://this.example",
    ] {
        assert!(
            s.contains(&t("a.cjs", "javascript:globalThis.fetch", d)),
            "{d}: {s:?}"
        );
    }
    let kinds: Vec<String> = spots(&r).into_iter().map(|(_, k)| k).collect();
    for k in [
        "reflective-access",
        "dynamic-code",
        "dynamic-import",
        "introspection",
        "monkeypatch",
    ] {
        assert!(kinds.iter().any(|x| x == k), "{k}: {kinds:?}");
    }
}

#[test]
fn covers_ae11_minified_bundle_site_is_labeled() {
    let mut src = String::from("var a=[");
    for i in 0..400 {
        src.push_str(&format!("{i},"));
    }
    src.push_str("0];function t(){return fetch(\"https://api.example.com/t\")}\n");
    let r = scan(&[("dist/app.min.js", &src)]);
    assert_eq!(r.sites.len(), 1);
    assert!(
        r.sites[0].labels.iter().any(|l| l.as_str() == "minified"),
        "{:?}",
        r.sites[0].labels
    );
}

#[test]
fn deeply_nested_and_unparsable_files_are_whole_file_blind_spots() {
    let deep = format!("x = {}y;\n", "a ? b : ".repeat(100_000));
    let r = scan(&[
        ("deep.js", &deep),
        (
            "flow.js",
            "// @flow\nfunction f(x: number): string { return x; }\n",
        ),
        ("ok.js", "export const add = (a, b) => a + b;\n"),
    ]);
    assert_eq!(
        spots(&r),
        vec![
            p("deep.js", "too-deeply-nested"),
            p("flow.js", "parse-error")
        ]
    );
}

#[test]
fn cjs_whole_module_export_escapes_and_re_exports() {
    let r = scan(&[
        ("lib.js", "module.exports = require(\"https\");\n"),
        (
            "main.js",
            "const h = require(\"./lib\");\nh.get(\"https://x.example.com\");\nconst { request } = require(\"./lib\");\nrequest(\"https://y.example.com\");\n",
        ),
        (
            "esm.mjs",
            "import lib from \"./lib.js\";\nimport { get } from \"./lib.js\";\nlib.request(\"https://z.example.com\");\nget(\"https://w.example.com\");\n",
        ),
    ]);
    assert_eq!(
        sites(&r),
        vec![
            t("esm.mjs", "javascript:https.get", "https://w.example.com"),
            t(
                "esm.mjs",
                "javascript:https.request",
                "https://z.example.com"
            ),
            t("lib.js", "javascript:https", "expr:require(\"https\")"),
            t("main.js", "javascript:https.get", "https://x.example.com"),
            t(
                "main.js",
                "javascript:https.request",
                "https://y.example.com"
            ),
        ]
    );
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

#[test]
fn cjs_whole_module_export_of_a_bound_module_re_exports() {
    let r = scan(&[
        (
            "lib.js",
            "const https = require(\"https\");\nmodule.exports = https;\n",
        ),
        (
            "main.js",
            "const h = require(\"./lib\");\nh.get(\"https://x.example.com\");\n",
        ),
    ]);
    assert_eq!(
        sites(&r),
        vec![
            t("lib.js", "javascript:https", "expr:https"),
            t("main.js", "javascript:https.get", "https://x.example.com"),
        ]
    );
}

#[test]
fn cjs_named_exports_of_modules_escape_and_re_export() {
    let r = scan(&[
        (
            "lib.js",
            "exports.x = require(\"net\");\nmodule.exports.y = require(\"tls\");\n",
        ),
        (
            "main.js",
            "const h = require(\"./lib\");\nh.x.connect(80, \"a.example.com\");\nconst { y } = require(\"./lib\");\ny.connect(443, \"b.example.com\");\n",
        ),
    ]);
    assert_eq!(
        sites(&r),
        vec![
            t("lib.js", "javascript:net", "expr:require(\"net\")"),
            t("lib.js", "javascript:tls", "expr:require(\"tls\")"),
            t("main.js", "javascript:net.connect", "a.example.com:80"),
            t("main.js", "javascript:tls.connect", "b.example.com:443"),
        ]
    );
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

#[test]
fn cjs_object_exports_re_export_members_and_modules() {
    let r = scan(&[
        (
            "lib.js",
            "const https = require(\"https\");\nmodule.exports = { get: https.get, net: require(\"net\"), https };\n",
        ),
        (
            "main.js",
            "const h = require(\"./lib\");\nh.get(\"https://x.example.com\");\nh.net.connect(80, \"a.example.com\");\nh.https.request(\"https://y.example.com\");\n",
        ),
    ]);
    assert_eq!(
        sites(&r),
        vec![
            t("lib.js", "javascript:https", "expr:https"),
            t("lib.js", "javascript:https.get", "expr:https.get"),
            t("lib.js", "javascript:net", "expr:require(\"net\")"),
            t("main.js", "javascript:https.get", "https://x.example.com"),
            t(
                "main.js",
                "javascript:https.request",
                "https://y.example.com"
            ),
            t("main.js", "javascript:net.connect", "a.example.com:80"),
        ]
    );
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

#[test]
fn cjs_object_assign_of_a_module_escapes() {
    let r = scan(&[(
        "lib.js",
        "Object.assign(module.exports, require(\"https\"));\n",
    )]);
    assert!(
        sites(&r).contains(&t("lib.js", "javascript:https", "expr:require(\"https\")")),
        "{:?}",
        sites(&r)
    );
}

#[test]
fn a_literal_require_passed_as_a_value_escapes() {
    let r = scan(&[("lib.js", "register(require(\"child_process\"));\n")]);
    assert_eq!(
        sites(&r),
        vec![t(
            "lib.js",
            "javascript:child_process",
            "expr:require(\"child_process\")"
        )]
    );
}

#[test]
fn must_not_cjs_exports_of_inert_or_first_party_modules() {
    let r = scan(&[
        (
            "lib.js",
            "module.exports = require(\"path\");\nexports.u = require(\"./util\");\nexports.c = require(\"./config.json\");\nrequire(\"https\");\n",
        ),
        ("util.js", "exports.join = (a, b) => a + b;\n"),
        ("config.json", "{}\n"),
        (
            "main.js",
            "const h = require(\"./lib\");\nh.join(\"a\", \"b\");\nh.u.join(\"a\", \"b\");\n",
        ),
    ]);
    assert!(r.sites.is_empty(), "{:?}", sites(&r));
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

#[test]
fn literal_dynamic_imports_outside_an_await_declarator_are_not_silent() {
    // A `.then` receiver and a returned import: the module value escapes.
    for (path, src) in [
        (
            "a.mjs",
            "import(\"child_process\").then(cp => cp.exec(\"x\"));\n",
        ),
        (
            "a.js",
            "export function f() { return import(\"child_process\"); }\n",
        ),
        (
            "a.js",
            "export async function f() { let cp; cp = await import(\"child_process\"); cp.exec(\"x\"); }\n",
        ),
    ] {
        let r = scan(&[(path, src)]);
        assert!(
            sites(&r)
                .iter()
                .any(|(_, m, _)| m.starts_with("javascript:child_process")),
            "{src}: {:?} {:?}",
            sites(&r),
            r.blind_spots
        );
    }
    // A member call on an awaited import resolves to the member.
    let r = scan(&[(
        "a.js",
        "export async function f() { return (await import(\"child_process\")).exec(\"x\"); }\n",
    )]);
    assert!(
        sites(&r)
            .iter()
            .any(|(_, m, _)| m == "javascript:child_process.exec"),
        "{:?} {:?}",
        sites(&r),
        r.blind_spots
    );
    // A member of an awaited import re-exported and called elsewhere.
    let r = scan(&[
        (
            "lib.mjs",
            "export const exec = (await import(\"child_process\")).exec;\n",
        ),
        (
            "main.mjs",
            "import { exec } from \"./lib.mjs\";\nexec(\"x\");\n",
        ),
    ]);
    assert!(
        sites(&r)
            .iter()
            .any(|(_, m, _)| m == "javascript:child_process.exec"),
        "{:?} {:?}",
        sites(&r),
        r.blind_spots
    );
}

#[test]
fn must_not_discarded_or_inert_dynamic_imports() {
    let r = scan(&[
        (
            "a.mjs",
            "import(\"child_process\");\nawait import(\"./side.mjs\");\nimport(\"path\").then(p => p.join(\"a\", \"b\"));\n",
        ),
        ("side.mjs", "export const x = 1;\n"),
    ]);
    assert!(r.sites.is_empty(), "{:?}", sites(&r));
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

#[test]
fn require_through_wrapped_callees_is_a_loader() {
    for src in [
        "(0, require)(\"child_process\").exec(\"x\");\n",
        "require.call(null, \"child_process\").exec(\"x\");\n",
        "require.apply(null, [\"child_process\"]).exec(\"x\");\n",
        "(true && require)(\"child_process\").exec(\"x\");\n",
        "(c ? require : null)(\"child_process\").exec(\"x\");\n",
        "const cp = (0, require)(\"child_process\");\ncp.exec(\"x\");\n",
    ] {
        let r = scan(&[("a.cjs", src)]);
        assert_eq!(
            sites(&r).into_iter().map(|(_, m, _)| m).collect::<Vec<_>>(),
            vec!["javascript:child_process.exec".to_string()],
            "{src}: {:?}",
            r.blind_spots
        );
    }
    // A non-literal or unreadable specifier through the same shapes, and a
    // bound `require`, are dynamic-import blind spots.
    for src in [
        "(0, require)(m);\n",
        "require.call(null, m);\n",
        "require.apply(null, args);\n",
        "require.bind(null)(\"child_process\");\n",
        "(c || require)(m);\n",
    ] {
        let r = scan(&[("a.cjs", src)]);
        assert_eq!(spots(&r), vec![p("a.cjs", "dynamic-import")], "{src}");
    }
}

#[test]
fn must_not_ordinary_require_member_reads() {
    let r = scan(&[(
        "a.cjs",
        "if (typeof require !== \"undefined\" && require.main === module) {}\nconst p = require.resolve(\"./a.cjs\");\nconst c = require.cache;\n",
    )]);
    assert!(r.sites.is_empty(), "{:?}", sites(&r));
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

#[test]
fn require_through_computed_call_apply_bind_is_a_loader() {
    for (file, src) in [
        (
            "a.cjs",
            "require[\"call\"](null, \"child_process\").exec(\"x\");\n",
        ),
        (
            "a.cjs",
            "require['apply'](null, [\"child_process\"]).exec(\"x\");\n",
        ),
        (
            "a.cjs",
            "require[`call`](null, \"child_process\").exec(\"x\");\n",
        ),
        (
            "a.cjs",
            "require.call[\"call\"](null, null, \"child_process\").exec(\"x\");\n",
        ),
        (
            "a.cjs",
            "require[\"call\"].call(null, null, \"child_process\").exec(\"x\");\n",
        ),
        (
            "a.mjs",
            "import { createRequire } from \"node:module\";\nconst r = createRequire(import.meta.url);\nr[\"call\"](null, \"child_process\").exec(\"x\");\n",
        ),
        (
            "a.mjs",
            "import { createRequire } from \"node:module\";\nconst r = createRequire(import.meta.url);\nr[\"apply\"](null, [\"child_process\"]).exec(\"x\");\n",
        ),
    ] {
        let r = scan(&[(file, src)]);
        assert_eq!(
            sites(&r).into_iter().map(|(_, m, _)| m).collect::<Vec<_>>(),
            vec!["javascript:child_process.exec".to_string()],
            "{src}: {:?}",
            r.blind_spots
        );
    }
    // Bound, non-literal, or unknown-key computed loader callees fail closed.
    for (file, src) in [
        ("a.cjs", "require[\"bind\"](null)(\"child_process\");\n"),
        ("a.cjs", "require[`bind`](null)(\"child_process\");\n"),
        ("a.cjs", "require[\"call\"](null, m);\n"),
        ("a.cjs", "require[\"apply\"](null, args);\n"),
        ("a.cjs", "require[k](null, \"child_process\");\n"),
        ("a.cjs", "require.call[k](null, null, \"child_process\");\n"),
        (
            "a.mjs",
            "import { createRequire } from \"node:module\";\nconst r = createRequire(import.meta.url);\nr[\"bind\"](null)(\"child_process\");\n",
        ),
        (
            "a.mjs",
            "import { createRequire } from \"node:module\";\nconst r = createRequire(import.meta.url);\nr[k](null, \"child_process\");\n",
        ),
    ] {
        let r = scan(&[(file, src)]);
        assert!(r.sites.is_empty(), "{src}: {:?}", sites(&r));
        assert!(
            r.blind_spots
                .iter()
                .any(|b| b.kind.as_str() == "dynamic-import"),
            "{src}: {:?}",
            r.blind_spots
        );
    }
    // The bracketed method read as a value is a loader too.
    let r = scan(&[(
        "a.cjs",
        "const f = require[\"call\"];\nmodule.exports = f;\n",
    )]);
    assert!(
        r.blind_spots
            .iter()
            .any(|b| b.kind.as_str() == "dynamic-import"),
        "{:?}",
        r.blind_spots
    );
}

#[test]
fn must_not_computed_ordinary_require_member_reads() {
    let r = scan(&[(
        "a.cjs",
        "if (typeof require !== \"undefined\") {}\nconst p = require[\"resolve\"](\"./a.cjs\");\nconst c = require[\"cache\"];\nconst q = require[`resolve`](\"./a.cjs\");\nconst m = require[\"main\"] === module;\n",
    )]);
    assert!(r.sites.is_empty(), "{:?}", sites(&r));
    assert!(r.blind_spots.is_empty(), "{:?}", r.blind_spots);
}

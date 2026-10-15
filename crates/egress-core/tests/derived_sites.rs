//! The derived-site pass (R10-R14, KTD7-KTD10): callers of a first-party
//! wrapper function get derived sites that carry the caller's concrete or
//! symbolic destination and a `via` chain back to the inner `param:` site.

mod classify_support;

use classify_support::*;
use egress_core::classify::Classified;
use egress_core::ir::UseKind::*;
use egress_core::ir::{Expr, Span, SymbolKind, SymbolSpan};
use egress_core::model::DerivedCut;

/// `api.py`: `post_json(url, body)` wraps `requests.post(url, ...)`; three
/// callers pass a literal, an environment read, and a computed argument.
fn three_callers() -> Fx {
    fx().file(
        "api.py",
        py().import(import_module("os"))
            .import(import_module("requests"))
            .sym(func("post_json", &["url", "body"]))
            .r(r(
                imp("requests"),
                &["post"],
                Call,
                "requests.post(url, json=body)",
            )
            .sym("post_json")
            .arg(Expr::Param(1))
            .kwarg("json", Expr::Param(2)))
            .r(r(
                local("post_json"),
                &[],
                Call,
                "post_json(\"https://hook.invalid\", u)",
            )
            .sym("send_hook")
            .arg(lit("https://hook.invalid"))
            .arg(name("u")))
            .r(r(
                local("post_json"),
                &[],
                Call,
                "post_json(os.environ[\"HOOK\"], x)",
            )
            .sym("send_env")
            .arg(subscript(
                r(imp("os"), &["environ"], ValueEscape, "os.environ").expr(),
                lit("HOOK"),
            ))
            .arg(name("x")))
            .r(
                r(local("post_json"), &[], Call, "post_json(build_url(), y)")
                    .sym("send_computed")
                    .arg(r(local("build_url"), &[], Call, "build_url()").expr())
                    .arg(name("y")),
            ),
    )
}

/// The sites carrying a `via`, as `(symbol, destination, argument)`.
fn derived(c: &Classified) -> Vec<(String, String, u32)> {
    let mut v: Vec<_> = c
        .sites
        .iter()
        .filter(|s| s.via.is_some())
        .map(|s| {
            (
                s.symbol.clone(),
                s.destination.display.clone(),
                s.via.as_ref().unwrap().argument,
            )
        })
        .collect();
    v.sort();
    v
}

/// A wrapper chain: `inner` holds the egress call on its own parameter, and
/// each `outer` forwards its own parameter one hop out.
fn chain(names: &[&str], outer_callers: Vec<R>) -> Ir {
    let mut ir = py()
        .import(import_module("requests"))
        .sym(func(names[0], &["url"]))
        .r(r(imp("requests"), &["post"], Call, "requests.post(url)")
            .sym(names[0])
            .arg(Expr::Param(1)));
    for (i, n) in names.iter().enumerate().skip(1) {
        ir = ir.sym(func(n, &["url"])).r(r(
            local(names[i - 1]),
            &[],
            Call,
            &format!("{}(url)", names[i - 1]),
        )
        .sym(n)
        .arg(Expr::Param(1)));
    }
    for c in outer_callers {
        ir = ir.r(c);
    }
    ir
}

#[test]
fn three_callers_get_derived_sites_naming_the_inner_site() {
    let c = three_callers().run();
    let inner = c
        .sites
        .iter()
        .find(|s| s.via.is_none())
        .expect("one direct site");
    assert_eq!(inner.destination.display, "param:1:post_json");
    assert_eq!(
        derived(&c),
        vec![
            (s("send_computed"), s("expr:build_url()"), 1),
            (s("send_env"), s("env:HOOK"), 1),
            (s("send_hook"), s("https://hook.invalid"), 1),
        ]
    );
    for s in c.sites.iter().filter(|s| s.via.is_some()) {
        let v = s.via.as_ref().unwrap();
        assert_eq!(v.inner_site, inner.id);
        assert_eq!(v.chain.len(), 1);
        assert_eq!(v.chain[0].symbol, "post_json");
        assert_eq!(v.chain[0].file, "api.py");
        assert_eq!(v.cut, None);
        assert_eq!(s.mechanism, inner.mechanism);
        assert_eq!(s.bucket, inner.bucket);
    }
}

#[test]
fn a_wrapper_chain_derives_for_the_outer_caller() {
    let c = fx()
        .file(
            "api.py",
            chain(
                &["w0", "w1"],
                vec![
                    r(local("w1"), &[], Call, "w1(\"https://x.invalid\")")
                        .sym("outside")
                        .arg(lit("https://x.invalid")),
                ],
            ),
        )
        .run();
    assert_eq!(derived(&c), vec![(s("outside"), s("https://x.invalid"), 1)]);
    let v = c
        .sites
        .iter()
        .find(|s| s.via.is_some())
        .unwrap()
        .via
        .as_ref()
        .unwrap();
    assert_eq!(
        v.chain
            .iter()
            .map(|h| h.symbol.as_str())
            .collect::<Vec<_>>(),
        vec!["w1", "w0"]
    );
}

#[test]
fn a_caller_passing_its_own_parameter_yields_no_derived_site_without_callers() {
    let c = fx().file("api.py", chain(&["w0", "w1"], vec![])).run();
    // `w1` is a wrapper for the next hop, but nobody calls it: the inner
    // `param:` site already names that coverage (KTD7).
    assert_eq!(derived(&c), Vec::<(String, String, u32)>::new());
    assert_eq!(sites(&c).len(), 1);
}

#[test]
fn the_hop_limit_cuts_the_deepest_reached_caller() {
    // w0 wraps the egress call; w1..w4 forward a parameter. With the hop
    // limit at 3 the walk reaches `w3`, whose own `param:` destination and
    // the `hop-limit` reason land on a derived site; the caller beyond the
    // cut gets nothing.
    let mut d = data().clone();
    d.wrappers.hop_limit = 3;
    let c = fx()
        .file(
            "api.py",
            chain(
                &["w0", "w1", "w2", "w3", "w4"],
                vec![
                    r(local("w4"), &[], Call, "w4(\"https://x.invalid\")")
                        .sym("outside")
                        .arg(lit("https://x.invalid")),
                ],
            ),
        )
        .run_with(&d, u64::MAX);
    assert_eq!(derived(&c), vec![(s("w3"), s("param:1:w3"), 1)]);
    let s = c.sites.iter().find(|s| s.via.is_some()).unwrap();
    let v = s.via.as_ref().unwrap();
    assert_eq!(v.cut, Some(DerivedCut::HopLimit));
    assert_eq!(v.chain.len(), 3);
    assert_eq!(
        v.chain
            .iter()
            .map(|h| h.symbol.as_str())
            .collect::<Vec<_>>(),
        vec!["w2", "w1", "w0"]
    );
    // `w4` and `outside` sit past the cut and get no derived site.
    assert!(c.blind_spots.is_empty());
    assert!(!c.resolver_budget_exceeded);
}

#[test]
fn mutual_recursion_cuts_with_a_recursion_reason() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("a", &["url"]))
                .sym(func("b", &["url", "seen"]))
                .r(r(imp("requests"), &["post"], Call, "requests.post(url)")
                    .sym("b")
                    .arg(Expr::Param(1)))
                .r(r(local("b"), &[], Call, "b(url)")
                    .sym("a")
                    .arg(Expr::Param(1)))
                .r(r(local("a"), &[], Call, "a(url)")
                    .sym("b")
                    .arg(Expr::Param(1)))
                .r(r(local("a"), &[], Call, "a(\"https://x.invalid\")")
                    .sym("outside")
                    .arg(lit("https://x.invalid"))),
        )
        .run();
    assert_eq!(
        derived(&c),
        vec![
            (s("b"), s("param:1:b"), 1),
            (s("outside"), s("https://x.invalid"), 1),
        ]
    );
    let s = c
        .sites
        .iter()
        .find(|s| s.via.is_some() && s.symbol == "b")
        .unwrap();
    let v = s.via.as_ref().unwrap();
    assert_eq!(v.cut, Some(DerivedCut::Recursion));
    assert_eq!(
        v.chain
            .iter()
            .map(|h| h.symbol.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b"]
    );
}

#[test]
fn a_python_kwarg_maps_by_parameter_name() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2)))
                .r(r(
                    local("post_json"),
                    &[],
                    Call,
                    "post_json(url=\"https://k.invalid\", body=b)",
                )
                .sym("caller")
                .kwarg("url", lit("https://k.invalid"))
                .kwarg("body", name("b"))),
        )
        .run();
    assert_eq!(derived(&c), vec![(s("caller"), s("https://k.invalid"), 1)]);
}

#[test]
fn a_spread_at_or_before_the_parameter_position_yields_expr() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2)))
                .r(r(local("post_json"), &[], Call, "post_json(*args, b)")
                    .sym("caller")
                    .arg(opaque("*args"))
                    .arg(name("b"))),
        )
        .run();
    assert_eq!(derived(&c), vec![(s("caller"), s("expr:*args"), 1)]);
}

#[test]
fn an_omitted_argument_uses_a_literal_default_from_the_wrapper() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(SymbolSpan {
                    path: "post_json".into(),
                    kind: SymbolKind::Function,
                    params: vec!["url".into(), "body".into()],
                    defaults: [(1, lit("https://d.invalid"))].into_iter().collect(),
                    strict: None,
                    span: Span { start: 0, end: 1 },
                })
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2)))
                .r(r(local("post_json"), &[], Call, "post_json(body=b)")
                    .sym("caller")
                    .kwarg("body", name("b"))),
        )
        .run();
    assert_eq!(derived(&c), vec![(s("caller"), s("https://d.invalid"), 1)]);
}

#[test]
fn an_omitted_argument_without_a_default_keeps_the_wrapper_param() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2)))
                .r(r(local("post_json"), &[], Call, "post_json(body=b)")
                    .sym("caller")
                    .kwarg("body", name("b"))),
        )
        .run();
    assert_eq!(derived(&c), vec![(s("caller"), s("param:1:post_json"), 1)]);
}

#[test]
fn a_token_prefixed_secret_in_a_caller_argument_is_redacted() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2)))
                .r(r(
                    local("post_json"),
                    &[],
                    Call,
                    "post_json(\"https://h.invalid/?t=ghp_abc012DEF345ghi678JKL901mno234PQR5\", b)",
                )
                .sym("caller")
                .arg(lit(
                    "https://h.invalid/?t=ghp_abc012DEF345ghi678JKL901mno234PQR5",
                ))
                .arg(name("b"))),
        )
        .run();
    assert_eq!(derived(&c).len(), 1);
    let (_, dest, _) = &derived(&c)[0];
    assert!(dest.contains("<redacted>"), "{dest}");
    assert!(!dest.contains("ghp_"), "{dest}");
}

#[test]
fn an_unprefixed_high_entropy_literal_inside_an_expression_is_redacted() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2)))
                .r(r(
                    local("post_json"),
                    &[],
                    Call,
                    "post_json(\"x\" + \"aBcDeFgH0123iJkLmNoP4567qRsTuVwX\", b)",
                )
                .sym("caller")
                .arg(opaque("\"x\" + \"aBcDeFgH0123iJkLmNoP4567qRsTuVwX\""))
                .arg(name("b"))),
        )
        .run();
    assert_eq!(derived(&c).len(), 1);
    let (_, dest, _) = &derived(&c)[0];
    assert!(dest.starts_with("expr:"), "{dest}");
    assert!(dest.contains("<redacted>"), "{dest}");
    assert!(!dest.contains("aBcDeFgH0123"), "{dest}");
}

#[test]
fn a_diamond_keeps_the_shortest_then_byte_wise_smallest_chain() {
    // `wa` and `wb` both wrap `w0`; `caller` calls both with a literal.
    // The chains tie on length, so the byte-wise smaller hop name wins.
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("w0", &["url"]))
                .r(r(imp("requests"), &["post"], Call, "requests.post(url)")
                    .sym("w0")
                    .arg(Expr::Param(1)))
                .sym(func("wa", &["url"]))
                .r(r(local("w0"), &[], Call, "w0(url)")
                    .sym("wa")
                    .arg(Expr::Param(1)))
                .sym(func("wb", &["url"]))
                .r(r(local("w0"), &[], Call, "w0(url)")
                    .sym("wb")
                    .arg(Expr::Param(1)))
                .r(r(local("wb"), &[], Call, "wb(\"https://x.invalid\")")
                    .sym("caller")
                    .arg(lit("https://x.invalid")))
                .r(r(local("wa"), &[], Call, "wa(\"https://x.invalid\")")
                    .sym("caller")
                    .arg(lit("https://x.invalid"))),
        )
        .run();
    assert_eq!(derived(&c), vec![(s("caller"), s("https://x.invalid"), 1)]);
    let v = c
        .sites
        .iter()
        .find(|s| s.via.is_some())
        .unwrap()
        .via
        .as_ref()
        .unwrap();
    assert_eq!(
        v.chain
            .iter()
            .map(|h| h.symbol.as_str())
            .collect::<Vec<_>>(),
        vec!["wa", "w0"]
    );
}

#[test]
fn a_wrapper_passed_as_a_value_or_through_partial_produces_no_derived_site() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("functools"))
                .import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2)))
                // `functools.partial(post_json, "https://x.invalid")`: the
                // callee is `partial`; `post_json` is only a value.
                .r(r(local("post_json"), &[], ValueEscape, "post_json").sym("make"))
                .r(r(
                    imp("functools"),
                    &["partial"],
                    Call,
                    "functools.partial(post_json, \"https://x.invalid\")",
                )
                .sym("make")
                .arg(r(local("post_json"), &[], ValueEscape, "post_json").expr())
                .arg(lit("https://x.invalid"))),
        )
        .run();
    assert_eq!(derived(&c), Vec::<(String, String, u32)>::new());
    assert_eq!(sites(&c).len(), 1);
}

#[test]
fn a_js_bind_call_produces_no_derived_site() {
    let c = fx()
        .file(
            "app.js",
            js().sym(func("postJson", &["url", "body"]))
                .r(r(amb("fetch"), &[], Call, "fetch(url)")
                    .sym("postJson")
                    .arg(Expr::Param(1)))
                .r(r(
                    local("postJson"),
                    &["bind"],
                    Call,
                    "postJson.bind(null, \"https://x.invalid\")",
                )
                .sym("caller")
                .arg(name("null"))
                .arg(lit("https://x.invalid"))),
        )
        .run();
    assert_eq!(derived(&c), Vec::<(String, String, u32)>::new());
    assert_eq!(sites(&c).len(), 1);
}

#[test]
fn a_method_call_that_does_not_resolve_to_a_first_party_def_derives_nothing() {
    // `Client.fetch` wraps `requests.get` on its `path` parameter, but
    // `c.fetch(u)` resolves `c` to a local instance, never to `Client`:
    // the resolver returns no `FirstPartyDef`, so no derived site (KTD7).
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("Client.fetch", &["path"]))
                .r(r(imp("requests"), &["get"], Call, "requests.get(path)")
                    .sym("Client.fetch")
                    .arg(Expr::Param(1)))
                .r(r(
                    local("c"),
                    &["fetch"],
                    Call,
                    "c.fetch(\"https://x.invalid\")",
                )
                .sym("caller")
                .arg(lit("https://x.invalid"))),
        )
        .run();
    assert_eq!(derived(&c), Vec::<(String, String, u32)>::new());
    assert_eq!(sites(&c).len(), 1);
}

#[test]
fn a_wrapper_in_another_first_party_file_derives_across_the_import() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2))),
        )
        .file(
            "cli.py",
            py().import(import(Some("post_json"), "api", &["post_json"]))
                .r(r(
                    imp("post_json"),
                    &[],
                    Call,
                    "post_json(\"https://x.invalid\", b)",
                )
                .sym("run")
                .arg(lit("https://x.invalid"))
                .arg(name("b"))),
        )
        .run();
    assert_eq!(derived(&c), vec![(s("run"), s("https://x.invalid"), 1)]);
    let v = c
        .sites
        .iter()
        .find(|s| s.via.is_some())
        .unwrap()
        .via
        .as_ref()
        .unwrap();
    assert_eq!(v.chain.len(), 1);
    assert_eq!(v.chain[0].file, "api.py");
    assert_eq!(v.chain[0].symbol, "post_json");
    let s = c.sites.iter().find(|s| s.via.is_some()).unwrap();
    assert_eq!(s.file, "cli.py");
}

#[test]
fn an_exported_wrapper_with_no_caller_produces_only_the_inner_site() {
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests"))
                .sym(func("post_json", &["url", "body"]))
                .r(r(
                    imp("requests"),
                    &["post"],
                    Call,
                    "requests.post(url, json=body)",
                )
                .sym("post_json")
                .arg(Expr::Param(1))
                .kwarg("json", Expr::Param(2))),
        )
        .file(
            "cli.py",
            py().import(import(Some("post_json"), "api", &["post_json"])),
        )
        .run();
    assert_eq!(derived(&c), Vec::<(String, String, u32)>::new());
    assert_eq!(sites(&c).len(), 1);
}

#[test]
fn a_resolver_budget_cut_inside_the_pass_marks_resolution_limit() {
    let f = three_callers();
    let full = f.run();
    // A budget one step short of the full run exhausts inside the pass:
    // the last followed hop either lands its edge as a `resolution-limit`
    // blind spot or degrades the argument eval, and not every caller
    // gets a derived site.
    let c = f.run_with(data(), full.resolver_steps - 1);
    assert!(c.resolver_budget_exceeded);
    assert!(derived(&c).len() < 3);
}

#[test]
fn direct_sites_and_their_ids_do_not_change() {
    // The classify-time phase-1 finalize runs before the pass, so the
    // inner `param:` site keeps the id it had without the pass.
    let a = three_callers().run();
    let b = three_callers().run();
    let inner_a = a.sites.iter().find(|s| s.via.is_none()).unwrap();
    let inner_b = b.sites.iter().find(|s| s.via.is_none()).unwrap();
    assert_eq!(inner_a.id, inner_b.id);
    assert!(!inner_a.id.is_empty());
    // Determinism across runs extends to the derived sites' provenance
    // (fixture locations are counter-based, so compare without them).
    let project = |c: &Classified| -> Vec<String> {
        let mut v: Vec<_> = c
            .sites
            .iter()
            .filter(|s| s.via.is_some())
            .map(|s| {
                let v = s.via.as_ref().unwrap();
                format!(
                    "{} {} arg{} {} {}",
                    s.symbol,
                    s.destination.display,
                    v.argument,
                    v.cut.map(|c| c.as_str()).unwrap_or("-"),
                    v.chain
                        .iter()
                        .map(|h| h.symbol.as_str())
                        .collect::<Vec<_>>()
                        .join(">")
                )
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(project(&a), project(&b));
}

//! Module index, alias resolution, budgets, and specifier targets on
//! hand-built IR.

mod classify_support;

use std::collections::{BTreeMap, BTreeSet};

use classify_support::*;
use egress_core::discover::FileKind;
use egress_core::ir::UseKind::*;
use egress_core::model::Language;
use egress_core::resolve::{
    Binding, GenericRules, PER_REFERENCE_STEPS, Program, Resolver, SpecifierKind, SpecifierRules,
    Target, package_name,
};

#[test]
fn generic_rules_probe_in_fixed_order_and_refuse_outside_root() {
    let g = GenericRules {
        extensions: vec![".ts".into(), ".js".into()],
        index_names: vec!["index".into()],
    };
    assert_eq!(
        g.classify(b"src/a.ts", "./b"),
        SpecifierKind::Path {
            probes: vec![
                b"src/b".to_vec(),
                b"src/b.ts".to_vec(),
                b"src/b.js".to_vec(),
                b"src/b/index.ts".to_vec(),
                b"src/b/index.js".to_vec(),
            ]
        }
    );
    assert_eq!(g.classify(b"a.js", "../../x"), SpecifierKind::OutsideRoot);
    assert_eq!(
        g.classify(b"a.js", "/opt/payload/net"),
        SpecifierKind::OutsideRoot
    );
    assert_eq!(
        g.classify(b"a.js", "axios"),
        SpecifierKind::Bare {
            probes: vec![],
            module: "axios".into()
        }
    );
}

#[test]
fn package_names_follow_the_import_root() {
    assert_eq!(package_name(Language::Python, "yaml.loader"), "yaml");
    assert_eq!(package_name(Language::Javascript, "lodash/fp"), "lodash");
    assert_eq!(
        package_name(Language::Javascript, "@acme/widgets/x"),
        "@acme/widgets"
    );
    assert_eq!(package_name(Language::Javascript, "node:fs"), "fs");
    assert_eq!(package_name(Language::Rust, "serde::de"), "serde");
}

#[test]
fn three_hop_first_party_re_export_chain_resolves_to_the_primitive() {
    let c = fx()
        .file(
            "net/a.py",
            py().import(import(
                Some("create_connection"),
                "socket",
                &["create_connection"],
            )),
        )
        .file(
            "net/b.py",
            py().import(import(
                Some("create_connection"),
                ".a",
                &["create_connection"],
            )),
        )
        .file(
            "net/__init__.py",
            py().import(import(Some("connect"), ".b", &["create_connection"])),
        )
        .file(
            "app.py",
            py().import(import(Some("connect"), "net", &["connect"]))
                .r(r(imp("connect"), &[], Call, "connect((\"h\", 80))")
                    .sym("main")
                    .arg(seq(vec![lit("h"), lit("80")]))),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![(
            s("app.py"),
            s("main"),
            s("python:socket.create_connection"),
            s("h:80")
        )]
    );
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
}

#[test]
fn js_re_export_requires_the_export_flag() {
    let exported = fx()
        .file(
            "lib.js",
            js().import(re_export(import(Some("connect"), "net", &["connect"]))),
        )
        .file(
            "app.js",
            js().import(import(Some("c"), "./lib", &["connect"])).r(r(
                imp("c"),
                &[],
                Call,
                "c(80, \"h\")",
            )
            .arg(lit("80"))
            .arg(lit("h"))),
        )
        .run();
    assert_eq!(
        mechs(&exported),
        vec![pair("javascript:net.connect", "h:80")]
    );

    // Not exported: the importer's name is first-party and not a site.
    let private = fx()
        .file(
            "lib.js",
            js().import(import(Some("connect"), "net", &["connect"])),
        )
        .file(
            "app.js",
            js().import(import(Some("c"), "./lib", &["connect"])).r(r(
                imp("c"),
                &[],
                Call,
                "c(80, \"h\")",
            )),
        )
        .run();
    assert!(private.sites.is_empty(), "{:?}", private.sites);
}

#[test]
fn first_party_star_import_expands_from_source() {
    // A name a star import brings in reaches the core either as an import
    // root with no binding import or as an ambient name; both expand from
    // the starred module's source.
    for root in [imp("system"), amb("system")] {
        let c = fx()
            .file(
                "util.py",
                py().import(import(Some("system"), "os", &["system"])),
            )
            .file(
                "app.py",
                py().import(star("util"))
                    .r(r(root, &[], Call, "system(\"curl x\")").arg(lit("curl x"))),
            )
            .run();
        assert_eq!(mechs(&c), vec![pair("python:os.system", "exec:curl")]);
        assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    }
}

#[test]
fn name_through_a_first_party_star_re_export_resolves() {
    let c = fx()
        .file(
            "inner.js",
            js().import(re_export(import(Some("connect"), "net", &["connect"]))),
        )
        .file("mid.js", js().import(re_export(star("./inner"))))
        .file(
            "app.js",
            js().import(import(Some("connect"), "./mid", &["connect"]))
                .r(r(imp("connect"), &[], Call, "connect(80, \"h\")")
                    .arg(lit("80"))
                    .arg(lit("h"))),
        )
        .run();
    assert_eq!(mechs(&c), vec![pair("javascript:net.connect", "h:80")]);
}

#[test]
fn two_file_export_star_cycle_terminates() {
    let c = fx()
        .file("a.js", js().import(re_export(star("./b"))))
        .file("b.js", js().import(re_export(star("./a"))))
        .file(
            "app.js",
            js().import(import(Some("x"), "./a", &["x"]))
                .r(r(imp("x"), &[], Call, "x()")),
        )
        .run();
    assert!(c.sites.is_empty());
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
}

/// A diamond of `levels` levels: `l{i}a` and `l{i}b` each star-re-export
/// both `l{i+1}a` and `l{i+1}b`; the bottom pair re-exports `net.connect`.
fn diamond(levels: usize) -> Fx {
    let mut f = fx();
    for i in 0..levels {
        for side in ["a", "b"] {
            let path = format!("l{i}{side}.js");
            let ir = if i + 1 == levels {
                js().import(re_export(import(Some("connect"), "net", &["connect"])))
            } else {
                js().import(re_export(star(&format!("./l{}a", i + 1))))
                    .import(re_export(star(&format!("./l{}b", i + 1))))
            };
            f = f.file(&path, ir);
        }
    }
    // `ghost` is defined nowhere, so finding that out searches the whole
    // diamond: linear with memoization, exponential without it.
    f.file(
        "app.js",
        js().import(import(Some("connect"), "./l0a", &["connect"]))
            .import(import(Some("ghost"), "./l0a", &["ghost"]))
            .r(r(imp("connect"), &[], Call, "connect(80, \"h\")")
                .arg(lit("80"))
                .arg(lit("h")))
            .r(r(imp("ghost"), &[], Call, "ghost()")),
    )
}

#[test]
fn thirty_level_diamond_resolves_with_linear_steps() {
    let c = diamond(30).run();
    assert_eq!(mechs(&c), vec![pair("javascript:net.connect", "h:80")]);
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    // 60 modules and 116 star edges; exponential work would be about 2^30.
    assert!(c.resolver_steps < 2_000, "steps {}", c.resolver_steps);
    let small = diamond(15).run().resolver_steps;
    let large = c.resolver_steps;
    assert!(
        large <= 2 * small + 50,
        "steps grow superlinearly: {small} then {large}"
    );
}

#[test]
fn chain_longer_than_the_step_budget_is_resolution_limit_never_inert() {
    let n = PER_REFERENCE_STEPS as usize + 10;
    let mut f = fx().file(
        "m0.py",
        py().import(import(Some("connect"), "socket", &["create_connection"])),
    );
    for i in 1..n {
        f = f.file(
            &format!("m{i}.py"),
            py().import(import(
                Some("connect"),
                &format!("m{}", i - 1),
                &["connect"],
            )),
        );
    }
    let f = f.file(
        "app.py",
        py().import(import(
            Some("connect"),
            &format!("m{}", n - 1),
            &["connect"],
        ))
        .r(r(imp("connect"), &[], Call, "connect(a)")),
    );
    let c = f.run();
    let limits: Vec<_> = c
        .blind_spots
        .iter()
        .filter(|b| b.kind.as_str() == "resolution-limit")
        .map(|b| b.file.clone())
        .collect();
    assert!(limits.contains(&s("app.py")), "{:?}", c.blind_spots);
    assert!(!c.resolver_budget_exceeded);
}

fn budget_fixture() -> Fx {
    let mut f = fx();
    for i in 0..6 {
        f = f.file(
            &format!("f{i}.py"),
            py().import(import_module("requests")).r(r(
                imp("requests"),
                &["get"],
                Call,
                "requests.get(\"https://x.example\")",
            )
            .arg(lit("https://x.example"))),
        );
    }
    f
}

#[test]
fn reduced_global_budget_turns_the_remaining_references_into_resolution_limits() {
    let full = budget_fixture().run();
    assert_eq!(full.sites.len(), 6);
    assert!(!full.resolver_budget_exceeded);
    let needed = full.resolver_steps;

    let budget = needed / 2;
    let f = budget_fixture();
    let a = f.run_with(data(), budget);
    let b = f.run_with(data(), budget);
    assert!(a.resolver_budget_exceeded);
    assert!(a.resolver_steps <= budget);
    let limits: Vec<_> = a
        .blind_spots
        .iter()
        .filter(|x| x.kind.as_str() == "resolution-limit")
        .map(|x| x.file.clone())
        .collect();
    assert!(!limits.is_empty());
    // References are charged in sorted order: the early files resolved, the
    // late ones did not.
    let resolved: Vec<_> = a.sites.iter().map(|x| x.file.clone()).collect();
    assert!(
        resolved.iter().all(|f| limits.iter().all(|l| f < l)),
        "{resolved:?} {limits:?}"
    );
    assert_eq!(
        a.sites.len() + limits.iter().collect::<BTreeSet<_>>().len(),
        6
    );
    // Deterministic across two runs.
    assert_eq!(a, b);
}

#[test]
fn relative_import_targets() {
    let c = fx()
        .other("payload.dat")
        .other("config.json")
        .excluded("node_modules")
        .file(
            "app.js",
            js().import(import(Some("p"), "./payload.dat", &[]))
                .import(import(Some("cfg"), "./config.json", &[]))
                .import(import(Some("m"), "./missing", &[]))
                .import(import(Some("x"), "./node_modules/lib/index.js", &[])),
        )
        .run();
    let got = spots(&c);
    assert!(
        got.contains(&pair("payload.dat", "loaded-as-code")),
        "{got:?}"
    );
    assert!(
        got.contains(&pair("app.js", "unresolved-module")),
        "{got:?}"
    );
    assert!(
        got.contains(&pair("app.js", "reference-into-excluded")),
        "{got:?}"
    );
    assert!(!got.iter().any(|(f, _)| f == "config.json"), "{got:?}");
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(c.loaded_as_code, 1);
    let loaded = c
        .blind_spots
        .iter()
        .find(|b| b.file == "payload.dat")
        .unwrap();
    assert!(loaded.whole_file && loaded.coverage_gap && loaded.language.is_none());
    let into = c
        .blind_spots
        .iter()
        .find(|b| b.kind.as_str() == "reference-into-excluded")
        .unwrap();
    assert!(into.coverage_gap);
    let unresolved = c
        .blind_spots
        .iter()
        .find(|b| b.kind.as_str() == "unresolved-module")
        .unwrap();
    assert!(!unresolved.coverage_gap);
}

#[test]
fn import_outside_root_is_a_gap_that_never_prints_the_target() {
    let c = fx()
        .file(
            "app.js",
            js().import(import(Some("n"), "/opt/payload/net", &[])),
        )
        .run();
    assert_eq!(spots(&c), vec![pair("app.js", "reference-outside-root")]);
    let b = &c.blind_spots[0];
    assert!(b.coverage_gap && !b.whole_file);
    assert!(!format!("{b:?}").contains("/opt/payload"));
}

#[test]
fn loaded_as_code_is_reported_once_per_target() {
    let c = fx()
        .other("payload.dat")
        .file("a.js", js().import(import(Some("p"), "./payload.dat", &[])))
        .file("b.js", js().import(import(Some("p"), "./payload.dat", &[])))
        .run();
    assert_eq!(spots(&c), vec![pair("payload.dat", "loaded-as-code")]);
    assert_eq!(c.loaded_as_code, 1);
}

#[test]
fn first_party_module_shadowing_an_egress_stdlib_name_is_a_blind_spot() {
    let c = fx()
        .file("socket.py", py())
        .file(
            "app.py",
            py().import(import_module("socket")).r(r(
                imp("socket"),
                &["create_connection"],
                Call,
                "socket.create_connection(a)",
            )),
        )
        .file("other.py", py().import(import_module("socket")))
        .run();
    assert_eq!(
        spots(&c),
        vec![
            pair("app.py", "shadowed-module"),
            pair("other.py", "shadowed-module")
        ]
    );
    assert!(c.sites.is_empty(), "{:?}", c.sites);
    assert!(c.unscanned_dependencies.is_empty());
}

#[test]
fn first_party_module_named_like_an_inert_stdlib_module_resolves_first_party() {
    let c = fx()
        .file("json.py", py().sym(func("dumps", &["x"])))
        .file(
            "app.py",
            py().import(import_module("json"))
                .r(r(imp("json"), &["dumps"], Call, "json.dumps(x)")),
        )
        .run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty(), "{c:?}");
}

#[test]
fn sibling_first_party_package_resolves_instead_of_an_unscanned_dependency() {
    let c = fx()
        .file(
            "mylib/__init__.py",
            py().import(import(Some("post"), "requests", &["post"])),
        )
        .file(
            "app.py",
            py().import(import_module("mylib")).r(r(
                imp("mylib"),
                &["post"],
                Call,
                "mylib.post(u)",
            )
            .arg(lit("https://p.example"))),
        )
        .run();
    assert!(
        c.unscanned_dependencies.is_empty(),
        "{:?}",
        c.unscanned_dependencies
    );
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.post", "https://p.example")]
    );
}

#[test]
fn submodule_import_from_a_package_follows_the_submodule_file() {
    let c = fx()
        .file("pkg/__init__.py", py())
        .file(
            "pkg/net.py",
            py().import(import(Some("post"), "requests", &["post"])),
        )
        .file(
            "app.py",
            py().import(import(Some("net"), "pkg", &["net"])).r(r(
                imp("net"),
                &["post"],
                Call,
                "net.post(u)",
            )
            .arg(lit("https://p.example"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.post", "https://p.example")]
    );
}

#[test]
fn type_only_imports_are_inert() {
    let mut i = import(Some("Socket"), "net", &["Socket"]);
    i.type_only = true;
    let mut j = import(Some("Foo"), "some-types-pkg", &["Foo"]);
    j.type_only = true;
    let c = fx()
        .file(
            "a.ts",
            js().import(i)
                .import(j)
                .r(r(imp("Socket"), &[], TypePosition, "Socket")),
        )
        .run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty(), "{c:?}");
    assert!(c.unscanned_dependencies.is_empty());
}

#[test]
fn resolver_binding_api_follows_a_chain_and_memoizes() {
    let a = js().import(re_export(import(Some("connect"), "net", &["connect"])));
    let b = js().import(re_export(import(Some("connect"), "./a", &["connect"])));
    let mut index = BTreeMap::new();
    index.insert(b"a.js".to_vec(), FileKind::Source(Language::Javascript));
    index.insert(b"b.js".to_vec(), FileKind::Source(Language::Javascript));
    let excluded = BTreeSet::new();
    let rules = TestRules;
    let mut program = Program::new(&index, &excluded);
    program.set_rules(Language::Javascript, &rules);
    for (p, ir) in [("a.js", &a.0), ("b.js", &b.0)] {
        program.add_file(
            p.as_bytes().to_vec(),
            egress_core::resolve::ProgramFile {
                file: egress_core::identity::encode_path_bytes(p.as_bytes()),
                language: Language::Javascript,
                labels: vec![],
                ir,
            },
        );
    }
    let mut r = Resolver::new(&program, data(), u64::MAX);
    r.begin_reference();
    let got = r.export(b"b.js", "connect").unwrap();
    assert_eq!(
        got,
        Some(Binding::External {
            module: "net".into(),
            members: vec!["connect".into()]
        })
    );
    let first = r.steps();
    r.begin_reference();
    r.export(b"b.js", "connect").unwrap();
    assert_eq!(r.steps(), first + 1, "a memoized lookup costs one step");
}

/// `a` star-imports `b` then `c`, `b` star-imports `a`, and `c` binds `x` to
/// an egress module. `first` imports `x` from `a`, `m2` imports it from `b`.
/// The lookup through `a` cuts the `b -> a` cycle; that cut must not be
/// remembered as `b` having no `x`.
fn star_cycle_py(first: &str) -> Fx {
    fx().file("a.py", py().import(star("b")).import(star("c")))
        .file("b.py", py().import(star("a")))
        .file("c.py", py().import(import(Some("x"), "requests", &[])))
        .file(
            first,
            py().import(import(Some("x"), "a", &["x"])).r(r(
                imp("x"),
                &["get"],
                Call,
                "x.get(\"http://1\")",
            )
            .arg(lit("http://1"))),
        )
        .file(
            "m2.py",
            py().import(import(Some("y"), "b", &["x"])).r(r(
                imp("y"),
                &["get"],
                Call,
                "y.get(\"http://2\")",
            )
            .arg(lit("http://2"))),
        )
}

#[test]
fn star_import_cycle_keeps_every_importer_regardless_of_file_order() {
    for first in ["m1.py", "z1.py"] {
        let c = star_cycle_py(first).run();
        assert_eq!(
            mechs(&c),
            vec![
                pair("python:requests.get", "http://1"),
                pair("python:requests.get", "http://2"),
            ],
            "first importer {first}"
        );
        assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    }
}

fn star_cycle_js(first: &str) -> Fx {
    fx().file(
        "a.js",
        js().import(re_export(star("./b")))
            .import(re_export(star("./c"))),
    )
    .file("b.js", js().import(re_export(star("./a"))))
    .file(
        "c.js",
        js().import(re_export(import(Some("x"), "net", &["connect"]))),
    )
    .file(
        first,
        js().import(import(Some("x"), "./a", &["x"]))
            .r(r(imp("x"), &[], Call, "x(80, \"one\")")
                .arg(lit("80"))
                .arg(lit("one"))),
    )
    .file(
        "m2.js",
        js().import(import(Some("y"), "./b", &["x"]))
            .r(r(imp("y"), &[], Call, "y(80, \"two\")")
                .arg(lit("80"))
                .arg(lit("two"))),
    )
}

#[test]
fn export_star_cycle_keeps_every_importer_regardless_of_file_order() {
    for first in ["m1.js", "z1.js"] {
        let c = star_cycle_js(first).run();
        assert_eq!(
            mechs(&c),
            vec![
                pair("javascript:net.connect", "one:80"),
                pair("javascript:net.connect", "two:80"),
            ],
            "first importer {first}"
        );
        assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    }
}

/// A three-hop cycle: `a` star-imports `b` then `d`, `b` star-imports `c`,
/// `c` star-imports `a`, and `d` binds `x`. The lookup through `a` cuts at
/// `c -> a`, two hops below it; neither `c` nor `b` may be remembered as
/// having no `x`.
fn star_cycle3_py(first: &str) -> Fx {
    fx().file("a.py", py().import(star("b")).import(star("d")))
        .file("b.py", py().import(star("c")))
        .file("c.py", py().import(star("a")))
        .file("d.py", py().import(import(Some("x"), "requests", &[])))
        .file(
            first,
            py().import(import(Some("x"), "a", &["x"])).r(r(
                imp("x"),
                &["get"],
                Call,
                "x.get(\"http://1\")",
            )
            .arg(lit("http://1"))),
        )
        .file(
            "m2.py",
            py().import(import(Some("y"), "b", &["x"])).r(r(
                imp("y"),
                &["get"],
                Call,
                "y.get(\"http://2\")",
            )
            .arg(lit("http://2"))),
        )
}

#[test]
fn three_hop_star_import_cycle_keeps_every_importer_regardless_of_file_order() {
    for first in ["m1.py", "z1.py"] {
        let c = star_cycle3_py(first).run();
        assert_eq!(
            mechs(&c),
            vec![
                pair("python:requests.get", "http://1"),
                pair("python:requests.get", "http://2"),
            ],
            "first importer {first}"
        );
        assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    }
}

fn star_cycle3_js(first: &str) -> Fx {
    fx().file(
        "a.js",
        js().import(re_export(star("./b")))
            .import(re_export(star("./d"))),
    )
    .file("b.js", js().import(re_export(star("./c"))))
    .file("c.js", js().import(re_export(star("./a"))))
    .file(
        "d.js",
        js().import(re_export(import(Some("x"), "net", &["connect"]))),
    )
    .file(
        first,
        js().import(import(Some("x"), "./a", &["x"]))
            .r(r(imp("x"), &[], Call, "x(80, \"one\")")
                .arg(lit("80"))
                .arg(lit("one"))),
    )
    .file(
        "m2.js",
        js().import(import(Some("y"), "./b", &["x"]))
            .r(r(imp("y"), &[], Call, "y(80, \"two\")")
                .arg(lit("80"))
                .arg(lit("two"))),
    )
}

#[test]
fn three_hop_export_star_cycle_keeps_every_importer_regardless_of_file_order() {
    for first in ["m1.js", "z1.js"] {
        let c = star_cycle3_js(first).run();
        assert_eq!(
            mechs(&c),
            vec![
                pair("javascript:net.connect", "one:80"),
                pair("javascript:net.connect", "two:80"),
            ],
            "first importer {first}"
        );
        assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    }
}

/// A resolver over `index` with `excluded` directories and generic rules.
fn target_of(excluded: &[&str], specifier: &str) -> Target {
    let index = BTreeMap::new();
    let excluded: BTreeSet<Vec<u8>> = excluded.iter().map(|d| d.as_bytes().to_vec()).collect();
    let rules = GenericRules::exact();
    let mut program = Program::new(&index, &excluded);
    program.set_rules(Language::Javascript, &rules);
    let mut r = Resolver::new(&program, data(), u64::MAX);
    r.target(b"app.js", Language::Javascript, specifier)
}

#[test]
fn unresolved_path_into_an_excluded_directory_matches_whole_components() {
    let ex = ["node_modules", "pkg/vendor"];
    assert_eq!(target_of(&ex, "./node_modules"), Target::IntoExcluded);
    assert_eq!(
        target_of(&ex, "./node_modules/a/b.js"),
        Target::IntoExcluded
    );
    assert_eq!(target_of(&ex, "./pkg/vendor"), Target::IntoExcluded);
    assert_eq!(target_of(&ex, "./pkg/vendor/x.js"), Target::IntoExcluded);
    // A sibling sharing a name prefix, or a parent of an excluded directory,
    // is not inside it.
    assert_eq!(target_of(&ex, "./node_modules2/a.js"), Target::Unresolved);
    assert_eq!(target_of(&ex, "./node_modules2"), Target::Unresolved);
    assert_eq!(target_of(&ex, "./pkg/vendored.js"), Target::Unresolved);
    assert_eq!(target_of(&ex, "./pkg"), Target::Unresolved);
    assert_eq!(target_of(&[], "./node_modules/a.js"), Target::Unresolved);
}

#[test]
fn unresolved_imports_against_many_excluded_directories_stay_cheap() {
    // Each unresolved probe used to scan every excluded directory, so a repo
    // with many tagged directories and many unresolved imports cost their
    // product. Lookups by ancestor keep it proportional to the path depth.
    let n = 20_000;
    let index = BTreeMap::new();
    let excluded: BTreeSet<Vec<u8>> = (0..n).map(|i| format!("cache/d{i}").into_bytes()).collect();
    let rules = GenericRules {
        extensions: vec![".js".into(), ".ts".into()],
        index_names: vec!["index".into()],
    };
    let mut program = Program::new(&index, &excluded);
    program.set_rules(Language::Javascript, &rules);
    let mut r = Resolver::new(&program, data(), u64::MAX);
    let start = std::time::Instant::now();
    for i in 0..n {
        assert_eq!(
            r.target(b"app.js", Language::Javascript, &format!("./src/m{i}")),
            Target::Unresolved
        );
    }
    assert_eq!(
        r.target(b"app.js", Language::Javascript, "./cache/d7/x"),
        Target::IntoExcluded
    );
    let took = start.elapsed();
    assert!(took.as_secs() < 10, "took {took:?}");
}

#[test]
fn python_bare_import_into_an_excluded_directory_is_a_gap() {
    // A `pyvenv.cfg` dropped into a first-party package excludes it; an
    // absolute import of a module inside it must not read as an external
    // dependency.
    let c = fx()
        .excluded("app")
        .file(
            "main.py",
            py().import(import(Some("go"), "app.net", &["go"]))
                .r(r(imp("go"), &[], Call, "go()")),
        )
        .run();
    assert_eq!(spots(&c), vec![pair("main.py", "reference-into-excluded")]);
    assert!(deps(&c).is_empty(), "{:?}", deps(&c));
}

#[test]
fn python_bare_import_beside_an_excluded_directory_stays_external() {
    let c = fx()
        .excluded("app")
        .file(
            "main.py",
            py().import(import(Some("go"), "apps.net", &["go"]))
                .r(r(imp("go"), &[], Call, "go()")),
        )
        .run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert_eq!(deps(&c), vec![s("apps")]);
}

#[test]
fn js_bare_import_whose_probe_is_excluded_stays_external() {
    // JS bare probes are workspace package entry points; a package whose
    // entry sits in an excluded directory stays an unscanned dependency.
    let c = fx()
        .excluded("lib")
        .file(
            "app.js",
            js().import(import(Some("x"), "lib", &["x"]))
                .r(r(imp("x"), &[], Call, "x()")),
        )
        .run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert_eq!(deps(&c), vec![s("lib")]);
}

/// `from pkg import app` and `from .. import app`, where `app` is a
/// subpackage the scan excluded (a `pyvenv.cfg` marks it), reach code the
/// scan skipped: the import is a reference-into-excluded blind spot, not a
/// definition in `pkg/__init__.py`.
#[test]
fn from_import_of_an_excluded_subpackage_is_a_reference_into_excluded() {
    let call = || r(imp("app"), &["go"], Call, "app.go()");
    let absolute = fx()
        .excluded("pkg/app")
        .file("pkg/__init__.py", py())
        .file(
            "main.py",
            py().import(import(Some("app"), "pkg", &["app"])).r(call()),
        )
        .run();
    // The test rules recurse on a bare `.`, so the relative form goes up
    // one package; the corpus covers `from . import app` with the real rules.
    let relative = fx()
        .excluded("pkg/app")
        .file("pkg/__init__.py", py())
        .file("pkg/sub/__init__.py", py())
        .file(
            "pkg/sub/main.py",
            py().import(import(Some("app"), "..", &["app"])).r(call()),
        )
        .run();
    for (c, file) in [(&absolute, "main.py"), (&relative, "pkg/sub/main.py")] {
        assert_eq!(
            spots(c),
            vec![pair(file, "reference-into-excluded")],
            "{file}"
        );
        assert!(c.blind_spots[0].coverage_gap, "{file}");
        assert!(c.sites.is_empty(), "{file}");
    }
}

/// Must-not: `from pkg import name` where `name` is an ordinary definition
/// in `pkg/__init__.py`, or a name the package binds in a way the resolver
/// does not see with no submodule of that name, stays first-party code with
/// no blind spot, even beside an excluded sibling subpackage.
#[test]
fn from_import_of_a_package_definition_is_not_a_gap() {
    let c = fx()
        .excluded("pkg/app")
        .file("pkg/__init__.py", py().sym(func("helper", &[])))
        .file(
            "main.py",
            py().import(import(Some("helper"), "pkg", &["helper"]))
                .import(import(Some("dynamic"), "pkg", &["dynamic"]))
                .r(r(imp("helper"), &[], Call, "helper()"))
                .r(r(imp("dynamic"), &["go"], Call, "dynamic.go()")),
        )
        .run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert!(c.sites.is_empty(), "{:?}", c.sites);
}

/// `from pkg import app` where `pkg/app.py` is indexed but not lowered is
/// first-party code the resolver does not look into, as a direct import of
/// it is.
#[test]
fn from_import_of_an_unlowered_submodule_is_first_party() {
    let c = fx()
        .unlowered("pkg/app.py")
        .file("pkg/__init__.py", py())
        .file(
            "main.py",
            py().import(import(Some("app"), "pkg", &["app"])).r(r(
                imp("app"),
                &["go"],
                Call,
                "app.go()",
            )),
        )
        .run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert!(c.sites.is_empty(), "{:?}", c.sites);
}

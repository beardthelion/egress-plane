//! Closure rules on hand-built IR (U4: KTD5 escape, value-use, and ambient
//! module rules; KTD15 structural families; AE20, AE21 at IR level, AE27).

mod classify_support;

use classify_support::*;
use egress_core::data::Data;
use egress_core::ir::ConstructKind;
use egress_core::ir::Provenance;
use egress_core::ir::UseKind::*;
use egress_core::model::Bucket;

// ---- escape rule ----------------------------------------------------------------

#[test]
fn module_value_escape_is_an_escape_site_and_inert_module_escape_is_nothing() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("os"))
                .r(r(imp("os"), &[], ValueEscape, "os").sym("f")),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![(s("a.py"), s("f"), s("python:os"), s("expr:os"))]
    );
    assert_eq!(c.sites[0].bucket, Bucket::Primitive);
    assert!(c.blind_spots.is_empty());

    let c = fx()
        .file(
            "a.py",
            py().import(import_module("json"))
                .r(r(imp("json"), &[], ValueEscape, "json")),
        )
        .run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty(), "{c:?}");
}

#[test]
fn catalogued_module_escape_is_a_catalogued_site() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests")).r(r(
                imp("requests"),
                &[],
                ValueEscape,
                "requests",
            )),
        )
        .run();
    assert_eq!(mechs(&c), vec![pair("python:requests", "expr:requests")]);
    assert_eq!(c.sites[0].bucket, Bucket::Catalogued);
}

#[test]
fn escape_of_a_module_holding_a_blind_spot_entry_is_module_escape() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("ctypes"))
                .r(r(imp("ctypes"), &[], ValueEscape, "ctypes")),
        )
        .run();
    assert!(c.sites.is_empty());
    assert_eq!(kinds(&c), vec![s("module-escape")]);
}

#[test]
fn with_embedded_data_os_holds_blind_spot_entries_so_its_escape_is_module_escape() {
    // The embedded list classifies `os.sys` (a re-exported module object)
    // and `os.add_dll_directory` as blind-spot entries, so KTD5's escape
    // rule makes an `os` escape a `module-escape` blind spot.
    let embedded = Data::embedded().unwrap();
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("os"))
                .r(r(imp("os"), &[], ValueEscape, "os")),
        )
        .run_with(&embedded, u64::MAX);
    assert_eq!(kinds(&c), vec![s("module-escape")]);
    assert!(c.sites.is_empty());
}

#[test]
fn star_import_of_os_is_an_escape_and_of_os_path_is_nothing() {
    let c = fx().file("a.py", py().import(star("os"))).run();
    assert_eq!(mechs(&c), vec![pair("python:os", "expr:os")]);

    let c = fx().file("a.py", py().import(star("os.path"))).run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty(), "{c:?}");
}

#[test]
fn js_export_star_from_a_builtin_is_an_escape() {
    let c = fx().file("a.js", js().import(re_export(star("net")))).run();
    assert_eq!(mechs(&c), vec![pair("javascript:net", "expr:net")]);
}

#[test]
fn unknown_member_of_an_egress_module_takes_the_module_bucket() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("subprocess")).r(r(
                imp("subprocess"),
                &["mystery"],
                Call,
                "subprocess.mystery(x)",
            )),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:subprocess", "expr:subprocess.mystery(x)")]
    );
}

// ---- value-use rule (AE20) --------------------------------------------------------

#[test]
fn covers_ae20_value_uses_of_egress_members_are_expr_sites() {
    let c = fx()
        .file(
            "jobs.py",
            py().import(import_module("os"))
                .import(import_module("functools"))
                .import(import_module("socket"))
                .r(r(
                    imp("functools"),
                    &["partial"],
                    Call,
                    "functools.partial(os.system, cmd)",
                )
                .sym("schedule"))
                .r(r(imp("os"), &["system"], ValueEscape, "os.system").sym("schedule"))
                .r(r(imp("os"), &["path", "join"], ValueEscape, "os.path.join").sym("schedule"))
                .r(r(imp("socket"), &["socket"], BaseClass, "socket.socket").sym("Conn")),
        )
        .file(
            "conn.js",
            js().import(import_module("net")).r(r(
                imp("net"),
                &["Socket"],
                BaseClass,
                "net.Socket",
            )
            .sym("Conn")),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![
            (
                s("conn.js"),
                s("Conn"),
                s("javascript:net.Socket"),
                s("expr:net.Socket")
            ),
            (
                s("jobs.py"),
                s("Conn"),
                s("python:socket.socket"),
                s("expr:socket.socket")
            ),
            (
                s("jobs.py"),
                s("schedule"),
                s("python:os.system"),
                s("expr:os.system")
            ),
        ]
    );
    assert!(c.blind_spots.is_empty());
}

#[test]
fn alias_of_an_egress_member_called_later_is_a_site() {
    let os_system = r(imp("os"), &["system"], ValueEscape, "os.system").sym("f");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("os"))
                .r(os_system.clone())
                .local(local_binding("f", "run", os_system.expr()))
                .r(r(local("run"), &[], Call, "run(\"curl x\")")
                    .sym("f")
                    .arg(lit("curl x"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![
            pair("python:os.system", "exec:curl"),
            pair("python:os.system", "expr:os.system")
        ]
    );
}

// ---- ambient module rule ----------------------------------------------------------

#[test]
fn covers_ae16_ambient_fetch_and_local_fetch_and_computed_global() {
    let c = fx()
        .file(
            "a.js",
            js().r(r(amb("fetch"), &[], Call, "fetch(url)").arg(name("url"))),
        )
        .file(
            "b.js",
            js().sym(func("fetch", &["u"]))
                .r(r(local("fetch"), &[], Call, "fetch(u)").arg(lit("https://x.example"))),
        )
        .file(
            "c.js",
            js().r(r(
                amb("globalThis"),
                &[],
                ComputedMember,
                "globalThis[name](url)",
            )
            .receiver(Provenance::AmbientModule)),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![(
            s("a.js"),
            s("<module>"),
            s("javascript:globalThis.fetch"),
            s("expr:url")
        )]
    );
    assert_eq!(spots(&c), vec![pair("c.js", "reflective-access")]);
}

#[test]
fn ambient_aliases_resolve_the_same_way() {
    let c = fx()
        .file(
            "a.js",
            js().r(
                r(amb("window"), &["fetch"], Call, "window.fetch(u)").arg(lit("https://w.example"))
            )
            .r(r(
                amb("document"),
                &["defaultView", "fetch"],
                Call,
                "document.defaultView.fetch(u)",
            )
            .arg(lit("https://d.example")))
            .r(
                r(amb("globalThis"), &["fetch"], Call, "globalThis.fetch(u)")
                    .arg(lit("https://g.example")),
            ),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![
            pair("javascript:globalThis.fetch", "https://d.example"),
            pair("javascript:globalThis.fetch", "https://g.example"),
            pair("javascript:globalThis.fetch", "https://w.example"),
        ]
    );
}

#[test]
fn binding_to_the_ambient_module_then_member_call_and_computed_access() {
    let g = r(amb("globalThis"), &[], ValueEscape, "globalThis");
    let base = || js().local(local_binding("<module>", "g", g.expr()));
    let c = fx()
        .file(
            "a.js",
            base().r(r(local("g"), &["fetch"], Call, "g.fetch(u)").arg(lit("https://g.example"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("javascript:globalThis.fetch", "https://g.example")]
    );

    let c = fx()
        .file(
            "a.js",
            base()
                .r(r(local("g"), &[], ComputedMember, "g[k](u)")
                    .receiver(Provenance::AmbientModule)),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("reflective-access")]);
    assert!(c.sites.is_empty());
}

#[test]
fn ambient_module_used_as_a_value_is_an_escape() {
    let c = fx()
        .file("a.js", js().r(r(amb("window"), &[], ValueEscape, "window")))
        .run();
    // globalThis holds blind-spot entries (eval), so its escape is a
    // module-escape blind spot.
    assert_eq!(kinds(&c), vec![s("module-escape")]);
}

#[test]
fn ambient_member_that_is_a_module_continues_into_it() {
    let c = fx()
        .file(
            "a.js",
            js().r(r(
                amb("process"),
                &["binding"],
                Call,
                "process.binding(\"tcp_wrap\")",
            )),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("native-code")]);
}

#[test]
fn python_builtins_subscript_with_a_non_literal_key_is_scope_injection() {
    let c = fx()
        .file(
            "a.py",
            py().r(
                r(amb("__builtins__"), &[], ComputedMember, "__builtins__[k]")
                    .receiver(Provenance::AmbientModule),
            ),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("scope-injection")]);
}

// ---- reflective access (KTD15, AE22, AE27) ------------------------------------------

#[test]
fn covers_ae22_getattr_with_a_non_literal_name_on_a_module_is_a_blind_spot() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests")).r(r(
                amb("getattr"),
                &[],
                Call,
                "getattr(requests, verb)",
            )
            .arg(name("requests"))
            .arg(name("verb"))
            .receiver(Provenance::ModuleBinding)),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("reflective-access")]);
    assert!(c.sites.is_empty());
}

#[test]
fn getattr_with_a_literal_name_resolves_as_member_access() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("os")).r(r(
                amb("getattr"),
                &[],
                Call,
                "getattr(os, \"system\")",
            )
            .arg(name("os"))
            .arg(lit("system"))),
        )
        .run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert_eq!(
        mechs(&c),
        vec![pair("python:os.system", "expr:getattr(os, \"system\")")]
    );
}

#[test]
fn computed_member_on_a_module_binding_is_reflective_access() {
    let c = fx()
        .file(
            "a.js",
            js().import(import_module("net"))
                .r(r(imp("net"), &[], ComputedMember, "net[k]")
                    .receiver(Provenance::ModuleBinding)),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("reflective-access")]);
}

#[test]
fn covers_ae27_non_literal_reflective_access_on_untracked_provenance_is_reflective_unknown() {
    for p in [
        Provenance::FirstPartyCallResult,
        Provenance::UnscannedCallResult,
        Provenance::Parameter(1),
    ] {
        let c = fx()
            .file(
                "a.py",
                py().r(r(amb("getattr"), &[], Call, "getattr(c, name)")
                    .arg(name("c"))
                    .arg(name("name"))
                    .receiver(p.clone())),
            )
            .file(
                "a.js",
                js().r(r(local("o"), &[], ComputedMember, "o[k](u)").receiver(p.clone())),
            )
            .run();
        assert_eq!(
            spots(&c),
            vec![
                pair("a.js", "reflective-unknown"),
                pair("a.py", "reflective-unknown")
            ],
            "provenance {p:?}"
        );
        assert!(c.sites.is_empty() && c.unscanned_dependencies.is_empty());
    }
}

#[test]
fn must_not_literal_name_or_literal_receiver_is_not_reflective_unknown() {
    let c = fx()
        .file(
            "a.py",
            py().r(r(amb("getattr"), &[], Call, "getattr(c, \"close\")")
                .arg(name("c"))
                .arg(lit("close"))
                .receiver(Provenance::FirstPartyCallResult)),
        )
        .file(
            "a.js",
            js().r(r(local("table"), &[], ComputedMember, "table[k]").receiver(Provenance::Literal)),
        )
        .run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert!(c.sites.is_empty());
}

#[test]
fn computed_access_on_a_tracked_constructor_result_is_carried_by_the_constructor_site() {
    let ctor = r(imp("requests"), &["Session"], Call, "requests.Session()").sym("f");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .r(ctor.clone())
                .local(local_binding("f", "s", ctor.expr()))
                .r(r(amb("getattr"), &[], Call, "getattr(s, verb)")
                    .sym("f")
                    .arg(name("s"))
                    .arg(name("verb"))
                    .receiver(Provenance::TrackedConstructor)),
        )
        .run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.Session", "expr:requests.Session()")]
    );
}

#[test]
fn js_reflect_get_follows_the_same_rules() {
    let c = fx()
        .file(
            "a.js",
            js().import(import_module("net"))
                .r(r(amb("Reflect"), &["get"], Call, "Reflect.get(net, k)")
                    .arg(name("net"))
                    .arg(name("k"))
                    .receiver(Provenance::ModuleBinding))
                .r(r(
                    amb("Reflect"),
                    &["get"],
                    Call,
                    "Reflect.get(net, \"connect\")",
                )
                .arg(name("net"))
                .arg(lit("connect"))),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("reflective-access")]);
    assert_eq!(
        mechs(&c),
        vec![pair(
            "javascript:net.connect",
            "expr:Reflect.get(net, \"connect\")"
        )]
    );
}

// ---- dynamic loading ----------------------------------------------------------------

#[test]
fn loader_with_a_non_literal_specifier_is_dynamic_import_and_literal_is_not() {
    let c = fx()
        .file(
            "a.js",
            js().r(r(amb("require"), &[], Call, "require(variable)").arg(name("variable")))
                .r(r(amb("require"), &[], Call, "require(\"http\")").arg(lit("http"))),
        )
        .file(
            "a.py",
            py().import(import_module("importlib"))
                .r(r(
                    imp("importlib"),
                    &["import_module"],
                    Call,
                    "importlib.import_module(n)",
                )
                .arg(name("n")))
                .r(r(
                    imp("importlib"),
                    &["import_module"],
                    Call,
                    "importlib.import_module(\"json\")",
                )
                .arg(lit("json")))
                .r(r(amb("__import__"), &[], Call, "__import__(n)").arg(name("n")))
                .r(r(amb("__import__"), &[], Call, "__import__(\"os\")").arg(lit("os"))),
        )
        .run();
    assert_eq!(
        spots(&c),
        vec![
            pair("a.js", "dynamic-import"),
            pair("a.py", "dynamic-import"),
            pair("a.py", "dynamic-import"),
        ]
    );
}

#[test]
fn worker_with_a_literal_in_root_specifier_resolves_and_otherwise_is_dynamic_import() {
    let w =
        |arg: egress_core::ir::Expr| r(imp("Worker"), &[], Construct, "new Worker(..)").arg(arg);
    let base = || js().import(import(Some("Worker"), "worker_threads", &["Worker"]));
    let c = fx().file("a.js", base().r(w(lit("./w.js")))).run();
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    for bad in [name("f"), lit("data:text/javascript,1"), lit("blob:x")] {
        let c = fx().file("a.js", base().r(w(bad))).run();
        assert_eq!(kinds(&c), vec![s("dynamic-import")]);
    }
    let c = fx()
        .file(
            "a.js",
            base().r(w(lit("code")).arg(obj(vec![("eval", lit("true"))]))),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("dynamic-import")]);
}

// ---- writes ---------------------------------------------------------------------------

#[test]
fn import_system_write_is_a_blind_spot() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("sys")).r(r(
                imp("sys"),
                &["path", "append"],
                Call,
                "sys.path.append(p)",
            )),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("import-system-mutation")]);
}

#[test]
fn setattr_and_assignment_on_an_egress_module_member_are_monkeypatch() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("socket"))
                .r(r(
                    amb("setattr"),
                    &[],
                    Call,
                    "setattr(socket, \"socket\", Fake)",
                )
                .arg(name("socket"))
                .arg(lit("socket"))
                .arg(name("Fake")))
                .r(r(
                    imp("socket"),
                    &["create_connection"],
                    AssignmentTarget,
                    "socket.create_connection",
                )),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("monkeypatch"), s("monkeypatch")]);
    assert!(c.sites.is_empty(), "{:?}", c.sites);

    // An inert module's member is not monkeypatch.
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("json")).r(r(
                imp("json"),
                &["dumps"],
                AssignmentTarget,
                "json.dumps",
            )),
        )
        .run();
    assert!(c.blind_spots.is_empty());
}

// ---- introspection and structural constructs ---------------------------------------------

#[test]
fn introspection_off_the_inert_list_is_a_blind_spot() {
    let c = fx()
        .file(
            "a.py",
            py().introspection(introspection("__self__", "len.__self__"))
                .introspection(introspection("f_builtins", "frame.f_builtins"))
                .introspection(introspection("__name__", "type(x).__name__"))
                .introspection(introspection("__init__", "Base.__init__")),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("introspection"), s("introspection")]);
    let mut constructs: Vec<_> = c.blind_spots.iter().map(|b| b.construct.clone()).collect();
    constructs.sort();
    assert_eq!(constructs, vec![s("frame.f_builtins"), s("len.__self__")]);
}

#[test]
fn structural_constructs_map_to_their_blind_spot_kinds() {
    let c = fx()
        .file(
            "a.js",
            js().construct(construct(ConstructKind::DynamicImport, "import(x)"))
                .construct(construct(
                    ConstructKind::RequireAsValue,
                    "const r = require",
                ))
                .construct(construct(ConstructKind::ScopeInjection, "with (o) {}"))
                .construct(construct(
                    ConstructKind::ImportSystemMutation,
                    "require.cache[k] = m",
                ))
                .construct(construct(
                    ConstructKind::ConstructorChain,
                    "(()=>{}).constructor(s)",
                )),
        )
        .file(
            "src/lib.rs",
            rs().construct(construct(ConstructKind::NativeCode, "extern \"C\" {}"))
                .construct(construct(
                    ConstructKind::MacroCode,
                    "include!(concat!(env!(\"OUT_DIR\"), \"/x.rs\"))",
                )),
        )
        .run();
    assert_eq!(
        kinds(&c),
        vec![
            s("dynamic-import"),
            s("dynamic-import"),
            s("import-system-mutation"),
            s("introspection"),
            s("macro-code"),
            s("native-code"),
            s("scope-injection"),
        ]
    );
    assert!(
        c.blind_spots
            .iter()
            .all(|b| !b.coverage_gap && !b.whole_file)
    );
}

#[test]
fn object_define_property_on_an_egress_module_is_monkeypatch() {
    let c = fx()
        .file(
            "a.js",
            js().import(import_module("net"))
                .import(import_module("path"))
                .r(r(
                    amb("Object"),
                    &["defineProperty"],
                    Call,
                    "Object.defineProperty(net, \"connect\", d)",
                )
                .arg(name("net"))
                .arg(lit("connect")))
                .r(r(amb("Object"), &["assign"], Call, "Object.assign(path, o)").arg(name("path")))
                .r(
                    r(amb("Object"), &["assign"], Call, "Object.assign(target, o)")
                        .arg(name("target")),
                ),
        )
        .run();
    assert_eq!(kinds(&c), vec![s("monkeypatch")]);
    assert!(
        c.blind_spots[0]
            .construct
            .starts_with("Object.defineProperty(net")
    );
}

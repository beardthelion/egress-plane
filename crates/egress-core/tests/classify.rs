//! Member-level classification, destinations, and instance tracking on
//! hand-built IR (U4: KTD5, KTD7, KTD8, R2, R3, R5, R6, R20).

mod classify_support;

use classify_support::*;
use egress_core::ir::UseKind::*;
use egress_core::ir::{Expr, Provenance};
use egress_core::model::{Bucket, DestinationKind};

#[test]
fn covers_ae15_os_path_join_is_inert_and_os_system_is_a_site() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("os"))
                .r(r(imp("os"), &["path", "join"], Call, "os.path.join(a, b)")
                    .arg(name("a"))
                    .arg(name("b")))
                .r(r(imp("os"), &["system"], Call, "os.system(cmd)")
                    .sym("run")
                    .arg(Expr::Param(1))),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![(s("a.py"), s("run"), s("python:os.system"), s("param:1:run"))]
    );
    assert_eq!(c.sites[0].bucket, Bucket::Primitive);
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert!(c.unscanned_dependencies.is_empty());
}

#[test]
fn covers_ae2_forty_calls_on_an_uncatalogued_package_list_it_once() {
    let mut ir = js().import(default_import("left-pad", "leftPad"));
    for i in 0..40 {
        ir = ir.r(r(imp("leftPad"), &[], Call, "leftPad(s)").arg(name(&format!("s{i}"))));
    }
    let c = fx().file("src/pad.js", ir).run();
    assert_eq!(deps(&c), vec![s("left-pad")]);
    assert_eq!(c.unscanned_dependencies[0].files, vec![s("src/pad.js")]);
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert!(c.sites.is_empty());
}

#[test]
fn scoped_and_subpath_packages_are_listed_by_package_name() {
    let c = fx()
        .file(
            "a.js",
            js().import(import(Some("fp"), "lodash/fp", &[]))
                .import(import(Some("w"), "@acme/widgets/button", &[])),
        )
        .run();
    assert_eq!(deps(&c), vec![s("@acme/widgets"), s("lodash")]);
}

#[test]
fn catalogued_egress_member_is_a_catalogued_site() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests")).r(r(
                imp("requests"),
                &["post"],
                Call,
                "requests.post(\"https://h.example/x\")",
            )
            .arg(lit("https://h.example/x"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.post", "https://h.example/x")]
    );
    assert_eq!(c.sites[0].bucket, Bucket::Catalogued);
    assert!(c.unscanned_dependencies.is_empty());
}

#[test]
fn catalogued_inert_member_is_nothing_and_unlisted_member_lists_the_package() {
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests")).r(r(
                imp("requests"),
                &["codes"],
                ValueEscape,
                "requests.codes",
            )),
        )
        .run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty());
    assert!(c.unscanned_dependencies.is_empty());

    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests")).r(r(
                imp("requests"),
                &["utils", "quote"],
                Call,
                "requests.utils.quote(x)",
            )),
        )
        .run();
    assert_eq!(deps(&c), vec![s("requests")]);
    assert!(c.sites.is_empty() && c.blind_spots.is_empty());
}

#[test]
fn tokio_sync_is_inert_tokio_net_is_a_site_and_other_members_list_tokio() {
    let c = fx()
        .file(
            "src/lib.rs",
            rs().import(import(Some("Mutex"), "tokio::sync", &["Mutex"]))
                .r(r(imp("Mutex"), &["new"], Call, "Mutex::new(0)")),
        )
        .run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty(), "{c:?}");
    assert!(c.unscanned_dependencies.is_empty());

    let c = fx()
        .file(
            "src/lib.rs",
            rs().import(import(Some("TcpStream"), "tokio::net", &["TcpStream"]))
                .r(r(
                    imp("TcpStream"),
                    &["connect"],
                    Call,
                    "TcpStream::connect(a)",
                )
                .arg(name("a"))),
        )
        .run();
    assert_eq!(mechs(&c).len(), 1);
    assert_eq!(c.sites[0].mechanism, "rust:tokio::net");
    assert!(c.unscanned_dependencies.is_empty());

    let c = fx()
        .file(
            "src/lib.rs",
            rs().import(import(Some("spawn"), "tokio::task", &["spawn"]))
                .r(r(imp("spawn"), &[], Call, "spawn(f)")),
        )
        .run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty());
    assert_eq!(deps(&c), vec![s("tokio")]);
}

#[test]
fn must_not_a_blind_spot_reference_carries_no_bucket_and_no_listing() {
    // A computed member on an uncatalogued module binding is a blind spot;
    // it adds no listing beyond the import's own, and no site.
    let c = fx()
        .file(
            "a.py",
            py().r(r(amb("eval"), &[], Call, "eval(s)").arg(name("s")))
                .import(import_module("requests"))
                .r(r(amb("getattr"), &[], Call, "getattr(requests, verb)")
                    .arg(name("requests"))
                    .arg(name("verb"))
                    .receiver(Provenance::ModuleBinding)),
        )
        .run();
    assert!(c.sites.is_empty(), "{:?}", c.sites);
    assert!(
        c.unscanned_dependencies.is_empty(),
        "{:?}",
        c.unscanned_dependencies
    );
    assert_eq!(kinds(&c), vec![s("dynamic-code"), s("reflective-access")]);
}

#[test]
fn must_not_a_first_party_function_call_is_no_site() {
    let c = fx()
        .file(
            "a.py",
            py().sym(func("fetch", &["u"]))
                .r(r(local("fetch"), &[], Call, "fetch(u)").arg(name("u"))),
        )
        .file(
            "b.py",
            py().import(import(Some("fetch"), "a", &["fetch"])).r(r(
                imp("fetch"),
                &[],
                Call,
                "fetch(u)",
            )
            .arg(name("u"))),
        )
        .run();
    assert!(c.sites.is_empty() && c.blind_spots.is_empty(), "{c:?}");
    assert!(c.unscanned_dependencies.is_empty());
}

// ---- destinations (KTD7) ----------------------------------------------------

fn post_with(arg: Expr) -> Ir {
    py().import(import_module("requests")).r(r(
        imp("requests"),
        &["post"],
        Call,
        "requests.post(...)",
    )
    .sym("send")
    .arg(arg))
}

fn one_dest(ir: Ir) -> String {
    let c = fx().file("a.py", ir).run();
    assert_eq!(c.sites.len(), 1, "{:?}", c.sites);
    c.sites[0].destination.display.clone()
}

#[test]
fn covers_ae1_env_subscript_is_env_name() {
    let environ = r(imp("os"), &["environ"], ValueEscape, "os.environ");
    let ir = post_with(subscript(environ.expr(), lit("WEBHOOK_URL"))).import(import_module("os"));
    assert_eq!(one_dest(ir), "env:WEBHOOK_URL");
}

#[test]
fn env_get_with_literal_default_records_the_default() {
    let get = r(
        imp("os"),
        &["environ", "get"],
        Call,
        "os.environ.get(\"X\", \"https://d.example\")",
    )
    .arg(lit("X"))
    .arg(lit("https://d.example"));
    let ir = post_with(get.expr()).import(import_module("os"));
    let c = fx().file("a.py", ir).run();
    let d = &c.sites[0].destination;
    assert_eq!(d.display, "env:X");
    assert_eq!(d.kind, DestinationKind::Env);
    assert_eq!(d.default.as_deref(), Some("https://d.example"));
}

#[test]
fn getenv_and_js_process_env_and_rust_env_var_are_env_reads() {
    let get = r(imp("os"), &["getenv"], Call, "os.getenv(\"API\")").arg(lit("API"));
    assert_eq!(
        one_dest(post_with(get.expr()).import(import_module("os"))),
        "env:API"
    );

    let env = r(
        amb("process"),
        &["env", "API_URL"],
        ValueEscape,
        "process.env.API_URL",
    );
    let c = fx()
        .file(
            "a.js",
            js().r(r(amb("fetch"), &[], Call, "fetch(process.env.API_URL)").arg(env.expr())),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("javascript:globalThis.fetch", "env:API_URL")]
    );

    let var = r(
        imp("env"),
        &["var", "unwrap"],
        Call,
        "env::var(\"HOST\").unwrap()",
    )
    .arg(lit("HOST"))
    .called_at(0);
    let c = fx()
        .file(
            "src/main.rs",
            rs().import(import(Some("env"), "std::env", &[]))
                .import(import(Some("TcpStream"), "std::net", &["TcpStream"]))
                .r(r(
                    imp("TcpStream"),
                    &["connect"],
                    Call,
                    "TcpStream::connect(..)",
                )
                .arg(var.expr())),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("rust:std::net::TcpStream::connect", "env:HOST")]
    );
}

#[test]
fn module_constant_same_file_resolves_to_its_literal() {
    let ir = post_with(name("BASE")).constant(constant("BASE", lit("https://api.example.com/v1")));
    assert_eq!(one_dest(ir), "https://api.example.com/v1");
}

#[test]
fn module_constant_imported_from_a_first_party_module_resolves_to_its_literal() {
    let c = fx()
        .file(
            "config.py",
            py().constant(constant("BASE_URL", lit("https://api.example.com/v1"))),
        )
        .file(
            "app.py",
            py().import(import(Some("BASE_URL"), "config", &["BASE_URL"]))
                .import(import_module("requests"))
                .r(r(imp("requests"), &["get"], Call, "requests.get(BASE_URL)")
                    .sym("status")
                    .arg(name("BASE_URL"))),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![(
            s("app.py"),
            s("status"),
            s("python:requests.get"),
            s("https://api.example.com/v1")
        )]
    );
}

#[test]
fn single_assignment_local_resolves_and_a_two_branch_local_is_expr() {
    let environ = r(imp("os"), &["environ"], ValueEscape, "os.environ");
    let ir = post_with(name("url"))
        .import(import_module("os"))
        .local(local_binding(
            "send",
            "url",
            subscript(environ.expr(), lit("REPORT_URL")),
        ));
    assert_eq!(one_dest(ir), "env:REPORT_URL");

    // Assigned in two branches: the frontend records no single-assignment
    // binding, so the name is unresolved.
    assert_eq!(one_dest(post_with(name("url"))), "expr:url");
}

#[test]
fn f_string_with_env_constant_is_a_template_with_a_hole() {
    let environ = r(imp("os"), &["environ"], ValueEscape, "os.environ");
    let ir = post_with(tmpl(vec![name("BASE"), lit("/v1")]))
        .import(import_module("os"))
        .constant(constant("BASE", subscript(environ.expr(), lit("BASE"))));
    let c = fx().file("a.py", ir).run();
    assert_eq!(c.sites[0].destination.display, "{env:BASE}/v1");
    assert_eq!(c.sites[0].destination.kind, DestinationKind::Template);
}

#[test]
fn f_string_with_a_parameter_is_a_template_with_a_param_hole() {
    let ir = post_with(tmpl(vec![
        lit("https://api.example.com/users/"),
        Expr::Param(1),
    ]));
    assert_eq!(one_dest(ir), "https://api.example.com/users/{param:1:send}");
}

#[test]
fn covers_ae22_encoded_destination_is_an_expr_site_without_a_blind_spot() {
    let decode = r(
        imp("base64"),
        &["b64decode", "decode"],
        Call,
        "base64.b64decode(blob).decode()",
    )
    .called_at(0);
    let ir = post_with(decode.expr())
        .import(import_module("base64"))
        .r(decode.clone());
    let c = fx().file("a.py", ir).run();
    assert_eq!(
        mechs(&c),
        vec![pair(
            "python:requests.post",
            "expr:base64.b64decode(blob).decode()"
        )]
    );
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
}

#[test]
fn config_attribute_destination_is_expr_of_the_reference() {
    let settings = r(
        imp("settings"),
        &["API_URL"],
        ValueEscape,
        "settings.API_URL",
    );
    let ir =
        post_with(settings.expr()).import(import(Some("settings"), "django.conf", &["settings"]));
    assert_eq!(one_dest(ir), "expr:settings.API_URL");
}

#[test]
fn subprocess_list_is_exec_of_the_program_and_cdll_is_lib() {
    let ir = py().import(import_module("subprocess")).r(r(
        imp("subprocess"),
        &["run"],
        Call,
        "subprocess.run([\"curl\", url])",
    )
    .arg(seq(vec![lit("curl"), name("url")])));
    let c = fx().file("a.py", ir).run();
    assert_eq!(mechs(&c), vec![pair("python:subprocess.run", "exec:curl")]);

    let ir = py().import(import_module("os")).r(r(
        imp("os"),
        &["system"],
        Call,
        "os.system(\"curl -s x\")",
    )
    .arg(lit("curl -s x")));
    let c = fx().file("a.py", ir).run();
    assert_eq!(mechs(&c), vec![pair("python:os.system", "exec:curl")]);

    let ir = py().import(import_module("ctypes")).r(r(
        imp("ctypes"),
        &["CDLL"],
        Call,
        "ctypes.CDLL(\"libc.so.6\")",
    )
    .arg(lit("libc.so.6")));
    let c = fx().file("a.py", ir).run();
    assert_eq!(mechs(&c), vec![pair("python:ctypes.CDLL", "lib:libc.so.6")]);
    assert_eq!(c.sites[0].destination.kind, DestinationKind::Lib);
}

#[test]
fn a_blind_spot_data_entry_yields_its_blind_spot() {
    let ir = py().import(import_module("ctypes")).r(r(
        imp("ctypes"),
        &["memmove"],
        Call,
        "ctypes.memmove(a, b, n)",
    ));
    let c = fx().file("a.py", ir).run();
    assert!(c.sites.is_empty());
    assert_eq!(kinds(&c), vec![s("native-code")]);
    assert_eq!(c.blind_spots[0].construct, "ctypes.memmove(a, b, n)");
    assert!(!c.blind_spots[0].coverage_gap);
}

#[test]
fn socket_tuple_is_host_port_and_keyword_is_used_when_positional_is_absent() {
    let ir = py().import(import_module("socket")).r(r(
        imp("socket"),
        &["create_connection"],
        Call,
        "socket.create_connection(..)",
    )
    .kwarg("address", seq(vec![lit("db.example"), lit("5432")])));
    let c = fx().file("a.py", ir).run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:socket.create_connection", "db.example:5432")]
    );
}

#[test]
fn missing_destination_argument_is_expr_of_the_call() {
    let ir = py().import(import_module("requests")).r(r(
        imp("requests"),
        &["post"],
        Call,
        "requests.post(**kw)",
    ));
    assert_eq!(one_dest(ir), "expr:requests.post(**kw)");
}

#[test]
fn literal_destination_is_redacted() {
    let ir = post_with(lit(
        "https://bob:hunter2@api.example.com/x?token=abc&page=2",
    ));
    let d = one_dest(ir);
    assert_eq!(
        d,
        "https://<redacted>@api.example.com/x?token=<redacted>&page=2"
    );
}

// ---- wrappers (R20) ----------------------------------------------------------

#[test]
fn covers_ae13_wrapper_param_is_one_site_and_callers_add_none() {
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
                    "post_json(\"https://a.example/u\", u)",
                )
                .sym("create_user")
                .arg(lit("https://a.example/u")))
                .r(r(
                    local("post_json"),
                    &[],
                    Call,
                    "post_json(\"https://a.example/t\", t)",
                )
                .sym("create_team")
                .arg(lit("https://a.example/t")))
                .r(r(
                    local("post_json"),
                    &[],
                    Call,
                    "post_json(\"https://e.example/i\", e)",
                )
                .sym("send_event")
                .arg(lit("https://e.example/i"))),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![(
            s("api.py"),
            s("post_json"),
            s("python:requests.post"),
            s("param:1:post_json")
        )]
    );
    assert_eq!(c.sites[0].destination.kind, DestinationKind::Param);
}

#[test]
fn method_wrapper_numbers_parameters_without_self() {
    // The frontend numbers parameters without `self` (KTD7); the core names
    // the method's symbol path.
    let c = fx()
        .file(
            "api.py",
            py().import(import_module("requests")).r(r(
                imp("requests"),
                &["get"],
                Call,
                "requests.get(url)",
            )
            .sym("Client.fetch")
            .arg(Expr::Param(1))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.get", "param:1:Client.fetch")]
    );
}

// ---- instances (KTD8) ---------------------------------------------------------

#[test]
fn session_local_yields_constructor_and_method_sites() {
    let ctor = r(imp("requests"), &["Session"], Call, "requests.Session()").sym("f");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .r(ctor.clone())
                .local(local_binding("f", "s", ctor.expr()))
                .r(r(local("s"), &["get"], Call, "s.get(u)")
                    .sym("f")
                    .arg(lit("https://u.example"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![
            pair("python:requests.Session", "expr:requests.Session()"),
            pair("python:requests.Session.get", "https://u.example"),
        ]
    );
}

#[test]
fn returned_session_yields_only_the_constructor_site() {
    let ctor = r(imp("requests"), &["Session"], Call, "requests.Session()").sym("f");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .r(ctor.clone())
                .local(local_binding("f", "s", ctor.expr()))
                .r(r(local("s"), &[], ValueEscape, "s").sym("f")),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.Session", "expr:requests.Session()")]
    );
}

#[test]
fn method_without_a_data_entry_on_a_tracked_instance_is_no_site() {
    let ctor = r(imp("socket"), &["socket"], Call, "socket.socket()").sym("probe");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("socket"))
                .r(ctor.clone())
                .local(local_binding("probe", "s", ctor.expr()))
                .r(r(local("s"), &["connect"], Call, "s.connect(..)")
                    .sym("probe")
                    .arg(seq(vec![lit("api.example.com"), lit("443")])))
                .r(r(local("s"), &["close"], Call, "s.close()").sym("probe")),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![
            pair("python:socket.socket", "expr:socket.socket()"),
            pair("python:socket.socket.connect", "api.example.com:443"),
        ]
    );
}

#[test]
fn local_in_another_function_is_not_tracked() {
    let ctor = r(imp("requests"), &["Session"], Call, "requests.Session()").sym("f");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .r(ctor.clone())
                .local(local_binding("f", "s", ctor.expr()))
                .r(r(local("s"), &["get"], Call, "s.get(u)")
                    .sym("g")
                    .arg(lit("https://u.example"))),
        )
        .run();
    assert_eq!(mechs(&c).len(), 1);
}

#[test]
fn running_loop_yields_constructor_and_create_connection_host_port() {
    let ctor = r(
        imp("asyncio"),
        &["get_running_loop"],
        Call,
        "asyncio.get_running_loop()",
    )
    .sym("main");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("asyncio"))
                .r(ctor.clone())
                .local(local_binding("main", "loop", ctor.expr()))
                .r(r(
                    local("loop"),
                    &["create_connection"],
                    Call,
                    "loop.create_connection(h, 80)",
                )
                .sym("main")
                .arg(lit("h"))
                .arg(lit("80"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![
            pair(
                "python:asyncio.get_running_loop",
                "expr:asyncio.get_running_loop()"
            ),
            pair("python:asyncio.get_running_loop.create_connection", "h:80"),
        ]
    );
}

#[test]
fn attribute_held_client_assigned_once_in_init_is_tracked() {
    let ctor = r(imp("requests"), &["Session"], Call, "requests.Session()").sym("Api.__init__");
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .sym(class("Api"))
                .r(ctor.clone())
                .self_attr(self_attr("Api", "s", ctor.expr()))
                .r(r(
                    egress_core::ir::Root::SelfValue,
                    &["s", "get"],
                    Call,
                    "self.s.get(u)",
                )
                .sym("Api.users")
                .arg(lit("https://api.example.com/users"))),
        )
        .run();
    assert_eq!(
        sites(&c),
        vec![
            (
                s("a.py"),
                s("Api.__init__"),
                s("python:requests.Session"),
                s("expr:requests.Session()")
            ),
            (
                s("a.py"),
                s("Api.users"),
                s("python:requests.Session.get"),
                s("https://api.example.com/users")
            ),
        ]
    );
}

#[test]
fn must_not_attribute_assigned_twice_or_outside_init_is_not_tracked() {
    let ctor = r(imp("requests"), &["Session"], Call, "requests.Session()").sym("Api.__init__");
    let use_ = r(
        egress_core::ir::Root::SelfValue,
        &["s", "get"],
        Call,
        "self.s.get(u)",
    )
    .sym("Api.users")
    .arg(lit("https://api.example.com/users"));
    // Assigned twice in `__init__`.
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .r(ctor.clone())
                .self_attr(self_attr("Api", "s", ctor.expr()))
                .self_attr(self_attr("Api", "s", ctor.expr()))
                .r(use_.clone()),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.Session", "expr:requests.Session()")]
    );

    // Assigned once in `__init__` and again in another method.
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .r(ctor.clone())
                .self_attr(self_attr("Api", "s", ctor.expr()))
                .r(r(
                    egress_core::ir::Root::SelfValue,
                    &["s"],
                    AssignmentTarget,
                    "self.s",
                )
                .sym("Api.reset"))
                .r(use_.clone()),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("python:requests.Session", "expr:requests.Session()")]
    );

    // Assigned only outside `__init__`: no self attribute is recorded.
    let c = fx()
        .file(
            "a.py",
            py().import(import_module("requests"))
                .r(r(
                    egress_core::ir::Root::SelfValue,
                    &["s"],
                    AssignmentTarget,
                    "self.s",
                )
                .sym("Api.setup"))
                .r(use_),
        )
        .run();
    assert!(c.sites.is_empty(), "{:?}", c.sites);
}

#[test]
fn js_options_object_and_call_apply_shift_the_destination() {
    let o = obj(vec![("host", lit("db.example")), ("port", lit("5432"))]);
    let base = || js().import(import_module("net"));
    // net.connect(o) with an options object.
    let c = fx()
        .file(
            "a.js",
            base().r(r(imp("net"), &["connect"], Call, "net.connect(o)").arg(o.clone())),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("javascript:net.connect", "db.example:5432")]
    );

    // net.connect.call(null, o) takes the destination from o, bound to a local.
    let c = fx()
        .file(
            "a.js",
            base().local(local_binding("<module>", "o", o.clone())).r(r(
                imp("net"),
                &["connect", "call"],
                Call,
                "net.connect.call(null, o)",
            )
            .arg(opaque("null"))
            .arg(name("o"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("javascript:net.connect", "db.example:5432")]
    );

    // net.connect.apply(null, [o]) takes it from the literal array.
    let c = fx()
        .file(
            "a.js",
            base().r(r(
                imp("net"),
                &["connect", "apply"],
                Call,
                "net.connect.apply(null, [o])",
            )
            .arg(opaque("null"))
            .arg(seq(vec![o.clone()]))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("javascript:net.connect", "db.example:5432")]
    );

    // .apply with a non-literal array is expr:.
    let c = fx()
        .file(
            "a.js",
            base().r(r(
                imp("net"),
                &["connect", "apply"],
                Call,
                "net.connect.apply(null, args)",
            )
            .arg(opaque("null"))
            .arg(name("args"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair(
            "javascript:net.connect",
            "expr:net.connect.apply(null, args)"
        )]
    );

    // Reflect.apply(net.connect, null, args): the value use is an expr: site.
    let c = fx()
        .file(
            "a.js",
            base()
                .r(r(imp("net"), &["connect"], ValueEscape, "net.connect"))
                .r(r(
                    amb("Reflect"),
                    &["apply"],
                    Call,
                    "Reflect.apply(net.connect, null, args)",
                )),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("javascript:net.connect", "expr:net.connect")]
    );
}

#[test]
fn js_default_import_names_the_module_itself() {
    let mut i = import(Some("axios"), "axios", &[]);
    i.default = true;
    let c = fx()
        .file(
            "a.js",
            js().import(i)
                .r(r(imp("axios"), &["get"], Call, "axios.get(u)").arg(lit("https://a.example"))),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![pair("javascript:axios.get", "https://a.example")]
    );
}

#[test]
fn node_prefix_is_stripped() {
    let c = fx()
        .file(
            "a.js",
            js().import(import(Some("connect"), "node:net", &["connect"]))
                .r(r(imp("connect"), &[], Call, "connect(80, \"h\")")
                    .arg(lit("80"))
                    .arg(lit("h"))),
        )
        .run();
    assert_eq!(mechs(&c), vec![pair("javascript:net.connect", "h:80")]);
}

#[test]
fn special_entry_ids_exist_in_the_embedded_data_as_blind_spot_entries() {
    let d = egress_core::data::Data::embedded().unwrap();
    for id in egress_core::classify::special_entry_ids() {
        let lang = egress_core::model::Language::parse(id.split(':').next().unwrap()).unwrap();
        let e = d
            .runtime(lang)
            .entry(id)
            .unwrap_or_else(|| panic!("{id} is not a data entry"));
        assert_eq!(e.kind.as_str(), "blind-spot", "{id}");
    }
}

#[test]
fn rust_tracked_client_methods_sit_on_the_type_beside_the_constructor() {
    let ctor = r(imp("Client"), &["new"], Call, "Client::new()").sym("fetch");
    let c = fx()
        .file(
            "src/lib.rs",
            rs().import(import(Some("Client"), "reqwest", &["Client"]))
                .r(ctor.clone())
                .local(local_binding("fetch", "c", ctor.expr()))
                .r(r(local("c"), &["get"], Call, "c.get(u)")
                    .sym("fetch")
                    .arg(lit("https://r.example")))
                .r(r(local("c"), &["new"], Call, "c.new()").sym("fetch")),
        )
        .run();
    assert_eq!(
        mechs(&c),
        vec![
            pair("rust:reqwest::Client::get", "https://r.example"),
            pair("rust:reqwest::Client::new", "expr:Client::new()"),
        ]
    );
}

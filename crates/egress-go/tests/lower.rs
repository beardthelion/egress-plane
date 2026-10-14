//! Lowering behavior through `egress_go::lower` and the registered
//! frontend: gosyn traps, the depth-cap reason, the package clause, and
//! error mapping.

use egress_go::LowerError;

fn lower(src: &str) -> Result<egress_core::ir::FileIr, LowerError> {
    let src = src.to_string();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || egress_go::lower(b"main.go", &src))
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn the_package_clause_lands_in_the_ir() {
    let ir = lower("package foo\n\nfunc f() {}\n").unwrap();
    assert_eq!(ir.package.as_deref(), Some("foo"));
}

#[test]
fn gosyn_pos_traps_do_not_panic() {
    // `f[int, string](x)` hits the `Expression::List` pos() trap; a
    // bare func declaration hits the `FieldList` trap.
    assert!(lower("package main\n\nfunc f[T, U any](x T) {}\nvar _ = f[int, string](1)\n").is_ok());
    assert!(lower("package main\n\nfunc f() {}\n").is_ok());
}

#[test]
fn parens_over_gosyns_cap_report_too_deeply_nested() {
    // 70 nested parens: under the core bracket bound, over gosyn's 64.
    let src = format!(
        "package main\n\nvar x = {}1{}\n",
        "(".repeat(70),
        ")".repeat(70)
    );
    assert_eq!(lower(&src), Err(LowerError::TooDeeplyNested));
}

#[test]
fn gosyn_reports_error_lines_one_lower() {
    // A syntax error on line 4 reports line 3 (a gosyn bug; a fixed
    // upgrade turns this test red).
    let err = gosyn::parse_source("package main\n\nfunc f() {\n    @\n}\n")
        .expect_err("the @ is a syntax error");
    let e = err.downcast_ref::<gosyn::Error>().expect("gosyn error");
    match e {
        gosyn::Error::UnexpectedToken { location, .. } | gosyn::Error::Else { location, .. } => {
            assert_eq!(location.0, 3, "gosyn line reports shifted by one");
        }
        other => panic!("expected a position error, got {other:?}"),
    }
}

#[test]
fn a_guarded_panic_is_parse_not_abort() {
    let out = egress_core::discover::guard(|| panic!("boom"));
    assert!(out.is_none(), "the panic is caught");
}

#[test]
fn registry_lists_go_and_maps_errors() {
    let r = egress_scan::registry::Registry::builtin();
    assert!(r.get(egress_core::model::Language::Go).is_some());
    assert_eq!(
        egress_scan::registry::FrontendError::from(LowerError::Parse),
        egress_scan::registry::FrontendError::Parse
    );
    assert_eq!(
        egress_scan::registry::FrontendError::from(LowerError::TooDeeplyNested),
        egress_scan::registry::FrontendError::TooDeeplyNested
    );
}

/// The full `lower` path over every stdlib file, including the
/// compiler's pathological `test/` suite: no abort, no panic escape.
/// `GOROOT=$(go env GOROOT) cargo test -p egress-go -- --ignored`.
#[test]
#[ignore = "needs a Go installation; GOROOT must be set"]
fn stdlib_files_survive_the_full_lower_path() {
    let goroot = std::env::var("GOROOT").expect("GOROOT unset");
    let mut too_deep = 0;
    let mut checked = 0;
    for root in ["src", "test"] {
        let root = std::path::Path::new(&goroot).join(root);
        let mut stack = vec![root];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "go") {
                    let text = std::fs::read_to_string(&p).unwrap();
                    let src2 = text.clone();
                    let r = std::thread::Builder::new()
                        .stack_size(64 * 1024 * 1024)
                        .spawn(move || egress_go::lower(b"f.go", &src2))
                        .unwrap()
                        .join();
                    assert!(r.is_ok(), "panic escaped on {p:?}");
                    let is_testdata = p.to_string_lossy().contains("testdata");
                    if r.unwrap() == Err(LowerError::TooDeeplyNested) && !is_testdata {
                        too_deep += 1;
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 1000, "too few files: {checked}");
    assert_eq!(too_deep, 0, "non-testdata files tripped a bound");
}

// ---- the walker ---------------------------------------------------------------

use egress_core::ir::{ConstructKind, Expr, FileIr, Provenance, Reference, Root, UseKind};

fn ir(src: &str) -> FileIr {
    let src = format!("package p\n\n{src}");
    lower(&src).unwrap()
}

fn refs(ir: &FileIr, kind: UseKind) -> Vec<&Reference> {
    ir.references
        .iter()
        .filter(|r| r.use_kind == kind)
        .collect()
}

fn is_client(r: &&Reference) -> bool {
    matches!(&r.root, Root::Import(l) if l == "http") && r.members == ["Client"]
}

/// `import "net/http"` binds `http`; every other specifier name lands on
/// the import's local.
#[test]
fn import_locals_follow_the_go_name_rules() {
    let ir = ir("import \"net/http\"\n\
         import nh \"net/http/httputil\"\n\
         import \"gopkg.in/yaml.v3\"\n\
         import \"github.com/redis/go-redis/v9\"\n");
    let locals: Vec<_> = ir
        .imports
        .iter()
        .map(|i| (i.specifier.as_str(), i.local.as_deref()))
        .collect();
    assert_eq!(
        locals,
        [
            ("net/http", Some("http")),
            ("net/http/httputil", Some("nh")),
            ("gopkg.in/yaml.v3", Some("yaml")),
            ("github.com/redis/go-redis/v9", Some("redis")),
        ]
    );
    assert!(ir.imports.iter().all(|i| i.symbol == "<module>" && !i.star));
}

#[test]
fn a_dot_import_is_a_star_and_names_go_unqualified() {
    let ir = ir("import . \"net/http\"\n\nfunc f() { Get(\"u\") }\n");
    let star = &ir.imports[0];
    assert!(star.star && star.local.is_none() && star.specifier == "net/http");
    let calls = refs(&ir, UseKind::Call);
    assert_eq!(calls.len(), 1);
    // The lowerer cannot say which file the name comes from; the core's
    // star-import lookup finishes it.
    assert!(matches!(calls[0].root, Root::Ambient(ref n) if n == "Get"));
}

#[test]
fn a_blank_import_is_a_value_use_of_the_whole_package() {
    let ir = ir("import _ \"net/mail\"\n");
    let escapes = refs(&ir, UseKind::ValueEscape);
    assert_eq!(escapes.len(), 1);
    assert!(matches!(&escapes[0].root, Root::Import(l) if l.starts_with("_#")));
    assert!(escapes[0].members.is_empty());
    assert_eq!(escapes[0].location.line, 3);
}

#[test]
fn a_qualified_call_is_a_call_reference() {
    let ir = ir("import \"net/http\"\n\n\
         func main() { http.Get(\"https://api.example.com/v1/ping\") }\n");
    let calls = refs(&ir, UseKind::Call);
    assert_eq!(calls.len(), 1);
    let c = calls[0];
    assert!(matches!(&c.root, Root::Import(l) if l == "http"));
    assert_eq!(c.members, ["Get"]);
    assert_eq!(c.calls_in_chain, [0]);
    assert_eq!(
        c.args,
        [Expr::Literal("https://api.example.com/v1/ping".into())]
    );
    assert_eq!(c.symbol, "main");
    // The site sits at the callee's `h`, not the call's `(`.
    assert_eq!(c.location.column, "func main() { ".len() as u32 + 1);
}

#[test]
fn a_deeper_selector_call_keeps_its_members() {
    let ir = ir("import \"net/http\"\n\nfunc f() { http.DefaultClient.Do(nil) }\n");
    let calls = refs(&ir, UseKind::Call);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].members, ["DefaultClient", "Do"]);
}

#[test]
fn a_typed_var_binds_the_constructor_type() {
    let ir = ir("import \"net/http\"\n\nfunc f() {\nvar c http.Client\nc.Get(u)\n}\n");
    let constructs = refs(&ir, UseKind::Construct);
    assert_eq!(constructs.len(), 1);
    assert!(is_client(&constructs[0]));
    assert_eq!(constructs[0].symbol, "f");
    let calls = refs(&ir, UseKind::Call);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].members, ["Client", "Get"]);
    // `c` is a local binding to the construct.
    let c = ir.locals.iter().find(|l| l.name == "c").expect("c binds");
    assert_eq!(c.symbol, "f");
    assert!(matches!(&c.value, Expr::Reference(r) if r.use_kind == UseKind::Construct));
}

#[test]
fn a_package_level_typed_var_constructs_under_module() {
    let ir = ir("import \"net/http\"\n\nvar c http.Client\n\nfunc f() { c.Get(u) }\n");
    let constructs = refs(&ir, UseKind::Construct);
    assert_eq!(constructs.len(), 1);
    assert_eq!(constructs[0].symbol, "<module>");
    let calls = refs(&ir, UseKind::Call);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].members, ["Client", "Get"]);
}

#[test]
fn new_composite_and_address_forms_construct() {
    let ir = ir("import \"net/http\"\n\nfunc f() {\n\
         _ = new(http.Client)\n\
         _ = http.Client{}\n\
         _ = &http.Client{Timeout: 1}\n\
         }\n");
    let constructs = refs(&ir, UseKind::Construct);
    assert_eq!(constructs.len(), 3);
    assert!(constructs.iter().all(is_client));
}

#[test]
fn a_pointer_var_is_a_type_position_not_a_construct() {
    let ir = ir("import \"net/http\"\n\nfunc f() { var c *http.Client; _ = c }\n");
    assert!(refs(&ir, UseKind::Construct).is_empty());
    let types = refs(&ir, UseKind::TypePosition);
    assert!(types.iter().any(is_client));
}

#[test]
fn function_values_are_value_escapes() {
    let ir = ir(
        "import \"net/http\"\nimport \"os\"\n\nfunc f(run func(string)) {\n\
         _ = http.Get\n\
         run(http.Get)\n\
         }\n",
    );
    let escapes = refs(&ir, UseKind::ValueEscape);
    let gets: Vec<_> = escapes.iter().filter(|r| r.members == ["Get"]).collect();
    assert_eq!(gets.len(), 2);
}

#[test]
fn go_and_defer_emit_call_references() {
    let ir = ir("import \"net/http\"\n\nfunc f() {\nvar c http.Client\n\
         go http.Get(u)\n\
         defer c.Close()\n\
         }\n");
    let calls = refs(&ir, UseKind::Call);
    let members: Vec<_> = calls.iter().map(|r| r.members.as_slice()).collect();
    assert!(members.iter().any(|m| *m == ["Get"].as_slice()));
    assert!(members.iter().any(|m| *m == ["Client", "Close"].as_slice()));
}

#[test]
fn an_embedded_type_is_a_value_use_not_a_construct() {
    let ir = ir("import \"net/http\"\n\n\
         type C struct {\n\thttp.Client\n\tcl http.Client\n\tp *http.Cookie\n}\n");
    let escapes: Vec<_> = refs(&ir, UseKind::ValueEscape)
        .into_iter()
        .filter(|r| r.symbol == "<module>")
        .collect();
    assert!(escapes.iter().any(|r| r.members == ["Client"]));
    // A named field is a value-carrying position.
    let constructs = refs(&ir, UseKind::Construct);
    assert!(constructs.iter().any(|r| r.members == ["Client"]));
    // A pointer field is a plain type position.
    let types = refs(&ir, UseKind::TypePosition);
    assert!(types.iter().any(|r| r.members.as_slice() == ["Cookie"]));
}

#[test]
fn value_carrying_type_positions_construct() {
    let ir = ir("import \"net/http\"\n\ntype Client = http.Client\n\n\
         func mk() (c http.Client) { return }\n\
         func f() {\n\
         \tvar cs [2]http.Client\n\
         \t_ = cs\n\
         \t_ = make([]http.Client, 3)\n\
         \tvar c Client\n\
         \t_ = c\n\
         }\n");
    let constructs = refs(&ir, UseKind::Construct);
    assert!(
        constructs.len() >= 4,
        "named result, array var, make slice, alias: {constructs:?}"
    );
    assert!(constructs.iter().all(is_client));
    // The named result carries a Construct; the alias `var c Client`
    // resolves through the alias target.
    assert!(constructs.iter().any(|r| r.symbol == "mk"));
    assert!(constructs.iter().any(|r| r.text == "Client"));
}

#[test]
fn an_elided_literal_is_a_resolution_limit() {
    let ir = ir("import \"net/http\"\n\nfunc f() {\n\
         \t_ = []http.Client{{Timeout: 1}}\n\
         \t_ = http.Client{Jar: {}}\n\
         }\n");
    let limits: Vec<_> = ir
        .constructs
        .iter()
        .filter(|c| c.kind == egress_core::ir::ConstructKind::ResolutionLimit)
        .collect();
    assert_eq!(limits.len(), 2, "{:?}", ir.constructs);
}

#[test]
fn a_local_type_elided_literal_is_not_flagged() {
    let ir = ir("type Point struct{ x, y int }\n\nfunc f() { _ = []Point{{1, 2}} }\n");
    assert!(ir.constructs.is_empty());
}

#[test]
fn a_package_var_candidate_is_a_module_local() {
    let ir = ir("var endpoint = \"https://api.example.com/v1/ping\"\n");
    let l = ir
        .locals
        .iter()
        .find(|l| l.name == "endpoint")
        .expect("endpoint binds");
    assert_eq!(l.symbol, "<module>");
    assert_eq!(
        l.value,
        Expr::Literal("https://api.example.com/v1/ping".into())
    );
    assert!(ir.constants.iter().all(|c| c.name != "endpoint"));
}

#[test]
fn package_var_mutations_drop_the_binding_and_leave_a_record() {
    for body in ["u = \"y\"", "u++", "f(&u)", "f(&u.field)"] {
        let ir = ir(&format!(
            "var u = \"https://x\"\nvar v = 0\n\nfunc f(p *string) {{ {body} }}\n"
        ));
        assert!(
            ir.locals.iter().all(|l| l.name != "u"),
            "{body}: u must not bind"
        );
    }
    // `=` and `&` leave an `AssignmentTarget` record for `link` to read.
    let ir = ir("var u = \"x\"\n\nfunc f(p *string) { u = \"y\"; f(&u) }\n");
    let targets = refs(&ir, UseKind::AssignmentTarget);
    assert_eq!(targets.len(), 2, "{:?}", ir.references);
    assert!(
        targets
            .iter()
            .all(|r| matches!(&r.root, Root::Local(n) if n == "u"))
    );
}

#[test]
fn const_declarations_lower_to_module_constants() {
    let ir = ir("const Exported = \"v\"\n\
         const hidden = `raw\nstr`\n\
         const esc = \"a\\nb\"\n\
         const (\n\ta = \"x\"\n\tb\n\tk = iota\n\tm\n)\n");
    let get = |n: &str| ir.constants.iter().find(|c| c.name == n).unwrap();
    assert!(get("Exported").exported);
    assert!(!get("hidden").exported);
    assert_eq!(get("hidden").value, Expr::Literal("raw\nstr".into()));
    assert_eq!(get("esc").value, Expr::Literal("a\nb".into()));
    // A grouped spec with no values repeats the previous expression.
    assert_eq!(get("b").value, Expr::Literal("x".into()));
    // `iota` is never guessed.
    assert!(matches!(get("k").value, Expr::Opaque(_)));
    assert!(matches!(get("m").value, Expr::Opaque(_)));
}

#[test]
fn a_string_concat_is_a_template() {
    let ir =
        ir("const base = \"https://api.example.com\"\n\nfunc f() { u := base + \"/v1\"; _ = u }\n");
    let u = ir.locals.iter().find(|l| l.name == "u").unwrap();
    assert_eq!(
        u.value,
        Expr::Template(vec![Expr::Name("base".into()), Expr::Literal("/v1".into())])
    );
}

#[test]
fn single_assignment_locals_bind_and_reassignment_drops_them() {
    let ir = ir(
        "func f() {\n\tx := \"a\"\n\ty := \"b\"\n\ty = \"c\"\n\tz := f2()\n\t_ = x\n\t_ = z\n}\n",
    );
    let names: Vec<_> = ir.locals.iter().map(|l| l.name.as_str()).collect();
    assert!(names.contains(&"x"));
    assert!(names.contains(&"z"));
    assert!(!names.contains(&"y"), "reassigned locals do not bind");
}

#[test]
fn symbol_paths_follow_the_shape() {
    let top = ir("import \"net/http\"\n\n\
         func Get() {}\n\
         type Store[K, V any] struct{ m map[K]V }\n\
         func (s *Store[K, V]) Put(k K) {}\n\
         func init() {}\n\
         func init() {}\n\
         func f() { g := func() { os.Getenv(\"X\") }; g() }\n");
    let paths: Vec<_> = top.symbols.iter().map(|s| s.path.as_str()).collect();
    assert!(paths.contains(&"Get"));
    assert!(paths.contains(&"Store.Put"));
    assert!(paths.contains(&"init"));
    assert!(paths.contains(&"init#2"));
    assert!(paths.contains(&"f.<closure>"));
    // Package-level initializers live under `<module>`: the `var` below.
    let ir2 = ir("import \"net/http\"\n\nvar c = http.Client{}\n");
    let constructs = refs(&ir2, UseKind::Construct);
    assert_eq!(constructs[0].symbol, "<module>");
}

#[test]
fn a_method_on_a_typed_param_resolves_its_chain() {
    let ir = ir("import \"net/http\"\n\nfunc f(c *http.Client) { c.Get(u) }\n");
    let calls = refs(&ir, UseKind::Call);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].members, ["Client", "Get"]);
}

#[test]
fn the_call_argument_exprs_drive_destinations() {
    let ir = ir("import \"net/http\"\nimport \"os\"\n\nfunc f(u string) {\n\
         \thttp.Get(u)\n\
         \thttp.Get(os.Getenv(\"HOME\"))\n\
         }\n");
    let calls = refs(&ir, UseKind::Call);
    let get = calls.iter().find(|r| r.members == ["Get"]).unwrap();
    assert_eq!(get.args, [Expr::Param(1)]);
    let getenv = calls.iter().find(|r| r.members == ["Getenv"]).unwrap();
    assert_eq!(getenv.args, [Expr::Literal("HOME".into())]);
    // `http.Get(os.Getenv("HOME"))`'s argument is the call's reference.
    let nested = calls
        .iter()
        .filter(|r| r.members == ["Get"])
        .nth(1)
        .unwrap();
    assert!(
        matches!(&nested.args[0], Expr::Reference(r) if r.members == ["Getenv"]),
        "{:?}",
        nested.args
    );
}

// ---- directives and native code (KTD7, KTD12) --------------------------------

fn constructs(ir: &FileIr, kind: ConstructKind) -> Vec<&egress_core::ir::DynamicConstruct> {
    ir.constructs.iter().filter(|c| c.kind == kind).collect()
}

#[test]
fn cgo_import_is_native_code_and_an_unfollowed_binding() {
    let ir = ir("import \"C\"\n\nfunc f() { C.puts(nil) }\n");
    let imp = &ir.imports[0];
    assert_eq!(imp.specifier, "C");
    assert_eq!(imp.local.as_deref(), Some("C"));
    // The record stays so `C.` chains are import-rooted; `type_only`
    // keeps the resolver from following it anywhere.
    assert!(imp.type_only);
    let native = constructs(&ir, ConstructKind::NativeCode);
    assert_eq!(native.len(), 1);
    assert_eq!(native[0].symbol, "<module>");
    assert_eq!(native[0].location.line, 3);
    // `C.puts` stays a reference; it resolves through the inert import.
    assert!(
        ir.references
            .iter()
            .any(|r| matches!(&r.root, Root::Import(l) if l == "C"))
    );
}

#[test]
fn linkname_directives_are_native_code() {
    let ir = ir("//go:linkname local runtime.nanotime\n\nfunc local() int64 { return 0 }\n");
    let native = constructs(&ir, ConstructKind::NativeCode);
    assert_eq!(native.len(), 1);
    let c = native[0];
    assert_eq!(c.symbol, "<module>");
    assert_eq!(c.location.line, 3);
    assert_eq!(c.location.column, 1);
    assert!(c.text.contains("//go:linkname local runtime.nanotime"));
}

#[test]
fn a_spaced_linkname_comment_is_not_a_directive() {
    let ir = ir("// go:linkname local runtime.nanotime\n\nfunc main() {}\n");
    assert!(ir.constructs.is_empty());
}

#[test]
fn generate_directives_are_build_hooks() {
    let ir =
        ir("//go:generate stringer -type=Pill\n\nfunc main() {}\n\n//go:generate\tgo run gen.go\n");
    let hooks = constructs(&ir, ConstructKind::BuildHook);
    assert_eq!(hooks.len(), 2);
    assert_eq!(hooks[0].symbol, "<module>");
    assert!(hooks[0].text.contains("stringer -type=Pill"));
    assert_eq!(hooks[0].location.line, 3);
    assert_eq!(hooks[1].location.line, 7);
    assert_eq!(hooks[1].location.column, 1);
}

#[test]
fn generate_inside_raw_strings_and_block_comments_counts() {
    let ir = ir(
        "var s = `\n//go:generate inside raw\n`\n\n/*\n//go:generate inside block\n*/\n\nfunc main() {}\n",
    );
    let hooks = constructs(&ir, ConstructKind::BuildHook);
    assert_eq!(hooks.len(), 2);
    assert!(hooks.iter().all(|h| h.location.column == 1));
    assert!(hooks.iter().all(|h| h.symbol == "<module>"));
}

#[test]
fn indented_and_spaced_generate_lines_are_not_directives() {
    let ir = ir("\t//go:generate indented\n// go:generate spaced\n\nfunc main() {}\n");
    assert!(ir.constructs.is_empty());
}

// ---- reflect chains (KTD12) ---------------------------------------------------

fn computed(ir: &FileIr) -> Vec<&Reference> {
    refs(ir, UseKind::ComputedMember)
}

#[test]
fn a_reflect_lookup_on_a_parameter_is_a_computed_member() {
    let ir = ir(
        "import \"reflect\"\n\nfunc f(v any, name string) {\n\treflect.ValueOf(v).MethodByName(name)\n}\n",
    );
    let c = computed(&ir);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].root, Root::Param(1));
    assert!(c[0].members.is_empty());
    assert_eq!(c[0].receiver, Some(Provenance::Parameter(1)));
    assert_eq!(c[0].symbol, "f");
}

#[test]
fn a_reflect_lookup_on_a_typed_var_is_import_rooted() {
    let ir = ir(
        "import (\n\t\"net/http\"\n\t\"reflect\"\n)\n\nvar client http.Client\n\nfunc f(name string) {\n\treflect.ValueOf(client).MethodByName(name)\n}\n",
    );
    let c = computed(&ir);
    assert_eq!(c.len(), 1);
    assert!(
        matches!(&c[0].root, Root::Import(l) if l == "http"),
        "{:?}",
        c[0].root
    );
    assert_eq!(c[0].members, ["Client"]);
    assert_eq!(c[0].receiver, Some(Provenance::TrackedConstructor));
}

#[test]
fn a_reflect_bound_local_carries_the_chain_target() {
    let ir = ir(
        "import \"reflect\"\n\nfunc f(v any, name string) {\n\trv := reflect.ValueOf(v)\n\trv.MethodByName(name)\n\trv.FieldByName(name)\n}\n",
    );
    let c = computed(&ir);
    assert_eq!(c.len(), 2);
    assert!(c.iter().all(|r| r.root == Root::Param(1)));
    assert!(
        c.iter()
            .all(|r| r.receiver == Some(Provenance::Parameter(1)))
    );
}

#[test]
fn typeof_supports_the_same_lookups() {
    let ir = ir(
        "import \"reflect\"\n\nfunc f(v any, name string) {\n\treflect.TypeOf(v).FieldByName(name)\n\treflect.ValueOf(v).MethodByIndex(name)\n}\n",
    );
    let c = computed(&ir);
    assert_eq!(c.len(), 2);
    assert!(c.iter().all(|r| r.root == Root::Param(1)));
}

#[test]
fn a_literal_reflect_name_is_an_ordinary_member() {
    let ir = ir(
        "import \"reflect\"\n\nfunc f(v any) {\n\treflect.ValueOf(v).MethodByName(\"Get\")\n}\n",
    );
    assert!(computed(&ir).is_empty());
    let member = ir
        .references
        .iter()
        .find(|r| r.members == ["Get"])
        .expect("a member reference for the literal name");
    assert_eq!(member.root, Root::Param(1));
    assert_eq!(member.use_kind, UseKind::ValueEscape);
}

#[test]
fn a_literal_lookup_then_call_is_not_reflective() {
    let ir = ir(
        "import \"reflect\"\n\nfunc f(v any) {\n\treflect.ValueOf(v).MethodByName(\"Get\").Call(nil)\n}\n",
    );
    assert!(computed(&ir).is_empty());
}

#[test]
fn call_and_call_slice_dispatch_reflectively() {
    let ir = ir(
        "import \"reflect\"\n\nfunc f(v any, name string) {\n\treflect.ValueOf(v).MethodByName(name).Call(nil)\n\treflect.ValueOf(v).CallSlice(nil)\n}\n",
    );
    // The lookup and both dispatches: three computed members on `v`.
    let c = computed(&ir);
    assert_eq!(c.len(), 3);
    assert!(c.iter().all(|r| r.root == Root::Param(1)));
}

#[test]
fn a_literal_index_lookup_emits_nothing() {
    let ir = ir("import \"reflect\"\n\nfunc f(v any) {\n\treflect.ValueOf(v).Method(0)\n}\n");
    assert!(computed(&ir).is_empty());
}

#[test]
fn a_reassigned_local_loses_its_reflect_binding() {
    let ir = ir(
        "import \"reflect\"\n\nfunc f(v any, name string) {\n\trv := reflect.ValueOf(v)\n\trv = plain()\n\trv.MethodByName(name)\n}\n\nfunc plain() any { return nil }\n",
    );
    assert!(computed(&ir).is_empty());
}

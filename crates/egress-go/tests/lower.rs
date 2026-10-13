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

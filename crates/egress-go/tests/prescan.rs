//! The prescan bounds are pinned just under and just over each limit
//! (KTD6): the "just over" case returns `TooDeeplyNested` before gosyn
//! can recurse into the shape.

use egress_go::LowerError;

/// `lower` runs on a 64 MiB stack, matching the scan's worker threads;
/// the test thread's default stack cannot hold the deepest legal inputs.
fn lower(src: &str) -> Result<(), LowerError> {
    let src = src.to_string();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || egress_go::lower(b"main.go", &src).map(|_| ()))
        .unwrap()
        .join()
        .unwrap()
}

fn wrap(stmt: &str) -> String {
    format!("package main\n\nfunc main() {{\n{stmt}\n}}\n")
}

#[test]
fn prefix_unary_run_at_the_bound() {
    let ok = wrap(&format!("x := {}true", "!".repeat(1024 - 2)));
    assert!(lower(&ok).is_ok(), "{:?}", lower(&ok));
    let over = wrap(&format!("x := {}true", "!".repeat(1024 + 2)));
    assert_eq!(lower(&over), Err(LowerError::TooDeeplyNested));
}

#[test]
fn else_if_chain_at_the_bound() {
    let mut ok = String::from("if a {\n");
    for _ in 0..1023 {
        ok.push_str("} else if b {\n");
    }
    ok.push('}');
    assert!(lower(&wrap(&ok)).is_ok());
    let mut over = String::from("if a {\n");
    for _ in 0..1030 {
        over.push_str("} else if b {\n");
    }
    over.push('}');
    assert_eq!(lower(&wrap(&over)), Err(LowerError::TooDeeplyNested));
}

#[test]
fn consecutive_labels_at_the_bound() {
    let ok: String = (0..512 - 2).map(|i| format!("L{i}:\n")).collect::<String>() + "x++\n";
    assert!(lower(&wrap(&ok)).is_ok(), "{:?}", lower(&wrap(&ok)));
    let over: String = (0..512 + 4).map(|i| format!("L{i}:\n")).collect::<String>() + "x++\n";
    assert_eq!(lower(&wrap(&over)), Err(LowerError::TooDeeplyNested));
}

#[test]
fn statement_chain_at_the_bound() {
    // A selector chain continued past newlines by a trailing dot is one
    // statement per the semicolon-insertion rule.
    let ok = wrap(&format!("x := a{}\n", ".b".repeat(32_768 - 8)));
    assert!(lower(&ok).is_ok(), "{:?}", lower(&ok));
    let over = wrap(&format!("x := a{}\n", ".b".repeat(32_768 + 8)));
    assert_eq!(lower(&over), Err(LowerError::TooDeeplyNested));
    // The same bound on a call chain and a binary chain.
    let call = wrap(&format!("x := f{}\n", "()".repeat(32_768 + 8)));
    assert_eq!(lower(&call), Err(LowerError::TooDeeplyNested));
    let bin = wrap(&format!("x := 1{}\n", " + 1".repeat(32_768 + 8)));
    assert_eq!(lower(&bin), Err(LowerError::TooDeeplyNested));
}

#[test]
fn a_chain_continued_past_newlines_still_counts() {
    // `a.\nb.\nb...` is one statement: the trailing dot defers the
    // semicolon.
    let src = format!("x := a{}\n", ".\nb".repeat(32_768 + 8));
    assert_eq!(lower(&wrap(&src)), Err(LowerError::TooDeeplyNested));
}

#[test]
fn nested_type_in_func_at_the_bound() {
    // `N + func() int { type U [...]int; return 0 }()` nests a `type`
    // declaration inside a bracketed array length inside a func
    // literal, the exponential re-parse shape.
    let inner = "type U [16]int\nreturn 0";
    let ok = format!("x := 1 + func() int {{\n{inner}\n}}()\n");
    assert!(lower(&wrap(&ok)).is_ok(), "{:?}", lower(&wrap(&ok)));
    // A `type` nested 7 deep is over the bound.
    let mut over = "type T [".to_string();
    for _ in 0..7 {
        over.push_str(
            "1 + func() int { type U [8]int; return "
                .len()
                .to_string()
                .as_str(),
        );
        over.push_str("[8]int{...".len().to_string().as_str());
    }
    // Simplest reliable over-bound: 7 `type` declarations nested in
    // bracketed array lengths.
    let src = (0..7).fold("int".to_string(), |acc, _| {
        format!("[1 + func() int {{ type U {acc}; return 0 }}()]int")
    });
    let over = format!("x := 1 + func() int {{\ntype U {src}\nreturn 0\n}}()\n");
    assert_eq!(
        lower(&wrap(&over)),
        Err(LowerError::TooDeeplyNested),
        "{over}"
    );
}

#[test]
fn func_literals_nested_past_the_bound() {
    let ok = (0..15).fold("x := f".to_string(), |acc, _| {
        format!("func() {{ {acc} }}()",)
    });
    assert!(lower(&wrap(&ok)).is_ok(), "{:?}", lower(&wrap(&ok)));
    let over = (0..20).fold("x := f".to_string(), |acc, _| {
        format!("func() {{ {acc} }}()")
    });
    assert_eq!(lower(&wrap(&over)), Err(LowerError::TooDeeplyNested));
}

#[test]
fn a_wide_slice_literal_is_not_too_deep() {
    // 50,000 elements is width, not depth.
    let src = wrap(&format!(
        "x := []int{{{}}}\n",
        (0..50_000)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    ));
    assert!(lower(&src).is_ok(), "{:?}", lower(&src));
}

#[test]
fn unlexable_input_is_parse_error() {
    assert_eq!(lower("package main\n\n\x01"), Err(LowerError::Parse));
}

#[test]
fn source_over_the_byte_cap_is_too_deep() {
    let big = format!("package main\n//{}\n", "x".repeat(5 * 1024 * 1024));
    assert_eq!(lower(&big), Err(LowerError::TooDeeplyNested));
}

/// No non-testdata stdlib file trips a bound. Run with GOROOT set:
/// `GOROOT=$(go env GOROOT) cargo test -p egress-go -- --ignored`.
#[test]
#[ignore = "needs a Go installation; GOROOT must be set"]
fn stdlib_files_pass_the_go_prescan() {
    let goroot = std::env::var("GOROOT").expect("GOROOT unset");
    let src = std::path::Path::new(&goroot).join("src");
    let mut checked = 0;
    for e in walk(&src) {
        let p = e.to_string_lossy();
        if !p.ends_with(".go") || p.contains("testdata") {
            continue;
        }
        let text = std::fs::read_to_string(&e).unwrap();
        assert_eq!(lower(&text), Ok(()), "{p} trips a prescan bound");
        checked += 1;
    }
    assert!(checked > 1000, "too few stdlib files: {checked}");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

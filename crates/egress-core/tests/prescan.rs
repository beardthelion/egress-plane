//! Bracket-depth pre-scan.

use egress_core::model::Language::{self, Javascript, Python, Rust};
use egress_core::prescan::{MAX_DEPTH, too_deep, too_deep_with_cap};

fn nest(open: &str, close: &str, n: usize) -> String {
    format!("{}{}", open.repeat(n), close.repeat(n))
}

#[test]
fn eight_mib_of_nested_brackets_is_rejected_in_each_language() {
    let n = 4 * 1024 * 1024;
    let body = nest("[", "]", n);
    for (lang, src) in [
        (Python, format!("x = {body}\n")),
        (Javascript, format!("const x = {body};\n")),
        (Rust, format!("const X: () = {body};\n")),
    ] {
        assert!(too_deep(lang, &src), "{lang:?}");
    }
}

#[test]
fn ordinary_code_passes() {
    assert!(!too_deep(
        Python,
        "def f(a, b):\n    return [a, {b: (1, 2)}]\n"
    ));
    assert!(!too_deep(Javascript, "const f = (a) => ({ x: [a] });\n"));
    assert!(!too_deep(Rust, "fn f() -> Vec<u8> { vec![(1)] }\n"));
}

#[test]
fn the_cap_is_exact() {
    for lang in [Python, Javascript, Rust] {
        assert!(
            !too_deep_with_cap(lang, &nest("(", ")", 10), 10),
            "{lang:?}"
        );
        assert!(too_deep_with_cap(lang, &nest("(", ")", 11), 10), "{lang:?}");
    }
    assert!(!too_deep(Python, &nest("(", ")", MAX_DEPTH)));
    assert!(too_deep(Python, &nest("(", ")", MAX_DEPTH + 1)));
}

#[test]
fn deep_nesting_inside_a_js_template_hole_counts() {
    let src = format!("const s = `text ${{{}}} more`;\n", nest("(", ")", 100_000));
    assert!(too_deep(Javascript, &src));
    let nested = format!(
        "const s = `a ${{ `b ${{{}}}` }}`;\n",
        nest("[", "]", 100_000)
    );
    assert!(too_deep(Javascript, &nested));
}

#[test]
fn deep_nesting_inside_a_python_fstring_field_counts() {
    let src = format!("s = f\"x {{{}}} y\"\n", nest("(", ")", 100_000));
    assert!(too_deep(Python, &src));
    let spec = format!("s = f'{{v:{{{}}}}}'\n", nest("[", "]", 100_000));
    assert!(too_deep(Python, &spec));
    let triple = format!("s = rf'''{{ {} }}'''\n", nest("{", "}", 100_000));
    assert!(too_deep(Python, &triple));
}

#[test]
fn deep_nesting_after_an_ambiguous_slash_counts() {
    // Regex or division after `)` and `}`: either reading must still count
    // the nesting that follows.
    for prefix in [
        "if (a) /[\"'`]/.test(b);\n",
        "x = (a) / 2 / 3;\n",
        "function f() {}\n/[`'\"]/g.exec(s);\n",
        "const o = {} / 1;\n",
        "a = b\n/ c / d;\n",
        // Same line: a block `}` makes the slash a regex, so the quote inside
        // it must not hide the nesting that follows.
        "function g() {} /'/.test(s); ",
    ] {
        let src = format!("{prefix}const deep = {};\n", nest("(", ")", 100_000));
        assert!(too_deep(Javascript, &src), "{prefix:?}");
    }
}

#[test]
fn unterminated_literals_resolve_toward_counting() {
    let deep = nest("(", ")", 100_000);
    assert!(too_deep(Javascript, &format!("x = `never closed {deep}")));
    assert!(too_deep(Javascript, &format!("/* never closed {deep}")));
    assert!(too_deep(Javascript, &format!("x = \"line\n{deep}")));
    assert!(too_deep(Python, &format!("x = '''never closed {deep}")));
    assert!(too_deep(Python, &format!("x = 'line\n{deep}")));
    assert!(too_deep(Rust, &format!("let s = r#\"never closed {deep}")));
    assert!(too_deep(Rust, &format!("/* never /* closed */ {deep}")));
}

#[test]
fn brackets_in_strings_comments_and_template_text_do_not_count() {
    let many = "(".repeat(10_000);
    let cases: Vec<(Language, String)> = vec![
        (Python, format!("s = '{many}'\n")),
        (Python, format!("s = \"\"\"{many}\n{many}\"\"\"\n")),
        (Python, format!("# {many}\n")),
        (Python, format!("s = r'{many}\\'{many}'\n")),
        (Python, format!("s = f'{{{{{many}'\n")),
        (Python, format!("s = b'{many}'\n")),
        (Javascript, format!("s = '{many}';\n")),
        (Javascript, format!("s = \"{many}\";\n")),
        (Javascript, format!("// {many}\n")),
        (Javascript, format!("/* {many} */\n")),
        (Javascript, format!("s = `{many}\n{many}`;\n")),
        (Javascript, format!("s = `${{ '{many}' }}`;\n")),
        (Javascript, format!("r = /{many}/;\n")),
        (Javascript, format!("r = x.replace(/[{many}]/g, '');\n")),
        (Rust, format!("let s = \"{many}\";\n")),
        (Rust, format!("let s = r##\"{many}\"#{many}\"##;\n")),
        (Rust, format!("let s = b\"{many}\";\n")),
        (Rust, format!("// {many}\n")),
        (Rust, format!("/* /* {many} */ {many} */\n")),
        (
            Rust,
            format!("fn f<'a>(x: &'a str) -> char {{ let c = '('; '{{'; x; c }}\n// {many}"),
        ),
    ];
    for (lang, src) in cases {
        assert!(
            !too_deep_with_cap(lang, &src, 50),
            "{lang:?}: {}",
            &src[..src.len().min(60)]
        );
    }
}

#[test]
fn rust_lifetimes_do_not_open_char_literals() {
    let deep = nest("(", ")", 1000);
    let src = format!("fn f<'a>(x: &'a u8) {{ {deep} }}\n");
    assert!(too_deep(Rust, &src));
}

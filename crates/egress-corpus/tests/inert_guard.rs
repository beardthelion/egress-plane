//! The inert fixture guard over lowered IR (R7, KTD3). A `must-not-`
//! case named by an inert entry or a Python introspection inert name
//! passes only when its tree names every listed member in code: a
//! comment, string, docstring, template, or doc comment never counts,
//! and neither does a same-named member on a local object or on a
//! different module.
//!
//! `egress-core` keeps the existence, `must-not-` prefix, and ledger
//! checks (KTD1); this guard owns the member-in-code check, which only
//! the frontends' IR can answer.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::data::guards::{self, Deferred};
use egress_core::data::{Data, RuntimeData, separator};
use egress_core::model::Language;
use egress_scan::{TreeIr, TreeRoot, lower_tree};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus() -> PathBuf {
    repo().join("fixtures/corpus")
}

fn data() -> Data {
    Data::embedded().unwrap_or_else(|e| panic!("{e}"))
}

fn deferred() -> Deferred {
    let text = std::fs::read_to_string(corpus().join("deferred.toml"))
        .unwrap_or_else(|e| panic!("deferred.toml: {e}"));
    guards::parse_deferred(&text).unwrap_or_else(|e| panic!("{e}"))
}

/// The Python keyword constants an inert entry may list but no source
/// can name: they lower as values, never as name references, so the
/// guard satisfies them without one (KTD3).
const PYTHON_CONSTANTS: [&str; 3] = ["False", "None", "True"];

/// Python keywords. A member spelled like one (other than the three
/// constants above) cannot appear as a name or attribute and is a data
/// error, not a gap the guard skips (KTD3).
const PYTHON_KEYWORDS: &[&str] = &[
    "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
    "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield", "False", "None",
    "True",
];

/// One member-chain segment pattern against a concrete identifier;
/// `*` is a glob, allowed in the last member segment only.
fn member_seg_matches(pattern: &str, seg: &str) -> bool {
    match pattern.split_once('*') {
        Some((pre, post)) => {
            seg.len() >= pre.len() + post.len() && seg.starts_with(pre) && seg.ends_with(post)
        }
        None => pattern == seg,
    }
}

/// A module segment against the concrete path segment: exact, or the
/// catalog's `@scope/*` form covering one package name under the scope.
fn module_seg_matches(pattern: &str, seg: &str) -> bool {
    match pattern.strip_suffix("/*") {
        Some(scope) => {
            seg == pattern || {
                seg.strip_prefix(scope)
                    .and_then(|r| r.strip_prefix('/'))
                    .is_some_and(|r| !r.is_empty() && !r.contains('/'))
            }
        }
        None => seg == pattern,
    }
}

/// Whether `path` (a module's own segments plus a member chain) names
/// `module` plus `members`: the module matches segment for segment and
/// the member chain is a prefix of the rest.
fn path_covers(sep: &str, path: &[String], module: &str, members: &[String]) -> bool {
    let msegs: Vec<&str> = module.split(sep).collect();
    if path.len() < msegs.len() + members.len() {
        return false;
    }
    for (i, m) in msegs.iter().enumerate() {
        if !module_seg_matches(m, &path[i]) {
            return false;
        }
    }
    for (i, m) in members.iter().enumerate() {
        if !member_seg_matches(m, &path[msegs.len() + i]) {
            return false;
        }
    }
    true
}

/// The (module, chain) an ambient-rooted reference names: the ambient
/// module's own name and aliases are stripped, and a member that is a
/// module object (`globalThis.process`) continues into that module.
fn ambient_ref(rt: &RuntimeData, name: &str, members: &[String]) -> Option<(String, Vec<String>)> {
    if rt.ambient.module.is_empty() {
        return None;
    }
    let mut chain = vec![name.to_string()];
    chain.extend(members.iter().cloned());
    loop {
        if chain.first() == Some(&rt.ambient.module) {
            chain.remove(0);
            continue;
        }
        let alias =
            rt.ambient.aliases.iter().find(|a| {
                a.len() <= chain.len() && a.iter().zip(chain.iter()).all(|(x, y)| x == y)
            });
        match alias {
            Some(a) => {
                chain.drain(..a.len());
            }
            None => break,
        }
    }
    if let Some((first, rest)) = chain.split_first()
        && let Some(m) = rt.ambient.module_members.get(first)
    {
        return Some((m.clone(), rest.to_vec()));
    }
    Some((rt.ambient.module.clone(), chain))
}

/// The module path every relevant IR fact reaches: an import-rooted
/// reference resolves to its module specifier (the import's own member
/// path prefixes the chain), an ambient reference resolves through the
/// runtime's ambient module, and each import names its own path.
/// `Root::Local` and the value roots name no module.
fn code_paths(rt: &RuntimeData, tree: &TreeIr, with_imports: bool) -> Vec<Vec<String>> {
    let sep = separator(rt.language);
    let split = |s: &str| -> Vec<String> { s.split(sep).map(str::to_string).collect() };
    let mut out = Vec::new();
    if with_imports {
        for (spec, members) in &tree.imports {
            let mut p = split(spec);
            p.extend(members.iter().cloned());
            out.push(p);
        }
    }
    for r in &tree.references {
        match &r.root {
            TreeRoot::Import(spec) => {
                let mut p = split(spec);
                p.extend(r.members.iter().cloned());
                out.push(p);
            }
            TreeRoot::Ambient(name) => {
                if let Some((m, chain)) = ambient_ref(rt, name, &r.members) {
                    let mut p = split(&m);
                    p.extend(chain);
                    out.push(p);
                }
            }
            TreeRoot::Local(_) => {}
        }
    }
    out
}

/// Whether the tree names `module` plus `members` in code: an
/// import-rooted or ambient reference whose path covers it, or, for an
/// entry listing no member, an import of the module itself (KTD3).
fn covered(rt: &RuntimeData, tree: &TreeIr, module: &str, members: &[String]) -> bool {
    let sep = separator(rt.language);
    code_paths(rt, tree, members.is_empty())
        .iter()
        .any(|p| path_covers(sep, p, module, members))
}

/// The inert check for one entry: the case tree must name the member in
/// code. Python's `True`, `False`, `None` are values and pass without a
/// reference; any other member no source can spell is a data error.
fn entry_violation(
    rt: &RuntimeData,
    tree: &TreeIr,
    fixture: &str,
    id: &str,
    module: &str,
    members: &[String],
) -> Option<String> {
    if rt.language == Language::Python {
        if members
            .iter()
            .any(|m| PYTHON_CONSTANTS.contains(&m.as_str()))
        {
            return None;
        }
        if let Some(kw) = members
            .iter()
            .find(|m| PYTHON_KEYWORDS.contains(&m.as_str()))
        {
            return Some(format!(
                "{id}: member {kw} is a Python keyword and cannot be referenced in code"
            ));
        }
    }
    if covered(rt, tree, module, members) {
        None
    } else {
        let sep = separator(rt.language);
        let path = if members.is_empty() {
            module.to_string()
        } else {
            format!("{module}{sep}{}", members.join(sep))
        };
        Some(format!(
            "{id}: fixture {fixture} does not name {path} in code"
        ))
    }
}

/// The Python introspection inert check: the name must be loaded as an
/// attribute on a function, class, or variable defined in the same
/// file, that is, a reference rooted at `Root::Local` (KTD3). A load on
/// an imported module or an ambient name does not count.
fn introspection_violation(tree: &TreeIr, fixture: &str, name: &str) -> Option<String> {
    let hit = tree.references.iter().any(|r| {
        matches!(r.root, TreeRoot::Local(_)) && r.members.first().is_some_and(|m| m == name)
    });
    (!hit)
        .then(|| format!("introspection inert name {name}: fixture {fixture} loads it on no local"))
}

/// Every inert fixture in the corpus that exists and is not deferred
/// names every member of its group in code, and every Python
/// introspection inert fixture loads its name on a local.
#[test]
fn every_inert_fixture_names_its_members_in_code() {
    let d = data();
    let def = deferred();
    let mut violations = Vec::new();
    for lang in Language::ALL {
        let rt = d.runtime(lang);
        for (fixture, entries) in guards::inert_groups(rt) {
            if def.cases.contains(fixture) {
                continue;
            }
            // A missing case is the fixture guard's report (KTD1).
            let tree_dir = corpus().join(fixture).join("tree");
            if !tree_dir.is_dir() {
                continue;
            }
            let tree = lower_tree(&tree_dir).unwrap_or_else(|e| panic!("{fixture}: {e}"));
            for e in entries {
                if let Some(v) = entry_violation(rt, &tree, fixture, &e.id, &e.module, &e.members) {
                    violations.push(v);
                }
            }
        }
        for n in &rt.closure.introspection_inert {
            if def.cases.contains(&n.fixture) {
                continue;
            }
            let tree_dir = corpus().join(&n.fixture).join("tree");
            if !tree_dir.is_dir() {
                continue;
            }
            let tree = lower_tree(&tree_dir).unwrap_or_else(|e| panic!("{}: {e}", n.fixture));
            if let Some(v) = introspection_violation(&tree, &n.fixture, &n.name) {
                violations.push(v);
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

// ---- synthetic trees ---------------------------------------------------------

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Writes a tree under the target tmpdir and returns its root.
fn write_tree(files: &[(&str, &str)]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "inert-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    for (name, text) in files {
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
    }
    dir
}

fn lower(dir: &Path) -> TreeIr {
    lower_tree(dir).unwrap_or_else(|e| panic!("{e}"))
}

fn member_path(s: &str) -> Vec<String> {
    s.split('.').map(str::to_string).collect()
}

/// One entry check: `id` on `module` with the `member` path.
fn check(rt: &RuntimeData, tree: &TreeIr, id: &str, module: &str, member: &str) -> Option<String> {
    entry_violation(rt, tree, "x/y/must-not-z", id, module, &member_path(member))
}

#[test]
fn a_member_named_only_in_a_comment_is_rejected() {
    let d = data();
    let py = d.runtime(Language::Python);
    let dir = write_tree(&[("app.py", "import os\n# os.path.join runs here\n")]);
    let v = check(py, &lower(&dir), "python:os.path.join", "os.path", "join").unwrap();
    assert!(v.contains("python:os.path.join"), "{v}");
    assert!(v.contains("os.path.join"), "{v}");
    // The same mention as a real reference passes.
    let dir = write_tree(&[("app.py", "import os\nx = os.path.join\n")]);
    assert!(check(py, &lower(&dir), "python:os.path.join", "os.path", "join").is_none());
}

#[test]
fn string_and_documentation_mentions_are_rejected() {
    let d = data();
    // A string literal and a docstring are not references (Python).
    let py = d.runtime(Language::Python);
    let dir = write_tree(&[(
        "app.py",
        "\"\"\"os.path.join appears in this docstring.\"\"\"\nHELP = \"call os.path.join\"\n",
    )]);
    assert!(check(py, &lower(&dir), "python:os.path.join", "os.path", "join").is_some());
    // Template text is not a reference (JavaScript).
    let js = d.runtime(Language::Javascript);
    let dir = write_tree(&[(
        "app.mjs",
        "export const HELP = `call http.get on ${tool}`;\n// http.get here\n",
    )]);
    assert!(check(js, &lower(&dir), "javascript:http.get", "http", "get").is_some());
    // Doc comments and strings are not references (Rust).
    let rs = d.runtime(Language::Rust);
    let dir = write_tree(&[(
        "src/lib.rs",
        "/// std::net::TcpStream does the connect\nfn s() {\n    let _ = \"std::net::TcpStream\";\n}\n",
    )]);
    assert!(
        check(
            rs,
            &lower(&dir),
            "rust:std::net::TcpStream::connect",
            "std::net::TcpStream",
            "connect"
        )
        .is_some()
    );
}

#[test]
fn every_member_of_a_group_must_appear() {
    let d = data();
    let py = d.runtime(Language::Python);
    // A group with two members where the case names only one is
    // rejected, naming the missing member.
    let dir = write_tree(&[(
        "app.py",
        "from asyncio import base_futures\nx = base_futures\n",
    )]);
    let tree = lower(&dir);
    assert!(
        check(
            py,
            &tree,
            "python:asyncio.base_futures",
            "asyncio",
            "base_futures"
        )
        .is_none()
    );
    let v = check(
        py,
        &tree,
        "python:asyncio.base_tasks",
        "asyncio",
        "base_tasks",
    )
    .unwrap();
    assert!(v.contains("python:asyncio.base_tasks"), "{v}");
    assert!(v.contains("base_tasks"), "{v}");
}

#[test]
fn a_member_on_a_local_or_another_module_is_rejected() {
    let d = data();
    let js = d.runtime(Language::Javascript);
    // A same-named member on a local object is not the module's member.
    let dir = write_tree(&[(
        "app.mjs",
        "export function probe(m) {\n  const http = {};\n  return http.get;\n}\n",
    )]);
    assert!(check(js, &lower(&dir), "javascript:http.get", "http", "get").is_some());
    // A same-named member on a different module is not it either.
    let dir = write_tree(&[(
        "app.mjs",
        "import http from \"./helper.mjs\";\nexport const x = http.get;\n",
    )]);
    assert!(check(js, &lower(&dir), "javascript:http.get", "http", "get").is_some());
    // And on the right module it passes.
    let dir = write_tree(&[(
        "app.mjs",
        "import http from \"http\";\nexport const x = http.get;\n",
    )]);
    assert!(check(js, &lower(&dir), "javascript:http.get", "http", "get").is_none());
}

#[test]
fn wildcard_members_and_scoped_modules_match_concrete_names() {
    let d = data();
    let js = d.runtime(Language::Javascript);
    // A `*Command` member pattern on a `@scope/*` module.
    let dir = write_tree(&[(
        "app.mjs",
        "import m from \"@scope/pkg\";\nexport const x = m.ExampleCommand;\n",
    )]);
    assert!(
        check(
            js,
            &lower(&dir),
            "javascript:@scope/*.*Command",
            "@scope/*",
            "*Command"
        )
        .is_none()
    );
    // A concrete name that does not match the glob does not satisfy it.
    let dir = write_tree(&[(
        "app.mjs",
        "import m from \"@scope/pkg\";\nexport const x = m.CommandLine;\n",
    )]);
    assert!(
        check(
            js,
            &lower(&dir),
            "javascript:@scope/*.*Command",
            "@scope/*",
            "*Command"
        )
        .is_some()
    );
    // A specifier under the scope with a deeper path is not `@scope/*`.
    let dir = write_tree(&[(
        "app.mjs",
        "import m from \"@scope/pkg/sub\";\nexport const x = m.ExampleCommand;\n",
    )]);
    assert!(
        check(
            js,
            &lower(&dir),
            "javascript:@scope/*.*Command",
            "@scope/*",
            "*Command"
        )
        .is_some()
    );
}

#[test]
fn a_dotted_member_needs_one_chained_reference() {
    let d = data();
    let py = d.runtime(Language::Python);
    // `aiohttp.web.Application` is satisfied by one chain, not by the
    // last segment alone.
    let dir = write_tree(&[("app.py", "from aiohttp import web\nx = web.Application\n")]);
    assert!(
        check(
            py,
            &lower(&dir),
            "python:aiohttp.web.Application",
            "aiohttp",
            "web.Application"
        )
        .is_none()
    );
    let dir = write_tree(&[("app.py", "import aiohttp\nx = aiohttp.Application\n")]);
    assert!(
        check(
            py,
            &lower(&dir),
            "python:aiohttp.web.Application",
            "aiohttp",
            "web.Application"
        )
        .is_some()
    );
}

#[test]
fn python_keyword_constants_pass_without_a_reference() {
    let d = data();
    let py = d.runtime(Language::Python);
    // True, False, None are values, not names: absent from the case they
    // still pass, and a member outside the three is rejected when absent
    // or a data error when it cannot be referenced at all.
    let dir = write_tree(&[("app.py", "x = (ArithmeticError,)\n")]);
    let tree = lower(&dir);
    for c in PYTHON_CONSTANTS {
        assert!(
            check(py, &tree, "python:builtins.X", "builtins", c).is_none(),
            "{c}"
        );
    }
    assert!(
        check(
            py,
            &tree,
            "python:builtins.ArithmeticError",
            "builtins",
            "ArithmeticError"
        )
        .is_none()
    );
    let v = check(
        py,
        &tree,
        "python:builtins.ValueError",
        "builtins",
        "ValueError",
    )
    .unwrap();
    assert!(v.contains("ValueError"), "{v}");
    // A member spelled like another keyword cannot be referenced.
    let v = check(py, &tree, "python:builtins.pass", "builtins", "pass").unwrap();
    assert!(v.contains("keyword"), "{v}");
}

#[test]
fn an_introspection_name_must_load_on_a_local() {
    // A load on a function defined in the file satisfies it.
    let dir = write_tree(&[("app.py", "def probe():\n    return probe.__name__\n")]);
    assert!(introspection_violation(&lower(&dir), "x/y/must-not-z", "__name__").is_none());
    // A load on an imported module does not.
    let dir = write_tree(&[("app.py", "import json\nx = json.__name__\n")]);
    assert!(introspection_violation(&lower(&dir), "x/y/must-not-z", "__name__").is_some());
    // Nor does the name in a comment or a string.
    let dir = write_tree(&[("app.py", "# __name__\nHELP = \"__name__\"\n")]);
    assert!(introspection_violation(&lower(&dir), "x/y/must-not-z", "__name__").is_some());
}

/// An existing hand-authored inert case is judged by the new rules:
/// `javascript/tricky/must-not-mentions-in-strings-and-comments` is
/// named by no inert entry, so the guard leaves it to must-not gating.
#[test]
fn a_comment_only_case_named_by_no_entry_is_untouched() {
    let d = data();
    let fixture = "javascript/tricky/must-not-mentions-in-strings-and-comments";
    for lang in Language::ALL {
        assert!(!guards::inert_groups(d.runtime(lang)).contains_key(fixture));
    }
    let tree = lower(&corpus().join(fixture).join("tree"));
    // Nothing in it is code, so any module member check against it fails.
    let js = d.runtime(Language::Javascript);
    assert!(check(js, &tree, "javascript:http.get", "http", "get").is_some());
}

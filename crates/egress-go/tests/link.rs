//! Whole-program link tests (KTD8, KTD9, KTD10): package-as-directory
//! binding, module and workspace resolution, vendored packages, replace
//! keying, and the link budget. The Go tables below stand in for the
//! embedded data, so these tests do not depend on U9 curation.

use std::collections::{BTreeMap, BTreeSet};

use egress_core::classify::{Classified, classify};
use egress_core::data::{Data, RuntimeData, load_runtime};
use egress_core::discover::FileKind;
use egress_core::discover::manifests::{self, ManifestKind, Manifests, Parsed};
use egress_core::identity::encode_path_bytes;
use egress_core::ir::FileIr;
use egress_core::model::{BlindSpotKind, Language};
use egress_core::resolve::{Program, ProgramFile};

use egress_go::{link_with, lower};

/// A small Go primitives table: `net/http` and `os` egress, the rest of
/// the injected standard library inert.
const GO_PRIM: &str = r#"
language = "go"
runtime_range = "1.18-1.26"

[[module]]
name = "net/http"
class = "egress"

[[module]]
name = "os"
class = "egress"

[[module]]
name = "fmt"
class = "inert"
justification = "output"

[[module]]
name = "net/url"
class = "inert"
justification = "url strings"

[[module]]
name = "context"
class = "inert"
justification = "cancellation plumbing"

[[module]]
name = "io"
class = "inert"
justification = "readers and writers"

[[entry]]
id = "go:net/http.Get"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "url" }
fixture = "f"

[[entry]]
id = "go:net/http.NewRequest"
kind = "egress"
mechanism = "network"
destination = { arg = 3, form = "url" }
fixture = "f"

[[entry]]
id = "go:net/http.ListenAndServe"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "host-port" }
fixture = "f"

[[entry]]
id = "go:os.Getenv"
kind = "inert"
justification = "reads the environment"
fixture = "f"

[[entry]]
id = "go:fmt.Println"
kind = "inert"
justification = "output"
fixture = "f"
"#;

const GO_CAT: &str = r#"
language = "go"

[[package]]
name = "github.com/acme/httpclient"

[[entry]]
id = "go:github.com/acme/httpclient.Fetch"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "url" }
fixture = "f"

[[package]]
name = "github.com/acme/rpcclient"
package_name = "rpcx"
"#;

/// An inventory listing only the small stdlib set the tests use.
const GO_INV: &str = r#"
language = "go"
stdlib_modules = [
    "context",
    "fmt",
    "io",
    "net/http",
    "net/url",
    "os",
]
"#;

fn rt() -> RuntimeData {
    load_runtime(
        Language::Go,
        ("prim", GO_PRIM),
        ("cat", GO_CAT),
        ("inv", GO_INV),
    )
    .expect("small Go tables")
}

fn data() -> Data {
    let mut d = Data::embedded().expect("embedded data");
    *d.runtime_mut(Language::Go) = rt();
    d
}

/// Parses `kind` at `path` and pushes it onto `manifests`.
fn manifest(manifests: &mut Manifests, kind: ManifestKind, path: &str, text: &str) {
    let (parsed, _) = manifests::parse(kind, path.as_bytes(), text).expect("manifest parses");
    match parsed {
        Parsed::GoMod(m) => manifests.go_mod.push(m),
        Parsed::GoWork(w) => manifests.go_work.push(w),
        Parsed::GoModules(v) => manifests.go_modules.push(v),
        _ => panic!("{kind:?} does not parse to a Go manifest"),
    }
}

fn go_mod(manifests: &mut Manifests, path: &str, text: &str) {
    manifest(manifests, ManifestKind::GoMod, path, text);
}

fn go_work(manifests: &mut Manifests, path: &str, text: &str) {
    manifest(manifests, ManifestKind::GoWork, path, text);
}

fn go_modules(manifests: &mut Manifests, path: &str, text: &str) {
    manifest(manifests, ManifestKind::GoModules, path, text);
}

/// A tree of Go sources plus manifests, lowered, linked, and classified
/// with the small tables.
fn run(
    files: &[(&str, &str)],
    manifests: &Manifests,
    extra_index: &[&str],
    budget: u64,
) -> (Classified, egress_go::Linked) {
    let mut owned: Vec<(Vec<u8>, FileIr)> = files
        .iter()
        .map(|(p, s)| {
            (
                p.as_bytes().to_vec(),
                lower(p.as_bytes(), s).expect("lowers"),
            )
        })
        .collect();
    let mut index: BTreeMap<Vec<u8>, FileKind> = BTreeMap::new();
    for (p, _) in &owned {
        index.insert(p.clone(), FileKind::Source(Language::Go));
    }
    for m in manifests
        .go_mod
        .iter()
        .map(|m| m.path.clone())
        .chain(manifests.go_work.iter().map(|w| w.path.clone()))
        .chain(manifests.go_modules.iter().map(|v| v.path.clone()))
    {
        index.insert(m, FileKind::Other);
    }
    for p in extra_index {
        index.insert(p.as_bytes().to_vec(), FileKind::Other);
    }
    let mut view: Vec<(&[u8], &mut FileIr)> =
        owned.iter_mut().map(|(p, ir)| (p.as_slice(), ir)).collect();
    let linked = link_with(manifests, &index, &mut view, &rt(), budget);
    let excluded: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut program = Program::new(&index, &excluded);
    program.set_rules(Language::Go, &linked.rules);
    for (p, ir) in &owned {
        program.add_file(
            p.clone(),
            ProgramFile {
                file: encode_path_bytes(p),
                language: Language::Go,
                labels: Vec::new(),
                ir,
            },
        );
    }
    let d = data();
    let classified = classify(&d, &program, budget);
    (classified, linked)
}

fn base_manifests() -> Manifests {
    let mut m = Manifests::default();
    go_mod(&mut m, "go.mod", "module example.com/m\n\ngo 1.22\n");
    m
}

fn dep_packages(c: &Classified) -> Vec<&str> {
    c.unscanned_dependencies
        .iter()
        .map(|d| d.package.as_str())
        .collect()
}

fn kinds(c: &Classified) -> Vec<BlindSpotKind> {
    c.blind_spots.iter().map(|b| b.kind).collect()
}

fn site_destinations(c: &Classified) -> Vec<(String, String)> {
    c.sites
        .iter()
        .map(|s| (s.mechanism.clone(), s.destination.value.clone()))
        .collect()
}

// --------------------------------------------------------------------
// package-as-directory binding (KTD8)

#[test]
fn a_sibling_constant_feeds_the_destination() {
    let m = base_manifests();
    let (c, _) = run(
        &[
            (
                "api/consts.go",
                "package api\n\nconst Base = \"https://api.example.com\"\n",
            ),
            ("api/server.go", "package api\n\nfunc Serve() {}\n"),
            (
                "main.go",
                "package main\n\nimport (\n\t\"net/http\"\n\t\"example.com/m/api\"\n)\n\nfunc main() {\n\thttp.Get(api.Base)\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    let sites = site_destinations(&c);
    assert_eq!(
        sites,
        vec![(
            "go:net/http.Get".to_string(),
            "https://api.example.com".to_string()
        )],
        "{sites:?}"
    );
    assert!(
        dep_packages(&c).is_empty(),
        "{:?}",
        c.unscanned_dependencies
    );
}

#[test]
fn the_package_clause_is_the_bound_name_not_the_path() {
    // The directory is `api` but the package declares `apiv2`; the code
    // uses the clause name.
    let m = base_manifests();
    let (c, _) = run(
        &[
            (
                "api/consts.go",
                "package apiv2\n\nconst Base = \"https://api.example.com\"\n",
            ),
            (
                "main.go",
                "package main\n\nimport (\n\t\"net/http\"\n\t\"example.com/m/api\"\n)\n\nfunc main() {\n\thttp.Get(apiv2.Base)\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(
        site_destinations(&c),
        vec![(
            "go:net/http.Get".to_string(),
            "https://api.example.com".to_string()
        )]
    );
}

#[test]
fn a_first_party_package_member_binding_reaches_its_declaring_file() {
    // `api.Serve` is a call member of the imported package: the reference
    // binds to server.go through the package index.
    let m = base_manifests();
    let (c, l) = run(
        &[
            ("api/server.go", "package api\n\nfunc Serve() {}\n"),
            (
                "main.go",
                "package main\n\nimport \"example.com/m/api\"\n\nfunc main() {\n\tapi.Serve()\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    assert!(c.blind_spots.is_empty(), "{:?}", c.blind_spots);
    assert!(dep_packages(&c).is_empty());
    assert!(l.steps > 0);
}

#[test]
fn a_sibling_var_mutated_in_any_file_is_not_a_constant() {
    let m = base_manifests();
    let (c, _) = run(
        &[
            (
                "cfg.go",
                "package main\n\nvar base = \"https://prod.example.com\"\n",
            ),
            (
                "init.go",
                "package main\n\nfunc init() { base = \"https://dev\" }\n",
            ),
            (
                "main.go",
                "package main\n\nimport \"net/http\"\n\nfunc main() {\n\thttp.Get(base)\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    // The mutated var is no constant: the site still fires but its
    // destination is symbolic, never the literal.
    let sites = site_destinations(&c);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_ne!(sites[0].1, "https://prod.example.com");
    assert!(!c.caveat_triggers.contains("go-var-ldflags"));
}

#[test]
fn a_surviving_package_var_fires_the_ldflags_caveat() {
    let m = base_manifests();
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"net/http\"\n\nvar endpoint = \"https://api.example.com\"\n\nfunc main() {\n\thttp.Get(endpoint)\n}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(
        site_destinations(&c),
        vec![(
            "go:net/http.Get".to_string(),
            "https://api.example.com".to_string()
        )]
    );
    assert!(c.caveat_triggers.contains("go-var-ldflags"));
}

#[test]
fn a_name_declared_in_two_files_is_a_resolution_limit_not_a_choice() {
    let m = base_manifests();
    let (c, _) = run(
        &[
            ("api/a.go", "package api\n\nconst Base = \"https://a\"\n"),
            ("api/b.go", "package api\n\nconst Base = \"https://b\"\n"),
            (
                "main.go",
                "package main\n\nimport (\n\t\"net/http\"\n\t\"example.com/m/api\"\n)\n\nfunc main() {\n\thttp.Get(api.Base)\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    assert!(
        kinds(&c).contains(&BlindSpotKind::ResolutionLimit),
        "{:?}",
        c.blind_spots
    );
    // The site still fires, but neither file's literal flows into it.
    let sites = site_destinations(&c);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert!(
        sites[0].1 != "https://a" && sites[0].1 != "https://b",
        "{sites:?}"
    );
}

#[test]
fn an_undeclared_selector_root_under_an_unknown_clause_is_flagged() {
    // `sqlite3x.Open` with the import guessing `driver`: the real clause
    // is unknown, so the reference is a resolution-limit, not silence.
    let m = base_manifests();
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport (\n\t\"net/http\"\n\t\"github.com/x/driver\"\n)\n\nfunc main() {\n\tsqlite3x.Open(http.StatusOK)\n}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert!(
        kinds(&c).contains(&BlindSpotKind::ResolutionLimit),
        "{:?}",
        c.blind_spots
    );
}

#[test]
fn a_catalogued_package_name_corrects_the_local() {
    // The catalog knows `github.com/acme/rpcclient` declares `rpcx`.
    let m = base_manifests();
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport (\n\t\"net/http\"\n\t\"github.com/acme/rpcclient\"\n)\n\nfunc main() {\n\thttp.Get(rpcx.Base)\n}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    // `rpcx` binds the import: no mystery-root flag.
    assert!(
        !kinds(&c).contains(&BlindSpotKind::ResolutionLimit),
        "{:?}",
        c.blind_spots
    );
}

// --------------------------------------------------------------------
// import resolution (KTD9)

#[test]
fn the_standard_library_wins_over_a_same_named_module() {
    let mut m = Manifests::default();
    go_mod(&mut m, "go.mod", "module net\n\ngo 1.22\n");
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"net/http\"\n\nfunc main() {\n\thttp.Get(\"https://api.example.com\")\n}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(
        site_destinations(&c),
        vec![(
            "go:net/http.Get".to_string(),
            "https://api.example.com".to_string()
        )]
    );
}

#[test]
fn a_no_dot_import_is_an_unresolved_module_gap() {
    let m = base_manifests();
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"corp/internal\"\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert!(
        kinds(&c).contains(&BlindSpotKind::UnresolvedModule),
        "{:?}",
        c.blind_spots
    );
}

#[test]
fn the_c_pseudo_package_is_an_unresolved_module() {
    let m = base_manifests();
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"C\"\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert!(
        kinds(&c).contains(&BlindSpotKind::UnresolvedModule),
        "{:?}",
        c.blind_spots
    );
}

#[test]
fn an_invalid_import_path_is_never_mapped_or_printed() {
    let m = base_manifests();
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"../escape\"\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert!(
        kinds(&c).contains(&BlindSpotKind::UnresolvedModule),
        "{:?}",
        c.blind_spots
    );
    assert!(
        !c.blind_spots
            .iter()
            .any(|b| b.construct.contains("../escape")),
        "{:?}",
        c.blind_spots
    );
}

#[test]
fn an_external_import_is_a_dependency_and_a_go_mod_one_uses_the_require_key() {
    let mut m = base_manifests();
    // require github.com/acme/lib, then import a package under it.
    m.go_mod.clear();
    go_mod(
        &mut m,
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/acme/lib v1.2.3\n",
    );
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport (\n\t\"github.com/acme/lib/sub\"\n\t\"github.com/other/free\"\n)\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    let mut deps = dep_packages(&c);
    deps.sort();
    // The required module is keyed by the longest matching require path;
    // the undeclared external keeps its own path.
    assert_eq!(
        deps,
        vec!["github.com/acme/lib", "github.com/other/free"],
        "{deps:?}"
    );
}

#[test]
fn a_module_path_replace_rekeys_the_dependency() {
    let mut m = Manifests::default();
    go_mod(
        &mut m,
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/acme/lib v1.0.0\n\nreplace github.com/acme/lib => github.com/fork/lib v2.0.0\n",
    );
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"github.com/acme/lib\"\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(dep_packages(&c), vec!["github.com/fork/lib@v2.0.0"]);
}

#[test]
fn a_local_replace_maps_the_import_to_first_party_source() {
    let mut m = Manifests::default();
    go_mod(
        &mut m,
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/acme/lib v1.0.0\n\nreplace github.com/acme/lib => ./lib\n",
    );
    let (c, _) = run(
        &[
            (
                "lib/lib.go",
                "package lib\n\nconst URL = \"https://replaced.example.com\"\n",
            ),
            (
                "main.go",
                "package main\n\nimport (\n\t\"net/http\"\n\t\"github.com/acme/lib\"\n)\n\nfunc main() {\n\thttp.Get(lib.URL)\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(
        site_destinations(&c),
        vec![(
            "go:net/http.Get".to_string(),
            "https://replaced.example.com".to_string()
        )]
    );
    assert!(dep_packages(&c).is_empty());
}

#[test]
fn an_outside_replace_target_is_a_gap() {
    let mut m = Manifests::default();
    go_mod(
        &mut m,
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/acme/lib v1.0.0\n\nreplace github.com/acme/lib => ../../lib\n",
    );
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"github.com/acme/lib\"\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    // The manifest already reports the outside replace; the import
    // itself resolves to a reference-outside-root gap, and nothing
    // leaves the root.
    assert!(
        kinds(&c).contains(&BlindSpotKind::ReferenceOutsideRoot),
        "{:?}",
        c.blind_spots
    );
}

#[test]
fn a_workspace_use_module_resolves_first_party() {
    let mut m = Manifests::default();
    go_mod(&mut m, "go.mod", "module example.com/m\n\ngo 1.22\n");
    go_mod(
        &mut m,
        "tools/go.mod",
        "module example.com/tools\n\ngo 1.22\n",
    );
    go_work(&mut m, "go.work", "go 1.22\n\nuse (\n\t.\n\t./tools\n)\n");
    let (c, _) = run(
        &[
            (
                "tools/helper/h.go",
                "package helper\n\nconst URL = \"https://tools.example.com\"\n",
            ),
            (
                "main.go",
                "package main\n\nimport (\n\t\"net/http\"\n\t\"example.com/tools/helper\"\n)\n\nfunc main() {\n\thttp.Get(helper.URL)\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(
        site_destinations(&c),
        vec![(
            "go:net/http.Get".to_string(),
            "https://tools.example.com".to_string()
        )]
    );
}

#[test]
fn two_use_modules_declaring_one_path_bind_neither() {
    let mut m = Manifests::default();
    go_mod(&mut m, "a/go.mod", "module example.com/dup\n\ngo 1.22\n");
    go_mod(&mut m, "b/go.mod", "module example.com/dup\n\ngo 1.22\n");
    go_work(&mut m, "go.work", "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n");
    let (c, _) = run(
        &[
            ("a/x.go", "package dup\n\nconst URL = \"https://a\"\n"),
            ("b/x.go", "package dup\n\nconst URL = \"https://b\"\n"),
            (
                "a/main.go",
                "package main2\n\nimport \"example.com/dup\"\n\nfunc f() { _ = dup.URL }\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    assert!(
        kinds(&c).contains(&BlindSpotKind::UnresolvedModule),
        "{:?}",
        c.blind_spots
    );
    assert!(
        kinds(&c).contains(&BlindSpotKind::ResolutionLimit),
        "{:?}",
        c.blind_spots
    );
}

#[test]
fn a_vendored_package_resolves_when_the_lists_agree() {
    let mut m = Manifests::default();
    go_mod(
        &mut m,
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/acme/vlib v1.0.0\n",
    );
    go_modules(
        &mut m,
        "vendor/modules.txt",
        "# github.com/acme/vlib v1.0.0\n## explicit; go 1.22\ngithub.com/acme/vlib\n",
    );
    let (c, _) = run(
        &[
            (
                "vendor/github.com/acme/vlib/vlib.go",
                "package vlib\n\nconst URL = \"https://vendored.example.com\"\n",
            ),
            (
                "main.go",
                "package main\n\nimport (\n\t\"net/http\"\n\t\"github.com/acme/vlib\"\n)\n\nfunc main() {\n\thttp.Get(vlib.URL)\n}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(
        site_destinations(&c),
        vec![(
            "go:net/http.Get".to_string(),
            "https://vendored.example.com".to_string()
        )],
        "{:?}",
        c.blind_spots
    );
    assert!(dep_packages(&c).is_empty());
}

#[test]
fn a_vendored_package_with_a_version_mismatch_stays_external() {
    let mut m = Manifests::default();
    go_mod(
        &mut m,
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/acme/vlib v2.0.0\n",
    );
    go_modules(
        &mut m,
        "vendor/modules.txt",
        "# github.com/acme/vlib v1.0.0\n## explicit; go 1.22\ngithub.com/acme/vlib\n",
    );
    let (c, _) = run(
        &[
            (
                "vendor/github.com/acme/vlib/vlib.go",
                "package vlib\n\nconst URL = \"https://vendored.example.com\"\n",
            ),
            (
                "main.go",
                "package main\n\nimport \"github.com/acme/vlib\"\n\nfunc main() {}\n",
            ),
        ],
        &m,
        &[],
        u64::MAX,
    );
    // The lists disagree, so vendor/ does not govern: the import is an
    // external dependency keyed by the require.
    assert_eq!(dep_packages(&c), vec!["github.com/acme/vlib"]);
}

#[test]
fn a_replaced_module_keeps_only_the_replacement_key() {
    // An inert-row-bearing module under a path replace ships the
    // replacement's code: the original's rows do not silence it.
    let mut m = Manifests::default();
    go_mod(
        &mut m,
        "go.mod",
        "module example.com/m\n\ngo 1.22\n\nrequire github.com/acme/lib v1.0.0\n\nreplace github.com/acme/lib => github.com/fork/lib v9.9.9\n",
    );
    let (c, _) = run(
        &[(
            "main.go",
            "package main\n\nimport \"github.com/acme/lib\"\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert_eq!(dep_packages(&c), vec!["github.com/fork/lib@v9.9.9"]);
}

// --------------------------------------------------------------------
// link limits

#[test]
fn an_exhausted_link_budget_marks_every_unreached_file() {
    let m = base_manifests();
    let (c, _) = run(
        &[
            ("a.go", "package main\n\nfunc a() {}\n"),
            (
                "b.go",
                "package main\n\nimport \"net/http\"\n\nfunc b() { http.Get(\"https://x\") }\n",
            ),
            ("c.go", "package main\n\nfunc c() {}\n"),
        ],
        &m,
        &[],
        1,
    );
    let limits = c
        .blind_spots
        .iter()
        .filter(|b| b.kind == BlindSpotKind::ResolutionLimit)
        .count();
    assert!(limits >= 2, "{:?}", c.blind_spots);
}

#[test]
fn the_fallback_rules_resolve_nothing() {
    let rules = egress_go::GoRules::fallback();
    use egress_core::resolve::SpecifierRules;
    let kind = rules.classify(b"main.go", "net/http");
    assert!(matches!(
        kind,
        egress_core::resolve::SpecifierKind::Path { ref probes } if probes.is_empty()
    ));
}

#[test]
fn link_charges_resolver_steps() {
    let m = base_manifests();
    let (_, l) = run(
        &[(
            "main.go",
            "package main\n\nimport \"net/http\"\n\nfunc main() {}\n",
        )],
        &m,
        &[],
        u64::MAX,
    );
    assert!(l.steps > 0);
    assert!(!l.budget_exhausted);
}

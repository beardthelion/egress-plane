//! JS specifier rules: probing order, NodeNext `.js` to `.ts`,
//! `.d.ts` exclusion, package `imports`, workspace package names, and
//! tsconfig `paths` and `baseUrl`.

use std::collections::BTreeMap;

use egress_core::discover::FileKind;
use egress_core::discover::manifests::{Manifests, PackageJson, TsConfig};
use egress_core::model::Language;
use egress_core::resolve::{SpecifierKind, SpecifierRules};
use egress_js::JsRules;

fn index(files: &[&str]) -> BTreeMap<Vec<u8>, FileKind> {
    files
        .iter()
        .map(|f| {
            (
                f.as_bytes().to_vec(),
                FileKind::Source(Language::Javascript),
            )
        })
        .collect()
}

fn pkg(
    path: &str,
    name: Option<&str>,
    main: Option<&str>,
    imports: &[(&str, &str)],
) -> PackageJson {
    PackageJson {
        path: path.as_bytes().to_vec(),
        name: name.map(str::to_string),
        workspaces: Vec::new(),
        bin: Vec::new(),
        main: main.map(|m| m.as_bytes().to_vec()),
        imports: imports
            .iter()
            .map(|(p, t)| (p.to_string(), t.as_bytes().to_vec()))
            .collect(),
        lifecycle: Vec::new(),
    }
}

/// The first probe the index holds, as the core's resolver picks it.
fn hit(
    rules: &JsRules,
    idx: &BTreeMap<Vec<u8>, FileKind>,
    from: &str,
    spec: &str,
) -> Option<String> {
    let probes = match rules.classify(from.as_bytes(), spec) {
        SpecifierKind::Path { probes } | SpecifierKind::Bare { probes, .. } => probes,
        SpecifierKind::OutsideRoot => return Some("<outside>".into()),
    };
    probes
        .iter()
        .find(|p| idx.contains_key(*p))
        .map(|p| String::from_utf8(p.clone()).unwrap())
}

#[test]
fn relative_specifiers_probe_extensions_index_and_ts_sources() {
    let idx = index(&[
        "src/net.ts",
        "src/api/index.ts",
        "src/util.ts",
        "src/both.js",
        "src/both.ts",
        "src/types.d.ts",
    ]);
    let rules = JsRules::from_parts(&idx, &Manifests::default());
    assert_eq!(
        hit(&rules, &idx, "src/app.ts", "./net").as_deref(),
        Some("src/net.ts")
    );
    assert_eq!(
        hit(&rules, &idx, "src/app.ts", "./api").as_deref(),
        Some("src/api/index.ts")
    );
    assert_eq!(
        hit(&rules, &idx, "src/app.ts", "./util.js").as_deref(),
        Some("src/util.ts")
    );
    // The exact path wins over the TypeScript stem.
    assert_eq!(
        hit(&rules, &idx, "src/app.ts", "./both.js").as_deref(),
        Some("src/both.js")
    );
    // A declaration file is never a target.
    assert_eq!(hit(&rules, &idx, "src/app.ts", "./types"), None);
    assert_eq!(
        hit(&rules, &idx, "src/app.ts", "../../x").as_deref(),
        Some("<outside>")
    );
    assert!(matches!(
        rules.classify(b"src/app.ts", "./types"),
        SpecifierKind::Path { .. }
    ));
}

#[test]
fn bare_specifiers_strip_node_and_stay_external() {
    let idx = index(&[]);
    let rules = JsRules::from_parts(&idx, &Manifests::default());
    assert_eq!(
        rules.classify(b"a.js", "node:http"),
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: "http".into()
        }
    );
    assert_eq!(
        rules.classify(b"a.js", "lodash/fp"),
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: "lodash/fp".into()
        }
    );
}

#[test]
fn package_imports_and_workspace_names_resolve_into_the_index() {
    let idx = index(&[
        "src/net.js",
        "packages/client/index.js",
        "packages/lib/dist/main.js",
        "packages/lib/sub/x.ts",
    ]);
    let m = Manifests {
        package_json: vec![
            pkg(
                "package.json",
                Some("app"),
                None,
                &[("#net", "src/net.js"), ("#lib/*", "src/*.js")],
            ),
            pkg(
                "packages/client/package.json",
                Some("@acme/client"),
                Some("packages/client/index.js"),
                &[],
            ),
            pkg(
                "packages/lib/package.json",
                Some("lib"),
                Some("packages/lib/dist/main.js"),
                &[],
            ),
        ],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    assert_eq!(
        hit(&rules, &idx, "src/app.js", "#net").as_deref(),
        Some("src/net.js")
    );
    assert_eq!(
        hit(&rules, &idx, "src/app.js", "#lib/net").as_deref(),
        Some("src/net.js")
    );
    assert_eq!(hit(&rules, &idx, "src/app.js", "#missing"), None);
    assert_eq!(
        hit(&rules, &idx, "packages/app/index.js", "@acme/client").as_deref(),
        Some("packages/client/index.js")
    );
    assert_eq!(
        hit(&rules, &idx, "a.js", "lib").as_deref(),
        Some("packages/lib/dist/main.js")
    );
    assert_eq!(
        hit(&rules, &idx, "a.js", "lib/sub/x").as_deref(),
        Some("packages/lib/sub/x.ts")
    );
    match rules.classify(b"a.js", "@acme/client") {
        SpecifierKind::Bare { module, .. } => assert_eq!(module, "@acme/client"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn dependency_package_resolves_its_own_name_and_leaves_others_external() {
    // Inside `node_modules/leftpad/` the package resolves its own name
    // through `package.json` `main` then `index`, as the dependency
    // pass reuses these rules over the scoped discovery (KTD10).
    let idx = index(&[
        "node_modules/leftpad/index.js",
        "node_modules/leftpad/api.js",
    ]);
    let m = Manifests {
        package_json: vec![pkg(
            "node_modules/leftpad/package.json",
            Some("leftpad"),
            Some("node_modules/leftpad/index.js"),
            &[],
        )],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    assert_eq!(
        hit(&rules, &idx, "node_modules/leftpad/api.js", "leftpad").as_deref(),
        Some("node_modules/leftpad/index.js")
    );
    assert_eq!(
        rules.classify(b"node_modules/leftpad/api.js", "padder"),
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: "padder".into()
        }
    );
    // Without `main`, the package's own name falls back to `index`.
    let m = Manifests {
        package_json: vec![pkg(
            "node_modules/leftpad/package.json",
            Some("leftpad"),
            None,
            &[],
        )],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    assert_eq!(
        hit(&rules, &idx, "node_modules/leftpad/api.js", "leftpad").as_deref(),
        Some("node_modules/leftpad/index.js")
    );
}

#[test]
fn tsconfig_paths_and_base_url_resolve_and_fall_back_to_bare() {
    let idx = index(&["src/net/http.ts", "src/lib/util.ts"]);
    let m = Manifests {
        tsconfig: vec![
            TsConfig {
                path: b"tsconfig.json".to_vec(),
                extends: vec![b"tsconfig.base.json".to_vec()],
                base_url: None,
                paths: Vec::new(),
            },
            TsConfig {
                path: b"tsconfig.base.json".to_vec(),
                extends: Vec::new(),
                base_url: Some(b"src".to_vec()),
                paths: vec![
                    ("@net/*".into(), vec![b"src/net/*".to_vec()]),
                    ("*".into(), vec![b"src/vendor/*".to_vec()]),
                ],
            },
        ],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    assert_eq!(
        hit(&rules, &idx, "src/app.ts", "@net/http").as_deref(),
        Some("src/net/http.ts")
    );
    assert_eq!(
        hit(&rules, &idx, "src/app.ts", "lib/util").as_deref(),
        Some("src/lib/util.ts")
    );
    // A catch-all pattern with no target falls back to the package.
    assert_eq!(
        rules.classify(b"src/app.ts", "axios"),
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: "axios".into()
        }
    );
}

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
                extends_package: Vec::new(),
                references: Vec::new(),
                include: None,
                files: None,
                exclude: None,
                base_url: None,
                paths: Vec::new(),
            },
            TsConfig {
                path: b"tsconfig.base.json".to_vec(),
                extends: Vec::new(),
                extends_package: Vec::new(),
                references: Vec::new(),
                include: None,
                files: None,
                exclude: None,
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

/// KTD15, AE11: a `references[]` config claims the files under its
/// `include`; ownership beats `nearest()`, and the first claimant in
/// depth-first reference order wins a contested file.
#[test]
fn tsconfig_references_claim_files_and_apply_their_paths() {
    let idx = index(&[
        "tsconfig.json",
        "tsconfig.app.json",
        "src/main.ts",
        "src/api.ts",
        "other/util.ts",
    ]);
    let m = Manifests {
        tsconfig: vec![
            TsConfig {
                path: b"tsconfig.json".to_vec(),
                extends: Vec::new(),
                extends_package: Vec::new(),
                references: vec![b"tsconfig.app.json".to_vec()],
                include: None,
                files: Some(Vec::new()),
                exclude: None,
                base_url: None,
                paths: Vec::new(),
            },
            TsConfig {
                path: b"tsconfig.app.json".to_vec(),
                extends: Vec::new(),
                extends_package: Vec::new(),
                references: Vec::new(),
                include: Some(vec![b"src".to_vec()]),
                files: None,
                exclude: None,
                base_url: None,
                paths: vec![("@/*".into(), vec![b"src/*".to_vec()])],
            },
        ],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    // src/main.ts is claimed by tsconfig.app.json: `@/api` resolves.
    assert_eq!(
        hit(&rules, &idx, "src/main.ts", "@/api").as_deref(),
        Some("src/api.ts")
    );
    // other/util.ts is claimed by none and falls back to nearest(),
    // which gives the root tsconfig.json: no paths, so `@/api` is bare.
    assert_eq!(
        rules.classify(b"other/util.ts", "@/api"),
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: "@/api".into()
        }
    );
}

/// Two configs claiming one file: the first in depth-first reference
/// order wins; with no references the byte-wise path order decides.
#[test]
fn tsconfig_contested_file_goes_to_the_first_claimant() {
    let idx = index(&[
        "a/tsconfig.json",
        "b/tsconfig.json",
        "x/file.ts",
        "x/api.ts",
    ]);
    let cfg =
        |path: &str, inc: &[&str], paths: Vec<(String, Vec<Vec<u8>>)>, refs: Vec<&str>| TsConfig {
            path: path.as_bytes().to_vec(),
            extends: Vec::new(),
            extends_package: Vec::new(),
            references: refs.iter().map(|r| r.as_bytes().to_vec()).collect(),
            include: Some(inc.iter().map(|i| i.as_bytes().to_vec()).collect()),
            files: None,
            exclude: None,
            base_url: None,
            paths,
        };
    // b claims x/** via a plain pattern; a references b and also claims
    // x/** with its own (wrong) paths. DFS from a reaches b second:
    // a's order puts b before a? No: the DFS visits a first, then b,
    // so a claims x/file.ts first.
    let m = Manifests {
        tsconfig: vec![
            cfg(
                "a/tsconfig.json",
                &["x/**"],
                vec![("@/*".into(), vec![b"x/*".to_vec()])],
                vec!["b/tsconfig.json"],
            ),
            cfg(
                "b/tsconfig.json",
                &["x/**"],
                vec![("!/*".into(), vec![b"x/*".to_vec()])],
                vec![],
            ),
        ],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    // a is visited first (roots byte-wise: a < b) and claims x/file.ts;
    // `@/api` resolves through a's paths.
    assert_eq!(
        hit(&rules, &idx, "x/file.ts", "@/api").as_deref(),
        Some("x/api.ts")
    );
    // `!/api` is b's pattern and never fires: the file belongs to a.
    assert_eq!(
        rules.classify(b"x/file.ts", "!/api"),
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: "!/api".into()
        }
    );
}

/// `exclude` removes a file from `include` claims but never from
/// `files`; `files: []` suppresses the default `**/*` include.
#[test]
fn tsconfig_exclude_filters_include_not_files() {
    let idx = index(&[
        "a/tsconfig.json",
        "b/tsconfig.json",
        "x/kept.ts",
        "x/gen/out.ts",
        "x/api.ts",
        "x/alt.ts",
        "listed.ts",
    ]);
    let cfg = |path: &str,
               inc: Option<&[&str]>,
               files: Option<&[&str]>,
               exc: Option<&[&str]>,
               paths: Vec<(String, Vec<Vec<u8>>)>| TsConfig {
        path: path.as_bytes().to_vec(),
        extends: Vec::new(),
        extends_package: Vec::new(),
        references: Vec::new(),
        include: inc.map(|v| v.iter().map(|i| i.as_bytes().to_vec()).collect()),
        files: files.map(|v| v.iter().map(|i| i.as_bytes().to_vec()).collect()),
        exclude: exc.map(|v| v.iter().map(|i| i.as_bytes().to_vec()).collect()),
        base_url: None,
        paths,
    };
    let m = Manifests {
        tsconfig: vec![
            // a (byte-wise first) claims x/** minus x/gen, plus listed.ts
            // through `files`; its `@/*` points at x/*.
            cfg(
                "a/tsconfig.json",
                Some(&["x/**"]),
                Some(&["listed.ts"]),
                Some(&["x/gen"]),
                vec![("@/*".into(), vec![b"x/*".to_vec()])],
            ),
            // b claims x/gen/** only; `!/*` points at x/* as well.
            cfg(
                "b/tsconfig.json",
                Some(&["x/gen/**"]),
                None,
                None,
                vec![("!/*".into(), vec![b"x/*".to_vec()])],
            ),
        ],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    // x/kept.ts is claimed by a; x/gen/out.ts is excluded from a's
    // include and falls to b's claim, so `!/api` resolves there but
    // `@/api` does not. listed.ts is claimed through a's `files`
    // even though it is under no `include` pattern.
    assert_eq!(
        hit(&rules, &idx, "x/kept.ts", "@/api").as_deref(),
        Some("x/api.ts")
    );
    assert_eq!(
        rules.classify(b"x/gen/out.ts", "@/api"),
        SpecifierKind::Bare {
            probes: Vec::new(),
            module: "@/api".into()
        }
    );
    assert_eq!(
        hit(&rules, &idx, "x/gen/out.ts", "!/alt").as_deref(),
        Some("x/alt.ts")
    );
    assert_eq!(
        hit(&rules, &idx, "listed.ts", "@/api").as_deref(),
        Some("x/api.ts")
    );
}

/// `include` inherited through `extends` resolves relative to the
/// declaring config, not the extending one.
#[test]
fn tsconfig_include_inherits_relative_to_the_declaring_config() {
    let idx = index(&[
        "tsconfig.json",
        "base/tsconfig.base.json",
        "base/src/api.ts",
        "base/src/main.ts",
    ]);
    let m = Manifests {
        tsconfig: vec![
            TsConfig {
                path: b"tsconfig.json".to_vec(),
                extends: vec![b"base/tsconfig.base.json".to_vec()],
                extends_package: Vec::new(),
                references: Vec::new(),
                include: None,
                files: None,
                exclude: None,
                base_url: None,
                paths: vec![("@/*".into(), vec![b"base/src/*".to_vec()])],
            },
            TsConfig {
                path: b"base/tsconfig.base.json".to_vec(),
                extends: Vec::new(),
                extends_package: Vec::new(),
                references: Vec::new(),
                include: Some(vec![b"base/src".to_vec()]),
                files: None,
                exclude: None,
                base_url: None,
                paths: Vec::new(),
            },
        ],
        ..Manifests::default()
    };
    let rules = JsRules::from_parts(&idx, &m);
    // The root config is a named root; its effective include comes from
    // the base config declaring `base/src`, so base/src/main.ts is
    // claimed and `@/api` resolves there.
    assert_eq!(
        hit(&rules, &idx, "base/src/main.ts", "@/api").as_deref(),
        Some("base/src/api.ts")
    );
}

/// A hostile `include` with dozens of `*`/`**` segments over a large
/// generated tree stays linear per file.
#[test]
fn tsconfig_hostile_include_stays_bounded() {
    let mut names: Vec<String> = Vec::new();
    for i in 0..3_000 {
        names.push(format!("src/d{}/f{}.ts", i % 40, i));
    }
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut idx = index(&refs);
    idx.insert(b"tsconfig.json".to_vec(), FileKind::Other);
    let pat = "**/*".repeat(24) + "/**/*.ts";
    let m = Manifests {
        tsconfig: vec![TsConfig {
            path: b"tsconfig.json".to_vec(),
            extends: Vec::new(),
            extends_package: Vec::new(),
            references: Vec::new(),
            include: Some(vec![pat.as_bytes().to_vec()]),
            files: None,
            exclude: None,
            base_url: None,
            paths: Vec::new(),
        }],
        ..Manifests::default()
    };
    let start = std::time::Instant::now();
    let _rules = JsRules::from_parts(&idx, &m);
    assert!(start.elapsed().as_secs() < 20, "{:?}", start.elapsed());
}

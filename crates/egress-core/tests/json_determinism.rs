//! Deterministic JSON and the v1 schema.

mod common;

use egress_core::json::to_json;
use egress_core::model::SCHEMA_VERSION;

#[test]
fn insertion_order_does_not_change_output() {
    let a = common::full_report();
    let mut b = a.clone();
    b.sites.reverse();
    b.blind_spots.reverse();
    b.excluded.reverse();
    b.completeness.budget_exceeded.reverse();
    b.sites[0].labels.reverse();
    b.sites[1].labels.reverse();
    b.sites[2].labels.reverse();
    let (ja, jb) = (to_json(&a), to_json(&b));
    assert_eq!(ja, jb);
    assert!(ja.ends_with("}\n") && !ja.ends_with("\n\n"));
}

#[test]
fn collections_are_sorted_by_identity_components_not_line() {
    let json = to_json(&common::full_report());
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let files: Vec<&str> = v["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["file"].as_str().unwrap())
        .collect();
    assert_eq!(files, vec!["src/api.py", "src/api.py", "src/notify.py"]);
    let symbols: Vec<&str> = v["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["symbol"].as_str().unwrap())
        .collect();
    assert_eq!(symbols, vec!["<module>", "Api.get", "send"]);
    let labels = &v["sites"][1]["labels"];
    assert_eq!(labels, &serde_json::json!(["test", "vendored"]));
    let budgets = &v["completeness"]["budget_exceeded"];
    assert_eq!(
        budgets,
        &serde_json::json!(["budget-files", "budget-findings"])
    );
}

#[test]
fn field_order_and_shape_follow_the_design() {
    let json = to_json(&common::full_report());
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["schema_version"], SCHEMA_VERSION);
    let top = [
        "\"schema_version\"",
        "\"tool\"",
        "\"completeness\"",
        "\"caveats\"",
        "\"sites\"",
        "\"blind_spots\"",
        "\"unscanned_dependencies\"",
        "\"excluded\"",
    ];
    let pos: Vec<usize> = top.iter().map(|k| json.find(k).unwrap()).collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}");
    assert_eq!(v["tool"]["runtime_range"]["node"], "18 to 22");
    assert_eq!(v["completeness"]["state"], "incomplete");
    assert_eq!(v["completeness"]["coverage"]["python"]["scanned"], 3);
    assert_eq!(v["caveats"][0]["id"], "browser-dom");
    let site = v["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["symbol"] == "send")
        .unwrap();
    assert_eq!(site["destination"]["kind"], "env");
    assert_eq!(site["destination"]["value"], "WEBHOOK_URL");
    assert_eq!(site["destination"]["default"], "https://h.example/x");
    assert_eq!(site["destination"]["display"], "env:WEBHOOK_URL");
    assert_eq!(site["bucket"], "catalogued");
    assert_eq!(site["mechanism"], "python:requests.post");
    assert_eq!(site["location"]["line"], 12);
    let whole = v["blind_spots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["kind"] == "parse-error")
        .unwrap();
    assert_eq!(whole["location"], serde_json::Value::Null);
    assert_eq!(whole["whole_file"], true);
    let gap = v["blind_spots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["kind"] == "unconfirmed-exclusion")
        .unwrap();
    assert_eq!(gap["language"], serde_json::Value::Null);
    assert_eq!(
        v["unscanned_dependencies"][0]["files"],
        serde_json::json!(["src/a.js", "src/z.js"])
    );
    assert_eq!(v["excluded"][0]["reason"], "broken-symlink");
    assert_eq!(v["excluded"][0]["path_bytes"], "626164ff");
}

#[test]
fn every_report_validates_against_the_schema() {
    for r in [
        common::full_report(),
        common::report(vec![], vec![]),
        common::report_with_dependencies(),
    ] {
        let json = to_json(&r);
        common::validate(&json).unwrap_or_else(|e| panic!("{e}\n{json}"));
    }
}

#[test]
fn absent_dependencies_serializes_to_the_existing_key_set_and_order() {
    let r = common::full_report();
    assert!(r.dependencies.is_none());
    let json = to_json(&r);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(!json.contains("\"dependencies\""));
    // Top level: exactly today's keys.
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "blind_spots",
            "caveats",
            "completeness",
            "excluded",
            "schema_version",
            "sites",
            "tool",
            "unscanned_dependencies"
        ]
    );
    // An unscanned entry with no new fields set: exactly today's keys,
    // in today's order.
    let entry = &v["unscanned_dependencies"][0];
    let mut keys: Vec<&str> = entry
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["files", "id", "language", "package"]);
    let entry_start = json.find("\"unscanned_dependencies\"").unwrap();
    let tail = &json[entry_start..];
    let order = ["\"id\"", "\"language\"", "\"package\"", "\"files\""];
    let pos: Vec<usize> = order.iter().map(|k| tail.find(k).unwrap()).collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}");
}

fn sorted_keys(v: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = v
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str().to_string())
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn full_dependency_section_uses_the_shape_table_key_order() {
    let json = to_json(&common::report_with_dependencies());
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    // `dependencies` comes after `excluded`.
    let ex = json.find("\"excluded\"").unwrap();
    let deps = json.find("\"dependencies\"").unwrap();
    assert!(ex < deps);
    let section = &json[deps..];
    let order = [
        "\"roots\"",
        "\"caveats\"",
        "\"budget_exceeded\"",
        "\"diagnostics\"",
        "\"auto_run\"",
        "\"packages\":",
    ];
    let pos: Vec<usize> = order.iter().map(|k| section.find(k).unwrap()).collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}");
    // The package entry holds every field in table order. `packages` also
    // appears as a budget value, so anchor on the key colon.
    let packages = section.find("\"packages\":").unwrap();
    let entry = &section[packages..];
    let order = [
        "\"id\"",
        "\"language\"",
        "\"package\"",
        "\"root\"",
        "\"locator\"",
        "\"version\"",
        "\"strength\"",
        "\"modified\"",
        "\"catalogued\"",
        "\"distribution\"",
        "\"distribution_source\"",
        "\"mark\"",
        "\"imported_by\"",
        "\"imported_by_packages\"",
        "\"state\"",
        "\"coverage\"",
        "\"sites\"",
        "\"blind_spots\"",
        "\"imports_unscanned\"",
    ];
    let pos: Vec<usize> = order.iter().map(|k| entry.find(k).unwrap()).collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}");
    // `imported_by` before `imported_by_packages`; `find` on the shorter
    // name would match the longer one's prefix, so check key sets too.
    let pkg = v["dependencies"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["package"] == "requests")
        .unwrap();
    assert_eq!(
        pkg["imported_by"],
        serde_json::json!(["src/a.py", "src/z.py"])
    );
    // Booleans true-or-absent: the linked entry emits `linked` and drops
    // `modified` and `catalogued`.
    let linked = v["dependencies"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["package"] == "serde")
        .unwrap();
    assert_eq!(sorted_keys(linked), {
        let mut k = sorted_keys(pkg);
        k.retain(|f| {
            ![
                "modified",
                "catalogued",
                "distribution",
                "distribution_source",
                "mark",
            ]
            .contains(&f.as_str())
        });
        k.push("linked".into());
        k.sort_unstable();
        k
    });
    assert_eq!(linked["linked"], true);
}

#[test]
fn dependency_lists_are_sorted_and_reverse_insertion_is_identical() {
    let a = common::report_with_dependencies();
    let mut b = a.clone();
    let d = b.dependencies.as_mut().unwrap();
    d.packages[1].sites.reverse();
    d.packages[1].blind_spots.reverse();
    d.packages.reverse();
    d.auto_run.reverse();
    d.roots.reverse();
    d.budget_exceeded.reverse();
    assert_eq!(to_json(&a), to_json(&b));
    let v: serde_json::Value = serde_json::from_str(&to_json(&a)).unwrap();
    let packages: Vec<&str> = v["dependencies"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["package"].as_str().unwrap())
        .collect();
    // Sorted by identity: language, package, root, locator.
    assert_eq!(packages, ["requests", "serde"]);
    let roots: Vec<&str> = v["dependencies"]["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["label"].as_str().unwrap())
        .collect();
    assert_eq!(roots, ["deps/vendor", "deps/venv"]);
    let auto: Vec<&str> = v["dependencies"]["auto_run"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["file"].as_str().unwrap())
        .collect();
    assert_eq!(auto, ["a.pth", "sitecustomize.py"]);
    assert_eq!(
        v["dependencies"]["budget_exceeded"],
        serde_json::json!(["files", "packages"])
    );
    let id: Vec<&str> = v["dependencies"]["auto_run"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert!(id.iter().all(|i| i.len() == 16));
}

#[test]
fn removing_required_dependency_lists_fails_validation() {
    let base: serde_json::Value =
        serde_json::from_str(&to_json(&common::report_with_dependencies())).unwrap();
    common::validate_value(&base).unwrap();
    for path in [
        &["dependencies", "roots"][..],
        &["dependencies", "packages"][..],
    ] {
        let mut v = base.clone();
        remove(&mut v, path);
        assert!(
            common::validate_value(&v).is_err(),
            "removing {path:?} still validates"
        );
    }
}

#[test]
fn unknown_property_inside_a_package_entry_fails_validation() {
    let mut v: serde_json::Value =
        serde_json::from_str(&to_json(&common::report_with_dependencies())).unwrap();
    v["dependencies"]["packages"][0]["surprise"] = 1.into();
    assert!(common::validate_value(&v).is_err());
    // The same holds inside the section itself and its other objects.
    let mut v: serde_json::Value =
        serde_json::from_str(&to_json(&common::report_with_dependencies())).unwrap();
    v["dependencies"]["surprise"] = 1.into();
    assert!(common::validate_value(&v).is_err());
    let mut v: serde_json::Value =
        serde_json::from_str(&to_json(&common::report_with_dependencies())).unwrap();
    v["dependencies"]["auto_run"][0]["surprise"] = 1.into();
    assert!(common::validate_value(&v).is_err());
    let mut v: serde_json::Value =
        serde_json::from_str(&to_json_report_with_unscanned_fields()).unwrap();
    v["unscanned_dependencies"][0]["surprise"] = 1.into();
    assert!(common::validate_value(&v).is_err());
}

fn to_json_report_with_unscanned_fields() -> String {
    let mut r = common::full_report();
    r.unscanned_dependencies[0].reason =
        Some(egress_core::model::UnscannedReason::NoSourceInNamedRoot);
    r.unscanned_dependencies[0].distribution = vec!["PyYAML".into()];
    r.unscanned_dependencies[0].distribution_source =
        Some(egress_core::model::DistributionSource::Curated);
    r.unscanned_dependencies[0].mark = Some(egress_core::model::DependencyMark {
        rules: vec![egress_core::model::MarkRule::NonAsciiName],
        resembles: vec!["left-pad".into()],
    });
    to_json(&r)
}

#[test]
fn new_unscanned_fields_serialize_and_validate() {
    let json = to_json_report_with_unscanned_fields();
    common::validate(&json).unwrap_or_else(|e| panic!("{e}\n{json}"));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let entry = &v["unscanned_dependencies"][0];
    assert_eq!(entry["reason"], "no-source-in-named-root");
    assert_eq!(entry["distribution"], serde_json::json!(["PyYAML"]));
    assert_eq!(entry["distribution_source"], "curated");
    assert_eq!(
        entry["mark"],
        serde_json::json!({"rules": ["non-ascii-name"], "resembles": ["left-pad"]})
    );
    // The new fields come after `files`, in table order.
    let start = json.find("\"unscanned_dependencies\"").unwrap();
    let tail = &json[start..];
    let order = [
        "\"files\"",
        "\"reason\"",
        "\"distribution\"",
        "\"distribution_source\"",
        "\"mark\"",
    ];
    let pos: Vec<usize> = order.iter().map(|k| tail.find(k).unwrap()).collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}");
}

#[test]
fn dependency_free_text_fields_are_escaped() {
    use egress_core::escape::needs_escape;
    let hostile = "a\u{202e}b\u{1b}";
    assert!(hostile.chars().any(needs_escape));
    let mut r = common::report(vec![], vec![]);
    let mut sec = common::dependency_section();
    sec.roots[0].label = hostile.into();
    sec.auto_run[0].file = hostile.into();
    sec.auto_run[0].root = hostile.into();
    sec.auto_run[0].distribution = hostile.into();
    let pkg = &mut sec.packages[1];
    pkg.package = hostile.into();
    pkg.root = hostile.into();
    pkg.locator = hostile.into();
    pkg.version = hostile.into();
    pkg.distribution = vec![hostile.into()];
    pkg.mark.as_mut().unwrap().resembles = vec![hostile.into()];
    pkg.imports_unscanned[0].package = hostile.into();
    r.dependencies = Some(sec);
    let json = to_json(&r);
    common::validate(&json).unwrap_or_else(|e| panic!("{e}\n{json}"));
    // U+202E survives serde's escaping; only `escape` renders it inert. In
    // the raw text the escaped form's backslash is itself JSON-escaped.
    assert!(!json.contains('\u{202e}'), "{json}");
    assert!(json.contains("a\\\\u{202e}b\\\\u{1b}"), "{json}");
    assert!(!json.contains("a\u{1b}b"), "{json}");
}

fn remove(v: &mut serde_json::Value, path: &[&str]) {
    let (last, parents) = path.split_last().unwrap();
    let mut cur = v;
    for p in parents {
        cur = match p.parse::<usize>() {
            Ok(i) => &mut cur[i],
            Err(_) => &mut cur[*p],
        };
    }
    assert!(
        cur.as_object_mut().unwrap().remove(*last).is_some(),
        "{path:?}"
    );
}

#[test]
fn removing_any_required_field_fails_validation() {
    let json = to_json(&common::full_report());
    let base: serde_json::Value = serde_json::from_str(&json).unwrap();
    common::validate_value(&base).unwrap();
    let cases: &[&[&str]] = &[
        &["caveats"],
        &["schema_version"],
        &["tool"],
        &["tool", "runtime_range"],
        &["tool", "data_digest"],
        &["completeness", "budget_exceeded"],
        &["completeness", "state"],
        &["completeness", "coverage", "rust"],
        &["completeness", "coverage", "unsupported"],
        &["sites"],
        &["sites", "0", "id"],
        &["sites", "0", "destination", "display"],
        &["sites", "0", "location"],
        &["blind_spots", "0", "construct"],
        &["blind_spots", "0", "coverage_gap"],
        &["unscanned_dependencies", "0", "package"],
        &["excluded", "0", "reason"],
        &["caveats", "0", "text"],
    ];
    for path in cases {
        let mut v = base.clone();
        remove(&mut v, path);
        assert!(
            common::validate_value(&v).is_err(),
            "removing {path:?} still validates"
        );
    }
}

#[test]
fn schema_rejects_wrong_values() {
    let base: serde_json::Value = serde_json::from_str(&to_json(&common::full_report())).unwrap();
    let mut bad = Vec::new();
    let mut v = base.clone();
    v["schema_version"] = 2.into();
    bad.push(v);
    let mut v = base.clone();
    v["completeness"]["state"] = "partial".into();
    bad.push(v);
    let mut v = base.clone();
    v["sites"][0]["id"] = "XYZ".into();
    bad.push(v);
    let mut v = base.clone();
    v["sites"][0]["destination"]["kind"] = "url".into();
    bad.push(v);
    let mut v = base.clone();
    v["blind_spots"][0]["kind"] = "nope".into();
    bad.push(v);
    let mut v = base.clone();
    v["sites"][0]["file_bytes"] = "FF".into();
    bad.push(v);
    for v in bad {
        assert!(common::validate_value(&v).is_err(), "{v}");
    }
}

#[test]
fn schema_enums_match_the_model() {
    use egress_core::model::*;
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schema/egress-report.v1.json")).unwrap();
    let list = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    };
    let strs = |v: Vec<&str>| -> Vec<String> { v.into_iter().map(String::from).collect() };
    let defs = &schema["$defs"];
    let props = &schema["properties"];
    assert_eq!(
        list(&defs["blind_spot"]["properties"]["kind"]["enum"]),
        strs(BlindSpotKind::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&defs["labels"]["items"]["enum"]),
        strs(Label::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&defs["language"]["enum"]),
        strs(Language::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&props["excluded"]["items"]["properties"]["reason"]["enum"]),
        strs(ExcludedReason::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&props["completeness"]["properties"]["budget_exceeded"]["items"]["enum"]),
        strs(BudgetReason::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&props["completeness"]["properties"]["state"]["enum"]),
        strs(CompletenessState::ALL.iter().map(|k| k.as_str()).collect())
    );
    let kinds = [
        DestinationKind::Literal,
        DestinationKind::Env,
        DestinationKind::Param,
        DestinationKind::Template,
        DestinationKind::Exec,
        DestinationKind::Lib,
        DestinationKind::Expr,
    ];
    assert_eq!(
        list(&defs["destination"]["properties"]["kind"]["enum"]),
        strs(kinds.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&defs["site"]["properties"]["bucket"]["enum"]),
        strs(vec![
            Bucket::Primitive.as_str(),
            Bucket::Catalogued.as_str()
        ])
    );
    let deps = &props["dependencies"]["properties"];
    let pkg = &defs["dependency_package"]["properties"];
    assert_eq!(
        list(&defs["unscanned_reason"]["enum"]),
        strs(UnscannedReason::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&defs["distribution_source"]["enum"]),
        strs(DistributionSource::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&defs["mark"]["properties"]["rules"]["items"]["enum"]),
        strs(MarkRule::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&deps["roots"]["items"]["properties"]["kind"]["enum"]),
        strs(DependencyRootKind::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&deps["budget_exceeded"]["items"]["enum"]),
        strs(
            DependencyBudgetReason::ALL
                .iter()
                .map(|k| k.as_str())
                .collect()
        )
    );
    assert_eq!(
        list(&deps["diagnostics"]["items"]["properties"]["problem"]["enum"]),
        strs(LockfileProblem::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&deps["auto_run"]["items"]["properties"]["trigger"]["enum"]),
        strs(AutoRunTrigger::ALL.iter().map(|k| k.as_str()).collect())
    );
    assert_eq!(
        list(&pkg["strength"]["enum"]),
        strs(
            VerificationStrength::ALL
                .iter()
                .map(|k| k.as_str())
                .collect()
        )
    );
    assert_eq!(
        list(&pkg["state"]["enum"]),
        strs(CompletenessState::ALL.iter().map(|k| k.as_str()).collect())
    );
}

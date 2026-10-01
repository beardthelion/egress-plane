//! Deterministic JSON and the v1 schema (KTD10, R10, R14, R16, R23).

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
    for r in [common::full_report(), common::report(vec![], vec![])] {
        let json = to_json(&r);
        common::validate(&json).unwrap_or_else(|e| panic!("{e}\n{json}"));
    }
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
}

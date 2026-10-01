use std::path::PathBuf;

use super::guards::{self, Deferred};
use super::*;

const PRIM: &str = r#"
language = "python"
runtime_range = "3.8-3.13"

[ambient]
module = "builtins"
aliases = ["__builtins__"]

[[module]]
name = "builtins"
class = "egress"

[[module]]
name = "json"
class = "inert"
justification = "Parses and serializes text; loads no code and opens nothing."

[[module]]
name = "os"
class = "egress"

[[module]]
name = "os.path"
class = "inert"
justification = "Pure path string functions."

[[module]]
name = "socket"
class = "egress"

[[entry]]
id = "python:builtins.eval"
kind = "blind-spot"
blind_spot = "dynamic-code"
reason = "evaluates a string as code"
fixture = "python/evasive/eval"

[[entry]]
id = "python:os.system"
kind = "egress"
mechanism = "process"
destination = { arg = 1, form = "program" }
fixture = "python/primitives/os-system"

[[entry]]
id = "python:socket.socket"
kind = "egress"
mechanism = "network"
constructor = true
fixture = "python/primitives/socket-socket"

[[entry]]
id = "python:socket.socket.connect"
kind = "egress"
mechanism = "network"
destination = { arg = 1, form = "host-port" }
fixture = "python/primitives/socket-socket"

[[inert]]
module = "socket"
members = ["AF_*", "htons"]
justification = "Constants and byte-order helpers."
fixture = "python/primitives/must-not-socket-constants"
"#;

const CAT: &str = r#"
language = "python"

[[package]]
name = "requests"

[[entry]]
id = "python:requests.get"
kind = "egress"
mechanism = "network"
destination = { arg = 1, keyword = "url", form = "url" }
fixture = "python/ordinary/requests-get-literal"

[[inert]]
module = "requests"
members = ["exceptions"]
justification = "Exception classes only."
fixture = "python/primitives/must-not-requests-exceptions"
"#;

const INV: &str = r#"
language = "python"
generated_from = ["3.12.3"]
stdlib_modules = ["builtins", "json", "os", "socket"]

[members]
builtins = ["eval"]
os = ["path", "system"]
socket = ["AF_INET", "socket", "htons"]
"#;

fn rt(prim: &str, cat: &str, inv: &str) -> Result<RuntimeData, String> {
    load_runtime(
        Language::Python,
        ("p.toml", prim),
        ("c.toml", cat),
        ("i.toml", inv),
    )
}

fn ok() -> RuntimeData {
    rt(PRIM, CAT, INV).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn loads_minimal_runtime() {
    let r = ok();
    assert_eq!(r.runtime_range, "3.8-3.13");
    assert!(r.entry("python:socket.AF_*").is_some());
    assert!(r.entry("python:requests.exceptions").is_some());
    assert_eq!(
        r.entry("python:os.system").map(|e| e.module.as_str()),
        Some("os")
    );
}

#[test]
fn digest_is_stable_order_independent_and_content_sensitive() {
    let a = data_digest(&[("a", "1"), ("b", "2")]);
    assert_eq!(a, data_digest(&[("a", "1"), ("b", "2")]));
    assert_eq!(a, data_digest(&[("b", "2"), ("a", "1")]));
    assert_ne!(a, data_digest(&[("a", "1"), ("b", "3")]));
    // Moving bytes across the file boundary changes the digest.
    assert_ne!(
        data_digest(&[("a", "12"), ("b", "")]),
        data_digest(&[("a", "1"), ("b", "2")])
    );
    assert!(a.starts_with("sha256:") && a.len() == 7 + 64);
}

#[test]
fn duplicate_entry_id_fails_with_the_id() {
    let dup = format!(
        "{PRIM}\n[[entry]]\nid = \"python:os.system\"\nkind = \"egress\"\nmechanism = \"process\"\nfixture = \"x/y/z\"\n"
    );
    let e = rt(&dup, CAT, INV).unwrap_err();
    assert!(e.contains("duplicate entry ID python:os.system"), "{e}");
}

#[test]
fn duplicate_from_inert_group_fails_with_the_id() {
    let dup = format!(
        "{PRIM}\n[[inert]]\nmodule = \"socket\"\nmembers = [\"htons\"]\njustification = \"j\"\nfixture = \"x/y/z\"\n"
    );
    let e = rt(&dup, CAT, INV).unwrap_err();
    assert!(e.contains("python:socket.htons"), "{e}");
}

#[test]
fn missing_kind_fails_with_the_id() {
    let bad = format!("{PRIM}\n[[entry]]\nid = \"python:os.popen\"\nfixture = \"x/y/z\"\n");
    let e = rt(&bad, CAT, INV).unwrap_err();
    assert!(
        e.contains("python:os.popen") && e.contains("missing kind"),
        "{e}"
    );
}

#[test]
fn wholly_inert_module_without_justification_fails_with_the_module() {
    let bad = format!("{PRIM}\n[[module]]\nname = \"csv\"\nclass = \"inert\"\n");
    let e = rt(&bad, CAT, INV).unwrap_err();
    assert!(
        e.contains("module csv") && e.contains("justification"),
        "{e}"
    );
    let blank =
        format!("{PRIM}\n[[module]]\nname = \"csv\"\nclass = \"inert\"\njustification = \"  \"\n");
    let e = rt(&blank, CAT, INV).unwrap_err();
    assert!(e.contains("module csv"), "{e}");
}

#[test]
fn catalog_inert_pattern_without_justification_fails_with_the_pattern() {
    let group = format!(
        "{CAT}\n[[inert]]\nmodule = \"requests\"\nmembers = [\"codes\"]\nfixture = \"x/y/z\"\n"
    );
    let e = rt(PRIM, &group, INV).unwrap_err();
    assert!(
        e.contains("requests") && e.contains("codes") && e.contains("justification"),
        "{e}"
    );
    let single = format!(
        "{CAT}\n[[entry]]\nid = \"python:requests.codes\"\nkind = \"inert\"\nfixture = \"x/y/z\"\n"
    );
    let e = rt(PRIM, &single, INV).unwrap_err();
    assert!(
        e.contains("python:requests.codes") && e.contains("justification"),
        "{e}"
    );
}

#[test]
fn undeclared_module_and_bad_glob_fail() {
    let bad = format!(
        "{PRIM}\n[[entry]]\nid = \"python:nosuch.x\"\nkind = \"egress\"\nmechanism = \"network\"\nfixture = \"x/y/z\"\n"
    );
    assert!(rt(&bad, CAT, INV).unwrap_err().contains("python:nosuch.x"));
    let glob = format!(
        "{PRIM}\n[[inert]]\nmodule = \"socket\"\nmembers = [\"a*.b\"]\njustification = \"j\"\nfixture = \"x/y/z\"\n"
    );
    assert!(rt(&glob, CAT, INV).unwrap_err().contains("glob"));
}

#[test]
fn lookup_is_longest_prefix_with_submodules_and_globs() {
    let r = ok();
    let id = |c: Option<Classification<'_>>| match c {
        Some(Classification::Entry(e)) => e.id.clone(),
        Some(Classification::Module(m)) => format!("module {}", m.name),
        Some(Classification::Package(p)) => format!("package {}", p.name),
        None => "none".into(),
    };
    assert_eq!(id(r.lookup("os", &["system"])), "python:os.system");
    assert_eq!(id(r.lookup("os", &["path", "join"])), "module os.path");
    assert_eq!(id(r.lookup("os.path", &["join"])), "module os.path");
    assert_eq!(id(r.lookup("os", &["getcwd"])), "module os");
    assert_eq!(
        id(r.lookup("socket", &["socket", "connect"])),
        "python:socket.socket.connect"
    );
    assert_eq!(
        id(r.lookup("socket", &["socket", "close"])),
        "python:socket.socket"
    );
    assert_eq!(id(r.lookup("socket", &["AF_INET"])), "python:socket.AF_*");
    assert_eq!(id(r.lookup("requests", &["get"])), "python:requests.get");
    assert_eq!(id(r.lookup("requests", &["foo"])), "package requests");
    assert_eq!(id(r.lookup("yaml", &["load"])), "none");
}

#[test]
fn ambient_forms_reach_one_entry() {
    let r = ok();
    for chain in [
        &["eval"][..],
        &["builtins", "eval"][..],
        &["__builtins__", "eval"][..],
    ] {
        match r.lookup_global(chain) {
            Some(Classification::Entry(e)) => assert_eq!(e.id, "python:builtins.eval", "{chain:?}"),
            other => panic!("{chain:?}: {other:?}"),
        }
    }
}

#[test]
fn scope_glob_package_matches_scoped_packages_only() {
    assert!(module_name_matches("@aws-sdk/*", "@aws-sdk/client-s3"));
    assert!(!module_name_matches("@aws-sdk/*", "@aws-sdk/client-s3/sub"));
    assert!(!module_name_matches("@aws-sdk/*", "@aws-sdkx/client"));
    assert!(!module_name_matches("@aws-sdk/*", "@aws-sdk/"));
    assert!(glob_matches("*Command", "GetObjectCommand"));
    assert!(!glob_matches("*Command", "S3Client"));
    assert!(glob_matches("AF_*", "AF_INET"));
    assert!(!glob_matches("AF_*", "SO_REUSEADDR"));
}

// ---- guards on synthetic data -------------------------------------------

#[test]
fn stdlib_guard_flags_unclassified_and_stray_modules() {
    let r = ok();
    assert!(guards::stdlib_classification(&r).is_empty());
    let mut missing = r.clone();
    missing.modules.retain(|m| m.name != "json");
    let v = guards::stdlib_classification(&missing);
    assert!(v.iter().any(|s| s.contains("json")), "{v:?}");
    let mut stray = r.clone();
    stray.inventory.stdlib_modules.retain(|m| m != "json");
    let v = guards::stdlib_classification(&stray);
    assert!(v.iter().any(|s| s.contains("json")), "{v:?}");
}

#[test]
fn deny_guard_flags_inert_module_and_covering_inert_pattern() {
    let r = ok();
    assert!(guards::deny_list(&r, &["os", "socket"]).is_empty());
    let mut m = r.clone();
    for x in &mut m.modules {
        if x.name == "os" {
            x.class = ModuleClass::Inert;
        }
    }
    assert!(!guards::deny_list(&m, &["os"]).is_empty());
    // An inert pattern at the module level of a deny-list submodule.
    assert!(!guards::deny_list(&r, &["os.path"]).is_empty());
}

#[test]
fn inventory_guard_flags_unclassified_member_and_missing_inventory() {
    let r = ok();
    assert!(
        guards::inventory(&r, &[]).is_empty(),
        "{:?}",
        guards::inventory(&r, &[])
    );
    let mut m = r.clone();
    m.entries.retain(|e| e.id != "python:socket.htons");
    let v = guards::inventory(&m, &[]);
    assert!(v.iter().any(|s| s.contains("socket.htons")), "{v:?}");
    let mut m = r.clone();
    m.inventory.members.remove("socket");
    assert!(!guards::inventory(&m, &[]).is_empty());
    // Must-not: an inert module outside the deny list needs no inventory.
    assert!(!r.inventory.members.contains_key("json"));
    assert!(guards::inventory(&r, &[]).is_empty());
    // A deny-list module needs an inventory even when it is not egress-class.
    let mut m = r.clone();
    for x in &mut m.modules {
        if x.name == "json" {
            x.class = ModuleClass::Inert;
        }
    }
    assert!(!guards::inventory(&m, &["json"]).is_empty());
}

#[test]
fn not_inert_guard() {
    let r = ok();
    assert!(guards::not_inert(&r, &["python:os.system", "python:builtins.eval"]).is_empty());
    assert!(!guards::not_inert(&r, &["python:socket.htons"]).is_empty());
    assert!(!guards::not_inert(&r, &["python:os.nosuch"]).is_empty());
}

struct TempCorpus(PathBuf);

impl TempCorpus {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("egress-core-data-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        TempCorpus(dir)
    }

    fn case(&self, id: &str, expected: &str, file: &str, source: &str) {
        let d = self.0.join(id);
        std::fs::create_dir_all(d.join("tree")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(d.join("expected.toml"), expected).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(d.join("tree").join(file), source).unwrap_or_else(|e| panic!("{e}"));
    }
}

impl Drop for TempCorpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn site_case(mechanism: &str) -> String {
    format!(
        "state = \"complete\"\nexit_code = 0\n\n[[sites]]\nfile = \"a.py\"\nsymbol = \"<module>\"\nmechanism = \"{mechanism}\"\ndestination = \"x\"\n"
    )
}

fn full_corpus(c: &TempCorpus) {
    c.case(
        "python/primitives/os-system",
        &site_case("python:os.system"),
        "a.py",
        "",
    );
    c.case(
        "python/primitives/socket-socket",
        &(site_case("python:socket.socket")
            + "\n[[sites]]\nfile = \"a.py\"\nsymbol = \"<module>\"\nmechanism = \"python:socket.socket.connect\"\ndestination = \"x\"\n"),
        "a.py",
        "",
    );
    c.case(
        "python/ordinary/requests-get-literal",
        &site_case("python:requests.get"),
        "a.py",
        "",
    );
    c.case(
        "python/primitives/must-not-socket-constants",
        "state = \"complete\"\nexit_code = 0\n",
        "a.py",
        "import socket\nsocket.htons(1)\nsocket.AF_INET\n",
    );
    c.case(
        "python/primitives/must-not-requests-exceptions",
        "state = \"complete\"\nexit_code = 0\n",
        "a.py",
        "import requests\nrequests.exceptions\n",
    );
}

fn deferred(cases: &[&str]) -> Deferred {
    Deferred {
        cases: cases.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn fixture_guard_accepts_existing_labeled_cases_and_deferred_entries() {
    let c = TempCorpus::new("ok");
    full_corpus(&c);
    let r = ok();
    let d = deferred(&["python/evasive/eval"]);
    let v = guards::fixtures(&r, &c.0, &d);
    assert!(v.is_empty(), "{v:?}");
    assert!(guards::stale_deferred(&[&r], &c.0, &d).is_empty());
}

#[test]
fn fixture_guard_fails_when_entry_names_neither_case_nor_deferred() {
    let c = TempCorpus::new("neither");
    full_corpus(&c);
    let r = ok();
    // The blind-spot entry's case exists nowhere and the ledger is empty.
    let v = guards::fixtures(&r, &c.0, &deferred(&[]));
    assert!(
        v.iter()
            .any(|s| s.contains("python:builtins.eval") && s.contains("python/evasive/eval")),
        "{v:?}"
    );
}

#[test]
fn fixture_guard_fails_when_a_fixture_is_deleted() {
    let c = TempCorpus::new("deleted");
    full_corpus(&c);
    let _ = std::fs::remove_dir_all(c.0.join("python/primitives/os-system"));
    let v = guards::fixtures(&ok(), &c.0, &deferred(&["python/evasive/eval"]));
    assert!(v.iter().any(|s| s.contains("python:os.system")), "{v:?}");
}

#[test]
fn fixture_guard_fails_when_case_does_not_label_the_entry() {
    let c = TempCorpus::new("unlabeled");
    full_corpus(&c);
    c.case(
        "python/primitives/os-system",
        &site_case("python:os.popen"),
        "a.py",
        "",
    );
    let v = guards::fixtures(&ok(), &c.0, &deferred(&["python/evasive/eval"]));
    assert!(v.iter().any(|s| s.contains("python:os.system")), "{v:?}");
    // An inert entry's case must be a must-not case naming the member.
    c.case(
        "python/primitives/must-not-socket-constants",
        "state = \"complete\"\nexit_code = 0\n",
        "a.py",
        "import socket\n",
    );
    let v = guards::fixtures(&ok(), &c.0, &deferred(&["python/evasive/eval"]));
    assert!(v.iter().any(|s| s.contains("python:socket.htons")), "{v:?}");
}

#[test]
fn deferred_ledger_rejects_stale_and_existing_entries() {
    let c = TempCorpus::new("stale");
    full_corpus(&c);
    let r = ok();
    let v = guards::stale_deferred(
        &[&r],
        &c.0,
        &deferred(&["python/evasive/eval", "python/evasive/unused"]),
    );
    assert!(
        v.iter().any(|s| s.contains("python/evasive/unused")),
        "{v:?}"
    );
    let v = guards::stale_deferred(
        &[&r],
        &c.0,
        &deferred(&["python/evasive/eval", "python/primitives/os-system"]),
    );
    assert!(
        v.iter().any(|s| s.contains("python/primitives/os-system")),
        "{v:?}"
    );
    assert!(guards::parse_deferred("cases = [\"a/b/c\", \"a/b/c\"]\n").is_err());
    assert_eq!(
        guards::parse_deferred("cases = [\"a/b/c\"]\n").map(|d| d.cases.len()),
        Ok(1)
    );
}

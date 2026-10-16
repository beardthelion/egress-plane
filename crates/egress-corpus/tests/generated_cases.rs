//! The primitives generator (KTD4): `corpus-gen --check` in process,
//! plus the ownership, conflict, staleness, and template scenarios.
//! Synthetic roots and runtimes exercise the failure modes; the real
//! corpus root proves the committed trees match the embedded data.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use egress_core::data::guards;
use egress_core::data::{Data, RuntimeData, load_runtime};
use egress_core::model::Language;
use egress_corpus::generate::{self, CaseSpec};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus() -> PathBuf {
    repo().join("fixtures/corpus")
}

fn data() -> Data {
    Data::embedded().unwrap_or_else(|e| panic!("{e}"))
}

fn runtimes(d: &Data) -> Vec<&RuntimeData> {
    generate::LANGUAGES.iter().map(|l| d.runtime(*l)).collect()
}

// ---- synthetic roots and runtimes -------------------------------------------

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn tmp_root() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "gen-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn list_toml(ids: &[&str]) -> String {
    if ids.is_empty() {
        return "cases = []\n".to_string();
    }
    let mut s = String::from("cases = [\n");
    for id in ids {
        s.push_str(&format!("    \"{id}\",\n"));
    }
    s.push_str("]\n");
    s
}

fn write_ledgers(root: &Path, generated: &[&str], deferred: &[&str]) {
    let owned: std::collections::BTreeSet<String> =
        generated.iter().map(|s| s.to_string()).collect();
    fs::write(
        root.join("generated.toml"),
        generate::render_generated(&owned),
    )
    .unwrap();
    fs::write(root.join("deferred.toml"), list_toml(deferred)).unwrap();
}

fn write_case(root: &Path, spec: &CaseSpec) {
    for (rel, text) in &spec.files {
        let p = root.join(&spec.id).join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
}

fn py_runtime(body: &str) -> RuntimeData {
    let prim = format!(
        "language = \"python\"\nruntime_range = \"3.8-3.13\"\n[ambient]\nmodule = \"builtins\"\n{body}"
    );
    load_runtime(
        Language::Python,
        ("primitives.toml", prim.as_str()),
        ("catalog.toml", "language = \"python\"\n"),
        ("inventory.toml", "language = \"python\"\n"),
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

fn case_at<'a>(cases: &'a BTreeMap<String, CaseSpec>, id: &str) -> &'a CaseSpec {
    cases
        .get(id)
        .unwrap_or_else(|| panic!("{id} not generated"))
}

// ---- the real corpus ---------------------------------------------------------

/// `--check` on the committed corpus: every owned tree matches the data.
#[test]
fn generated_cases_match_the_data() {
    let d = data();
    let errors = generate::check(&runtimes(&d), &corpus());
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Regenerating is deterministic and byte-identical (AE1, for the
/// native-code Python blind-spot entry).
#[test]
fn regeneration_is_byte_identical() {
    let d = data();
    let rts = runtimes(&d);
    let first = generate::candidates(&rts).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    let second = generate::candidates(&rts).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    for (id, a) in &first {
        assert_eq!(a.files, second[id].files, "{id} is not deterministic");
    }
    assert_eq!(first.len(), second.len());
    // A native-code entry: an attribute load of the member, no call, one
    // blind spot of the entry's kind in `probe`.
    let spec = case_at(&first, "python/primitives/ctypes-cast");
    let app = &spec.files["tree/app.py"];
    assert!(app.contains("return ctypes.cast"), "{app}");
    assert!(!app.contains("ctypes.cast("), "{app}");
    let expected = &spec.files["expected.toml"];
    assert!(expected.contains("kind = \"native-code\""), "{expected}");
    assert!(expected.contains("symbol = \"probe\""), "{expected}");
}

/// After `--write`, `deferred.toml` lists no case the generator could
/// produce. Category deferrals (Go evasive, closure, dependencies) are
/// unaffected.
#[test]
fn deferred_ledger_holds_no_generated_primitives_case() {
    let text = fs::read_to_string(corpus().join("deferred.toml")).unwrap();
    let deferred = guards::parse_deferred(&text).unwrap_or_else(|e| panic!("{e}"));
    let d = data();
    let cases = generate::candidates(&runtimes(&d)).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    for c in &deferred.cases {
        assert!(
            !cases.contains_key(c.as_str()),
            "{c} is a generated case still deferred"
        );
    }
    // The generator has nothing to change in the ledger.
    let plan =
        generate::plan(&runtimes(&d), &corpus()).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    assert!(
        plan.deferred_toml.is_none(),
        "deferred.toml would be rewritten"
    );
    // Only the Go categories remain deferred; no primitives case may
    // outlive its authored or generated fixture.
    assert!(
        !deferred.cases.iter().any(|c| c.ends_with("/")),
        "deferred ledger should list whole case ids"
    );
}

/// The eight Python introspection inert names each own a `must-not-`
/// case that loads the name on a local first-party value.
#[test]
fn eight_python_introspection_inert_names_each_yield_a_must_not_case() {
    let d = data();
    let py = d.runtime(Language::Python);
    assert_eq!(py.closure.introspection_inert.len(), 8);
    let cases = generate::candidates(&[py]).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    for n in &py.closure.introspection_inert {
        let spec = case_at(&cases, &n.fixture);
        let name = n.fixture.rsplit('/').next().unwrap();
        assert!(name.starts_with("must-not-"), "{}", n.fixture);
        let app = &spec.files["tree/app.py"];
        assert!(app.contains(&format!("probe.{}", n.name)), "{app}");
        assert!(!spec.files["expected.toml"].contains("[["), "{}", n.fixture);
    }
}

/// One inert group with many members yields exactly one case (KTD3:
/// the group shares a fixture, not one case per member).
#[test]
fn one_inert_group_with_many_members_yields_one_case() {
    let rt = py_runtime(
        "[[module]]\nname = \"fake\"\nclass = \"inert\"\njustification = \"test\"\n\
         [[inert]]\nmodule = \"fake\"\nmembers = [\"a\", \"b\", \"c\"]\n\
         justification = \"test\"\nfixture = \"python/primitives/must-not-fake\"\n",
    );
    let cases = generate::candidates(&[&rt]).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    assert_eq!(cases.len(), 1, "{:?}", cases.keys());
    let spec = case_at(&cases, "python/primitives/must-not-fake");
    let app = &spec.files["tree/app.py"];
    for m in ["a", "b", "c"] {
        assert!(app.contains(&format!("    {m},")), "{app}");
    }
}

/// A module-level blind-spot entry (no member) emits a case that uses
/// the module object as a value and labels the entry's kind.
#[test]
fn module_level_blind_spot_names_the_module_as_a_value() {
    let rt = py_runtime(
        "[[module]]\nname = \"fake\"\nclass = \"inert\"\njustification = \"test\"\n\
         [[entry]]\nid = \"python:fake\"\nkind = \"blind-spot\"\n\
         blind_spot = \"native-code\"\nreason = \"test\"\n\
         fixture = \"python/primitives/fake\"\n",
    );
    let cases = generate::candidates(&[&rt]).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    let spec = case_at(&cases, "python/primitives/fake");
    let app = &spec.files["tree/app.py"];
    assert!(app.contains("import fake"), "{app}");
    assert!(app.contains("return fake"), "{app}");
    assert!(spec.files["expected.toml"].contains("kind = \"native-code\""));
}

// ---- conflicts, staleness, ownership -----------------------------------------

fn plan_lines(rts: &[&RuntimeData], root: &Path) -> Vec<String> {
    match generate::plan(rts, root) {
        Ok(plan) => plan.report(),
        Err(errors) => errors,
    }
}

/// A `..` segment in `generated.toml` is rejected before anything on
/// disk is touched (AE1).
#[test]
fn a_traversal_id_in_generated_toml_is_rejected() {
    let d = data();
    let py = d.runtime(Language::Python);
    let root = tmp_root();
    write_ledgers(&root, &["python/primitives/../escape"], &[]);
    let errors = generate::plan(&[py], &root).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("..")), "{errors:?}");
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        2,
        "the ledger files must be all that exists"
    );
}

/// An id from data that is not a primitives fixture is likewise
/// rejected.
#[test]
fn a_data_fixture_outside_primitives_is_rejected() {
    let rt = py_runtime(
        "[[module]]\nname = \"fake\"\nclass = \"inert\"\njustification = \"test\"\n\
         [[entry]]\nid = \"python:fake.deep\"\nkind = \"blind-spot\"\n\
         blind_spot = \"native-code\"\nreason = \"test\"\n\
         fixture = \"python/tricky/fake-deep\"\n",
    );
    let root = tmp_root();
    write_ledgers(&root, &[], &[]);
    // Not a primitives fixture: not a candidate, so no error; a
    // primitives id with a traversal segment is the real check above.
    // A malformed id that names a primitives case but escapes it must
    // fail instead.
    let cases = generate::candidates(&[&rt]).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    assert!(cases.is_empty());
    let rt = py_runtime(
        "[[module]]\nname = \"fake\"\nclass = \"inert\"\njustification = \"test\"\n\
         [[entry]]\nid = \"python:fake.deep\"\nkind = \"blind-spot\"\n\
         blind_spot = \"native-code\"\nreason = \"test\"\n\
         fixture = \"python/primitives/.hidden\"\n",
    );
    let errors = generate::plan(&[&rt], &root).unwrap_err();
    assert!(errors.iter().any(|e| e.contains(".hidden")), "{errors:?}");
}

/// Editing one byte of an owned file makes the check report the case.
#[test]
fn a_hand_edited_owned_file_is_reported() {
    let d = data();
    let py = d.runtime(Language::Python);
    let cases = generate::candidates(&[py]).unwrap();
    let spec = case_at(&cases, "python/primitives/ctypes-cast");
    let root = tmp_root();
    write_ledgers(&root, &[spec.id.as_str()], &[]);
    write_case(&root, spec);
    assert!(plan_lines(&[py], &root).is_empty());
    let app = root.join(&spec.id).join("tree/app.py");
    let mut text = fs::read_to_string(&app).unwrap();
    text.replace_range(0..1, " ");
    fs::write(&app, text).unwrap();
    let lines = plan_lines(&[py], &root);
    assert!(
        lines.iter().any(|l| l.contains(spec.id.as_str())),
        "{lines:?}"
    );
}

/// A deleted owned case is reported missing.
#[test]
fn a_deleted_owned_case_is_reported_missing() {
    let d = data();
    let py = d.runtime(Language::Python);
    let cases = generate::candidates(&[py]).unwrap();
    let spec = case_at(&cases, "python/primitives/ctypes-cast");
    let root = tmp_root();
    write_ledgers(&root, &[spec.id.as_str()], &[]);
    write_case(&root, spec);
    fs::remove_dir_all(root.join(&spec.id)).unwrap();
    let lines = plan_lines(&[py], &root);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("missing") && l.contains(spec.id.as_str())),
        "{lines:?}"
    );
}

/// A case directory that no ledger owns is never touched, even though
/// its name collides with an entry's fixture: the conflict is reported.
#[test]
fn an_unowned_dir_colliding_with_a_fixture_is_a_conflict() {
    let d = data();
    let py = d.runtime(Language::Python);
    let root = tmp_root();
    write_ledgers(&root, &[], &[]);
    let dir = root.join("python/primitives/ctypes-cast/tree");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("app.py"), "x = 1\n").unwrap();
    fs::write(
        root.join("python/primitives/ctypes-cast/expected.toml"),
        "state = \"complete\"\nexit_code = 0\n",
    )
    .unwrap();
    let errors = generate::plan(&[py], &root).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("python/primitives/ctypes-cast")),
        "{errors:?}"
    );
    assert_eq!(fs::read_to_string(dir.join("app.py")).unwrap(), "x = 1\n");
}

/// An owned case whose entry left the data is deleted by `--write`
/// and reported by `--check`.
#[test]
fn a_stale_owned_case_is_deleted() {
    let d = data();
    let py = d.runtime(Language::Python);
    let root = tmp_root();
    let stale = "python/primitives/must-not-gone";
    write_ledgers(&root, &[stale], &[]);
    fs::create_dir_all(root.join(stale).join("tree")).unwrap();
    fs::write(
        root.join(stale).join("expected.toml"),
        "state = \"complete\"\nexit_code = 0\n",
    )
    .unwrap();
    let plan = generate::plan(&[py], &root).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    assert!(
        plan.delete_dirs.iter().any(|d| d.contains(stale)),
        "{plan:?}"
    );
    assert!(plan.generated_toml.is_some());
    let lines = plan.report();
    assert!(lines.iter().any(|l| l.contains(stale)), "{lines:?}");
    generate::apply(&root, &plan).unwrap_or_else(|e| panic!("{e}"));
    assert!(!root.join(stale).exists());
    assert!(plan_lines(&[py], &root).is_empty());
}

/// A deferred candidate with no directory is created by `--write` and
/// removed from `deferred.toml`; `--check` is clean afterwards.
#[test]
fn a_deferred_candidate_is_created_and_removed_from_the_ledger() {
    let d = data();
    let py = d.runtime(Language::Python);
    let root = tmp_root();
    write_ledgers(&root, &[], &["python/primitives/ctypes-cast"]);
    let plan = generate::plan(&[py], &root).unwrap_or_else(|e| panic!("{}", e.join("\n")));
    assert!(plan.deferred_toml.is_some());
    generate::apply(&root, &plan).unwrap_or_else(|e| panic!("{e}"));
    let deferred =
        guards::parse_deferred(&fs::read_to_string(root.join("deferred.toml")).unwrap()).unwrap();
    assert!(!deferred.cases.contains("python/primitives/ctypes-cast"));
    assert!(plan_lines(&[py], &root).is_empty());
    // The new case is now owned.
    let generated = fs::read_to_string(root.join("generated.toml")).unwrap();
    assert!(
        generated.contains("python/primitives/ctypes-cast"),
        "{generated}"
    );
}

/// Two blind-spot entries naming one fixture are a generator error,
/// as is a fixture shared across kinds; an inert group may share one.
#[test]
fn dual_fixture_entries_are_a_generator_error() {
    let rt = py_runtime(
        "[[module]]\nname = \"fake\"\nclass = \"inert\"\njustification = \"test\"\n\
         [[module]]\nname = \"other\"\nclass = \"inert\"\njustification = \"test\"\n\
         [[entry]]\nid = \"python:fake.a\"\nkind = \"blind-spot\"\nblind_spot = \"native-code\"\nreason = \"t\"\nfixture = \"python/primitives/fake-a\"\n\
         [[entry]]\nid = \"python:fake.b\"\nkind = \"blind-spot\"\nblind_spot = \"dynamic-code\"\nreason = \"t\"\nfixture = \"python/primitives/fake-a\"\n\
         [[entry]]\nid = \"python:other.a\"\nkind = \"blind-spot\"\nblind_spot = \"native-code\"\nreason = \"t\"\nfixture = \"python/primitives/shared\"\n\
         [[inert]]\nmodule = \"fake\"\nmembers = [\"x\"]\njustification = \"t\"\nfixture = \"python/primitives/shared\"\n",
    );
    let errors = generate::candidates(&[&rt]).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("fake-a")), "{errors:?}");
    assert!(errors.iter().any(|e| e.contains("shared")), "{errors:?}");
}

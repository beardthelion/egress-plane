//! The KTD17 Python distribution signal: installed metadata in a named
//! root first, then the curated table filtered by the declarations read
//! on every scan. The signal annotates entries only (R19).

mod support;

use egress_core::data::{Data, DistributionMapping};
use egress_core::deps::inventory::Inventory;
use egress_core::discover::budgets::DependencyBudgets;
use egress_core::discover::dependency_roots::{inventory, open};
use egress_core::discover::open::RootDir;
use egress_core::discover::{Config, Discovery, discover};
use egress_core::model::DistributionSource;
use egress_core::names::python_distribution;
use support::Tree;

fn table() -> Vec<DistributionMapping> {
    Data::embedded()
        .unwrap_or_else(|e| panic!("{e}"))
        .python_distributions
}

fn declared(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn resolve(
    import: &str,
    inventories: &[Inventory],
    declared: &[String],
) -> (Vec<String>, Option<DistributionSource>) {
    python_distribution(import, inventories, declared, &table())
}

// ---- curated table ---------------------------------------------------------

/// AE7: `import yaml` with `PyYAML` declared and no root named gives
/// `PyYAML`, source curated.
#[test]
fn declared_distribution_is_emitted_as_declared_and_curated() {
    let (d, s) = resolve("yaml", &[], &declared(&["PyYAML"]));
    assert_eq!(d, ["PyYAML"]);
    assert_eq!(s, Some(DistributionSource::Curated));
    // The declared spelling wins over the table's.
    let (d, s) = resolve("yaml", &[], &declared(&["pyyaml"]));
    assert_eq!(d, ["pyyaml"]);
    assert_eq!(s, Some(DistributionSource::Curated));
}

#[test]
fn with_no_declaration_the_table_spelling_stands() {
    let (d, s) = resolve("yaml", &[], &[]);
    assert_eq!(d, ["PyYAML"]);
    assert_eq!(s, Some(DistributionSource::Curated));
}

#[test]
fn declarations_that_omit_the_candidate_drop_it() {
    let (d, s) = resolve("yaml", &[], &declared(&["requests"]));
    assert!(d.is_empty() && s.is_none());
    // A declaration that names only some candidates keeps those.
    let (d, s) = resolve("Crypto", &[], &declared(&["pycryptodome"]));
    assert_eq!(d, ["pycryptodome"]);
    assert_eq!(s, Some(DistributionSource::Curated));
}

#[test]
fn several_candidates_give_a_sorted_list_never_a_guess() {
    let (d, s) = resolve("cv2", &[], &[]);
    assert_eq!(
        d,
        [
            "opencv-contrib-python",
            "opencv-python",
            "opencv-python-headless"
        ]
    );
    assert_eq!(s, Some(DistributionSource::Curated));
}

#[test]
fn an_import_the_table_does_not_map_stays_unattributed() {
    let (d, s) = resolve("leftpad", &[], &[]);
    assert!(d.is_empty() && s.is_none());
}

// ---- installed metadata ------------------------------------------------------

fn disc(t: &Tree) -> Discovery {
    discover(&t.root, &Config::default()).unwrap_or_else(|e| panic!("{e}"))
}

fn venv_inventory(t: &Tree, tag: &str) -> Vec<Inventory> {
    let venv = t.outside.join(tag);
    let named = open(
        &RootDir::open(&t.root).unwrap_or_else(|e| panic!("{e}")),
        &[venv],
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let d = disc(t);
    inventory(&named, &d, &DependencyBudgets::default()).unwrap_or_else(|e| panic!("{e}"))
}

/// A venv holding `PyJWT` whose `RECORD` lists `jwt/`: `import jwt`
/// resolves `PyJWT` from installed metadata, not the table.
#[test]
fn a_named_venv_record_gives_the_distribution_as_installed_metadata() {
    let t = Tree::new("names-record");
    t.outside_file("venv/pyvenv.cfg", "home = /usr/bin\n");
    t.outside_file(
        "venv/lib/python3.12/site-packages/PyJWT-2.8.0.dist-info/METADATA",
        "Metadata-Version: 2.1\nName: PyJWT\nVersion: 2.8.0\n",
    );
    t.outside_file(
        "venv/lib/python3.12/site-packages/PyJWT-2.8.0.dist-info/RECORD",
        "jwt/__init__.py,sha256=a,1\njwt/api.py,sha256=b,1\nPyJWT-2.8.0.dist-info/RECORD,,\n",
    );
    t.outside_file("venv/lib/python3.12/site-packages/jwt/__init__.py", "");
    let inv = venv_inventory(&t, "venv");
    // The table also maps `jwt`; installed metadata still wins.
    let (d, s) = resolve("jwt", &inv, &declared(&["jwt"]));
    assert_eq!(d, ["PyJWT"]);
    assert_eq!(s, Some(DistributionSource::InstalledMetadata));
}

/// `top_level.txt` supplies the import names when `RECORD` is missing.
#[test]
fn top_level_txt_is_used_when_record_is_missing() {
    let t = Tree::new("names-top-level");
    t.outside_file(
        "sitepk/leftpy-1.0.0.dist-info/METADATA",
        "Metadata-Version: 2.1\nName: LeftPy\nVersion: 1.0.0\n",
    );
    t.outside_file("sitepk/leftpy-1.0.0.dist-info/top_level.txt", "leftpy\n");
    t.outside_file("sitepk/leftpy/__init__.py", "");
    let inv = venv_inventory(&t, "sitepk");
    let (d, s) = python_distribution("leftpy", &inv, &[], &[]);
    assert_eq!(d, ["LeftPy"]);
    assert_eq!(s, Some(DistributionSource::InstalledMetadata));
}

/// An instance flagged unsupported contributes no installed candidate;
/// a loose module with no `dist-info` is not a distribution either.
#[test]
fn unsupported_or_distributionless_instances_contribute_nothing() {
    let t = Tree::new("names-unsupported");
    // METADATA is missing, so the instance is flagged unsupported.
    t.outside_file(
        "sitepk/junk-1.0.dist-info/RECORD",
        "jwt/__init__.py,sha256=a,1\n",
    );
    t.outside_file("sitepk/jwt/__init__.py", "");
    t.outside_file("sitepk/loose.py", "");
    let inv = venv_inventory(&t, "sitepk");
    let (d, s) = python_distribution("jwt", &inv, &[], &[]);
    assert!(d.is_empty() && s.is_none());
    let (d, s) = python_distribution("loose", &inv, &[], &[]);
    assert!(d.is_empty() && s.is_none());
}

// ---- declarations on disk ----------------------------------------------------

/// The requirements-file parser skips option lines, URLs, and comments.
#[test]
fn requirements_lines_contribute_only_requirement_names() {
    let text = "\
-r base.txt
--requirement other.txt
-e .
--editable ../pkg
--hash=sha256:deadbeef
https://example.com/pkg.tar.gz
git+https://example.com/repo.git#egg=x
# a comment
./local/dir

PyYAML>=6; python_version>\"3\"
requests[security] @ https://example.com/r.whl
";
    let got = egress_core::discover::manifests::requirements(text);
    assert_eq!(got, ["PyYAML", "requests"]);
}

/// `requirements*.txt` files are read through the index: a dev file
/// contributes names and `must_not_change_state_on_unreadable_declarations`
/// holds for one that cannot be read.
#[test]
fn requirements_files_on_disk_feed_declarations() {
    let t = Tree::new("names-requirements");
    t.file("requirements-dev.txt", "-r base.txt\nPyYAML>=6\n")
        .file("requirements/base.txt", "requests\n")
        .file("notes.txt", "PyMuPDF\n");
    let d = disc(&t);
    assert_eq!(d.manifests.python_declarations, ["PyYAML"]);
    // `base.txt` is not a `requirements*.txt` name.
    assert!(d.blind_spots.is_empty(), "{:?}", d.blind_spots);
}

#[test]
fn must_not_change_state_on_unreadable_declarations() {
    if support::privileged() {
        return;
    }
    let t = Tree::new("names-unreadable-req");
    t.file("requirements.txt", "PyYAML\n")
        .file("app.py", "x = 1\n");
    t.chmod("requirements.txt", 0o000);
    let d = disc(&t);
    assert!(d.manifests.python_declarations.is_empty());
    assert!(
        !d.blind_spots.iter().any(|b| b.file == "requirements.txt"),
        "{:?}",
        d.blind_spots
    );
}

//! Manifest parsing and manifest-declared paths.
//!
//! Discovery reads each manifest through the safe open path with the 8 MiB
//! cap, then parses it here on a worker stack with panic capture. A failure is
//! a `manifest-parse-error` for that manifest, never a tool error. JSON is
//! strict except for `tsconfig.json` and the in-tree files its `extends`
//! names, which are JSONC as `tsc` accepts. Every declared path is folded
//! lexically against the manifest's directory: a target that is absolute or
//! climbs above the root is reported by the key that named it, and the target
//! itself is never kept.

use serde_json::Value;

use crate::model::Language;
use crate::paths::{dir_of, is_dot_relative};

/// A manifest that does not parse; reported as `manifest-parse-error`. Parser
/// messages are dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed manifest")
    }
}

impl std::error::Error for Malformed {}

/// Manifest files discovery parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    Cargo,
    PackageJson,
    TsConfig,
    PyProject,
    SetupCfg,
    GoMod,
    GoWork,
    /// `vendor/modules.txt`. It is never routed by name alone: discovery
    /// parses it only when its parent directory is named `vendor` and a
    /// `go.mod` or `go.work` sits at or above that directory (KTD9).
    GoModules,
}

impl ManifestKind {
    pub const ALL: [ManifestKind; 8] = [
        Self::Cargo,
        Self::PackageJson,
        Self::TsConfig,
        Self::PyProject,
        Self::SetupCfg,
        Self::GoMod,
        Self::GoWork,
        Self::GoModules,
    ];

    /// The file name that routes to this kind.
    pub fn file_name(self) -> &'static [u8] {
        match self {
            Self::Cargo => b"Cargo.toml",
            Self::PackageJson => b"package.json",
            Self::TsConfig => b"tsconfig.json",
            Self::PyProject => b"pyproject.toml",
            Self::SetupCfg => b"setup.cfg",
            Self::GoMod => b"go.mod",
            Self::GoWork => b"go.work",
            Self::GoModules => b"modules.txt",
        }
    }

    /// The language whose spec row lists this manifest's file name.
    pub fn language(self) -> Language {
        // `modules.txt` is path-routed, so no spec row lists it.
        if self == Self::GoModules {
            return Language::Go;
        }
        let name = self.file_name();
        Language::ALL
            .into_iter()
            .find(|l| l.spec().manifests.iter().any(|m| m.as_bytes() == name))
            .unwrap_or_else(|| panic!("manifest kind has no spec row"))
    }

    /// The kind a file name routes to. `GoModules` is absent: a
    /// `vendor/modules.txt` is routed by the vendor-directory path gate
    /// in `discover`, never by name.
    pub fn for_name(name: &[u8]) -> Option<ManifestKind> {
        Self::ALL
            .into_iter()
            .find(|k| *k != ManifestKind::GoModules && k.file_name() == name)
    }
}

/// How a Cargo package declares its build script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildScript {
    /// No `build` key: `build.rs` beside the manifest, when present.
    Default,
    /// `build = false`.
    Disabled,
    /// `build = "<path>"`, as an in-root path.
    Path(Vec<u8>),
    /// The named script lies outside the root.
    Outside,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoManifest {
    pub path: Vec<u8>,
    /// Whether the manifest has a `[package]` table (a virtual workspace
    /// manifest has none and runs no build script).
    pub has_package: bool,
    pub name: Option<String>,
    pub build: BuildScript,
    pub proc_macro: bool,
    /// In-root paths of `[lib]`, `[[bin]]`, `[[example]]`, `[[test]]`, and
    /// `[[bench]]` targets.
    pub targets: Vec<Vec<u8>>,
    /// The in-root `[lib] path`, when declared.
    pub lib_path: Option<Vec<u8>>,
    /// The `[lib] name`, when declared.
    pub lib_name: Option<String>,
    /// Dependency keys renamed with `package = "..."`, as (key, package),
    /// from every dependency table of the package.
    pub renames: Vec<(String, String)>,
    /// Dependency keys declared with `workspace = true`.
    pub inherited: Vec<String>,
    /// Renames declared in `[workspace.dependencies]`, as (key, package).
    pub workspace_renames: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageJson {
    pub path: Vec<u8>,
    pub name: Option<String>,
    /// In-root `workspaces` patterns, root-relative; globs expand later only
    /// against the file index.
    pub workspaces: Vec<Vec<u8>>,
    /// In-root `bin` targets.
    pub bin: Vec<Vec<u8>>,
    /// The in-root `main` entry point, if any. Resolution facts only: an
    /// out-of-root `main` or `imports` target is left out here and reported
    /// by the importing reference.
    pub main: Option<Vec<u8>>,
    /// `imports` (`#internal`) patterns and their in-root path targets; a
    /// conditional target takes its `node`, `import`, `require`, or
    /// `default` branch, first present wins.
    pub imports: Vec<(String, Vec<u8>)>,
    /// npm lifecycle scripts present, in [`NPM_LIFECYCLE`] order.
    pub lifecycle: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsConfig {
    pub path: Vec<u8>,
    /// In-root `extends` targets.
    pub extends: Vec<Vec<u8>>,
    pub base_url: Option<Vec<u8>>,
    /// `paths` patterns and their in-root target patterns.
    pub paths: Vec<(String, Vec<Vec<u8>>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyProject {
    pub path: Vec<u8>,
    pub build_backend: Option<String>,
    /// In-root `backend-path` entries.
    pub backend_path: Vec<Vec<u8>>,
    /// Declared distribution names (KTD17) from `[project] dependencies`
    /// and `[tool.poetry.dependencies]`, as written.
    pub declared: Vec<String>,
}

/// Parsed `setup.cfg` facts (KTD17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCfg {
    pub path: Vec<u8>,
    /// `[options] install_requires` distribution names, as written.
    pub declared: Vec<String>,
}

/// A `replace` right-hand side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoReplaceTarget {
    /// An in-root path, folded against the manifest's directory.
    Path(Vec<u8>),
    /// A path outside the root: never followed, read, or printed.
    Outside,
    /// A module path and version (`example.com/x v1.2.3`).
    Module {
        path: String,
        version: Option<String>,
    },
}

/// One `replace` directive: `from[ version] => target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoReplace {
    pub from: String,
    /// The version the left side pins; `None` replaces every version.
    pub from_version: Option<String>,
    pub to: GoReplaceTarget,
}

/// Parsed `go.mod` facts (KTD9). `toolchain`, `tool`, `exclude`,
/// `retract`, and unknown directives are skipped and never acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoMod {
    pub path: Vec<u8>,
    /// The `module` path, when declared.
    pub module: Option<String>,
    /// The `go` directive's version text, for example `1.22`.
    pub go: Option<String>,
    /// `require` entries as (module path, version).
    pub require: Vec<(String, String)>,
    pub replace: Vec<GoReplace>,
}

/// Parsed `go.work` facts (KTD9). `toolchain`, `godebug`, and unknown
/// directives are skipped and never acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoWork {
    pub path: Vec<u8>,
    pub go: Option<String>,
    /// Folded in-root `use` directories.
    pub uses: Vec<Vec<u8>>,
    pub replace: Vec<GoReplace>,
}

/// One package a `vendor/modules.txt` lists under its module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoVendorPackage {
    /// The package's import path, for example `github.com/acme/lib/sub`.
    pub path: String,
    /// The module the package was vendored from.
    pub module: String,
    /// The module version the `#` line records.
    pub version: Option<String>,
}

/// A parsed `vendor/modules.txt` (KTD9). Discovery parses it only under
/// `vendor/` with a `go.mod` or `go.work` at or above; `link` keys the
/// vendored package set by the file's governing vendor directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoModules {
    pub path: Vec<u8>,
    /// Vendored package paths in file order.
    pub packages: Vec<GoVendorPackage>,
}

/// Parsed manifest facts later stages map into the file index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifests {
    pub cargo: Vec<CargoManifest>,
    pub package_json: Vec<PackageJson>,
    pub tsconfig: Vec<TsConfig>,
    pub pyproject: Vec<PyProject>,
    pub setup_cfg: Vec<SetupCfg>,
    pub go_mod: Vec<GoMod>,
    pub go_work: Vec<GoWork>,
    /// Parsed `vendor/modules.txt` lists.
    pub go_modules: Vec<GoModules>,
    /// Declared Python distribution names from `pyproject.toml`,
    /// `setup.cfg`, and `requirements*.txt`, in index order (KTD17).
    pub python_declarations: Vec<String>,
}

/// npm scripts that run on install or publish.
pub const NPM_LIFECYCLE: [&str; 6] = [
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepack",
    "prepublish",
];

/// One parsed manifest plus the keys whose paths leave the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Cargo(CargoManifest),
    PackageJson(PackageJson),
    TsConfig(TsConfig),
    PyProject(PyProject),
    SetupCfg(SetupCfg),
    GoMod(GoMod),
    GoWork(GoWork),
    GoModules(GoModules),
}

/// The parse result: the manifest and the keys that named an out-of-root
/// target, one entry per such reference.
pub type ParseOutcome = (Parsed, Vec<&'static str>);

/// Folds `target` onto the in-root directory `base`. Returns `None` for an
/// absolute target or one that climbs above the root.
pub fn fold(base: &[u8], target: &str) -> Option<Vec<u8>> {
    if target.starts_with('/') || target.starts_with('\\') {
        return None;
    }
    let mut parts: Vec<&[u8]> = base
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .collect();
    for c in target.as_bytes().split(|b| *b == b'/' || *b == b'\\') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop()?;
            }
            _ => parts.push(c),
        }
    }
    Some(parts.join(&b'/'))
}

struct Refs<'a> {
    base: &'a [u8],
    outside: Vec<&'static str>,
}

impl Refs<'_> {
    fn add(&mut self, key: &'static str, target: &str) -> Option<Vec<u8>> {
        let r = fold(self.base, target);
        if r.is_none() {
            self.outside.push(key);
        }
        r
    }
}

/// Parses one manifest. `Err` is a `manifest-parse-error`.
pub fn parse(kind: ManifestKind, path: &[u8], text: &str) -> Result<ParseOutcome, Malformed> {
    let mut refs = Refs {
        base: dir_of(path),
        outside: Vec::new(),
    };
    let parsed = match kind {
        ManifestKind::Cargo => Parsed::Cargo(cargo(path, text, &mut refs)?),
        ManifestKind::PackageJson => Parsed::PackageJson(package_json(path, text, &mut refs)?),
        ManifestKind::TsConfig => Parsed::TsConfig(tsconfig(path, &parse_jsonc(text)?, &mut refs)),
        ManifestKind::PyProject => Parsed::PyProject(pyproject(path, text, &mut refs)?),
        ManifestKind::SetupCfg => Parsed::SetupCfg(setup_cfg(path, text)?),
        ManifestKind::GoMod => Parsed::GoMod(go_mod(path, text, &mut refs)?),
        ManifestKind::GoWork => Parsed::GoWork(go_work(path, text, &mut refs)?),
        ManifestKind::GoModules => Parsed::GoModules(go_modules(path, text)?),
    };
    Ok((parsed, refs.outside))
}

/// Parses a file named by a `tsconfig.json` `extends` chain (JSONC).
pub fn parse_tsconfig(path: &[u8], text: &str) -> Result<(TsConfig, Vec<&'static str>), Malformed> {
    let mut refs = Refs {
        base: dir_of(path),
        outside: Vec::new(),
    };
    let t = tsconfig(path, &parse_jsonc(text)?, &mut refs);
    Ok((t, refs.outside))
}

fn cargo(path: &[u8], text: &str, refs: &mut Refs<'_>) -> Result<CargoManifest, Malformed> {
    let t: toml::Table = toml::from_str(text).map_err(|_| Malformed)?;
    let pkg = t.get("package").and_then(toml::Value::as_table);
    let build = match pkg.and_then(|p| p.get("build")) {
        None | Some(toml::Value::Boolean(true)) => BuildScript::Default,
        Some(toml::Value::Boolean(false)) => BuildScript::Disabled,
        Some(toml::Value::String(s)) => match refs.add("package.build", s) {
            Some(p) => BuildScript::Path(p),
            None => BuildScript::Outside,
        },
        Some(_) => return Err(Malformed),
    };
    let lib = t.get("lib").and_then(toml::Value::as_table);
    let proc_macro = lib.is_some_and(|l| {
        ["proc-macro", "proc_macro"]
            .iter()
            .any(|k| l.get(*k).and_then(toml::Value::as_bool) == Some(true))
    });
    let mut targets = Vec::new();
    let mut lib_path = None;
    if let Some(p) = lib
        .and_then(|l| l.get("path"))
        .and_then(toml::Value::as_str)
    {
        lib_path = refs.add("lib.path", p);
        targets.extend(lib_path.clone());
    }
    let lib_name = lib
        .and_then(|l| l.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let mut renames = Vec::new();
    let mut inherited = Vec::new();
    let mut tables: Vec<&toml::Table> = ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|k| t.get(*k).and_then(toml::Value::as_table))
        .collect();
    for target in t
        .get("target")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|x| x.values())
        .filter_map(toml::Value::as_table)
    {
        tables.extend(
            ["dependencies", "dev-dependencies", "build-dependencies"]
                .iter()
                .filter_map(|k| target.get(*k).and_then(toml::Value::as_table)),
        );
    }
    let rename_of = |v: &toml::Value| {
        v.as_table()
            .and_then(|d| d.get("package"))
            .and_then(toml::Value::as_str)
            .map(str::to_string)
    };
    for table in tables {
        for (key, v) in table {
            if let Some(p) = rename_of(v) {
                renames.push((key.clone(), p));
            }
            if v.as_table()
                .and_then(|d| d.get("workspace"))
                .and_then(toml::Value::as_bool)
                == Some(true)
            {
                inherited.push(key.clone());
            }
        }
    }
    let workspace_renames = t
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| rename_of(v).map(|p| (k.clone(), p)))
        .collect();
    for (key, label) in [
        ("bin", "bin.path"),
        ("example", "example.path"),
        ("test", "test.path"),
        ("bench", "bench.path"),
    ] {
        for item in t
            .get(key)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(p) = item.get("path").and_then(toml::Value::as_str) {
                targets.extend(refs.add(label, p));
            }
        }
    }
    Ok(CargoManifest {
        path: path.to_vec(),
        has_package: pkg.is_some(),
        name: pkg
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        build,
        proc_macro,
        targets,
        lib_path,
        lib_name,
        renames,
        inherited,
        workspace_renames,
    })
}

fn package_json(path: &[u8], text: &str, refs: &mut Refs<'_>) -> Result<PackageJson, Malformed> {
    let v: Value = serde_json::from_str(text).map_err(|_| Malformed)?;
    if !v.is_object() {
        return Err(Malformed);
    }
    let ws = match v.get("workspaces") {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Object(o)) => match o.get("packages") {
            Some(Value::Array(a)) => a.clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    let workspaces = ws
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|p| refs.add("workspaces", p))
        .collect();
    let bin = match v.get("bin") {
        Some(Value::String(s)) => refs.add("bin", s).into_iter().collect(),
        Some(Value::Object(o)) => o
            .values()
            .filter_map(Value::as_str)
            .filter_map(|p| refs.add("bin", p))
            .collect(),
        _ => Vec::new(),
    };
    let main = v
        .get("main")
        .and_then(Value::as_str)
        .and_then(|m| fold(refs.base, m));
    let mut imports = Vec::new();
    if let Some(Value::Object(m)) = v.get("imports") {
        for (pattern, target) in m {
            let t = match target {
                Value::String(s) => Some(s.as_str()),
                Value::Object(o) => ["node", "import", "require", "default"]
                    .iter()
                    .find_map(|k| o.get(*k).and_then(Value::as_str)),
                _ => None,
            };
            // Bare package targets name dependencies, not paths.
            if let Some(t) = t.filter(|t| is_path_specifier(t))
                && let Some(p) = fold(refs.base, t)
            {
                imports.push((pattern.clone(), p));
            }
        }
    }
    let scripts = v.get("scripts").and_then(Value::as_object);
    let lifecycle = NPM_LIFECYCLE
        .iter()
        .copied()
        .filter(|s| scripts.is_some_and(|m| m.contains_key(*s)))
        .collect();
    Ok(PackageJson {
        path: path.to_vec(),
        name: v.get("name").and_then(Value::as_str).map(str::to_string),
        workspaces,
        bin,
        main,
        imports,
        lifecycle,
    })
}

fn is_path_specifier(s: &str) -> bool {
    is_dot_relative(s) || s.starts_with('/')
}

fn tsconfig(path: &[u8], v: &Value, refs: &mut Refs<'_>) -> TsConfig {
    let ext: Vec<&str> = match v.get("extends") {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    // Bare package specifiers name configs outside the tree; following them is
    // deferred, so only path specifiers are checked here.
    let extends = ext
        .into_iter()
        .filter(|s| is_path_specifier(s))
        .filter_map(|s| refs.add("extends", s))
        .collect();
    let opts = v.get("compilerOptions");
    let base_url = opts
        .and_then(|o| o.get("baseUrl"))
        .and_then(Value::as_str)
        .and_then(|b| refs.add("compilerOptions.baseUrl", b));
    let mut paths = Vec::new();
    if let Some(Value::Object(m)) = opts.and_then(|o| o.get("paths")) {
        let saved = refs.base;
        let base = base_url.clone().unwrap_or_else(|| saved.to_vec());
        let mut inner = Refs {
            base: &base,
            outside: Vec::new(),
        };
        for (pattern, targets) in m {
            let t: Vec<Vec<u8>> = targets
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(|s| inner.add("compilerOptions.paths", s))
                .collect();
            paths.push((pattern.clone(), t));
        }
        refs.outside.extend(inner.outside);
    }
    TsConfig {
        path: path.to_vec(),
        extends,
        base_url,
        paths,
    }
}

fn pyproject(path: &[u8], text: &str, refs: &mut Refs<'_>) -> Result<PyProject, Malformed> {
    let t: toml::Table = toml::from_str(text).map_err(|_| Malformed)?;
    let bs = t.get("build-system").and_then(toml::Value::as_table);
    let backend_path = bs
        .and_then(|b| b.get("backend-path"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter_map(|p| refs.add("build-system.backend-path", p))
        .collect();
    // KTD17 declarations: `[project] dependencies` PEP 508 strings and
    // `[tool.poetry.dependencies]` keys (`python` is the interpreter
    // constraint, never a package).
    let mut declared = Vec::new();
    if let Some(deps) = t
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        declared.extend(
            deps.iter()
                .filter_map(toml::Value::as_str)
                .filter_map(requirement_name),
        );
    }
    if let Some(deps) = t
        .get("tool")
        .and_then(|x| x.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        declared.extend(
            deps.keys()
                .filter(|k| crate::deps::version::pep503(k) != "python")
                .cloned(),
        );
    }
    Ok(PyProject {
        path: path.to_vec(),
        build_backend: bs
            .and_then(|b| b.get("build-backend"))
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        backend_path,
        declared,
    })
}

/// `[options] install_requires` from a `setup.cfg` (KTD17). The key's
/// value is one requirement per line; continuation lines are indented.
fn setup_cfg(path: &[u8], text: &str) -> Result<SetupCfg, Malformed> {
    ini(text)?;
    let mut in_options = false;
    let mut collecting = false;
    let mut declared = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if !line.starts_with([' ', '\t']) {
            collecting = false;
            if t.starts_with('[') {
                in_options = t == "[options]";
                continue;
            }
            if in_options
                && !t.is_empty()
                && !t.starts_with('#')
                && !t.starts_with(';')
                && let Some((key, value)) = t.split_once(['=', ':'])
                && key.trim() == "install_requires"
            {
                collecting = true;
                if let Some(n) = requirement_name(value) {
                    declared.push(n);
                }
            }
        } else if in_options
            && collecting
            && let Some(n) = requirement_name(t)
        {
            declared.push(n);
        }
    }
    Ok(SetupCfg {
        path: path.to_vec(),
        declared,
    })
}

/// The distribution name a PEP 508 requirement string declares:
/// `PyYAML` from `PyYAML>=6; python_version>"3"`, `name` from
/// `name[extra]`, `name (>=1)`, or `name @ url`. A bare URL, path, or
/// line holding no requirement yields `None`.
pub fn requirement_name(text: &str) -> Option<String> {
    let t = text.trim().trim_end_matches('\\').trim_end();
    let mut end = 0;
    for (i, c) in t.char_indices() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 || !t.as_bytes()[0].is_ascii_alphanumeric() {
        return None;
    }
    let name = &t[..end];
    match t[end..].trim_start().chars().next() {
        // `name` alone, then extras, a version spec or parenthesized
        // spec, a marker, or a direct `name @ url` reference.
        None => Some(name.to_string()),
        Some(c) if "([<>=!~;@".contains(c) => Some(name.to_string()),
        _ => None,
    }
}

/// Declared distribution names in a `requirements*.txt` file (KTD17):
/// one requirement per line. Option lines (`-r`, `-e`, `--hash`, `-i`),
/// bare URLs and paths, comments, and blank lines contribute nothing;
/// a `#` at the line start or after whitespace begins a comment, and a
/// trailing `\` continues the line.
pub fn requirements(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw
            .char_indices()
            .find(|(i, c)| *c == '#' && (*i == 0 || raw.as_bytes()[i - 1].is_ascii_whitespace()))
            .map(|(i, _)| &raw[..i])
            .unwrap_or(raw);
        let line = line.trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        if let Some(n) = requirement_name(line) {
            out.push(n);
        }
    }
    out
}

/// Checks INI syntax as `configparser` reads it: sections, `key = value` or
/// `key: value` lines, comments, and indented continuation lines.
fn ini(text: &str) -> Result<(), Malformed> {
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        if t.starts_with('[') {
            if t.ends_with(']') {
                continue;
            }
            return Err(Malformed);
        }
        if !t.contains(['=', ':']) {
            return Err(Malformed);
        }
    }
    Ok(())
}

/// Whether a `pyvenv.cfg` has a `home` key.
pub fn pyvenv_has_home(text: &str) -> bool {
    text.lines()
        .any(|l| l.split_once('=').is_some_and(|(k, _)| k.trim() == "home"))
}

/// Parses JSON with comments and trailing commas, as `tsc` accepts.
pub fn parse_jsonc(text: &str) -> Result<Value, Malformed> {
    let b = text.as_bytes();
    // Pass 1: blank out comments, keeping string contents intact.
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                out.push(b'"');
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        out.push(b[i]);
                        i += 1;
                    }
                    out.push(b[i]);
                    i += 1;
                }
                if i < b.len() {
                    out.push(b'"');
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = b[i + 2..]
                    .windows(2)
                    .position(|w| w == b"*/")
                    .ok_or(Malformed)?;
                i += end + 4;
                out.push(b' ');
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    // Pass 2: drop a comma that follows a value and precedes `}` or `]`.
    let mut res = Vec::with_capacity(out.len());
    let mut in_str = false;
    let mut j = 0;
    while j < out.len() {
        let c = out[j];
        if in_str {
            res.push(c);
            if c == b'\\' && j + 1 < out.len() {
                res.push(out[j + 1]);
                j += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
            res.push(c);
        } else if c == b',' {
            let next = out[j + 1..].iter().find(|x| !x.is_ascii_whitespace());
            let prev = res.iter().rev().find(|x| !x.is_ascii_whitespace());
            let after_value = prev.is_some_and(|p| !matches!(p, b'{' | b'[' | b','));
            if !(after_value && matches!(next, Some(b'}') | Some(b']'))) {
                res.push(c);
            }
        } else {
            res.push(c);
        }
        j += 1;
    }
    let s = String::from_utf8(res).map_err(|_| Malformed)?;
    serde_json::from_str(&s).map_err(|_| Malformed)
}

// ---- go.mod / go.work (line grammar) ----------------------------------------
//
// A pure text reader: no Go toolchain runs at scan time (R8). Each
// directive is `verb args`; `//` starts a comment and `"` quotes a token.
// `require`, `replace`, and `use` also take a parenthesized block whose
// lines carry the directive's arguments. `toolchain`, `tool`, `exclude`,
// `retract`, `godebug`, and unknown verbs are skipped, never acted on.

/// Splits one line into tokens: `//` starts a comment, a `"` opens a
/// quoted run to the next `"`, whitespace splits. A quote that never
/// closes is malformed.
fn go_tokens(line: &str) -> Result<Vec<String>, Malformed> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            break;
        } else if c == b'"' {
            let end = b[i + 1..]
                .iter()
                .position(|x| *x == b'"')
                .ok_or(Malformed)?
                + i
                + 1;
            out.push(line[i + 1..end].to_string());
            i = end + 1;
        } else {
            let start = i;
            while i < b.len() && !b[i].is_ascii_whitespace() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
                    break;
                }
                i += 1;
            }
            out.push(line[start..i].to_string());
        }
    }
    Ok(out)
}

/// Whether `s` reads as a directive verb (a leading ASCII letter followed
/// by letters, digits, or `_`).
fn go_verb(s: &str) -> bool {
    s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// One directive: its verb and its entries (one per single line, or one
/// per inner line of a parenthesized block).
type GoDirective = (String, Vec<Vec<String>>);

/// Reads `text` as `(verb, entries)` pairs: a block form (`require (`)
/// yields one entry per inner line, and a one-line `require ( m v )`
/// yields a single inner entry. A non-word first token, a `(` or `)` in
/// entry position, or an unterminated block is malformed.
fn go_directives(text: &str) -> Result<Vec<GoDirective>, Malformed> {
    let mut out: Vec<GoDirective> = Vec::new();
    let mut lines = text.lines();
    while let Some(raw) = lines.next() {
        let tokens = go_tokens(raw)?;
        let Some(verb) = tokens.first() else { continue };
        if !go_verb(verb) {
            return Err(Malformed);
        }
        let mut entries: Vec<Vec<String>> = Vec::new();
        match tokens.get(1).map(String::as_str) {
            Some("(") => {
                let inner = &tokens[2..];
                match inner.iter().position(|t| t == ")") {
                    // The block opens and closes on one line.
                    Some(pos) => {
                        if pos > 0 {
                            entries.push(inner[..pos].to_vec());
                        }
                        if pos + 1 != inner.len() {
                            return Err(Malformed);
                        }
                    }
                    // A real block: entry lines until a `)` line.
                    None => loop {
                        let Some(raw) = lines.next() else {
                            return Err(Malformed);
                        };
                        let t = go_tokens(raw)?;
                        match t.first().map(String::as_str) {
                            None => continue,
                            Some(")") if t.len() == 1 => break,
                            Some("(") | Some(")") => return Err(Malformed),
                            _ => entries.push(t),
                        }
                    },
                }
            }
            _ => entries.push(tokens[1..].to_vec()),
        }
        for e in &entries {
            if e.iter().any(|t| t == "(" || t == ")") {
                return Err(Malformed);
            }
        }
        out.push((verb.clone(), entries));
    }
    Ok(out)
}

/// One argument out of an entry: anything else is malformed.
fn go_one(e: &[String]) -> Result<&str, Malformed> {
    match e {
        [a] => Ok(a),
        _ => Err(Malformed),
    }
}

/// Whether `t` reads as a `use` or `replace` directory target
/// (`.`/`..`-relative or absolute), never a module path.
fn go_is_path(t: &str) -> bool {
    t == "." || t == ".." || t.starts_with("./") || t.starts_with("../") || t.starts_with('/')
}

/// Parses `replace from[ version] => target`. A path target is folded
/// against the manifest's directory; an out-of-root fold lands in `refs`
/// as `replace` and records `Outside`, never the path.
fn go_replace(e: &[String], refs: &mut Refs<'_>) -> Result<GoReplace, Malformed> {
    let pos = e.iter().position(|t| t == "=>").ok_or(Malformed)?;
    let (left, right) = (&e[..pos], &e[pos + 1..]);
    if right.iter().any(|t| t == "=>") {
        return Err(Malformed);
    }
    let (from, from_version) = match left {
        [p] => (p.clone(), None),
        [p, v] => (p.clone(), Some(v.clone())),
        _ => return Err(Malformed),
    };
    let to = match right {
        // A path target takes no version beside it.
        [t] if go_is_path(t) => match refs.add("replace", t) {
            Some(p) => GoReplaceTarget::Path(p),
            None => GoReplaceTarget::Outside,
        },
        [p] => GoReplaceTarget::Module {
            path: p.clone(),
            version: None,
        },
        [p, v] => GoReplaceTarget::Module {
            path: p.clone(),
            version: Some(v.clone()),
        },
        _ => return Err(Malformed),
    };
    Ok(GoReplace {
        from,
        from_version,
        to,
    })
}

/// The `go` directive's argument: one token starting with a digit
/// (`1.22`, `1.22.0`, `1.23rc1`); anything else is malformed.
fn go_version_arg(e: &[String]) -> Result<String, Malformed> {
    let v = go_one(e)?;
    if v.as_bytes()[0].is_ascii_digit() {
        Ok(v.to_string())
    } else {
        Err(Malformed)
    }
}

fn go_mod(path: &[u8], text: &str, refs: &mut Refs<'_>) -> Result<GoMod, Malformed> {
    let mut m = GoMod {
        path: path.to_vec(),
        module: None,
        go: None,
        require: Vec::new(),
        replace: Vec::new(),
    };
    for (verb, entries) in go_directives(text)? {
        match verb.as_str() {
            "module" => {
                for e in &entries {
                    m.module = Some(go_one(e)?.to_string());
                }
            }
            "go" => {
                for e in &entries {
                    m.go = Some(go_version_arg(e)?);
                }
            }
            "require" => {
                for e in &entries {
                    match e.as_slice() {
                        [p, v] => m.require.push((p.clone(), v.clone())),
                        _ => return Err(Malformed),
                    }
                }
            }
            "replace" => {
                for e in &entries {
                    m.replace.push(go_replace(e, refs)?);
                }
            }
            // toolchain, tool, exclude, retract, and unknown verbs.
            _ => {}
        }
    }
    Ok(m)
}

fn go_work(path: &[u8], text: &str, refs: &mut Refs<'_>) -> Result<GoWork, Malformed> {
    let mut w = GoWork {
        path: path.to_vec(),
        go: None,
        uses: Vec::new(),
        replace: Vec::new(),
    };
    for (verb, entries) in go_directives(text)? {
        match verb.as_str() {
            "go" => {
                for e in &entries {
                    w.go = Some(go_version_arg(e)?);
                }
            }
            "use" => {
                for e in &entries {
                    let d = go_one(e)?;
                    if !go_is_path(d) {
                        return Err(Malformed);
                    }
                    if let Some(p) = refs.add("use", d) {
                        w.uses.push(p);
                    }
                }
            }
            "replace" => {
                for e in &entries {
                    w.replace.push(go_replace(e, refs)?);
                }
            }
            // toolchain, godebug, and unknown verbs.
            _ => {}
        }
    }
    Ok(w)
}

/// Go's lexical check on an import path or module path: non-empty, no
/// element empty or `.`/`..`, and no control, quote, space, or backslash
/// bytes (x/mod's `checkPath` shape). Import paths and `modules.txt`
/// paths are validated with it before any directory mapping, so a path
/// that cannot name a package never maps to files.
pub fn go_import_path(s: &str) -> bool {
    // `:` is excluded so no source-written specifier can carry the
    // frontend's synthetic `gofile:` namespace.
    !s.is_empty()
        && !s.chars().any(|c| {
            c.is_control() || c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '`' | '#' | ':')
        })
        && s.split('/').all(|e| !e.is_empty() && e != "." && e != "..")
}

/// Parses `vendor/modules.txt`: `# module version [=> target]` module
/// lines, `## explicit; go X.Y` marker lines, and the package import
/// paths that follow each module line. Only the module side matters to
/// vendoring; the `=>` side is recorded for a reader that needs the
/// replacement and otherwise ignored. A package line before any module
/// line, a malformed `#` line, or a path failing `go_import_path` is a
/// parse error.
fn go_modules(path: &[u8], text: &str) -> Result<GoModules, Malformed> {
    let mut out = GoModules {
        path: path.to_vec(),
        packages: Vec::new(),
    };
    let mut module: Option<(String, Option<String>)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("##") {
            continue;
        }
        if let Some(decl) = line.strip_prefix('#') {
            if decl.starts_with('#') {
                continue;
            }
            // `<path> [<version>] [=> ...]`: only the left side is read.
            let left = decl.trim().split("=>").next().unwrap_or_default().trim();
            let mut it = left.split_whitespace();
            let path = it.next().ok_or(Malformed)?;
            if !go_import_path(path) {
                return Err(Malformed);
            }
            let version = it.next().map(str::to_string);
            if it.next().is_some() {
                return Err(Malformed);
            }
            module = Some((path.to_string(), version));
            continue;
        }
        let Some((mpath, mver)) = &module else {
            return Err(Malformed);
        };
        if !go_import_path(line) {
            return Err(Malformed);
        }
        out.packages.push(GoVendorPackage {
            path: line.to_string(),
            module: mpath.clone(),
            version: mver.clone(),
        });
    }
    Ok(out)
}

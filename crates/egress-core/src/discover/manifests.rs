//! Manifest parsing (KTD13) and manifest-declared paths (KTD12).
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

/// A manifest that does not parse; reported as `manifest-parse-error`. Parser
/// messages are dropped (KTD13).
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
}

impl ManifestKind {
    pub fn for_name(name: &[u8]) -> Option<ManifestKind> {
        Some(match name {
            b"Cargo.toml" => Self::Cargo,
            b"package.json" => Self::PackageJson,
            b"tsconfig.json" => Self::TsConfig,
            b"pyproject.toml" => Self::PyProject,
            b"setup.cfg" => Self::SetupCfg,
            _ => return None,
        })
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
    /// from every dependency table of the package (KTD16).
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
}

/// Parsed manifest facts later stages map into the file index (KTD16).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifests {
    pub cargo: Vec<CargoManifest>,
    pub package_json: Vec<PackageJson>,
    pub tsconfig: Vec<TsConfig>,
    pub pyproject: Vec<PyProject>,
}

/// npm scripts that run on install or publish (KTD17).
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
    SetupCfg,
}

/// The parse result: the manifest and the keys that named an out-of-root
/// target, one entry per such reference.
pub type ParseOutcome = (Parsed, Vec<&'static str>);

fn dir_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[..i],
        None => b"",
    }
}

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
        ManifestKind::SetupCfg => {
            ini(text)?;
            Parsed::SetupCfg
        }
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
        lifecycle,
    })
}

fn is_path_specifier(s: &str) -> bool {
    s.starts_with("./") || s.starts_with("../") || s.starts_with('/') || s == "." || s == ".."
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
    Ok(PyProject {
        path: path.to_vec(),
        build_backend: bs
            .and_then(|b| b.get("build-backend"))
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        backend_path,
    })
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

//! Package metadata parsers: `package.json`, Python `METADATA`,
//! `RECORD`, `top_level.txt`, `.cargo-checksum.json`, and `[package]`
//! of `Cargo.toml`. Everything takes bytes and never opens a path
//! (KTD24). A parse that fails yields `Malformed`, never a tool error.

use crate::discover::manifests::Malformed;

/// `name` and `version` from `package.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmMeta {
    pub name: String,
    pub version: String,
}

/// `name` and `version` from a `package.json` body. Strict JSON per the
/// manifest table; both fields must be present strings.
pub fn package_json(bytes: &[u8]) -> Result<NpmMeta, Malformed> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Malformed)?;
    let name = v.get("name").and_then(|n| n.as_str()).ok_or(Malformed)?;
    let version = v.get("version").and_then(|n| n.as_str()).ok_or(Malformed)?;
    Ok(NpmMeta {
        name: name.to_string(),
        version: version.to_string(),
    })
}

/// `Name` and `Version` from a Python `METADATA`/`PKG-INFO` header
/// block. Continuation lines (leading whitespace) append to the open
/// header; the body after the first blank line is never read.
pub fn metadata(bytes: &[u8]) -> Result<NpmMeta, Malformed> {
    let text = std::str::from_utf8(bytes).map_err(|_| Malformed)?;
    let mut name = String::new();
    let mut version = String::new();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        // Header continuation lines never carry Name/Version.
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "Name" => name = value.trim().to_string(),
            "Version" => version = value.trim().to_string(),
            _ => {}
        }
    }
    if name.is_empty() || version.is_empty() {
        return Err(Malformed);
    }
    Ok(NpmMeta { name, version })
}

/// One `RECORD` CSV row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRow {
    /// The path as written (may be quoted in the source).
    pub path: String,
    /// `sha256=<b64-nopad>` when the row hashes the file; a `RECORD`'s
    /// own row and other unsupported hashes stay `None`.
    pub sha256: Option<String>,
    /// Declared byte size when present.
    pub size: Option<u64>,
}

/// Minimal RFC 4180 CSV split for `RECORD`: quotes escape embedded
/// commas and doubled quotes.
fn csv_row(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted => {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            }
            '"' => quoted = true,
            ',' if !quoted => {
                out.push(std::mem::take(&mut cur));
            }
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// `RECORD` rows. A non-`sha256` hash column yields a hashless row, not
/// a parse error (KTD16).
pub fn record(bytes: &[u8]) -> Result<Vec<RecordRow>, Malformed> {
    let text = std::str::from_utf8(bytes).map_err(|_| Malformed)?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let fields = csv_row(line);
        let Some(path) = fields.first() else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let sha256 = fields.get(1).and_then(|h| h.strip_prefix("sha256="));
        let size = fields.get(2).and_then(|s| s.parse().ok());
        rows.push(RecordRow {
            path: path.clone(),
            sha256: sha256.map(str::to_string),
            size,
        });
    }
    Ok(rows)
}

/// Top-level import names from `RECORD`: `yaml/` gives `yaml`, `six.py`
/// gives `six`, `_cffi.abi3.so` gives `_cffi`; `*.dist-info`,
/// `__pycache__`, `*.pth`, and paths escaping the root (`../bin/x`)
/// are dropped.
pub fn top_level_names(rows: &[RecordRow]) -> Vec<String> {
    let mut out = Vec::new();
    for row in rows {
        let first = row.path.split('/').next().unwrap_or("");
        if first.is_empty()
            || first.starts_with('.')
            || first == "__pycache__"
            || first.ends_with(".dist-info")
            || first.ends_with(".egg-info")
            || row.path.ends_with(".pth")
            || first == "RECORD"
        {
            continue;
        }
        let name = first.split('.').next().unwrap_or("");
        if !name.is_empty() && !out.contains(&name.to_string()) {
            out.push(name.to_string());
        }
    }
    out
}

/// `top_level.txt`: one import name per line, blanks skipped.
pub fn top_level(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// `.cargo-checksum.json`: the `files` map of path to hex sha256 and
/// the `package` checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoChecksum {
    /// path -> hex sha256.
    pub files: Vec<(String, String)>,
    /// `package` checksum when present (vendor dirs carry the crates.io
    /// sha; git checkouts carry none).
    pub package: Option<String>,
}

pub fn cargo_checksum(bytes: &[u8]) -> Result<CargoChecksum, Malformed> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Malformed)?;
    let files = v
        .get("files")
        .and_then(|f| f.as_object())
        .ok_or(Malformed)?
        .iter()
        .map(|(p, h)| (p.clone(), h.as_str().unwrap_or("").to_string()))
        .collect();
    let package = v
        .get("package")
        .and_then(|p| p.as_str())
        .map(str::to_string);
    Ok(CargoChecksum { files, package })
}

/// `[package] name` and `version` from a `Cargo.toml`.
pub fn cargo_toml_name_version(bytes: &[u8]) -> Result<(String, String), Malformed> {
    let t: toml::Table = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| toml::from_str(s).ok())
        .ok_or(Malformed)?;
    let pkg = t.get("package").ok_or(Malformed)?;
    let name = pkg.get("name").and_then(|v| v.as_str()).ok_or(Malformed)?;
    let version = pkg
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or(Malformed)?;
    Ok((name.to_string(), version.to_string()))
}

/// `[lib] name` when it differs from the package name (KTD5 fold).
pub fn cargo_toml_lib_name(bytes: &[u8]) -> Option<String> {
    let t: toml::Table = toml::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
    t.get("lib")
        .and_then(|l| l.get("name"))
        .and_then(|n| n.as_str())
        .map(str::to_string)
}

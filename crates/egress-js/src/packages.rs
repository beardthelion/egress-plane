//! JS module specifier rules (KTD16).
//!
//! Relative and `paths` specifiers probe in a fixed order, first match
//! wins: the exact path; for a `.js`, `.jsx`, `.mjs`, or `.cjs` specifier,
//! the TypeScript source of the same stem (NodeNext and Bundler); the path
//! with each extension appended; then `index` with each extension inside a
//! directory of that name. A `.d.ts` file is never a target. `#internal`
//! specifiers use the nearest `package.json` `imports`; a bare specifier
//! naming an in-tree `package.json` (workspace members included) probes
//! that package's `main` and index; `tsconfig.json` `paths` and `baseUrl`
//! apply when a target exists in the index. Everything else is a bare
//! external module with `node:` stripped. All candidates map only into
//! discovery's file index (KTD12).

use std::collections::{BTreeMap, BTreeSet};

use egress_core::discover::manifests::{Manifests, fold};
use egress_core::discover::{Discovery, FileKind};
use egress_core::resolve::{SpecifierKind, SpecifierRules};

/// Extensions in probe order.
const EXTENSIONS: [&str; 8] = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

#[derive(Debug, Clone)]
struct Package {
    dir: Vec<u8>,
    name: Option<String>,
    main: Option<Vec<u8>>,
    imports: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone)]
struct TsPaths {
    dir: Vec<u8>,
    base_url: Option<Vec<u8>>,
    paths: Vec<(String, Vec<Vec<u8>>)>,
}

/// Specifier rules for one repository.
#[derive(Debug, Clone, Default)]
pub struct JsRules {
    files: BTreeSet<Vec<u8>>,
    packages: Vec<Package>,
    tsconfigs: Vec<TsPaths>,
}

fn dir_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[..i],
        None => b"",
    }
}

fn file_name(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Whether directory `dir` contains `path` (the root contains everything).
fn contains(dir: &[u8], path: &[u8]) -> bool {
    dir.is_empty() || (path.len() > dir.len() && path.starts_with(dir) && path[dir.len()] == b'/')
}

fn is_declaration(p: &[u8]) -> bool {
    [".d.ts", ".d.mts", ".d.cts"]
        .iter()
        .any(|s| p.ends_with(s.as_bytes()))
}

fn with(base: &[u8], suffix: &str) -> Vec<u8> {
    [base, suffix.as_bytes()].concat()
}

/// Candidate paths for `base` in KTD16 probe order.
pub fn probes(base: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![base.to_vec()];
    let ts_stems: &[(&str, &[&str])] = &[
        (".js", &[".ts", ".tsx"]),
        (".jsx", &[".tsx", ".ts"]),
        (".mjs", &[".mts"]),
        (".cjs", &[".cts"]),
    ];
    for (ext, ts) in ts_stems {
        if let Some(stem) = base.strip_suffix(ext.as_bytes()) {
            out.extend(ts.iter().map(|t| with(stem, t)));
        }
    }
    out.extend(EXTENSIONS.iter().map(|e| with(base, e)));
    let index = if base.is_empty() {
        b"index".to_vec()
    } else {
        with(base, "/index")
    };
    out.extend(EXTENSIONS.iter().map(|e| with(&index, e)));
    out.retain(|p| !p.is_empty() && !is_declaration(p));
    out
}

/// Matches `spec` against a `paths` or `imports` pattern with at most one
/// `*`, returning the text the `*` stands for.
fn match_pattern<'s>(pattern: &str, spec: &'s str) -> Option<&'s str> {
    match pattern.split_once('*') {
        None => (pattern == spec).then_some(""),
        Some((pre, post)) => {
            if spec.len() >= pre.len() + post.len() && spec.starts_with(pre) && spec.ends_with(post)
            {
                Some(&spec[pre.len()..spec.len() - post.len()])
            } else {
                None
            }
        }
    }
}

fn substitute(target: &[u8], star: &str) -> Vec<u8> {
    match target.iter().position(|b| *b == b'*') {
        Some(i) => [&target[..i], star.as_bytes(), &target[i + 1..]].concat(),
        None => target.to_vec(),
    }
}

impl JsRules {
    /// Rules over a file index and parsed manifests.
    pub fn from_parts(index: &BTreeMap<Vec<u8>, FileKind>, manifests: &Manifests) -> JsRules {
        let packages = manifests
            .package_json
            .iter()
            .map(|p| Package {
                dir: dir_of(&p.path).to_vec(),
                name: p.name.clone(),
                main: p.main.clone(),
                imports: p.imports.clone(),
            })
            .collect();
        let by_path: BTreeMap<&[u8], _> = manifests
            .tsconfig
            .iter()
            .map(|t| (t.path.as_slice(), t))
            .collect();
        let mut tsconfigs = Vec::new();
        for t in &manifests.tsconfig {
            let name = file_name(&t.path);
            if name != b"tsconfig.json" && name != b"jsconfig.json" {
                continue;
            }
            // `baseUrl` and `paths` come from the nearest config in the
            // `extends` chain that sets them.
            let mut base_url = None;
            let mut paths = None;
            let mut seen = BTreeSet::new();
            let mut queue = vec![t];
            while let Some(c) = queue.pop() {
                if !seen.insert(c.path.clone()) {
                    continue;
                }
                if base_url.is_none() {
                    base_url.clone_from(&c.base_url);
                }
                if paths.is_none() && !c.paths.is_empty() {
                    paths = Some(c.paths.clone());
                }
                for e in c.extends.iter().rev() {
                    let next = by_path
                        .get(e.as_slice())
                        .or_else(|| by_path.get(with(e, ".json").as_slice()));
                    if let Some(n) = next {
                        queue.push(n);
                    }
                }
            }
            tsconfigs.push(TsPaths {
                dir: dir_of(&t.path).to_vec(),
                base_url,
                paths: paths.unwrap_or_default(),
            });
        }
        JsRules {
            files: index.keys().cloned().collect(),
            packages,
            tsconfigs,
        }
    }

    fn any_indexed(&self, probes: &[Vec<u8>]) -> bool {
        probes.iter().any(|p| self.files.contains(p))
    }

    /// The nearest enclosing package or tsconfig by directory.
    fn nearest<'r, T>(items: &'r [T], dir: impl Fn(&T) -> &[u8], from: &[u8]) -> Option<&'r T> {
        items
            .iter()
            .filter(|i| contains(dir(i), from))
            .max_by_key(|i| dir(i).len())
    }

    fn package_imports(&self, from: &[u8], spec: &str) -> SpecifierKind {
        let mut probes_out = Vec::new();
        if let Some(pkg) = Self::nearest(
            &self
                .packages
                .iter()
                .filter(|p| !p.imports.is_empty())
                .cloned()
                .collect::<Vec<_>>(),
            |p| &p.dir,
            from,
        ) {
            for (pattern, target) in &pkg.imports {
                if let Some(star) = match_pattern(pattern, spec) {
                    probes_out = probes(&substitute(target, star));
                    break;
                }
            }
        }
        SpecifierKind::Path { probes: probes_out }
    }

    fn tsconfig_paths(&self, from: &[u8], spec: &str) -> Option<Vec<Vec<u8>>> {
        let ts = Self::nearest(&self.tsconfigs, |t| &t.dir, from)?;
        for (pattern, targets) in &ts.paths {
            if let Some(star) = match_pattern(pattern, spec) {
                let candidates: Vec<Vec<u8>> = targets
                    .iter()
                    .flat_map(|t| probes(&substitute(t, star)))
                    .collect();
                if self.any_indexed(&candidates) {
                    return Some(candidates);
                }
            }
        }
        let base = ts.base_url.as_ref()?;
        let candidates = probes(&fold(base, spec)?);
        self.any_indexed(&candidates).then_some(candidates)
    }

    fn package_name(&self, spec: &str) -> Option<Vec<Vec<u8>>> {
        for p in &self.packages {
            let Some(name) = &p.name else { continue };
            if spec == name {
                let mut out = Vec::new();
                if let Some(main) = &p.main {
                    out.extend(probes(main));
                }
                let index = if p.dir.is_empty() {
                    Vec::new()
                } else {
                    p.dir.clone()
                };
                out.extend(probes(&index).into_iter().filter(|c| c != &index));
                return Some(out);
            }
            if let Some(sub) = spec
                .strip_prefix(name.as_str())
                .and_then(|r| r.strip_prefix('/'))
            {
                return Some(probes(&fold(&p.dir, sub)?));
            }
        }
        None
    }
}

/// Builds the rules from discovery's manifests and file index.
pub fn rules(discovery: &Discovery) -> JsRules {
    JsRules::from_parts(&discovery.index, &discovery.manifests)
}

impl SpecifierRules for JsRules {
    fn classify(&self, from: &[u8], specifier: &str) -> SpecifierKind {
        if let Some(m) = specifier.strip_prefix("node:") {
            return SpecifierKind::Bare {
                probes: Vec::new(),
                module: m.to_string(),
            };
        }
        if specifier.starts_with('/') || specifier.starts_with('\\') {
            return SpecifierKind::OutsideRoot;
        }
        let relative = specifier == "."
            || specifier == ".."
            || specifier.starts_with("./")
            || specifier.starts_with("../");
        if relative {
            return match fold(dir_of(from), specifier) {
                Some(base) => SpecifierKind::Path {
                    probes: probes(&base),
                },
                None => SpecifierKind::OutsideRoot,
            };
        }
        if specifier.starts_with('#') {
            return self.package_imports(from, specifier);
        }
        if let Some(p) = self.tsconfig_paths(from, specifier) {
            return SpecifierKind::Path { probes: p };
        }
        let probes = self.package_name(specifier).unwrap_or_default();
        SpecifierKind::Bare {
            probes,
            module: specifier.to_string(),
        }
    }
}

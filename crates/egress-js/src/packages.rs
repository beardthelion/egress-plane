//! JS module specifier rules.
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
//! discovery's file index.

use std::collections::{BTreeMap, BTreeSet};

use egress_core::discover::manifests::{Manifests, fold};
use egress_core::discover::{Discovery, FileKind};
use egress_core::paths::{dir_of, file_name, is_dot_relative};
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
    /// One `TsPaths` per parsed tsconfig, parallel to `resolved`
    /// ordering, for ownership claims (KTD15).
    owners: Vec<TsPaths>,
    /// Source file to owning config index into `owners`.
    owner: BTreeMap<Vec<u8>, usize>,
}

/// A parsed tsconfig with its effective fields resolved through the
/// `extends` chain (KTD15).
struct Resolved {
    path: Vec<u8>,
    dir: Vec<u8>,
    base_url: Option<Vec<u8>>,
    paths: Vec<(String, Vec<Vec<u8>>)>,
    include: Option<Vec<Vec<u8>>>,
    files: Option<Vec<Vec<u8>>>,
    exclude: Option<Vec<Vec<u8>>>,
    references: Vec<Vec<u8>>,
    /// Named `tsconfig.json` or `jsconfig.json`: an ownership root.
    named: bool,
}

impl Resolved {
    /// Whether this config claims `file`: an exact `files` entry, or an
    /// `include` match not removed by `exclude`. When neither `include`
    /// nor `files` is set, the default include is the config's own
    /// subtree (`**/*` under its directory).
    fn claims(&self, file: &[u8]) -> bool {
        if let Some(files) = &self.files
            && files.iter().any(|f| f.as_slice() == file)
        {
            return true;
        }
        if let Some(include) = &self.include {
            if !include.iter().any(|p| covers(p, file)) {
                return false;
            }
        } else if self.files.is_none() {
            if !self.dir.is_empty()
                && !(file.len() > self.dir.len()
                    && file.starts_with(&self.dir[..])
                    && file[self.dir.len()] == b'/')
            {
                return false;
            }
        } else {
            return false;
        }
        match &self.exclude {
            Some(exclude) => !exclude.iter().any(|p| covers(p, file)),
            None => true,
        }
    }
}

/// Whether an `include`/`exclude` pattern covers `file`: a glob match,
/// or the pattern is a literal directory whose subtree holds the file.
fn covers(pattern: &[u8], file: &[u8]) -> bool {
    if !pattern.iter().any(|b| matches!(b, b'*' | b'?'))
        && file.len() > pattern.len()
        && file.starts_with(pattern)
        && file[pattern.len()] == b'/'
    {
        return true;
    }
    glob_match(pattern, file)
}

/// The `*`/`**`/`?` glob subset (KTD15): `**` spans path segments, `*`
/// stays inside one, `?` is one character. Runs in pattern-length
/// times path-length worst case.
fn glob_match(pattern: &[u8], path: &[u8]) -> bool {
    let p: Vec<&[u8]> = pattern.split(|&b| b == b'/').collect();
    let f: Vec<&[u8]> = path.split(|&b| b == b'/').collect();
    // DP over (pi, fi): `**` matches zero or more segments.
    let (pn, fn_) = (p.len(), f.len());
    let mut dp = vec![vec![false; fn_ + 1]; pn + 1];
    dp[pn][fn_] = true;
    for i in (0..pn).rev() {
        for j in (0..fn_ + 1).rev() {
            dp[i][j] = if p[i] == b"**" {
                dp[i + 1][j] || (j < fn_ && dp[i][j + 1])
            } else {
                j < fn_ && seg_match(p[i], f[j]) && dp[i + 1][j + 1]
            };
        }
    }
    dp[0][0]
}

/// Within-segment wildcard match: `*` any run, `?` one byte.
fn seg_match(pat: &[u8], seg: &[u8]) -> bool {
    let mut dp = vec![vec![false; seg.len() + 1]; pat.len() + 1];
    dp[0][0] = true;
    for i in 1..=pat.len() {
        dp[i][0] = pat[i - 1] == b'*' && dp[i - 1][0];
        for j in 1..=seg.len() {
            dp[i][j] = match pat[i - 1] {
                b'*' => dp[i - 1][j] || dp[i][j - 1],
                b'?' => dp[i - 1][j - 1],
                c => seg[j - 1] == c && dp[i - 1][j - 1],
            };
        }
    }
    dp[pat.len()][seg.len()]
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

/// Candidate paths for `base` in probe order.
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
    egress_core::paths::star_match(pattern, spec)
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
        // Resolve every config's effective fields through its `extends`
        // chain: the first config in the chain that sets each field wins.
        let mut resolved = Vec::new();
        for t in &manifests.tsconfig {
            let mut base_url = None;
            let mut paths = None;
            let mut include = None;
            let mut files = None;
            let mut exclude = None;
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
                if include.is_none() {
                    include.clone_from(&c.include);
                }
                if files.is_none() {
                    files.clone_from(&c.files);
                }
                if exclude.is_none() {
                    exclude.clone_from(&c.exclude);
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
            let named = matches!(file_name(&t.path), b"tsconfig.json" | b"jsconfig.json");
            resolved.push(Resolved {
                path: t.path.clone(),
                dir: dir_of(&t.path).to_vec(),
                base_url,
                paths: paths.unwrap_or_default(),
                include,
                files,
                exclude,
                references: t.references.clone(),
                named,
            });
        }
        // Ownership (KTD15): claimants are configs named tsconfig.json or
        // jsconfig.json plus whatever their `references` reach, visited
        // depth-first from roots taken in byte-wise path order. The first
        // claimant wins a file; unclaimed files fall back to `nearest()`.
        let mut order: Vec<usize> = Vec::new();
        let mut visited = vec![false; resolved.len()];
        let pos: BTreeMap<&[u8], usize> = resolved
            .iter()
            .enumerate()
            .map(|(i, r)| (r.path.as_slice(), i))
            .collect();
        let mut roots: Vec<usize> = (0..resolved.len()).filter(|&i| resolved[i].named).collect();
        roots.sort_by_key(|&i| resolved[i].path.clone());
        let mut stack: Vec<usize> = Vec::new();
        for r in roots {
            stack.push(r);
            while let Some(i) = stack.pop() {
                if visited[i] {
                    continue;
                }
                visited[i] = true;
                order.push(i);
                for rf in resolved[i].references.iter().rev() {
                    if let Some(&j) = pos.get(rf.as_slice()) {
                        stack.push(j);
                    }
                }
            }
        }
        let mut owner: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        for &i in &order {
            for f in index.keys() {
                if !owner.contains_key(f) && resolved[i].claims(f) {
                    owner.insert(f.clone(), i);
                }
            }
        }
        let tsconfigs = resolved
            .iter()
            .filter(|r| r.named)
            .map(|r| TsPaths {
                dir: r.dir.clone(),
                base_url: r.base_url.clone(),
                paths: r.paths.clone(),
            })
            .collect();
        JsRules {
            files: index.keys().cloned().collect(),
            packages,
            tsconfigs,
            owners: resolved
                .iter()
                .map(|r| TsPaths {
                    dir: r.dir.clone(),
                    base_url: r.base_url.clone(),
                    paths: r.paths.clone(),
                })
                .collect(),
            owner,
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
        let ts = self
            .owner
            .get(from)
            .map(|&i| &self.owners[i])
            .or_else(|| Self::nearest(&self.tsconfigs, |t| &t.dir, from))?;
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
        let relative = is_dot_relative(specifier);
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

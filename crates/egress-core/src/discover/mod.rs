//! Discovery: walks the disk under the canonical root, builds the
//! file index, routes files to languages, applies exclusions, labels, hooks,
//! manifests, and the file and byte budgets. It ignores VCS ignore files and
//! is the only code that opens paths.

pub mod budgets;
pub mod completeness;
pub mod hooks;
pub mod labels;
pub mod manifests;
pub mod open;
pub mod symlinks;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::{Once, OnceLock};

use serde::Deserialize;

use self::budgets::Charger;
use self::completeness::counts_mut;
use self::manifests::{ManifestKind, Parsed};
use self::open::{EntryType, ReadError, RootDir, Stat};
use self::symlinks::LinkTarget;
use crate::identity::{EncodedPath, encode_path_bytes};
use crate::model::{
    BlindSpot, BlindSpotKind, BudgetReason, Coverage, Excluded, ExcludedReason, Label, Language,
    ToolError,
};
use crate::paths::file_name;

pub use budgets::Budgets;
pub use manifests::Manifests;

/// Largest file read, in bytes.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Stack size of every thread that parses untrusted input.
pub const WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;
/// Bytes read to find a `#!` line; Linux reads no more for a shebang.
const SHEBANG_BYTES: u64 = 256;
/// The standard cache-directory tag signature Cargo writes.
const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Raw text of `data/unsupported-file-types.toml`.
pub const UNSUPPORTED_TOML: &str = include_str!("../../../../data/unsupported-file-types.toml");

/// Discovery settings.
#[derive(Debug, Clone)]
pub struct Config {
    pub budgets: Budgets,
    /// Test seam: behave as a host without the safe-open guarantee, so every
    /// read becomes `unsafe-open-unavailable`.
    #[doc(hidden)]
    pub force_unsafe_open_unavailable: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            budgets: Budgets::embedded(),
            force_unsafe_open_unavailable: false,
        }
    }
}

/// What discovery made of one indexed regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Source(Language),
    Unsupported,
    Other,
}

/// A supported file admitted for parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// Raw repo-relative path bytes with `/` separators.
    pub path: Vec<u8>,
    pub file: EncodedPath,
    pub language: Language,
    /// Size from `lstat` at walk time.
    pub size: u64,
    /// Path labels and `build-hook`, sorted; content labels are added after
    /// reading.
    pub labels: Vec<Label>,
}

/// The result of discovery.
#[derive(Debug)]
pub struct Discovery {
    root: RootDir,
    unsafe_open: bool,
    /// Every regular in-root file outside excluded directories.
    pub index: BTreeMap<Vec<u8>, FileKind>,
    /// Supported files admitted by the budgets, in byte-wise path order.
    pub sources: Vec<SourceFile>,
    pub blind_spots: Vec<BlindSpot>,
    pub excluded: Vec<Excluded>,
    /// Raw paths of excluded directories.
    pub excluded_dirs: BTreeSet<Vec<u8>>,
    pub manifests: Manifests,
    /// Counts from discovery: files skipped before any source read.
    pub coverage: Coverage,
    pub budget_exceeded: Vec<BudgetReason>,
    /// Languages with at least one supported file in the tree.
    pub languages: BTreeSet<Language>,
}

// ---- panic capture ---------------------------------------------------------

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` and turns a panic into `None`. The panic message is not printed,
/// so panic payloads (which may quote scanned input) never reach a terminal.
pub fn guard<T>(f: impl FnOnce() -> T) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                prev(info);
            }
        }));
    });
    let was = QUIET.with(|q| q.replace(true));
    let r = std::panic::catch_unwind(AssertUnwindSafe(f)).ok();
    QUIET.with(|q| q.set(was));
    r
}

/// Runs `f` on a thread with a [`WORKER_STACK_BYTES`] stack, under [`guard`].
pub fn run_guarded<T: Send>(f: impl FnOnce() -> T + Send) -> Option<T> {
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(WORKER_STACK_BYTES)
            .spawn_scoped(s, || guard(f))
            .ok()?
            .join()
            .ok()
            .flatten()
    })
}

// ---- file types ------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnsupported {
    extensions: Vec<String>,
}

fn unsupported_extensions() -> &'static [String] {
    static T: OnceLock<Vec<String>> = OnceLock::new();
    T.get_or_init(|| {
        let raw: RawUnsupported =
            toml::from_str(UNSUPPORTED_TOML).expect("embedded data/unsupported-file-types.toml");
        raw.extensions
            .into_iter()
            .map(|e| e.to_ascii_lowercase())
            .collect()
    })
}

/// The extension including its dot; a leading dot does not start one.
fn extension(name: &[u8]) -> Option<&[u8]> {
    let i = name.iter().rposition(|b| *b == b'.')?;
    (i > 0).then(|| &name[i..])
}

/// Classification by name alone: supported language, unsupported code type,
/// or `None` for anything else.
fn kind_by_name(name: &[u8]) -> Option<FileKind> {
    let ext = extension(name)?;
    let lang = match ext {
        b".py" | b".pyi" | b".pyw" => Some(Language::Python),
        b".js" | b".mjs" | b".cjs" | b".jsx" | b".ts" | b".tsx" | b".mts" | b".cts" => {
            Some(Language::Javascript)
        }
        b".rs" => Some(Language::Rust),
        _ => None,
    };
    if let Some(l) = lang {
        return Some(FileKind::Source(l));
    }
    let lower = ext.to_ascii_lowercase();
    unsupported_extensions()
        .iter()
        .any(|e| e.as_bytes() == lower.as_slice())
        .then_some(FileKind::Unsupported)
}

/// The language a `#!` line names, if any.
fn shebang_language(head: &[u8]) -> Option<Language> {
    let line = head.strip_prefix(b"#!")?;
    let line = line.split(|b| *b == b'\n').next().unwrap_or(line);
    let line = std::str::from_utf8(line).ok()?;
    let mut words = line.split_whitespace();
    let mut prog = words.next()?;
    if prog.rsplit('/').next() == Some("env") {
        prog = words.find(|w| !w.starts_with('-') && !w.contains('='))?;
    }
    let base = prog.rsplit('/').next().unwrap_or(prog);
    if let Some(rest) = base.strip_prefix("python")
        && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return Some(Language::Python);
    }
    matches!(base, "node" | "nodejs" | "deno" | "bun").then_some(Language::Javascript)
}

fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        name.to_vec()
    } else {
        [dir, b"/", name].concat()
    }
}

fn within(path: &[u8], dir: &[u8]) -> bool {
    dir.is_empty()
        || path == dir
        || (path.len() > dir.len() && path.starts_with(dir) && path[dir.len()] == b'/')
}

fn language_of(path: &[u8]) -> Option<Language> {
    match kind_by_name(file_name(path)) {
        Some(FileKind::Source(l)) => Some(l),
        _ => None,
    }
}

// ---- blind spots -----------------------------------------------------------

fn spot(
    path: &[u8],
    kind: BlindSpotKind,
    language: Option<Language>,
    coverage_gap: bool,
    construct: &str,
) -> BlindSpot {
    let enc = encode_path_bytes(path);
    BlindSpot {
        id: String::new(),
        language,
        file: enc.display,
        file_bytes: enc.bytes_hex,
        symbol: "<module>".into(),
        kind,
        whole_file: kind.is_whole_file(),
        coverage_gap,
        construct: construct.into(),
        ordinal: 0,
        labels: labels::path_labels(path),
        location: None,
    }
}

/// A whole-file blind spot on `path` with its path labels, for failures found
/// after discovery (read, pre-scan, and frontend faults).
pub fn whole_file_blind_spot(
    path: &[u8],
    kind: BlindSpotKind,
    language: Option<Language>,
) -> BlindSpot {
    spot(path, kind, language, true, "")
}

fn excluded_entry(path: &[u8], reason: ExcludedReason) -> Excluded {
    let enc = encode_path_bytes(path);
    Excluded {
        path: enc.display,
        path_bytes: enc.bytes_hex,
        reason,
    }
}

// ---- discovery -------------------------------------------------------------

struct Walk<'a> {
    root: &'a RootDir,
    unsafe_open: bool,
    files: Vec<(Vec<u8>, u64)>,
    links: Vec<Vec<u8>>,
    specials: Vec<Vec<u8>>,
    excluded: Vec<Excluded>,
    excluded_dirs: BTreeSet<Vec<u8>>,
    blind_spots: Vec<BlindSpot>,
}

/// A directory's listing, or `Err` when it could not be listed.
type Listing = Result<Vec<(Vec<u8>, Stat)>, ()>;

enum DirClass {
    /// Walk the directory, reusing the listing `classify_dir` took.
    Walk(Listing),
    Exclude(ExcludedReason),
}

impl Walk<'_> {
    /// Reads a small in-root file through the safe open path.
    fn read(&self, path: &[u8], limit: u64) -> Result<Vec<u8>, BlindSpotKind> {
        if self.unsafe_open {
            return Err(BlindSpotKind::UnsafeOpenUnavailable);
        }
        self.root.read_file(path, limit).map_err(|e| match e {
            ReadError::NotRegular => BlindSpotKind::NotRegularFile,
            ReadError::TooLarge => BlindSpotKind::TooLarge,
            ReadError::Unreadable => BlindSpotKind::Unreadable,
        })
    }

    fn classify_dir(&mut self, path: &[u8], parent: &[(Vec<u8>, Stat)]) -> DirClass {
        let name = file_name(path);
        let has = |entries: &[(Vec<u8>, Stat)], n: &[u8]| {
            entries
                .iter()
                .any(|(e, st)| e == n && st.kind == EntryType::File)
        };
        if name == b".git" {
            return DirClass::Exclude(ExcludedReason::Vcs);
        }
        if name == b"node_modules" {
            return DirClass::Exclude(if has(parent, b"package.json") {
                ExcludedReason::InstallOutput
            } else {
                ExcludedReason::UnconfirmedInstallOutput
            });
        }
        let Ok(entries) = self.root.list_dir(path) else {
            return DirClass::Walk(Err(()));
        };
        if has(&entries, b"pyvenv.cfg") {
            let cfg = join(path, b"pyvenv.cfg");
            let home = match self.read(&cfg, MAX_FILE_BYTES) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => manifests::pyvenv_has_home(&text),
                    Err(_) => {
                        self.blind_spots.push(spot(
                            &cfg,
                            BlindSpotKind::ManifestParseError,
                            None,
                            true,
                            "",
                        ));
                        false
                    }
                },
                Err(kind) => {
                    let kind = manifest_read_kind(kind);
                    self.blind_spots.push(spot(&cfg, kind, None, true, ""));
                    false
                }
            };
            return DirClass::Exclude(if home {
                ExcludedReason::InstallOutput
            } else {
                ExcludedReason::UnconfirmedInstallOutput
            });
        }
        let tagged = has(&entries, b"CACHEDIR.TAG");
        if name == b"target" || tagged {
            let cargo_tag = tagged
                && self
                    .read(&join(path, b"CACHEDIR.TAG"), 4096)
                    .is_ok_and(|t| t.starts_with(CACHEDIR_SIGNATURE));
            let confirmed = name == b"target" && cargo_tag && has(parent, b"Cargo.toml");
            return DirClass::Exclude(if confirmed {
                ExcludedReason::InstallOutput
            } else {
                ExcludedReason::UnconfirmedInstallOutput
            });
        }
        DirClass::Walk(Ok(entries))
    }

    /// Whether an excluded directory may hide a supported file: true when a
    /// supported file name is found or when any directory in it cannot be
    /// listed, since an unlisted subtree cannot be shown to hold none. Only
    /// names are listed; nothing inside is opened or parsed.
    fn may_hold_supported(&self, dir: &[u8]) -> bool {
        let mut stack = vec![dir.to_vec()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = self.root.list_dir(&d) else {
                return true;
            };
            for (name, st) in entries {
                if st.kind == EntryType::Dir {
                    stack.push(join(&d, &name));
                } else if matches!(kind_by_name(&name), Some(FileKind::Source(_))) {
                    return true;
                }
            }
        }
        false
    }

    fn walk(&mut self) -> Result<(), ToolError> {
        // The root is listed here; every other directory carries the listing
        // its classification took.
        let root = self.root.list_dir(b"").map_err(|_| ());
        let mut stack: Vec<(Vec<u8>, Listing)> = vec![(Vec::new(), root)];
        while let Some((dir, listing)) = stack.pop() {
            let entries = match listing {
                Ok(e) => e,
                Err(_) if dir.is_empty() => {
                    return Err(ToolError::Internal("cannot list the scan root"));
                }
                Err(_) => {
                    self.blind_spots
                        .push(spot(&dir, BlindSpotKind::Unreadable, None, true, ""));
                    continue;
                }
            };
            for (name, st) in &entries {
                let child = join(&dir, name);
                match st.kind {
                    EntryType::Dir => match self.classify_dir(&child, &entries) {
                        DirClass::Walk(listing) => stack.push((child, listing)),
                        DirClass::Exclude(reason) => {
                            if reason != ExcludedReason::InstallOutput
                                && self.may_hold_supported(&child)
                            {
                                self.blind_spots.push(spot(
                                    &child,
                                    BlindSpotKind::UnconfirmedExclusion,
                                    None,
                                    true,
                                    "",
                                ));
                            }
                            self.excluded.push(excluded_entry(&child, reason));
                            self.excluded_dirs.insert(child);
                        }
                    },
                    EntryType::File => self.files.push((child, st.size)),
                    EntryType::Symlink => self.links.push(child),
                    EntryType::Other => self.specials.push(child),
                }
            }
        }
        Ok(())
    }
}

fn manifest_read_kind(kind: BlindSpotKind) -> BlindSpotKind {
    match kind {
        BlindSpotKind::TooLarge => BlindSpotKind::ManifestParseError,
        other => other,
    }
}

/// Discovers the tree at `root`.
pub fn discover(root: &Path, config: &Config) -> Result<Discovery, ToolError> {
    let rootdir = RootDir::open(root)?;
    let unsafe_open = config.force_unsafe_open_unavailable;
    let mut w = Walk {
        root: &rootdir,
        unsafe_open,
        files: Vec::new(),
        links: Vec::new(),
        specials: Vec::new(),
        excluded: Vec::new(),
        excluded_dirs: BTreeSet::new(),
        blind_spots: Vec::new(),
    };
    w.walk()?;
    w.files.sort();
    w.links.sort();
    w.specials.sort();

    let mut coverage = Coverage::default();
    let mut languages = BTreeSet::new();
    let mut index = BTreeMap::new();
    let mut candidates: Vec<(Vec<u8>, Language, u64)> = Vec::new();

    let files = std::mem::take(&mut w.files);
    for (path, size) in files {
        let name = file_name(&path);
        let kind = match kind_by_name(name) {
            Some(k) => k,
            None if extension(name).is_none() => match w.read_prefix(&path) {
                Ok(head) => shebang_language(&head).map_or(FileKind::Other, FileKind::Source),
                Err(kind) => {
                    // The first line cannot be read, so the file could be a
                    // script in any language.
                    w.blind_spots.push(spot(&path, kind, None, true, ""));
                    FileKind::Other
                }
            },
            None => FileKind::Other,
        };
        index.insert(path.clone(), kind);
        match kind {
            FileKind::Unsupported => {
                w.blind_spots.push(spot(
                    &path,
                    BlindSpotKind::UnsupportedFileType,
                    None,
                    true,
                    "",
                ));
                counts_mut(&mut coverage, None).skipped += 1;
            }
            FileKind::Source(lang) => {
                languages.insert(lang);
                let skip = if std::str::from_utf8(&path).is_err() {
                    Some(BlindSpotKind::NonUtf8Path)
                } else if size > MAX_FILE_BYTES {
                    Some(BlindSpotKind::TooLarge)
                } else {
                    None
                };
                match skip {
                    Some(k) => {
                        w.blind_spots.push(spot(&path, k, Some(lang), true, ""));
                        counts_mut(&mut coverage, Some(lang)).skipped += 1;
                    }
                    None => candidates.push((path, lang, size)),
                }
            }
            FileKind::Other => {}
        }
    }

    for path in std::mem::take(&mut w.specials) {
        match kind_by_name(file_name(&path)) {
            Some(FileKind::Source(lang)) => {
                languages.insert(lang);
                w.blind_spots.push(spot(
                    &path,
                    BlindSpotKind::NotRegularFile,
                    Some(lang),
                    true,
                    "",
                ));
                counts_mut(&mut coverage, Some(lang)).skipped += 1;
            }
            Some(FileKind::Unsupported) => {
                w.blind_spots.push(spot(
                    &path,
                    BlindSpotKind::UnsupportedFileType,
                    None,
                    true,
                    "",
                ));
                counts_mut(&mut coverage, None).skipped += 1;
            }
            _ => {}
        }
    }

    // Links are resolved in byte-wise path order against one step budget, so
    // which links the budget cuts is deterministic.
    let mut steps = symlinks::Steps::new(config.budgets.resolver_steps);
    for link in std::mem::take(&mut w.links) {
        // A gap on the link itself: its content is unknown or never scanned
        // under the language its name claims.
        let mut gap = |w: &mut Walk, kind: BlindSpotKind| {
            let lang = language_of(&link);
            w.blind_spots.push(spot(&link, kind, lang, true, ""));
            match kind_by_name(file_name(&link)) {
                Some(FileKind::Source(l)) => {
                    languages.insert(l);
                    counts_mut(&mut coverage, Some(l)).skipped += 1;
                }
                Some(FileKind::Unsupported) => counts_mut(&mut coverage, None).skipped += 1,
                _ => {}
            }
        };
        match symlinks::resolve(&rootdir, &link, &mut steps) {
            LinkTarget::Outside => gap(&mut w, BlindSpotKind::SymlinkOutsideRoot),
            LinkTarget::Budget => gap(&mut w, BlindSpotKind::ResolutionLimit),
            LinkTarget::Unresolved => gap(&mut w, BlindSpotKind::Unreadable),
            LinkTarget::Broken => w
                .excluded
                .push(excluded_entry(&link, ExcludedReason::BrokenSymlink)),
            LinkTarget::HopLimit => w
                .excluded
                .push(excluded_entry(&link, ExcludedReason::SymlinkHopLimit)),
            LinkTarget::InRoot { path, kind } => {
                let link_kind = kind_by_name(file_name(&link));
                if w.excluded_dirs.iter().any(|d| within(&path, d)) {
                    w.blind_spots.push(spot(
                        &link,
                        BlindSpotKind::ReferenceIntoExcluded,
                        language_of(&link),
                        true,
                        "",
                    ));
                } else if let Some(FileKind::Source(l)) = link_kind
                    && kind != EntryType::Dir
                    && index.get(&path) != Some(&FileKind::Source(l))
                {
                    // The alias rule holds only when the target is scanned
                    // as the same language under its own name. `net.py ->
                    // payload.txt` would otherwise hide the payload.
                    gap(&mut w, BlindSpotKind::LoadedAsCode);
                    continue;
                }
                w.excluded
                    .push(excluded_entry(&link, ExcludedReason::SymlinkAlias));
            }
        }
    }

    // Manifests.
    let mut manifests = Manifests::default();
    let mut failed_cargo = Vec::new();
    let mut ts_queue: Vec<Vec<u8>> = Vec::new();
    for path in index.keys() {
        let Some(kind) = ManifestKind::for_name(file_name(path)) else {
            continue;
        };
        let lang = match kind {
            ManifestKind::Cargo => Language::Rust,
            ManifestKind::PackageJson | ManifestKind::TsConfig => Language::Javascript,
            ManifestKind::PyProject | ManifestKind::SetupCfg => Language::Python,
        };
        let parsed = w.read_manifest(path).and_then(|text| {
            let p = path.clone();
            run_guarded(move || manifests::parse(kind, &p, &text))
                .and_then(Result::ok)
                .ok_or(BlindSpotKind::ManifestParseError)
        });
        match parsed {
            Ok((parsed, outside)) => {
                for key in outside {
                    w.blind_spots.push(spot(
                        path,
                        BlindSpotKind::ReferenceOutsideRoot,
                        Some(lang),
                        true,
                        key,
                    ));
                }
                match parsed {
                    Parsed::Cargo(c) => manifests.cargo.push(c),
                    Parsed::PackageJson(p) => manifests.package_json.push(p),
                    Parsed::TsConfig(t) => {
                        ts_queue.extend(t.extends.iter().cloned());
                        manifests.tsconfig.push(t);
                    }
                    Parsed::PyProject(p) => manifests.pyproject.push(p),
                    Parsed::SetupCfg => {}
                }
            }
            Err(k) => {
                if kind == ManifestKind::Cargo {
                    failed_cargo.push(path.clone());
                }
                w.blind_spots.push(spot(path, k, None, true, ""));
            }
        }
    }
    // In-tree `extends` targets are JSONC too; each file is parsed once, so
    // cycles terminate.
    let mut seen: BTreeSet<Vec<u8>> = manifests.tsconfig.iter().map(|t| t.path.clone()).collect();
    while let Some(target) = ts_queue.pop() {
        let target = if index.contains_key(&target) {
            target
        } else {
            let with_ext = [target.as_slice(), b".json"].concat();
            if !index.contains_key(&with_ext) {
                continue;
            }
            with_ext
        };
        if !seen.insert(target.clone()) {
            continue;
        }
        let parsed = w.read_manifest(&target).and_then(|text| {
            let p = target.clone();
            run_guarded(move || manifests::parse_tsconfig(&p, &text))
                .and_then(Result::ok)
                .ok_or(BlindSpotKind::ManifestParseError)
        });
        match parsed {
            Ok((t, outside)) => {
                for key in outside {
                    w.blind_spots.push(spot(
                        &target,
                        BlindSpotKind::ReferenceOutsideRoot,
                        Some(Language::Javascript),
                        true,
                        key,
                    ));
                }
                ts_queue.extend(t.extends.iter().cloned());
                manifests.tsconfig.push(t);
            }
            Err(k) => w.blind_spots.push(spot(&target, k, None, true, "")),
        }
    }

    // Hooks.
    let hook_list = hooks::detect(&index, &manifests, &failed_cargo);
    let hook_files: BTreeSet<Vec<u8>> = hook_list.iter().map(|h| h.path.clone()).collect();
    for h in &hook_list {
        w.blind_spots.push(spot(
            &h.path,
            BlindSpotKind::BuildHook,
            Some(h.language),
            false,
            h.name,
        ));
    }

    // Budgets, charged in byte-wise path order (the walk output is sorted).
    let mut charger = Charger::new(config.budgets);
    let mut sources = Vec::new();
    for (path, language, size) in candidates {
        if charger.admit(size) {
            let mut l = labels::path_labels(&path);
            if hook_files.contains(&path) {
                l.push(Label::BuildHook);
                l.sort();
            }
            sources.push(SourceFile {
                file: encode_path_bytes(&path),
                path,
                language,
                size,
                labels: l,
            });
        } else {
            counts_mut(&mut coverage, Some(language)).skipped += 1;
        }
    }

    Ok(Discovery {
        unsafe_open,
        index,
        sources,
        blind_spots: w.blind_spots,
        excluded: w.excluded,
        excluded_dirs: w.excluded_dirs,
        manifests,
        coverage,
        budget_exceeded: charger
            .exhausted()
            .into_iter()
            .chain(steps.exhausted().then_some(BudgetReason::ResolverSteps))
            .collect(),
        languages,
        root: rootdir,
    })
}

impl Walk<'_> {
    fn read_prefix(&self, path: &[u8]) -> Result<Vec<u8>, BlindSpotKind> {
        if self.unsafe_open {
            return Err(BlindSpotKind::UnsafeOpenUnavailable);
        }
        self.root
            .read_prefix(path, SHEBANG_BYTES)
            .map_err(|e| match e {
                ReadError::NotRegular => BlindSpotKind::NotRegularFile,
                ReadError::TooLarge => BlindSpotKind::TooLarge,
                ReadError::Unreadable => BlindSpotKind::Unreadable,
            })
    }

    fn read_manifest(&self, path: &[u8]) -> Result<String, BlindSpotKind> {
        let bytes = self
            .read(path, MAX_FILE_BYTES)
            .map_err(manifest_read_kind)?;
        let text = String::from_utf8(bytes).map_err(|_| BlindSpotKind::ManifestParseError)?;
        Ok(text
            .strip_prefix('\u{feff}')
            .map(str::to_string)
            .unwrap_or(text))
    }
}

impl Discovery {
    /// Reads one source file through the safe open path, strips a UTF-8 BOM,
    /// and decodes it. UTF-8 is the only accepted encoding.
    pub fn read_source(&self, file: &SourceFile) -> Result<String, BlindSpotKind> {
        if self.unsafe_open {
            return Err(BlindSpotKind::UnsafeOpenUnavailable);
        }
        let bytes = self
            .root
            .read_file(&file.path, MAX_FILE_BYTES)
            .map_err(|e| match e {
                ReadError::NotRegular => BlindSpotKind::NotRegularFile,
                ReadError::TooLarge => BlindSpotKind::TooLarge,
                ReadError::Unreadable => BlindSpotKind::Unreadable,
            })?;
        // A leading BOM is valid UTF-8, so decoding the whole buffer accepts
        // exactly what decoding the body after it would.
        let mut text = String::from_utf8(bytes).map_err(|_| BlindSpotKind::Undecodable)?;
        if text.starts_with('\u{feff}') {
            text.drain(..'\u{feff}'.len_utf8());
        }
        Ok(text)
    }
}

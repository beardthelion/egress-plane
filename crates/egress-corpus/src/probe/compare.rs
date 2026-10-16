//! Comparison of one snapshot probe run against its labels (KTD13).
//!
//! The harness compares the emitted JSON, not internal types: routes,
//! layers, unknowns, and tamper indicators are exact multisets; unclassified
//! members, inert members, and attribute labels are at-least checks;
//! `absent_routes` and `absent_text` are never-present checks over the JSON
//! and the text output. The read log adds two whole-run assertions: no
//! content read under a metadata-only signal path (credentials, socket
//! markers; R17/KTD31), and no call of any kind under a no-touch filesystem
//! (KTD26/R31).

use std::collections::BTreeMap;

use egress_core::model::ToolError;
use serde_json::Value;

use crate::compare::CaseOutcome;
use crate::probe::labels::Expected;
use crate::probe::{ReadCall, ScanOutput};

/// No-touch filesystems (KTD26): network and user-space mounts. The union of
/// the Linux and macOS sets; `fuse.` prefixes count for both.
const NO_TOUCH_FSTYPES: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ceph",
    "glusterfs",
    "lustre",
    "afs",
    "autofs",
    "fuse",
    "afpfs",
    "webdav",
    "osxfuse",
    "macfuse",
];

pub(crate) fn is_no_touch_fstype(fstype: &str) -> bool {
    NO_TOUCH_FSTYPES.contains(&fstype) || fstype.starts_with("fuse.")
}

/// What one case's filesystem state tells the read-log assertions.
#[derive(Debug, Clone, Default)]
pub struct CaseContext {
    /// Mount points from the case's `proc/self/mountinfo` (Linux), each as
    /// `(components, fstype)`. Empty when the mount table is unreadable or
    /// absent; the manifest override below still applies (expected.toml
    /// contract).
    pub mounts: Vec<(Vec<String>, String)>,
    /// Manifest node paths whose `fs` override names a no-touch fstype,
    /// each as components.
    pub no_touch_overrides: Vec<Vec<String>>,
    /// The case's platform directory name (`linux` or `macos`).
    pub platform: String,
}

/// Paths a passive probe may stat and list but never content-read:
/// `credential-path` and `credential-dir` signal paths (R17), and `socket`
/// signal paths, which resolve metadata-only even through symlinks (KTD31).
/// Components matched exactly; `*` matches one component. A `true` second
/// element means the entry is a directory: the path itself and anything
/// under it are covered.
const METADATA_ONLY_PATHS: &[(&[&str], bool)] = &[
    // Kubernetes service-account tree, including the AtomicWriter targets
    // (`..data/...`) the symlinks resolve to.
    (&["var", "run", "secrets"], true),
    (&["run", "secrets"], true),
    // Credential files that are not declared signals but are never content.
    (&["etc", "shadow"], false),
    (&["etc", "gshadow"], false),
    // Loader and proxy markers: presence only, contents never read.
    (&["etc", "ld.so.preload"], false),
    (&["etc", "apt", "apt.conf.d"], true),
    (&["etc", "pip.conf"], false),
    // Container-runtime sockets (KTD31 metadata-only resolution).
    (&["run", "docker.sock"], false),
    (&["var", "run", "docker.sock"], false),
    (&["private", "var", "run", "docker.sock"], false),
    (&["run", "podman", "podman.sock"], false),
    (&["run", "user", "*", "podman", "podman.sock"], false),
    (&["run", "containerd", "containerd.sock"], false),
    (&["var", "run", "crio", "crio.sock"], false),
    (&["var", "run", "cri-dockerd.sock"], false),
    (&["run", "k3s", "containerd", "containerd.sock"], false),
    // Host IPC and agent sockets.
    (&["run", "dbus", "system_bus_socket"], false),
    (&["var", "run", "dbus", "system_bus_socket"], false),
    (&["run", "pcscd", "pcscd.comm"], false),
    (&["run", "user", "*", "gnupg", "S.gpg-agent.ssh"], false),
    (&["run", "user", "*", "keyring", "ssh"], false),
];

/// Credential and socket signal paths relative to `<home>`: matched against
/// the tail of a path, so they apply to `/root/...`, `/home/u/...`, and
/// `/Users/u/...` alike without resolving a home directory.
const METADATA_ONLY_SUFFIXES: &[&[&str]] = &[
    &[".aws", "credentials"],
    &[".aws", "config"],
    &[".config", "gcloud", "application_default_credentials.json"],
    &[".docker", "config.json"],
    &[".kube", "config"],
    &[".npmrc"],
    &[".wgetrc"],
    &[".curlrc"],
    &[".config", "pip", "pip.conf"],
    &[".docker", "run", "docker.sock"],
    &[".colima", "default", "docker.sock"],
    &[".rd", "docker.sock"],
    &[".orbstack", "run", "docker.sock"],
    &[
        ".local",
        "share",
        "containers",
        "podman",
        "machine",
        "podman.sock",
    ],
    &["Library", "Keychains", "login.keychain-db"],
];

/// `<home>`-relative directories whose entries are stat-only.
const METADATA_ONLY_SUFFIX_DIRS: &[&[&str]] = &[
    &[".azure"],
    &[".ssh"],
    &["Library", "CloudStorage"],
    &["Library", "Mobile Documents"],
];

pub(crate) fn components(path: &str) -> Vec<String> {
    path.trim_matches('/')
        .split('/')
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

fn prefix_of(prefix: &[String], path: &[String]) -> bool {
    path.starts_with(prefix)
}

fn pattern_matches(pattern: &[&str], path: &[String]) -> bool {
    pattern.len() == path.len()
        && pattern
            .iter()
            .zip(path.iter())
            .all(|(p, c)| *p == "*" || *p == c.as_str())
}

fn pattern_prefix_matches(pattern: &[&str], path: &[String]) -> bool {
    path.len() >= pattern.len()
        && pattern
            .iter()
            .zip(path.iter())
            .all(|(p, c)| *p == "*" || *p == c.as_str())
}

/// True when `path` is a metadata-only signal path (credential, socket, or
/// marker a passive run may stat but never content-read).
fn metadata_only(path: &[String]) -> bool {
    for (pattern, is_dir) in METADATA_ONLY_PATHS {
        let hit = if *is_dir {
            pattern_prefix_matches(pattern, path)
        } else {
            pattern_matches(pattern, path)
        };
        if hit {
            return true;
        }
    }
    // `<home>` patterns: the tail of the path must equal (or sit under) the
    // pattern, at any depth.
    for i in 0..path.len() {
        let tail = &path[i..];
        if METADATA_ONLY_SUFFIXES
            .iter()
            .any(|p| p.len() == tail.len() && p.iter().zip(tail.iter()).all(|(p, c)| *p == c))
        {
            return true;
        }
        if METADATA_ONLY_SUFFIX_DIRS
            .iter()
            .any(|p| tail.len() >= p.len() && p.iter().zip(tail.iter()).all(|(p, c)| *p == c))
        {
            return true;
        }
    }
    false
}

/// The containing mount of `path` per KTD26: the longest mount point that
/// covers it on component boundaries. None when the mount table does not
/// reach the path.
fn containing_mount<'a>(mounts: &'a [(Vec<String>, String)], path: &[String]) -> Option<&'a str> {
    mounts
        .iter()
        .filter(|(mp, _)| prefix_of(mp, path))
        .max_by_key(|(mp, _)| mp.len())
        .map(|(_, fs)| fs.as_str())
}

/// True when any component of `path` sits on a no-touch filesystem, per
/// KTD26: each intermediate directory's containing mount counts, because the
/// walk opens every component. Also true under a manifest `fs` override that
/// names a no-touch fstype.
fn on_no_touch_fs(ctx: &CaseContext, path: &[String]) -> bool {
    for o in &ctx.no_touch_overrides {
        if prefix_of(o, path) {
            return true;
        }
    }
    if ctx.mounts.is_empty() {
        return false;
    }
    for i in 1..=path.len() {
        if let Some(fs) = containing_mount(&ctx.mounts, &path[..i])
            && is_no_touch_fstype(fs)
        {
            return true;
        }
    }
    false
}

/// Decodes the octal escapes mountinfo uses (`\040` space, `\011` tab,
/// `\012` newline, `\134` backslash).
fn decode_octal(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
        {
            let v = (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `proc/self/mountinfo` text into `(mount point components, fstype)`
/// pairs. Best effort for the read-log assertion: unparseable lines are
/// skipped (the probe itself reports `partial`, which the case labels cover).
pub fn parse_mountinfo_mounts(text: &str) -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        if fields.len() < 6 || sep + 1 >= fields.len() || sep < 5 {
            continue;
        }
        let point = components(&decode_octal(fields[4]));
        let fstype = fields[sep + 1].to_string();
        out.push((point, fstype));
    }
    out
}

/// Compares one snapshot run with the case's labels.
pub fn compare(
    expected: &Expected,
    ctx: &CaseContext,
    result: &Result<ScanOutput, ToolError>,
) -> CaseOutcome {
    let mut out = CaseOutcome::default();
    let output = match result {
        Ok(o) => o,
        Err(e) => {
            out.failures.push(format!(
                "tool error ({e}); expected state {} with exit code {}",
                expected.state.as_str(),
                expected.exit_code
            ));
            return out;
        }
    };
    let report: Value = match serde_json::from_str(&output.json) {
        Ok(v) => v,
        Err(e) => {
            out.failures
                .push(format!("output JSON does not parse: {e}"));
            return out;
        }
    };

    if let Some(source) = report.get("source").and_then(Value::as_str)
        && source != "snapshot"
    {
        out.failures.push(format!(
            "source {source:?} but corpus runs emit \"snapshot\""
        ));
    }
    if let Some(platform) = report.get("platform").and_then(Value::as_str)
        && platform != ctx.platform
    {
        out.failures.push(format!(
            "platform {platform:?} but the case lives under {}",
            ctx.platform
        ));
    }

    let state = report
        .get("completeness")
        .and_then(|c| c.get("state"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if state != expected.state.as_str() {
        out.failures.push(format!(
            "state {state:?} but expected state {:?} (exit code {})",
            expected.state.as_str(),
            expected.exit_code
        ));
    }

    // Member displays, for resolving `member` ids in routes, unclassified,
    // and inert entries.
    let mut member_display: BTreeMap<&str, &str> = BTreeMap::new();
    for u in arr(&report, "universes") {
        for m in arr(u, "members") {
            if let (Some(id), Some(display)) = (str_field(m, "id"), str_field(m, "display")) {
                member_display.insert(id, display);
            }
        }
    }
    let resolve = |id: &str| -> String {
        member_display
            .get(id)
            .map(|d| d.to_string())
            .unwrap_or_else(|| id.to_string())
    };

    compare_routes(expected, &report, &resolve, &mut out);
    compare_layers(expected, &report, &mut out);
    compare_exact_multiset(
        "unknown",
        &expected
            .unknowns
            .iter()
            .map(|u| format!("{} ({})", u.source, u.reason))
            .collect::<Vec<_>>(),
        arr(&report, "unknowns")
            .iter()
            .map(|u| {
                format!(
                    "{} ({})",
                    str_field(u, "source").unwrap_or("?"),
                    str_field(u, "reason").unwrap_or("?")
                )
            })
            .collect::<Vec<_>>(),
        &mut out,
    );
    compare_exact_multiset(
        "tamper indicator",
        &expected
            .tamper
            .iter()
            .map(|t| format!("{} ({})", t.indicator, t.strength))
            .collect::<Vec<_>>(),
        arr(&report, "tamper_indicators")
            .iter()
            .map(|t| {
                format!(
                    "{} ({})",
                    str_field(t, "indicator").unwrap_or("?"),
                    str_field(t, "strength").unwrap_or("?")
                )
            })
            .collect::<Vec<_>>(),
        &mut out,
    );

    // At-least sections. Unclassified members appear in the `unclassified`
    // section; members also carry `class` inside `universes`, and inert
    // members carry their rules there, so both shapes are collected.
    let unclassified = unclassified_members(&report, &resolve);
    for u in &expected.unclassified {
        let hit = unclassified
            .iter()
            .any(|(universe, member)| *universe == u.universe && *member == u.member);
        if !hit {
            out.failures.push(format!(
                "missing unclassified member {} in {}",
                u.member, u.universe
            ));
        }
    }
    let inert = inert_members(&report, &resolve);
    for i in &expected.inert {
        let hit = inert.iter().any(|(universe, rule, member)| {
            *universe == i.universe && *rule == i.rule && *member == i.member
        });
        if !hit {
            out.failures.push(format!(
                "missing inert member {} under rule {} in {}",
                i.member, i.rule, i.universe
            ));
        }
    }
    for a in &expected.attributes {
        let hit = arr(&report, "layers").iter().any(|l| {
            str_field(l, "kind") == Some(a.layer.as_str())
                && attribute_matches(l, &a.name, &a.value)
        });
        if !hit {
            out.failures.push(format!(
                "missing attribute {} = {:?} on layer {}",
                a.name, a.value, a.layer
            ));
        }
    }

    if let Some(want) = &expected.not_applicable {
        let mut got: Vec<String> = arr(&report, "not_applicable")
            .iter()
            .map(|e| {
                e.as_str()
                    .map(str::to_string)
                    .or_else(|| str_field(e, "id").map(str::to_string))
                    .or_else(|| str_field(e, "source").map(str::to_string))
                    .unwrap_or_default()
            })
            .collect();
        got.sort();
        let mut want = want.clone();
        want.sort();
        if got != want {
            out.failures
                .push(format!("not_applicable {got:?} but expected {want:?}"));
        }
    }

    for kind in &expected.absent_routes {
        let present = ["egress_routes", "escape_routes"]
            .iter()
            .flat_map(|k| arr(&report, k))
            .any(|r| str_field(r, "kind") == Some(kind.as_str()));
        if present {
            out.failures
                .push(format!("route kind {kind:?} must be absent but appears"));
        }
    }

    for needle in &expected.absent_text {
        let mut found = Vec::new();
        collect_text(&report, &mut found);
        if found.iter().any(|t| t.contains(needle.as_str())) {
            out.failures
                .push(format!("JSON output contains forbidden text {needle:?}"));
        }
        if output.text.contains(needle.as_str()) {
            out.failures
                .push(format!("text output contains forbidden text {needle:?}"));
        }
    }

    // Read-log assertions (KTD13).
    for entry in &output.read_log {
        let path = components(&entry.path);
        if entry.kind == ReadCall::Read && metadata_only(&path) {
            out.failures.push(format!(
                "read log: content read of metadata-only path {}",
                entry.path
            ));
        }
        if on_no_touch_fs(ctx, &path) {
            out.failures.push(format!(
                "read log: call on a no-touch filesystem path {}",
                entry.path
            ));
        }
    }

    out
}

/// The display string of the member an entry references: resolved through
/// the `universes` member table when `member` is an id, else the `display`
/// or raw `member`/`location` string.
fn member_of(entry: &Value, resolve: &dyn Fn(&str) -> String) -> String {
    if let Some(id) = str_field(entry, "member") {
        return resolve(id);
    }
    if let Some(d) = str_field(entry, "display") {
        return d.to_string();
    }
    str_field(entry, "location").unwrap_or_default().to_string()
}

/// `(universe, member display)` pairs from the `unclassified` section and
/// from members carrying `class: "unclassified"` inside `universes`.
fn unclassified_members(report: &Value, resolve: &dyn Fn(&str) -> String) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in arr(report, "unclassified") {
        out.push((
            str_field(e, "universe").unwrap_or("?").to_string(),
            member_of(e, resolve),
        ));
    }
    for u in arr(report, "universes") {
        let universe = str_field(u, "id").unwrap_or("?").to_string();
        for m in arr(u, "members") {
            if str_field(m, "class") == Some("unclassified") {
                out.push((
                    universe.clone(),
                    str_field(m, "display").unwrap_or("?").to_string(),
                ));
            }
        }
    }
    out
}

/// `(universe, rule, member display)` triples from an `inert` section and
/// from members carrying `class: "inert"` inside `universes`.
fn inert_members(
    report: &Value,
    resolve: &dyn Fn(&str) -> String,
) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for e in arr(report, "inert") {
        let universe = str_field(e, "universe").unwrap_or("?").to_string();
        let member = member_of(e, resolve);
        if let Some(rule) = str_field(e, "rule") {
            out.push((universe.clone(), rule.to_string(), member.clone()));
        }
        for r in arr(e, "rules") {
            if let Some(r) = r.as_str() {
                out.push((universe.clone(), r.to_string(), member.clone()));
            }
        }
    }
    for u in arr(report, "universes") {
        let universe = str_field(u, "id").unwrap_or("?").to_string();
        for m in arr(u, "members") {
            if str_field(m, "class") == Some("inert") {
                let member = str_field(m, "display").unwrap_or("?").to_string();
                if let Some(rule) = str_field(m, "rule") {
                    out.push((universe.clone(), rule.to_string(), member.clone()));
                }
                for r in arr(m, "rules") {
                    if let Some(r) = r.as_str() {
                        out.push((universe.clone(), r.to_string(), member.clone()));
                    }
                }
            }
        }
    }
    out
}

fn attribute_matches(layer: &Value, name: &str, value: &str) -> bool {
    match layer.get("attributes") {
        Some(Value::Object(map)) => map.get(name).is_some_and(|v| value_string(v) == value),
        Some(Value::Array(items)) => items.iter().any(|item| {
            str_field(item, "name") == Some(name)
                && item.get("value").is_some_and(|v| value_string(v) == value)
        }),
        _ => false,
    }
}

fn value_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// A route reduced to its comparison key: class (from its section), kind,
/// the `rule` or `signal` id, and the member's display string or the route
/// location.
struct ActualRoute {
    class: String,
    kind: String,
    id: String,
    member: String,
}

impl ActualRoute {
    fn describe(&self) -> String {
        format!(
            "{} {} at {} ({})",
            self.class, self.kind, self.member, self.id
        )
    }
}

fn compare_routes(
    expected: &Expected,
    report: &Value,
    resolve: &dyn Fn(&str) -> String,
    out: &mut CaseOutcome,
) {
    let mut actual: Vec<ActualRoute> = Vec::new();
    for (section, class) in [("egress_routes", "egress"), ("escape_routes", "escape")] {
        for r in arr(report, section) {
            actual.push(ActualRoute {
                class: class.to_string(),
                kind: str_field(r, "kind").unwrap_or("?").to_string(),
                id: str_field(r, "rule")
                    .or_else(|| str_field(r, "signal"))
                    .unwrap_or("?")
                    .to_string(),
                member: member_of(r, resolve),
            });
        }
    }
    let mut unclaimed = vec![true; actual.len()];
    for e in &expected.routes {
        let id = e.rule.as_deref().or(e.signal.as_deref()).unwrap_or("?");
        let describe = format!(
            "{} {} at {} ({})",
            e.class,
            e.kind,
            e.member.as_deref().unwrap_or_default(),
            id
        );
        let hit = actual.iter().enumerate().position(|(i, a)| {
            unclaimed[i]
                && a.class == e.class
                && a.kind == e.kind
                && a.id == id
                && e.member.as_deref().is_none_or(|m| a.member == m)
        });
        match hit {
            Some(i) => unclaimed[i] = false,
            None => out.failures.push(format!("missing route {describe}")),
        }
    }
    for (i, a) in actual.iter().enumerate() {
        if unclaimed[i] {
            out.failures
                .push(format!("unexpected route {}", a.describe()));
        }
    }
}

fn compare_layers(expected: &Expected, report: &Value, out: &mut CaseOutcome) {
    let layers = arr(report, "layers");
    let claimed: usize = expected
        .layers
        .iter()
        .map(|e| (e.order as usize).saturating_sub(1))
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);
    for l in layers.iter().skip(claimed.max(expected.layers.len())) {
        out.failures.push(format!(
            "unexpected layer {} {}",
            str_field(l, "family").unwrap_or("?"),
            str_field(l, "kind").unwrap_or("?")
        ));
    }
    if layers.len() < expected.layers.len() {
        out.failures.push(format!(
            "{} layers but expected {}",
            layers.len(),
            expected.layers.len()
        ));
    }
    for e in &expected.layers {
        let idx = (e.order as usize).saturating_sub(1);
        let Some(l) = layers.get(idx) else {
            out.failures
                .push(format!("missing layer {} {} {}", e.order, e.family, e.kind));
            continue;
        };
        let family = str_field(l, "family").unwrap_or("?");
        let kind = str_field(l, "kind").unwrap_or("?");
        if family != e.family || kind != e.kind {
            out.failures.push(format!(
                "layer {} is {family} {kind} but expected {} {}",
                e.order, e.family, e.kind
            ));
        }
        if let Some(want) = &e.evidence_classes {
            let mut got: Vec<String> = arr(l, "evidence_classes")
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if got.is_empty() {
                got = arr(l, "evidence")
                    .iter()
                    .filter_map(|v| str_field(v, "class").map(str::to_string))
                    .collect();
            }
            let mut got_set: Vec<_> = got.clone();
            got_set.sort();
            got_set.dedup();
            let mut want_set = want.clone();
            want_set.sort();
            want_set.dedup();
            if got_set != want_set {
                out.failures.push(format!(
                    "layer {} {} evidence classes {got_set:?} but expected {want_set:?}",
                    e.order, e.kind
                ));
            }
        }
    }
}

/// Exact multiset comparison: every expected entry must be claimed by a
/// distinct actual entry, and every actual entry must be claimed.
fn compare_exact_multiset(
    what: &str,
    expected: &[String],
    actual: Vec<String>,
    out: &mut CaseOutcome,
) {
    let mut unclaimed = vec![true; actual.len()];
    for e in expected {
        match actual
            .iter()
            .enumerate()
            .position(|(i, a)| unclaimed[i] && a == e)
        {
            Some(i) => unclaimed[i] = false,
            None => out.failures.push(format!("missing {what} {e}")),
        }
    }
    for (i, a) in actual.iter().enumerate() {
        if unclaimed[i] {
            out.failures.push(format!("unexpected {what} {a}"));
        }
    }
}

/// Every string value in the JSON, skipping `id` and `member` (identity
/// hashes and references to them), `data_digest`, and `*_bytes` hex fields:
/// a short forbidden string can occur in a hash or hex blob by chance, and
/// those are not text.
fn collect_text<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if k == "id" || k == "member" || k == "data_digest" || k.ends_with("_bytes") {
                    continue;
                }
                collect_text(val, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_text(item, out);
            }
        }
        Value::String(s) => out.push(s),
        _ => {}
    }
}

fn arr<'a>(v: &'a Value, key: &str) -> Vec<&'a Value> {
    match v.get(key) {
        Some(Value::Array(items)) => items.iter().collect(),
        _ => Vec::new(),
    }
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

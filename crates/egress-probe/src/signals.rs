//! Named-signal evaluation (R11): path markers, credential paths and
//! directories (metadata and access only, never content), DMI values,
//! sysctl-value attribute producers, derived conditions, and the
//! integrity declarations the tamper stage produces.

use std::collections::{BTreeMap, BTreeSet};

use crate::data::{Condition, Data, MountCond, Signal, SignalKind, SignalPlatform};
use crate::facts::Facts;
use crate::model::{
    AttrValue, Layer, MemberValue, Route, TamperIndicator, Universe, Unknown, UnknownReason,
};
use crate::reader::{Denial, Reader};
use crate::universe::denial_reason;

/// What one signal evaluation may produce.
#[derive(Debug, Default)]
pub struct SignalOutput {
    /// Signals whose evidence held.
    pub present: BTreeSet<String>,
    /// Routes produced by present signals.
    pub egress: Vec<Route>,
    pub escape: Vec<Route>,
    /// Tamper indicators produced by present signals.
    pub tamper: Vec<TamperIndicator>,
    /// Signal states that could not be decided.
    pub unknowns: Vec<Unknown>,
    /// Attributes produced by `sysctl-value` signals (KTD28).
    pub attributes: BTreeMap<String, AttrValue>,
}

/// Read-side facts and member context conditions evaluate against.
pub struct Ctx<'a> {
    pub platform: &'a str,
    pub universes: &'a [Universe],
    pub attributes: &'a BTreeMap<String, AttrValue>,
    pub euid: Option<u32>,
    pub home: &'a Result<Vec<u8>, UnknownReason>,
    pub fired: BTreeSet<String>,
    pub layers: &'a [Layer],
    pub facts: &'a Facts,
    /// Weak tamper flags collected during the run (loader env names).
    pub tracer_pid: Option<u64>,
    /// A strong `traced` tamper was produced by the integrity checks.
    pub traced: bool,
    /// A strong `fs-type-mismatch` unknown exists on some source.
    pub fs_type_mismatch: bool,
    /// A strong `proc-self-mismatch` unknown exists on some source.
    pub proc_self_mismatch: bool,
    /// Sources that already carry an unknown (seeded from the scan and
    /// appended as signals produce more); a derived signal whose
    /// dependency hits this set is itself `depends-on-unknown`.
    pub unknown_sources: BTreeSet<String>,
}

fn subst(path: &str, ctx: &Ctx<'_>, euid: Option<u32>) -> Option<Vec<u8>> {
    let mut p = path.to_string();
    if p.contains("<euid>") {
        let e = euid?;
        p = p.replace("<euid>", &e.to_string());
    }
    if p.contains("<home>") {
        match ctx.home {
            Ok(h) => p = p.replace("<home>", &String::from_utf8_lossy(h)),
            Err(_) => return None,
        }
    }
    Some(p.trim_start_matches('/').as_bytes().to_vec())
}

fn signal_route(sig: &Signal, display: String, location: Option<Vec<u8>>) -> Option<Route> {
    let r = sig.route.as_ref()?;
    Some(Route {
        id: String::new(),
        kind: r.kind.clone(),
        rule: None,
        signal: Some(sig.id.clone()),
        member: None,
        location,
        verified: false,
        display,
    })
}

/// Evaluates every declared signal for this platform against the reader
/// and the context. `derived` signals marked `after-layers` are skipped
/// here and evaluated by [`evaluate_after_layers`].
pub fn evaluate<R: Reader>(r: &mut R, data: &Data, ctx: &mut Ctx<'_>) -> SignalOutput {
    let mut out = SignalOutput::default();
    for sig in &data.signals {
        if !platform_matches(sig, ctx.platform) {
            continue;
        }
        if sig.kind == SignalKind::Integrity {
            // Produced by the integrity checks, not evaluated here.
            continue;
        }
        if sig.after_layers {
            continue;
        }
        eval_one(r, sig, data, ctx, &mut out);
        for u in &out.unknowns {
            ctx.unknown_sources.insert(u.source.clone());
        }
    }
    out
}

/// Evaluates the `after-layers` derived signals once layers are known.
pub fn evaluate_after_layers<R: Reader>(r: &mut R, data: &Data, ctx: &mut Ctx<'_>) -> SignalOutput {
    let mut out = SignalOutput::default();
    for sig in &data.signals {
        if !platform_matches(sig, ctx.platform) || !sig.after_layers {
            continue;
        }
        eval_one(r, sig, data, ctx, &mut out);
        for u in &out.unknowns {
            ctx.unknown_sources.insert(u.source.clone());
        }
    }
    out
}

fn platform_matches(sig: &Signal, platform: &str) -> bool {
    match sig.platform {
        SignalPlatform::Both => true,
        SignalPlatform::Linux => platform == "linux",
        SignalPlatform::Macos => platform == "macos",
    }
}

fn structural_denial(d: Denial) -> Option<UnknownReason> {
    match d {
        Denial::DependsOnUnknown => Some(UnknownReason::DependsOnUnknown),
        Denial::NotTouched => Some(UnknownReason::NetworkFilesystemNotTouched),
        Denial::LinkPolicy => Some(UnknownReason::LinkPolicy),
        Denial::FsTypeMismatch => Some(UnknownReason::FsTypeMismatch),
        Denial::ProcSelfMismatch => Some(UnknownReason::ProcSelfMismatch),
        Denial::DescriptorLimit => Some(UnknownReason::DescriptorLimit),
        Denial::TooLarge => Some(UnknownReason::BudgetExceeded),
        Denial::Absent | Denial::Unreadable(_) | Denial::NotRegular => None,
    }
}

fn record_present(
    sig: &Signal,
    out: &mut SignalOutput,
    display: String,
    location: Option<Vec<u8>>,
) {
    out.present.insert(sig.id.clone());
    if let Some(mut route) = signal_route(sig, display, location) {
        route.verified = false;
        match sig.route.as_ref().map(|r| r.class) {
            Some(crate::data::RuleClass::Egress) => out.egress.push(route),
            _ => out.escape.push(route),
        }
    }
    if let Some(t) = &sig.tamper {
        out.tamper.push(TamperIndicator {
            id: String::new(),
            indicator: t.indicator.clone(),
            strength: t.strength,
            display: sig.id.clone(),
        });
    }
}

fn unknown(sig: &Signal, out: &mut SignalOutput, reason: UnknownReason) {
    out.unknowns.push(Unknown {
        id: String::new(),
        source: sig.id.clone(),
        reason,
    });
}

/// The attribute name to the source that produces it, for the
/// `depends-on-unknown` propagation of derived signals.
fn attr_source(name: &str) -> Option<&'static str> {
    match name {
        "namespaces" | "ns-ipc-inode" | "ns-pid-inode" | "ns-net-inode" | "ns-mnt-inode"
        | "ns-user-inode" | "ns-uts-inode" | "ns-cgroup-inode" | "ns-time-inode" => {
            Some("linux.attr.namespaces")
        }
        "cgroups" => Some("linux.attr.cgroup"),
        "uid-map-lines" | "gid-map-lines" => Some("linux.attr.id-maps"),
        "ptrace_scope" => Some("linux.attr.ptrace-scope"),
        "landlock-abi" => Some("linux.attr.landlock-abi"),
        "max_user_namespaces"
        | "unprivileged_userns_clone"
        | "apparmor_restrict_unprivileged_userns" => Some("linux.sysctl.userns"),
        _ => Some("linux.attr.status"),
    }
}

/// The sources a condition consults for `depends-on-unknown`
/// propagation: member-universe sources always; `attr` only for
/// after-layers signals (a plain derived signal with an unreadable
/// attribute source is absent, not unknown); `signal`, `capabilities`,
/// `layer-family`, and `fact` conditions contribute none.
fn condition_sources(c: &Condition, platform: &str, after_layers: bool) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let u = |name: &str| format!("{platform}.{name}");
    if !c.env.is_empty() || !c.env_prefix.is_empty() {
        out.insert(u("env-names"));
    }
    if !c.cgroup_contains.is_empty() {
        out.insert("linux.attr.cgroup".to_string());
    }
    if !c.resolver.is_empty()
        || !c.resolver_search.is_empty()
        || !c.resolver_search_suffix.is_empty()
    {
        out.insert(u("resolvers"));
    }
    if after_layers
        && let Some(a) = &c.attr
        && let Some(src) = attr_source(a)
    {
        out.insert(src.to_string());
    }
    if !c.interface.is_empty() || !c.interface_prefix.is_empty() {
        out.insert(u("interfaces"));
    }
    if c.mount.is_some() || c.no_mount.is_some() || !c.root_fstype.is_empty() {
        out.insert(u("mounts"));
    }
    out
}

/// Every source a signal's own conditions consult for
/// `depends-on-unknown` propagation (see [`condition_sources`]).
pub fn signal_deps(sig: &Signal, platform: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if !sig.names.is_empty() || !sig.name_prefixes.is_empty() {
        out.insert(format!("{platform}.env-names"));
    }
    for c in sig.all.iter().chain(sig.any.iter()) {
        out.extend(condition_sources(c, platform, sig.after_layers));
    }
    out
}

fn eval_one<R: Reader>(
    r: &mut R,
    sig: &Signal,
    data: &Data,
    ctx: &mut Ctx<'_>,
    out: &mut SignalOutput,
) {
    match sig.kind {
        SignalKind::PathMarker | SignalKind::CredentialPath => eval_paths(r, sig, ctx, out, false),
        SignalKind::CredentialDir => eval_dir(r, sig, ctx, out),
        SignalKind::DmiValue => eval_dmi(r, sig, ctx, out),
        SignalKind::SysctlValue => eval_sysctl(r, sig, ctx, out),
        SignalKind::Derived => eval_derived(sig, data, ctx, out),
        SignalKind::Integrity => {}
    }
}

fn eval_paths<R: Reader>(r: &mut R, sig: &Signal, ctx: &Ctx<'_>, out: &mut SignalOutput, _: bool) {
    let mut any = false;
    let mut first_denial: Option<UnknownReason> = None;
    for raw in &sig.paths {
        let Some(path) = subst(raw, ctx, ctx.euid) else {
            // <home> unresolved: the signal is unknown, not absent.
            unknown(
                sig,
                out,
                ctx.home
                    .clone()
                    .err()
                    .unwrap_or(UnknownReason::NoAccountHome),
            );
            return;
        };
        match r.metadata(&path) {
            Ok(_meta) => {
                any = true;
                let mut loc = path.clone();
                loc.insert(0, b'/');
                if let Some(route) =
                    signal_route(sig, String::from_utf8_lossy(&loc).into_owned(), Some(loc))
                {
                    match sig.route.as_ref().map(|s| s.class) {
                        Some(crate::data::RuleClass::Egress) => out.egress.push(route),
                        _ => out.escape.push(route),
                    }
                }
            }
            Err(d) => {
                if let Some(reason) = structural_denial(d) {
                    first_denial = Some(reason);
                }
            }
        }
    }
    if let Some(dir) = &sig.dir {
        let Some(path) = subst(dir, ctx, ctx.euid) else {
            unknown(
                sig,
                out,
                ctx.home
                    .clone()
                    .err()
                    .unwrap_or(UnknownReason::NoAccountHome),
            );
            return;
        };
        match r.list(&path) {
            Ok(entries) => {
                let needle = sig
                    .name_contains
                    .as_deref()
                    .unwrap_or_default()
                    .to_lowercase();
                for (name, _meta) in entries {
                    let n = String::from_utf8_lossy(&name).to_lowercase();
                    if !needle.is_empty() && n.contains(&needle) {
                        any = true;
                        let mut loc = path.clone();
                        loc.insert(0, b'/');
                        loc.push(b'/');
                        loc.extend_from_slice(&name);
                        record_present(
                            sig,
                            out,
                            String::from_utf8_lossy(&loc).into_owned(),
                            Some(loc),
                        );
                    }
                }
            }
            Err(d) => {
                if let Some(reason) = structural_denial(d) {
                    first_denial = Some(reason);
                }
            }
        }
    }
    if let Some(reason) = first_denial {
        unknown(sig, out, reason);
    } else if any {
        // record_present was already called per member above for routed
        // entries; a bare marker with no route still needs the flag.
        out.present.insert(sig.id.clone());
        if let Some(t) = &sig.tamper {
            out.tamper.push(TamperIndicator {
                id: String::new(),
                indicator: t.indicator.clone(),
                strength: t.strength,
                display: sig.id.clone(),
            });
        }
    }
}

fn eval_dir<R: Reader>(r: &mut R, sig: &Signal, ctx: &Ctx<'_>, out: &mut SignalOutput) {
    let Some(dir) = &sig.dir else { return };
    let Some(path) = subst(dir, ctx, ctx.euid) else {
        unknown(
            sig,
            out,
            ctx.home
                .clone()
                .err()
                .unwrap_or(UnknownReason::NoAccountHome),
        );
        return;
    };
    match r.list(&path) {
        Ok(entries) => {
            let mut found = false;
            for (name, _meta) in entries {
                let n = String::from_utf8_lossy(&name);
                if let Some(pre) = &sig.entry_prefix
                    && !n.starts_with(pre.as_str())
                {
                    continue;
                }
                if let Some(suf) = &sig.entry_exclude_suffix
                    && n.ends_with(suf.as_str())
                {
                    continue;
                }
                found = true;
                let mut loc = path.clone();
                loc.insert(0, b'/');
                loc.push(b'/');
                loc.extend_from_slice(&name);
                record_present(
                    sig,
                    out,
                    String::from_utf8_lossy(&loc).into_owned(),
                    Some(loc),
                );
            }
            if found {
                out.present.insert(sig.id.clone());
            }
        }
        Err(d) => {
            if let Some(reason) = structural_denial(d) {
                unknown(sig, out, reason);
            }
        }
    }
}

fn eval_dmi<R: Reader>(r: &mut R, sig: &Signal, ctx: &Ctx<'_>, out: &mut SignalOutput) {
    let mut groups: BTreeMap<u32, bool> = BTreeMap::new();
    let mut any_denial = None;
    for v in &sig.values {
        let Some(path) = subst(&v.path, ctx, ctx.euid) else {
            unknown(sig, out, UnknownReason::NoAccountHome);
            return;
        };
        match r.read(&path, 4096) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let text = text.trim();
                let ok = match (&v.equals, &v.prefix) {
                    (Some(e), _) => text == e,
                    (None, Some(p)) => text.starts_with(p.as_str()),
                    _ => !text.is_empty(),
                };
                *groups.entry(v.group).or_insert(true) &= ok;
            }
            Err(Denial::Absent) => {
                // Missing directory or file: the group is absent, not a
                // denial (a missing DMI tree means no firmware data).
                groups.entry(v.group).or_insert(false);
            }
            Err(d) => {
                any_denial = Some(denial_reason(d));
            }
        }
    }
    if let Some(reason) = any_denial {
        unknown(sig, out, reason);
    } else if groups.values().any(|g| *g) {
        out.present.insert(sig.id.clone());
    }
}

fn eval_sysctl<R: Reader>(r: &mut R, sig: &Signal, ctx: &Ctx<'_>, out: &mut SignalOutput) {
    let mut first_denial: Option<UnknownReason> = None;
    for (i, raw) in sig.paths.iter().enumerate() {
        let Some(path) = subst(raw, ctx, ctx.euid) else {
            continue;
        };
        match r.read(&path, 128) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                match text.trim().parse::<i64>() {
                    Ok(n) => {
                        if let Some(name) = sig.attributes.get(i) {
                            out.attributes.insert(name.clone(), AttrValue::Int(n));
                        }
                        out.present.insert(sig.id.clone());
                    }
                    Err(_) => {
                        if first_denial.is_none() {
                            first_denial = Some(UnknownReason::Partial);
                        }
                    }
                }
            }
            Err(Denial::Absent) => {}
            Err(d) => {
                if first_denial.is_none() {
                    first_denial = Some(denial_reason(d));
                }
            }
        }
    }
    if let Some(reason) = first_denial {
        unknown(sig, out, reason);
    }
}

// ---------------------------------------------------------------------------
// Condition evaluation (derived signals and layer conditions).
// ---------------------------------------------------------------------------

fn members<'c>(ctx: &Ctx<'c>, universe: &str) -> impl Iterator<Item = &'c crate::model::Member> {
    ctx.universes
        .iter()
        .find(|u| u.id == universe)
        .into_iter()
        .flat_map(|u| u.members.iter())
}

fn field_text(m: &crate::model::Member, field: &str) -> String {
    m.fields
        .iter()
        .find(|f| f.name == field)
        .map(|f| match &f.value {
            MemberValue::Text(b) => String::from_utf8_lossy(b).into_owned(),
            MemberValue::Int(n) => n.to_string(),
            MemberValue::Bool(b) => b.to_string(),
        })
        .unwrap_or_default()
}

fn env_names(ctx: &Ctx<'_>) -> Vec<String> {
    members(ctx, "linux.env-names")
        .map(|m| field_text(m, "name"))
        .collect()
}

fn resolvers(ctx: &Ctx<'_>) -> Vec<(String, String)> {
    members(ctx, "linux.resolvers")
        .chain(members(ctx, "macos.resolvers"))
        .map(|m| (field_text(m, "directive"), field_text(m, "value")))
        .collect()
}

fn mount_matches(m: &crate::model::Member, cond: &MountCond) -> bool {
    let point = field_text(m, "mount-point");
    let fstype = field_text(m, "fstype");
    if !cond.fstype.is_empty() && !cond.fstype.contains(&fstype) {
        return false;
    }
    if !cond.point.is_empty() && !cond.point.contains(&point) {
        return false;
    }
    if !cond.under.is_empty() {
        let p = point.as_bytes();
        let ok = cond.under.iter().any(|u| component_under(p, u));
        if !ok {
            return false;
        }
    }
    if let Some(w) = cond.writable {
        let writable = m
            .fields
            .iter()
            .find(|f| f.name == "writable")
            .and_then(|f| match &f.value {
                MemberValue::Bool(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);
        if writable != w {
            return false;
        }
    }
    true
}

fn component_under(value: &[u8], prefix: &str) -> bool {
    let p = prefix.as_bytes();
    value == p || (value.len() > p.len() && value.starts_with(p) && value[p.len()] == b'/')
}

fn attr_equals(ctx: &Ctx<'_>, name: &str, want: &str) -> bool {
    match ctx.attributes.get(name) {
        Some(AttrValue::Str(s)) => s == want,
        Some(AttrValue::Int(n)) => n.to_string() == want,
        Some(AttrValue::Bool(b)) => b.to_string() == want,
        Some(AttrValue::Strings(list)) => list.iter().any(|s| s == want),
        _ => false,
    }
}

fn fact_true(ctx: &Ctx<'_>, name: &str) -> bool {
    match name {
        "sandbox_check" => ctx
            .facts
            .sandbox_check
            .as_ref()
            .and_then(|f| f.read())
            .is_some_and(|v| *v != 0),
        "hv_vmm_present" => ctx
            .facts
            .hv_vmm_present
            .as_ref()
            .and_then(|f| f.read())
            .copied()
            .unwrap_or(false),
        _ => false,
    }
}

/// The 41-name capability table used by the `all-effective` condition:
/// every known capability name must appear with set `effective`.
const KNOWN_CAPS: &[&str] = &[
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

pub fn condition_holds(c: &Condition, ctx: &Ctx<'_>) -> bool {
    if !c.signal.is_empty() && !c.signal.iter().any(|s| ctx.fired.contains(s)) {
        return false;
    }
    if !c.env.is_empty() || !c.env_prefix.is_empty() {
        let names = env_names(ctx);
        let hit = names.iter().any(|n| {
            c.env.iter().any(|e| e == n) || c.env_prefix.iter().any(|p| n.starts_with(p.as_str()))
        });
        if !hit {
            return false;
        }
    }
    if !c.cgroup_contains.is_empty() {
        let lines = match ctx.attributes.get("cgroups") {
            Some(AttrValue::Strings(l)) => l.clone(),
            _ => Vec::new(),
        };
        let hit = c
            .cgroup_contains
            .iter()
            .any(|needle| lines.iter().any(|l| l.contains(needle.as_str())));
        if !hit {
            return false;
        }
    }
    if !c.resolver.is_empty() {
        let res = resolvers(ctx);
        if !c
            .resolver
            .iter()
            .any(|v| res.iter().any(|(d, val)| d == "nameserver" && val == v))
        {
            return false;
        }
    }
    if !c.resolver_search.is_empty() || !c.resolver_search_suffix.is_empty() {
        let res = resolvers(ctx);
        let hit = res.iter().any(|(d, val)| {
            if d != "search" && d != "domain" {
                return false;
            }
            c.resolver_search.iter().any(|v| val == v)
                || c.resolver_search_suffix
                    .iter()
                    .any(|s| val.ends_with(s.as_str()))
                || val.split_whitespace().any(|tok| {
                    c.resolver_search.iter().any(|v| tok == v)
                        || c.resolver_search_suffix
                            .iter()
                            .any(|s| tok.ends_with(s.as_str()))
                })
        });
        if !hit {
            return false;
        }
    }
    if let Some(a) = &c.attr {
        let want = c.equals.as_deref().unwrap_or_default();
        if !attr_equals(ctx, a, want) {
            return false;
        }
    }
    if !c.capabilities.is_empty() {
        let effective: BTreeSet<String> = members(ctx, "linux.capabilities")
            .filter(|m| field_text(m, "set") == "effective")
            .map(|m| field_text(m, "name"))
            .collect();
        let all = KNOWN_CAPS.iter().all(|k| effective.contains(*k));
        if !all {
            return false;
        }
    }
    if !c.layer_family.is_empty() {
        let hit = c
            .layer_family
            .iter()
            .any(|f| ctx.layers.iter().any(|l| l.family.as_str() == f.as_str()));
        if !hit {
            return false;
        }
    }
    if !c.interface.is_empty() || !c.interface_prefix.is_empty() {
        let names: Vec<String> = members(ctx, "linux.interfaces")
            .chain(members(ctx, "macos.interfaces"))
            .map(|m| field_text(m, "name"))
            .collect();
        let hit = names.iter().any(|n| {
            c.interface.iter().any(|i| i == n)
                || c.interface_prefix.iter().any(|p| n.starts_with(p.as_str()))
        });
        if !hit {
            return false;
        }
    }
    if let Some(mc) = &c.mount {
        let hit = members(ctx, "linux.mounts")
            .chain(members(ctx, "macos.mounts"))
            .any(|m| mount_matches(m, mc));
        if !hit {
            return false;
        }
    }
    if let Some(mc) = &c.no_mount {
        let hit = members(ctx, "linux.mounts")
            .chain(members(ctx, "macos.mounts"))
            .any(|m| mount_matches(m, mc));
        if hit {
            return false;
        }
    }
    if !c.root_fstype.is_empty() {
        let root = members(ctx, "linux.mounts")
            .chain(members(ctx, "macos.mounts"))
            .find(|m| field_text(m, "mount-point") == "/")
            .map(|m| field_text(m, "fstype"))
            .unwrap_or_default();
        if !c.root_fstype.contains(&root) {
            return false;
        }
    }
    if !c.fact.is_empty() && !c.fact.iter().any(|f| fact_true(ctx, f)) {
        return false;
    }
    true
}

/// A derived signal fires when every `all` condition holds (with at least
/// one) or any `any` condition holds; env `names`/`name_prefixes` at the
/// signal level are a shorthand any-condition over env-names members.
fn derived_fires(sig: &Signal, ctx: &Ctx<'_>) -> bool {
    if !sig.names.is_empty() || !sig.name_prefixes.is_empty() {
        let names = env_names(ctx);
        if names.iter().any(|n| {
            sig.names.iter().any(|e| e == n)
                || sig.name_prefixes.iter().any(|p| n.starts_with(p.as_str()))
        }) {
            return true;
        }
    }
    if !sig.all.is_empty() && sig.all.iter().all(|c| condition_holds(c, ctx)) {
        return true;
    }
    sig.any.iter().any(|c| condition_holds(c, ctx))
}

/// The metadata endpoint address a detected cloud layer implies
/// (the well-known provider literal; never a connection target, R3).
fn metadata_endpoint(ctx: &Ctx<'_>) -> &'static [u8] {
    if ctx.layers.iter().any(|l| l.kind == "azure") {
        b"168.63.129.16"
    } else {
        b"169.254.169.254"
    }
}

fn eval_derived(sig: &Signal, _data: &Data, ctx: &Ctx<'_>, out: &mut SignalOutput) {
    if signal_deps(sig, ctx.platform)
        .iter()
        .any(|d| ctx.unknown_sources.contains(d))
    {
        unknown(sig, out, UnknownReason::DependsOnUnknown);
        return;
    }
    if derived_fires(sig, ctx) {
        out.present.insert(sig.id.clone());
        let (display, location) = if sig
            .route
            .as_ref()
            .is_some_and(|r| r.kind == "metadata-endpoint")
        {
            let loc = metadata_endpoint(ctx);
            (
                String::from_utf8_lossy(loc).into_owned(),
                Some(loc.to_vec()),
            )
        } else {
            (sig.id.clone(), None)
        };
        if let Some(route) = signal_route(sig, display, location) {
            match sig.route.as_ref().map(|s| s.class) {
                Some(crate::data::RuleClass::Egress) => out.egress.push(route),
                _ => out.escape.push(route),
            }
        }
        if let Some(t) = &sig.tamper {
            out.tamper.push(TamperIndicator {
                id: String::new(),
                indicator: t.indicator.clone(),
                strength: t.strength,
                display: sig.id.clone(),
            });
        }
    }
}

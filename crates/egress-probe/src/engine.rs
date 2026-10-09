//! The probe pipeline: enumerate universes, classify members, evaluate
//! signals, detect layers, produce tamper indicators, derive
//! completeness, finalize, render. The same stages run for live and
//! snapshot sources (KTD3, KTD4); only the reader differs.

use std::collections::BTreeSet;

use crate::classify;
use crate::completeness;
use crate::data::Data;
use crate::facts::Platform;
use crate::integrity;
use crate::layers;
use crate::model::{
    Mode, Privilege, Report, Signal, SignalState, Source, TamperIndicator, TamperStrength, Tool,
    Unknown, UnknownReason,
};
use crate::reader::{Denial, Reader};
use crate::signals;
use crate::universe::{self, Scan};

/// Runs the full pipeline over an already-open reader and returns the
/// report, unfinalized until the caller runs `identity::finalize`.
pub fn run<R: Reader>(reader: &mut R, data: &Data, source: Source, mode: Mode) -> Report {
    let facts = reader.facts().clone();
    let platform = facts.platform.unwrap_or(Platform::Linux);

    let mut scan: Scan = if platform == Platform::Linux {
        universe::linux::enumerate(reader, data)
    } else {
        universe::macos::enumerate(reader, data)
    };

    let (mut egress, mut escape) = classify::classify(&mut scan.universes, data, scan.euid);

    // Signals: read-side kinds first, then derived (before layers),
    // then after-layers. Signal-produced attributes join the scan's
    // before layer detection so conditions can consult them.
    let platform_name = match platform {
        Platform::Linux => "linux",
        Platform::Macos => "macos",
    };
    // Signals before layers see no sysctl-produced attributes; the
    // attributes merge into the scan set before layer detection.
    let sig_facts = facts.clone();
    let home_err = scan
        .home
        .clone()
        .err()
        .unwrap_or(UnknownReason::NoAccountHome);
    let _ = home_err;
    let mut sig_out = {
        let mut ctx = signals::Ctx {
            platform: platform_name,
            universes: &scan.universes,
            attributes: &scan.attributes,
            euid: scan.euid,
            home: &scan.home,
            fired: BTreeSet::new(),
            layers: &[],
            facts: &sig_facts,
            tracer_pid: scan.tracer_pid,
            traced: false,
            fs_type_mismatch: scan
                .unknowns
                .iter()
                .any(|u| u.reason == UnknownReason::FsTypeMismatch),
            proc_self_mismatch: scan
                .unknowns
                .iter()
                .any(|u| u.reason == UnknownReason::ProcSelfMismatch),
            unknown_sources: scan.unknowns.iter().map(|u| u.source.clone()).collect(),
        };
        signals::evaluate(reader, data, &mut ctx)
    };
    scan.attributes.append(&mut sig_out.attributes);

    let mut detected = {
        let ctx = signals::Ctx {
            platform: platform_name,
            universes: &scan.universes,
            attributes: &scan.attributes,
            euid: scan.euid,
            home: &scan.home,
            fired: sig_out.present.clone(),
            layers: &[],
            facts: &sig_facts,
            tracer_pid: scan.tracer_pid,
            traced: false,
            fs_type_mismatch: scan
                .unknowns
                .iter()
                .any(|u| u.reason == UnknownReason::FsTypeMismatch),
            proc_self_mismatch: scan
                .unknowns
                .iter()
                .any(|u| u.reason == UnknownReason::ProcSelfMismatch),
            unknown_sources: sig_out
                .unknowns
                .iter()
                .map(|u| u.source.clone())
                .chain(scan.unknowns.iter().map(|u| u.source.clone()))
                .collect(),
        };
        layers::detect(data, &ctx)
    };

    // Attach confinement attributes to the innermost detected layer, or
    // to the synthesized host layer when there is none (R12).
    if let Some(innermost) = detected.last_mut() {
        innermost.attributes.extend(scan.attributes.clone());
    }

    let sig2 = {
        let mut ctx = signals::Ctx {
            platform: platform_name,
            universes: &scan.universes,
            attributes: &scan.attributes,
            euid: scan.euid,
            home: &scan.home,
            fired: sig_out.present.clone(),
            layers: &detected,
            facts: &sig_facts,
            tracer_pid: scan.tracer_pid,
            traced: false,
            fs_type_mismatch: scan
                .unknowns
                .iter()
                .any(|u| u.reason == UnknownReason::FsTypeMismatch),
            proc_self_mismatch: scan
                .unknowns
                .iter()
                .any(|u| u.reason == UnknownReason::ProcSelfMismatch),
            unknown_sources: sig_out
                .unknowns
                .iter()
                .map(|u| u.source.clone())
                .chain(scan.unknowns.iter().map(|u| u.source.clone()))
                .collect(),
        };
        signals::evaluate_after_layers(reader, data, &mut ctx)
    };
    sig_out.present.extend(sig2.present);
    sig_out.egress.extend(sig2.egress);
    sig_out.escape.extend(sig2.escape);
    sig_out.tamper.extend(sig2.tamper);
    sig_out.unknowns.extend(sig2.unknowns);

    // Tamper indicators: the integrity checks produce `traced`,
    // `fs-type-mismatch`, and `proc-self-mismatch`; signals produced
    // their own weak/strong entries already.
    let mut tamper: Vec<TamperIndicator> = sig_out.tamper;
    let mut extra_unknowns: Vec<Unknown> = sig_out.unknowns;
    integrity_tamper(reader, &scan, &mut tamper, &mut extra_unknowns);
    // traced is recorded on the tamper list; no ctx consumer needs it.

    let mut unknowns = scan.unknowns;
    unknowns.extend(extra_unknowns);
    let mut seen_unknowns = BTreeSet::new();
    unknowns.retain(|u| seen_unknowns.insert((u.source.clone(), u.reason)));

    // Signal states for the report's signal roster: every declared signal
    // on this platform is present, absent, unknown, or not-applicable.
    let unknown_sources: BTreeSet<&str> = unknowns.iter().map(|u| u.source.as_str()).collect();
    let mut signals: Vec<Signal> = data
        .signals
        .iter()
        .map(|s| {
            let state = if !platform_matches_signal(s.platform, platform_name) {
                SignalState::NotApplicable
            } else if sig_out.present.contains(&s.id) {
                SignalState::Present
            } else if unknown_sources.contains(s.id.as_str()) {
                SignalState::Unknown
            } else {
                SignalState::Absent
            };
            Signal {
                id: String::new(),
                signal: s.id.clone(),
                state,
            }
        })
        .collect();
    // Integrity signals declare indicators the tamper stage produced.
    for s in &mut signals {
        let decl = data.signals.iter().find(|d| d.id == s.signal);
        if let Some(d) = decl
            && d.kind == crate::data::SignalKind::Integrity
            && let Some(t) = &d.tamper
            && tamper.iter().any(|i| i.indicator == t.indicator)
        {
            s.state = SignalState::Present;
        }
    }

    egress.extend(sig_out.egress);
    escape.extend(sig_out.escape);

    let mut report = Report {
        schema_version: crate::model::SCHEMA_VERSION,
        tool: Tool {
            name: "egress-plane".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            data_digest: data_digest(data),
        },
        source,
        platform,
        privilege: Privilege {
            euid: scan.euid.unwrap_or(u32::MAX),
            egid: scan.egid.unwrap_or(u32::MAX),
        },
        mode,
        nonce: None,
        completeness: egress_core::model::CompletenessState::Complete,
        layers: detected,
        egress_routes: egress,
        escape_routes: escape,
        unknowns,
        tamper_indicators: tamper,
        not_observable: data
            .not_observable
            .iter()
            .filter(|n| platform_matches_str(&n.platform, platform_name))
            .map(|n| crate::model::NotObservable {
                id: n.id.clone(),
                statement: n.statement.clone(),
                reason: n.reason.clone(),
            })
            .collect(),
        not_applicable: scan.not_applicable.clone(),
        unclassified: Vec::new(),
        universes: scan.universes,
        signals,
        active_checks: Vec::new(),
        caveats: Vec::new(),
    };
    report.completeness = completeness::derive(&report);
    report
}

fn platform_matches_signal(p: crate::data::SignalPlatform, platform: &str) -> bool {
    match p {
        crate::data::SignalPlatform::Both => true,
        crate::data::SignalPlatform::Linux => platform == "linux",
        crate::data::SignalPlatform::Macos => platform == "macos",
    }
}

fn platform_matches_str(p: &str, platform: &str) -> bool {
    p == "both" || p == platform
}

fn data_digest(data: &Data) -> String {
    data.data_digest.clone()
}

/// The integrity tamper indicators (KTD25): `traced` reads the traced
/// state again at finalize so a tracer that attached mid-run is caught;
/// `fs-type-mismatch` and `proc-self-mismatch` follow the unknowns the
/// reader already produced on their sources. On macOS the second read
/// is the `traced` fact the adapter produced (the KERN_PROC_PID sysctl
/// is fact-backed like every other source).
fn integrity_tamper<R: Reader>(
    reader: &mut R,
    scan: &Scan,
    tamper: &mut Vec<TamperIndicator>,
    unknowns: &mut Vec<Unknown>,
) {
    let (start_traced, end_traced) =
        if reader.facts().platform == Some(crate::facts::Platform::Macos) {
            let t = matches!(reader.facts().traced, Some(crate::facts::Fact::Read(true)));
            (t, t)
        } else {
            let start = scan.tracer_pid.is_some_and(|t| t != 0);
            let end = match reader.read(b"proc/self/status", 65536) {
                Ok(bytes) => integrity::tracer_pid(&bytes).is_some_and(|t| t != 0),
                Err(Denial::Absent | Denial::NotRegular) | Err(_) => {
                    scan.tracer_pid.is_some_and(|t| t != 0)
                }
            };
            (start, end)
        };
    if start_traced || end_traced {
        tamper.push(TamperIndicator {
            id: String::new(),
            indicator: "traced".to_string(),
            strength: TamperStrength::Strong,
            display: "traced".to_string(),
        });
        unknowns.push(Unknown {
            id: String::new(),
            source: "probe-integrity".to_string(),
            reason: UnknownReason::Traced,
        });
    }
    if scan
        .unknowns
        .iter()
        .any(|u| u.reason == UnknownReason::FsTypeMismatch)
    {
        tamper.push(TamperIndicator {
            id: String::new(),
            indicator: "fs-type-mismatch".to_string(),
            strength: TamperStrength::Strong,
            display: "fs-type-mismatch".to_string(),
        });
    }
    if scan
        .unknowns
        .iter()
        .any(|u| u.reason == UnknownReason::ProcSelfMismatch)
    {
        tamper.push(TamperIndicator {
            id: String::new(),
            indicator: "proc-self-mismatch".to_string(),
            strength: TamperStrength::Strong,
            display: "proc-self-mismatch".to_string(),
        });
    }
}

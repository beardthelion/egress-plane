//! The live entry point (KTD8, KTD18, KTD25).
//!
//! The first action of a probe run makes the process non-dumpable
//! (`PR_SET_DUMPABLE 0`), the second takes the startup descriptor
//! inventory; both happen inside the platform fact collection before
//! anything else is opened. The whole pipeline then runs on a worker
//! thread while the calling thread waits up to the `run-deadline-ms`
//! budget: on expiry the run is a tool error with nothing on stdout.

use std::time::Duration;

use egress_core::model::ToolError;

use crate::active::{self, Connector, Target};
use crate::data::Data;
use crate::engine;
use crate::facts::Facts;
use crate::model::{Mode, Report, Source};
use crate::reader::{LiveReader, Reader};
use crate::watchdog;

/// What one probe run was asked to do beyond the passive enumeration.
#[derive(Debug)]
pub struct Request {
    /// `Passive` sends nothing; `Active` runs the allowlist checks.
    pub mode: Mode,
    /// The caller nonce echoed into the report (KTD23).
    pub nonce: Option<String>,
    /// The parsed and validated allowlist; empty in passive mode.
    pub targets: Vec<Target>,
    /// Which report form to render.
    pub output: Output,
}

/// The report form the CLI prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// The escaped text report.
    Text,
    /// The schema-versioned JSON report.
    Json,
}

/// The rendered report and the exit code its completeness earns.
#[derive(Debug)]
pub struct Rendered {
    pub output: String,
    pub exit_code: i32,
}

/// The platform fact collection (KTD8): the process is already
/// non-dumpable and the inventory complete when this returns.
#[cfg(target_os = "linux")]
fn platform_facts() -> Result<Facts, ToolError> {
    Ok(crate::facts::linux::collect())
}

/// The macOS platform fact collection (KTD8, KTD17).
#[cfg(target_os = "macos")]
fn platform_facts() -> Result<Facts, ToolError> {
    Ok(crate::facts::macos::collect())
}

/// The live entry exists on Linux and macOS.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_facts() -> Result<Facts, ToolError> {
    Err(ToolError::Internal(
        "the live probe is implemented on Linux and macOS",
    ))
}

/// The live probe entry: facts first (non-dumpable, descriptor
/// inventory), then the pipeline on a worker thread under the KTD18 run
/// deadline.
pub fn run(request: Request) -> Result<Rendered, ToolError> {
    // First actions of the probe path: non-dumpable, then the
    // descriptor inventory (both inside `platform_facts`).
    let facts = platform_facts()?;
    let data = Data::embedded().map_err(|_| ToolError::Internal("probe data failed to load"))?;
    let reader = LiveReader::live(facts)?;
    let deadline = Duration::from_millis(data.budgets.run_deadline_ms);
    watchdog::call(deadline, move || {
        let mut reader = reader;
        run_with(&mut reader, &data, Source::Live, &request, &mut active::Tcp)
    })
}

/// Runs the full pipeline over `reader` and renders the report: the
/// engine (universes, classification, signals, layers, tamper,
/// completeness), then the active checks when the mode asks for them
/// (they never change the completeness state), the nonce, and the
/// render under the report byte budget.
pub fn run_with<R: Reader>(
    reader: &mut R,
    data: &Data,
    source: Source,
    request: &Request,
    connector: &mut impl Connector,
) -> Rendered {
    let mut report = engine::run(reader, data, source, request.mode);
    if request.mode == Mode::Active {
        report.active_checks = active::run_checks(
            &data.active,
            &request.targets,
            connector,
            Duration::from_millis(data.budgets.connect_timeout_ms),
        );
    }
    report.nonce = request.nonce.clone();
    render(&report, data, request.output)
}

/// Renders `report` in the asked format and derives the exit code from
/// the completeness the emitted report carries (the JSON render's
/// budget replacement can add an unknown, so it decides the state).
fn render(report: &Report, data: &Data, output: Output) -> Rendered {
    match output {
        Output::Text => Rendered {
            exit_code: report.exit_code(),
            output: crate::text::render(report),
        },
        Output::Json => {
            let (output, state) =
                crate::json::to_json_bounded_state(report, data.budgets.report_bytes);
            Rendered {
                exit_code: state.exit_code(),
                output,
            }
        }
    }
}

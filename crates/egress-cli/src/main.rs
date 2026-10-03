//! `egress-plane scan <root> [--format text|json]`.
//!
//! Prints the text report (the default) or the JSON report on stdout and
//! exits with the code assigned to the completeness state: 0
//! complete, 2 incomplete, 3 empty. A tool error, including a usage error,
//! writes one line to stderr, nothing to stdout, and exits 1. The binary
//! spawns no subprocess, opens no network connection, and reads no
//! environment variable.

mod text_report;

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use egress_core::discover::guard;
use egress_core::json::to_json;
use egress_core::model::EXIT_TOOL_ERROR;

const USAGE: &str = "usage: egress-plane scan <root> [--format text|json]";

#[derive(Clone, Copy)]
enum Format {
    Text,
    Json,
}

enum Command {
    Help,
    Version,
    Scan { root: PathBuf, format: Format },
}

fn parse_format(v: &OsString) -> Result<Format, String> {
    match v.to_str() {
        Some("text") => Ok(Format::Text),
        Some("json") => Ok(Format::Json),
        _ => Err("--format must be text or json".into()),
    }
}

fn parse(args: Vec<OsString>) -> Result<Command, String> {
    let mut it = args.into_iter();
    match it.next().as_ref().and_then(|a| a.to_str()) {
        Some("scan") => {}
        Some("-h" | "--help" | "help") => return Ok(Command::Help),
        Some("-V" | "--version") => return Ok(Command::Version),
        Some(_) => return Err("unknown command".into()),
        None => return Err("missing command".into()),
    }
    let mut root = None;
    let mut format = Format::Text;
    let mut only_paths = false;
    while let Some(a) = it.next() {
        let s = a.to_str();
        if only_paths || !s.is_some_and(|s| s.starts_with('-')) {
            if root.is_some() {
                return Err("more than one scan root".into());
            }
            root = Some(PathBuf::from(a));
            continue;
        }
        match s {
            Some("--") => only_paths = true,
            Some("--format") => {
                let v = it.next().ok_or("--format needs a value")?;
                format = parse_format(&v)?;
            }
            Some(s) if s.starts_with("--format=") => {
                format = parse_format(&OsString::from(&s["--format=".len()..]))?;
            }
            _ => return Err("unknown option".into()),
        }
    }
    let root = root.ok_or("missing scan root")?;
    Ok(Command::Scan { root, format })
}

fn fail(message: &str) -> ExitCode {
    // Fixed text only: no scanned-input string or host value reaches stderr.
    let _ = writeln!(std::io::stderr().lock(), "egress-plane: {message}");
    ExitCode::from(EXIT_TOOL_ERROR as u8)
}

fn print(out: &str) -> Result<(), ()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(out.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|_| ())
}

fn main() -> ExitCode {
    let (root, format) = match parse(std::env::args_os().skip(1).collect()) {
        Ok(Command::Scan { root, format }) => (root, format),
        Ok(Command::Help) => {
            return match print(&format!("{USAGE}\n")) {
                Ok(()) => ExitCode::SUCCESS,
                Err(()) => fail("cannot write to stdout"),
            };
        }
        Ok(Command::Version) => {
            return match print(&format!("egress-plane {}\n", env!("CARGO_PKG_VERSION"))) {
                Ok(()) => ExitCode::SUCCESS,
                Err(()) => fail("cannot write to stdout"),
            };
        }
        Err(e) => return fail(&format!("{e}\n{USAGE}")),
    };
    // A panic outside the per-file guards is a tool error; `guard` keeps its
    // payload, which may quote scanned input, off stderr.
    let report = match guard(|| egress_scan::scan(&root)) {
        Some(Ok(r)) => r,
        Some(Err(e)) => return fail(&format!("error: {e}")),
        None => return fail("error: internal failure"),
    };
    let rendered = match format {
        Format::Text => guard(|| text_report::render(&report)),
        Format::Json => guard(|| to_json(&report)),
    };
    let Some(rendered) = rendered else {
        return fail("error: internal failure");
    };
    match print(&rendered) {
        Ok(()) => ExitCode::from(report.exit_code() as u8),
        Err(()) => fail("error: cannot write to stdout"),
    }
}

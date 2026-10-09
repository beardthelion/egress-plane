//! `egress-plane scan <root> [--format text|json] [--deps <path>]...` and
//! `egress-plane probe [--format text|json] [--nonce HEX]
//! [--active --allow IP:PORT ...]`.
//!
//! Prints the text report (the default) or the JSON report on stdout and
//! exits with the code assigned to the completeness state: 0
//! complete, 2 incomplete, 3 empty. A tool error, including a usage error,
//! writes one line to stderr, nothing to stdout, and exits 1.
//!
//! The binary spawns no subprocess. `scan` and a passive `probe` open no
//! network connection; `probe --active` opens bounded TCP connects to
//! the allowlisted destinations only (KTD20, KTD21). `scan` reads no
//! environment variable; `probe` enumerates environment variable names,
//! never values.

mod text_report;

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use egress_core::discover::guard;
use egress_core::json::to_json;
use egress_core::model::EXIT_TOOL_ERROR;

const USAGE: &str = "usage: egress-plane scan <root> [--format text|json] [--deps <path>]...\n       egress-plane probe [--format text|json] [--nonce HEX] [--active --allow IP:PORT ...]";

#[derive(Clone, Copy)]
enum Format {
    Text,
    Json,
}

enum Command {
    Help,
    Version,
    Scan {
        root: PathBuf,
        format: Format,
        deps: Vec<PathBuf>,
    },
    Probe {
        format: Format,
        nonce: Option<String>,
        allow: Vec<String>,
    },
}

fn parse_format(v: &OsString) -> Result<Format, String> {
    match v.to_str() {
        Some("text") => Ok(Format::Text),
        Some("json") => Ok(Format::Json),
        _ => Err("--format must be text or json".into()),
    }
}

/// The value of an option that takes text, or the fixed usage error.
fn text_arg(it: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String, String> {
    it.next()
        .ok_or_else(|| format!("{name} needs a value"))?
        .into_string()
        .map_err(|_| format!("{name} needs a text value"))
}

fn parse(args: Vec<OsString>) -> Result<Command, String> {
    let mut it = args.into_iter();
    match it.next().as_ref().and_then(|a| a.to_str()) {
        Some("scan") => parse_scan(it),
        Some("probe") => parse_probe(it),
        Some("-h" | "--help" | "help") => Ok(Command::Help),
        Some("-V" | "--version") => Ok(Command::Version),
        Some(_) => Err("unknown command".into()),
        None => Err("missing command".into()),
    }
}

fn parse_scan(mut it: std::vec::IntoIter<OsString>) -> Result<Command, String> {
    let mut root = None;
    let mut format = Format::Text;
    let mut deps = Vec::new();
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
            // A `--deps` value is a path, so it is taken raw, not through
            // `text_arg`: non-UTF-8 paths are accepted.
            Some("--deps") => {
                deps.push(PathBuf::from(it.next().ok_or("--deps needs a value")?));
            }
            Some(s) if s.starts_with("--deps=") => {
                deps.push(PathBuf::from(&s["--deps=".len()..]));
            }
            _ => return Err("unknown option".into()),
        }
    }
    let root = root.ok_or("missing scan root")?;
    Ok(Command::Scan { root, format, deps })
}

/// `probe` takes no positional argument. `--active` and `--allow` require
/// each other; `--nonce` is 1 to 64 lowercase hex characters; usage
/// errors carry fixed text only.
fn parse_probe(mut it: std::vec::IntoIter<OsString>) -> Result<Command, String> {
    let mut format = Format::Text;
    let mut nonce = None;
    let mut active = false;
    let mut allow = Vec::new();
    while let Some(a) = it.next() {
        let Some(s) = a.to_str() else {
            return Err("unknown option".into());
        };
        match s {
            "--format" => {
                let v = it.next().ok_or("--format needs a value")?;
                format = parse_format(&v)?;
            }
            "--nonce" => nonce = Some(text_arg(&mut it, "--nonce")?),
            "--active" => active = true,
            "--allow" => allow.push(text_arg(&mut it, "--allow")?),
            s if s.starts_with("--format=") => {
                format = parse_format(&OsString::from(&s["--format=".len()..]))?;
            }
            s if s.starts_with("--nonce=") => {
                nonce = Some(s["--nonce=".len()..].to_string());
            }
            s if s.starts_with("--allow=") => {
                allow.push(s["--allow=".len()..].to_string());
            }
            _ if s.starts_with('-') => return Err("unknown option".into()),
            _ => return Err("probe takes no path argument".into()),
        }
    }
    if let Some(n) = &nonce {
        let ok = (1..=64).contains(&n.len())
            && n.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err("--nonce must be 1 to 64 lowercase hex characters".into());
        }
    }
    if active && allow.is_empty() {
        return Err("--active needs at least one --allow".into());
    }
    if !active && !allow.is_empty() {
        return Err("--allow needs --active".into());
    }
    Ok(Command::Probe {
        format,
        nonce,
        allow,
    })
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

fn scan(root: PathBuf, format: Format, deps: Vec<PathBuf>) -> ExitCode {
    // A panic outside the per-file guards is a tool error; `guard` keeps its
    // payload, which may quote scanned input, off stderr.
    let report = match guard(|| {
        egress_scan::scan_with(
            &root,
            &egress_scan::ScanOptions {
                dependency_roots: deps,
                ..egress_scan::ScanOptions::default()
            },
        )
        .map(|o| o.report)
    }) {
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

fn probe(format: Format, nonce: Option<String>, allow: Vec<String>) -> ExitCode {
    use egress_probe::live::{Output, Request};
    use egress_probe::model::Mode;

    let data = match egress_probe::data::Data::embedded() {
        Ok(d) => d,
        Err(_) => return fail("error: internal failure"),
    };
    let targets = if allow.is_empty() {
        Ok(Vec::new())
    } else {
        egress_probe::active::parse_allowlist(&allow, data.budgets.active_targets)
    };
    let targets = match targets {
        Ok(t) => t,
        Err(msg) => return fail(&format!("{msg}\n{USAGE}")),
    };
    // The live entry's first action makes the process non-dumpable and
    // the second takes the descriptor inventory; the scan then runs on
    // a worker thread under the run deadline (KTD8, KTD18, KTD25). On
    // expiry the tool error prints a fixed stderr line and nothing
    // reaches stdout.
    let rendered = match guard(|| {
        egress_probe::live::run(Request {
            mode: if targets.is_empty() {
                Mode::Passive
            } else {
                Mode::Active
            },
            nonce,
            targets,
            output: match format {
                Format::Text => Output::Text,
                Format::Json => Output::Json,
            },
        })
    }) {
        Some(Ok(r)) => r,
        Some(Err(e)) => return fail(&format!("error: {e}")),
        None => return fail("error: internal failure"),
    };
    match print(&rendered.output) {
        Ok(()) => ExitCode::from(rendered.exit_code as u8),
        Err(()) => fail("error: cannot write to stdout"),
    }
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1).collect()) {
        Ok(Command::Scan { root, format, deps }) => scan(root, format, deps),
        Ok(Command::Probe {
            format,
            nonce,
            allow,
        }) => probe(format, nonce, allow),
        Ok(Command::Help) => match print(&format!("{USAGE}\n")) {
            Ok(()) => ExitCode::SUCCESS,
            Err(()) => fail("cannot write to stdout"),
        },
        Ok(Command::Version) => {
            match print(&format!("egress-plane {}\n", env!("CARGO_PKG_VERSION"))) {
                Ok(()) => ExitCode::SUCCESS,
                Err(()) => fail("cannot write to stdout"),
            }
        }
        Err(e) => fail(&format!("{e}\n{USAGE}")),
    }
}

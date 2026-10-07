//! The `resolvers` universe: `/etc/resolv.conf` on Linux, `/etc/resolver/`
//! plus the stub on macOS. Members are directive and value pairs;
//! unrecognized lines are counted, never echoed (R17, KTD3).

use super::{Outcome, bfield, check_members, denial_reason, ifield, member, tfield};
use crate::data::Budgets;
use crate::model::{Member, UnknownReason};
use crate::reader::{Denial, Reader};

/// Enumerates `linux.resolvers`: a missing `etc/resolv.conf` (or a
/// dangling allowlisted hop) is the declared absent signature.
pub fn enumerate_linux(r: &mut impl Reader, budgets: &Budgets) -> Result<Outcome, UnknownReason> {
    match r.read(b"etc/resolv.conf", budgets.bytes_per_file) {
        Ok(bytes) => {
            let members = parse(&bytes)?;
            check_members(&members, budgets)?;
            Ok(Outcome::Enumerated(members))
        }
        Err(Denial::Absent) => Ok(Outcome::Absent),
        Err(d) => Err(denial_reason(d)),
    }
}

/// One directive's result, or the count for a line the grammar does not
/// recognize.
enum Line {
    Member { directive: String, value: String },
    Unrecognized,
}

/// Parses resolv.conf text. `nameserver` values are IP literals,
/// `search` and `domain` values hostname characters, `options` tokens
/// `[a-z0-9:._-]`; a value that fails its check is `partial` (R17).
fn parse(bytes: &[u8]) -> Result<Vec<Member>, UnknownReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| UnknownReason::Partial)?;
    let mut members = Vec::new();
    let mut parsed: Vec<Line> = Vec::new();
    for line in text.lines() {
        // `#` and `;` start comments that run to the end of the line.
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(directive) = it.next() else { continue };
        let value = it.collect::<Vec<_>>().join(" ");
        let line_out = match directive {
            "nameserver" => {
                if value.parse::<std::net::IpAddr>().is_err() {
                    return Err(UnknownReason::Partial);
                }
                Line::Member {
                    directive: "nameserver".to_string(),
                    value,
                }
            }
            "search" | "domain" => {
                if value.split_whitespace().any(|t| !hostname_chars(t)) || value.is_empty() {
                    return Err(UnknownReason::Partial);
                }
                Line::Member {
                    directive: directive.to_string(),
                    value,
                }
            }
            "options" => {
                if value.split_whitespace().any(|t| !option_chars(t)) || value.is_empty() {
                    return Err(UnknownReason::Partial);
                }
                Line::Member {
                    directive: "options".to_string(),
                    value,
                }
            }
            _ => Line::Unrecognized,
        };
        parsed.push(line_out);
    }
    for (i, l) in parsed.iter().enumerate() {
        if let Line::Member { directive, value } = l {
            members.push(member(
                vec![
                    tfield("directive", directive, true),
                    bfield("value", value.as_bytes(), true),
                    ifield("line-order", i as u64),
                    ifield("unrecognized-count", unrecognized_total(&parsed)),
                ],
                format!("{directive} {value}"),
            ));
        }
    }
    Ok(members)
}

fn unrecognized_total(lines: &[Line]) -> u64 {
    lines
        .iter()
        .filter(|l| matches!(l, Line::Unrecognized))
        .count() as u64
}

fn hostname_chars(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn option_chars(t: &str) -> bool {
    !t.is_empty()
        && t.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'.' | b'_' | b'-')
        })
}

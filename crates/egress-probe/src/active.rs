//! Active-mode checks (KTD21, R4, R25, AE6, AE11).
//!
//! An allowlist entry parses as an IPv4 `a.b.c.d:port` or an IPv6
//! `[addr]:port` literal; anything else, a port of 0, a duplicate entry,
//! or more entries than the `active-targets` budget is a usage error and
//! sends nothing. Before the refused check, IPv4-mapped
//! (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), and NAT64
//! well-known-prefix (`64:ff9b::/96`) addresses are canonicalized to
//! IPv4, and the tunnel-embedded forms (6to4 `2002::/16`, Teredo
//! `2001::/32`, a ULA `fc00::/7` literal carrying an IPv4 address in its
//! low bits) are checked as IPv4 too, so no translated form of a refused
//! address is attempted.
//!
//! A destination the refused list of `data/probe/active.toml` covers is
//! recorded with its declared result (`refused-metadata-address` or
//! `refused-special-address`) and creates no socket. Every other target
//! gets one sequential non-blocking TCP connect bounded by the
//! `connect-timeout-ms` budget, closed at once, no payload. Results are
//! `connected`, `refused`, `timed-out`, `unreachable`, or
//! `error:<errno name>`; nothing records a timing value.
//!
//! This module is the only place the probe may name a socket entry
//! point; the KTD7 passive guard (`tests/passive_guard.rs`) enforces it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use crate::data::Refused;
use crate::model::ActiveCheck;

/// One parsed allowlist entry: the canonical connect target plus every
/// address form the refused check sees.
#[derive(Debug, Clone)]
pub struct Target {
    /// The `IP:port` a connector is asked to reach, after the KTD21
    /// canonicalization of mapped, compatible, and NAT64 forms.
    addr: SocketAddr,
    /// The canonical address plus every tunnel-embedded IPv4 form.
    refused_forms: Vec<IpAddr>,
}

impl Target {
    /// The canonical `IP:port` a connector is asked to reach.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Parses and validates an allowlist: every value is an `IP:port`
/// literal, no port is 0, no two entries canonicalize to the same
/// target, and the list fits the `active-targets` budget (KTD21). The
/// error is fixed text for the CLI's usage path.
pub fn parse_allowlist(values: &[String], limit: u64) -> Result<Vec<Target>, &'static str> {
    if values.len() as u64 > limit {
        return Err("too many --allow entries");
    }
    let mut targets = Vec::with_capacity(values.len());
    for v in values {
        let addr = parse_literal(v).ok_or("--allow value must be an IP:port literal")?;
        let target = canonicalize(addr);
        if targets.iter().any(|t: &Target| t.addr == target.addr) {
            return Err("duplicate --allow entry");
        }
        targets.push(target);
    }
    Ok(targets)
}

/// Parses one `a.b.c.d:port` or `[addr]:port` literal. A domain name is
/// not an IP literal and is never resolved (AE11); port 0 and anything
/// that is not all digits is refused here.
fn parse_literal(v: &str) -> Option<SocketAddr> {
    let (ip, port) = if let Some(rest) = v.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        (IpAddr::V6(Ipv6Addr::from_str(host).ok()?), port)
    } else {
        let (host, port) = v.split_once(':')?;
        (IpAddr::V4(Ipv4Addr::from_str(host).ok()?), port)
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

/// The NAT64 well-known prefix `64:ff9b::/96` (KTD21).
fn is_nat64(v6: &Ipv6Addr) -> bool {
    let seg = v6.segments();
    seg[..6] == [0x0064, 0xff9b, 0, 0, 0, 0]
}

fn v4_of(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8)
}

/// Canonicalizes a connect target per KTD21: an IPv4-mapped,
/// IPv4-compatible, or NAT64 address becomes its IPv4 form. Every other
/// target is unchanged, and its tunnel-embedded forms are still checked
/// against the refused list through [`Target::refused_forms`].
fn canonicalize(addr: SocketAddr) -> Target {
    let IpAddr::V6(v6) = addr.ip() else {
        return Target {
            addr,
            refused_forms: vec![addr.ip()],
        };
    };
    let seg = v6.segments();
    if let Some(v4) = v6.to_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(v4), addr.port());
        return Target {
            addr,
            refused_forms: vec![addr.ip()],
        };
    }
    if is_nat64(&v6) {
        let addr = SocketAddr::new(IpAddr::V4(v4_of(seg[6], seg[7])), addr.port());
        return Target {
            addr,
            refused_forms: vec![addr.ip()],
        };
    }
    let mut forms = vec![IpAddr::V6(v6)];
    // 6to4 (2002::/16) carries the IPv4 site address in bits 16..48,
    // Teredo (2001::/32) carries its server IPv4 in bits 32..64, and a
    // ULA (fc00::/7) literal may carry an IPv4 address in its low bits.
    if seg[0] == 0x2002 {
        forms.push(IpAddr::V4(v4_of(seg[1], seg[2])));
    }
    if seg[0] == 0x2001 && seg[1] == 0 {
        forms.push(IpAddr::V4(v4_of(seg[2], seg[3])));
    }
    if seg[0] & 0xfe00 == 0xfc00 {
        forms.push(IpAddr::V4(v4_of(seg[6], seg[7])));
    }
    Target {
        addr,
        refused_forms: forms,
    }
}

/// Whether `ip` falls in the refused entry `value` (an IP literal or an
/// `addr/prefix` range, already validated by the data loader).
fn refused_matches(ip: &IpAddr, value: &str) -> bool {
    let (base, bits) = match value.split_once('/') {
        None => match IpAddr::from_str(value) {
            Ok(base) => (base, if base.is_ipv4() { 32 } else { 128 }),
            Err(_) => return false,
        },
        Some((a, p)) => match (IpAddr::from_str(a), p.parse::<u32>()) {
            (Ok(base), Ok(bits)) => (base, bits),
            _ => return false,
        },
    };
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) => {
            bits == 0 || (ip.to_bits() ^ base.to_bits()) >> (32 - bits.min(32)) == 0
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) => {
            bits == 0 || (ip.to_bits() ^ base.to_bits()) >> (128 - bits.min(128)) == 0
        }
        _ => false,
    }
}

/// What one bounded connect observed. Carries no timing value (KTD21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The connect completed.
    Connected,
    /// The destination actively refused.
    Refused,
    /// The bound expired with no answer.
    TimedOut,
    /// No route to the destination.
    Unreachable,
    /// Any other failure, as the raw errno.
    Error(i32),
}

impl ConnectOutcome {
    /// The `result` string the check records.
    fn result(&self) -> String {
        match self {
            Self::Connected => "connected".to_string(),
            Self::Refused => "refused".to_string(),
            Self::TimedOut => "timed-out".to_string(),
            Self::Unreachable => "unreachable".to_string(),
            Self::Error(e) => format!("error:{}", errno_name(*e)),
        }
    }
}

/// The errno name for `error:<errno name>` results.
fn errno_name(e: i32) -> String {
    let name = match e {
        libc::EACCES => "EACCES",
        libc::EADDRINUSE => "EADDRINUSE",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EAGAIN => "EAGAIN",
        libc::EALREADY => "EALREADY",
        libc::EBADF => "EBADF",
        libc::ECONNABORTED => "ECONNABORTED",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::ECONNRESET => "ECONNRESET",
        libc::EFAULT => "EFAULT",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        libc::EINPROGRESS => "EINPROGRESS",
        libc::EINTR => "EINTR",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::EISCONN => "EISCONN",
        libc::ENETDOWN => "ENETDOWN",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::ENOBUFS => "ENOBUFS",
        libc::ENOMEM => "ENOMEM",
        libc::ENOTCONN => "ENOTCONN",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::EPERM => "EPERM",
        libc::EPROTOTYPE => "EPROTOTYPE",
        libc::ETIMEDOUT => "ETIMEDOUT",
        _ => return format!("errno-{e}"),
    };
    name.to_string()
}

/// The bounded-connect seam: the live run uses [`Tcp`]; tests inject a
/// fake and count its calls (a refused destination must create no
/// socket, so the connector sees nothing).
pub trait Connector {
    /// One bounded connect attempt to `addr`.
    fn connect(&mut self, addr: &SocketAddr, timeout: Duration) -> ConnectOutcome;
}

/// The real connector: `TcpStream::connect_timeout`, a non-blocking TCP
/// connect bounded by `timeout`, closed at once, no payload (KTD21).
pub struct Tcp;

impl Connector for Tcp {
    fn connect(&mut self, addr: &SocketAddr, timeout: Duration) -> ConnectOutcome {
        match std::net::TcpStream::connect_timeout(addr, timeout) {
            Ok(_) => ConnectOutcome::Connected,
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused => ConnectOutcome::Refused,
                std::io::ErrorKind::TimedOut => ConnectOutcome::TimedOut,
                _ => match e.raw_os_error() {
                    Some(e)
                        if e == libc::ENETUNREACH
                            || e == libc::EHOSTUNREACH
                            || e == libc::ENETDOWN =>
                    {
                        ConnectOutcome::Unreachable
                    }
                    Some(e) => ConnectOutcome::Error(e),
                    None => ConnectOutcome::Error(0),
                },
            },
        }
    }
}

/// Runs the checks of one allowlist, sequentially in sorted canonical
/// address order (KTD21): refused entries record their declared result
/// and reach no connector, the rest get one bounded connect each.
pub fn run_checks(
    refused: &[Refused],
    targets: &[Target],
    connector: &mut impl Connector,
    timeout: Duration,
) -> Vec<ActiveCheck> {
    let mut sorted: Vec<&Target> = targets.iter().collect();
    sorted.sort_by_key(|t| t.addr);
    sorted
        .into_iter()
        .map(|t| {
            let refused = t.refused_forms.iter().find_map(|ip| {
                refused
                    .iter()
                    .find(|r| refused_matches(ip, &r.value))
                    .map(|r| r.result)
            });
            let result = match refused {
                Some(r) => r.as_str().to_string(),
                None => connector.connect(&t.addr, timeout).result(),
            };
            ActiveCheck {
                id: String::new(),
                target: t.addr.to_string(),
                result,
            }
        })
        .collect()
}

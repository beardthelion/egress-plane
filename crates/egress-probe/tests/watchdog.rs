//! The KTD18 run deadline: a run that blocks past the deadline returns
//! the deadline tool error and renders nothing; a run inside it is
//! unaffected.

use std::time::{Duration, Instant};

use egress_core::model::ToolError;
use egress_probe::active;
use egress_probe::data::Data;
use egress_probe::facts::Facts;
use egress_probe::live::{self, Output, Request};
use egress_probe::model::{Mode, Source};
use egress_probe::reader::{AccessMask, AccessResult, Denial, Meta, Mount, ReadLogEntry, Reader};
use egress_probe::watchdog;

/// A reader whose `read` never returns; every other call is absent.
struct BlockReader {
    facts: Facts,
    log: Vec<ReadLogEntry>,
    block: bool,
}

impl Reader for BlockReader {
    fn read(&mut self, _path: &[u8], _limit: u64) -> Result<Vec<u8>, Denial> {
        if self.block {
            loop {
                std::thread::park();
            }
        }
        Err(Denial::Absent)
    }
    fn list(&mut self, _path: &[u8]) -> Result<Vec<(Vec<u8>, Meta)>, Denial> {
        Err(Denial::Absent)
    }
    fn metadata(&mut self, _path: &[u8]) -> Result<Meta, Denial> {
        Err(Denial::Absent)
    }
    fn access(&mut self, _path: &[u8], _mask: AccessMask) -> Result<AccessResult, Denial> {
        Err(Denial::Absent)
    }
    fn readlink(&mut self, _path: &[u8]) -> Result<Vec<u8>, Denial> {
        Err(Denial::Absent)
    }
    fn signal_metadata(&mut self, path: &[u8]) -> Result<Meta, Denial> {
        self.metadata(path)
    }
    fn signal_access(&mut self, path: &[u8], mask: AccessMask) -> Result<AccessResult, Denial> {
        self.access(path, mask)
    }
    fn facts(&self) -> &Facts {
        &self.facts
    }
    fn read_log(&self) -> &[ReadLogEntry] {
        &self.log
    }
    fn arm_mounts(&mut self, _mounts: Vec<Mount>) {}
    fn mounts_unknown(&mut self) {}
    fn accepted_ancestor_pidns(&self) -> bool {
        false
    }
}

fn request() -> Request {
    Request {
        mode: Mode::Passive,
        nonce: None,
        targets: Vec::new(),
        output: Output::Text,
    }
}

#[test]
fn a_blocked_run_returns_the_deadline_tool_error_and_renders_nothing() {
    // The engine's first read (mountinfo) never returns, so the 100 ms
    // deadline is what ends the wait.
    let data = Data::embedded().unwrap();
    let reader = BlockReader {
        facts: Facts::default(),
        log: Vec::new(),
        block: true,
    };
    let start = Instant::now();
    let out = watchdog::call(Duration::from_millis(100), move || {
        let mut reader = reader;
        live::run_with(
            &mut reader,
            &data,
            Source::Live,
            &request(),
            &mut active::Tcp,
        )
    });
    assert!(
        matches!(out, Err(ToolError::Internal(_))),
        "expected the deadline tool error"
    );
    // The deadline decided the return, far short of any run duration.
    assert!(start.elapsed() < Duration::from_secs(30));
    // Nothing was produced: there is no report to render, and stdout
    // would carry nothing.
}

#[test]
fn a_run_inside_the_deadline_returns_its_output() {
    let data = Data::embedded().unwrap();
    let reader = BlockReader {
        facts: Facts::default(),
        log: Vec::new(),
        block: false,
    };
    let out = watchdog::call(Duration::from_secs(30), move || {
        let mut reader = reader;
        live::run_with(
            &mut reader,
            &data,
            Source::Live,
            &request(),
            &mut active::Tcp,
        )
    })
    .expect("a fast run is unaffected by the deadline");
    assert!(!out.output.is_empty());
}

#[test]
fn a_panicking_run_is_an_internal_failure_not_a_deadline() {
    let out = watchdog::call(Duration::from_secs(30), || -> u32 {
        panic!("worker exploded")
    });
    assert!(matches!(out, Err(ToolError::Internal(_))));
}

#[test]
fn a_fast_return_needs_no_run_at_all() {
    let out = watchdog::call(Duration::from_secs(5), || 40 + 2);
    assert_eq!(out.unwrap(), 42);
}

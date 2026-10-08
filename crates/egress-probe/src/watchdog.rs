//! The run deadline (KTD18).
//!
//! Counts decide every passive outcome; the deadline is the one
//! wall-clock rule. A read on a network or user-space filesystem can
//! block a thread forever and no per-call timeout interrupts it, so the
//! whole scan runs on a worker thread and the calling thread waits. On
//! expiry the run is a tool error and nothing the worker produced is
//! returned, so no partial report can render.

use std::sync::mpsc;
use std::time::Duration;

use egress_core::discover::guard;
use egress_core::model::ToolError;

/// Runs `work` on a worker thread and waits up to `deadline` for it.
/// A finish inside the deadline returns the value; expiry is the
/// deadline tool error; a worker that panicked or died before sending
/// is an internal failure (the panic itself is caught by [`guard`], so
/// its payload, which may quote environment data, never reaches
/// stderr). A still-blocked worker is abandoned; the process exits on
/// the tool-error path.
pub fn call<T>(
    deadline: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ToolError>
where
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("egress-probe-run".into())
        .stack_size(egress_core::discover::WORKER_STACK_BYTES)
        .spawn(move || {
            // A panic inside `guard` yields `None`; either way `tx` is
            // dropped, which the caller reads as disconnected.
            let _ = tx.send(guard(work));
        })
        .map_err(|_| ToolError::Internal("could not start the probe worker"))?;
    match rx.recv_timeout(deadline) {
        Ok(Some(v)) => Ok(v),
        Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(ToolError::Internal("the probe run failed"))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Err(ToolError::Internal("the probe run deadline expired"))
        }
    }
}

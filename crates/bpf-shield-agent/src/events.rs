//! Ring-buffer consumer.
//!
//! # The backpressure story
//!
//! The kernel never blocks on this pipeline. `bpf_ringbuf_reserve` returns
//! NULL when the buffer is full, the probe counts a drop and returns. So the
//! *only* place backpressure can accumulate is in this process, and it is
//! bounded by the `mpsc` channel below: when it is full, events are dropped
//! and counted rather than queued without limit.
//!
//! Dropping telemetry is strictly preferable to growing an unbounded queue in
//! an agent whose whole job is to stay out of the way of the host.
//!
//! # Waking up
//!
//! `poll_next` + `AsyncFd` is the cheapest correct option: one epoll
//! registration, no threads, and the kernel's "consumer is behind" busy bit
//! does the deduplication for us. A polling loop would burn a core; a dedicated
//! thread per buffer would not scale to multiple buffers.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use aya::maps::RingBuf;
use bpf_shield_common::Event;
use tokio::{
    io::unix::AsyncFd,
    sync::mpsc,
    task,
};
use tracing::{debug, error, warn};

/// Counters the consumer maintains about its own behaviour.
#[derive(Debug, Default)]
pub struct ConsumerStats {
    pub received: AtomicU64,
    pub channel_drops: AtomicU64,
    pub decode_errors: AtomicU64,
}

/// A decoded event, with the string fields already lossily rendered.
#[derive(Clone, Debug)]
pub struct DecodedEvent {
    pub raw: Event,
    pub target: String,
    pub comm: String,
}

/// Spawn the consumer task.
///
/// `ring_buf` is moved in: its consumer cursor lives in the mmap, so it cannot
/// be shared with another reader.
pub fn spawn(
    ring_buf: RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<DecodedEvent>,
    stats: Arc<ConsumerStats>,
) -> tokio::task::JoinHandle<()> {
    task::spawn(async move {
        use std::os::fd::AsRawFd;

        let mut afd = match AsyncFd::new(ring_buf) {
            Ok(afd) => afd,
            Err(e) => {
                error!(error = %e, "cannot register ring buffer with the event loop");
                return;
            }
        };

        loop {
            // Wait for the kernel to tell us there is data. `readable_mut` is
            // required because draining advances the consumer cursor.
            let mut guard = match afd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    warn!(error = %e, "ring buffer readiness error, stopping consumer");
                    return;
                }
            };

            // Drain everything currently available, then re-arm. `try_io_with`
            // returns `Err(_)` if the fd was not actually ready, in which case
            // we simply loop and wait again.
            let drained = guard.try_io_with(|inner| {
                let mut n = 0usize;
                let ring = inner.get_mut();
                while let Some(item) = ring.next() {
                    n += 1;

                    let Some(event) = decode(item) else {
                        stats.decode_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    stats.received.fetch_add(1, Ordering::Relaxed);

                    // `try_send` is deliberate: `send().await` would let one
                    // slow sink stall the drain loop, which in turn stalls the
                    // ring buffer, which in turn starts dropping kernel events.
                    if tx.try_send(event).is_err() {
                        stats.channel_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Some(n)
            });

            match drained {
                Ok(Some(0)) => debug!("ring buffer woke with no events"),
                Ok(Some(n)) => debug!(events = n, "drained events"),
                Ok(None) => {}
                Err(_would_block) => {}
            }
            // `guard` drops here, clearing readiness.
        }
    })
}

/// Decode a borrowed ring-buffer record into an [`Event`].
///
/// # Why the length check is mandatory
///
/// `RingBufItem` is a `&[u8]` whose length the kernel guarantees to be a whole
/// number of records, but it is *shared memory*. We validate the length before
/// transmuting; a short record would otherwise be read past its end.
fn decode(item: &[u8]) -> Option<DecodedEvent> {
    const NEED: usize = std::mem::size_of::<Event>();

    if item.len() < NEED {
        return None;
    }

    // SAFETY: `Event` is `#[repr(C)]`, `Copy`, and padding-free (asserted in
    // `bpf-shield-common`); the kernel wrote exactly `size_of::<Event>()` bytes
    // for this record and we verified the length above. The `read_unaligned`
    // is needed because the kernel only guarantees 8-byte alignment for
    // ring-buffer records, not `align_of::<Event>()`.
    let raw: Event = unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<Event>()) };

    let target = String::from_utf8_lossy(raw.target_bytes()).into_owned();
    let comm = String::from_utf8_lossy(raw.comm_bytes()).into_owned();

    Some(DecodedEvent { raw, target, comm })
}

/// Sink that writes NDJSON to stdout, one object per line.
pub async fn run_stdout_sink(mut rx: mpsc::Receiver<DecodedEvent>) {
    use std::io::Write;

    while let Some(ev) = rx.recv().await {
        let line = serde_json::json!({
            "ts_ns": ev.raw.ts_ns,
            "hook": ev.raw.hook,
            "action": ev.raw.action,
            "rule_id": ev.raw.rule_id,
            "errno": ev.raw.errno,
            "pid": ev.raw.pid,
            "tgid": ev.raw.tgid,
            "uid": ev.raw.uid,
            "gid": ev.raw.gid,
            "cpu": ev.raw.cpu,
            "comm": ev.comm,
            "target": ev.target,
        });

        // A closed stdout (agent run without a journal) must not kill the task.
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{line}").is_err() || out.flush().is_err() {
            return;
        }
    }
}

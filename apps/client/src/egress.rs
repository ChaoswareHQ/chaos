//! Off-thread shipping: the collection loop never waits on the network.
//!
//! # The flaw this exists to remove
//!
//! `IngestSink` submits over HTTP the moment a batch fills. That submit used to
//! run on the thread draining ETW, so a slow or unreachable server stalled
//! collection, the kernel buffers filled behind it, and the sensor dropped
//! events because its *downstream* was busy. A collector that can be stopped by
//! its own egress is not a collector.
//!
//! So the sink moves to a writer thread and the loop only hands it batches
//! through a bounded queue. This module is that queue.
//!
//! # Why a full queue drops instead of waiting
//!
//! When the queue is full the batch is **dropped and counted**, never waited on.
//! Losing a batch under overload is a smaller failure than going blind, and the
//! counter is what keeps the loss honest rather than invisible — the same
//! accounting A3 asks for at the sensor boundary. A block here would put the
//! network back on the collection path, which is the thing being fixed.
//!
//! The queue is deliberately shallow: memory held for a server that is not
//! answering is memory the sensor is not using, and a deep queue only delays the
//! moment the drop counter starts moving.

use crossbeam_channel::{Sender, TrySendError, bounded};
use model::{Alert, TelemetryEvent};
use ports::EventSink;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use transport::IngestSink;

/// Batches the queue holds before it starts dropping.
const QUEUE_DEPTH: usize = 8;

/// One batch for the writer: the events, and the alerts that belong with them so
/// the server can take both in one request.
pub struct Batch {
    pub events: Vec<TelemetryEvent>,
    pub alerts: Vec<Alert>,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.alerts.is_empty()
    }
}

/// What became of a batch the loop handed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// On the queue.
    Queued,
    /// Nothing to send.
    Empty,
    /// The queue was full, so this batch was dropped and counted.
    Dropped,
    /// The writer has stopped. Nothing more will be delivered.
    Closed,
}

/// Counters readable while the writer runs.
#[derive(Debug, Default)]
pub struct EgressStats {
    /// Events handed over and not yet delivered.
    queued_events: AtomicU64,
    /// Events the server accepted, as the sink counts them.
    shipped: AtomicU64,
    /// Batches whose submission failed.
    failed: AtomicU64,
    /// Batches dropped because the queue was full.
    dropped_batches: AtomicU64,
    /// Events in those dropped batches.
    dropped_events: AtomicU64,
}

impl EgressStats {
    pub fn queued_events(&self) -> u64 {
        self.queued_events.load(Ordering::Relaxed)
    }

    pub fn shipped(&self) -> u64 {
        self.shipped.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    pub fn dropped_batches(&self) -> u64 {
        self.dropped_batches.load(Ordering::Relaxed)
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

/// What the writer had done by the time it stopped.
#[derive(Debug, Clone)]
pub struct EgressReport {
    pub host_id: String,
    /// Events the server accepted.
    pub shipped: u64,
    /// Batches whose submission failed.
    pub failed: u64,
    /// Batches dropped because the queue was full.
    pub dropped_batches: u64,
    /// Events in those dropped batches.
    pub dropped_events: u64,
    pub last_error: Option<String>,
}

/// The queue and the thread behind it.
pub struct Egress {
    tx: Option<Sender<Batch>>,
    writer: Option<JoinHandle<()>>,
    stats: Arc<EgressStats>,
    last_error: Arc<Mutex<Option<String>>>,
    host_id: String,
}

impl Egress {
    /// Move a sink onto its own thread.
    pub fn spawn(mut sink: IngestSink) -> Self {
        let host_id = sink.host_id().to_string();
        let (tx, rx) = bounded::<Batch>(QUEUE_DEPTH);
        let stats = Arc::new(EgressStats::default());
        let last_error = Arc::new(Mutex::new(None));

        let thread_stats = Arc::clone(&stats);
        let thread_error = Arc::clone(&last_error);
        let writer = thread::Builder::new()
            .name("chaos-egress".to_string())
            .spawn(move || {
                while let Ok(batch) = rx.recv() {
                    let queued = batch.events.len() as u64;
                    deliver(&mut sink, batch);
                    mirror(&sink, &thread_stats, &thread_error);
                    thread_stats
                        .queued_events
                        .fetch_sub(queued, Ordering::Relaxed);
                }
                // Every sender is gone: one last submit for whatever the sink
                // still holds, so a clean shutdown does not lose the tail.
                let _ = sink.flush();
                mirror(&sink, &thread_stats, &thread_error);
            })
            .expect("the egress thread spawns");

        Self {
            tx: Some(tx),
            writer: Some(writer),
            stats,
            last_error,
            host_id,
        }
    }

    /// Hand a batch to the writer. Never blocks.
    pub fn send(&self, batch: Batch) -> SendOutcome {
        if batch.is_empty() {
            return SendOutcome::Empty;
        }
        let events = batch.events.len() as u64;
        let Some(tx) = self.tx.as_ref() else {
            return SendOutcome::Closed;
        };

        match tx.try_send(batch) {
            Ok(()) => {
                self.stats
                    .queued_events
                    .fetch_add(events, Ordering::Relaxed);
                SendOutcome::Queued
            }
            Err(TrySendError::Full(_)) => {
                self.stats.dropped_batches.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .dropped_events
                    .fetch_add(events, Ordering::Relaxed);
                SendOutcome::Dropped
            }
            Err(TrySendError::Disconnected(_)) => SendOutcome::Closed,
        }
    }

    /// Live counters, for a run that never ends.
    pub fn stats(&self) -> &EgressStats {
        &self.stats
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|slot| slot.clone())
    }

    /// Stop the writer, drain what it holds, and report what it did.
    ///
    /// Dropping the sender is what ends the loop: the writer finishes the queue
    /// and submits the tail before the join returns, so a clean shutdown ships
    /// everything it accepted.
    pub fn shutdown(mut self) -> EgressReport {
        self.tx = None;
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }

        EgressReport {
            host_id: self.host_id.clone(),
            shipped: self.stats.shipped(),
            failed: self.stats.failed(),
            dropped_batches: self.stats.dropped_batches(),
            dropped_events: self.stats.dropped_events(),
            last_error: self.last_error(),
        }
    }
}

/// One batch: alerts ride with the events, so the server takes both in one pass.
fn deliver(sink: &mut IngestSink, batch: Batch) {
    for alert in batch.alerts {
        sink.enqueue_alert(alert);
    }
    // `write` queues and submits once its own batch target is reached; `flush`
    // submits whatever is left. One batch in, one request out.
    let _ = sink.write(batch.events);
    let _ = sink.flush();
}

/// Copy the sink's own counters into the shared ones.
fn mirror(sink: &IngestSink, stats: &EgressStats, last_error: &Mutex<Option<String>>) {
    stats.shipped.store(sink.shipped(), Ordering::Relaxed);
    stats.failed.store(sink.failed(), Ordering::Relaxed);
    if let Ok(mut slot) = last_error.lock() {
        *slot = sink.last_error().map(str::to_string);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{EventId, EventKind, EventSource, HostId, Payload, ProviderId, TelemetryEvent};
    use transport::{Endpoint, HostCredential};

    /// A transport that refuses instantly.
    ///
    /// The drop policy is about a server that is *not keeping up*, and a test
    /// that proves it must not wait on a real connect timeout to find out.
    struct Refusing;

    impl transport::Transport for Refusing {
        fn post_json(
            &mut self,
            _endpoint: &Endpoint,
            _path: &str,
            _headers: &[(&str, &str)],
            _body: &[u8],
        ) -> transport::Result<transport::HttpResponse> {
            Err(transport::TransportError::Io(
                "refused by the test".to_string(),
            ))
        }
    }

    fn event(id: u64) -> TelemetryEvent {
        TelemetryEvent::new(
            EventId::new(id),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            EventSource::WindowsEtw,
            ProviderId::new("p"),
            1,
            1,
            1,
            4,
            EventKind::Unclassified,
            Payload::empty(),
        )
    }

    fn batch(n: usize) -> Batch {
        Batch {
            events: (0..n as u64).map(event).collect(),
            alerts: Vec::new(),
        }
    }

    /// A sink whose submissions fail immediately, so the queue fills fast.
    fn refusing_sink() -> IngestSink {
        let endpoint = Endpoint::parse("http://127.0.0.1:1").expect("a valid endpoint");
        let token = format!("0123456789abcdef.{}", "a".repeat(64));
        let credential = HostCredential::new(token).expect("a well-formed token");
        IngestSink::new(endpoint, Box::new(Refusing), &credential, 1)
    }

    #[test]
    fn a_full_queue_drops_and_counts_rather_than_blocking() {
        // The property that matters: `send` returns, whatever the server is
        // doing. If this ever blocks, the collection loop is back on the network.
        let egress = Egress::spawn(refusing_sink());

        let mut outcomes = Vec::new();
        for _ in 0..500 {
            outcomes.push(egress.send(batch(1)));
        }
        assert!(
            outcomes.contains(&SendOutcome::Dropped),
            "an unreachable server must eventually drop rather than wait"
        );
        assert!(
            outcomes.iter().all(|o| *o != SendOutcome::Empty),
            "a non-empty batch is never reported as empty"
        );

        let report = egress.shutdown();
        assert!(report.dropped_batches > 0, "{report:?}");
        assert!(report.dropped_events > 0, "{report:?}");
    }

    #[test]
    fn an_empty_batch_is_not_sent() {
        let egress = Egress::spawn(refusing_sink());
        assert_eq!(
            egress.send(Batch {
                events: Vec::new(),
                alerts: Vec::new()
            }),
            SendOutcome::Empty
        );
        let report = egress.shutdown();
        assert_eq!(report.dropped_batches, 0);
        assert_eq!(report.dropped_events, 0);
    }
}

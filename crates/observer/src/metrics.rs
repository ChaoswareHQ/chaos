//! Counters, snapshots, and the heartbeat line.
//!
//! `Counters` lives behind an `Arc` shared with the handle, so a control
//! thread can read the numbers while the loop is running without asking it
//! to stop. Every field is an atomic; the loop uses `Relaxed` ordering
//! because the counters are read at the end of a run, not used to
//! synchronise anything.
//!
//! # The accounting
//!
//! Every raw event the source produced falls into exactly one bucket at the
//! observer boundary:
//!
//! | Bucket | Meaning |
//! |---|---|
//! | `unmapped` | The source saw it; the translator did not score it. |
//! | `undecodable` | Scored shape, but a field was missing. |
//! | `scored` | Translated and handed to the scorer. |
//!
//! `raw_seen == unmapped + undecodable + scored`. A run where that does not
//! close is a bug in the source, and the report says so.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// The live counters. Shared by value with the handle.
#[derive(Debug, Default)]
pub struct Counters {
    /// Raw events the source produced, before translation.
    pub raw_seen: AtomicU64,
    /// Wire events that reached the scorer.
    pub scored: AtomicU64,
    /// Alerts the scorer produced.
    pub alerts: AtomicU64,
    /// Wire events handed to the sink.
    pub shipped: AtomicU64,
    /// Events the sink refused or a full channel dropped.
    pub dropped: AtomicU64,
    /// Times the sink's `flush` returned an error.
    pub sink_errors: AtomicU64,
    /// Times the source's `next_batch` returned an error.
    pub source_errors: AtomicU64,
    /// Flush cycles completed. Not events; a run with `flush_count == 0` on
    /// a deadline longer than `flush` did not finish, and that is a fact.
    pub flush_count: AtomicU64,
    /// Alerts restated on the flush interval.
    pub restated: AtomicU64,
}

impl Counters {
    #[inline]
    pub(crate) fn bump(counter: &AtomicU64, by: u64) {
        counter.fetch_add(by, Ordering::Relaxed);
    }

    /// Read every counter in one go.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            raw_seen: self.raw_seen.load(Ordering::Relaxed),
            scored: self.scored.load(Ordering::Relaxed),
            alerts: self.alerts.load(Ordering::Relaxed),
            shipped: self.shipped.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            sink_errors: self.sink_errors.load(Ordering::Relaxed),
            source_errors: self.source_errors.load(Ordering::Relaxed),
            flush_count: self.flush_count.load(Ordering::Relaxed),
            restated: self.restated.load(Ordering::Relaxed),
        }
    }
}

/// A `Counters` reading, taken at a moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub raw_seen: u64,
    pub scored: u64,
    pub alerts: u64,
    pub shipped: u64,
    pub dropped: u64,
    pub sink_errors: u64,
    pub source_errors: u64,
    pub flush_count: u64,
    pub restated: u64,
}

impl MetricsSnapshot {
    /// Events per second over `wall`. Saturates at zero on a zero-length run.
    pub fn eps(&self, wall: std::time::Duration) -> f64 {
        let secs = wall.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.scored as f64 / secs
        }
    }

    /// Fraction of raw events that became wire events.
    ///
    /// The one number that answers "is the translator keeping up with the
    /// source", and the one that goes to 0.000 when the field table is wrong
    /// for the Windows build in front of you.
    pub fn coverage(&self) -> f64 {
        if self.raw_seen == 0 {
            return 1.0;
        }
        self.scored as f64 / self.raw_seen as f64
    }
}

/// The one-line heartbeat, formatted.
///
/// A struct rather than a `println!` in the loop so tests can assert on the
/// shape without capturing stdout, and so the fields an operator actually
/// reads are named.
#[derive(Debug, Clone, Copy)]
pub struct Heartbeat {
    pub events: u64,
    pub eps: f64,
    pub alerts: u64,
    pub shipped: u64,
    pub pending: u64,
    pub unmapped: u64,
    pub undecodable: u64,
}

impl fmt::Display for Heartbeat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "  live   events {:>10}  {:>8.0}/s  alerts {:>5}  shipped {:>10}  pending {:>6}  \
             unmapped {:>7}  undecodable {:>7}",
            self.events,
            self.eps,
            self.alerts,
            self.shipped,
            self.pending,
            self.unmapped,
            self.undecodable,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn counters_round_trip_through_a_snapshot() {
        let c = Counters::default();
        Counters::bump(&c.raw_seen, 100);
        Counters::bump(&c.scored, 90);
        Counters::bump(&c.alerts, 3);
        Counters::bump(&c.shipped, 88);
        Counters::bump(&c.dropped, 2);

        let s = c.snapshot();
        assert_eq!(s.raw_seen, 100);
        assert_eq!(s.scored, 90);
        assert_eq!(s.alerts, 3);
        assert_eq!(s.shipped, 88);
        assert_eq!(s.dropped, 2);
    }

    #[test]
    fn an_idle_run_reports_full_coverage_not_nan() {
        let s = MetricsSnapshot::default();
        assert_eq!(s.coverage(), 1.0);
        assert_eq!(s.eps(Duration::from_secs(1)), 0.0);
        assert_eq!(s.eps(Duration::ZERO), 0.0);
    }

    #[test]
    fn coverage_is_the_fraction_that_made_it_through() {
        let s = MetricsSnapshot {
            raw_seen: 100,
            scored: 25,
            ..Default::default()
        };
        assert!((s.coverage() - 0.25).abs() < 1e-12);
    }

    #[test]
    fn the_heartbeat_names_the_numbers_it_prints() {
        let h = Heartbeat {
            events: 42,
            eps: 100.5,
            alerts: 3,
            shipped: 41,
            pending: 1,
            unmapped: 900,
            undecodable: 0,
        };
        let line = h.to_string();
        assert!(line.contains("events"));
        assert!(line.contains("alerts"));
        assert!(line.contains("unmapped"));
        assert!(line.contains("undecodable"));
        // The number an operator reads to decide whether the host is quiet or
        // the sensor is broken.
        assert!(line.contains("900"));
    }
}

//! Counters for the sensor hot path.
//!
//! These live behind atomics rather than a mutex because the callback writes
//! them and a stalled callback costs far more than the atomic traffic does.
//!
//! They are not diagnostics. `received - delivered` is the number of events the
//! sensor saw and the pipeline did not, and that difference is what makes the
//! A3 observation gap an empirical claim instead of an assumption.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Stats {
    received: AtomicU64,
    delivered: AtomicU64,
    filtered: AtomicU64,
    classic: AtomicU64,
    dropped: AtomicU64,
    payload_bytes: AtomicU64,
}

impl Stats {
    /// Callback produced a usable event and copied its payload.
    pub(crate) fn received(&self, bytes: usize) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.payload_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Event made it into the channel.
    pub(crate) fn delivered(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }

    /// Event was rejected before any allocation: too verbose for this run.
    pub(crate) fn filtered(&self) {
        self.filtered.fetch_add(1, Ordering::Relaxed);
    }

    /// A classic (pre-manifest) header, whose descriptor cannot be trusted the
    /// same way. Counted rather than silently coerced.
    pub(crate) fn classic(&self) {
        self.classic.fetch_add(1, Ordering::Relaxed);
    }

    /// The channel was full, so the event was discarded instead of blocking the
    /// callback.
    pub(crate) fn dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            filtered: self.filtered.load(Ordering::Relaxed),
            classic: self.classic.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            payload_bytes: self.payload_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub received: u64,
    pub delivered: u64,
    pub filtered: u64,
    pub classic: u64,
    pub dropped: u64,
    pub payload_bytes: u64,
}

impl StatsSnapshot {
    /// Events the sensor saw but the pipeline never got.
    pub fn lost(&self) -> u64 {
        self.received.saturating_sub(self.delivered)
    }

    /// Fraction of received events that reached the consumer.
    pub fn coverage(&self) -> f64 {
        if self.received == 0 {
            return 1.0;
        }
        self.delivered as f64 / self.received as f64
    }

    pub fn mean_payload_bytes(&self) -> f64 {
        if self.delivered == 0 {
            return 0.0;
        }
        self.payload_bytes as f64 / self.delivered as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_add_up_and_coverage_is_honest() {
        let s = Stats::default();
        s.received(100);
        s.received(200);
        s.received(50);
        s.delivered();
        s.delivered();
        s.filtered();
        s.classic();
        s.dropped();

        let snap = s.snapshot();
        assert_eq!(snap.received, 3);
        assert_eq!(snap.delivered, 2);
        assert_eq!(snap.filtered, 1);
        assert_eq!(snap.classic, 1);
        assert_eq!(snap.dropped, 1);
        assert_eq!(snap.payload_bytes, 350);
        assert_eq!(snap.lost(), 1);
        assert!((snap.coverage() - 2.0 / 3.0).abs() < 1e-12);
        assert!((snap.mean_payload_bytes() - 175.0).abs() < 1e-12);
    }

    #[test]
    fn an_idle_sensor_reports_full_coverage_not_nan() {
        let snap = Stats::default().snapshot();
        assert_eq!(snap.coverage(), 1.0);
        assert_eq!(snap.mean_payload_bytes(), 0.0);
        assert_eq!(snap.lost(), 0);
    }
}

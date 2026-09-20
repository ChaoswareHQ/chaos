//! Turning raw ETW events into the pipeline's wire format.
//!
//! # Composition
//!
//! [`Translator`] owns five things:
//!
//! * a [`Decoder`] — TDH field resolution, per worker;
//! * a [`ShapeCounts`] — per-shape counters, for the report;
//! * an [`UnrecognisedHistogram`] — what the shape table does not claim;
//! * a bounded failure log — the last eight decode failures, for diagnosis;
//! * two `Arc`-backed caches — [`KeyCache`] and [`ImageMetaCache`] —
//!   shared across observer workers so a KCB learned by one worker is
//!   visible to another, and a DLL hashed by one is not re-hashed by
//!   another.
//!
//! # Why `Clone`
//!
//! The observer runs N decode workers, each with its own `Translator`.
//! The `Decoder` is per-clone (each worker warms its own schema cache);
//! the two correlation caches are `Arc`-backed and shared.
//!
//! # Flow, per event
//!
//! 1. `learn_kcb` — cross-event correlation, before the shape match,
//!    because the events that teach the KCB cache are mostly unrecognised.
//! 2. `shape_of` — does the sensor care about this `(provider, id)`?
//! 3. `from_filetime` — is the timestamp usable?
//! 4. dispatch to a per-shape decoder;
//! 5. `note_mapped` or `note_failure`, then construct the `TelemetryEvent`.

mod counts;
mod decoders;
mod histogram;
mod render;
mod shape;

pub use counts::{GapSeverity, ShapeCounts, TelemetryGap};
pub use histogram::UnrecognisedHistogram;
pub use render::render_registry_value;
pub use shape::{Shape, shape_of};

use crate::boundary::callback::EtwRaw;
use crate::decode::Decoder;
use crate::enrich::image::ImageMetaCache;
use crate::enrich::kcb::KeyCache;
use model::{EventId, EventSource, HostId, Payload, TelemetryEvent};

/// How many distinct failure messages are kept, for the run report.
///
/// Eight is a compromise: enough to spot a pattern (a wrong field name
/// repeats), small enough that every kept message is visible on one
/// screen. The failures are printed one per line; more than eight pushes
/// the useful ones off the top.
const KEPT_FAILURES: usize = 8;

/// The provider whose events populate and query the KCB cache.
const KERNEL_REGISTRY: &str = "Microsoft-Windows-Kernel-Registry";

/// A reading of the KCB cache's work, for the run report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KcbStats {
    /// Events that carried both a pointer and a path and were recorded.
    pub learned: u64,
    /// `SetValueKey` events whose pointer the cache could resolve.
    pub hits: u64,
    /// `SetValueKey` events whose pointer the cache could not resolve.
    pub misses: u64,
    /// Entries currently held.
    pub cache_size: usize,
    /// The cache's configured ceiling.
    pub cache_capacity: usize,
}

impl KcbStats {
    /// Fraction of correlated lookups that succeeded.
    ///
    /// A run with zero lookups reports `1.0`, because "no misses" is the
    /// honest reading of "no data". The distinction from `0.0` matters:
    /// a rate of zero says the cache is broken, and a run that has not
    /// seen a `SetValueKey` yet has no evidence either way.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            1.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Translates raw ETW events, and reports what it could not translate.
///
/// Clone is cheap and **shares both caches**. The schema cache in
/// [`Decoder`] is per-clone; the KCB and image-metadata caches are
/// `Arc`-backed because a `KCBCreate` seen by one worker must be visible
/// to another, and a DLL hashed by one worker must not be re-hashed by
/// another.
#[derive(Debug, Clone)]
pub struct Translator {
    host: HostId,
    decoder: Decoder,
    next_event_id: u64,
    counts: ShapeCounts,
    histogram: UnrecognisedHistogram,
    failures: Vec<String>,
    key_cache: KeyCache,
    image_meta: ImageMetaCache,
    kcb_learned: u64,
    kcb_hits: u64,
    kcb_misses: u64,
}

impl Translator {
    pub fn new(host: HostId) -> Self {
        Self {
            host,
            decoder: Decoder::new(),
            next_event_id: 0,
            counts: ShapeCounts::default(),
            histogram: UnrecognisedHistogram::default(),
            failures: Vec::new(),
            key_cache: KeyCache::default(),
            image_meta: ImageMetaCache::default(),
            kcb_learned: 0,
            kcb_hits: 0,
            kcb_misses: 0,
        }
    }

    /// Total events mapped to a wire shape.
    pub fn mapped(&self) -> u64 {
        self.counts.total_mapped()
    }

    /// Events that were a scored shape but could not be decoded.
    ///
    /// A non-zero value here is a bug in the field table for this build
    /// of Windows, not a quiet host. The failure log names each one.
    pub fn undecodable(&self) -> u64 {
        self.counts
            .total_attempted()
            .saturating_sub(self.counts.total_mapped())
    }

    pub fn counts(&self) -> ShapeCounts {
        self.counts
    }

    pub fn histogram(&self) -> &UnrecognisedHistogram {
        &self.histogram
    }

    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    pub fn kcb_stats(&self) -> KcbStats {
        KcbStats {
            learned: self.kcb_learned,
            hits: self.kcb_hits,
            misses: self.kcb_misses,
            cache_size: self.key_cache.len(),
            cache_capacity: self.key_cache.capacity(),
        }
    }

    /// Detect shapes that are silent while the sensor is otherwise active.
    ///
    /// A shape that has *never* fired is untested, not silent. A shape
    /// that has fired and stopped while another shape of the opposite
    /// kind is still active is the ETW-bypass signature: a user-mode
    /// provider that no longer emits because someone patched the export
    /// function, while the kernel-mode events keep flowing.
    pub fn detect_gaps(&self) -> Vec<TelemetryGap> {
        if self.counts.total_attempted() == 0 {
            return Vec::new();
        }

        let kernel_active = self.counts.kernel_side_active();
        let user_active = self.counts.user_mode_active();
        let mut gaps = Vec::new();

        for shape in Shape::ALL {
            let attempted = self.counts.attempted(*shape);
            let mapped = self.counts.mapped(*shape);

            let severity = if attempted == 0 {
                if !self.counts.ever_fired(*shape) {
                    GapSeverity::Healthy
                } else if shape.is_user_mode() && kernel_active {
                    GapSeverity::Silent
                } else if shape.is_kernel_side() && user_active {
                    GapSeverity::Silent
                } else {
                    GapSeverity::Healthy
                }
            } else if attempted > mapped {
                GapSeverity::DecodeFailure
            } else {
                GapSeverity::Healthy
            };

            if severity != GapSeverity::Healthy {
                gaps.push(TelemetryGap {
                    shape: *shape,
                    attempted,
                    mapped,
                    severity,
                });
            }
        }

        gaps.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.shape.as_str().cmp(b.shape.as_str()))
        });
        gaps
    }

    /// One line summarising every shape's mapped/attempted counts.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (shape, attempted, mapped) in self.counts.by_shape() {
            parts.push(format!("{}: {}/{}", shape.as_str(), mapped, attempted));
        }
        if self.counts.unrecognised() > 0 {
            parts.push(format!("unrecognised: {}", self.counts.unrecognised()));
        }
        parts.join(", ")
    }

    /// Translate one raw event.
    ///
    /// Returns `Some` when the event is a shape the sensor scores and the
    /// decoder had every mandatory field. Returns `None` for one of three
    /// reasons, each counted so the run report can say which:
    ///
    /// * not a scored shape — `note_unrecognised` and the histogram;
    /// * a scored shape with an unusable timestamp — a failure;
    /// * a scored shape with a missing mandatory field — a failure.
    pub fn translate(&mut self, raw: &EtwRaw) -> Option<TelemetryEvent> {
        // Cross-event correlation first: a `SetValueKey` we are about to
        // decode may need a mapping learned from an `OpenKey` that arrived
        // a millisecond ago and would otherwise be dropped as
        // unrecognised.
        self.learn_kcb(raw);

        let provider = raw.wire.provider.as_str();
        let event_id = raw.wire.event_id;

        let Some(shape) = shape_of(provider, event_id) else {
            self.counts.note_unrecognised();
            self.histogram.note(provider, event_id);
            return None;
        };
        self.counts.note_attempt(shape);

        let Some(timestamp) = render::from_filetime(raw.wire.timestamp_raw) else {
            self.note_failure(format!(
                "{provider} id={event_id}: timestamp {} is not a valid FILETIME",
                raw.wire.timestamp_raw
            ));
            return None;
        };

        let kind = match shape {
            Shape::ProcessStart => self.process_start(raw, timestamp),
            Shape::ProcessExit => self.process_exit(raw, timestamp),
            Shape::ImageLoad => self.image_load(raw, timestamp),
            Shape::RegistrySet => self.registry_set(raw, timestamp),
            Shape::DnsQuery => self.dns_query(raw, timestamp),
            Shape::ScriptBlock => self.script_block(raw, timestamp),
        };

        let kind = match kind {
            Ok(k) => k,
            Err(reason) => {
                self.note_failure(format!("{provider} id={event_id}: {reason}"));
                return None;
            }
        };

        self.counts.note_mapped(shape);
        self.next_event_id += 1;

        Some(TelemetryEvent::new(
            EventId::new(self.next_event_id),
            self.host.clone(),
            timestamp,
            EventSource::WindowsEtw,
            raw.wire.provider.clone(),
            event_id,
            raw.wire.pid,
            raw.wire.tid,
            raw.wire.level,
            kind,
            Payload::empty(),
        ))
    }

    fn note_failure(&mut self, reason: String) {
        if self.failures.len() < KEPT_FAILURES {
            self.failures.push(reason);
        }
    }

    /// Learn `KeyObject → path` from any registry event that carries both.
    ///
    /// Called on *every* registry event, before the shape match. The
    /// events that teach the cache are mostly events we do not score — an
    /// `OpenKey` is not a detection — so they would never reach a decoder
    /// if this ran after the match.
    ///
    /// The cost is one or two TDH calls per registry event, and only when
    /// the path field resolves to something non-empty. On a desktop that
    /// is a few thousand calls per second at peak.
    fn learn_kcb(&mut self, raw: &EtwRaw) {
        if raw.wire.provider.as_str() != KERNEL_REGISTRY {
            return;
        }
        // Path first: an event without one has nothing to teach. Reading
        // it first means the many events that only carry a `KeyObject`
        // (queries, enumerations, rundowns) cost one TDH call and exit,
        // rather than two.
        let Some(path) = self.decoder.text_first_nonempty(raw, shape::KEY_NAME) else {
            return;
        };
        let Some(key_object) = self.decoder.u64_any(raw, shape::KCB_KEY_OBJECT) else {
            return;
        };
        self.key_cache.learn(key_object, &path);
        self.kcb_learned += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{ProviderId, RawEvent};
    use windows::core::GUID;

    const KNOWN_FILETIME: i64 = 133_444_736_000_000_000;

    fn raw(provider: &'static str, event_id: u16, data: Vec<u8>) -> EtwRaw {
        EtwRaw {
            wire: RawEvent {
                source: EventSource::WindowsEtw,
                provider: ProviderId::new(provider),
                event_id,
                timestamp_raw: KNOWN_FILETIME,
                pid: 4242,
                tid: 4243,
                level: 4,
                data,
            },
            guid: GUID::from_u128(0),
            version: 0,
            opcode: 0,
            keyword: 0,
            activity_id: [0; 16],
            related_activity_id: None,
            process_start_key: Some(1),
            is_wow64: false,
        }
    }

    fn translator() -> Translator {
        Translator::new(HostId::new("host-a").unwrap())
    }

    #[test]
    fn unscored_traffic_lands_in_the_histogram() {
        let mut t = translator();
        for id in [3u16, 4, 6, 7] {
            assert!(
                t.translate(&raw("Microsoft-Windows-Kernel-Process", id, vec![1]))
                    .is_none()
            );
        }
        t.translate(&raw("Some-Other-Provider", 1, vec![]));

        assert_eq!(t.undecodable(), 0);
        assert_eq!(t.counts().unrecognised(), 5);
        assert_eq!(t.histogram().total(), 5);
        let top = t.histogram().top(10);
        assert_eq!(top[0].0, "Microsoft-Windows-Kernel-Process");
        assert_eq!(top[0].2, 4);
    }

    #[test]
    fn a_process_start_with_an_empty_imagename_is_undecodable() {
        let mut t = translator();
        assert!(
            t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, vec![1; 16]))
                .is_none()
        );
        assert_eq!(t.mapped(), 0);
        assert_eq!(t.undecodable(), 1);
        assert!(t.failures()[0].contains("ImageName"), "{:?}", t.failures());
    }

    #[test]
    fn a_registry_set_that_cannot_be_correlated_names_the_pointer() {
        let mut t = translator();
        assert!(
            t.translate(&raw("Microsoft-Windows-Kernel-Registry", 5, vec![1; 8]))
                .is_none()
        );
        assert_eq!(t.mapped(), 0);
        assert_eq!(t.counts().attempted(Shape::RegistrySet), 1);
        assert_eq!(t.counts().mapped(Shape::RegistrySet), 0);
        assert!(
            t.failures()[0].contains("KeyName"),
            "{:?}",
            t.failures()
        );
        assert_eq!(t.kcb_stats().misses, 1);
    }

    #[test]
    fn the_accounting_closes_across_all_buckets() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, Vec::new()));
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 3, Vec::new()));
        t.translate(&raw("Some-Other-Provider", 1, Vec::new()));
        t.translate(&raw("Microsoft-Windows-Kernel-Process", 5, Vec::new()));

        let accounted = t.mapped() + t.undecodable() + t.counts().unrecognised();
        assert_eq!(accounted, 4);
    }

    #[test]
    fn an_idle_sensor_reports_no_gaps() {
        let t = translator();
        assert!(t.detect_gaps().is_empty());
    }

    #[test]
    fn kcb_stats_start_at_zero_and_a_full_cache() {
        let t = translator();
        let s = t.kcb_stats();
        assert_eq!(s.learned, 0);
        assert_eq!(s.hits, 0);
        assert_eq!(s.misses, 0);
        assert_eq!(s.cache_size, 0);
        assert!(s.cache_capacity > 0);
        assert_eq!(s.hit_rate(), 1.0);
    }

    #[test]
    fn the_failure_log_is_bounded() {
        let mut t = translator();
        for _ in 0..500 {
            t.translate(&raw("Microsoft-Windows-Kernel-Process", 1, vec![1; 16]));
        }
        assert_eq!(t.undecodable(), 500);
        assert_eq!(t.failures().len(), KEPT_FAILURES);
    }

    #[test]
    fn a_shape_that_stopped_firing_is_silent() {
        let mut t = translator();
        t.translate(&raw("Microsoft-Windows-DNS-Client", 3006, Vec::new()));
        for _ in 0..3 {
            t.translate(&raw("Microsoft-Windows-Kernel-Registry", 5, Vec::new()));
        }
        let gaps = t.detect_gaps();
        let dns_gap = gaps
            .iter()
            .find(|g| g.shape == Shape::DnsQuery)
            .expect("DNS gap");
        assert_eq!(dns_gap.severity, GapSeverity::Silent);
    }
}

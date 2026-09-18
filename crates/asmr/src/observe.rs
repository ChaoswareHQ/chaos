//! Implements A3 (Observation and Partial Observability) and A15 (Channel Capacity).
//!
//! Formal objects: observations `o = (id, entity, channel, ts, value)`, the
//! partial observation map `O : Entity -/-> ObsId`, the blind spot
//! `1 - |O| / |U|`, and a binary asymmetric sensor channel with false-positive
//! and false-negative rates.
//!
//! In a SIEM/XDR pipeline this crate answers "what did we actually see, and how
//! much can that channel tell us?". Detectors consult coverage before claiming
//! absence of evidence, and A15 bounds how much discriminating power a noisy
//! sensor can ever deliver.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// Stable handle for a recorded observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObsId(pub u64);

/// One A3 observation of an entity on a sensor channel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Observation {
    /// Stable observation identity.
    pub id: ObsId,
    /// Entity observed.
    pub entity: u64,
    /// Source channel (sensor or provider index).
    pub channel: u32,
    /// Timestamp in nanoseconds since the epoch.
    pub ts_ns: i64,
    /// Observed scalar value.
    pub value: f64,
}

/// The A3 partial observation map; unobserved entities are simply absent.
#[derive(Debug, Clone)]
pub struct ObservationMap {
    seen: BTreeMap<u64, ObsId>,
}

impl ObservationMap {
    /// Creates an empty observation map.
    pub fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
        }
    }

    /// Records the latest observation for an entity, overwriting any previous one.
    pub fn observe(&mut self, entity: u64, obs: ObsId) {
        self.seen.insert(entity, obs);
    }

    /// Returns the recorded observation id for an entity, if any.
    pub fn get(&self, entity: u64) -> Option<ObsId> {
        self.seen.get(&entity).copied()
    }

    /// Number of distinct entities observed at least once.
    pub fn observed_count(&self) -> usize {
        self.seen.len()
    }

    /// Universe members with no observation, in ascending order. The set is
    /// deduplicated so callers may pass a messy universe.
    pub fn unobserved(&self, universe: impl IntoIterator<Item = u64>) -> Vec<u64> {
        let mut all: BTreeSet<u64> = universe.into_iter().collect();
        all.retain(|e| !self.seen.contains_key(e));
        all.into_iter().collect()
    }

    /// Observed fraction of a universe of known size; 1.0 when it is empty.
    pub fn coverage_ratio(&self, universe_size: usize) -> f64 {
        if universe_size == 0 {
            1.0
        } else {
            (self.observed_count() as f64 / universe_size as f64).min(1.0)
        }
    }

    /// The A3 blind spot, the complement of coverage.
    pub fn blind_spot(&self, universe_size: usize) -> f64 {
        1.0 - self.coverage_ratio(universe_size)
    }
}

impl Default for ObservationMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Binary entropy `h2(p)` in bits; outside the open unit interval it is zero.
pub fn binary_entropy(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        0.0
    } else {
        -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
    }
}

/// A binary asymmetric sensor channel parameterised by its error rates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Channel {
    /// `P(alert | benign)`, clamped to `[0, 1]`.
    pub false_positive: f64,
    /// `P(no alert | malicious)`, clamped to `[0, 1]`.
    pub false_negative: f64,
}

impl Channel {
    /// Builds a channel, clamping both rates into the unit interval.
    pub fn new(false_positive: f64, false_negative: f64) -> Self {
        Self {
            false_positive: false_positive.clamp(0.0, 1.0),
            false_negative: false_negative.clamp(0.0, 1.0),
        }
    }

    /// Mutual information of the binary asymmetric channel under a UNIFORM
    /// input, in bits, using exactly
    /// `h2((1 + fp - fn)/2) - h2(fp)/2 - h2(fn)/2`, clamped to `>= 0`.
    ///
    /// Under a uniform input this expression *is* the mutual information, which
    /// equals the Shannon capacity in the symmetric case (`fp == fn`) and is a
    /// lower bound on capacity otherwise; the true capacity maximises over the
    /// input distribution instead.
    pub fn capacity(&self) -> f64 {
        let cross = binary_entropy((1.0 + self.false_positive - self.false_negative) / 2.0);
        (cross
            - 0.5 * binary_entropy(self.false_positive)
            - 0.5 * binary_entropy(self.false_negative))
        .max(0.0)
    }

    /// Fano floor: the residual uncertainty left by misses alone, `h2(fn)`.
    pub fn fano_floor(&self) -> f64 {
        binary_entropy(self.false_negative)
    }

    /// True when the channel reports the truth with no error in either direction.
    pub fn is_perfect(&self) -> bool {
        self.false_positive == 0.0 && self.false_negative == 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_boundaries_and_symmetry() {
        assert_eq!(binary_entropy(0.0), 0.0);
        assert_eq!(binary_entropy(1.0), 0.0);
        assert_eq!(binary_entropy(-0.5), 0.0);
        assert_eq!(binary_entropy(1.5), 0.0);
        assert_eq!(binary_entropy(0.5), 1.0);
        assert!((binary_entropy(0.25) - binary_entropy(0.75)).abs() < 1e-12);
        assert!((binary_entropy(0.25) - 0.811_278_124_459_132_9).abs() < 1e-12);
    }

    #[test]
    fn channel_rates_are_clamped_to_the_unit_interval() {
        let c = Channel::new(-1.0, 2.0);
        assert_eq!(c.false_positive, 0.0);
        assert_eq!(c.false_negative, 1.0);
        let d = Channel::new(0.2, 0.3);
        assert_eq!(
            d,
            Channel {
                false_positive: 0.2,
                false_negative: 0.3
            }
        );
    }

    #[test]
    fn perfect_channel_carries_one_bit() {
        let c = Channel::new(0.0, 0.0);
        assert!(c.is_perfect());
        assert_eq!(c.capacity(), 1.0);
        assert_eq!(c.fano_floor(), 0.0);
    }

    #[test]
    fn useless_channel_carries_no_information() {
        let c = Channel::new(0.5, 0.5);
        assert!(!c.is_perfect());
        assert_eq!(c.capacity(), 0.0);
        assert_eq!(c.fano_floor(), 1.0);
        // The clamp guarantees no negative "capacity" from rounding.
        assert!(c.capacity() >= 0.0);
    }

    #[test]
    fn fano_floor_tracks_misses_only() {
        assert_eq!(Channel::new(0.9, 0.0).fano_floor(), 0.0);
        assert_eq!(Channel::new(0.0, 0.5).fano_floor(), 1.0);
        assert!((Channel::new(0.4, 0.25).fano_floor() - 0.811_278_124_459_132_9).abs() < 1e-12);
    }

    #[test]
    fn observation_map_reports_the_blind_spot() {
        let mut m = ObservationMap::new();
        assert_eq!(m.coverage_ratio(0), 1.0);
        assert_eq!(m.blind_spot(0), 0.0);
        m.observe(1, ObsId(10));
        m.observe(2, ObsId(11));
        m.observe(2, ObsId(12));
        assert_eq!(m.get(1), Some(ObsId(10)));
        assert_eq!(m.get(2), Some(ObsId(12)));
        assert_eq!(m.get(3), None);
        assert_eq!(m.observed_count(), 2);
        assert_eq!(m.unobserved(vec![1, 2, 3, 3, 4]), vec![3, 4]);
        assert_eq!(m.unobserved([2u64, 3]), vec![3]);
        assert!((m.coverage_ratio(4) - 0.5).abs() < 1e-12);
        assert!((m.blind_spot(4) - 0.5).abs() < 1e-12);
        assert_eq!(m.coverage_ratio(1), 1.0);
    }
}

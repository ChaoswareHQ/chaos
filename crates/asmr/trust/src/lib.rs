//! Implements A10 (Trust and Integrity).
//!
//! The formal object is trust as a bounded lattice: a value in `[0, 1]` for each
//! source of evidence, combined by `meet` (the worst-case view) and `join` (the
//! best-case view), and decayed along a propagation path.
//!
//! Why a pipeline needs this: every signal arrives from somewhere — an ETW
//! sensor the agent owns, a third-party EDR feed, a threat-intel list of
//! unknown freshness. A likelihood ratio from an untrusted source is not
//! evidence, and the honest way to say that is to pull its log-ratio toward
//! zero in proportion to trust, rather than to accept or discard it wholesale.
#![forbid(unsafe_code)]

/// A trust value, always clamped to `[0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Trust(f64);

impl Trust {
    /// No trust: evidence from this source is ignored.
    pub const NONE: Trust = Trust(0.0);
    /// No opinion yet. Distinct from `NONE` because "we have not decided" is
    /// not the same as "we have decided it is worthless".
    pub const UNKNOWN: Trust = Trust(0.5);
    /// Local sensor we control end to end.
    pub const FULL: Trust = Trust(1.0);

    pub fn new(v: f64) -> Self {
        // `f64::clamp` propagates NaN, and a NaN trust would silently poison
        // every weighted likelihood downstream. Fail closed to "no opinion".
        if v.is_nan() {
            return Trust::UNKNOWN;
        }
        Trust(v.clamp(0.0, 1.0))
    }

    pub fn get(&self) -> f64 {
        self.0
    }

    /// Degradation: the pessimistic combination. Trust is only as good as the
    /// weaker of two sources.
    pub fn meet(&self, other: Trust) -> Trust {
        Trust(self.0.min(other.0))
    }

    /// The optimistic combination.
    pub fn join(&self, other: Trust) -> Trust {
        Trust(self.0.max(other.0))
    }
}

impl Default for Trust {
    fn default() -> Self {
        Trust::UNKNOWN
    }
}

/// Trust after traversing `hops` links that each cost `hop_decay` of it.
pub fn propagate(origin: Trust, hop_decay: f64, hops: u32) -> Trust {
    let decay = hop_decay.clamp(0.0, 1.0);
    Trust::new(origin.get() * decay.powi(hops as i32))
}

/// A10: evidence from a partially trusted source, discounted toward "no
/// evidence". A log-ratio of 0 means the observation cannot distinguish the
/// hypotheses, so `Trust::NONE` correctly yields exactly that.
pub fn weighted_log_ratio(log_ratio: f64, trust: Trust) -> f64 {
    log_ratio * trust.get()
}

/// Per-source trust for a running pipeline.
#[derive(Debug, Clone, Default)]
pub struct TrustLedger {
    sources: std::collections::BTreeMap<Box<str>, Trust>,
}

impl TrustLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absent sources are `UNKNOWN`, not `NONE`: an unknown feed should weaken
    /// evidence, not annihilate it.
    pub fn get(&self, source: &str) -> Trust {
        self.sources.get(source).copied().unwrap_or(Trust::UNKNOWN)
    }

    pub fn set(&mut self, source: &str, t: Trust) {
        self.sources.insert(source.into(), t);
    }

    /// Reduce a source's trust, e.g. after it is caught emitting a false
    /// positive. Trust is only ever degraded by evidence, never silently
    /// restored.
    pub fn degrade(&mut self, source: &str, factor: f64) {
        let current = self.get(source);
        self.set(source, Trust::new(current.get() * factor.clamp(0.0, 1.0)));
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> [Trust; 4] {
        [Trust::NONE, Trust::new(0.25), Trust::UNKNOWN, Trust::FULL]
    }

    #[test]
    fn lattice_laws_hold() {
        for a in samples() {
            assert_eq!(a.meet(a), a, "meet must be idempotent");
            assert_eq!(a.join(a), a, "join must be idempotent");
            for b in samples() {
                assert_eq!(a.meet(b), b.meet(a), "meet must commute");
                assert_eq!(a.join(b), b.join(a), "join must commute");
                for c in samples() {
                    assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)), "meet must associate");
                    assert_eq!(a.join(b).join(c), a.join(b.join(c)), "join must associate");
                }
            }
        }
    }

    #[test]
    fn meet_is_the_lower_bound_and_join_the_upper() {
        let a = Trust::new(0.3);
        let b = Trust::new(0.7);
        assert_eq!(a.meet(b), a);
        assert_eq!(a.join(b), b);
    }

    #[test]
    fn construction_clamps_out_of_range_and_rejects_nan() {
        assert_eq!(Trust::new(2.0).get(), 1.0);
        assert_eq!(Trust::new(-3.0).get(), 0.0);
        assert_eq!(Trust::new(f64::NAN), Trust::UNKNOWN);
    }

    #[test]
    fn propagation_decays_monotonically_and_stops_at_none() {
        let origin = Trust::FULL;
        let one = propagate(origin, 0.5, 1);
        let two = propagate(origin, 0.5, 2);
        assert_eq!(one.get(), 0.5);
        assert_eq!(two.get(), 0.25);
        assert!(two < one);
        assert_eq!(propagate(origin, 0.0, 3), Trust::NONE);
        assert_eq!(
            propagate(origin, 0.5, 0),
            Trust::FULL,
            "zero hops is identity"
        );
    }

    #[test]
    fn untrusted_evidence_carries_no_weight() {
        assert_eq!(weighted_log_ratio(3.0, Trust::NONE), 0.0);
        assert_eq!(weighted_log_ratio(3.0, Trust::FULL), 3.0);
        assert_eq!(weighted_log_ratio(3.0, Trust::UNKNOWN), 1.5);
        // The point of the whole crate: an untrusted feed cannot manufacture
        // certainty, no matter how confident its log-ratio claims to be.
        assert!(weighted_log_ratio(20.0, Trust::new(0.01)).abs() < 0.21);
    }

    #[test]
    fn ledger_defaults_to_unknown_and_only_degrades() {
        let mut l = TrustLedger::new();
        assert_eq!(l.get("never-seen"), Trust::UNKNOWN);
        l.set("edr", Trust::FULL);
        l.degrade("edr", 0.5);
        assert_eq!(l.get("edr").get(), 0.5);
        l.degrade("edr", 0.5);
        assert_eq!(l.get("edr").get(), 0.25);
        assert_eq!(l.len(), 1);
        assert!(!l.is_empty());
    }
}

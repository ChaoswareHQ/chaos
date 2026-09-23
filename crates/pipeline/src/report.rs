//! Pipeline telemetry: what the run actually observed, and what that is worth.
//!
//! Two things live here that a monitoring system should not be able to skip.
//!
//! The first is loss accounting. `coverage` is not a health metric, it is a
//! bound on every other number in the report: if 3% of events never arrived,
//! then 3% of the state space was never projected, and any claim about unseen
//! behaviour has to carry that.
//!
//! The second is per-rule channel capacity (A15). A rule firing `n` times says
//! nothing about whether it was worth running. Its capacity — the bits it
//! carries about the hypothesis, computed from its own hit and false-positive
//! rates — is comparable across rules and across days, and it is the only
//! defensible way to decide which rule to turn off when the queue is too long.

use asmr::observe::{Channel, ObservationMap};
use asmr::resource::{overload, utilization};
use std::collections::BTreeMap;

/// One rule's observed firing behaviour.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuleFiring {
    pub firings: u64,
    /// P(rule fires | host compromised), as claimed by the rule.
    pub hit: f64,
    /// P(rule fires | host clean), as claimed by the rule.
    pub miss: f64,
}

impl RuleFiring {
    /// Bits this rule carries about the compromise hypothesis.
    ///
    /// With `false_positive = miss` and `false_negative = 1 - hit`, this is the
    /// uniform-input mutual information of the rule treated as a binary
    /// observation channel.
    pub fn capacity_bits(&self) -> f64 {
        Channel::new(self.miss, 1.0 - self.hit).capacity()
    }

    /// Lower bound on the error any decoder of this rule must have (Fano).
    pub fn fano_floor_bits(&self) -> f64 {
        Channel::new(self.miss, 1.0 - self.hit).fano_floor()
    }
}

/// Running counters for one pipeline instance.
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub events: u64,
    pub process_starts: u64,
    pub findings: u64,
    pub alerts: u64,
    pub abstained: u64,
    /// Repeat firings folded into an earlier alert instead of emitted again.
    pub suppressed: u64,
    /// Firings that never cleared the severity floor.
    ///
    /// Counted rather than published. Reported separately from `suppressed`
    /// because the two mean opposite things: a folded firing is one the analyst
    /// has effectively been told about, and a below-floor one is a decision not
    /// to tell them. Read this number before raising the floor.
    pub below_floor: u64,
    /// Findings suppressed by A12 governance before they could become alerts.
    pub withheld_by_policy: u64,
    /// Sensitive fields replaced by A19 minimisation before leaving the host.
    pub redacted_fields: u64,
    pub by_rule: BTreeMap<&'static str, RuleFiring>,
}

impl Metrics {
    /// Record one firing of a rule.
    pub fn record_finding(&mut self, rule: &'static str, hit: f64, miss: f64) {
        self.findings += 1;
        let entry = self.by_rule.entry(rule).or_insert(RuleFiring {
            firings: 0,
            hit,
            miss,
        });
        entry.firings += 1;
    }

    /// Rules ordered by how much information they actually carried.
    ///
    /// Deliberately by capacity rather than by count: the noisiest rule is
    /// usually the one firing most, and sorting by volume would put it at the
    /// top of a list whose purpose is to identify it.
    pub fn rules_by_capacity(&self) -> Vec<(&'static str, RuleFiring)> {
        let mut rules: Vec<_> = self.by_rule.iter().map(|(k, v)| (*k, *v)).collect();
        rules.sort_by(|a, b| {
            b.1.capacity_bits()
                .partial_cmp(&a.1.capacity_bits())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(b.0))
        });
        rules
    }

    /// Total bits of evidence the run accumulated across all rules.
    pub fn total_capacity_bits(&self) -> f64 {
        self.by_rule.values().map(RuleFiring::capacity_bits).sum()
    }
}

/// Everything the run is worth, in one place.
#[derive(Debug, Clone)]
pub struct Observation {
    pub metrics: Metrics,
    /// Entities projected into the A1 state space.
    pub entities: usize,
    /// Distinct executables seen (A22 population).
    pub distinct_images: usize,
    /// Distinct structural edges seen (A23 graph).
    pub known_edges: usize,
    /// Fraction of the entity universe never observed (A3 blind spot).
    pub blind_spot: f64,
    /// A15 capacity of the observation channel, in bits per observation.
    pub channel_capacity_bits: f64,
    /// Offered event rate over the sensor's configured capacity.
    pub load_factor: f64,
}

impl Observation {
    /// Fraction of the entity universe that was actually observed.
    pub fn coverage(&self) -> f64 {
        1.0 - self.blind_spot
    }

    pub fn triage_utilization(&self, budget: f64) -> f64 {
        utilization(self.metrics.alerts as f64, budget)
    }
}

/// Assemble a report from the engine's live pieces.
pub fn build(
    metrics: &Metrics,
    observe: &ObservationMap,
    entities: usize,
    distinct_images: usize,
    known_edges: usize,
    offered_rate: f64,
    sensor_capacity: f64,
) -> Observation {
    Observation {
        metrics: metrics.clone(),
        entities,
        distinct_images,
        known_edges,
        // `entities`, not `entities.max(1)`. A universe of zero is not a blind
        // spot of one: A3's blind spot is the unobserved fraction of a universe
        // we know of, and when nothing has been projected there is no universe
        // to be blind to. `ObservationMap` already implements exactly that
        // convention and tests it — `coverage_ratio(0) == 1.0` — so guarding the
        // argument here against a division that cannot happen inverted the
        // answer and reported `coverage 0.000000` for a run that had simply seen
        // no process starts yet.
        blind_spot: observe.blind_spot(entities),
        channel_capacity_bits: aggregate_capacity(metrics),
        load_factor: overload(offered_rate, sensor_capacity),
    }
}

/// Capacity of the whole detector stack, treated as one channel.
///
/// Averaging the *rates* rather than summing capacities is deliberate: the
/// rules fire on the same events and their evidence overlaps, so summing would
/// claim more information than the events contain. An average is an honest
/// under-claim.
fn aggregate_capacity(metrics: &Metrics) -> f64 {
    let rules = metrics.by_rule.values().filter(|r| r.firings > 0).count();
    if rules == 0 {
        return 0.0;
    }
    metrics.total_capacity_bits() / rules as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use asmr::observe::ObsId;

    fn metrics() -> Metrics {
        let mut m = Metrics::default();
        // A strong rule: fires on 92% of compromised hosts, 1% of clean ones.
        m.record_finding("encoded_powershell", 0.92, 0.010);
        // A weak rule, firing on a third of everything.
        m.record_finding("high_abuse_tld", 0.30, 0.070);
        m
    }

    #[test]
    fn firings_accumulate_per_rule() {
        let mut m = Metrics::default();
        m.record_finding("a", 0.5, 0.1);
        m.record_finding("a", 0.5, 0.1);
        m.record_finding("b", 0.5, 0.1);
        assert_eq!(m.findings, 3);
        assert_eq!(m.by_rule["a"].firings, 2);
        assert_eq!(m.by_rule["b"].firings, 1);
    }

    #[test]
    fn strong_rules_carry_more_bits_than_weak_ones() {
        let m = metrics();
        let strong = m.by_rule["encoded_powershell"].capacity_bits();
        let weak = m.by_rule["high_abuse_tld"].capacity_bits();

        assert!(strong > weak, "{strong} vs {weak}");
        assert!(
            strong > 0.4,
            "a clean 0.92/0.01 rule should carry real bits"
        );
        assert!(weak < 0.1, "a 0.30/0.07 rule carries almost nothing");
    }

    #[test]
    fn a_perfect_rule_approaches_one_bit() {
        let mut m = Metrics::default();
        m.record_finding("perfect", 1.0, 0.0001);
        // Clamped away from 0/1 so the log-ratio stays finite; capacity should
        // still be close to the one bit a perfect binary test can carry.
        assert!(m.by_rule["perfect"].capacity_bits() > 0.9);
    }

    #[test]
    fn a_useless_rule_carries_nothing() {
        let mut m = Metrics::default();
        // Fires equally often either way: no information at all.
        m.record_finding("coin_flip", 0.5, 0.5);
        assert!(m.by_rule["coin_flip"].capacity_bits() < 1e-9);
    }

    #[test]
    fn ordering_is_by_value_not_by_volume() {
        let mut m = Metrics::default();
        for _ in 0..100 {
            m.record_finding("cheap_noise", 0.30, 0.070);
        }
        m.record_finding("rare_and_decisive", 0.92, 0.010);

        let ranked = m.rules_by_capacity();
        assert_eq!(ranked[0].0, "rare_and_decisive", "capacity, not count");
        assert_eq!(ranked[1].1.firings, 100);
    }

    #[test]
    fn an_idle_stack_carries_no_bits_and_does_not_divide_by_zero() {
        let m = Metrics::default();
        assert_eq!(m.total_capacity_bits(), 0.0);
        assert_eq!(aggregate_capacity(&m), 0.0);
        assert!(m.rules_by_capacity().is_empty());
    }

    /// The empty universe is not a blind sensor.
    ///
    /// A run that has projected no entity yet reported `coverage 0.000000` and
    /// `blind spot 1.000000`, which reads as "this sensor sees nothing" while
    /// thousands of events were flowing through it. A3's convention is the
    /// opposite, and `asmr` implements it; this is the test that says the report
    /// agrees.
    #[test]
    fn a_run_with_no_entities_yet_is_fully_covered_not_fully_blind() {
        let empty = build(
            &Metrics::default(),
            &ObservationMap::new(),
            0,
            0,
            0,
            0.0,
            1.0,
        );
        assert_eq!(empty.blind_spot, 0.0);
        assert_eq!(empty.coverage(), 1.0);
        assert_eq!(empty.entities, 0);
    }

    #[test]
    fn an_entity_that_was_never_observed_is_a_blind_spot() {
        // The other direction, so the fix cannot be "return zero always": a
        // projected entity with nothing recorded against it is exactly the gap
        // A3 exists to represent.
        let observation = build(
            &Metrics::default(),
            &ObservationMap::new(),
            4,
            0,
            0,
            0.0,
            1.0,
        );
        assert_eq!(observation.blind_spot, 1.0);
        assert_eq!(observation.coverage(), 0.0);
    }

    #[test]
    fn a_fully_observed_universe_has_no_blind_spot() {
        let mut observe = ObservationMap::new();
        for entity in 0..4 {
            observe.observe(entity, ObsId(entity));
        }
        let observation = build(&Metrics::default(), &observe, 4, 0, 0, 0.0, 1.0);
        assert_eq!(observation.blind_spot, 0.0);
        assert_eq!(observation.coverage(), 1.0);
    }
}

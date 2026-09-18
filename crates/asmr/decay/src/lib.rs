//! Implements A16 (Temporal Decay) and A26 (Patch Latency).
//!
//! The formal object is a weighting over time: evidence does not stay equally
//! informative forever. A26 supplies the other half of the clock — the window
//! during which a known-bad condition is exploitable, which is what turns
//! "we are exposed" into "we are exposed for eleven more days".
//!
//! A SIEM without decay accumulates stale verdicts: a process that looked
//! suspicious an hour ago and has done nothing since should not still be one
//! `log_ratio` away from an isolation order. Decay makes confidence a quantity
//! with a half-life instead of a high-water mark.
#![forbid(unsafe_code)]

/// A half-life over seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HalfLife {
    pub seconds: f64,
}

impl HalfLife {
    /// Clamped to a strictly positive floor so `weight` cannot divide by zero.
    pub fn new(seconds: f64) -> Self {
        // `f64::max` ignores NaN, so a NaN half-life becomes the floor rather
        // than silently making every weight NaN.
        Self {
            seconds: seconds.max(1e-9),
        }
    }

    /// Weight of an observation `age_s` seconds old: `2^(-age / half_life)`.
    pub fn weight(&self, age_s: f64) -> f64 {
        if age_s <= 0.0 {
            return 1.0;
        }
        2f64.powf(-age_s / self.seconds)
    }
}

/// Log-odds that decay as it ages.
#[derive(Debug, Clone)]
pub struct DecayedEvidence {
    hl: HalfLife,
    log_odds: f64,
    last_ns: Option<i64>,
}

impl DecayedEvidence {
    pub fn new(hl: HalfLife) -> Self {
        Self {
            hl,
            log_odds: 0.0,
            last_ns: None,
        }
    }

    /// Add one piece of evidence.
    ///
    /// What we already hold decays over the interval since the last update, and
    /// the incoming observation is itself discounted by its own age — which
    /// matters when replaying a backlog, because a two-hour-old event should
    /// not land with the same force as one from this second.
    pub fn add(&mut self, now_ns: i64, ts_ns: i64, log_ratio: f64) {
        let interval_s = match self.last_ns {
            Some(prev) => (now_ns.saturating_sub(prev) as f64 / 1e9).max(0.0),
            None => 0.0,
        };
        let age_s = (now_ns.saturating_sub(ts_ns) as f64 / 1e9).max(0.0);

        self.log_odds =
            self.log_odds * self.hl.weight(interval_s) + log_ratio * self.hl.weight(age_s);
        self.last_ns = Some(now_ns);
    }

    pub fn log_odds(&self) -> f64 {
        self.log_odds
    }

    pub fn to_prob(&self) -> f64 {
        1.0 / (1.0 + (-self.log_odds).exp())
    }
}

/// A26: how long vulnerabilities have been taking to patch, in days.
#[derive(Debug, Clone, Default)]
pub struct PatchLatency {
    pub observed_days: Vec<f64>,
}

impl PatchLatency {
    pub fn new(days: Vec<f64>) -> Self {
        Self {
            observed_days: days,
        }
    }

    pub fn len(&self) -> usize {
        self.observed_days.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observed_days.is_empty()
    }

    pub fn mean(&self) -> f64 {
        if self.observed_days.is_empty() {
            return 0.0;
        }
        self.observed_days.iter().sum::<f64>() / self.observed_days.len() as f64
    }

    /// Nearest-rank percentile. `q` is clamped to `[0, 1]`; empty input is 0.0.
    pub fn percentile(&self, q: f64) -> f64 {
        if self.observed_days.is_empty() {
            return 0.0;
        }
        let mut sorted = self.observed_days.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = (((sorted.len() - 1) as f64) * q.clamp(0.0, 1.0)).round() as usize;
        sorted[idx]
    }

    /// A26: days of exposure, floored at zero. If the adversary weaponises
    /// faster than we patch, the difference is the window we are open — the
    /// quantity a zero-day response is actually trying to shrink.
    pub fn exposure_days(&self, adversary_weaponization_days: f64) -> f64 {
        (self.mean() - adversary_weaponization_days).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000_000;

    #[test]
    fn half_life_halves_and_never_exceeds_one() {
        let hl = HalfLife::new(60.0);
        assert_eq!(hl.weight(0.0), 1.0);
        assert_eq!(hl.weight(-5.0), 1.0, "future timestamps are not amplified");
        assert!((hl.weight(60.0) - 0.5).abs() < 1e-12);
        assert!((hl.weight(120.0) - 0.25).abs() < 1e-12);
        assert!(hl.weight(30.0) > hl.weight(90.0), "strictly decreasing");
    }

    #[test]
    fn a_zero_half_life_does_not_produce_nan() {
        let hl = HalfLife::new(0.0);
        assert!(hl.seconds > 0.0);
        assert!(hl.weight(1.0).is_finite());
        assert!(HalfLife::new(f64::NAN).weight(1.0).is_finite());
    }

    #[test]
    fn accumulated_evidence_halves_after_one_half_life() {
        let mut e = DecayedEvidence::new(HalfLife::new(60.0));
        e.add(0, 0, 2.0);
        assert_eq!(e.log_odds(), 2.0);

        // One half-life later, with no new evidence: the 2.0 becomes 1.0.
        e.add(60 * S, 60 * S, 0.0);
        assert!((e.log_odds() - 1.0).abs() < 1e-12);

        e.add(120 * S, 120 * S, 0.0);
        assert!((e.log_odds() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn stale_evidence_lands_softer_than_fresh_evidence() {
        let mut fresh = DecayedEvidence::new(HalfLife::new(60.0));
        fresh.add(1_000 * S, 1_000 * S, 3.0);

        let mut stale = DecayedEvidence::new(HalfLife::new(60.0));
        stale.add(1_000 * S, 940 * S, 3.0); // observed one half-life ago
        stale.add(1_000 * S, 940 * S, 0.0); // no further evidence, no further time

        assert!(stale.log_odds() < fresh.log_odds());
        assert!((stale.log_odds() - 1.5).abs() < 1e-12);
    }

    #[test]
    fn probability_tracks_log_odds_without_overflow() {
        let mut e = DecayedEvidence::new(HalfLife::new(60.0));
        assert_eq!(e.to_prob(), 0.5);
        e.add(0, 0, 1e6);
        assert!((e.to_prob() - 1.0).abs() < 1e-9);
        e.add(0, 0, -1e12);
        assert!(e.to_prob() < 1e-9);
    }

    #[test]
    fn percentiles_work_on_unsorted_input() {
        let p = PatchLatency::new(vec![30.0, 5.0, 14.0, 90.0, 1.0]);
        assert_eq!(p.mean(), 28.0);
        assert_eq!(p.percentile(0.0), 1.0);
        assert_eq!(p.percentile(0.5), 14.0);
        assert_eq!(p.percentile(1.0), 90.0);
        assert_eq!(p.percentile(2.0), 90.0, "q is clamped");
        // The input must not be reordered by the call.
        assert_eq!(p.observed_days[0], 30.0);
    }

    #[test]
    fn exposure_floors_at_zero_and_reports_the_window() {
        let p = PatchLatency::new(vec![30.0, 30.0]);
        assert_eq!(p.exposure_days(10.0), 20.0);
        assert_eq!(p.exposure_days(30.0), 0.0);
        assert_eq!(p.exposure_days(90.0), 0.0, "never negative");
        assert_eq!(PatchLatency::new(vec![]).exposure_days(1.0), 0.0);
    }
}

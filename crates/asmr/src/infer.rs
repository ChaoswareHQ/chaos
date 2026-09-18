//! Implements A5 (Uncertainty), A9 (Information Sets), and A24 (Epistemic Uncertainty).
//!
//! Formal objects: log-odds beliefs, likelihood ratios for evidence,
//! the A9 information set of surviving hypotheses with its posterior weights,
//! and the A24 decomposition of total uncertainty into aleatoric (irreducible)
//! and epistemic (reducible) parts.
//!
//! In a SIEM/XDR pipeline this is the belief core: detections enter as
//! likelihood ratios against a prior, the posterior drives decisions, and the
//! A24 split tells an analyst whether more collection would actually help or
//! whether the residual uncertainty is inherent to the phenomenon.
#![forbid(unsafe_code)]

/// Log-odds belief; the natural parameterisation for sequential evidence.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LogOdds(pub f64);

impl LogOdds {
    /// Converts a probability to log-odds. `p` is clamped to `[1e-9, 1-1e-9]`
    /// so the result is always finite.
    pub fn from_prob(p: f64) -> Self {
        let p = p.clamp(1e-9, 1.0 - 1e-9);
        Self((p / (1.0 - p)).ln())
    }

    /// Converts back to a probability using a branch that avoids `exp` overflow
    /// for large `|x|`.
    pub fn to_prob(&self) -> f64 {
        let x = self.0;
        if x >= 0.0 {
            1.0 / (1.0 + (-x).exp())
        } else {
            let e = x.exp();
            e / (1.0 + e)
        }
    }

    /// Adds a log likelihood ratio in place; evidence accumulates additively.
    pub fn add(&mut self, log_lr: f64) {
        self.0 += log_lr;
    }

    /// The neutral belief: odds 1, probability 0.5.
    pub fn zero() -> Self {
        Self(0.0)
    }

    /// Raw log-odds value.
    pub fn get(&self) -> f64 {
        self.0
    }
}

/// Evidence quality: `hit = P(e | malicious)`, `miss = P(e | benign)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Likelihood {
    /// Probability of observing the evidence under the malicious hypothesis.
    pub hit: f64,
    /// Probability of observing the evidence under the benign hypothesis.
    pub miss: f64,
}

impl Likelihood {
    /// Records the two conditional probabilities.
    pub fn new(hit: f64, miss: f64) -> Self {
        Self { hit, miss }
    }

    /// `ln(hit/miss)`, clamped to `[-20, 20]`. Returns 0.0 when either side is
    /// non-positive, since such evidence cannot move a belief.
    pub fn log_ratio(&self) -> f64 {
        if self.hit <= 0.0 || self.miss <= 0.0 {
            0.0
        } else {
            (self.hit / self.miss).ln().clamp(-20.0, 20.0)
        }
    }
}

/// A posterior belief carried as log-odds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Posterior {
    log_odds: LogOdds,
}

impl Posterior {
    /// Starts from a prior probability (clamped like `LogOdds::from_prob`).
    pub fn from_prior(p: f64) -> Self {
        Self {
            log_odds: LogOdds::from_prob(p),
        }
    }

    /// Current probability of the malicious hypothesis.
    pub fn prob(&self) -> f64 {
        self.log_odds.to_prob()
    }

    /// Current log-odds.
    pub fn log_odds(&self) -> f64 {
        self.log_odds.get()
    }

    /// Incorporates one piece of evidence via its log likelihood ratio.
    pub fn observe(&mut self, l: &Likelihood) {
        self.log_odds.add(l.log_ratio());
    }
}

/// The A24 decomposition of total predictive uncertainty.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UncertaintySplit {
    /// Mean entropy across hypotheses; aleatoric plus epistemic.
    pub total: f64,
    /// Entropy of the mean prediction; the irreducible part.
    pub aleatoric: f64,
    /// Reducible part, `(total - aleatoric).max(0)`.
    pub epistemic: f64,
}

/// Splits uncertainty given the mean entropy and the entropy of the mean.
pub fn split_uncertainty(mean_entropy: f64, entropy_of_mean: f64) -> UncertaintySplit {
    UncertaintySplit {
        total: mean_entropy,
        aleatoric: entropy_of_mean,
        epistemic: (mean_entropy - entropy_of_mean).max(0.0),
    }
}

/// An A9 information set: hypotheses reduced to those still consistent with the
/// evidence, with normalised posterior weights.
#[derive(Debug, Clone, PartialEq)]
pub struct InformationSet {
    candidates: Vec<(Box<str>, f64)>,
}

impl InformationSet {
    /// Normalises the weights and drops non-positive or non-finite ones. An
    /// input with no usable mass yields the empty information set.
    pub fn new(hyps: impl IntoIterator<Item = (Box<str>, f64)>) -> Self {
        let kept: Vec<(Box<str>, f64)> = hyps
            .into_iter()
            .filter(|(_, p)| *p > 0.0 && p.is_finite())
            .collect();
        let total: f64 = kept.iter().map(|(_, p)| *p).sum();
        let candidates = if total > 0.0 {
            kept.into_iter().map(|(n, p)| (n, p / total)).collect()
        } else {
            Vec::new()
        };
        Self { candidates }
    }

    /// Number of surviving hypotheses.
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// True when no hypothesis survived.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// The weighted hypotheses in insertion order.
    pub fn candidates(&self) -> &[(Box<str>, f64)] {
        &self.candidates
    }

    /// The maximum-weight hypothesis, first wins on ties.
    pub fn best(&self) -> Option<(&str, f64)> {
        let mut best: Option<&(Box<str>, f64)> = None;
        for c in &self.candidates {
            if best.is_none_or(|b| c.1 > b.1) {
                best = Some(c);
            }
        }
        best.map(|(n, p)| (n.as_ref(), *p))
    }

    /// A9 refinement: keep only hypotheses satisfying the predicate, then
    /// renormalise the surviving weights to sum to one.
    pub fn refine<F: Fn(&str) -> bool>(&self, keep: F) -> InformationSet {
        InformationSet::new(
            self.candidates
                .iter()
                .filter(|(n, _)| keep(n.as_ref()))
                .map(|(n, p)| (n.clone(), *p)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_odds_round_trips_probabilities() {
        for p in [0.001, 0.1, 0.5, 0.9, 0.999] {
            let q = LogOdds::from_prob(p).to_prob();
            assert!((q - p).abs() < 1e-9, "round trip failed at {p}: {q}");
        }
        assert_eq!(LogOdds::from_prob(0.5).get(), 0.0);
        assert_eq!(LogOdds::zero().to_prob(), 0.5);
    }

    #[test]
    fn log_odds_saturates_without_overflow() {
        assert_eq!(LogOdds(1e6).to_prob(), 1.0);
        assert_eq!(LogOdds(-1e6).to_prob(), 0.0);
        assert_eq!(LogOdds(0.0).to_prob(), 0.5);
        let mut x = LogOdds::from_prob(0.5);
        x.add(1.0);
        assert_eq!(x.get(), 1.0);
    }

    #[test]
    fn from_prob_clamps_extremes() {
        assert_eq!(
            LogOdds::from_prob(0.0).get(),
            LogOdds::from_prob(1e-9).get()
        );
        assert_eq!(
            LogOdds::from_prob(-3.0).get(),
            LogOdds::from_prob(1e-9).get()
        );
        assert_eq!(
            LogOdds::from_prob(1.0).get(),
            LogOdds::from_prob(1.0 - 1e-9).get()
        );
    }

    #[test]
    fn likelihood_ratio_is_clamped_and_neutral_on_zero() {
        assert_eq!(Likelihood::new(0.5, 0.5).log_ratio(), 0.0);
        assert_eq!(Likelihood::new(0.0, 0.5).log_ratio(), 0.0);
        assert_eq!(Likelihood::new(0.5, 0.0).log_ratio(), 0.0);
        assert_eq!(Likelihood::new(1.0, 1e-30).log_ratio(), 20.0);
        assert_eq!(Likelihood::new(1e-30, 1.0).log_ratio(), -20.0);
        assert!((Likelihood::new(0.9, 0.1).log_ratio() - 9.0_f64.ln()).abs() < 1e-12);
    }

    #[test]
    fn posterior_moves_exactly_by_the_likelihood_ratio() {
        let mut post = Posterior::from_prior(0.5);
        post.observe(&Likelihood::new(0.9, 0.1));
        assert!((post.prob() - 0.9).abs() < 1e-12);
        // A stronger benign signal overwhelms the prior and the first evidence.
        let mut down = Posterior::from_prior(0.5);
        down.observe(&Likelihood::new(0.1, 0.9));
        assert!((down.prob() - 0.1).abs() < 1e-12);
        assert!((down.log_odds() + 9.0_f64.ln()).abs() < 1e-12);
    }

    #[test]
    fn uncertainty_split_isolates_the_reducible_part() {
        let s = split_uncertainty(1.0, 0.6);
        assert_eq!(s.total, 1.0);
        assert_eq!(s.aleatoric, 0.6);
        assert!((s.epistemic - 0.4).abs() < 1e-12);
        assert!((s.aleatoric + s.epistemic - s.total).abs() < 1e-12);

        // When the mean is more certain than the individual models, epistemic
        // mass clamps to zero rather than going negative.
        let clamped = split_uncertainty(0.2, 0.5);
        assert_eq!(clamped.epistemic, 0.0);
        assert_eq!(clamped.total, 0.2);
        assert_eq!(clamped.aleatoric, 0.5);
    }

    #[test]
    fn information_set_normalises_filters_and_refines() {
        let set = InformationSet::new(vec![
            ("a".into(), 1.0),
            ("b".into(), 3.0),
            ("c".into(), 0.0),
            ("d".into(), -1.0),
        ]);
        assert_eq!(set.len(), 2);
        assert_eq!(set.candidates()[0].0.as_ref(), "a");
        assert_eq!(set.candidates()[0].1, 0.25);
        assert_eq!(set.best(), Some(("b", 0.75)));

        let only_b = set.refine(|h| h == "b");
        assert_eq!(only_b.len(), 1);
        assert_eq!(only_b.best(), Some(("b", 1.0)));

        let none = set.refine(|_| false);
        assert!(none.is_empty());
        assert_eq!(none.best(), None);
        assert!(InformationSet::new(Vec::new()).is_empty());
    }
}

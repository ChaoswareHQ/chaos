//! Implements A8 (Cost and Utility) and A25 (Minimax Response).
//!
//! Formal objects: the cost pair `(C_fp, C_fn)`, the expected-loss vector of
//! acting versus abstaining, regret against the better action, and the A25
//! worst-case (minimax) decision with its robustness inflation.
//!
//! In a SIEM/XDR pipeline this crate converts a posterior into an action: it
//! supplies the alert threshold that a response engine compares against, prices
//! the regret of a wrong call, and offers a distribution-free fallback when the
//! posterior cannot be trusted at all.
#![forbid(unsafe_code)]

/// Relative prices of the two error kinds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Costs {
    /// Cost of acting on a benign entity.
    pub false_positive: f64,
    /// Cost of failing to act on a malicious entity.
    pub false_negative: f64,
}

impl Costs {
    /// Records the two costs.
    pub fn new(false_positive: f64, false_negative: f64) -> Self {
        Self {
            false_positive,
            false_negative,
        }
    }

    /// The threshold theorem: act iff `P(malicious) > C_fp / (C_fp + C_fn)`.
    /// Returns 0.5 when the costs are symmetric and 0.0 when `C_fp == 0`
    /// (which also covers the degenerate case of both costs being zero).
    pub fn threshold(&self) -> f64 {
        let denom = self.false_positive + self.false_negative;
        if denom > 0.0 {
            self.false_positive / denom
        } else {
            0.0
        }
    }
}

/// The A8 action set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Take the response action.
    Act,
    /// Do nothing this round.
    Abstain,
}

/// `(expected loss of acting, expected loss of abstaining)`.
/// Acting costs `C_fp * (1 - p)`; abstaining costs `C_fn * p`.
pub fn expected_loss(p: f64, costs: &Costs) -> (f64, f64) {
    (costs.false_positive * (1.0 - p), costs.false_negative * p)
}

/// Acts iff the expected loss of acting is strictly lower; ties abstain, which
/// reproduces the strict threshold inequality exactly.
pub fn decide(p: f64, costs: &Costs) -> Decision {
    let (act, abstain) = expected_loss(p, costs);
    if act < abstain {
        Decision::Act
    } else {
        Decision::Abstain
    }
}

/// Loss actually suffered minus the loss the better action would have suffered;
/// always non-negative, and zero when the chosen action was optimal.
pub fn regret(p: f64, costs: &Costs, acted: bool) -> f64 {
    let (act, abstain) = expected_loss(p, costs);
    let actual = if acted { act } else { abstain };
    (actual - act.min(abstain)).max(0.0)
}

/// A25 minimax: the action minimising WORST-CASE loss over `p` in `[0, 1]`.
///
/// Acting worst case is `C_fp` (at `p = 0`) and abstaining worst case is `C_fn`
/// (at `p = 1`), so this returns `Act` iff `C_fp <= C_fn`.
///
/// This deliberately ignores the evidence entirely: minimax is the right tool
/// only when the posterior is worthless. Once a calibrated posterior exists,
/// [`decide`] strictly dominates it.
pub fn minimax_decision(p: f64, costs: &Costs) -> Decision {
    let _ = p; // A25 is evidence-blind by construction; the parameter is kept for API symmetry.
    if costs.false_positive <= costs.false_negative {
        Decision::Act
    } else {
        Decision::Abstain
    }
}

/// A25 robust threshold for when the cost estimates themselves are untrustworthy.
///
/// Inflates `C_fp` by `(1 + u)` and deflates `C_fn` by `(1 - u)`, with `u`
/// clamped to `[0, 1)`. Monotone increasing in `u`, approaching 1.0 as `u`
/// approaches 1.0; at `u = 0` it equals [`Costs::threshold`].
pub fn robust_threshold(costs: &Costs, cost_uncertainty: f64) -> f64 {
    let u = cost_uncertainty.clamp(0.0, 1.0 - f64::EPSILON);
    let inflated = costs.false_positive * (1.0 + u);
    let deflated = costs.false_negative * (1.0 - u);
    let denom = inflated + deflated;
    if denom > 0.0 {
        (inflated / denom).clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_matches_cost_ratios() {
        assert!((Costs::new(5.0, 5.0).threshold() - 0.5).abs() < 1e-12);
        assert!((Costs::new(9.0, 1.0).threshold() - 0.9).abs() < 1e-12);
        assert!((Costs::new(1.0, 9.0).threshold() - 0.1).abs() < 1e-12);
        assert_eq!(Costs::new(0.0, 4.0).threshold(), 0.0);
        assert_eq!(Costs::new(0.0, 0.0).threshold(), 0.0);
    }

    #[test]
    fn expected_loss_prices_both_mistakes() {
        let c = Costs::new(4.0, 10.0);
        assert_eq!(expected_loss(0.0, &c), (4.0, 0.0));
        assert_eq!(expected_loss(1.0, &c), (0.0, 10.0));
        assert_eq!(expected_loss(0.5, &c), (2.0, 5.0));
    }

    #[test]
    fn decide_is_exactly_the_threshold_rule() {
        let c = Costs::new(1.0, 3.0); // threshold 0.25
        assert_eq!(decide(0.26, &c), Decision::Act);
        assert_eq!(decide(0.24, &c), Decision::Abstain);
        assert_eq!(decide(0.25, &c), Decision::Abstain); // ties abstain
        // A zero false-positive cost means alert on any positive evidence.
        let free = Costs::new(0.0, 1.0);
        assert_eq!(decide(1e-9, &free), Decision::Act);
    }

    #[test]
    fn regret_is_zero_for_the_better_action_only() {
        let c = Costs::new(2.0, 6.0); // threshold 0.25
        assert_eq!(regret(0.9, &c, true), 0.0); // acting was right
        assert_eq!(regret(0.1, &c, false), 0.0); // abstaining was right
        assert!((regret(0.9, &c, false) - 5.2).abs() < 1e-12); // 5.4 actual - 0.2 better
        assert!((regret(0.1, &c, true) - 1.2).abs() < 1e-12); // 1.8 actual - 0.6 better
        assert!(regret(0.5, &c, true) >= 0.0);
        assert!(regret(0.5, &c, false) >= 0.0);
    }

    #[test]
    fn minimax_ignores_the_evidence_and_prices_worst_cases() {
        let cheap_fp = Costs::new(1.0, 9.0);
        let cheap_fn = Costs::new(9.0, 1.0);
        assert_eq!(minimax_decision(0.999, &cheap_fp), Decision::Act);
        assert_eq!(minimax_decision(0.001, &cheap_fn), Decision::Abstain);
        // Equal worst cases: acting is never worse than abstaining.
        assert_eq!(minimax_decision(0.0, &Costs::new(3.0, 3.0)), Decision::Act);
        // Acting at p=0 loses C_fp; abstaining at p=1 loses C_fn.
        assert_eq!(expected_loss(0.0, &cheap_fp).0, 1.0);
        assert_eq!(expected_loss(1.0, &cheap_fn).1, 1.0);
    }

    #[test]
    fn robust_threshold_is_monotone_and_approaches_one() {
        let c = Costs::new(1.0, 1.0);
        assert!((robust_threshold(&c, 0.0) - c.threshold()).abs() < 1e-12);
        assert!((robust_threshold(&c, 0.25) - 0.625).abs() < 1e-12);
        assert!((robust_threshold(&c, 0.5) - 0.75).abs() < 1e-12);
        assert!((robust_threshold(&c, 0.75) - 0.875).abs() < 1e-12);
        let mut prev = robust_threshold(&c, 0.0);
        for step in 1..=9 {
            let t = robust_threshold(&c, step as f64 / 10.0);
            assert!(
                t > prev || (t - prev).abs() < 1e-15,
                "not monotone at {step}"
            );
            prev = t;
        }
        assert!(robust_threshold(&c, 0.9) > 0.9);
        assert!(robust_threshold(&c, 1.5) <= 1.0);
        assert_eq!(robust_threshold(&Costs::new(0.0, 1.0), 0.5), 0.0);
    }
}

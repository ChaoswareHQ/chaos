//! Implements A7 (Agents and Games), A14 (Adversarial Adaptation) and A29 (Transfer Learning).
//!
//! The formal object is the defender's policy — a distribution over actions —
//! plus its interaction with an adaptive opponent. A SIEM rule that cannot move
//! is a rule the attacker reads once and walks around, so A7 says the defender
//! chooses against an opponent, not against nature.
//!
//! A14 supplies the master equation: a coupled pair in which defence and attack
//! each grow with their own success and shrink under the other's pressure. Its
//! fixed point tells you which side of a detection/evasion race you are on.
//! A29 is the pragmatic half — a likelihood ratio learned elsewhere is worth
//! only as much as the similarity of the environment it is applied to.
#![forbid(unsafe_code)]

/// The defender's mixed strategy over `n` actions.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    probs: Vec<f64>,
}

impl Policy {
    pub fn uniform(n: usize) -> Self {
        Self {
            probs: if n == 0 {
                Vec::new()
            } else {
                vec![1.0 / n as f64; n]
            },
        }
    }

    pub fn len(&self) -> usize {
        self.probs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.probs.is_empty()
    }

    pub fn prob(&self, action: usize) -> f64 {
        self.probs.get(action).copied().unwrap_or(0.0)
    }

    pub fn probs(&self) -> &[f64] {
        &self.probs
    }

    /// The action the defender would play if it had to commit to a single one.
    /// Ties go to the lowest index so the answer is stable across runs.
    pub fn argmax(&self) -> Option<usize> {
        self.probs
            .iter()
            .enumerate()
            .fold(None, |best: Option<(usize, f64)>, (i, p)| match best {
                Some((_, bp)) if bp >= *p => best,
                _ => Some((i, *p)),
            })
            .map(|(i, _)| i)
    }

    /// Regret-matching step: move `rate` of the mass sitting on `decay` over to
    /// `reinforce`, then renormalise.
    ///
    /// Shifting mass rather than nudging a value keeps this a valid
    /// distribution at every step; a policy that quietly stops summing to one
    /// changes what its own probabilities mean.
    pub fn update(&mut self, reinforce: usize, decay: usize, rate: f64) {
        if reinforce == decay || reinforce >= self.probs.len() || decay >= self.probs.len() {
            return;
        }
        let moved = self.probs[decay] * rate.clamp(0.0, 1.0);
        self.probs[decay] -= moved;
        self.probs[reinforce] += moved;
        normalize(&mut self.probs);
    }
}

fn normalize(probs: &mut [f64]) {
    let sum: f64 = probs.iter().sum();
    if sum <= 0.0 {
        probs.fill(1.0 / probs.len() as f64);
        return;
    }
    for p in probs.iter_mut() {
        *p /= sum;
    }
}

/// A14: distance from the best response to the opponent's observed play.
/// `0.0` means the defender is already playing it, `1.0` means it is nowhere.
pub fn drift(policy: &Policy, best_response: usize) -> f64 {
    (1.0 - policy.prob(best_response)).clamp(0.0, 1.0)
}

/// A7: one explicit step of the coupled defender/attacker master equation.
///
/// The logistic terms keep both sides inside `(0, 1)` — neither a defence nor
/// an attack can grow past saturation — and `coupling` is the rate at which
/// each side's progress is cancelled by the other's.
pub fn master_step(
    defense: f64,
    attack: f64,
    coupling: f64,
    progress: f64,
    attack_gain: f64,
    dt: f64,
) -> (f64, f64) {
    let d = defense.clamp(0.0, 1.0);
    let a = attack.clamp(0.0, 1.0);

    let d_defense = d * (1.0 - d) * (progress - a * coupling);
    let d_attack = a * (1.0 - a) * (attack_gain - d * coupling);

    (
        (d + d_defense * dt).clamp(0.0, 1.0),
        (a + d_attack * dt).clamp(0.0, 1.0),
    )
}

/// A29: discount a likelihood ratio learned in another environment.
/// `similarity` is clamped, so `0.0` transfers no evidence at all and `1.0`
/// leaves the source ratio untouched.
pub fn transfer_log_ratio(source_log_ratio: f64, similarity: f64) -> f64 {
    source_log_ratio * similarity.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_policy_is_a_distribution() {
        let p = Policy::uniform(4);
        assert_eq!(p.len(), 4);
        assert_eq!(p.prob(0), 0.25);
        assert!((p.probs().iter().sum::<f64>() - 1.0).abs() < 1e-12);
        assert_eq!(p.argmax(), Some(0), "ties resolve to the lowest index");

        let empty = Policy::uniform(0);
        assert!(empty.is_empty());
        assert_eq!(empty.argmax(), None);
        assert_eq!(empty.prob(3), 0.0);
    }

    #[test]
    fn update_reinforces_without_breaking_the_distribution() {
        let mut p = Policy::uniform(3);
        p.update(2, 0, 0.5);

        assert!(p.prob(2) > p.prob(0), "reinforced action must gain mass");
        assert!((p.probs().iter().sum::<f64>() - 1.0).abs() < 1e-12);
        assert_eq!(p.argmax(), Some(2));
    }

    #[test]
    fn update_is_a_no_op_for_degenerate_arguments() {
        let mut p = Policy::uniform(2);
        let before = p.clone();
        p.update(1, 1, 1.0);
        p.update(9, 0, 1.0);
        p.update(0, 9, 1.0);
        assert_eq!(p, before);
    }

    #[test]
    fn repeated_updates_converge_on_the_reinforced_action() {
        let mut p = Policy::uniform(2);
        for _ in 0..50 {
            p.update(0, 1, 0.5);
        }
        assert!(p.prob(0) > 0.99, "wall-clock mass moved, got {}", p.prob(0));
    }

    #[test]
    fn drift_measures_the_gap_to_the_best_response() {
        let p = Policy::uniform(2);
        assert!((drift(&p, 0) - 0.5).abs() < 1e-12);

        let mut q = Policy::uniform(2);
        q.update(1, 0, 1.0);
        assert_eq!(drift(&q, 1), 0.0, "already playing the best response");
        assert_eq!(drift(&q, 0), 1.0, "playing it never");
    }

    #[test]
    fn the_master_equation_has_a_fixed_point_at_balance() {
        // progress == attack * coupling and attack_gain == defense * coupling
        let (d, a) = master_step(0.5, 0.5, 1.0, 0.5, 0.5, 1.0);
        assert!((d - 0.5).abs() < 1e-12);
        assert!((a - 0.5).abs() < 1e-12);
    }

    #[test]
    fn the_master_equation_moves_toward_whoever_has_the_advantage() {
        // Defender has an edge: its own progress is high and nothing opposes
        // it, while the attacker gains nothing.
        let (d, a) = master_step(0.5, 0.5, 0.0, 1.0, 0.0, 0.1);
        assert!(d > 0.5, "defence should grow, got {d}");
        assert!(
            (a - 0.5).abs() < 1e-12,
            "an attacker with no gain is stationary, not shrinking: {a}"
        );

        // Now the defender exerts enough pressure to reverse the attacker's
        // gain: attack_gain (0.2) < defence (0.9) * coupling (0.5), so the
        // attack term goes negative. This is the case that matters — an
        // attacker only retreats under active pressure.
        let (d2, a2) = master_step(0.9, 0.5, 0.5, 0.1, 0.2, 0.1);
        assert!(a2 < 0.5, "attack should shrink under pressure, got {a2}");
        assert!(
            d2 < 0.9,
            "and defence recedes while the attack is still live"
        );
    }

    #[test]
    fn the_master_equation_stays_in_range_under_a_huge_step() {
        let (d, a) = master_step(0.9, 0.9, -50.0, 500.0, 500.0, 1e6);
        assert!((0.0..=1.0).contains(&d));
        assert!((0.0..=1.0).contains(&a));
    }

    #[test]
    fn transfer_interpolates_between_nothing_and_everything() {
        assert_eq!(transfer_log_ratio(3.0, 0.0), 0.0);
        assert_eq!(transfer_log_ratio(3.0, 1.0), 3.0);
        assert_eq!(transfer_log_ratio(3.0, 0.5), 1.5);
        assert_eq!(transfer_log_ratio(3.0, 9.0), 3.0, "similarity is clamped");
        assert_eq!(transfer_log_ratio(3.0, -1.0), 0.0);
    }
}

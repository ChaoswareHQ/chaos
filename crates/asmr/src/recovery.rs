//! Implements A20 (Recovery and Resilience).
//!
//! The formal object is the recovery operator: the map from a contained
//! incident back to a known-good state, together with its cost in time.
//!
//! Detection gets the attention, but the number a business actually feels is
//! availability, and availability is `MTTF / (MTTF + MTTR)` — an incident that
//! is detected in one second and recovered from in nine hours costs far more
//! than one detected in five minutes and cleared in ten. That is why A20 exists
//! as its own axiom: the pipeline is not finished when it raises an alert, it
//! is finished when the restored state is verified. A30's isolate action is
//! only defensible because this crate can price the way back.
#![forbid(unsafe_code)]

/// One step of a recovery procedure.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryStep {
    pub name: Box<str>,
    pub est_seconds: f64,
    pub parallel: bool,
}

impl RecoveryStep {
    pub fn new(name: &str, est_seconds: f64, parallel: bool) -> Self {
        Self {
            name: name.into(),
            est_seconds: est_seconds.max(0.0),
            parallel,
        }
    }
}

/// An ordered recovery procedure.
#[derive(Debug, Clone, Default)]
pub struct RecoveryPlan {
    steps: Vec<RecoveryStep>,
}

impl RecoveryPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, s: RecoveryStep) {
        self.steps.push(s);
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// A20: MTTR estimate.
    ///
    /// Serial steps add up; a *run* of consecutive parallel steps costs only
    /// its longest member. The run, rather than each step individually, is the
    /// right unit because parallelism only helps while it is sustained — two
    /// parallel steps separated by a serial one cannot overlap.
    pub fn mttr_estimate(&self) -> f64 {
        let mut total = 0.0;
        let mut run: Option<f64> = None;

        for step in &self.steps {
            if step.parallel {
                run = Some(run.map_or(step.est_seconds, |m: f64| m.max(step.est_seconds)));
            } else {
                if let Some(m) = run.take() {
                    total += m;
                }
                total += step.est_seconds;
            }
        }
        if let Some(m) = run {
            total += m;
        }
        total
    }

    /// The worst case where nothing overlaps: the sum of every step. The gap
    /// between this and `mttr_estimate` is the value the parallel steps are
    /// actually delivering.
    pub fn serial_critical_path(&self) -> f64 {
        self.steps.iter().map(|s| s.est_seconds).sum()
    }
}

/// A20: steady-state availability. A system that never fails is available; one
/// with either parameter at zero and the other non-zero is unavailable.
pub fn availability(mttf_hours: f64, mttr_hours: f64) -> f64 {
    let mttf = mttf_hours.max(0.0);
    let mttr = mttr_hours.max(0.0);
    let total = mttf + mttr;
    if total <= 0.0 {
        return 1.0;
    }
    (mttf / total).clamp(0.0, 1.0)
}

/// The three stages a pipeline has to get right.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Resilience {
    pub detection: f64,
    pub containment: f64,
    pub recovery: f64,
}

impl Resilience {
    pub fn new(detection: f64, containment: f64, recovery: f64) -> Self {
        Self {
            detection: detection.clamp(0.0, 1.0),
            containment: containment.clamp(0.0, 1.0),
            recovery: recovery.clamp(0.0, 1.0),
        }
    }

    /// A20: resilience is a product, not a sum. A pipeline with perfect
    /// detection and perfect recovery but no containment recovers nothing,
    /// because the adversary is still inside.
    pub fn score(&self) -> f64 {
        self.detection * self.containment * self.recovery
    }

    /// Where to spend the next engineering hour. Ties resolve in pipeline
    /// order, which is the order an incident actually traverses.
    pub fn weakest_link(&self) -> &'static str {
        if self.detection <= self.containment && self.detection <= self.recovery {
            "detection"
        } else if self.containment <= self.recovery {
            "containment"
        } else {
            "recovery"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_steps_add_up() {
        let mut p = RecoveryPlan::new();
        p.add(RecoveryStep::new("triage", 30.0, false));
        p.add(RecoveryStep::new("rebuild", 600.0, false));
        assert_eq!(p.mttr_estimate(), 630.0);
        assert_eq!(p.serial_critical_path(), 630.0);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn a_run_of_parallel_steps_costs_only_its_longest() {
        let mut p = RecoveryPlan::new();
        p.add(RecoveryStep::new("quarantine", 10.0, false));
        p.add(RecoveryStep::new("scan-a", 5.0, true));
        p.add(RecoveryStep::new("scan-b", 20.0, true));
        p.add(RecoveryStep::new("restore", 3.0, false));
        // 10 + max(5, 20) + 3
        assert_eq!(p.mttr_estimate(), 33.0);
        assert_eq!(p.serial_critical_path(), 38.0);
    }

    #[test]
    fn parallel_steps_separated_by_a_serial_one_do_not_overlap() {
        let mut p = RecoveryPlan::new();
        p.add(RecoveryStep::new("a", 10.0, true));
        p.add(RecoveryStep::new("barrier", 1.0, false));
        p.add(RecoveryStep::new("b", 10.0, true));
        // Two separate runs of length 1: 10 + 1 + 10
        assert_eq!(p.mttr_estimate(), 21.0);
    }

    #[test]
    fn an_empty_plan_costs_nothing() {
        let p = RecoveryPlan::new();
        assert_eq!(p.mttr_estimate(), 0.0);
        assert_eq!(p.serial_critical_path(), 0.0);
        assert!(p.is_empty());
    }

    #[test]
    fn negative_durations_are_clamped() {
        let mut p = RecoveryPlan::new();
        p.add(RecoveryStep::new("bogus", -100.0, false));
        assert_eq!(p.mttr_estimate(), 0.0);
        assert_eq!(p.serial_critical_path(), 0.0);
    }

    #[test]
    fn availability_is_the_mttf_share_of_uptime() {
        assert_eq!(availability(99.0, 1.0), 0.99);
        assert_eq!(availability(1000.0, 0.0), 1.0);
        assert_eq!(availability(0.0, 5.0), 0.0);
        assert_eq!(availability(0.0, 0.0), 1.0, "never-failing and never-fixed");
        assert_eq!(availability(-1.0, -1.0), 1.0);
    }

    #[test]
    fn resilience_is_a_product_and_names_its_weakest_stage() {
        let r = Resilience::new(0.9, 0.9, 0.9);
        assert!((r.score() - 0.729).abs() < 1e-12);
        assert_eq!(
            r.weakest_link(),
            "detection",
            "ties resolve in pipeline order"
        );

        let bad = Resilience::new(0.99, 0.10, 0.99);
        assert_eq!(bad.weakest_link(), "containment");
        assert!(
            bad.score() < 0.11,
            "one weak stage dominates: {}",
            bad.score()
        );

        // Perfect detection cannot rescue no containment.
        assert_eq!(Resilience::new(1.0, 0.0, 1.0).score(), 0.0);
        assert_eq!(Resilience::new(1.0, 1.0, 1.0).score(), 1.0);
    }
}

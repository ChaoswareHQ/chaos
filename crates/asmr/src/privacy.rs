//! Implements A19 (Privacy and Data Minimization).
//!
//! The formal object is a randomised reporting mechanism with a provable
//! disclosure bound, plus the utility cost of that bound.
//!
//! Telemetry is the most sensitive data most organisations hold: process
//! command lines contain credentials typed into the wrong window, file paths
//! contain customer names, DNS queries contain medical conditions. A19 says the
//! pipeline should be able to answer "is this host compromised" without keeping
//! the answer to "what is this employee working on". Two mechanisms here:
//! Laplace noise for a numeric release, and a generalisation bucket that keeps
//! only the file extension.
//!
//! `laplace_noise` takes the uniform input as a *parameter* rather than reading
//! an RNG. That is deliberate: it makes the mechanism deterministic and
//! testable, and it forces the caller to be explicit about where its entropy
//! comes from instead of letting a library choice quietly decide.
#![forbid(unsafe_code)]

/// An `(epsilon, sensitivity)` differential-privacy guarantee.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LaplaceSpec {
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl LaplaceSpec {
    /// `epsilon` is clamped to a strictly positive floor: an infinite epsilon
    /// would advertise privacy that does not exist.
    pub fn new(epsilon: f64, sensitivity: f64) -> Self {
        Self {
            epsilon: epsilon.max(1e-9),
            sensitivity: sensitivity.max(0.0),
        }
    }

    /// The Laplace scale `b = sensitivity / epsilon`.
    pub fn scale(&self) -> f64 {
        self.sensitivity / self.epsilon
    }
}

/// Laplace noise for a uniform input `u` in `[0, 1)`.
///
/// Inverse-CDF sampling, so the distribution is exactly Laplace and the result
/// is antisymmetric: `noise(u) == -noise(1 - u)`.
pub fn laplace_noise(u: f64, spec: &LaplaceSpec) -> f64 {
    let b = spec.scale();
    let u = u.clamp(1e-12, 1.0 - 1e-12);
    if u < 0.5 {
        b * (2.0 * u).ln()
    } else {
        -b * (2.0 - 2.0 * u).ln()
    }
}

/// A19: the price of the guarantee, as the variance of the added noise
/// (`2b^2`). This is what "privacy costs accuracy" means numerically — halving
/// epsilon quadruples the noise power.
pub fn utility_loss(epsilon: f64, sensitivity: f64) -> f64 {
    let spec = LaplaceSpec::new(epsilon, sensitivity);
    2.0 * spec.scale().powi(2)
}

/// A total `epsilon` allowance that is never overdrawn.
#[derive(Debug, Clone, PartialEq)]
pub struct PrivacyBudget {
    spent: f64,
    total: f64,
}

impl PrivacyBudget {
    pub fn new(total_epsilon: f64) -> Self {
        Self {
            spent: 0.0,
            total: total_epsilon.max(0.0),
        }
    }

    pub fn remaining(&self) -> f64 {
        (self.total - self.spent).max(0.0)
    }

    /// Charge `epsilon`. Returns false and charges nothing when the request
    /// would exceed the allowance, or when `epsilon` is not positive.
    ///
    /// Refusing rather than clamping is the point: a mechanism that quietly
    /// spends more than its budget composes into an unbounded disclosure over
    /// many queries.
    pub fn spend(&mut self, epsilon: f64) -> bool {
        if epsilon <= 0.0 || self.spent + epsilon > self.total {
            return false;
        }
        self.spent += epsilon;
        true
    }
}

/// A19: coarsen a path to its extension, e.g. `C:\work\q3\invoice_2024.xlsx`
/// becomes `.xlsx`. Returns `"unknown"` when there is no extension after the
/// final separator, so callers get a value they can act on rather than an empty
/// string they might mistake for absence of data.
pub fn generalisation_bucket(value: &str) -> &str {
    let tail = match value.rfind(['\\', '/']) {
        Some(idx) => &value[idx + 1..],
        None => value,
    };
    match tail.rfind('.') {
        Some(dot) if dot + 1 < tail.len() => &tail[dot..],
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laplace_noise_is_antisymmetric_around_the_median() {
        let spec = LaplaceSpec::new(1.0, 1.0);
        for u in [0.01, 0.1, 0.25, 0.4, 0.49] {
            let a = laplace_noise(u, &spec);
            let b = laplace_noise(1.0 - u, &spec);
            assert!(
                (a + b).abs() < 1e-12,
                "noise({u}) + noise({}) != 0",
                1.0 - u
            );
        }
    }

    #[test]
    fn scale_grows_as_epsilon_falls() {
        let strict = LaplaceSpec::new(0.1, 1.0);
        let loose = LaplaceSpec::new(1.0, 1.0);
        assert!(strict.scale() > loose.scale());
        assert_eq!(loose.scale(), 1.0);
        // Lower epsilon means a wider distribution at the same quantile.
        assert!(laplace_noise(0.01, &strict).abs() > laplace_noise(0.01, &loose).abs());
    }

    #[test]
    fn epsilon_floor_protects_against_an_infinite_guarantee() {
        let spec = LaplaceSpec::new(0.0, 1.0);
        assert!(spec.epsilon > 0.0);
        assert!(spec.scale().is_finite());
    }

    #[test]
    fn utility_loss_quadruples_when_epsilon_halves() {
        let a = utility_loss(1.0, 2.0);
        let b = utility_loss(0.5, 2.0);
        assert!((b / a - 4.0).abs() < 1e-9);
        assert_eq!(a, 8.0); // 2 * (2/1)^2
    }

    #[test]
    fn budget_exhausts_exactly_and_never_overdraws() {
        let mut b = PrivacyBudget::new(1.0);
        assert!(b.spend(0.4));
        assert!(b.spend(0.6));
        assert!((b.remaining() - 0.0).abs() < 1e-12);
        assert!(!b.spend(0.1), "exhausted budget must refuse");
        assert_eq!(b.remaining(), 0.0, "a refused charge costs nothing");

        let mut c = PrivacyBudget::new(1.0);
        assert!(!c.spend(1.5));
        assert_eq!(c.remaining(), 1.0);
        assert!(!c.spend(0.0), "zero-epsilon queries are not free");
        assert!(!c.spend(-1.0));
    }

    #[test]
    fn generalisation_keeps_only_the_extension() {
        assert_eq!(
            generalisation_bucket(r"C:\work\q3\invoice_2024.xlsx"),
            ".xlsx"
        );
        assert_eq!(generalisation_bucket("/var/log/auth.log"), ".log");
        assert_eq!(generalisation_bucket("C:\\a\\b\\payload.exe"), ".exe");
        // A dot in a directory name must not be mistaken for the extension.
        assert_eq!(generalisation_bucket("C:\\my.dir\\README"), "unknown");
        assert_eq!(generalisation_bucket("noext"), "unknown");
        assert_eq!(generalisation_bucket("trailing."), "unknown");
        assert_eq!(generalisation_bucket(""), "unknown");
    }
}

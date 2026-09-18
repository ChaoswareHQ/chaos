//! Implements A18 (Multi-Scale Hierarchy).
//!
//! The formal object is a family of abstraction levels over the same quantity,
//! with coarsening, refinement, and fusion between them.
//!
//! A monitoring system always has more than one scale in play. One process
//! writing 40 files is noise; forty processes each writing one file is
//! ransomware. The event counts are identical, and the only difference is the
//! scale at which you look. `coarsen` is the aggregation step, `fuse` combines
//! the same measurement taken at several scales, and `refinement_delta`
//! measures how much detail a coarse view is hiding — which is the number that
//! tells an analyst whether it is safe to look away from the raw stream.
#![forbid(unsafe_code)]

/// A scale index. Level 0 is the raw stream; each increment doubles the bucket
/// width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Level(pub u8);

impl Level {
    pub fn rank(&self) -> u8 {
        self.0
    }
}

/// Aggregate `values` into `2^level`-wide buckets, replacing each bucket with
/// its mean.
///
/// Level 0 is the identity. A final short bucket is averaged over the elements
/// it actually contains rather than being padded, because padding a sparse tail
/// with zeros would report a drop in activity that never happened.
pub fn coarsen(values: &[f64], level: Level) -> Vec<f64> {
    let width = 1usize << level.rank().min(20);
    if width <= 1 || values.is_empty() {
        return values.to_vec();
    }

    values
        .chunks(width)
        .map(|chunk| chunk.iter().sum::<f64>() / chunk.len() as f64)
        .collect()
}

/// A18: fuse one quantity measured at several scales.
///
/// Weights are clamped to non-negative and normalised. If they carry no weight
/// at all the result degrades to the plain mean, which keeps a misconfigured
/// weight vector from collapsing the answer to zero.
pub fn fuse(levels: &[f64], weights: &[f64]) -> f64 {
    if levels.is_empty() {
        return 0.0;
    }

    let mut weighted = 0.0;
    let mut total_weight = 0.0;
    for (i, value) in levels.iter().enumerate() {
        let w = weights.get(i).copied().unwrap_or(0.0).max(0.0);
        weighted += value * w;
        total_weight += w;
    }

    if total_weight <= 0.0 {
        return levels.iter().sum::<f64>() / levels.len() as f64;
    }
    weighted / total_weight
}

/// A18: total absolute detail lost by the coarse view, over the positions the
/// two share. A large value means the coarse series is not a faithful summary
/// and any threshold applied at that scale is measuring something else.
pub fn refinement_delta(fine: &[f64], coarse: &[f64]) -> f64 {
    fine.iter()
        .zip(coarse.iter())
        .map(|(f, c)| (f - c).abs())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_zero_is_the_identity() {
        let v = vec![1.0, 2.0, 3.0];
        assert_eq!(coarsen(&v, Level(0)), v);
        assert_eq!(coarsen(&[], Level(4)), Vec::<f64>::new());
    }

    #[test]
    fn coarsening_averages_within_buckets() {
        let v = vec![1.0, 3.0, 10.0, 20.0, 5.0, 5.0, 5.0, 5.0];
        assert_eq!(coarsen(&v, Level(1)), vec![2.0, 15.0, 5.0, 5.0]);
        assert_eq!(coarsen(&v, Level(2)), vec![8.5, 5.0]);
    }

    #[test]
    fn a_short_tail_bucket_is_not_padded_with_zeros() {
        // Four elements at width 4 -> one bucket, then a ragged remainder.
        let v = vec![2.0, 4.0, 6.0, 8.0, 10.0, 30.0];
        let coarse = coarsen(&v, Level(2));
        assert_eq!(coarse, vec![5.0, 20.0], "tail mean, not (10+30+0+0)/4");
    }

    #[test]
    fn coarsening_conserves_the_total_mass() {
        let v = vec![2.0, 4.0, 6.0, 8.0, 10.0, 30.0];
        for level in [1u8, 2, 3] {
            let coarse = coarsen(&v, Level(level));
            let width = (1usize << level) as f64;
            // Sum(mean_i * bucket_len_i) == Sum(values)
            let recovered: f64 = coarse
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    let start = i * width as usize;
                    let len = v.len().saturating_sub(start).min(width as usize);
                    m * len as f64
                })
                .sum();
            assert!(
                (recovered - v.iter().sum::<f64>()).abs() < 1e-9,
                "level {level}"
            );
        }
    }

    #[test]
    fn fuse_normalises_weights() {
        assert_eq!(fuse(&[1.0, 3.0], &[1.0, 1.0]), 2.0);
        assert_eq!(fuse(&[1.0, 3.0], &[1.0, 3.0]), 2.5);
        // Scaling every weight must not change the answer.
        assert_eq!(fuse(&[1.0, 3.0], &[10.0, 30.0]), 2.5);
    }

    #[test]
    fn fuse_degrades_gracefully() {
        assert_eq!(fuse(&[], &[]), 0.0);
        assert_eq!(fuse(&[2.0, 4.0], &[]), 3.0, "no weights -> plain mean");
        assert_eq!(
            fuse(&[2.0, 4.0], &[0.0, 0.0]),
            3.0,
            "zero weights -> plain mean"
        );
        assert_eq!(
            fuse(&[2.0, 4.0], &[-1.0, -1.0]),
            3.0,
            "negative weights ignored"
        );
    }

    #[test]
    fn refinement_delta_measures_lost_detail() {
        assert_eq!(refinement_delta(&[1.0, 2.0], &[1.0, 2.0]), 0.0);
        assert_eq!(refinement_delta(&[1.0, 5.0], &[1.0, 2.0]), 3.0);
        // Only the shared prefix counts.
        assert_eq!(refinement_delta(&[1.0, 5.0, 9.0], &[1.0, 2.0]), 3.0);
        assert_eq!(refinement_delta(&[], &[1.0]), 0.0);
    }
}

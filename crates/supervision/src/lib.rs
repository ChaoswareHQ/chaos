//! The supervision policy.
//!
//! Pure decisions about whether a sensor is alive and how to bring it back.
//! The platform half — the `cwatchdog` binary that spawns the sensor, reads
//! the wall clock and waits — lives elsewhere; everything here takes its
//! inputs by argument, so it is testable from literals the way [`observer`] is
//! testable from a mock source.
//!
//! No I/O, no threads, no globals, no dependencies: std only.
//!
//! [`observer`]: ../observer/index.html

/// A sensor's liveness record: how far it has got, and when.
///
/// The sequence number is what makes a restart visible. A fresh process starts
/// counting again, so a `seq` that goes *backwards* is a restart even if the
/// wall-clock stamp keeps climbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    /// Monotonically increasing within one sensor process. A smaller value
    /// than the last one seen means the process was replaced.
    pub seq: u64,
    /// Wall-clock milliseconds, written by the sensor.
    pub at_millis: i64,
}

impl Heartbeat {
    /// Pack into the 16-byte little-endian layout: `seq` in bytes 0..8,
    /// `at_millis` in 8..16.
    ///
    /// Fixed-width and endian-explicit so the pair can agree through a
    /// shared-memory block or a file without either owning the other.
    pub fn encode(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.seq.to_le_bytes());
        out[8..16].copy_from_slice(&self.at_millis.to_le_bytes());
        out
    }

    /// Read the 16-byte layout written by [`Heartbeat::encode`].
    ///
    /// `None` for a slice shorter than 16: a supervisor that has not seen a
    /// full record has not seen a heartbeat, and must not act on a torn one.
    /// Bytes past the record are ignored, so a larger block may carry more.
    pub fn decode(bytes: &[u8]) -> Option<Heartbeat> {
        let seq = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
        let at_millis = i64::from_le_bytes(bytes.get(8..16)?.try_into().ok()?);
        Some(Heartbeat { seq, at_millis })
    }
}

/// How often a heartbeat is expected, and how much slack to allow past that
/// before calling it late.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// Expected gap between heartbeats.
    pub interval_millis: i64,
    /// Extra slack past the interval. Never negative.
    pub grace_millis: i64,
}

impl Cadence {
    /// Build a cadence. A negative grace is clamped to zero: grace is slack,
    /// and negative slack would put the deadline before the interval it is
    /// meant to qualify.
    pub fn new(interval_millis: i64, grace_millis: i64) -> Cadence {
        Cadence {
            interval_millis,
            grace_millis: grace_millis.max(0),
        }
    }

    /// The age, in milliseconds since a heartbeat, at which it stops being
    /// [`Liveness::Alive`]. Saturating, so absurd spans cap rather than wrap.
    pub fn deadline_millis(&self) -> i64 {
        self.interval_millis.saturating_add(self.grace_millis)
    }
}

/// A judgement about a sensor, taken at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// A heartbeat arrived within the deadline.
    Alive,
    /// A heartbeat arrived, but too long ago.
    Stale,
    /// No heartbeat has ever arrived.
    NeverSeen,
}

impl Liveness {
    /// Judge the sensor at `now_millis` against `cadence`.
    ///
    /// `None` is [`Liveness::NeverSeen`], not [`Liveness::Stale`]: a sensor
    /// that has not started is not one that has died, and the platform half
    /// treats a first start differently from a restart.
    ///
    /// A heartbeat exactly at the deadline is still [`Liveness::Alive`] — the
    /// deadline is inclusive, so the boundary belongs to liveness. A clock
    /// that has gone backwards also reads as alive: it is not evidence of a
    /// missed beat.
    pub fn judge(now_millis: i64, last: Option<Heartbeat>, cadence: Cadence) -> Liveness {
        let Some(last) = last else {
            return Liveness::NeverSeen;
        };
        if now_millis <= last.at_millis.saturating_add(cadence.deadline_millis()) {
            Liveness::Alive
        } else {
            Liveness::Stale
        }
    }

    /// Whether the sensor was [`Liveness::Alive`]. The one predicate a caller
    /// should branch on; matching the variant by hand invites treating
    /// `NeverSeen` as dead.
    pub fn is_alive(&self) -> bool {
        matches!(self, Liveness::Alive)
    }
}

/// How to space out restarts.
///
/// Deterministic on purpose: every input is a number, so the same attempt
/// always yields the same delay. Jitter, when an operator wants it, is the
/// caller's to add as an explicit parameter rather than something hidden
/// here, where it would defeat the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    /// Delay before the first restart.
    pub base_millis: i64,
    /// Delay no restart will wait longer than.
    pub ceiling_millis: i64,
    /// Restarts allowed before giving up.
    pub max_attempts: u32,
}

impl RestartPolicy {
    /// The delay before attempt `attempt`, doubling from `base_millis` and
    /// never past `ceiling_millis`. Attempt 0 is the first restart and takes
    /// the base delay.
    ///
    /// Saturating, so a huge attempt caps instead of wrapping to a wrong,
    /// tiny delay.
    pub fn delay_millis(&self, attempt: u32) -> i64 {
        self.base_millis
            .saturating_mul(2i64.saturating_pow(attempt))
            .min(self.ceiling_millis)
    }

    /// Whether attempt `attempt` is within budget.
    ///
    /// `false` once `attempt` reaches `max_attempts`: the count of attempts
    /// already recorded is what decides, so the boundary attempt is refused.
    pub fn should_restart(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }
}

/// What a supervision window saw: beats observed, beats missed, restarts.
///
/// Counted by the platform half and handed here for the arithmetic, so the
/// availability number is a pure function of the window's history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Duty {
    /// Heartbeats that arrived within the deadline.
    pub observed: u64,
    /// Deadlines that passed with no heartbeat.
    pub missed: u64,
    /// Restarts triggered during the window.
    pub restarts: u64,
}

impl Duty {
    /// Count a heartbeat that arrived on time.
    pub fn record_beat(&mut self) {
        self.observed += 1;
    }

    /// Count a deadline that passed with no heartbeat.
    pub fn record_miss(&mut self) {
        self.missed += 1;
    }

    /// Count a restart triggered during the window.
    pub fn record_restart(&mut self) {
        self.restarts += 1;
    }

    /// Fraction of expected beats that arrived: observed / (observed + missed).
    ///
    /// A window with no observations reads as 1.0, not 0.0 or NaN. "No data"
    /// is not "no availability": a supervisor that has not yet had a chance to
    /// watch anything must not report a dead sensor, or every fresh start
    /// would begin by failing its own availability check.
    pub fn availability(&self) -> f64 {
        let expected = self.observed + self.missed;
        if expected == 0 {
            return 1.0;
        }
        self.observed as f64 / expected as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_heartbeat_round_trips_through_its_encoded_form() {
        let hb = Heartbeat {
            seq: 7,
            at_millis: 1_700_000_000_000,
        };
        assert_eq!(Heartbeat::decode(&hb.encode()), Some(hb));
    }

    #[test]
    fn the_layout_is_little_endian_seq_then_stamp() {
        let hb = Heartbeat {
            seq: 0x0102_0304_0506_0708,
            at_millis: -2,
        };
        let bytes = hb.encode();
        assert_eq!(bytes[0..8], 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(bytes[8..16], (-2i64).to_le_bytes());
        // The first byte is the low byte of seq, not the high one.
        assert_eq!(bytes[0], 0x08);
    }

    #[test]
    fn decode_rejects_a_slice_shorter_than_sixteen_bytes() {
        let full = Heartbeat {
            seq: 1,
            at_millis: 2,
        }
        .encode();
        assert!(Heartbeat::decode(&full).is_some());
        assert_eq!(Heartbeat::decode(&full[..15]), None);
        assert_eq!(Heartbeat::decode(&full[..8]), None);
        assert_eq!(Heartbeat::decode(&[]), None);
    }

    #[test]
    fn decode_ignores_bytes_past_the_record() {
        let hb = Heartbeat {
            seq: 5,
            at_millis: 6,
        };
        let mut bytes = hb.encode().to_vec();
        bytes.extend_from_slice(&[0xff; 4]);
        assert_eq!(Heartbeat::decode(&bytes), Some(hb));
    }

    #[test]
    fn a_restart_shows_up_as_the_sequence_going_backwards() {
        let before = Heartbeat::decode(
            &Heartbeat {
                seq: 412,
                at_millis: 1_000,
            }
            .encode(),
        )
        .unwrap();
        let after = Heartbeat::decode(
            &Heartbeat {
                seq: 3,
                at_millis: 1_500,
            }
            .encode(),
        )
        .unwrap();
        // The stamp only climbs, so the sequence is the only evidence.
        assert!(after.at_millis > before.at_millis);
        assert!(after.seq < before.seq);
    }

    #[test]
    fn cadence_clamps_a_negative_grace_to_zero() {
        assert_eq!(Cadence::new(100, -50).grace_millis, 0);
        assert_eq!(Cadence::new(100, 0).grace_millis, 0);
        assert_eq!(Cadence::new(100, 20).grace_millis, 20);
    }

    #[test]
    fn the_deadline_is_interval_plus_grace() {
        assert_eq!(Cadence::new(1_000, 250).deadline_millis(), 1_250);
        assert_eq!(Cadence::new(1_000, -250).deadline_millis(), 1_000);
    }

    #[test]
    fn a_heartbeat_inside_the_window_is_alive() {
        let cadence = Cadence::new(1_000, 100);
        let last = Some(Heartbeat {
            seq: 1,
            at_millis: 10_000,
        });
        assert_eq!(Liveness::judge(10_500, last, cadence), Liveness::Alive);
    }

    #[test]
    fn a_heartbeat_exactly_at_the_deadline_is_still_alive() {
        let cadence = Cadence::new(1_000, 100);
        let last = Some(Heartbeat {
            seq: 1,
            at_millis: 10_000,
        });
        // 10_000 + 1_000 + 100; the boundary belongs to liveness.
        assert_eq!(Liveness::judge(11_100, last, cadence), Liveness::Alive);
    }

    #[test]
    fn a_heartbeat_one_millisecond_past_the_deadline_is_stale() {
        let cadence = Cadence::new(1_000, 100);
        let last = Some(Heartbeat {
            seq: 1,
            at_millis: 10_000,
        });
        assert_eq!(Liveness::judge(11_101, last, cadence), Liveness::Stale);
    }

    #[test]
    fn a_sensor_that_has_never_beaten_is_never_seen() {
        let cadence = Cadence::new(1_000, 100);
        assert_eq!(Liveness::judge(99_999, None, cadence), Liveness::NeverSeen);
    }

    #[test]
    fn a_backwards_clock_is_not_evidence_of_a_missed_beat() {
        let cadence = Cadence::new(1_000, 100);
        let last = Some(Heartbeat {
            seq: 1,
            at_millis: 10_000,
        });
        assert_eq!(Liveness::judge(9_000, last, cadence), Liveness::Alive);
    }

    #[test]
    fn only_alive_counts_as_alive() {
        assert!(Liveness::Alive.is_alive());
        assert!(!Liveness::Stale.is_alive());
        assert!(!Liveness::NeverSeen.is_alive());
    }

    #[test]
    fn delay_starts_at_the_base_and_doubles() {
        let policy = RestartPolicy {
            base_millis: 500,
            ceiling_millis: 60_000,
            max_attempts: 10,
        };
        assert_eq!(policy.delay_millis(0), 500);
        assert_eq!(policy.delay_millis(1), 1_000);
        assert_eq!(policy.delay_millis(2), 2_000);
        assert_eq!(policy.delay_millis(3), 4_000);
    }

    #[test]
    fn delay_is_capped_at_the_ceiling() {
        let policy = RestartPolicy {
            base_millis: 500,
            ceiling_millis: 5_000,
            max_attempts: 10,
        };
        assert_eq!(policy.delay_millis(3), 4_000);
        assert_eq!(policy.delay_millis(4), 5_000);
        assert_eq!(policy.delay_millis(40), 5_000);
    }

    #[test]
    fn delay_saturates_instead_of_overflowing_on_a_huge_attempt() {
        let policy = RestartPolicy {
            base_millis: 500,
            ceiling_millis: i64::MAX,
            max_attempts: u32::MAX,
        };
        // 2^u32::MAX * 500 does not fit in i64; the cap holds the answer.
        assert_eq!(policy.delay_millis(u32::MAX), i64::MAX);
    }

    #[test]
    fn restart_is_budgeted_and_the_boundary_is_refused() {
        let policy = RestartPolicy {
            base_millis: 500,
            ceiling_millis: 5_000,
            max_attempts: 3,
        };
        assert!(policy.should_restart(0));
        assert!(policy.should_restart(1));
        assert!(policy.should_restart(2));
        assert!(!policy.should_restart(3));
        assert!(!policy.should_restart(4));
    }

    #[test]
    fn a_zero_attempt_budget_refuses_the_first_restart() {
        let policy = RestartPolicy {
            base_millis: 500,
            ceiling_millis: 5_000,
            max_attempts: 0,
        };
        assert!(!policy.should_restart(0));
    }

    #[test]
    fn recording_moves_each_counter_once() {
        let mut duty = Duty::default();
        duty.record_beat();
        duty.record_beat();
        duty.record_miss();
        duty.record_restart();
        assert_eq!(duty.observed, 2);
        assert_eq!(duty.missed, 1);
        assert_eq!(duty.restarts, 1);
    }

    #[test]
    fn availability_is_observed_over_expected() {
        let mut duty = Duty::default();
        duty.record_beat();
        duty.record_beat();
        duty.record_beat();
        duty.record_miss();
        // 3 of 4 expected beats arrived.
        assert_eq!(duty.availability(), 0.75);
    }

    #[test]
    fn availability_is_full_when_every_beat_arrived() {
        let mut duty = Duty::default();
        duty.record_beat();
        duty.record_beat();
        assert_eq!(duty.availability(), 1.0);
    }

    #[test]
    fn no_observations_reads_as_full_availability_not_zero() {
        let duty = Duty::default();
        assert_eq!(duty.availability(), 1.0);
    }
}

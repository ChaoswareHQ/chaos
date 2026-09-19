//! When the loop pulls, flushes, reports, and stops.

use std::time::Duration;

/// How the observer schedules its work.
///
/// Every field is a duration or a count, never a policy. A run that bounds
/// itself is a diagnostic; one that runs until stopped is a deployment, and
/// which one this is comes from `deadline`.
#[derive(Debug, Clone)]
pub struct ObserverConfig {
    /// Wire events pulled from the source per iteration. Bounds the memory
    /// the source holds between flushes; a bigger batch means fewer
    /// syscalls and worse latency, and `4096` is the same number the
    /// example uses because it is what fits in an L2 cacheline's worth of
    /// pointer chasing without spilling.
    pub batch: usize,

    /// How long the source may wait for its first event. A timeout, not a
    /// sleep, so an idle host does not stall the loop's own deadlines.
    pub poll: Duration,

    /// How often the sink is flushed. A batch that fills first goes out on
    /// the fill; this is the ceiling on how long a partial batch can sit.
    pub flush: Duration,

    /// How often the heartbeat is printed and `restate` is called. On a
    /// bounded run the whole thing is a diagnostic and this is what tells an
    /// operator it is still alive.
    pub report: Duration,

    /// Stop after this long, measured from the start of `run`.
    /// `None` runs until the handle is stopped, which is deployment.
    pub deadline: Option<Duration>,

    /// Stop after this long with no events. `None` never stops on silence:
    /// a host that is quiet is not a host that is dead, and a sensor that
    /// confuses the two restarts on every overnight window.
    pub idle_timeout: Option<Duration>,

    /// Suppress the heartbeat. The run report still prints.
    pub quiet: bool,
}

impl Default for ObserverConfig {
    fn default() -> Self {
        Self {
            batch: 4096,
            poll: Duration::from_millis(250),
            flush: Duration::from_secs(2),
            report: Duration::from_secs(2),
            deadline: None,
            idle_timeout: None,
            quiet: false,
        }
    }
}

impl ObserverConfig {
    /// Run until the deadline elapses. The bounded diagnostic.
    pub fn for_duration(seconds: u64) -> Self {
        Self {
            deadline: Some(Duration::from_secs(seconds)),
            ..Default::default()
        }
    }

    /// The smallest batch that still fills in a reasonable time on a quiet
    /// host: a laptop's DNS traffic, in practice. Used by tests.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            batch: 16,
            poll: Duration::from_millis(5),
            flush: Duration::from_millis(50),
            report: Duration::from_millis(50),
            deadline: Some(Duration::from_millis(200)),
            idle_timeout: None,
            quiet: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_a_deployment() {
        let c = ObserverConfig::default();
        assert!(c.deadline.is_none(), "no deadline by default");
        assert!(c.idle_timeout.is_none(), "silence is not failure");
        assert!(!c.quiet);
        assert_eq!(c.batch, 4096);
    }

    #[test]
    fn for_duration_sets_only_the_deadline() {
        let c = ObserverConfig::for_duration(30);
        assert_eq!(c.deadline, Some(Duration::from_secs(30)));
        assert_eq!(c.batch, ObserverConfig::default().batch);
        assert_eq!(c.flush, ObserverConfig::default().flush);
    }
}

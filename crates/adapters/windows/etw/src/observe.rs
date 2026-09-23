//! ETW as an [`observer::Observe`] source.
//!
//! [`EtwSession`] already implements [`ports::EventSource`], but that yields
//! raw [`crate::EtwRaw`] — bytes plus a TDH descriptor, which is what a
//! decoder consumes, not what a rule scores. The observer runtime drives a
//! *translated* source, so this module is the one place that joins the two
//! ETW halves: a session and a [`Translator`].
//!
//! The join is not incidental. Translation is stateful — the KCB cache is
//! taught by `OpenKey` events that are never scored themselves, and the
//! shape counters are the sensor report — so a session paired with a fresh
//! translator per batch would both lose correlations and misreport its own
//! coverage. One session, one translator, for the life of the run.
//!
//! # The diagnostic accessors
//!
//! [`observer::Observe`] reports `unmapped`, `undecodable` and a name. The
//! run report needs more than that — the kernel's own loss counters, the
//! per-shape mapping totals, the decode failure log — and those live on the
//! session and the translator, which this type owns. The accessors below
//! are how a caller reads them back after [`observer::Observe::shutdown`],
//! without reaching inside the box the runtime holds.

use crate::{EnableReport, EtwError, EtwSession, SessionConfig, StatsSnapshot, Translator};
use model::{HostId, TelemetryEvent};
use observer::Observe;
use ports::{EventSource, SourceError};
use std::time::Duration;

/// A live ETW session paired with the translator that scores its events.
///
/// Constructed either from a [`SessionConfig`] via [`Self::start`] — the
/// shape `apps/client` uses — or from a session and a translator that were
/// built separately, via [`Self::new`].
pub struct EtwObservation {
    session: EtwSession,
    translator: Translator,
}

impl EtwObservation {
    /// Start a session and pair it with a fresh translator for `host`.
    ///
    /// Returns the adapter and the per-provider enable reports, because
    /// the caller is the one that decides whether a provider that failed to
    /// enable is fatal.
    pub fn start(
        host: HostId,
        config: SessionConfig,
    ) -> Result<(Self, Vec<EnableReport>), EtwError> {
        let (session, reports) = EtwSession::start(config)?;
        Ok((
            Self {
                session,
                translator: Translator::new(host),
            },
            reports,
        ))
    }

    /// Pair an already-started session with a translator.
    pub fn new(session: EtwSession, translator: Translator) -> Self {
        Self {
            session,
            translator,
        }
    }

    /// The underlying session, for a caller that needs the raw handle.
    pub fn session(&self) -> &EtwSession {
        &self.session
    }

    /// The underlying translator.
    pub fn translator(&self) -> &Translator {
        &self.translator
    }

    /// Kernel-side delivery counters: what the sensor received, delivered,
    /// filtered and dropped.
    pub fn stats(&self) -> StatsSnapshot {
        self.session.stats()
    }

    /// Kernel-reported losses: `(EventsLost, RealTimeBuffersLost)`.
    pub fn kernel_lost(&self) -> (u32, u32) {
        self.session.kernel_lost()
    }

    /// Events mapped to a wire shape, over the run.
    pub fn mapped(&self) -> u64 {
        self.translator.mapped()
    }

    /// Scored shapes that could not be decoded. Non-zero is a field-table
    /// bug for this build of Windows, not a quiet host.
    pub fn undecodable(&self) -> u64 {
        self.translator.undecodable()
    }

    /// The decode failures, bounded, for the run report.
    pub fn failures(&self) -> &[String] {
        self.translator.failures()
    }
}

impl Observe for EtwObservation {
    fn next_batch(
        &mut self,
        out: &mut Vec<TelemetryEvent>,
        max: usize,
        timeout: Duration,
    ) -> Result<usize, SourceError> {
        // Destructured so the session and the translator are borrowed
        // separately: `drain_each` holds the session for the duration of the
        // call, and the closure translates each event as it arrives rather
        // than staging a second batch vector.
        let Self {
            session,
            translator,
        } = self;

        let before = out.len();
        session.drain_each(max, timeout, |raw| {
            if let Some(event) = translator.translate(&raw) {
                out.push(event);
            }
        });
        Ok(out.len() - before)
    }

    fn unmapped(&self) -> u64 {
        self.translator.counts().unrecognised()
    }

    fn undecodable(&self) -> u64 {
        self.translator.undecodable()
    }

    fn name(&self) -> &str {
        // The session's name, not the observer's placeholder: two agents on
        // one host must be tellable apart in the heartbeat.
        self.session.name()
    }

    fn shutdown(&mut self) -> Result<(), SourceError> {
        self.session
            .shutdown()
            .map_err(|e| SourceError::Unavailable(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime requires its source to be `Send`. A session is a
    /// `ProcessTrace` thread and a channel, so this is not free, and the
    /// proof belongs next to the type rather than in a build error at the
    /// call site.
    #[test]
    fn the_adapter_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<EtwObservation>();
    }
}

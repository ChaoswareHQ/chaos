//! `cwatchdog` — the supervisor.
//!
//! # What it is for
//!
//! An endpoint agent can be alive and *blind*: the process is running, the
//! console shows a host, and nothing is being collected because the trace
//! session died, a provider was disabled, or the agent is wedged. Process
//! liveness is not the signal worth watching, so this watches two things
//! instead: whether the sensor is still **publishing a heartbeat**, and whether
//! the process it started is still there.
//!
//! # The split with `supervision`
//!
//! Every decision — is this heartbeat stale, how long to wait before the next
//! restart, how available was this window — lives in the `supervision` crate as
//! pure functions over injected numbers, and is tested there with literals. What
//! is left here is the parts that need an operating system: reading a file,
//! spawning a process, sleeping.
//!
//! # It is a speed bump, not a wall
//!
//! A supervisor and the process it supervises usually run under the same token
//! on the same host, so whoever can kill one can kill both. What this buys is
//! that the kill has to be deliberate and quick, and that a *crash* is recovered
//! without a human. The watcher that genuinely survives is off-host: the server
//! knows when a host stops reporting, and that is where silence is finally
//! visible. This publishes its own heartbeat too, so a third party can watch the
//! watcher.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use supervision::{Cadence, Heartbeat, Liveness, RestartPolicy};

fn main() {
    let args = Args::parse();

    let cadence = Cadence::new(
        (args.interval_secs * 1000) as i64,
        (args.grace_secs * 1000) as i64,
    );
    // Backoff is capped well below the ceiling a human would tolerate for a
    // service, because a sensor that is down is a host that is blind: five
    // attempts at 1, 2, 4, 8 and 16 seconds is about half a minute of trying
    // before giving up and saying so.
    let policy = RestartPolicy {
        base_millis: 1_000,
        ceiling_millis: 30_000,
        max_attempts: 5,
    };

    println!(
        "cwatchdog supervising {:?} (heartbeat {}, cadence {}s + {}s grace)",
        args.command.first().map(String::as_str).unwrap_or("<none>"),
        args.heartbeat
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not used".to_string()),
        args.interval_secs,
        args.grace_secs,
    );

    let mut started_at = Instant::now();
    let mut child = spawn(&args.command);
    let mut attempts = 0u32;
    let mut watch_seq = 0u64;

    loop {
        let poll = Duration::from_millis((args.interval_secs * 1000 / 2).max(100));
        std::thread::sleep(poll);

        // Publish our own liveness first: the point of a mutual watch is that
        // both halves are visible, and a watcher nobody can see is a watcher
        // nobody can tell has died.
        if let Some(path) = &args.watch_heartbeat {
            watch_seq += 1;
            publish(path, watch_seq);
        }

        let last = args.heartbeat.as_ref().and_then(|path| read(path));
        let liveness = judge(&args, last, cadence, started_at);

        let exited = match child.as_mut() {
            Some(running) => !matches!(running.try_wait(), Ok(None)),
            None => true,
        };

        if liveness.is_alive() && !exited {
            // Healthy: forget the failures, because a restart budget that never
            // resets turns one bad afternoon into a permanent give-up.
            attempts = 0;
            continue;
        }

        let reason = if exited {
            "the sensor process is gone".to_string()
        } else {
            format!("no heartbeat for {}ms", cadence.deadline_millis())
        };

        if !policy.should_restart(attempts) {
            eprintln!("cwatchdog: {reason}, and the restart budget ({attempts}) is spent");
            std::process::exit(3);
        }

        let delay = policy.delay_millis(attempts);
        attempts += 1;
        eprintln!(
            "cwatchdog: {reason}; restart {attempts}/{} in {delay}ms",
            policy.max_attempts
        );

        // Take the old one down before starting a new one, or two sensors share a
        // host and a trace session name.
        if let Some(mut stale) = child.take() {
            let _ = stale.kill();
            let _ = stale.wait();
        }
        std::thread::sleep(Duration::from_millis(delay.max(0) as u64));
        child = spawn(&args.command);
        started_at = Instant::now();
    }
}

/// Whether the sensor looks alive, given what is available to look at.
fn judge(args: &Args, last: Option<Heartbeat>, cadence: Cadence, started_at: Instant) -> Liveness {
    match (&args.heartbeat, last) {
        // A heartbeat we can read: the ordinary case, decided by the policy.
        (Some(_), Some(_)) => Liveness::judge(now_millis(), last, cadence),
        // No heartbeat yet. Either it has not written one or it never will, and
        // only the clock can tell those apart — so give it one full deadline from
        // the moment it was started before calling it dead. Without this, every
        // restart would be followed immediately by another, because a sensor
        // cannot publish a beat before it has finished starting.
        (Some(_), None) => {
            let deadline = Duration::from_millis(cadence.deadline_millis().max(0) as u64);
            if started_at.elapsed() < deadline {
                Liveness::Alive
            } else {
                Liveness::NeverSeen
            }
        }
        // No heartbeat configured: process exit is the only signal there is.
        (None, _) => Liveness::Alive,
    }
}

fn spawn(command: &[String]) -> Option<Child> {
    let (program, rest) = command.split_first()?;
    match Command::new(program).args(rest).spawn() {
        Ok(child) => Some(child),
        Err(e) => {
            eprintln!("cwatchdog: cannot start {program}: {e}");
            None
        }
    }
}

fn read(path: &Path) -> Option<Heartbeat> {
    let bytes = std::fs::read(path).ok()?;
    Heartbeat::decode(&bytes)
}

/// Write a heartbeat whole, so a reader never sees half of one.
fn publish(path: &Path, seq: u64) {
    let record = Heartbeat {
        seq,
        at_millis: now_millis(),
    }
    .encode();
    let temporary = path.with_extension("tmp");
    if std::fs::write(&temporary, record).is_ok() {
        let _ = std::fs::rename(&temporary, path);
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

struct Args {
    /// The sensor's heartbeat. Without it, only process exit is supervised.
    heartbeat: Option<PathBuf>,
    /// Where to publish this supervisor's own liveness.
    watch_heartbeat: Option<PathBuf>,
    interval_secs: u64,
    grace_secs: u64,
    /// The program to run, and its arguments.
    command: Vec<String>,
}

impl Args {
    fn parse() -> Self {
        let mut args = Args {
            heartbeat: None,
            watch_heartbeat: None,
            interval_secs: 2,
            grace_secs: 6,
            command: Vec::new(),
        };

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--heartbeat" => args.heartbeat = it.next().map(PathBuf::from),
                "--watch-heartbeat" => args.watch_heartbeat = it.next().map(PathBuf::from),
                "--interval" => {
                    if let Some(secs) = it.next().and_then(|v| v.parse::<u64>().ok()) {
                        args.interval_secs = secs.max(1);
                    }
                }
                "--grace" => {
                    if let Some(secs) = it.next().and_then(|v| v.parse::<u64>().ok()) {
                        args.grace_secs = secs;
                    }
                }
                "--help" | "-h" => {
                    println!(
                        "{}",
                        concat!(
                            "cwatchdog — supervise a sensor\n",
                            "\n",
                            "usage: cwatchdog [--heartbeat PATH] [--watch-heartbeat PATH]\n",
                            "                 [--interval SECS] [--grace SECS] -- COMMAND [ARGS...]\n",
                            "\n",
                            "--heartbeat PATH       the sensor's liveness record; without it only\n",
                            "                      the process' exit is supervised\n",
                            "--watch-heartbeat PATH publish this supervisor's own liveness\n",
                            "--interval SECS        how often the sensor is expected to beat, default 2\n",
                            "--grace SECS           how long past that before it counts as stale,\n",
                            "                      default 6; also the startup allowance\n",
                            "\n",
                            "Anything after `--` is the sensor to run and restart.\n",
                        )
                    );
                    std::process::exit(0);
                }
                "--" => {
                    args.command = it.collect();
                    break;
                }
                other => {
                    eprintln!("cwatchdog: unknown argument `{other}`; try --help");
                    std::process::exit(2);
                }
            }
        }

        if args.command.is_empty() {
            eprintln!("cwatchdog: nothing to supervise; pass the sensor after `--`");
            std::process::exit(2);
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_heartbeat_configured_means_only_exit_is_supervised() {
        // A supervisor started without a heartbeat must not treat "never seen" as
        // dead, or it would restart the sensor forever on a host where the
        // heartbeat is simply not configured.
        let args = Args {
            heartbeat: None,
            watch_heartbeat: None,
            interval_secs: 2,
            grace_secs: 6,
            command: vec!["client".to_string()],
        };
        let cadence = Cadence::new(2_000, 6_000);
        assert!(judge(&args, None, cadence, Instant::now()).is_alive());
    }

    #[test]
    fn a_configured_heartbeat_gets_a_startup_allowance() {
        // The bug this prevents: a sensor needs seconds to start, and a
        // supervisor that judges it instantly kills it in a restart loop.
        let args = Args {
            heartbeat: Some(PathBuf::from("nothing-here")),
            watch_heartbeat: None,
            interval_secs: 2,
            grace_secs: 6,
            command: vec!["client".to_string()],
        };
        let cadence = Cadence::new(2_000, 6_000);

        assert!(
            judge(&args, None, cadence, Instant::now()).is_alive(),
            "just started: not yet dead"
        );
        let long_ago = Instant::now() - Duration::from_millis(60_000);
        assert_eq!(
            judge(&args, None, cadence, long_ago),
            Liveness::NeverSeen,
            "long past its deadline with no record at all"
        );
    }
}

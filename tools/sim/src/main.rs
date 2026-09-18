//! Benign adversary simulator.
//!
//! This generates the *shape* of suspicious behaviour so the collector has
//! something to be right or wrong about. It is the defensive half of a red-team
//! exercise: without a controlled source of known-malicious-shaped activity you
//! cannot tell a detector that works from one that never fires.
//!
//! Everything here is harmless and reversible on purpose:
//!
//! * The `powershell -EncodedCommand` payload decodes to `Write-Output`, not to
//!   a download cradle. The encoding is the detectable part; the payload is not.
//! * Files are written to `%TEMP%` with system-process names, then deleted.
//! * The registry key is `HKCU\Software\ChaosSim\Run`. It deliberately is NOT
//!   the real `...\CurrentVersion\Run` autostart key, even though a real
//!   implant would use that and it would be more faithful. This tool has no
//!   business creating working persistence, so it creates something that
//!   *looks* like persistence to a watcher and does nothing.
//! * Network traffic goes to a loopback listener this process owns. Nothing
//!   leaves the machine.
//!
//! Usage:
//!   cargo run -p sim -- --cycles 3
//!   cargo run -p sim -- --scenario chain --cycles 1
//!   cargo run -p sim -- --flood 300      # load generator for throughput tests

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SIM_TEMP_PREFIX: &str = "chaos_sim_";
const SIM_REG_KEY: &str = r"HKCU\Software\ChaosSim\Run";

fn main() {
    let args = Args::parse();

    if args.flood > 0 {
        flood(args.flood);
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let beacon = listener.local_addr().expect("listener address");

    println!("sim: benign suspicious-activity generator");
    println!(
        "sim: {} cycle(s), {} ms apart, beacon {beacon}",
        args.cycles, args.pace_ms
    );
    println!("sim: nothing here persists or leaves this machine\n");

    for cycle in 1..=args.cycles {
        let started = Instant::now();
        println!("--- cycle {cycle}/{} ---", args.cycles);

        if args.wants(Scenario::Chain) {
            scenario_encoded_chain();
        }
        if args.wants(Scenario::Dropper) {
            scenario_temp_dropper();
        }
        if args.wants(Scenario::Registry) {
            scenario_registry_persistence();
        }
        if args.wants(Scenario::Beacon) {
            scenario_beacon(beacon);
        }
        if args.wants(Scenario::Lolbin) {
            scenario_lolbin();
        }
        if args.wants(Scenario::Discovery) {
            scenario_discovery();
        }

        println!("    cycle took {} ms", started.elapsed().as_millis());
        if cycle < args.cycles {
            std::thread::sleep(Duration::from_millis(args.pace_ms));
        }
    }

    // Reap anything a scenario left behind.
    cleanup();
    println!("\nsim: done, temporary artefacts removed");
}

// ---------------------------------------------------------------------------
// scenarios
// ---------------------------------------------------------------------------

/// A script interpreter spawning a second interpreter with an encoded command.
/// The parent/child shape and the `-EncodedCommand` flag are the signal; the
/// decoded payload is a no-op.
fn scenario_encoded_chain() {
    let payload = utf16le("Write-Output 'chaos-sim: benign'");
    let encoded = base64(&payload);
    println!(
        "  [chain]     cmd.exe -> powershell.exe -EncodedCommand ({} bytes)",
        encoded.len()
    );

    quiet_command("cmd.exe", &[
        "/C",
        &format!("powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}"),
    ]);
}

/// Write a file into %TEMP% carrying a system binary's name, then remove it.
/// Masquerading plus a dropper-shaped write, with no payload.
fn scenario_temp_dropper() {
    let path = std::env::temp_dir().join(format!("{SIM_TEMP_PREFIX}svchost_update.exe"));
    println!("  [dropper]   write {}", path.display());

    if let Ok(mut f) = std::fs::File::create(&path) {
        // Not an executable: the name is the whole point.
        let _ = f.write_all(b"chaos-sim: this is text, not a PE\n");
        let _ = f.flush();
        drop(f);

        // A second write, to a sibling "config", mimics the config-drop pattern.
        let cfg = std::env::temp_dir().join(format!("{SIM_TEMP_PREFIX}config.dat"));
        if let Ok(mut c) = std::fs::File::create(&cfg) {
            let _ = c.write_all(b"beacon_interval=60\n");
        }
    }
}

/// Create a Run-shaped registry key under our own subtree, then show it. A real
/// implant would target the autostart key; see the module docs for why this one
/// does not.
fn scenario_registry_persistence() {
    println!("  [registry]  set {SIM_REG_KEY}");
    quiet_command(
        "reg.exe",
        &[
            "add",
            SIM_REG_KEY,
            "/v",
            "WindowsUpdate",
            "/t",
            "REG_SZ",
            "/d",
            "C:\\Users\\Public\\chaos_sim_update.exe",
            "/f",
        ],
    );
}

/// Open and close a connection to our own loopback listener: the connect /
/// short-lived-flow shape of a beacon, without a destination.
fn scenario_beacon(addr: std::net::SocketAddr) {
    println!("  [beacon]    connect {addr}");
    if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        let _ = s.write_all(b"chaos-sim-beacon\n");
        let _ = s.flush();
    }
}

/// A signed Windows binary doing something it does not normally do. Classic
/// living-off-the-land shape; `-hashfile` is benign.
fn scenario_lolbin() {
    let path = std::env::temp_dir().join(format!("{SIM_TEMP_PREFIX}svchost_update.exe"));
    if !path.exists() {
        let _ = std::fs::File::create(&path);
    }
    println!(
        "  [lolbin]    certutil.exe -hashfile {}",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    quiet_command(
        "certutil.exe",
        &["-hashfile", &path.to_string_lossy(), "MD5"],
    );
}

/// Rapid host and account enumeration in one short burst.
fn scenario_discovery() {
    println!("  [discovery] whoami, net user, tasklist");
    quiet_command("whoami.exe", &[]);
    quiet_command("net.exe", &["user"]);
    quiet_command("tasklist.exe", &["/fo", "csv", "/nh"]);
}

// ---------------------------------------------------------------------------
// load generation
// ---------------------------------------------------------------------------

/// Spawn short-lived processes back to back. Each process start costs one
/// Kernel-Process event and roughly twenty ImageLoad events, so this is the
/// cheapest way to push the collector into five figures of events per second
/// while staying entirely benign.
fn flood(count: u32) {
    println!("sim: flood mode, spawning {count} short-lived processes");
    let started = Instant::now();

    for i in 0..count {
        quiet_command("cmd.exe", &["/C", "exit 0"]);
        if i % 100 == 0 && i > 0 {
            let secs = started.elapsed().as_secs_f64();
            println!("    {i}/{count}  ({:.0} proc/s)", i as f64 / secs);
        }
    }

    let secs = started.elapsed().as_secs_f64();
    println!(
        "sim: spawned {count} processes in {secs:.2}s ({:.0} proc/s)",
        count as f64 / secs
    );
}

// ---------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------

/// Run a program with output discarded. The simulator is generating telemetry,
/// not results, and a chatty `tasklist` would bury the interesting lines.
fn quiet_command(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn cleanup() {
    let _ = Command::new("reg.exe")
        .args(["delete", SIM_REG_KEY, "/f"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(SIM_TEMP_PREFIX)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// PowerShell's `-EncodedCommand` takes UTF-16LE, not UTF-8.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);

        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Chain,
    Dropper,
    Registry,
    Beacon,
    Lolbin,
    Discovery,
}

struct Args {
    cycles: u32,
    pace_ms: u64,
    scenario: Option<Scenario>,
    flood: u32,
}

impl Args {
    fn parse() -> Self {
        let mut args = Args {
            cycles: 3,
            pace_ms: 400,
            scenario: None,
            flood: 0,
        };

        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            match flag.as_str() {
                "--cycles" => {
                    args.cycles = it.next().and_then(|v| v.parse().ok()).unwrap_or(3).max(1)
                }
                "--pace-ms" => args.pace_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(400),
                "--flood" => args.flood = it.next().and_then(|v| v.parse().ok()).unwrap_or(200),
                "--scenario" => args.scenario = it.next().and_then(|v| Self::parse_scenario(&v)),
                "--help" | "-h" => {
                    println!(
                        "usage: sim [--cycles N] [--pace-ms M] [--flood N] [--scenario NAME]\n\
                         scenarios: chain, dropper, registry, beacon, lolbin, discovery"
                    );
                    std::process::exit(0);
                }
                other => eprintln!("sim: ignoring unknown argument `{other}`"),
            }
        }
        args
    }

    fn parse_scenario(name: &str) -> Option<Scenario> {
        match name {
            "chain" => Some(Scenario::Chain),
            "dropper" => Some(Scenario::Dropper),
            "registry" => Some(Scenario::Registry),
            "beacon" => Some(Scenario::Beacon),
            "lolbin" => Some(Scenario::Lolbin),
            "discovery" => Some(Scenario::Discovery),
            other => {
                eprintln!("sim: unknown scenario `{other}`");
                None
            }
        }
    }

    fn wants(&self, s: Scenario) -> bool {
        self.scenario.is_none_or(|want| want == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn utf16le_is_twice_the_length_for_bmp_text() {
        assert_eq!(utf16le("A").len(), 2);
        assert_eq!(utf16le("AB"), vec![0x41, 0x00, 0x42, 0x00]);
    }
}

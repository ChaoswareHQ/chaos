//! A synthetic workload, for measuring the sensor against something other than
//! an idle desktop.
//!
//! A quiet host produces about 3,000 raw events per second, almost all of them
//! `Kernel-Registry` reads the shape table does not score. That is a fine
//! smoke test and a useless benchmark: the decode path is idle 99% of the time
//! and every number the capture reports is a number about the host, not about
//! the sensor.
//!
//! This drives the three providers the sensor actually decodes:
//!
//! * `Kernel-File` — create, write, rename, delete in a private temp
//!   directory. Each iteration produces a create (id 12), a rename (20), a
//!   delete (27), and a handful of close/write events the shape table does
//!   not score. The first three are **mapped** shapes, so each one costs a
//!   full decode.
//! * `Kernel-Registry` — open, query, and close a key.
//! * `Kernel-Process` — spawn a short-lived process, which is also the
//!   cheapest way to produce a burst of `ImageLoad` events: every DLL the
//!   child imports is one.
//!
//! # It is bounded, deliberately
//!
//! The run is measured in *operations*, not seconds, because the point is to
//! compare two builds of the sensor against the same workload. A
//! wall-clock-bounded generator does less work on a machine that is busy
//! encoding, which would make the busier build look faster.
//!
//! # What it does not do
//!
//! It does not require elevation, it does not write outside its own temp
//! directory, and it does not modify the registry: every registry operation is
//! a read. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
//! is opened, queried, and closed.
//!
//! Run it alongside the capture:
//!
//! ```text
//! cargo run --release --example etw_load -p etw
//! cargo run --release --example etw_load -p etw -- 5000 20000 30 4
//!                                                      │    │     │  └ threads
//!                                                      │    │     └ process spawns
//!                                                      │    └ registry ops
//!                                                      └ file ops per thread
//! ```

#[cfg(windows)]
mod load {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use std::time::Instant;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_READ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
    };
    use windows::core::PCWSTR;

    /// File-system operations per worker thread.
    const DEFAULT_FILE_OPS: u64 = 20_000;
    /// Registry open/query/close triples.
    const DEFAULT_REG_OPS: u64 = 40_000;
    /// Process spawns.
    const DEFAULT_SPAWNS: u64 = 40;
    /// Worker threads for the file loop.
    const DEFAULT_THREADS: u64 = 4;

    pub fn run() {
        let args: Vec<u64> = std::env::args()
            .skip(1)
            .filter_map(|a| a.parse().ok())
            .collect();
        let file_ops = args.first().copied().unwrap_or(DEFAULT_FILE_OPS);
        let reg_ops = args.get(1).copied().unwrap_or(DEFAULT_REG_OPS);
        let spawns = args.get(2).copied().unwrap_or(DEFAULT_SPAWNS);
        let threads = args.get(3).copied().unwrap_or(DEFAULT_THREADS).max(1);

        println!("=== ETW load ===");
        println!("  file ops   {file_ops} x {threads} threads");
        println!("  reg ops    {reg_ops}");
        println!("  spawns     {spawns}");

        let dir = scratch_directory();
        let started = Instant::now();

        let mut workers = Vec::with_capacity(threads as usize + 2);
        for worker in 0..threads {
            let dir = dir.join(format!("w{worker}"));
            workers.push(thread::spawn(move || file_worker(&dir, file_ops)));
        }
        workers.push(thread::spawn(move || registry_worker(reg_ops)));
        workers.push(thread::spawn(move || spawn_worker(spawns)));

        let ops: u64 = workers.into_iter().map(|w| w.join().unwrap_or(0)).sum();
        let wall = started.elapsed();
        let _ = fs::remove_dir_all(&dir);

        println!(
            "  {ops} operations in {:.2}s ({:.0}/s)",
            wall.as_secs_f64(),
            ops as f64 / wall.as_secs_f64().max(f64::MIN_POSITIVE)
        );
    }

    /// A private directory to churn files in, so the workload cannot touch
    /// anything a user would miss.
    fn scratch_directory() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("chaos-etw-load-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    /// Create, write, rename, delete. Returns the number of operations
    /// performed.
    ///
    /// `a.tmp` and `b.tmp` are reused rather than generated per iteration: a
    /// unique name per operation would spend most of the loop inside the
    /// allocator, and the kernel does not care which name it reports.
    fn file_worker(dir: &Path, ops: u64) -> u64 {
        if fs::create_dir_all(dir).is_err() {
            return 0;
        }
        let a = dir.join("a.tmp");
        let b = dir.join("b.tmp");
        let mut done = 0;

        for _ in 0..ops {
            if File::create(&a)
                .and_then(|mut f| f.write_all(b"chaos"))
                .is_err()
            {
                continue;
            }
            let _ = fs::rename(&a, &b);
            let _ = fs::remove_file(&b);
            done += 1;
        }
        done
    }

    /// Open, query, close. Returns the number of operations performed.
    fn registry_worker(ops: u64) -> u64 {
        let path: Vec<u16> = r"Software\Microsoft\Windows\CurrentVersion\Run"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value: Vec<u16> = "chaos".encode_utf16().chain(std::iter::once(0)).collect();

        let mut done = 0;
        for _ in 0..ops {
            let mut key = HKEY::default();
            // SAFETY: both strings are NUL-terminated and live for the call.
            let rc = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(path.as_ptr()),
                    None,
                    KEY_READ,
                    &mut key,
                )
            };
            if rc.is_err() {
                continue;
            }
            let mut size = 0u32;
            // SAFETY: `key` is open and `value` is NUL-terminated. A
            // `FILE_NOT_FOUND` here is the expected outcome on a host with no
            // `chaos` value, and it still produces the query event.
            let _ = unsafe {
                RegQueryValueExW(
                    key,
                    PCWSTR(value.as_ptr()),
                    None,
                    None,
                    None,
                    Some(&mut size),
                )
            };
            // SAFETY: `key` came from `RegOpenKeyExW` and is closed once.
            let _ = unsafe { RegCloseKey(key) };
            done += 1;
        }
        done
    }

    /// Spawn a short-lived process. Returns the number of spawns performed.
    fn spawn_worker(spawns: u64) -> u64 {
        let mut done = 0;
        for _ in 0..spawns {
            // `cmd /c exit` is the cheapest thing that is still a real process
            // creation, with a real image-load burst behind it.
            let _ = Command::new("cmd.exe").args(["/c", "exit"]).status();
            done += 1;
        }
        done
    }
}

#[cfg(windows)]
fn main() {
    load::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This example requires Windows.");
}

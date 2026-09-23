//! A durable, rotated, retained log of the facts the store is built from.
//!
//! The store is in memory, which makes its `max_alerts`/`max_batches` bounds
//! meaningful only until the next restart: after one, `enforce_retention` has
//! nothing left to bound. The journal is the other half. Every enrollment and
//! every accepted batch is written down, and startup replays the file through
//! the same code the live path runs, so a restart is invisible in the rebuilt
//! state.
//!
//! # What a record is
//!
//! Two facts, not a copy of the store: a host enrolled, or a batch was accepted.
//! Recording *what happened* rather than *what the state became* means a later
//! change to how the store folds alerts into rows still applies to old data, and
//! the file does not grow with the retention cap or with every evicted row.
//!
//! [`Record::Ingest`] carries the server's clock reading at the moment the batch
//! was accepted. Replay uses that and never reads the wall clock, or a restart
//! would re-stamp every row with the time the server came back up.
//!
//! # Framing and the torn tail
//!
//! Each record is a `u32` little-endian length followed by that many bytes of
//! JSON. The length is what makes a half-written record findable: a record whose
//! prefix or body is short is the process having died mid-write, and without the
//! prefix there is no way to tell that from a valid shorter record.
//!
//! A torn tail is the one thing this file is allowed to lose, and it is
//! discarded deliberately and loudly: everything before it is kept, the file is
//! cut back to the last good boundary, and a warning naming the path and offset
//! goes to stderr. A record whose body is complete but does not parse is *not* a
//! torn tail — that is corruption, and opening fails rather than quietly
//! dropping something that looked whole.
//!
//! # Rotation, retention, and what "durable" means here
//!
//! Segments rotate at `max_segment_bytes` and only `retain_segments` of them are
//! kept, oldest deleted first, so a server that has run for a year does not try
//! to hold a year of batches in memory at startup.
//!
//! [`Journal::append`] writes and flushes but deliberately does **not** `fsync`.
//! The honest claim is that the file survives the process dying, not the machine
//! losing power: a clean crash leaves the OS page cache intact, a power cut does
//! not. Flushing every batch to stable storage would cost more than telemetry is
//! worth on a host producing thousands of events a second, and the worst case
//! loses only the few seconds an agent will happily resend.

use crate::store::{HostRecord, IncomingAlert};
use chrono::{DateTime, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// One durable fact: either a host enrolled, or a batch was accepted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Host {
        record: HostRecord,
    },
    Ingest {
        host_id: String,
        batch_id: String,
        events: usize,
        alerts: Vec<IncomingAlert>,
        /// When the server accepted this batch. Authoritative on replay.
        at: DateTime<Utc>,
    },
}

const SEGMENT_PREFIX: &str = "journal-";
const SEGMENT_SUFFIX: &str = ".log";

/// Ten digits so a plain directory listing sorts into write order.
const SEQUENCE_DIGITS: usize = 10;

/// What the journal holds, for the startup banner and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalStats {
    /// Segments retained, including the one being appended to.
    pub segments: usize,
    /// Records read back during [`Journal::open`].
    pub replayed: usize,
    /// Torn records discarded from the end of a segment.
    pub skipped: usize,
    /// Bytes held across the retained segments.
    pub bytes: u64,
}

/// An append-only log of [`Record`]s, split into rotated segments.
pub struct Journal {
    dir: PathBuf,
    max_segment_bytes: u64,
    retain_segments: usize,
    /// Sequence numbers of the retained segments, oldest first.
    segments: Vec<u64>,
    active: u64,
    writer: BufWriter<File>,
    /// Bytes in the active segment, so rotation does not have to stat per append.
    active_bytes: u64,
    bytes: u64,
    replayed: usize,
    skipped: usize,
}

fn segment_path(dir: &Path, sequence: u64) -> PathBuf {
    dir.join(format!(
        "{SEGMENT_PREFIX}{sequence:0width$}{SEGMENT_SUFFIX}",
        width = SEQUENCE_DIGITS
    ))
}

/// The sequence number a segment's name encodes, or `None` for anything else in
/// the directory. Strict about the width so an unrelated file cannot be mistaken
/// for a segment and truncated.
fn parse_sequence(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(SEGMENT_PREFIX)?
        .strip_suffix(SEGMENT_SUFFIX)?;
    if digits.len() != SEQUENCE_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn list_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some(sequence) = parse_sequence(&name) {
            found.push((sequence, entry.path()));
        }
    }
    found.sort_by_key(|(sequence, _)| *sequence);
    Ok(found)
}

/// Parse one segment's bytes, appending every record to `records`.
///
/// Returns the offset of a torn tail when there is one, which is the only signal
/// that the file needs cutting back. A body that is present but unparseable is an
/// error: that is damaged data, not an interrupted write, and pretending
/// otherwise would hide it.
fn parse_segment(path: &Path, raw: &[u8]) -> io::Result<(Vec<Record>, Option<u64>)> {
    let mut records = Vec::new();
    let mut offset = 0usize;

    while offset < raw.len() {
        if raw.len() - offset < 4 {
            return Ok((records, Some(offset as u64)));
        }
        let mut header = [0u8; 4];
        header.copy_from_slice(&raw[offset..offset + 4]);
        let length = u32::from_le_bytes(header) as usize;

        let body_start = offset + 4;
        if length > raw.len() - body_start {
            return Ok((records, Some(offset as u64)));
        }

        let body = &raw[body_start..body_start + length];
        let record = serde_json::from_slice(body).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: unreadable journal record at byte {offset}: {e}",
                    path.display()
                ),
            )
        })?;
        records.push(record);
        offset = body_start + length;
    }

    Ok((records, None))
}

impl Journal {
    /// Open or create a journal directory, replay the retained segments, and
    /// position the writer on the newest segment ready to append.
    ///
    /// Applies retention before replaying, so the records returned are exactly
    /// the ones the server will come back with. A torn tail in any segment is
    /// truncated and reported on stderr; a segment whose JSON does not parse
    /// fails the open.
    pub fn open(
        dir: &Path,
        max_segment_bytes: u64,
        retain_segments: usize,
    ) -> io::Result<(Journal, Vec<Record>)> {
        fs::create_dir_all(dir)?;

        let mut existing = list_segments(dir)?;
        let retain = retain_segments.max(1);
        if existing.len() > retain {
            // Drop the oldest beyond the cap before reading any of them, so a
            // long-running server does not pay to replay what it will not keep.
            for (_, path) in existing.drain(..existing.len() - retain) {
                if let Err(e) = fs::remove_file(&path) {
                    eprintln!(
                        "warning: could not remove old journal segment {}: {e}",
                        path.display()
                    );
                }
            }
        }

        let mut records = Vec::new();
        let mut skipped = 0usize;
        let mut bytes = 0u64;
        let mut segments = Vec::with_capacity(existing.len());
        for (sequence, path) in &existing {
            let raw = fs::read(path)?;
            let (parsed, torn) = parse_segment(path, &raw)?;
            records.extend(parsed);

            let good = torn.unwrap_or(raw.len() as u64);
            if let Some(offset) = torn {
                // The process died mid-write. Keep everything written before the
                // torn record and cut the file back to a record boundary so the
                // next append starts clean.
                eprintln!(
                    "warning: discarding a torn journal record at {} byte {offset} \
                     (interrupted write); truncating",
                    path.display()
                );
                OpenOptions::new().write(true).open(path)?.set_len(good)?;
                skipped += 1;
            }
            bytes += good;
            segments.push(*sequence);
        }

        let active = match segments.last().copied() {
            Some(sequence) => sequence,
            None => {
                segments.push(0);
                0
            }
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(segment_path(dir, active))?;
        let active_bytes = file.metadata()?.len();

        let journal = Journal {
            dir: dir.to_path_buf(),
            max_segment_bytes: max_segment_bytes.max(1),
            retain_segments: retain,
            segments,
            active,
            writer: BufWriter::new(file),
            active_bytes,
            bytes,
            replayed: records.len(),
            skipped,
        };
        Ok((journal, records))
    }

    /// Write one record and flush it.
    ///
    /// Flushed, not synchronized: this survives the process dying, not the
    /// machine losing power. See the module documentation for why that is the
    /// deliberate trade rather than an oversight.
    pub fn append(&mut self, record: &Record) -> io::Result<()> {
        let body = serde_json::to_vec(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let length = u32::try_from(body.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "journal record does not fit a 4 GiB length prefix",
            )
        })?;

        if self.active_bytes >= self.max_segment_bytes {
            self.rotate()?;
        }

        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(&body)?;
        self.writer.flush()?;

        let written = 4 + body.len() as u64;
        self.active_bytes += written;
        self.bytes += written;
        Ok(())
    }

    pub fn stats(&self) -> JournalStats {
        JournalStats {
            segments: self.segments.len(),
            replayed: self.replayed,
            skipped: self.skipped,
            bytes: self.bytes,
        }
    }

    /// Close the active segment and start the next one.
    ///
    /// Rotation is lazy — it happens before the write that would overflow the
    /// bound — so a quiet server never leaves an empty segment behind, and the
    /// file that a restart opens is always the one with data in it.
    fn rotate(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        let next = self.active + 1;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(segment_path(&self.dir, next))?;

        // Assigning drops the previous writer, which is the point: the file it
        // held is about to be deleted on Windows, where an open handle blocks
        // that.
        self.writer = BufWriter::new(file);
        self.active = next;
        self.active_bytes = 0;
        self.segments.push(next);

        self.enforce_retention();
        Ok(())
    }

    /// Delete the oldest segments beyond the cap. Best-effort: failing to remove
    /// an old segment must not fail the append that triggered the rotation, so it
    /// is logged and the file is left for the next attempt.
    fn enforce_retention(&mut self) {
        while self.segments.len() > self.retain_segments {
            let oldest = self.segments.remove(0);
            let path = segment_path(&self.dir, oldest);
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            match fs::remove_file(&path) {
                Ok(()) => self.bytes = self.bytes.saturating_sub(size),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => eprintln!(
                    "warning: could not remove old journal segment {}: {e}",
                    path.display()
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, Store};
    use model::Severity;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    /// A unique directory per test. `temp_dir` is shared between test binaries
    /// and between runs, so the name carries the test, the process, and a
    /// counter, and any stale copy is cleared first.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chaos-journal-{name}-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn host(id: &str) -> HostRecord {
        HostRecord {
            host_id: id.to_string(),
            hostname: format!("host-{id}"),
            os: "windows".to_string(),
            secret_hash: [7u8; 32],
            enrolled_at: Utc::now(),
            last_seen: Utc::now(),
            events: 0,
            alerts: 0,
        }
    }

    fn alert(rule: &str, id: &str) -> IncomingAlert {
        IncomingAlert {
            alert_id: id.to_string(),
            rule_id: rule.to_string(),
            severity: Severity::High,
            title: format!("title for {rule}"),
            description: format!("description for {rule}"),
            technique: "T1059.001".to_string(),
            count: 1,
        }
    }

    fn segment_files(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name();
                parse_sequence(name.to_str()?).map(|_| entry.path())
            })
            .collect()
    }

    #[test]
    fn the_journal_can_move_between_threads() {
        fn assert_send<T: Send>() {}
        assert_send::<Journal>();
    }

    #[test]
    fn a_record_survives_reopening_the_journal() {
        let dir = scratch("reopen");
        let written = Record::Host { record: host("a") };
        {
            let (mut journal, records) = Journal::open(&dir, 1 << 20, 8).unwrap();
            assert!(records.is_empty(), "a fresh journal has nothing to replay");
            journal.append(&written).unwrap();
        }

        let (journal, records) = Journal::open(&dir, 1 << 20, 8).unwrap();
        assert_eq!(records, vec![written], "what was written comes back");
        assert_eq!(journal.stats().replayed, 1);
        assert_eq!(journal.stats().skipped, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_tail_is_discarded_not_fatal() {
        let dir = scratch("torn");
        let first = Record::Host { record: host("a") };
        let second = Record::Host { record: host("b") };
        {
            let (mut journal, _) = Journal::open(&dir, 1 << 20, 8).unwrap();
            journal.append(&first).unwrap();
            journal.append(&second).unwrap();
        }

        // A length prefix promising far more bytes than follow: the process died
        // between the header and the body.
        let path = segment_path(&dir, 0);
        let good = fs::metadata(&path).unwrap().len();
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&400u32.to_le_bytes()).unwrap();
            file.write_all(b"{\"kind\":\"host\"").unwrap();
            file.flush().unwrap();
        }

        let (journal, records) = Journal::open(&dir, 1 << 20, 8).unwrap();
        assert_eq!(
            records,
            vec![first, second],
            "the records before the tear survive"
        );
        assert_eq!(journal.stats().replayed, 2);
        assert_eq!(
            journal.stats().skipped,
            1,
            "the torn record is counted, not applied, and open still succeeds"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            good,
            "the file is cut back to the last good boundary"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_whole_record_that_does_not_parse_is_an_error() {
        // The counterpart to the torn tail: bytes that are present but wrong are
        // corruption, and opening must fail loudly rather than drop them.
        let dir = scratch("corrupt");
        {
            let (mut journal, _) = Journal::open(&dir, 1 << 20, 8).unwrap();
            journal.append(&Record::Host { record: host("a") }).unwrap();
        }

        let path = segment_path(&dir, 0);
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            let garbage = b"this is not json";
            file.write_all(&(garbage.len() as u32).to_le_bytes())
                .unwrap();
            file.write_all(garbage).unwrap();
            file.flush().unwrap();
        }

        assert!(
            Journal::open(&dir, 1 << 20, 8).is_err(),
            "a complete but unparseable record is not a torn tail"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_segment_rotates_once_the_size_bound_is_passed() {
        let dir = scratch("rotate");
        let (mut journal, _) = Journal::open(&dir, 100, 100).unwrap();
        for i in 0..10 {
            journal
                .append(&Record::Host {
                    record: host(&format!("h{i}")),
                })
                .unwrap();
        }

        assert!(
            journal.stats().segments >= 2,
            "the size bound must force a second segment"
        );
        assert_eq!(
            segment_files(&dir).len(),
            journal.stats().segments,
            "every segment the journal counts is a file on disk"
        );
        drop(journal);

        let (_, records) = Journal::open(&dir, 100, 100).unwrap();
        assert_eq!(records.len(), 10, "rotation must not lose a record");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_deletes_the_oldest_and_replay_sees_only_the_tail() {
        let dir = scratch("retain");
        // A one-byte bound rotates on every append, so each record gets its own
        // segment and retention has something to delete.
        let (mut journal, _) = Journal::open(&dir, 1, 2).unwrap();
        for i in 0..5 {
            journal
                .append(&Record::Host {
                    record: host(&format!("h{i}")),
                })
                .unwrap();
        }
        assert_eq!(journal.stats().segments, 2, "the cap is enforced");
        drop(journal);

        let (journal, records) = Journal::open(&dir, 1, 2).unwrap();
        assert_eq!(journal.stats().segments, 2);
        let ids: Vec<String> = records
            .into_iter()
            .map(|record| match record {
                Record::Host { record } => record.host_id,
                Record::Ingest { .. } => unreachable!("only hosts were written"),
            })
            .collect();
        assert_eq!(
            ids,
            vec!["h3".to_string(), "h4".to_string()],
            "replay reads the retained segments and nothing older"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_duplicate_batch_reaches_the_journal_once() {
        // Drive the same helper the ingest handler uses, so this covers the
        // wiring rather than a re-implementation of it: the retry must change
        // nothing in the store and add nothing to the file.
        let dir = scratch("duplicate");
        let (mut journal, _) = Journal::open(&dir, 1 << 20, 8).unwrap();
        let enrolled = host("a");
        journal
            .append(&Record::Host {
                record: enrolled.clone(),
            })
            .unwrap();

        let store = MemoryStore::default();
        store.insert_host(enrolled);
        let journal = Mutex::new(journal);

        let first = crate::apply_batch(
            &store,
            Some(&journal),
            "a",
            "batch-1",
            3,
            vec![alert("R1", "a-1")],
        );
        let retry = crate::apply_batch(
            &store,
            Some(&journal),
            "a",
            "batch-1",
            3,
            vec![alert("R1", "a-1")],
        );
        assert!(!first.duplicate);
        assert!(retry.duplicate, "the retry is recognised, not re-stored");

        drop(journal);
        let (_, records) = Journal::open(&dir, 1 << 20, 8).unwrap();
        let ingests = records
            .iter()
            .filter(|record| matches!(record, Record::Ingest { .. }))
            .count();
        assert_eq!(ingests, 1, "a duplicate batch is not written twice");

        // Which is what makes a restart not count the batch twice.
        let rebuilt = MemoryStore::default();
        rebuilt.replay(&records);
        assert_eq!(rebuilt.snapshot().total_events, 3);
        assert_eq!(rebuilt.snapshot().total_alerts, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_journal_round_trip_rebuilds_the_snapshot_a_restart_would_destroy() {
        // The strongest statement available: write the same facts a live server
        // would, close the file, reopen it, replay, and compare the whole
        // strongly-typed snapshot — not a rendering of it, and not the totals.
        // Going through the file also covers serde round-tripping the hash and
        // the timestamps.
        let dir = scratch("identity");

        let original = MemoryStore::default();
        let enrolled = host("a");
        original.insert_host(enrolled.clone());
        let at_first = enrolled.enrolled_at + chrono::Duration::seconds(1);
        let at_second = enrolled.enrolled_at + chrono::Duration::seconds(2);

        let first = alert("R1", "a-1");
        let mut second = alert("R1", "a-2");
        second.count = 9;
        original.apply_ingest("a", "b-1", 4, vec![first.clone()], at_first);
        original.apply_ingest("a", "b-2", 0, vec![second.clone()], at_second);
        let before = original.snapshot();

        {
            let (mut journal, _) = Journal::open(&dir, 1 << 20, 8).unwrap();
            journal.append(&Record::Host { record: enrolled }).unwrap();
            journal
                .append(&Record::Ingest {
                    host_id: "a".to_string(),
                    batch_id: "b-1".to_string(),
                    events: 4,
                    alerts: vec![first],
                    at: at_first,
                })
                .unwrap();
            journal
                .append(&Record::Ingest {
                    host_id: "a".to_string(),
                    batch_id: "b-2".to_string(),
                    events: 0,
                    alerts: vec![second],
                    at: at_second,
                })
                .unwrap();
        }

        let (_, records) = Journal::open(&dir, 1 << 20, 8).unwrap();
        let rebuilt = MemoryStore::default();
        let outcome = rebuilt.replay(&records);
        assert_eq!(outcome.applied, 3);
        assert_eq!(outcome.unknown_hosts, 0);
        assert_eq!(
            rebuilt.snapshot(),
            before,
            "coming back from disk must reproduce the live state exactly"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

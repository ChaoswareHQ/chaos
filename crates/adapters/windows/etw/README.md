# `etw`

The Windows ETW sensor. It owns a real-time trace session, decodes provider
payloads with TDH, and hands the result to the pipeline as wire events.

This crate is `#![cfg(windows)]` and is the only part of the product that talks
to the trace API. It produces telemetry; it does not know what a technique is,
what a rule is, or what an alert is.

> **A note on `tools/`.** This document names four files under `tools/` —
> `dump-fields.ps1`, `attack-corpus.md`, `verify-coverage.ps1` and
> `etw-load.ps1`. None of them is in the repository. The provenance they are
> cited for is real: every field name below was read off a running host with
> `dump-fields.ps1`. The script itself is not shipped, so re-checking a name on
> a new build means re-creating it. `attack-corpus.md` and
> `verify-coverage.ps1` are the measurement half and have never been written,
> which is why this crate can state what it collects rather than a coverage
> percentage.

## Shape

Five layers, in the order an event flows through them:

```
boundary/       the Windows side: session, callback, counters
  session.rs      owns the kernel session and the thread in ProcessTrace
  callback.rs     runs per event on that thread: copies the payload, hands off
  stats.rs        counters, including what was lost
  constants.rs    the flags and levels the callback reads
  mod.rs          re-exports, and the boundary's own rules
decode/         the TDH side: rebuilds an EVENT_RECORD, asks TDH for names
  decoder.rs      the Decoder: a property buffer, a name buffer, the schema cache
  schema.rs       the TRACE_EVENT_INFO parse and the schema cache key
  value.rs        FieldValue, FieldType, and the two classification paths
wire/           the wire format: decoded fields -> the event the pipeline scores
  shape.rs        one declare_shapes! table: which (provider, id) is which shape
  decoders.rs     one function per shape
  render.rs       FILETIME, registry types, DNS mnemonics, script capping
  counts.rs       per-shape counters and the gap detector
  histogram.rs    what the shape table does not claim
enrich/         host facts the kernel does not emit: four caches
diagnostics/    operator-facing checks. Never on the hot path.
provider.rs     GUIDs, keyword masks, and the default provider list
error.rs        error codes, hints, and the two remedies worth writing down
```

The split between `boundary` and `decode` is the central design decision, and it
exists for one reason: **TDH can only read a live `EVENT_RECORD`, and the kernel
recycles the real one the moment the callback returns.** So the callback copies
`UserData` into our own buffer — one memcpy, no decoding, no allocation beyond
the copy — and later, off the hot path, `decode` rebuilds a synthetic
`EVENT_RECORD` over that copy and lets TDH name the fields. That copy is the
only one: every field read points TDH at the event's own payload and fills the
decoder's reusable buffer, so a decode that reads six fields neither copies the
payload nor allocates six times.

That is also why `EtwRaw` carries a GUID, a version, an opcode and a keyword that
the wire format does not: TDH resolves a schema from the provider GUID plus the
event descriptor, and a provider *name* is not invertible back into either.

Two rules hold in the callback, and both are load-bearing:

- **Never block.** A callback that waits on a full channel stalls `ProcessTrace`,
  and the kernel responds by dropping events in bulk. Losing one event to
  `try_send` is far cheaper than losing a buffer.
- **Never panic.** Unwinding out of an `extern "system"` frame aborts the
  process. Every operation there is total.

## Typed decode, not width guessing

`TdhGetProperty` returns a byte buffer and does not say whether those bytes are
a `UInt32`, four bytes of a `Binary` field, or the first half of a UTF-16 string.
Guessing from the width works until it does not — the registry provider's
`CapturedData` is declared `Binary`, so a four-byte `REG_DWORD` Run value would
be read as an integer where the manifest says bytes.

`Decoder` fetches the declared type once per `(provider, event id, version)` via
`TdhGetEventInformation` and caches it, so a field's type is a fact. Two
accessors:

- `Decoder::typed_field` asks the schema and classifies by declared `InType`.
  This is what `wire::decoders::registry_set` uses, because the shape of a
  registry value is not obvious from its name.
- `Decoder::field` keeps the width-based classification for fields the caller
  already knows are fixed-width scalars (a `ProcessID`, a `QueryType`).

`FieldType` is the subset of `TDH_INTYPE_*` this crate acts on; anything else
becomes `FieldType::Unknown` and is kept as bytes.

## What is collected

`default_providers()` returns nine providers. Level is informational; keyword
masks are `0` ("every keyword") except for `Kernel-Process`, which subscribes to
**process and image** but deliberately not **thread**:

| Provider | GUID | Keywords | What it is for |
|---|---|---|---|
| `Kernel-Process` | `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716` | process (`0x10`) + image (`0x40`) | Process lifecycle, image loads |
| `Kernel-File` | `EDD08927-9CC4-4E65-B970-C2560FB5C289` | all | File create/delete/rename |
| `Kernel-Network` | `7DD42A49-5329-4832-8DFD-43D979153A88` | IPv4 + IPv6 | TCP connect/disconnect |
| `Kernel-Registry` | `70EB4F03-C1DE-4F73-A051-33D13D5413BD` | all | Registry writes, with KCB correlation |
| `Security-Auditing` | `54849625-5478-4994-A5BA-3E3B0328C30D` | all | Command lines, parent image (4688 v2) |
| `DNS-Client` | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | all | Name resolution |
| `PowerShell` | `A0C1853B-5C40-4B15-8766-3CF1C58F985A` | all | Script blocks, when SBL is on |
| `WMI-Activity` | `1418EF04-B0B4-4623-BF7E-D74AB47BBDAA` | all | WMI process creation (T1047), permanent subscriptions (T1546.003) |
| `TaskScheduler` | `DE7B24EA-73C8-4A09-985D-5BDADCFA9017` | all | Task registration (T1053.005) |

`Security-Auditing` is the one entry that needs the non-default enable call —
see `enable_keyword_zero` below.

Thread keywords are volume, not signal: `matchanykeyword = 0` against a manifest
provider is the difference between a few thousand and a few hundred thousand
events per second for the same amount of *useful* evidence.

The registry provider is enabled because `T1547.001` reads a Run-key write and no
other event carries one. Leaving it out is not a performance decision — it is a
rule that can never fire on a real host while passing every test against a
fixture.

### The providers that are defined and deliberately not enabled

Four GUIDs above are defined and left out of the default list, each for a reason
that is written down in `provider.rs` and pinned by a test:

- **`AMSI`** — not registered on every host, and where it is, its 1101
  content-scan event says much the same thing as `ScriptBlock` 4104 for
  PowerShell.
- **`SERVICES`** — its id 105 carries a service's `ImageName`, which is exactly
  the field a persistence rule wants, but the host this table was built on ships
  no message template for it, so whether `ImageName` names the service's binary
  or the `svchost.exe` hosting it is unconfirmed.
- **`CODE_INTEGRITY`** — ids 3076/3077 are verified, and their field names
  contain **spaces** (`"File Name"`, not `FileName`). They are also extremely
  high-volume on a host with a policy in audit mode.
- **`DOTNET_RUNTIME`** — volume without a consumer today.

`THREAT_INTELLIGENCE` is a fifth and different case: it is a kernel-mode
provider that a user-mode process cannot subscribe to at all. See
[What ETW cannot see](#what-etw-cannot-see).

A provider that is enabled and unread is a coverage number on paper and nothing
on a host, so the list grows one rule at a time rather than one GUID at a time.

## What becomes a wire event

The shape table (`wire/shape.rs`, one `declare_shapes!` block) maps fifteen
`(provider, id)` pairs onto `EventKind`. Everything else the session delivers is
counted and dropped — a deliberate choice about which events are worth shipping,
not a limit of the sensor. The PowerShell provider alone emits two dozen event
ids of its own logging, and claiming them would ship a great deal and detect
nothing.

| Provider | Event id | Shape | Becomes |
|---|---|---|---|
| `Kernel-Process` | 1 | `process_start` | `EventKind::ProcessStart` |
| `Kernel-Process` | 2 | `process_exit` | `EventKind::ProcessExit` |
| `Kernel-Process` | 5 | `image_load` | `EventKind::ImageLoad` |
| `Kernel-Registry` | 5 | `registry_set` | `EventKind::RegistrySet` |
| `DNS-Client` | 3006 | `dns_query` | `EventKind::DnsQuery` |
| `PowerShell` | 4104 | `script_block` | `EventKind::ScriptBlock` |
| `Kernel-File` | 12 | `file_create` | `EventKind::FileCreate` |
| `Kernel-File` | 20 | `file_rename` | `EventKind::FileRename` |
| `Kernel-File` | 27 | `file_delete` | `EventKind::FileDelete` |
| `Kernel-Network` | 10 | `network_connect` | `EventKind::NetworkConnect` |
| `Kernel-Network` | 11 | `network_disconnect` | `EventKind::NetworkDisconnect` |
| `Security-Auditing` | 4688 | `process_start_audit` | `EventKind::ProcessStart` |
| `WMI-Activity` | 23 | `wmi_process` | `EventKind::WmiProcess` |
| `WMI-Activity` | 5861 | `wmi_subscription` | `EventKind::WmiSubscription` |
| `TaskScheduler` | 106 | `task_registered` | `EventKind::TaskRegistered` |

Shape order is frozen and load-bearing: `ShapeCounts` indexes its per-shape
arrays by position, so reordering the table would misattribute every number in
a historical report. New shapes append. Both facts are pinned by
`shape_indices_are_stable`.

`ScriptBlock` is the shape that makes `T1059.001` reachable on a live host. The
script text is capped at 8 KiB on the way in, at a character boundary, so one
enormous script cannot fail a whole batch; and a script long enough to be split
arrives as several events sharing a `ScriptBlockId`, which nothing reassembles.
Both facts are visible in the wire event rather than hidden.

`WmiSubscription` is the shape worth reading the model docs for. A permanent WMI
event subscription survives reboot with no process to find, which is why the
event exists at all — and why the rule keys on the *consumer* rather than on the
subscription: only a `CommandLineEventConsumer` or an `ActiveScriptEventConsumer`
can run attacker-supplied code. A stock Windows host already carries a few
permanent subscriptions of its own, so "any 5861" is not the rule.

## The field names come from the machine, not from memory

TDH addresses properties by *name* (`TdhGetProperty` takes a `PCWSTR`, not an
index), and the name has to match the provider's manifest exactly. Every name in
`wire/shape.rs` was read off a real host with `tools/dump-fields.ps1`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
    -Provider Microsoft-Windows-Kernel-Registry
```

**Reading a manifest needs no elevation.** The manifests are shipped files; this
is not a privileged operation, which makes the table checkable on any machine
rather than a matter of trust.

Two of these templates are genuinely surprising, and both cost detections
silently:

### `Kernel-Process` `ProcessStart` has no command line

Its fields are `ProcessID`, `ProcessSequenceNumber`, `CreateTime`,
`ParentProcessID`, `ParentProcessSequenceNumber`, `SessionID`, `Flags`,
`ProcessTokenElevationType`, `ProcessTokenIsElevated`, `MandatoryLabel`,
`ImageName`, `ImageChecksum`, `TimeDateStamp`, `PackageFullName`,
`PackageRelativeAppId`.

There is no command-line field. **Every rule that reads a command line is
unreachable from this provider**, which is why `T1059.001` (encoded command) and
`T1218` (signed binary against a remote location) cannot fire from it, however
well they test against a fixture.

### `RegistrySetValue` has no string value

It carries `KeyObject`, `Status`, `Type`, `DataSize`, `KeyName`, `ValueName`,
`CapturedDataSize`, `CapturedData`, `PreviousDataType` and friends. The value
written is `CapturedData`, a **`Binary`** field. Its shape is decided by the
companion `Type` field, which is a `REG_*` constant — `render_registry_value`
reads it and decodes the bytes accordingly, so a `REG_SZ` Run value arrives as
the path it names rather than as the hex of its UTF-16.

Property names are looked up through a chain rather than a single name
(`PROCESS_ID = &["ProcessID", "ProcessId"]`) because templates are not identical
across Windows builds and a miss has to degrade to `None` rather than to a guess.

## Where a command line actually comes from

Verified from this machine's shipped manifests with `tools/dump-fields.ps1`, not
from documentation. Both of these need a policy turned on before the events are
emitted at all, so on a stock host neither one fires and the sensor is correct to
be quiet.

### PowerShell 4104 — script text. **Decoded today.**

```
id=4104  v=1  MessageNumber, MessageTotal, ScriptBlockText, ScriptBlockId, Path
```

`ScriptBlockText` is the script body, and it is what the four `script_block_*`
rules in the pipeline read. Requires **Script Block Logging**
(`EnableScriptBlockLogging`), and covers PowerShell only. When the policy is off
the provider emits nothing, which is why a quiet host proves nothing about
whether this path works.

The event carries no pid field: the header's process is the interpreter that
logged it, so that is the process the evidence accumulates against. A script long
enough to be split arrives as several events sharing a `ScriptBlockId` and
counting themselves with `MessageNumber`/`MessageTotal` — nothing reassembles
them, and `message_total > 1` is how a reader can tell the text in hand is one
piece of something larger.

### Security-Auditing 4688 — every process, with the command line. **Decoded today.**

```
id=4688  v=0  SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId,
              NewProcessId, NewProcessName, TokenElevationType, ProcessId
id=4688  v=1  ... (v0) ..., CommandLine
id=4688  v=2  ... (v1) ..., TargetUserSid, TargetUserName, TargetDomainName,
              TargetLogonId, ParentProcessName, MandatoryLabel
```

`v2` is the one worth wanting: it carries the parent image name and the mandatory
label as well, which is what the masquerading and fan-out rules read. It needs
`Audit Process Creation` **and** `ProcessCreationIncludeCmdLine_Enabled` — the
latter is off by default, which is why the template on a stock machine is `v0` and
has no `CommandLine` at all. This is the route to `T1218`, which PowerShell 4104
cannot cover.

All three versions decode into `EventKind::ProcessStart`. The decoder is
indifferent to the version: it reads whatever the manifest declares and leaves the
rest `None`, so a `v0` event is still a legitimate `ProcessStart` with a
`command_line` of `None` rather than a decode failure. A host where the flag is
off is not a broken sensor.

**Two sources, one shape.** `Kernel-Process` id 1 and 4688 both fire for the same
process creation, a millisecond apart, and both decode into
`EventKind::ProcessStart`. The split is deliberate and the fields say which
source an event came from:

- id 1 always fires when the provider is enabled, and carries PID, parent PID,
  image and the WOW64 flag — but **no command line**. Its `command_line` is
  `None` because the manifest has no such field, not because the decode failed.
- 4688 fires only with the audit policy on, and carries the command line, the
  user, the parent image and the integrity level.

So a rule that wants a command line filters on `command_line.is_some()`; a rule
that only wants the image matches on `executable` and works on both. Neither
source is authoritative over the other — 4688 is richer, id 1 is always present —
and merging them into one event at the sensor would mean choosing which host's
configuration to trust. Deduplicating for an alert queue is a downstream concern;
the sensor ships what it sees.

### Not a route: Kernel-Audit-API-Calls

`Microsoft-Windows-Kernel-Audit-API-Calls` looks promising by name and declares
**zero templates**: its events carry no named fields, so nothing can be addressed
by name and the payload would have to be parsed by hand.

### Verified on the same machine, for whoever adds the next shape

Every row below was read off an installed manifest with
`tools/dump-fields.ps1`; the "at" column says whether a shape reads it yet.
Re-check any row with the same tool before trusting it on another build.

| Provider | Events | Verified fields | At |
|---|---|---|---|
| `Kernel-File` | 10, 11, 12, 20, 25, 26, 27, 28, 30 | `FileName`, `FilePath` | 12, 20, 27 shipped |
| `Kernel-Network` | 10–16, 26–34, 42, 43, 58, 59 | `PID`, `saddr`, `daddr`, `sport`, `dport` | 10, 11 shipped |
| `WMI-Activity` | 23 | `Commandline`, `CreatedProcessId`, `ClientProcessId`, `ClientMachine`, `User`, `IsLocal` | shipped |
| `WMI-Activity` | 5861 | `Namespace`, `ESS`, `CONSUMER` | shipped |
| `TaskScheduler` | 106 | `TaskName`, `UserContext` | shipped |
| `TaskScheduler` | 129, 200, 201, 310, 311, 414 | `TaskName`, `Path`, `ProcessID`, `Command`, `Parameter`, `ActionName` | candidate |
| `Services` | 105 | `ServiceName`, `ImageName`, `StartType`, `CurrentState`, `PID` | candidate, meaning unconfirmed |
| `Services` | 200–205 | `ServiceName`, `NewStartType`, `NewValueName`, `ClientProcessId` | candidate |
| `CodeIntegrity` | 3076, 3077 | `"File Name"`, `"Process Name"`, `Status`, `"SHA256 Hash"`, `USN` | candidate |

Three traps in that table are worth naming out loud, because each one fails
silently rather than loudly:

- **`CodeIntegrity`'s names contain spaces.** It is `"File Name"`, not
  `FileName`, and `"SHA256 Hash"`, not `SHA256Hash`. TDH matches names
  case-sensitively and space-sensitively, so a lookup copied from the
  `Kernel-Process` style resolves nothing and reports `undecodable` rather than
  the wrong value. `dump-fields.ps1` quotes any such name for exactly this
  reason. The 3114/3115 ids, confusingly, use the *unspaced* spellings — so the
  chain for a CodeIntegrity shape needs both.
- **`WMI-Activity` 23 spells it `Commandline`** (lowercase `l`) and 5861 spells
two of its fields `ESS` and `CONSUMER` in capitals.
- **`Kernel-Audit-API-Calls` is not a route at all.** It looks promising by name
  and declares **zero templates**: its events carry no named fields, so nothing
  can be addressed by name and the payload would have to be parsed by hand.

The useful thing about `WMI-Activity` 23 is that the message template states the
field mapping outright:

```
CorrelationId = %1; GroupOperationId = %2; OperationId = %3; Commandline= %4;
CreatedProcessId = %5; ClientMachine = %6; User = %8; ClientProcessId = %9
```

`dump-fields.ps1` prints that template alongside the fields, which is what makes a
doc comment like this one checkable instead of folklore.

`Microsoft-Windows-Sysmon` is not installed on the reference machine and the
sensor does not need it: it is only another provider, and every field above comes
from something already present.

## Coverage: what this sensor can and cannot see

### Coverage is measured by rules, not by providers

The useful definition is narrow: *of the ATT&CK techniques a corpus tests for, how
many produced an event that reached a rule that fired?* Adding a provider that no
rule reads, or an event id nothing matches on, changes no host's behaviour — it
only changes a number on a slide. So every shape in the table above has a rule in
`crates/pipeline/src/rules.rs`, and the rule list is what to read to know what this
sensor actually detects.

Measuring it needs four things. Two are in this repository; the other two are
not yet written, and saying which is which matters more than a tidy sentence,
because a coverage *claim* is exactly what this section exists to prevent:

1. **A corpus** — per technique, the exact event that would prove it executed.
   **Not in the tree.** This is the shape `tools/attack-corpus.md` would take.
2. **A live test** — run the technique on a controlled host with the sensor on.
   This is the operator's step, and no script can do it safely.
3. **A sensor trace** — did the shape fire? Did it reach the wire? Did the rule
   score it? **In the tree:** `Translator::counts()` reports `attempted`/`mapped`
   per shape, `undecodable` names a wrong field table, and `detect_gaps()`
   separates a quiet host from a shape that stopped firing.
4. **A count** — techniques detected ÷ techniques tested. Needs (1), and the
   script that would read (3) into a per-technique report. Neither is written.

Step 3 is already instrumented in the sensor itself: `Translator::counts()`
reports `attempted`/`mapped` per shape, `undecodable` names the shapes whose field
table is wrong for this build, and `detect_gaps()` separates "the host is quiet"
from "this shape stopped firing while others are still active". That last
distinction is the ETW-bypass signature, and it is the reason `ShapeCounts` is
per-shape rather than one total.

The corpus and the script are the difference between a coverage *claim* and a
coverage *measurement*. The script's own header states the limit of what it
proves, and it is worth repeating: it measures the sensor, not the adversary. A
row that reads `none` means no evidence was observed, which is only the same thing
as "missed" if the technique was actually performed during the window.

### Every shape now has a rule

The five shapes that used to decode with nothing reading them — `file_delete`,
`file_rename`, `network_connect`, `network_disconnect` and `process_exit` — now
have rules. They were last for a reason, and it is the same reason each of them
is weak: every one is a *single-event* signal from a provider that does not carry
enough context to do better. What each is worth is written down here rather than
left for a reader to discover:

| Shape | Rule | Technique | What limits it |
|---|---|---|---|
| `file_delete` | `executable_deleted_from_staging_location` | T1070.004 | Installers delete from `%TEMP%` too. The location test is the *staging* subset and not every writable place, so a build under `\users\` does not fire it. |
| `file_rename` | `ransomware_extension_on_rename` | T1486 | The provider reports a name *fragment* and no rename target, so only the tail of the name is readable. A fragment ending in `.locked` names an encrypted file; nothing else about a rename is ruleable. |
| `network_connect` | `connect_to_implant_default_port` | T1571 | Needs both a default implant port *and* a routable destination: `127.0.0.1:4444` is a test harness and `10.0.0.5:4444` is a lab. |
| `network_disconnect` | `large_transfer_to_implant_port` | T1041 | The byte count is the total moved in *both* directions, so on its own it cannot separate an upload from a download. Multiplexed onto an implant port it can. |
| `process_exit` | `exploitation_crash_exit_code` | T1203 | The exit code is the only field the event carries. `STATUS_STACK_OVERFLOW` is deliberately excluded — a recursive bug produces it far more often than an exploit. |

None of these alerts on its own. Each carries a likelihood pair whose `miss` is a
substantial fraction of its `hit`, which is the file's way of saying *evidence,
not verdict*, and the engine's threshold, decay and coalescing are what decide
when several of them add up to a row. Counting them as coverage would still be
the mistake this section exists to avoid — but a shape with no rule at all was
the larger one, because a decode with nothing behind it changes no host's
behaviour.

### What ETW cannot see

No number of enabled providers reaches 100%, and it is worth being precise about
why rather than describing the gap as an implementation detail. Four things are
invisible to **any** user-mode ETW sensor, however it is configured:

| Blind spot | Why | What would be needed |
|---|---|---|
| Hardware breakpoints (`DR0–DR7`, driven from a VEH) | No byte in any image changes, so there is nothing for an image-integrity or code-integrity event to report | A kernel driver |
| IAT hooking in a *calling* module | The hook lives in the caller's import table; `ntdll.dll`'s `.text` is untouched, so the integrity checks in `diagnostics/security.rs` see nothing | A kernel driver |
| The sensor patching itself | "Who watches the watchmen" — a process cannot detect its own compromise reliably. `examples/etw_attack.rs` attack 5 is this case, and it is listed as undetectable rather than as a failure | A separate process, on a different host or under a different token |
| Purely in-memory fileless execution | If nothing is written to disk, loaded as an image, or passed to a provider that inspects content, no ETW provider is involved | `Threat-Intelligence`, or a PPL |

Everything else is reachable, which is what makes the phases below a plan rather
than a wish:

- **Phase 1 — command lines and process attribution.** `Security-Auditing` 4688
  v2, decoded as `process_start_audit`. *Landed.* This is the single largest jump
  available, because it is what makes `T1059.*`, `T1218.*` and `T1105` writable at
  all. It needs a policy turned on, not just a provider enabled.
- **Phase 2 — script content and fileless execution.** `WMI-Activity` 23 and
  5861, `TaskScheduler` 106. *Landed.* AMSI 1101 is defined and deliberately not
  enabled — see the provider notes above for the reason.
- **Phase 3 — persistence and privilege.** `TaskScheduler` 129/200/201,
  `Services` 105 and 200–205, `CodeIntegrity` 3076/3077. *Partial:* task
  registration is in; the rest are verified-but-unshaped, for the reasons in the
  provider and field tables above.
- **Phase 4 — lateral movement.** `Security-Auditing` 4624/4648/4672, the
  Kerberos, NTLM, SMB, WinRM, DCOM and LDAP-Client providers. *Not started.* Most
  of these only fire with the matching audit policy on, which is a group-policy
  conversation rather than a code change, and on a workstation none of the domain
  providers fire at all.
- **Phase 5 — kernel-level visibility.** `Threat-Intelligence`
  (`F4E1897C-BB5D-5668-F1D8-040F4D8DD344`). *Not reachable from this crate.* See
  below.

### Why Phase 5 is a business decision, not a code change

`Threat-Intelligence` is a **kernel-mode** provider. A user-mode process cannot
subscribe to it, whatever the session's flags are: the documented requirement is
that the caller run as `PROTECTED_PROCESS` or `PROTECTED_LIGHT` with
`PsProtectedSignerAntimalware-Light` or higher. There are two ways to get there,
and both are procurement rather than engineering:

- **A PPL signature** — applying to Microsoft's Early Launch Anti-Malware
  program, which means a business justification, a review, and a signed binary
  re-signed on every release.
- **A signed kernel driver** — driver signing, WHQL submission, and the
  maintenance burden of a driver on every supported Windows build.

The practical consequence is that a user-mode ETW sensor has a structural ceiling,
and the remaining gap is concentrated in the memory-injection family (every
`T1055.*`, the credential-dumping techniques, and reflective loading). That is the
honest description of the boundary: not "we detect 100% of attacks", and not "we
detect nothing in memory", but "the memory-injection family is out of reach
without a kernel component, and everything else is a rule away".

This crate does not claim a coverage percentage, because the number is a property
of the corpus and the host, not of the code. What it can state as fact is what it
collects, which shape each event becomes, and which rules read them — all three are
testable, and all three are in this document.

## Boot-time capture, and the limit of it

A session created by `EtwSession::start` begins when the agent does. Everything
before that — the services that started, the logon, the Run key that fired during
it — happened with nothing listening, and no care in the consumer recovers it.

Windows has a mechanism for this. A subkey under
`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger` describes a session and the
kernel starts it during boot. Read off this machine's own `EventLog-System`
session, the layout is:

```
[EventLog-System]
  Start          REG_DWORD  0x1       1 = started at boot
  Guid           REG_SZ     {d2112be4-cd15-5a9c-e38f-080a207e08d5}
  BufferSize     REG_DWORD  0x40      in KB, as here
  MinimumBuffers REG_DWORD  0x0
  MaximumBuffers REG_DWORD  0x10
  FlushTimer     REG_DWORD  0x1       seconds
  LogFileMode    REG_DWORD  0x98000180
  <provider guid>                      one subkey per provider
      Enabled        REG_DWORD 1
      EnableLevel    REG_DWORD 4
      MatchAnyKeyword REG_QWORD
```

`autologger.rs` gives three things and deliberately withholds a fourth:

- **`AutologgerState::read(session)`** — reads that configuration back. Reading a
  *named* session needs no elevation; enumerating which sessions exist does, and
  the container key refuses a normal user outright. That is why this takes a name.
- **`AutologgerSpec::problems(&state)`** — the self-check. Each string names one
  value that is missing or wrong, because "the autologger is broken" is not
  something an operator can act on. Empty means the host is configured as this
  deployment expects. **It notices a *changed* `MatchAnyKeyword`, not only an
  absent one**: a mask narrowed from `0x50` to `0x10` silently drops image-load
  telemetry, and the check that used to fire only on absence could not see it.
- **`AutologgerSpec::reg_commands()`** — the exact `reg add` lines that create the
  session, rendered from the same data the check compares against, so the
  instructions cannot drift from the code.
- **No writing.** Creating the key needs an elevated token, and a library that
  quietly rewrites `HKLM` at startup is a library nobody should trust.

`EtwSession::attach(cfg)` consumes such a session: it does not start anything and
**enables no provider** — that was decided by whoever created the session — so the
provider list passed to it is used only to *name* providers in outgoing events. It
refuses a session whose `LogFileMode` lacks `EVENT_TRACE_REAL_TIME_MODE (0x100)`,
because a session that only writes to a file has nothing to join. And it will not
stop what it did not start: [`EtwSession::shutdown`] leaves an attached session
running, since killing it would blind every other consumer and end a session that
is supposed to outlive the process.

### What is unverified

Attaching to a real-time session created by another process is the one part of
this module that cannot be tested without elevation and a boot-time session. The
FFI is the documented shape — `LoggerName` plus `PROCESS_TRACE_MODE_REAL_TIME` —
and the failure paths are explicit rather than silent, but "another consumer can
attach to a boot session while it runs" is a claim from documentation, not from
this machine. It is reported as `EtwError::NoSuchSession` or `NotRealTime` if it
does not hold, and neither of those is a hang.

### It is a speed bump, not a wall

An autologger is started by the kernel but *configured* by a registry key. An
administrator can stop the session (`logman stop -ets`) or edit the key and
reboot. What it buys is that doing so has to be deliberate, privileged and
recorded — which is why `problems()` exists: a host can be asked whether its own
telemetry is still configured the way it was, and the answer is worth alerting on.

## Reading a manifest

`tools/dump-fields.ps1` prints the data-field names each event template declares,
per provider, together with the event's message template:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
    -Provider Microsoft-Windows-Kernel-Process
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
    -Provider Microsoft-Windows-PowerShell -Id "4103,4104"
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 -List Security
```

It calls the three TDH manifest entry points directly — `TdhEnumerateProviders`,
`TdhEnumerateManifestProviderEvents` and `TdhGetManifestEventInformation` — and
walks the returned `TRACE_EVENT_INFO`. Reading a manifest needs no elevation, so
this is checkable on any machine rather than a matter of trust.

`-List` exists because the exact provider spelling is what a lookup fails on, and
guessing it wastes an afternoon. `-ExecutionPolicy Bypass` scopes the permission to
that one process; a stock machine refuses to run a script file at all.

Use this rather than `wevtutil gp`, which prints a provider's channels, levels,
opcodes and tasks and **nothing about the data fields** — a difference that costs
an afternoon if you assume otherwise. Enumerated here, that mistake showed
`Kernel-Audit-API-Calls` as having "no named events" when the real answer was
that `wevtutil` never prints the names either way.

### A caveat about the script itself

`TRACE_EVENT_INFO` is 112 bytes of header followed by an array of
`EVENT_PROPERTY_INFO` records, and the record stride is **24 bytes**, not the 16
the 8-byte union in older `tdh.h` suggests. Reading at 16 does not fail — it
produces plausible-looking but shifted names, which is the worst kind of wrong:
for PowerShell 4104 it printed `MessageNumber`, two unnamed entries, then
`ScriptBlockText`, where the real template is `MessageNumber`, `MessageTotal`,
`ScriptBlockText`, `ScriptBlockId`, `Path`.

The script therefore re-derives the stride per event and reports
`EVENT_PROPERTY_INFO stride not recognised` rather than printing names read at the
wrong stride. If a future Windows build changes the layout, the tool says so.

## Timestamps

ETW's `TimeStamp` is a `FILETIME`: 100-nanosecond intervals since 1601-01-01.

```rust
const FILETIME_EPOCH_DELTA: i64 = 116_444_736_000_000_000;
const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;
```

`from_filetime` returns `None` for anything that cannot be a real instant. A
wrong timestamp is worse than a missing event: the engine builds a causal order
from these, and a plausible-looking wrong one corrupts it silently.

## Failures an operator actually hits

`error.rs` turns OS codes into something actionable, and keeps the two cases with
a real answer separate from the ones without:

| Code | Meaning | Remedy |
|---|---|---|
| 5 | `ERROR_ACCESS_DENIED` | open an **elevated** prompt (Win+X, "Terminal (Admin)"), `cd` to the same directory, run the same command |
| 183 | `ERROR_ALREADY_EXISTS` | another process owns this session name — stop the other copy |
| 8 | `ERROR_NOT_ENOUGH_MEMORY` | reduce `BufferSize` or `MaximumBuffers` |
| 4201 | `ERROR_WMI_INSTANCE_NOT_FOUND` | the provider manifest is not registered |

An error whose remedy is not obvious gets **no** remedy. An invented instruction
is worse than none, because the reader follows it.

Partial success is the normal case: `EtwSession::start` returns a per-provider
`EnableReport` and the session runs with what it was granted. The agent prints
one line per provider and only fails if *no* provider could be enabled.

## The counters are not diagnostics

`stats.rs` counts `received`, `delivered`, `filtered`, `classic`, `dropped` and
`payload_bytes` behind atomics. They are load-bearing:

- `received - delivered` is the number of events the sensor saw and the pipeline
  did not, which is what makes the A3 observation gap an empirical claim rather
  than an assumption;
- `coverage()` reports `1.0` for an idle sensor rather than `NaN`;
- `dropped` is the bounded channel refusing to block the callback, which is a
  real ceiling on burst absorption (`capacity` in `SessionConfig` — a depth of
  65,536 events by default).

`Translator` keeps a per-shape pair: `ShapeCounts` holds `attempted` and `mapped`
arrays indexed by `Shape`, so the report can say *which* shape went quiet rather
than only that something did. One number cannot tell "the host is idle" from
"PowerShell logging is off and only PowerShell events are missing". A shape with
`attempted == 0` is absent, not healthy, and the array makes the difference
visible.

A non-zero `undecodable` means a property name in `wire/shape.rs` is wrong for
this build of Windows — **not** that the machine was quiet — and the first eight
failures are retained with their reason so the report can say which field went
missing. A silent hole is the failure mode this exists to prevent.

## Running it

ETW requires an elevated token; without one `StartTraceW` returns `5` and the
agent says why. The session is real-time, so `FlushTimer` is a latency floor
rather than a tuning knob — a sparse provider's events are delivered on flush,
so one second is the compromise between seeing quiet providers at all and paying
per-buffer overhead for nothing.

```powershell
# in an elevated prompt, from the repo root
.\target\release\client.exe --ship http://127.0.0.1:8787 --token-file dev-host.token --etw 60
```

`--etw SECONDS` bounds the run and prints a full report — sensor counters, then
what the pipeline made of it, then what left the host, in the order those things
happened. With no duration, the agent runs until stopped.

## Measuring it

A quiet desktop produces about 3,000 raw events a second, almost all of them
`Kernel-Registry` reads that no shape scores — a fine smoke test and a useless
benchmark, because every number a run on an idle host reports is a number about
the host. The two examples are the measurement, and they are meant to be run
against each other:

```sh
# terminal 1
cargo run --release --example etw_capture -p etw -- 30 --quiet

# terminal 2
cargo run --release --example etw_load -p etw
```

`etw_capture --quiet` skips the per-event line, so the only work between the
channel and the counter is the decode: the rate it reports is the decoder's
throughput rather than the terminal's. `etw_load` drives the three providers
that are actually decoded — `Kernel-File` (create, write, rename, delete),
`Kernel-Registry` (open, query, close) and `Kernel-Process` (spawns, which is
also how it produces `ImageLoad` bursts) — for a fixed number of operations, so
two builds of the sensor can be compared against the same workload.

The run ends with a cost report, not only a rate report: process CPU time, the
consumer thread's share of it, CPU per raw and per wire event, what the wire
measurement itself took, and the queue's fixed memory. A rate with no cost
beside it cannot tell a sensor that is keeping up from one that is already at
its ceiling.

Two rules for reading any of these numbers. Measure in release: TDH is 10–30×
slower in a debug build. And check the load generator's own operations/second
before comparing two runs — the host's state moves these numbers by more than
most code changes do, and that line is what says so.

## Testing

```sh
cargo test -p etw
```

Note what the unit tests can and cannot cover. They pin GUIDs, keyword masks,
event names, `FILETIME` conversion, property lookup chains, the declared-type
classification and the error hints — all against literals. They **cannot** tell
you that a field name matches your machine's manifest, because that is a
property of the machine.

That gap is why the report prints `undecodable` and the retained reasons instead
of a bare count, and why `ShapeCounts` carries the shape an event belonged to.
If you are adding a shape to `wire/shape.rs`, read the template off a real host
first.

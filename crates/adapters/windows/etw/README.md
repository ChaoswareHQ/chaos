# `etw`

The Windows ETW sensor. It owns a real-time trace session, decodes provider
payloads with TDH, and hands the result to the pipeline as wire events.

This crate is `#![cfg(windows)]` and is the only part of the product that talks
to the trace API. It produces telemetry; it does not know what a technique is,
what a rule is, or what an alert is.

## Shape

```
session.rs     owns the kernel session and the thread blocked in ProcessTrace
callback.rs    runs per event on that thread: copies the payload, hands off
decode.rs      runs on the consumer side: rebuilds an EVENT_RECORD, asks TDH
translate.rs   decoded fields -> the wire format the pipeline scores
provider.rs    GUIDs, keyword masks, and the default provider list
autologger.rs  boot-time sessions: read the configuration, render the commands
stats.rs       counters, including what was lost
error.rs       error codes, hints, and the two remedies worth writing down
```

The split between `callback` and `decode` is the central design decision, and it
exists for one reason: **TDH can only read a live `EVENT_RECORD`, and the kernel
recycles the real one the moment the callback returns.** So the callback copies
`UserData` into our own buffer — one memcpy, no decoding, no allocation beyond
the copy — and later, off the hot path, `decode` rebuilds a synthetic
`EVENT_RECORD` over that copy and lets TDH name the fields.

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
  This is what `translate::registry_set` uses, because the shape of a registry
  value is not obvious from its name.
- `Decoder::field` keeps the width-based classification for fields the caller
  already knows are fixed-width scalars (a `ProcessID`, a `QueryType`).

`FieldType` is the subset of `TDH_INTYPE_*` this crate acts on; anything else
becomes `FieldType::Unknown` and is kept as bytes.

## What is collected

`default_providers()` returns four providers, in priority order. Level is
informational; keyword masks are `0` ("every keyword") except for
`Kernel-Process`, which subscribes to **process and image** but deliberately not
**thread**:

| Provider | GUID | Keywords |
|---|---|---|
| `Microsoft-Windows-Kernel-Process` | `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716` | process (`0x10`) + image (`0x40`) |
| `Microsoft-Windows-Kernel-Registry` | `70EB4F03-C1DE-4F73-A051-33D13D5413BD` | all |
| `Microsoft-Windows-DNS-Client` | `1C95126E-7EEA-49A9-A3FE-A378B03DDB4D` | all |
| `Microsoft-Windows-PowerShell` | `A0C1853B-5C40-4B15-8766-3CF1C58F985A` | all |

Thread keywords are volume, not signal: `matchanykeyword = 0` against a manifest
provider is the difference between a few thousand and a few hundred thousand
events per second for the same amount of *useful* evidence.

The registry provider is enabled because `T1547.001` reads a Run-key write and no
other event carries one. Leaving it out is not a performance decision — it is a
rule that can never fire on a real host while passing every test against a
fixture.

The other GUIDs are defined for later (`KERNEL_FILE`, `KERNEL_NETWORK`,
`THREAT_INTELLIGENCE`, `AMSI`, `DOTNET_RUNTIME`, `WMI_ACTIVITY`) but are not
enabled by default.

## What becomes a wire event

`translate.rs` maps four shapes today:

| Provider | Event id | Name | Becomes |
|---|---|---|---|
| `Kernel-Process` | 1 | `ProcessStart` | `EventKind::ProcessStart` |
| `Kernel-Registry` | 5 | `RegistrySetValue` | `EventKind::RegistrySet` |
| `DNS-Client` | 3006 | `DnsQuery` | `EventKind::DnsQuery` |
| `PowerShell` | 4104 | `ScriptBlock` | `EventKind::ScriptBlock` |

Everything else the session delivers is counted and dropped. That is a
deliberate choice about which events are worth shipping, not a limit of the
sensor — the PowerShell provider, for instance, emits two dozen event ids of its
own logging, and claiming them would ship a great deal and detect nothing.

`ScriptBlock` is the shape that makes `T1059.001` reachable on a live host. The
script text is capped at 8 KiB on the way in, at a character boundary, so one
enormous script cannot fail a whole batch; and a script long enough to be split
arrives as several events sharing a `ScriptBlockId`, which nothing reassembles.
Both facts are visible in the wire event rather than hidden.

## The field names come from the machine, not from memory

TDH addresses properties by *name* (`TdhGetProperty` takes a `PCWSTR`, not an
index), and the name has to match the provider's manifest exactly. Every name in
`translate.rs` was read off a real host with `tools/dump-fields.ps1`:

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

### Security-Auditing 4688 — every process, with the command line. Not decoded.

```
id=4688  v=0  ... NewProcessName, TokenElevationType, ProcessId
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

### Not a route: Kernel-Audit-API-Calls

`Microsoft-Windows-Kernel-Audit-API-Calls` looks promising by name and declares
**zero templates**: its events carry no named fields, so nothing can be addressed
by name and the payload would have to be parsed by hand.

### Verified on the same machine, for whoever adds the next shape

| Provider | Event | Fields worth having |
|---|---|---|
| `Kernel-File` | 10, 11, 12, 20, 25, 26, 27, 28, 30 | `FileName`, `FilePath` |
| `Kernel-Network` | 10–16, 26–34, 42, 43, 58, 59 | `PID`, `saddr`, `daddr`, `sport`, `dport` |
| `WMI-Activity` | 23 | `Commandline`, `CreatedProcessId`, `ClientProcessId`, `User`, `IsLocal` |
| `TaskScheduler` | 129, 310, 311, 414 | `TaskName`, `Path`, `Command`, `Parameter` |
| `CodeIntegrity` | 3076, 3077, 3114, 3115 | `File Name`, `Process Name`, `SHA256 Hash`, `USN` |

`WMI-Activity` 23 is the interesting one: a WMI-initiated process creation with
its command line, which is `T1047` and the usual first step before an encoded
PowerShell. `CodeIntegrity` is the trap in the table — its field names contain
**spaces** (`File Name`, not `FileName`), so a TDH lookup that copies the
`Kernel-Process` style silently resolves nothing.

`Microsoft-Windows-Sysmon` is not installed on the reference machine and the
sensor does not need it: it is only another provider, and every field above comes
from something already present.

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
per provider:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
    -Provider Microsoft-Windows-Kernel-Process
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dump-fields.ps1 `
    -Provider Microsoft-Windows-PowerShell -Id "4103,4104"
```

`-ExecutionPolicy Bypass` scopes the permission to that one process; a stock
machine refuses to run a script file at all.

Use this rather than `wevtutil gp`, which prints a provider's channels, levels,
opcodes and tasks and **nothing about the data fields** — a difference that costs
an afternoon if you assume otherwise. Enumerated here, that mistake showed
`Kernel-Audit-API-Calls` as having "no named events" when the real answer was
that `wevtutil` never prints the names either way.

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

A non-zero `undecodable` means a property name in `translate.rs` is wrong for
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
If you are adding a shape to `translate.rs`, read the template off a real host
first.

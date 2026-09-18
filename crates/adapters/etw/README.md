# `etw`

The Windows ETW sensor. It owns a real-time trace session, decodes provider
payloads with TDH, and hands the result to the pipeline as wire events.

This crate is `#![cfg(windows)]` and is the only part of the product that talks
to the trace API. It produces telemetry; it does not know what a technique is,
what a rule is, or what an alert is.

## Shape

```
session.rs    owns the kernel session and the thread blocked in ProcessTrace
callback.rs   runs per event on that thread: copies the payload, hands off
decode.rs     runs on the consumer side: rebuilds an EVENT_RECORD, asks TDH
translate.rs  decoded fields -> the wire format the pipeline scores
provider.rs   GUIDs, keyword masks, and the default provider list
stats.rs      counters, including what was lost
error.rs      error codes, hints, and the two remedies worth writing down
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

`translate.rs` maps exactly three shapes today:

| Provider | Event id | Name | Becomes |
|---|---|---|---|
| `Kernel-Process` | 1 | `ProcessStart` | `EventKind::ProcessStart` |
| `Kernel-Registry` | 5 | `RegistrySetValue` | `EventKind::RegistrySet` |
| `DNS-Client` | 3006 | `DnsQuery` | `EventKind::DnsQuery` |

Everything else the session delivers is counted and dropped. That is a
deliberate choice about which events are worth shipping, not a limit of the
sensor.

## The field names come from the machine, not from memory

TDH addresses properties by *name* (`TdhGetProperty` takes a `PCWSTR`, not an
index), and the name has to match the provider's manifest exactly. Every name in
`translate.rs` was read off the shipped templates:

```powershell
Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process
wevtutil gp Microsoft-Windows-Kernel-Registry /ge:true
```

**Both work without elevation.** The manifests are shipped files; reading them is
not a privileged operation, which makes this table checkable on any machine
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
well they test against a fixture. Two other providers on a stock machine do carry
a command line — see [Where a command line actually
comes from](#where-a-command-line-actually-comes-from).

### `RegistrySetValue` has no string value

It carries `KeyObject`, `Status`, `Type`, `DataSize`, `KeyName`, `ValueName`,
`CapturedDataSize`, `CapturedData`, `PreviousDataType` and friends. The value
written is `CapturedData`, a **`Binary`** field sized by `CapturedDataSize`.
There is no `Data` or `ValueData` string, so a rule cannot grep the written value
without decoding the binary form.

Property names are looked up through a chain rather than a single name
(`PROCESS_ID = &["ProcessID", "ProcessId"]`) because templates are not identical
across Windows builds and a miss has to degrade to `None` rather than to a guess.

## Where a command line actually comes from

Verified from this machine's shipped manifests, not from documentation. Both of
these need a policy turned on before the events are emitted at all, so on a
stock host neither one fires and the sensor is correct to be quiet.

### PowerShell 4104 — script text, no policy work beyond logging

```
id=4104  v=1  MessageNumber, MessageTotal, ScriptBlockText, ScriptBlockId, Path
```

`ScriptBlockText` is the script body. Requires **Script Block Logging**
(`EnableScriptBlockLogging`), and covers PowerShell only. This is the direct
route to `T1059.001`: the encoded-command rule reads a command line, and a
script block is the same evidence at a different level.

### Security-Auditing 4688 — every process, with the command line

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
has no `CommandLine` at all.

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

`Translator` keeps its own pair: `mapped` and `undecodable`. A non-zero
`undecodable` means a property name in `translate.rs` is wrong for this build of
Windows — **not** that the machine was quiet — and the first eight failures are
retained with their reason so the report can say which field went missing. A
silent hole is the failure mode this exists to prevent.

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
event names, `FILETIME` conversion, property lookup chains and the error hints —
all against literals. They **cannot** tell you that a field name matches your
machine's manifest, because that is a property of the machine.

That gap is why the report prints `undecodable` and the retained reasons instead
of a bare count. If you are adding a shape to `translate.rs`, read the template
off a real host first.

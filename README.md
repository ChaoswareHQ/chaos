# Chaos

A Windows-first XDR agent and server, built on **ASMR** — Algebraic Security for
Monitoring and Response, the axiom system A1–A30 set out in
[`chaoswarehq/asmr`](https://github.com/chaoswarehq/asmr).

The agent reads ETW, scores what it sees against a cost-derived threshold, and
proposes a response. The server receives telemetry, holds it, and serves a
console that reads like a queue rather than a wall of numbers.

Nothing here is a wrapper around someone else's engine. The detection threshold
is derived from the cost of a false positive against the cost of a missed
intrusion, alert severity comes from the evidence rather than from the response
verb, and the numbers the console prints are the ones the algebra defines — not
ones picked because they look good on a dashboard.

## Status

This is early. It runs, it detects, it ships, it displays, and it can suspend a
process — but see [What is not implemented](#what-is-not-implemented) before
trusting it with anything, because the honest list is longer than the feature
list.

## The shape of the thing

```
apps/
  client/            endpoint agent: collect, score, ship, respond
  server/            axum ingest + zero-JavaScript console

crates/
  asmr/              the algebra: A1-A30, one module per axiom group, no I/O
  model/             the wire format — see crates/model/README.md
  pipeline/          the only crate that knows both the algebra and telemetry
  ports/             traits: sources, sinks, registry, and the actuator
  protocol/          the client/server wire contract, shared by both sides
  transport/         client HTTP, enrollment, batching, retry
  config/            configuration loading
  adapters/
    etw/             Windows ETW sensor — see crates/adapters/etw/README.md
    respond/         response actuation, and the only code that changes a host
    ebpf/  es/       cfg-gated placeholders that refuse rather than pretend
```

Three rules hold the layout together:

1. **`asmr` is mathematics.** Standard library only, no I/O, no globals, no
   third-party crates, and no module imports a sibling. Enforced by tests that
   read the sources.
2. **Adapters produce bytes and know nothing about meaning.** The ETW crate
   decodes a provider payload; it does not know what a technique is.
3. **`pipeline` is where the two meet.** Every place the algebra touches
   telemetry is in that one crate, so the algebra stays testable with numbers
   and the sensor stays testable with bytes.

## Running it

Two processes. The server listens; the agent reads the host it runs on.

```sh
cargo build --release --workspace
```

**Server** — runs anywhere, no privileges needed:

```powershell
.\target\release\server.exe --enrollment-token test-secret-123
```

It prints its bind address, a console URL, and the two agent commands you need.
`--enrollment-token` matters: without it a random secret is generated per run,
so a host enrolled yesterday is not enrolled today.

**Agent** — collects ETW, so this needs **an elevated prompt**:

```powershell
# once, to exchange the bootstrap secret for this host's credential
.\target\release\client.exe --enroll http://127.0.0.1:8787 `
    --enrollment-token test-secret-123 --token-file dev-host.token

# then, to collect and ship until stopped
.\target\release\client.exe --ship http://127.0.0.1:8787 --token-file dev-host.token
```

Without elevation the trace session fails with `code 5`, and the agent says so
along with what to do about it. `--etw SECONDS` bounds a run and prints a full
report; with no duration it runs until stopped.

The console is then at <http://127.0.0.1:8787/>. It is empty until a host enrols
and ships data, which is the correct answer rather than a failure.

## Response

The agent can suspend a process, and this is the one capability in the product
that changes anything. Three gates guard it, and they are independent:

| Gate | Decides | Default |
|---|---|---|
| **Governance** (A12) | whether an action may run without a human | `approve` — propose, never act |
| **Operator** | whether this run may act at all | off — `--respond` to enable |
| **Guards** | whether *this* target may be touched | always on, no configuration opens it |

The third gate is the last word. A protected process is refused even when the
pipeline and the operator both asked for it, and the refusal is logged as a
refusal rather than as a failure, because a guard working is not a bug.

```powershell
# see what this agent would do, and touch nothing
client.exe --ship http://127.0.0.1:8787 --token-file dev-host.token --respond --dry-run

# propose only; governance refuses to run a disruptive action unattended
client.exe --ship http://127.0.0.1:8787 --token-file dev-host.token --respond

# allow a freeze to run without a human
client.exe --ship http://127.0.0.1:8787 --token-file dev-host.token `
    --respond --autonomy auto --max-auto high
```

Only `freeze` maps to a concrete action. `isolate` is deliberately unmapped, so
no alert can claim a host was isolated when nothing isolated it. A suspend is
released when the agent stops, including on Ctrl-C — a stopped agent does not
leave a process frozen.

## How a detection happens

One event, in order:

1. **Project** into the A1 state space; append to the A2 trace.
2. **Evaluate** the rules. Each produces a [`Finding`] carrying a likelihood
   ratio, not a verdict.
3. **Accumulate** as log-odds (A5) — addition, because independent evidence
   composes additively in that representation.
4. **Decide** (A8) against a threshold derived by the threshold theorem from
   `C_fp : C_fn`, which defaults to 1 : 20.
5. **Govern** (A12) the chosen action, recording the outcome whether or not it
   was permitted.
6. **Minimise** (A19) the alert body before it leaves the host.

The rules are in `crates/pipeline/src/rules.rs`, each naming its technique:

| Rule | Technique | What it reads |
|---|---|---|
| `encoded_powershell` | T1059.001 | an interpreter invoked with an encoded command |
| `interpreter_from_host_app` | T1059 | an interpreter spawned by an application with no business spawning one |
| `masquerading_outside_system32` | T1036.005 | a system binary's name in a location a system binary never runs from |
| `lolbin_remote_fetch` | T1218 | a signed binary used against a remote location |
| `run_key_persistence` | T1547.001 | a value written under a Run key |
| `high_abuse_tld` | T1071.004 | name resolution in a high-abuse namespace |
| `novel_binary_in_writable_location` | T1036 | first sighting (A22) of a binary in a writable place |
| `process_fanout_burst` | T1055 | a parent producing children at an unusual rate |
| `script_block_encoded_command` | T1059.001 | a PowerShell script that passes an encoded command |
| `script_block_obfuscated` | T1140 | a PowerShell script that decodes or assembles itself |
| `script_block_remote_fetch` | T1105 | a PowerShell script that fetches over the network |
| `script_block_defence_evasion` | T1562.001 | a PowerShell script that touches AMSI or Defender |

The last four read a PowerShell `4104` script block rather than a command line,
which is the only way `T1059.001` fires on a live host: the process provider on
Windows carries no command line, so `encoded_powershell` needs a source that does.
A 4104 also carries the *whole script* rather than the first 260 characters of a
command line, which is where a staged loader keeps its payload. They report which
pattern matched and never quote the script — an alert body is minimised before it
leaves the host (A19), and the script is the most sensitive thing on the machine.

Each tell is its own finding with its own likelihood, so a loader that fetches,
decodes and disables AMSI adds three pieces of evidence rather than asserting one
verdict. That follows A5, and it carries A5's caveat as well: the tells are
correlated in reality and treated as independent here, so a loader's posterior is
higher than a strict reading would give. It matters at the top of the range, where
the decision has already been made.

## The console

Four pages, server-rendered, **no JavaScript**, one dense table per page, and a
`default-src 'none'; style-src 'self'` CSP. Every control is a link and the
filters are both the state and the URL, so a view can be shared by copying it.

- **Detections** — the queue, one row per `(host, rule)`, severity distribution
  as filters rather than as a chart
- **Hosts** — what has enrolled and what is silent
- **Techniques** — coverage by MITRE technique
- **Detection** — drill-down: evidence, and the sibling firings

Repeat firings of one rule are folded into one row carrying a count, because a
queue of two hundred near-identical rows is the same as no queue: the analyst
stops reading it.

The console has no authentication. That is why it has no acknowledge or close
button — there is no identity to attribute a write to yet, and adding the button
first would produce a queue full of claims about who closed what.

## Testing

The suite is run as

```sh
cargo test --workspace
cargo fmt --all --check
```

and the tests are written to fail when the interesting thing is wrong rather than
to raise a coverage number, which is why several of them exist because a run on a
real machine found a bug the suite had been happy with:

- counts froze at 4,210 while events passed 2M, because a flush advanced a copy
  of the alert instead of the alert;
- the server *added* merged counts instead of replacing them, so a restated
  alert inflated its own total;
- `explorer.exe` was flagged as masquerading 27,441 times;
- `T1547.001` could never fire, because the registry provider was not enabled.

## What is not implemented

Stated plainly, because the alternative is a reader assuming these are done:

- **No TLS.** Enrollment and ingest are cleartext. The client refuses to send a
  token to anything but loopback for that reason; the server refuses a
  non-loopback bind without `--allow-cleartext`. A bearer token over a network
  without TLS is not a security boundary.
- **The store is in memory.** Restarting the server forgets everything,
  including enrollment.
- **The enrollment token is reusable and cannot be revoked.** It is capped at
  500 hosts and is a shared bootstrap secret, not per-host.
- **The console has no authentication.**
- **Response covers suspend only**, on Windows only. No quarantine, no
  isolation, no registry repair.
- **Response has never suspended a process on real hardware in testing.** The
  guards, the gates and the dry-run path are exercised by tests that call the
  real OS bindings; the call that actually suspends has not been run, because a
  freeze needs `p ≥ 0.98` from live evidence and a trace session needs
  elevation.
- **No HTTP proxy support** in the client.
- **Alert rows do not record which process** they came from; the evidence body
  carries the detail.
- **`crates/config` is not wired to the server** — the server's flags are
  parsed in its own `main`.
- **`T1218` cannot fire on a live host yet.** It reads a command line, and the
  process provider does not carry one. The route is Security-Auditing `4688` v2
  (`CommandLine`, `ParentProcessName`) once `Audit Process Creation` and
  `ProcessCreationIncludeCmdLine_Enabled` are on; the field names are verified in
  [`crates/adapters/etw/README.md`](crates/adapters/etw/README.md) and no shape
  reads them yet.
- **The PowerShell script-block rules have never seen a live 4104.** The decode
  path, the rules and the end-to-end result are covered by tests; the field names
  are verified against this machine's manifest. What is untested is a real script
  block in a real batch, because the host needs Script Block Logging on for one to
  exist at all.
- **Evidence from different tells is summed as if independent**, which A5 says to
  do and which is not strictly true: a loader that fetches, decodes and disables
  AMSI is one behaviour, not three. The effect is a higher posterior at the top of
  the range, where the decision is already made.
- **The event schema is version 2** as of the `Payload` change. A client and a
  server built from different commits will not understand each other's events,
  so rebuild both together.

## License

MIT OR Apache-2.0.

[`Finding`]: crates/pipeline/src/rules.rs

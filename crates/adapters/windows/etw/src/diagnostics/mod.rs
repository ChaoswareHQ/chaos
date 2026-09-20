//! Operator-facing checks. Never on the hot path.
//!
//! These modules answer two questions an operator actually asks:
//!
//! * **Is the sensor trustworthy?** — [`security`]. Inspects the `ntdll`
//!   exports in this process for patches, compares the whole `.text`
//!   section against the on-disk copy, checks the trace session's health
//!   against the kernel, and reports whether VBS/HVCI is constraining
//!   kernel-level tampering.
//!
//! * **Is the sensor configured the way it should be?** — [`autologger`].
//!   Reads `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<session>`
//!   and reports whether a boot-time session exists, is started, is
//!   real-time, and has the expected providers with the expected keyword
//!   masks.
//!
//! # Where they run
//!
//! Neither module is called from the callback or from `Translator`. They
//! are called once at startup, once at shutdown, and on demand via a CLI
//! flag. A sensor that spent its hot path on `VirtualProtect` checks would
//! be a sensor that could not keep up with its own events.
//!
//! # The residual gap
//!
//! Three bypasses are not caught by anything in [`security`]:
//!
//! * **IAT hooks** — modifying the import table of a *calling* module so
//!   the call never reaches `ntdll`. The bytes in `ntdll` are untouched.
//! * **Hardware breakpoints** — setting `DR0`–`DR3` via a vectored
//!   exception handler. No bytes change, so no byte comparison can see it.
//! * **Detector self-patching** — patching the code of
//!   `check_ntdll_exports` itself. This is the "who watches the watchmen"
//!   problem and cannot be solved from inside the same process.
//!
//! Closing these requires either a separate process reading this one's
//! memory, or kernel-level monitoring. The correct architecture for a
//! high-assurance deployment, and out of scope for this crate.

pub mod autologger;
pub mod security;

//! Host-local facts the kernel does not emit.
//!
//! Four modules, one pattern: the kernel gives us one form, the rule
//! author expects another, and the work happens on the sensor's side.
//! Each module is a self-contained "the event tells us X, but the rule
//! needs Y" translation.
//!
//! * [`paths`] — `\Device\HarddiskVolumeN\...` → `C:\...`.
//!   The mount manager knows the mapping; the kernel's ETW providers do
//!   not consult it. [`paths::DevicePaths`] queries it once and caches.
//!
//! * [`registry`] — `\REGISTRY\MACHINE\...` → `HKLM\...`.
//!   A fixed prefix table, no query, no state. Pure function.
//!
//! * [`image`] — SHA-256 + Authenticode signature, cached on
//!   `(path, mtime, size)`. The kernel does not hash files or check
//!   signatures; that is user-mode work, and doing it once per file is
//!   cheap because the working set of loaded DLLs is tiny.
//!
//! * [`kcb`] — the KCB pointer → registry path correlation. `SetValueKey`
//!   events carry a kernel pointer and no path; the events that carry
//!   both teach the cache, and the writes read from it.
//!
//! # The rule for adding a new one
//!
//! It must be a **pure fact about this host**, not a detection. A
//! detection belongs in `pipeline`. A translation, a lookup, or a derived
//! value belongs here.
//!
//! It must be **bounded**. Every module here has a size ceiling and an
//! eviction policy. An enrichment cache that grows without bound is a
//! memory leak with a security-sounding name.

pub mod image;
pub mod kcb;
pub mod paths;
pub mod registry;

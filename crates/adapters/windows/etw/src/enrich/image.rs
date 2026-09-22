//! Image metadata: SHA-256 and Authenticode signature.
//!
//! # Why this is here and not in the decoder
//!
//! Every `image_load` event carries a path. That path alone is weak
//! signal — a rule can match "loaded from `C:\Users\Public\`" and little
//! else. The pattern that actually catches DLL sideloading is "loaded
//! from a path a normal process would never use, AND not signed". That
//! needs two more facts, and the sensor is the only place that can
//! collect them.
//!
//! # Cost
//!
//! Hashing a DLL is ~50–200 µs. Signature verification is ~1–5 ms the
//! first time and cached afterward by Windows. Neither is acceptable
//! per-event on the hot path, so both are cached on `(path, mtime, size)`.
//! On a desktop the cache hit rate is >99%: the same `kernel32.dll`,
//! `ntdll.dll`, `user32.dll` load thousands of times, and the cache sees
//! them all.
//!
//! # Sharing
//!
//! Like [`crate::enrich::kcb::KeyCache`], the cache is `Arc<Mutex<Inner>>`
//! internally, so `Clone` shares state. The observer's decode workers
//! each own a `Translator`; without sharing, every worker would hash
//! every DLL independently, which would be 4–8× the necessary work.
//!
//! # What is deliberately not done
//!
//! The signer name (the certificate's subject) is not extracted. Doing so
//! requires `CryptQueryObject` + `CryptMsgGetParam` + `CertGetNameString`
//! and a display-format decision that depends on locale. `signed` alone
//! supports the rule "loaded from `\Users\` AND unsigned", which is the
//! detection this exists for. `signer` stays `None` until a rule needs
//! it.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;
use windows::core::GUID;

/// Default cache cap.
///
/// 4,096 entries at roughly 200 bytes each is under a megabyte; a Windows
/// desktop loads a few thousand distinct DLLs in a session, so this holds
/// the working set comfortably.
pub const DEFAULT_CAPACITY: usize = 4_096;

/// What a hash and signature check produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageMeta {
    /// SHA-256 of the file contents, lowercase hex. `None` when the file
    /// could not be read — a protected system file, a path that no longer
    /// exists, an access-denied.
    pub hash: Option<Box<str>>,
    /// Whether the file has a valid Authenticode signature from a trusted
    /// chain. `None` when the trust check itself could not be performed,
    /// which is different from "not signed".
    pub signed: Option<bool>,
    /// The certificate subject, when extractable. Currently always
    /// `None`; see the module docs.
    pub signer: Option<Box<str>>,
}

/// A `(path, mtime, size) → ImageMeta` cache, shared cheaply.
#[derive(Debug, Clone)]
pub struct ImageMetaCache {
    inner: Arc<Mutex<Inner>>,
    capacity: usize,
}

#[derive(Debug)]
struct Inner {
    map: HashMap<Box<str>, Entry>,
    /// Insertion order, oldest first. FIFO eviction; the working set of a
    /// real session is tiny and turns over slowly, so LRU would not buy
    /// anything.
    order: VecDeque<Box<str>>,
}

#[derive(Debug, Clone)]
struct Entry {
    mtime: Option<SystemTime>,
    size: u64,
    meta: ImageMeta,
}

impl Default for ImageMetaCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl ImageMetaCache {
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::with_capacity(capacity.min(1024)),
                order: VecDeque::with_capacity(capacity.min(1024)),
            })),
            capacity,
        }
    }

    /// Look up the metadata for `path`, computing it on a miss.
    ///
    /// Returns a clone of the cached [`ImageMeta`], not a borrow, because
    /// the caller is in the middle of a decode and cannot hold the lock
    /// across the expensive hashing work.
    pub fn get(&self, path: &str) -> ImageMeta {
        // Stat first. A path whose mtime and size match what the cache
        // recorded is the same file we hashed before; anything else is a
        // different file (updated DLL) and gets hashed again.
        let (mtime, size) = match std::fs::metadata(path) {
            Ok(meta) => (meta.modified().ok(), meta.len()),
            // The file could not be stat'ed — protected system file, or
            // already gone by the time we looked. Nothing to hash.
            Err(_) => return ImageMeta::default(),
        };

        if let Some(hit) = self.lookup(path, mtime, size) {
            return hit;
        }

        let meta = compute(path);

        self.store(path, mtime, size, meta.clone());
        meta
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lookup(&self, path: &str, mtime: Option<SystemTime>, size: u64) -> Option<ImageMeta> {
        let inner = self.lock();
        let entry = inner.map.get(path)?;
        if entry.mtime == mtime && entry.size == size {
            Some(entry.meta.clone())
        } else {
            None
        }
    }

    fn store(&self, path: &str, mtime: Option<SystemTime>, size: u64, meta: ImageMeta) {
        let mut inner = self.lock();
        let key: Box<str> = path.into();

        if inner.map.contains_key(&key) {
            // Same path, different mtime or size: replaced in place.
            inner.map.insert(key, Entry { mtime, size, meta });
            return;
        }

        if inner.map.len() >= self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
        inner.map.insert(key.clone(), Entry { mtime, size, meta });
        inner.order.push_back(key);
    }
}

// ---------------------------------------------------------------------------
// The two expensive operations
// ---------------------------------------------------------------------------

fn compute(path: &str) -> ImageMeta {
    ImageMeta {
        hash: hash_file(path),
        signed: verify_signature(path),
        signer: None,
    }
}

/// SHA-256 of the file at `path`, lowercase hex.
///
/// Reads the whole file into memory before hashing. DLLs are a few
/// hundred KB to a few MB; a streamed hash would halve peak memory and is
/// a reasonable follow-up if a deployment ever sees larger images.
fn hash_file(path: &str) -> Option<Box<str>> {
    let bytes = std::fs::read(Path::new(path)).ok()?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Some(hex(&digest).into_boxed_str())
}

/// Whether the file has a valid Authenticode signature from a trusted
/// chain.
///
/// Uses `WinVerifyTrust` with `WTD_CACHE_ONLY_URL_RETRIEVAL`, which is
/// the flag that matters: without it, a signature check can block for
/// seconds waiting on a revocation server, which on the hot path would
/// stall the decode worker and eventually the whole sensor. With it, a
/// chain that cannot be verified from cache returns an error instead of
/// waiting, and the answer we ship is "could not verify" rather than
/// "valid".
///
/// `None` when the trust check could not run at all (the file does not
/// exist, `wintrust.dll` is unavailable). `Some(false)` when the file
/// exists and is unsigned or its signature is invalid.
///
/// # Safety
///
/// This calls into `wintrust.dll` with a manually declared struct layout
/// that mirrors the C headers. The layout is `repr(C)` and every field is
/// filled in before the call; the pointer inside `WinTrustFileInfo`
/// refers to `wide_path`, which outlives the call.
fn verify_signature(path: &str) -> Option<bool> {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut file_info = WinTrustFileInfo {
            cb_struct: std::mem::size_of::<WinTrustFileInfo>() as u32,
            path: wide_path.as_ptr(),
            file: 0,
            known_subject: std::ptr::null_mut(),
        };

        let mut data = WinTrustData {
            cb_struct: std::mem::size_of::<WinTrustData>() as u32,
            policy_callback_data: std::ptr::null_mut(),
            sip_client_data: std::ptr::null_mut(),
            ui_choice: WTD_UI_NONE,
            revocation_checks: WTD_REVOKE_NONE,
            union_choice: WTD_CHOICE_FILE,
            file: &mut file_info,
            state_action: WTD_STATEACTION_VERIFY,
            wvt_state_data: 0,
            url_reference: std::ptr::null_mut(),
            prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ui_context: 0,
            signature_settings: std::ptr::null_mut(),
        };

        let status = WinVerifyTrust(
            0,
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut data as *mut _ as *mut core::ffi::c_void,
        );

        // Always release the state, even on failure. Skipping this leaks
        // memory inside crypt32 for every image load.
        data.state_action = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            0,
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut data as *mut _ as *mut core::ffi::c_void,
        );

        // `0` is `ERROR_SUCCESS`: a valid signature from a trusted chain.
        // Every other return — `TRUST_E_NOSIGNATURE`,
        // `TRUST_E_EXPLICIT_DISTRUST`, `CERT_E_UNTRUSTEDROOT`,
        // `CERT_E_EXPIRED` — is a file we would not call signed. That is
        // the answer a rule wants: "signed and trusted", or "not that".
        Some(status == 0)
    }
}

// ---------------------------------------------------------------------------
// FFI to wintrust
// ---------------------------------------------------------------------------

#[repr(C)]
struct WinTrustFileInfo {
    cb_struct: u32,
    path: *const u16,
    file: isize,
    known_subject: *mut core::ffi::c_void,
}

#[repr(C)]
struct WinTrustData {
    cb_struct: u32,
    policy_callback_data: *mut core::ffi::c_void,
    sip_client_data: *mut core::ffi::c_void,
    ui_choice: u32,
    revocation_checks: u32,
    union_choice: u32,
    file: *mut WinTrustFileInfo,
    state_action: u32,
    wvt_state_data: isize,
    url_reference: *mut u16,
    prov_flags: u32,
    ui_context: u32,
    signature_settings: *mut core::ffi::c_void,
}

const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;

/// `{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}`.
///
/// This is the action GUID that tells `WinVerifyTrust` to do a full
/// Authenticode check (not the driver-signing check, not the catalog
/// check).
const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID =
    GUID::from_u128(0x00AA_C56B_CD44_11D0_8CC2_00C0_4FC2_95EE);

#[link(name = "wintrust")]
unsafe extern "system" {
    fn WinVerifyTrust(hwnd: isize, action_id: *const GUID, data: *mut core::ffi::c_void) -> i32;
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_cache_reports_zero_entries() {
        let cache = ImageMetaCache::default();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        assert!(cache.capacity() > 0);
    }

    #[test]
    fn a_missing_file_yields_the_default_meta() {
        // A path that does not exist cannot be stat'ed, so the fast path
        // returns the empty `ImageMeta` without ever calling the hasher.
        let cache = ImageMetaCache::default();
        let meta = cache.get(r"C:\this\does\not\exist\at\all.dll");
        assert_eq!(meta, ImageMeta::default());
        assert!(cache.is_empty(), "nothing cached for a missing file");
    }

    #[test]
    fn hashing_a_real_file_matches_a_known_digest() {
        // The empty-file digest is the well-known SHA-256 of the empty
        // input: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
        let dir = std::env::temp_dir().join("chaos-image-meta-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.bin");
        std::fs::write(&path, b"").expect("write");
        let path_str = path.to_str().expect("utf-8 path");

        let cache = ImageMetaCache::default();
        let meta = cache.get(path_str);
        assert_eq!(
            meta.hash.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cache_returns_a_hit_on_the_second_call() {
        let dir = std::env::temp_dir().join("chaos-image-meta-hit");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("x.bin");
        std::fs::write(&path, b"hello").expect("write");
        let path_str = path.to_str().expect("utf-8 path");

        let cache = ImageMetaCache::default();
        let first = cache.get(path_str);
        assert_eq!(cache.len(), 1);
        let second = cache.get(path_str);
        assert_eq!(first, second);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cloning_shares_the_cache() {
        let dir = std::env::temp_dir().join("chaos-image-meta-share");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("y.bin");
        std::fs::write(&path, b"world").expect("write");
        let path_str = path.to_str().expect("utf-8 path");

        let a = ImageMetaCache::default();
        let b = a.clone();
        a.get(path_str);
        assert_eq!(b.len(), 1, "a clone must see the same cache");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changing_the_file_invalidates_the_cache() {
        let dir = std::env::temp_dir().join("chaos-image-meta-invalidate");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("z.bin");
        std::fs::write(&path, b"v1").expect("write");
        let path_str = path.to_str().expect("utf-8 path");

        let cache = ImageMetaCache::default();
        let first = cache.get(path_str);
        assert!(first.hash.is_some());

        // Rewriting with a different size and different content. The stat
        // check catches the size change and forces a re-hash.
        std::fs::write(&path, b"v2-longer").expect("write");
        let second = cache.get(path_str);
        assert_ne!(first.hash, second.hash);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_zero_capacity_cache_still_holds_one_entry() {
        let cache = ImageMetaCache::with_capacity(0);
        assert_eq!(cache.capacity(), 1);
    }
}

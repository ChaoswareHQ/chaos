//! Per-shape decoders.
//!
//! Each returns `Result<EventKind, String>` where the `Err` string names
//! the field that was missing or empty. Callers log it via
//! [`super::Translator`]'s failure log and increment `undecodable`; the
//! reason must be specific enough that an operator can act on it, which
//! is why "no ImageName" is not "decode failed".
//!
//! # Two rules this module holds to
//!
//! * **Empty string is missing.** A field that resolves to `""` is treated
//!   the same as a field that did not resolve. The registry-key bug that
//!   produced `key=` in production was exactly this: TDH returned an
//!   empty string and the old decoder accepted it as a value.
//! * **A shape is not `mapped` until its mandatory fields are present.**
//!   `note_mapped` fires only after the decoder returns `Ok`.
//!
//! # Two enrichments over the raw event
//!
//! * `registry_set` reads the path from the KCB cache when the manifest's
//!   `KeyName` is empty, then translates it to the documentation spelling
//!   (`\REGISTRY\MACHINE\...` → `HKLM\...`).
//! * `image_load` fills `image_hash`, `signed`, and `signer` from the
//!   image-metadata cache, so a rule can match "loaded from an unusual
//!   path AND not signed".

use super::shape::*;
use super::Translator;
use crate::boundary::callback::EtwRaw;
use crate::decode::FieldValue;
use crate::enrich::{image::ImageMeta, paths::DevicePaths, registry};
use chrono::{DateTime, Utc};
use model::{
    DnsQueryPayload, EventKind, ImageLoad, ProcessExit, ProcessId, ProcessStart, RegistrySet,
    ScriptBlock,
};

impl Translator {
    pub(super) fn process_start(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let image = self
            .decoder
            .text_first_nonempty(raw, IMAGE_NAME)
            .ok_or("no ImageName; cannot attribute the process")?;
        let image = DevicePaths::global().translate(&image).into_owned();

        let pid = self
            .decoder
            .u32_any(raw, PROCESS_ID)
            .unwrap_or(raw.wire.pid);

        Ok(EventKind::ProcessStart(ProcessStart {
            pid: ProcessId::new(pid),
            parent_pid: self
                .decoder
                .u32_any(raw, PARENT_PROCESS_ID)
                .map(ProcessId::new),
            executable: image.into(),
            command_line: None,
            user: None,
            working_directory: None,
            started_at: at,
            image_hash: None,
            integrity_level: None,
            is_wow64: raw.is_wow64,
        }))
    }

    pub(super) fn process_exit(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        // The exit event's `ProcessID` is the process that exited; the
        // header's `ProcessId` is the same value on this provider, but
        // reading the field directly keeps the two paths honest.
        let pid = self
            .decoder
            .u32_any(raw, PROCESS_ID)
            .unwrap_or(raw.wire.pid);
        let exit_code = self.decoder.u32_any(raw, EXIT_CODE).map(|v| v as i32);

        Ok(EventKind::ProcessExit(ProcessExit {
            pid: ProcessId::new(pid),
            exit_code,
            exited_at: at,
        }))
    }

    pub(super) fn image_load(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let image = self
            .decoder
            .text_first_nonempty(raw, IMAGE_NAME)
            .ok_or("no ImageName; cannot attribute the loaded module")?;
        let image = DevicePaths::global().translate(&image).into_owned();

        let pid = self
            .decoder
            .u32_any(raw, PROCESS_ID)
            .unwrap_or(raw.wire.pid);

        // Metadata (hash + signature) is looked up per path, cached on
        // (path, mtime, size). The cache is shared across workers so a
        // module loaded twice in the same process is hashed once.
        let meta: ImageMeta = self.image_meta.get(&image);

        Ok(EventKind::ImageLoad(ImageLoad {
            pid: ProcessId::new(pid),
            image_path: image.into(),
            image_hash: meta.hash,
            signed: meta.signed,
            signer: meta.signer,
            loaded_at: at,
            is_wow64: raw.is_wow64,
        }))
    }

    pub(super) fn registry_set(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        // Read the path, in one of two ways, in order of preference:
        //
        // 1. `KeyName` (or an alternative spelling) is present and
        //    non-empty — use it directly. This is what happens on a build
        //    where the kernel does resolve the path before the event is
        //    emitted.
        //
        // 2. `KeyName` is empty but the KCB cache knows the pointer. This
        //    is what happens on every current build: `learn_kcb` has been
        //    filling the cache from `OpenKey`, `CreateKey`, and the
        //    `KCBCreate` family, and the `SetValueKey` event's
        //    `KeyObject` is looked up.
        //
        // A miss from both goes to `undecodable` with a reason that names
        // the pointer — the operator sees a specific fact, not a generic
        // failure.
        let kernel_path = match self.decoder.text_first_nonempty(raw, KEY_NAME) {
            Some(path) => path,
            None => {
                let key_object = self.decoder.u64_any(raw, KCB_KEY_OBJECT).unwrap_or(0);
                match self.key_cache.lookup(key_object) {
                    Some(path) => {
                        self.kcb_hits += 1;
                        path
                    }
                    None => {
                        self.kcb_misses += 1;
                        return Err(format!(
                            "KeyName empty and KeyObject {key_object:#018x} unknown to the \
                             KCB cache (learned {} so far, cache holds {}/{})",
                            self.kcb_learned,
                            self.key_cache.len(),
                            self.key_cache.capacity(),
                        ));
                    }
                }
            }
        };

        // Translate `\REGISTRY\MACHINE\...` to `HKLM\...` so a rule author
        // never has to know the kernel's spelling.
        let key_path = registry::translate(&kernel_path).into_owned();

        let value_data = match self.decoder.typed_field(raw, CAPTURED_DATA) {
            Some((FieldValue::Binary(bytes), _)) => {
                let declared = self.decoder.u32_any(raw, REGISTRY_TYPE).unwrap_or(0);
                Some(super::render::render_registry_value(declared, &bytes).into())
            }
            Some((other, _)) => Some(render_field(&other).into()),
            None => None,
        };

        Ok(EventKind::RegistrySet(RegistrySet {
            pid: ProcessId::new(raw.wire.pid),
            key_path: key_path.into(),
            value_name: self
                .decoder
                .text_first_nonempty(raw, VALUE_NAME)
                .map(Into::into),
            value_data,
            set_at: at,
        }))
    }

    pub(super) fn dns_query(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let name = self
            .decoder
            .text_first_nonempty(raw, QUERY_NAME)
            .ok_or("no QueryName; cannot tell what was looked up")?;

        Ok(EventKind::DnsQuery(DnsQueryPayload {
            pid: ProcessId::new(raw.wire.pid),
            query_name: name.into(),
            query_type: self
                .decoder
                .u32_any(raw, QUERY_TYPE)
                .map(super::render::query_type_name)
                .unwrap_or_else(|| "A".to_string())
                .into(),
            answers: Vec::new(),
            response_code: None,
            queried_at: at,
        }))
    }

    pub(super) fn script_block(
        &mut self,
        raw: &EtwRaw,
        at: DateTime<Utc>,
    ) -> Result<EventKind, String> {
        let text = self
            .decoder
            .text_first_nonempty(raw, SCRIPT_BLOCK_TEXT)
            .ok_or("no ScriptBlockText; cannot tell what was run")?;

        let path = self
            .decoder
            .text_first_nonempty(raw, SCRIPT_BLOCK_PATH)
            .map(|p| DevicePaths::global().translate(&p).into_owned());

        Ok(EventKind::ScriptBlock(ScriptBlock {
            pid: ProcessId::new(raw.wire.pid),
            text: super::render::cap_script_text(&text).into(),
            script_block_id: self
                .decoder
                .text_first_nonempty(raw, SCRIPT_BLOCK_ID)
                .map(Into::into),
            path: path.map(Into::into),
            message_number: self.decoder.u32_any(raw, MESSAGE_NUMBER),
            message_total: self.decoder.u32_any(raw, MESSAGE_TOTAL),
            recorded_at: at,
        }))
    }
}

/// Render a non-binary `FieldValue` as text.
///
/// Kept separate from `decode::value::render_text` because that one is
/// `pub(crate)` inside `decode` and this is used by decoders that receive
/// a value from `typed_field` and want its string form. The two render
/// identically; the split is about where each is called from.
pub(crate) fn render_field(value: &FieldValue) -> String {
    match value {
        FieldValue::Str(s) => s.clone(),
        FieldValue::I8(v) => v.to_string(),
        FieldValue::U8(v) => v.to_string(),
        FieldValue::I16(v) => v.to_string(),
        FieldValue::U16(v) => v.to_string(),
        FieldValue::I32(v) => v.to_string(),
        FieldValue::U32(v) => v.to_string(),
        FieldValue::I64(v) => v.to_string(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::F32(v) => v.to_string(),
        FieldValue::F64(v) => v.to_string(),
        FieldValue::Guid(b) => super::render::hex(b),
        FieldValue::Binary(b) => super::render::hex(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_field_renders_every_variant() {
        assert_eq!(render_field(&FieldValue::Str("x".into())), "x");
        assert_eq!(render_field(&FieldValue::I32(-1)), "-1");
        assert_eq!(render_field(&FieldValue::U32(42)), "42");
        assert_eq!(render_field(&FieldValue::U64(u64::MAX)), u64::MAX.to_string());
        assert_eq!(render_field(&FieldValue::Binary(vec![0xab])), "ab");
        assert_eq!(render_field(&FieldValue::Guid([0u8; 16])), "0".repeat(32));
    }
}

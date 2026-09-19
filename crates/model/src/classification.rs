#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataClass {
    Public,
    Internal,
    Sensitive,
}

pub const REDACTED: &str = "[REDACTED]";

impl DataClass {
    #[inline]
    pub const fn requires_redaction(self) -> bool {
        matches!(self, DataClass::Sensitive)
    }

    #[inline]
    pub const fn retention_days(self) -> u32 {
        match self {
            DataClass::Public | DataClass::Internal => 365,
            DataClass::Sensitive => 90,
        }
    }

    #[inline]
    pub const fn stripped_in_cold_storage(self) -> bool {
        matches!(self, DataClass::Sensitive)
    }

    #[inline]
    pub const fn requires_export_opt_in(self) -> bool {
        matches!(self, DataClass::Sensitive)
    }

    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            DataClass::Public => "public",
            DataClass::Internal => "internal",
            DataClass::Sensitive => "sensitive",
        }
    }
}

impl Default for DataClass {
    #[inline]
    fn default() -> Self {
        DataClass::Sensitive
    }
}

impl std::fmt::Display for DataClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[inline]
pub fn class_of(field: &str) -> DataClass {
    class_of_known(field).unwrap_or(DataClass::Sensitive)
}

/// The explicit classification table, without the fail-closed default.
///
/// `None` means the field is not in the table. Callers that need a decision
/// should use [`class_of`] instead; this exists because "we decided this is
/// sensitive" and "we have never heard of this" are different situations that
/// deserve different handling. Redaction in particular has to tell them apart,
/// or a payload keyed by provider-specific names collapses entirely.
pub fn class_of_known(field: &str) -> Option<DataClass> {
    match field {
        "pid" | "parent_pid" | "tid" | "exit_code" | "level" | "source_port"
        | "destination_port" | "bytes_sent" | "bytes_received" | "size" | "bytes_written"
        | "started_at" | "exited_at" | "initiated_at" | "ended_at" | "created_at"
        | "written_at" | "deleted_at" | "renamed_at" | "set_at" | "queried_at" | "loaded_at"
        | "image_hash" | "signed" | "signer" | "integrity_level" | "protocol" | "query_type"
        | "response_code" | "id" | "event_id" | "schema_version" | "source" | "rule_id"
        | "alert_id" | "severity" | "status" | "kind" | "mitre_techniques" | "enabled"
        | "message_number" | "message_total" | "recorded_at" => {
            Some(DataClass::Public)
        }

        "source_ip" | "destination_ip" | "provider" | "hostname" | "os" | "labels"
        | "first_seen" | "last_seen"
        // Identifies which block, not what was in it, and is the join key when a
        // long script arrives in fragments.
        | "script_block_id" => Some(DataClass::Internal),

        "command_line" | "user" | "executable" | "image_path" | "path" | "old_path"
        | "new_path" | "working_directory" | "key_path" | "value_name" | "value_data"
        | "query_name" | "answers" | "title" | "description" | "host" | "host_id" | "events"
        // Script text is the interpreter's input: the same class of secret as a
        // command line, and in practice more of it. Naming it here rather than
        // letting it fall through to the fail-closed default is about intent —
        // the answer is the same, and a reader should not have to derive it.
        | "text" => {
            Some(DataClass::Sensitive)
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_fields() {
        assert_eq!(class_of("pid"), DataClass::Public);
        assert_eq!(class_of("image_hash"), DataClass::Public);
        assert_eq!(class_of("started_at"), DataClass::Public);
        assert_eq!(class_of("severity"), DataClass::Public);
        assert_eq!(class_of("event_id"), DataClass::Public);
        assert_eq!(class_of("renamed_at"), DataClass::Public);
    }

    #[test]
    fn internal_fields() {
        assert_eq!(class_of("source_ip"), DataClass::Internal);
        assert_eq!(class_of("destination_ip"), DataClass::Internal);
        assert_eq!(class_of("hostname"), DataClass::Internal);
        assert_eq!(class_of("provider"), DataClass::Internal);
    }

    #[test]
    fn sensitive_fields() {
        assert_eq!(class_of("command_line"), DataClass::Sensitive);
        assert_eq!(class_of("user"), DataClass::Sensitive);
        assert_eq!(class_of("path"), DataClass::Sensitive);
        assert_eq!(class_of("old_path"), DataClass::Sensitive);
        assert_eq!(class_of("new_path"), DataClass::Sensitive);
        assert_eq!(class_of("executable"), DataClass::Sensitive);
        assert_eq!(class_of("query_name"), DataClass::Sensitive);
        assert_eq!(class_of("value_data"), DataClass::Sensitive);
    }

    #[test]
    fn unknown_fields_fail_closed() {
        assert_eq!(class_of("environment_variables"), DataClass::Sensitive);
        assert_eq!(class_of("some_future_field"), DataClass::Sensitive);
        assert_eq!(class_of(""), DataClass::Sensitive);
    }

    #[test]
    fn the_explicit_table_reports_ignorance_as_ignorance() {
        // `class_of` and `class_of_known` must agree on everything the table
        // knows, and differ only on what it does not.
        assert_eq!(class_of_known("pid"), Some(DataClass::Public));
        assert_eq!(class_of_known("command_line"), Some(DataClass::Sensitive));
        assert_eq!(class_of_known("hostname"), Some(DataClass::Internal));
        assert_eq!(class_of_known("image_path"), Some(DataClass::Sensitive));

        assert_eq!(class_of_known("environment_variables"), None);
        assert_eq!(class_of_known("some_future_field"), None);
        assert_eq!(class_of_known(""), None);

        assert_eq!(class_of("some_future_field"), DataClass::Sensitive);
    }

    #[test]
    fn policy_methods() {
        assert!(DataClass::Sensitive.requires_redaction());
        assert!(!DataClass::Public.requires_redaction());
        assert_eq!(DataClass::Sensitive.retention_days(), 90);
        assert_eq!(DataClass::Public.retention_days(), 365);
        assert!(DataClass::Sensitive.stripped_in_cold_storage());
        assert!(DataClass::Sensitive.requires_export_opt_in());
    }
}

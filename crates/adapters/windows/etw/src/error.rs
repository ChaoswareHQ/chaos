use thiserror::Error;
use windows::core::GUID;

/// Everything the sensor can fail at, with the OS error code preserved so a
/// caller can tell "you are not elevated" apart from "someone already owns this
/// session name".
#[derive(Debug, Error)]
pub enum EtwError {
    #[error("StartTraceW failed with code {code} ({hint})")]
    StartTrace { code: u32, hint: &'static str },

    #[error("EnableTraceEx2 failed for provider {guid:?} with code {code} ({hint})")]
    EnableProvider {
        guid: GUID,
        code: u32,
        hint: &'static str,
    },

    #[error("OpenTraceW failed")]
    OpenTrace,

    #[error("ProcessTrace failed with code {0}")]
    ProcessTrace(u32),

    #[error("ControlTraceW failed with code {0}")]
    ControlTrace(u32),

    #[error("session name must not be empty")]
    EmptySessionName,

    #[error("channel capacity must be greater than zero")]
    InvalidChannelCapacity,

    #[error("failed to spawn the consumer thread: {0}")]
    Spawn(String),

    #[error("could not resolve a schema for the event: {0}")]
    Schema(String),

    #[error("no trace session named {name}")]
    NoSuchSession { name: String },

    #[error("session {name} is not real-time (LogFileMode {mode:#010x})")]
    NotRealTime { name: String, mode: u32 },

    #[error("the registry would not open {path}: code {code}")]
    Registry { path: String, code: u32 },
}

/// Turn a Win32 error code into something an operator can act on.
///
/// Deliberately short: this is embedded inline in the error text *and* in the
/// per-provider table the client prints, where a sentence would wreck the
/// column alignment. The longer "what to do about it" belongs in [`remedy`].
pub fn hint(code: u32) -> &'static str {
    match code {
        5 => "ERROR_ACCESS_DENIED -- trace sessions require an elevated token",
        8 => "ERROR_NOT_ENOUGH_MEMORY -- reduce BufferSize or MaximumBuffers",
        87 => "ERROR_INVALID_PARAMETER",
        183 => "ERROR_ALREADY_EXISTS -- another process owns this session name",
        4201 => "ERROR_WMI_INSTANCE_NOT_FOUND -- provider manifest is not registered",
        2 => "ERROR_FILE_NOT_FOUND -- the key or value does not exist",
        _ => "see winerror.h",
    }
}

/// What the operator should actually do about a failure, when there is a
/// specific answer.
///
/// Separate from [`hint`] because "you are not elevated" is only half an answer:
/// the full one includes where to get an elevated prompt, and that does not fit
/// in a table cell. Says nothing for errors whose remedy is not obvious — an
/// invented instruction is worse than none.
pub fn remedy(error: &EtwError) -> Option<&'static str> {
    match error {
        EtwError::StartTrace { code: 5, .. } => Some(
            "open PowerShell as Administrator (Win+X, then \"Terminal (Admin)\"), \
             cd to the same directory, and run the same command",
        ),
        EtwError::StartTrace { code: 183, .. } => Some(
            "another process already owns this session name; stop the other copy of \
             the agent, or let it exit on its own",
        ),
        // Attaching is what an agent does when the session was started at boot, so
        // the two ways that fails both have a real answer.
        EtwError::NoSuchSession { .. } => Some(
            "nothing is publishing under that name: either the agent should start the \
             session itself, or the autologger that was supposed to start it at boot is \
             missing or not enabled",
        ),
        EtwError::NotRealTime { .. } => Some(
            "only a real-time session can be consumed live. An autologger whose LogFileMode \
             omits EVENT_TRACE_REAL_TIME_MODE (0x100) writes to a file and cannot be \
             attached to; add the flag to the session's registry values",
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_gets_an_actionable_hint() {
        assert!(hint(5).contains("elevated"));
        assert!(hint(183).contains("ALREADY_EXISTS"));
        assert_eq!(hint(0xdead), "see winerror.h");
    }

    #[test]
    fn a_remedy_says_where_to_get_an_elevated_prompt() {
        let denied = EtwError::StartTrace {
            code: 5,
            hint: hint(5),
        };
        let instruction = remedy(&denied).expect("access denied has a remedy");
        assert!(instruction.contains("Administrator"), "{instruction}");
        assert!(
            instruction.contains("cd to the same directory"),
            "{instruction} — an elevated prompt opens somewhere else, so the relative --token-file would not resolve"
        );

        let taken = EtwError::StartTrace {
            code: 183,
            hint: hint(183),
        };
        assert!(remedy(&taken).expect("remedy").contains("another"));
    }

    #[test]
    fn an_error_without_an_obvious_remedy_gets_none() {
        // An invented instruction is worse than none: the reader follows it.
        assert_eq!(
            remedy(&EtwError::StartTrace {
                code: 87,
                hint: hint(87)
            }),
            None
        );
        assert_eq!(remedy(&EtwError::OpenTrace), None);
    }
}

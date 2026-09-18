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
}

/// Turn a Win32 error code into something an operator can act on.
pub fn hint(code: u32) -> &'static str {
    match code {
        5 => "ERROR_ACCESS_DENIED -- trace sessions require an elevated token",
        8 => "ERROR_NOT_ENOUGH_MEMORY -- reduce BufferSize or MaximumBuffers",
        87 => "ERROR_INVALID_PARAMETER",
        183 => "ERROR_ALREADY_EXISTS -- another process owns this session name",
        4201 => "ERROR_WMI_INSTANCE_NOT_FOUND -- provider manifest is not registered",
        _ => "see winerror.h",
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
}

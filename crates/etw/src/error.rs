use thiserror::Error;
use windows::core::GUID;

#[derive(Debug, Error)]
pub enum EtwError {
    #[error("StartTraceW failed with code {0}")]
    StartTrace(u32),

    #[error("EnableTraceEx2 failed for provider {guid:?} with code {code}")]
    EnableProvider { guid: GUID, code: u32 },

    #[error("OpenTraceW failed")]
    OpenTrace,

    #[error("ProcessTrace failed with code {0}")]
    ProcessTrace(u32),

    #[error("ControlTraceW(stop) failed with code {0}")]
    StopTrace(u32),

    #[error("session name must not be empty")]
    EmptySessionName,

    #[error("channel capacity must be greater than zero")]
    InvalidChannelCapacity,
}

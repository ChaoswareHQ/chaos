use thiserror::Error;

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("source temporarily unavailable: {0}")]
    Unavailable(String),

    #[error("source produced malformed data: {0}")]
    Malformed(String),

    #[error("source shut down")]
    ShutDown,
}

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("sink temporarily unavailable: {0}")]
    Temporary(String),

    #[error("sink rejected event permanently: {0}")]
    Permanent(String),

    #[error("sink backpressure: buffer full")]
    Backpressure,
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("rule parse error in {location}: {message}")]
    Parse { location: String, message: String },

    #[error("rule store unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Error)]
pub enum AlertError {
    #[error("alert delivery failed: {0}")]
    Delivery(String),

    #[error("alert rejected: {0}")]
    Rejected(String),
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("host not found: {0}")]
    NotFound(String),

    #[error("registry unavailable: {0}")]
    Unavailable(String),
}

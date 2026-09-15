use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("field `{field}` must not be empty")]
    EmptyField { field: &'static str },

    #[error("field `{field}` has invalid value: {value}")]
    InvalidValue {
        field: &'static str,
        value: Box<str>,
    },

    #[error("timestamp {0} is in the future")]
    TimestampInFuture(DateTime<Utc>),

    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },
}

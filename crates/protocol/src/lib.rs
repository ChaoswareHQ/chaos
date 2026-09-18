//! The client/server wire contract.
//!
//! One definition of the protocol, shared by both sides, so a change to a field
//! name fails to compile rather than failing at three in the morning on a
//! host you cannot log into.
//!
//! # How a client is allowed to talk to the server
//!
//! Two credentials, with different lifetimes and different blast radii:
//!
//! 1. An **enrollment token** — a shared bootstrap secret, provisioned
//!    out-of-band (installer, configuration management, MDM). It is only good
//!    for one thing: exchanging itself for a host credential. It is sent in
//!    `X-Enrollment-Token`.
//! 2. A **host token** — issued by the server at enrollment, unique per host,
//!    and the only thing used from then on. It is sent as
//!    `Authorization: Bearer <token>`.
//!
//! The host token is deliberately *self-identifying*: its format is
//! `{host_id}.{secret}`, so the server can look up the record by `host_id` and
//! then compare only the secret. That is the difference between an
//! authenticate-any-token endpoint, which must scan every host and compare in
//! constant time against each, and a lookup followed by one comparison. It also
//! means the server never stores the secret itself, only a hash of it — a
//! stolen database is not a set of usable credentials.
//!
//! What this does *not* give you, and what the deployment must add: the token
//! is a bearer credential, so it is only as safe as the channel. Enrollment and
//! ingest must run over TLS, and the client refuses to send a token in
//! cleartext to anything but loopback for exactly that reason.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Bumped when a change to these types is not backward compatible.
pub const API_VERSION: u16 = 1;

pub const HEALTH_PATH: &str = "/health";
pub const ENROLL_PATH: &str = "/v1/enroll";
pub const INGEST_PATH: &str = "/v1/ingest";

/// Carries the bootstrap secret. A request header rather than a body field so
/// it never lands in a request log that records bodies.
pub const ENROLLMENT_HEADER: &str = "x-enrollment-token";

pub const BEARER_SCHEME: &str = "Bearer";

/// Largest batch a client may submit. The server enforces its own limit too;
/// this one exists so a well-behaved client can split before it is rejected.
pub const MAX_BATCH_EVENTS: usize = 5_000;

// ---------------------------------------------------------------------------
// enrollment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub hostname: String,
    pub os: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub host_id: String,
    /// Returned exactly once. The server keeps only a hash of it.
    pub host_token: String,
    pub server_time: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// ingest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRequest {
    /// Client-generated, unique per batch. Retries reuse it, which is what
    /// makes at-least-once delivery safe to implement on the client.
    pub batch_id: String,
    pub sent_at: DateTime<Utc>,
    pub events: Vec<model::TelemetryEvent>,
    #[serde(default)]
    pub alerts: Vec<model::Alert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub accepted_events: usize,
    /// Alerts the server counted as new. A restatement of an alert it already
    /// holds is not counted again, so this can be smaller than the number of
    /// alerts the client sent.
    pub accepted_alerts: usize,
    /// Set when the batch had already been seen, so the client can tell a
    /// successful retry from a first delivery.
    pub duplicate: bool,
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub api_version: u16,
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/// The only error shape the API returns.
///
/// `detail` is for the operator reading a log, never for the caller: an
/// authentication failure says `unauthorized` and nothing else, because
/// "unknown host id" and "bad secret" would together turn the endpoint into a
/// host enumeration oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ApiError {
    pub fn new(error: &str) -> Self {
        Self {
            error: error.to_string(),
            detail: None,
        }
    }

    pub fn with_detail(error: &str, detail: impl Into<String>) -> Self {
        Self {
            error: error.to_string(),
            detail: Some(detail.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// host tokens
// ---------------------------------------------------------------------------

/// A parsed `{host_id}.{secret}` credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostToken {
    pub host_id: String,
    secret: String,
}

impl HostToken {
    /// Parse without validating the secret — the server still has to look the
    /// record up and compare. Only the *shape* is checked here, so a malformed
    /// token is rejected before any store access.
    pub fn parse(raw: &str) -> Option<Self> {
        let (host_id, secret) = raw.split_once('.')?;
        if !is_host_id(host_id) || !is_secret(secret) {
            return None;
        }
        Some(Self {
            host_id: host_id.to_string(),
            secret: secret.to_string(),
        })
    }

    /// Construct from parts. Used by the server when issuing a credential.
    pub fn new(host_id: impl Into<String>, secret: impl Into<String>) -> Option<Self> {
        let token = Self {
            host_id: host_id.into(),
            secret: secret.into(),
        };
        if is_host_id(&token.host_id) && is_secret(&token.secret) {
            Some(token)
        } else {
            None
        }
    }

    pub fn encode(&self) -> String {
        format!("{}.{}", self.host_id, self.secret)
    }

    /// The secret half, which is the only part the server need not store.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Extract the token from an `Authorization: Bearer <token>` value.
    ///
    /// The scheme comparison is ASCII case-insensitive because HTTP says it is,
    /// but the token itself is not trimmed or normalised beyond the single
    /// separating space — silently accepting whitespace variants is how you end
    /// up with two tokens that mean the same thing.
    pub fn from_authorization(value: &str) -> Option<Self> {
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
            return None;
        }
        Self::parse(token.trim())
    }
}

/// 16 lowercase hex characters: the public half of a token, safe to log.
pub fn is_host_id(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// 64 lowercase hex characters: 32 bytes of entropy, never logged.
pub fn is_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Constant-time byte comparison.
///
/// Length is allowed to leak — every candidate here is a fixed-width hash, so
/// length carries no secret. Content comparison does not branch, which is the
/// part that matters: a `==` on secrets fails fast at the first differing byte
/// and turns "is this the right token" into a byte-at-a-time search.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    difference == 0
}

/// Lowercase hex encoding. Hand-rolled because the alternative is a dependency
/// for twelve lines, and both directions are pinned by tests.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn a_well_formed_token_round_trips() {
        let id = "0123456789abcdef";
        let secret = "a".repeat(64);
        let token = HostToken::new(id, secret.clone()).expect("valid shape");
        assert_eq!(token.host_id, id);
        assert_eq!(token.secret(), secret);

        let encoded = token.encode();
        assert_eq!(encoded, format!("{id}.{secret}"));
        assert_eq!(HostToken::parse(&encoded), Some(token));
    }

    #[test]
    fn malformed_tokens_are_rejected_before_any_lookup() {
        let good_id = "0123456789abcdef";
        let good_secret = "b".repeat(64);

        // Wrong lengths.
        assert!(HostToken::parse("").is_none());
        assert!(
            HostToken::parse("0123456789abcdef").is_none(),
            "no separator"
        );
        assert!(
            HostToken::parse(&format!(".{good_secret}")).is_none(),
            "empty host id"
        );
        assert!(
            HostToken::parse(&format!("{good_id}.")).is_none(),
            "empty secret"
        );
        assert!(
            HostToken::parse(&format!("{good_id}.{}", "b".repeat(63))).is_none(),
            "short secret"
        );

        // Uppercase hex is a different string, not a case-insensitive alias.
        assert!(HostToken::parse(&format!("{}.{good_secret}", good_id.to_uppercase())).is_none());
        assert!(HostToken::parse(&format!("{good_id}.{}", good_secret.to_uppercase())).is_none());

        // Non-hex characters, including the ones a path-traversal attempt
        // would need.
        assert!(HostToken::parse(&format!("{good_id}../../etc")).is_none());
        assert!(HostToken::parse(&format!("{good_id}.{}", "z".repeat(64))).is_none());
    }

    #[test]
    fn extra_dots_do_not_smuggle_a_longer_secret() {
        // `split_once` splits at the first dot, so the remainder is the secret
        // and its length check rejects this. Worth pinning: a `splitn` would
        // have silently dropped the tail.
        let id = "0123456789abcdef";
        let raw = format!("{id}.{}.{}", "a".repeat(64), "b".repeat(64));
        assert!(HostToken::parse(&raw).is_none());
    }

    #[test]
    fn authorization_parsing_is_strict_but_scheme_insensitive() {
        let id = "0123456789abcdef";
        let secret = "c".repeat(64);
        let raw = format!("{id}.{secret}");

        assert!(HostToken::from_authorization(&format!("Bearer {raw}")).is_some());
        assert!(HostToken::from_authorization(&format!("bearer {raw}")).is_some());
        assert!(HostToken::from_authorization(&format!("BEARER {raw}")).is_some());

        // Wrong scheme, or no scheme at all.
        assert!(HostToken::from_authorization(&format!("Basic {raw}")).is_none());
        assert!(HostToken::from_authorization(&raw).is_none());
        assert!(HostToken::from_authorization("Bearer").is_none());
        assert!(HostToken::from_authorization("").is_none());
        // A malformed credential is rejected even with the right scheme.
        assert!(HostToken::from_authorization("Bearer nonsense").is_none());
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(
            !constant_time_eq(b"abc", b"abd"),
            "differs in the last byte"
        );
        assert!(
            !constant_time_eq(b"abc", b"xbc"),
            "differs in the first byte"
        );
        assert!(!constant_time_eq(b"abc", b"ab"), "length mismatch");
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn api_errors_omit_detail_when_there_is_none() {
        let bare = ApiError::new("unauthorized");
        let json = serde_json::to_string(&bare).unwrap();
        assert_eq!(json, r#"{"error":"unauthorized"}"#);

        let detailed = ApiError::with_detail("bad_request", "batch too large");
        let json = serde_json::to_string(&detailed).unwrap();
        assert!(json.contains("batch too large"));
    }
}

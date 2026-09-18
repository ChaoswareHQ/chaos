//! Credentials: issuing host tokens, and verifying them without leaking.
//!
//! # The two secrets
//!
//! * The **enrollment token** is a shared bootstrap secret. It is provisioned
//!   out of band and only exchanged for a host credential. The server keeps a
//!   hash of it, so a config dump does not reveal it.
//! * A **host token** is issued per host and is the only credential used
//!   afterwards. Its format is `{host_id}.{secret}`; the server stores a hash of
//!   the secret half and nothing else. A stolen database yields no usable
//!   credentials, only hashes of credentials that were never sent to it.
//!
//! # Not leaking which hosts exist
//!
//! Verification always hashes the presented secret and always compares against
//! 32 bytes, using a random dummy hash when the host id is unknown. The obvious
//! implementation — look the host up, return early if it is missing — answers
//! two different questions in two different amounts of time, which turns the
//! ingest endpoint into an oracle for enumerating enrolled hosts. The cost of
//! closing that is one hash and one comparison.

use protocol::{HostToken, constant_time_eq, to_hex};
use sha2::{Digest, Sha256};

/// A verified caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHost {
    pub host_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("entropy source unavailable: {0}")]
    Entropy(String),
}

/// SHA-256 of the secret half.
///
/// Hashing the *hex string* rather than the decoded bytes, because that is what
/// arrives on the wire and decoding first would add a failure mode (invalid
/// hex) in exchange for nothing.
pub fn hash_secret(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn random_hex(bytes: usize) -> Result<String, AuthError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).map_err(|e| AuthError::Entropy(e.to_string()))?;
    Ok(to_hex(&buffer))
}

/// 8 bytes: enough to make collision negligible, short enough to read aloud.
pub fn new_host_id() -> Result<String, AuthError> {
    random_hex(8)
}

/// 32 bytes of OS entropy. This is the whole of the credential's strength.
pub fn new_secret() -> Result<String, AuthError> {
    random_hex(32)
}

/// Generate an enrolment token, for operators who would rather not invent one.
pub fn new_enrollment_token() -> Result<String, AuthError> {
    random_hex(32)
}

/// Everything the server needs to hand a new host its credential.
#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub host_id: String,
    /// Returned to the client exactly once; never stored.
    pub token: String,
    /// What the server keeps.
    pub secret_hash: [u8; 32],
}

pub fn issue_credential() -> Result<IssuedCredential, AuthError> {
    let host_id = new_host_id()?;
    let secret = new_secret()?;
    let token = HostToken::new(host_id.clone(), secret.clone())
        .map(|token| token.encode())
        .ok_or_else(|| AuthError::Entropy("generated a malformed token".to_string()))?;

    Ok(IssuedCredential {
        secret_hash: hash_secret(&secret),
        host_id,
        token,
    })
}

/// Checks the bootstrap secret presented at enrollment.
pub struct EnrollmentAuthority {
    expected_hash: [u8; 32],
    /// Ceiling on how many hosts may enrol. A shared bootstrap secret that
    /// enrolls without limit is a self-inflicted resource exhaustion bug.
    pub max_hosts: usize,
}

impl EnrollmentAuthority {
    pub fn new(token: &str, max_hosts: usize) -> Self {
        Self {
            expected_hash: hash_secret(token),
            max_hosts: max_hosts.max(1),
        }
    }

    /// Both sides are hashed first so the comparison is always over 32 bytes,
    /// whatever length was presented.
    pub fn accepts(&self, presented: &str) -> bool {
        constant_time_eq(&hash_secret(presented), &self.expected_hash)
    }
}

/// Verifies bearer credentials on the ingest path.
pub struct TokenVerifier {
    /// Compares against this when the host id is unknown, so a missing host and
    /// a wrong secret cost the same.
    dummy_hash: [u8; 32],
}

impl TokenVerifier {
    pub fn new() -> Result<Self, AuthError> {
        Ok(Self {
            dummy_hash: hash_secret(&new_secret()?),
        })
    }

    /// Verify an `Authorization` header value.
    ///
    /// Returns `None` for every failure — malformed, unknown host, wrong secret
    /// — because the caller must answer all of them identically. `lookup`
    /// supplies the stored hash for a host id.
    pub fn verify(
        &self,
        authorization: &str,
        lookup: impl Fn(&str) -> Option<[u8; 32]>,
    ) -> Option<VerifiedHost> {
        let token = HostToken::from_authorization(authorization)?;
        let stored = lookup(&token.host_id).unwrap_or(self.dummy_hash);
        let presented = hash_secret(token.secret());

        if constant_time_eq(&stored, &presented) && lookup(&token.host_id).is_some() {
            return Some(VerifiedHost {
                host_id: token.host_id,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_and_secrets_have_the_declared_shape() {
        for _ in 0..32 {
            let id = new_host_id().unwrap();
            let secret = new_secret().unwrap();
            assert!(protocol::is_host_id(&id), "{id}");
            assert!(protocol::is_secret(&secret), "{secret}");
            assert_ne!(id, new_host_id().unwrap(), "ids must not repeat");
        }
    }

    #[test]
    fn issued_credentials_verify_against_their_hash() {
        let issued = issue_credential().unwrap();
        let verifier = TokenVerifier::new().unwrap();
        let header = format!("Bearer {}", issued.token);

        let verified = verifier
            .verify(&header, |id| {
                (id == issued.host_id).then_some(issued.secret_hash)
            })
            .expect("the credential it just issued must verify");
        assert_eq!(verified.host_id, issued.host_id);
    }

    #[test]
    fn every_failure_mode_looks_the_same_from_outside() {
        let issued = issue_credential().unwrap();
        let verifier = TokenVerifier::new().unwrap();
        let other = issue_credential().unwrap();

        let lookup = |id: &str| (id == issued.host_id).then_some(issued.secret_hash);

        // Malformed.
        assert!(verifier.verify("", lookup).is_none());
        assert!(verifier.verify("Bearer", lookup).is_none());
        assert!(verifier.verify("Basic abc", lookup).is_none());
        assert!(verifier.verify("Bearer not-a-token", lookup).is_none());

        // Unknown host, well-formed shape.
        let unknown = format!("Bearer {}", other.token);
        assert!(verifier.verify(&unknown, lookup).is_none());

        // Known host, wrong secret.
        let wrong = format!("Bearer {}.{}", issued.host_id, "f".repeat(64));
        assert!(verifier.verify(&wrong, lookup).is_none());
    }

    #[test]
    fn a_token_from_another_server_does_not_verify() {
        // Two independently issued credentials must never cross-verify, even
        // when their host ids happen to collide.
        let a = issue_credential().unwrap();
        let b = issue_credential().unwrap();
        let verifier = TokenVerifier::new().unwrap();
        let header = format!("Bearer {}", a.token);

        assert!(
            verifier
                .verify(&header, |id| (id == b.host_id).then_some(b.secret_hash))
                .is_none()
        );
    }

    #[test]
    fn enrollment_accepts_only_the_configured_secret() {
        let authority = EnrollmentAuthority::new("correct-horse", 10);
        assert!(authority.accepts("correct-horse"));
        assert!(!authority.accepts("correct-horse "));
        assert!(!authority.accepts("correct"));
        assert!(!authority.accepts(""));
        assert!(!authority.accepts("CORRECT-HORSE"));
    }

    #[test]
    fn secrets_are_not_stored_in_the_clear() {
        let issued = issue_credential().unwrap();
        let secret = issued.token.split_once('.').unwrap().1;
        assert_ne!(issued.secret_hash.to_vec(), secret.as_bytes().to_vec());
        // The hash is a hash, not an encoding of the secret.
        assert_eq!(hash_secret(secret), issued.secret_hash);
    }
}

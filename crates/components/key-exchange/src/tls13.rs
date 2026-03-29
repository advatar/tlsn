//! TLS 1.3 helpers for the 3-party key exchange protocol.
//!
//! The initial workstream is intentionally narrow:
//!
//! - full 1-RTT handshakes only
//! - `secp256r1` / P-256 only
//! - `TLS_AES_128_GCM_SHA256` only
//! - no PSK, resumption, 0-RTT, client authentication,
//!   post-handshake authentication, or key updates

use mpz_memory_core::{binary::U8, Array};
use thiserror::Error;

/// TLS 1.3 ECDHE shared secret.
///
/// In v0 the supported group is `secp256r1`, so the secret remains 32 bytes.
pub type SharedSecret = Array<U8, 32>;

/// Supported named groups for the initial TLS 1.3 workstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// NIST P-256 / secp256r1.
    Secp256r1,
}

/// Narrow TLS 1.3 scope enforced by the workstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    /// Supported group for the ECDHE exchange.
    pub named_group: NamedGroup,
    /// Whether PSK handshakes are enabled.
    pub psk: bool,
    /// Whether resumption is enabled.
    pub resumption: bool,
    /// Whether 0-RTT is enabled.
    pub zero_rtt: bool,
    /// Whether client certificate authentication is enabled.
    pub client_auth: bool,
    /// Whether post-handshake authentication is enabled.
    pub post_handshake_auth: bool,
    /// Whether key updates are enabled.
    pub key_update: bool,
}

impl Scope {
    /// Canonical v0 scope.
    pub const fn v0() -> Self {
        Self {
            named_group: NamedGroup::Secp256r1,
            psk: false,
            resumption: false,
            zero_rtt: false,
            client_auth: false,
            post_handshake_auth: false,
            key_update: false,
        }
    }

    /// Validates the scope against the v0 boundary.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.named_group != NamedGroup::Secp256r1 {
            return Err(ScopeError::NamedGroup);
        }
        if self.psk {
            return Err(ScopeError::Psk);
        }
        if self.resumption {
            return Err(ScopeError::Resumption);
        }
        if self.zero_rtt {
            return Err(ScopeError::ZeroRtt);
        }
        if self.client_auth {
            return Err(ScopeError::ClientAuth);
        }
        if self.post_handshake_auth {
            return Err(ScopeError::PostHandshakeAuth);
        }
        if self.key_update {
            return Err(ScopeError::KeyUpdate);
        }
        Ok(())
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self::v0()
    }
}

/// Scope validation errors for the TLS 1.3 workstream.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    /// Only P-256 is in scope for v0.
    #[error("named group is out of scope for v0")]
    NamedGroup,
    /// PSK is explicitly excluded from v0.
    #[error("psk handshakes are out of scope for v0")]
    Psk,
    /// Resumption is explicitly excluded from v0.
    #[error("session resumption is out of scope for v0")]
    Resumption,
    /// 0-RTT is explicitly excluded from v0.
    #[error("0-rtt is out of scope for v0")]
    ZeroRtt,
    /// Client certificate authentication is explicitly excluded from v0.
    #[error("client authentication is out of scope for v0")]
    ClientAuth,
    /// Post-handshake authentication is explicitly excluded from v0.
    #[error("post-handshake authentication is out of scope for v0")]
    PostHandshakeAuth,
    /// KeyUpdate is explicitly excluded from v0.
    #[error("key updates are out of scope for v0")]
    KeyUpdate,
}

#[cfg(test)]
mod tests {
    use super::{NamedGroup, Scope, ScopeError};

    #[test]
    fn v0_scope_is_valid() {
        Scope::v0().validate().unwrap();
        Scope::default().validate().unwrap();
    }

    #[test]
    fn scope_validation_rejects_out_of_scope_features() {
        let cases = [
            (
                Scope {
                    named_group: NamedGroup::Secp256r1,
                    psk: true,
                    ..Scope::v0()
                },
                ScopeError::Psk,
            ),
            (
                Scope {
                    named_group: NamedGroup::Secp256r1,
                    resumption: true,
                    ..Scope::v0()
                },
                ScopeError::Resumption,
            ),
            (
                Scope {
                    named_group: NamedGroup::Secp256r1,
                    zero_rtt: true,
                    ..Scope::v0()
                },
                ScopeError::ZeroRtt,
            ),
            (
                Scope {
                    named_group: NamedGroup::Secp256r1,
                    client_auth: true,
                    ..Scope::v0()
                },
                ScopeError::ClientAuth,
            ),
            (
                Scope {
                    named_group: NamedGroup::Secp256r1,
                    post_handshake_auth: true,
                    ..Scope::v0()
                },
                ScopeError::PostHandshakeAuth,
            ),
            (
                Scope {
                    named_group: NamedGroup::Secp256r1,
                    key_update: true,
                    ..Scope::v0()
                },
                ScopeError::KeyUpdate,
            ),
        ];

        for (scope, expected) in cases {
            assert_eq!(scope.validate().unwrap_err(), expected);
        }
    }
}

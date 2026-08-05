//! A single-party TLS 1.3 reference implementation, used as a **test oracle**.
//!
//! This crate exists to answer one question precisely: *what should the MPC
//! implementation have produced?* It computes the TLS 1.3 key schedule
//! ([`schedule`]), traffic keys ([`traffic`]) and record protection
//! ([`record`]) in ordinary, single-party Rust, records every derivation step
//! ([`trace`]), and is validated against the published RFC 8448 handshake
//! traces.
//!
//! # Narrow profile
//!
//! Deliberately limited to the profile the MPC backend targets first:
//!
//! - cipher suite `TLS_AES_128_GCM_SHA256` (SHA-256, AES-128-GCM);
//! - 1-RTT, server-authenticated handshakes;
//! - no PSK, no 0-RTT, no resumption, no `HelloRetryRequest`, no `KeyUpdate`.
//!
//! # Not for production
//!
//! This is test scaffolding, not a TLS stack. It performs no certificate
//! validation, makes no attempt at constant-time behaviour beyond what the
//! underlying primitives provide, and does **not** zeroize secrets — every
//! intermediate secret is retained on purpose, because exposing them is the
//! entire point of an oracle. Never use it to protect real traffic.
//!
//! # Relationship to the MPC implementation
//!
//! The entry point [`KeySchedule::derive_handshake_secret`] takes the ECDHE
//! shared secret, which is exactly the input `tlsn_hmac_sha256::Tls13KeySched`
//! receives as its secret-shared `pms`. [`HandshakeKeys`] and
//! [`ApplicationKeys`] mirror the field names of their MPC counterparts so the
//! two can be compared directly.

/// SHA-256 output length, the hash length of `TLS_AES_128_GCM_SHA256`.
pub const HASH_LEN: usize = 32;

/// AES-128 key length.
pub const KEY_LEN: usize = 16;

/// TLS 1.3 AEAD nonce / IV length.
pub const IV_LEN: usize = 12;

/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

pub mod hkdf;
pub mod record;
pub mod schedule;
pub mod trace;
pub mod traffic;
pub mod transcript;

pub use record::{ContentType, Record};
pub use schedule::{ApplicationKeys, DirectionalSecrets, HandshakeKeys, KeySchedule};
pub use trace::{Step, Trace};
pub use traffic::TrafficSecret;
pub use transcript::Transcript;

/// Errors produced by the reference implementation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A record was too short to be a valid `TLSCiphertext`.
    #[error("record too short: {0} bytes")]
    ShortRecord(usize),
    /// The record's declared length did not match the bytes supplied.
    #[error("record length mismatch: header declares {declared}, got {actual}")]
    LengthMismatch {
        /// Length from the record header.
        declared: usize,
        /// Length actually available.
        actual: usize,
    },
    /// AEAD tag verification failed.
    #[error("AEAD tag verification failed")]
    BadTag,
    /// The inner plaintext was all padding, so carried no content type.
    #[error("inner plaintext contains no content type")]
    NoContentType,
    /// The inner plaintext's content type byte is not one we recognise.
    #[error("unknown content type: {0:#04x}")]
    UnknownContentType(u8),
    /// The key schedule was driven out of order.
    #[error("key schedule stage error: {0}")]
    Stage(&'static str),
}

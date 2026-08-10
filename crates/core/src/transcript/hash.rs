//! Plaintext hash commitments.

use serde::{Deserialize, Serialize};

use crate::{
    connection::SessionId,
    hash::{Blinder, HashAlgId, HashAlgorithm, TypedHash},
    transcript::{Direction, RangeSet, RecordId},
};

/// Hashes plaintext with a blinder.
///
/// By convention, plaintext is hashed as `H(msg | blinder)`.
pub fn hash_plaintext(
    hasher: &dyn HashAlgorithm,
    session_id: SessionId,
    direction: Direction,
    idx: &RangeSet<usize>,
    record_ids: &[RecordId],
    msg: &[u8],
    blinder: &Blinder,
) -> TypedHash {
    let mut bound = commitment_prefix(session_id, direction, idx, record_ids);
    bound.extend_from_slice(msg);
    TypedHash {
        alg: hasher.id(),
        value: hasher.hash_prefixed(&bound, blinder.as_bytes()),
    }
}

/// Canonical public domain prefix for a session-bound transcript commitment.
pub fn commitment_prefix(
    session_id: SessionId,
    direction: Direction,
    idx: &RangeSet<usize>,
    record_ids: &[RecordId],
) -> Vec<u8> {
    let ranges: Vec<_> = idx.iter().collect();
    let mut prefix = Vec::with_capacity(32 + 32 + ranges.len() * 16);
    prefix.extend_from_slice(b"tlsn/plaintext-commitment/v1\0");
    prefix.extend_from_slice(session_id.as_bytes());
    prefix.push(match direction {
        Direction::Sent => 0,
        Direction::Received => 1,
    });
    prefix.extend_from_slice(&(ranges.len() as u32).to_be_bytes());
    for range in ranges {
        prefix.extend_from_slice(&(range.start as u64).to_be_bytes());
        prefix.extend_from_slice(&(range.end as u64).to_be_bytes());
    }
    prefix.extend_from_slice(&(record_ids.len() as u32).to_be_bytes());
    for record in record_ids {
        prefix.extend_from_slice(record.session_id.as_bytes());
        prefix.push(match record.direction {
            Direction::Sent => 0,
            Direction::Received => 1,
        });
        prefix.extend_from_slice(&record.generation.to_be_bytes());
        prefix.extend_from_slice(&record.sequence.to_be_bytes());
    }
    prefix
}

/// Hash of plaintext in the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlaintextHash {
    /// Cryptographic session identity bound into the hash preimage.
    pub session_id: SessionId,
    /// Authenticated TLS records containing the committed plaintext stream.
    pub record_ids: Vec<RecordId>,
    /// Direction of the plaintext.
    pub direction: Direction,
    /// Index of plaintext.
    pub idx: RangeSet<usize>,
    /// The hash of the data.
    pub hash: TypedHash,
}

/// Secret component of [`PlaintextHash`].
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextHashSecret {
    /// Cryptographic session identity bound into the hash preimage.
    pub session_id: SessionId,
    /// Authenticated TLS records containing the committed plaintext stream.
    pub record_ids: Vec<RecordId>,
    /// Direction of the plaintext.
    pub direction: Direction,
    /// Index of plaintext.
    pub idx: RangeSet<usize>,
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// Blinder for the hash.
    pub blinder: Blinder,
}

opaque_debug::implement!(PlaintextHashSecret);

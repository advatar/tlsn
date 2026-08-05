//! The running handshake transcript hash.

use sha2::{Digest, Sha256};

use crate::HASH_LEN;

/// `Transcript-Hash(messages)` maintained incrementally.
///
/// The transcript covers complete handshake messages **including** their
/// four-byte `Handshake` headers, and excludes record-layer framing. Messages
/// must be appended in the order they appear on the wire.
#[derive(Clone, Default)]
pub struct Transcript {
    hasher: Sha256,
    len: usize,
}

impl Transcript {
    /// Creates an empty transcript.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one complete handshake message.
    pub fn push(&mut self, msg: &[u8]) -> &mut Self {
        self.hasher.update(msg);
        self.len += msg.len();
        self
    }

    /// Appends several handshake messages in order.
    pub fn extend<'a, I>(&mut self, msgs: I) -> &mut Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        for msg in msgs {
            self.push(msg);
        }
        self
    }

    /// The hash of every message appended so far.
    ///
    /// Cheap to call at any point: the key schedule needs the transcript hash
    /// at several distinct positions, and this clones the hasher rather than
    /// finalising it.
    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.hasher.clone().finalize().into()
    }

    /// Total number of transcript bytes appended so far.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no messages have been appended.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transcript")
            .field("len", &self.len)
            .field("hash", &hex(&self.hash()))
            .finish()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hkdf;

    #[test]
    fn empty_transcript_hashes_empty_string() {
        assert_eq!(Transcript::new().hash(), hkdf::empty_hash());
    }

    #[test]
    fn hash_is_concatenation_not_tree() {
        let mut split = Transcript::new();
        split.push(b"abc").push(b"def");

        let mut whole = Transcript::new();
        whole.push(b"abcdef");

        assert_eq!(split.hash(), whole.hash());
        assert_eq!(split.len(), 6);
    }

    #[test]
    fn hash_does_not_consume_state() {
        let mut t = Transcript::new();
        t.push(b"abc");
        let first = t.hash();
        assert_eq!(t.hash(), first, "hash() must be repeatable");
        t.push(b"def");
        assert_ne!(t.hash(), first, "further messages must change the hash");
    }
}

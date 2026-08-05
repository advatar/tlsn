//! Traffic secrets and the key material derived from them.

use crate::{HASH_LEN, IV_LEN, KEY_LEN, hkdf};

/// One direction's traffic secret, at one generation.
///
/// This is the value that must stay secret-shared in the MPC protocol: holding
/// it is equivalent to holding the traffic keys, since [`TrafficSecret::key`]
/// and [`TrafficSecret::iv`] are public functions of it.
#[derive(Clone, PartialEq, Eq)]
pub struct TrafficSecret([u8; HASH_LEN]);

impl TrafficSecret {
    /// Wraps a raw traffic secret.
    pub fn new(secret: [u8; HASH_LEN]) -> Self {
        Self(secret)
    }

    /// The raw secret.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// `HKDF-Expand-Label(secret, "key", "", key_length)`.
    pub fn key(&self) -> [u8; KEY_LEN] {
        hkdf::expand_label(&self.0, b"key", &[], KEY_LEN)
            .out
            .try_into()
            .expect("expansion produced KEY_LEN bytes")
    }

    /// `HKDF-Expand-Label(secret, "iv", "", iv_length)`.
    pub fn iv(&self) -> [u8; IV_LEN] {
        hkdf::expand_label(&self.0, b"iv", &[], IV_LEN)
            .out
            .try_into()
            .expect("expansion produced IV_LEN bytes")
    }

    /// `HKDF-Expand-Label(secret, "finished", "", Hash.length)`.
    pub fn finished_key(&self) -> [u8; HASH_LEN] {
        hkdf::expand_label(&self.0, b"finished", &[], HASH_LEN)
            .out
            .try_into()
            .expect("expansion produced HASH_LEN bytes")
    }

    /// The `verify_data` for a `Finished` message (RFC 8446 section 4.4.4):
    /// `HMAC(finished_key, Transcript-Hash(...))`.
    pub fn verify_data(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        hkdf::hmac(&self.finished_key(), transcript_hash)
    }

    /// Both traffic keys at once.
    pub fn keys(&self) -> TrafficKeys {
        TrafficKeys {
            key: self.key(),
            iv: self.iv(),
        }
    }

    /// The next generation of this secret, as used by `KeyUpdate`.
    ///
    /// Outside the narrow profile — the MPC backend rejects `KeyUpdate` — but
    /// included so a test can assert that rejection is not masking a
    /// disagreement about the derivation itself.
    pub fn next_generation(&self) -> Self {
        Self(
            hkdf::expand_label(&self.0, b"traffic upd", &[], HASH_LEN)
                .out
                .try_into()
                .expect("expansion produced HASH_LEN bytes"),
        )
    }
}

/// Deliberately opaque: traffic secrets should not land in logs.
impl std::fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrafficSecret(..)")
    }
}

/// The AEAD key and IV for one direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficKeys {
    /// `[sender]_write_key`.
    pub key: [u8; KEY_LEN],
    /// `[sender]_write_iv`.
    pub iv: [u8; IV_LEN],
}

/// Builds the per-record nonce (RFC 8446 section 5.3).
///
/// The 64-bit sequence number is encoded big-endian, left-padded to the IV
/// length, and XORed with the static IV. The sequence number is per-direction
/// and per-key-generation, and resets to zero on every key change — which is
/// why records under handshake keys and under application keys both start at 0.
pub fn nonce(iv: &[u8; IV_LEN], seq: u64) -> [u8; IV_LEN] {
    let mut nonce = *iv;
    let seq = seq.to_be_bytes();
    for (n, s) in nonce[IV_LEN - seq.len()..].iter_mut().zip(seq) {
        *n ^= s;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_zero_sequence_is_the_iv() {
        let iv = [0xaa; IV_LEN];
        assert_eq!(nonce(&iv, 0), iv);
    }

    #[test]
    fn nonce_xors_big_endian_into_the_low_bytes() {
        let iv = [0u8; IV_LEN];
        // Only the final 8 bytes may be affected.
        let n = nonce(&iv, 1);
        assert_eq!(n[IV_LEN - 1], 1);
        assert!(n[..IV_LEN - 1].iter().all(|&b| b == 0));

        let n = nonce(&iv, 0x0102_0304_0506_0708);
        assert_eq!(&n[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&n[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn nonce_is_an_xor_not_an_overwrite() {
        // A set IV bit must survive where the sequence number bit is zero.
        let iv = [0xff; IV_LEN];
        assert_eq!(nonce(&iv, 1)[IV_LEN - 1], 0xfe);
    }

    #[test]
    fn key_iv_and_finished_key_are_distinct() {
        let s = TrafficSecret::new([7u8; HASH_LEN]);
        assert_ne!(&s.key()[..], &s.iv()[..]);
        assert_ne!(&s.finished_key()[..KEY_LEN], &s.key()[..]);
        assert_ne!(s.next_generation(), s);
    }
}

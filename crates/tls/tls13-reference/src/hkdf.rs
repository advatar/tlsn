//! HKDF (RFC 5869) and the TLS 1.3 key-derivation functions of RFC 8446
//! section 7.1, instantiated with SHA-256.
//!
//! Every function here is a direct transcription of the specification with no
//! caching or restructuring, so that a disagreement with the MPC
//! implementation points at the MPC side rather than at a clever shortcut here.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::HASH_LEN;

type HmacSha256 = Hmac<Sha256>;

/// The label prefix every TLS 1.3 `HkdfLabel` carries (RFC 8446 section 7.1).
pub const LABEL_PREFIX: &[u8] = b"tls13 ";

/// The inputs and output of one `HKDF-Expand-Label` invocation.
///
/// `info` is retained because it is the serialized `HkdfLabel`, and a mismatch
/// there — rather than in the output — localises a bug to label construction.
/// RFC 8448 prints this value, so it can be asserted against directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    /// The serialized `HkdfLabel` passed to `HKDF-Expand` as `info`.
    pub info: Vec<u8>,
    /// The expanded output key material.
    pub out: Vec<u8>,
}

/// `HMAC-SHA256(key, msg)`.
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// `SHA-256(msg)`.
pub fn hash(msg: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(msg).into()
}

/// `SHA-256("")`.
///
/// This is the transcript hash used by the two context-free `Derive-Secret`
/// calls in the key schedule (`"derived"`).
pub fn empty_hash() -> [u8; HASH_LEN] {
    hash(&[])
}

/// `HKDF-Extract(salt, IKM)` (RFC 5869 section 2.2).
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    // HKDF-Extract is HMAC with the salt as key and the IKM as message.
    hmac(salt, ikm)
}

/// `HKDF-Expand(PRK, info, L)` (RFC 5869 section 2.3), filling `out`.
pub fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) {
    assert!(
        out.len() <= 255 * HASH_LEN,
        "HKDF-Expand output length {} exceeds 255 * HashLen",
        out.len()
    );

    // T(0) = ""; T(n) = HMAC(PRK, T(n-1) || info || n); output is T(1) | T(2) | ...
    let mut prev: Option<[u8; HASH_LEN]> = None;
    for (block, counter) in out.chunks_mut(HASH_LEN).zip(1u8..) {
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts keys of any length");
        if let Some(prev) = prev {
            mac.update(&prev);
        }
        mac.update(info);
        mac.update(&[counter]);
        let t: [u8; HASH_LEN] = mac.finalize().into_bytes().into();
        block.copy_from_slice(&t[..block.len()]);
        prev = Some(t);
    }
}

/// Serializes the `HkdfLabel` structure of RFC 8446 section 7.1.
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// `label` is given **without** the `"tls13 "` prefix, which this function
/// prepends.
///
/// # Panics
///
/// Panics if the prefixed label is outside `7..=255` bytes or the context
/// exceeds 255 bytes; both are protocol invariants, not runtime conditions.
pub fn label_info(label: &[u8], context: &[u8], out_len: u16) -> Vec<u8> {
    let label_len = LABEL_PREFIX.len() + label.len();
    assert!(
        (7..=255).contains(&label_len),
        "prefixed label length {label_len} outside 7..=255"
    );
    assert!(
        context.len() <= 255,
        "context length {} exceeds 255",
        context.len()
    );

    let mut info = Vec::with_capacity(2 + 1 + label_len + 1 + context.len());
    info.extend_from_slice(&out_len.to_be_bytes());
    info.push(label_len as u8);
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

/// `HKDF-Expand-Label(secret, label, context, length)` (RFC 8446 section 7.1),
/// returning both the output and the `HkdfLabel` used to produce it.
pub fn expand_label(secret: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Expansion {
    let info = label_info(
        label,
        context,
        u16::try_from(out_len).expect("TLS 1.3 output lengths fit in u16"),
    );
    let mut out = vec![0u8; out_len];
    expand(secret, &info, &mut out);
    Expansion { info, out }
}

/// `Derive-Secret(secret, label, messages)` (RFC 8446 section 7.1).
///
/// `transcript_hash` is `Transcript-Hash(messages)`; this function does not
/// hash for you, mirroring the specification's split.
pub fn derive_secret(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Expansion {
    expand_label(secret, label, transcript_hash, HASH_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_info_matches_rfc8446_layout() {
        // "tls13 derived" with a 32-byte context, expanding to 32 bytes.
        let info = label_info(b"derived", &[0xab; 32], 32);
        assert_eq!(&info[..2], &[0x00, 0x20], "uint16 length");
        assert_eq!(info[2], 13, "len(\"tls13 derived\")");
        assert_eq!(&info[3..16], b"tls13 derived");
        assert_eq!(info[16], 32, "context length");
        assert_eq!(&info[17..], &[0xab; 32]);
        assert_eq!(info.len(), 49);
    }

    #[test]
    fn label_info_with_empty_context() {
        // The "finished" key uses a zero-length context.
        let info = label_info(b"finished", &[], 32);
        assert_eq!(info, {
            let mut want = vec![0x00, 0x20, 0x0e];
            want.extend_from_slice(b"tls13 finished");
            want.push(0x00);
            want
        });
        assert_eq!(info.len(), 18);
    }

    #[test]
    fn expand_spans_multiple_blocks() {
        // 80 bytes needs three HMAC blocks; check the prefix property that
        // T(1) is independent of the requested length.
        let short = {
            let mut o = [0u8; HASH_LEN];
            expand(b"prk", b"info", &mut o);
            o
        };
        let mut long = [0u8; 80];
        expand(b"prk", b"info", &mut long);
        assert_eq!(&long[..HASH_LEN], &short[..]);
    }

    #[test]
    fn empty_hash_is_sha256_of_empty_string() {
        assert_eq!(
            empty_hash(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }
}

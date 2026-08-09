//! Clear SHA-384 TLS 1.3 reference functions.
//!
//! These functions are deliberately not used by the MPC protocol. They are a
//! byte-level oracle for the future secret-shared SHA-384 implementation.

use hmac::{Hmac, Mac};
use sha2::Sha384;

type HmacSha384 = Hmac<Sha384>;

pub(crate) fn hkdf_extract_sha384(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha384::new_from_slice(salt).expect("HMAC accepts arbitrary key length");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn hkdf_expand_sha384(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    assert!(length <= 255 * 48, "HKDF output exceeds SHA-384 limit");
    let mut output = Vec::with_capacity(length);
    let mut previous = Vec::new();
    for counter in 1..=((length + 47) / 48) {
        let mut mac = HmacSha384::new_from_slice(prk).expect("HMAC accepts arbitrary key length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter as u8]);
        previous = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(length);
    output
}

pub(crate) fn hkdf_expand_label_sha384(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    assert!(label.len() + 6 <= u8::MAX as usize);
    assert!(context.len() <= u8::MAX as usize);
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((label.len() + 6) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand_sha384(secret, &info, length)
}

#[cfg(test)]
mod tests {
    use super::{hkdf_expand_sha384, hkdf_extract_sha384};

    fn hex(value: &str) -> Vec<u8> {
        value
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    // SHA-384 structural reference test. RFC 5869 publishes SHA-1/SHA-256
    // vectors; TLS 1.3 supplies the SHA-384 vectors separately.
    #[test]
    fn rfc5869_sha384_extract_and_expand() {
        let ikm = vec![0x0b; 22];
        let salt = hex("60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a");
        let info = hex("f0 f1 f2 f3 f4 f5 f6 f7 f8 f9");
        let prk = hkdf_extract_sha384(&salt, &ikm);
        assert_eq!(prk.len(), 48);
        let okm = hkdf_expand_sha384(&prk, &info, 42);
        assert_eq!(okm.len(), 42);
    }
}

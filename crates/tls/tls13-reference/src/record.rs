//! The TLS 1.3 record layer (RFC 8446 section 5).

use aes_gcm::{
    Aes128Gcm, NewAead,
    aead::{Aead, Payload, generic_array::GenericArray},
};

use crate::{Error, IV_LEN, KEY_LEN, TAG_LEN, traffic::nonce};

/// The `legacy_record_version` every TLS 1.3 record carries.
pub const RECORD_VERSION: [u8; 2] = [0x03, 0x03];

/// Length of a `TLSCiphertext` header, which is also the AEAD additional data.
pub const HEADER_LEN: usize = 5;

/// Record content types (RFC 8446 section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// Only ever seen as a middlebox-compatibility no-op.
    ChangeCipherSpec = 20,
    /// An alert.
    Alert = 21,
    /// A handshake message.
    Handshake = 22,
    /// Application data. Also the outer type of every protected record.
    ApplicationData = 23,
}

impl ContentType {
    /// The wire encoding.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a content type byte.
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        match byte {
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            other => Err(Error::UnknownContentType(other)),
        }
    }
}

/// A decrypted record: its content and the real content type recovered from the
/// inner plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's content, with content type and padding stripped.
    pub content: Vec<u8>,
    /// The true content type, from inside the encrypted envelope.
    pub content_type: ContentType,
}

/// Builds a `TLSInnerPlaintext`: `content || content_type || zeros`.
///
/// The content type moves *inside* the encryption in TLS 1.3; the outer header
/// always claims `application_data`.
pub fn inner_plaintext(content: &[u8], content_type: ContentType, padding: usize) -> Vec<u8> {
    let mut inner = Vec::with_capacity(content.len() + 1 + padding);
    inner.extend_from_slice(content);
    inner.push(content_type.as_u8());
    inner.resize(inner.len() + padding, 0);
    inner
}

/// Builds the 5-byte `TLSCiphertext` header for a ciphertext of `len` bytes.
///
/// This doubles as the AEAD additional data (RFC 8446 section 5.2), so a bug
/// here shows up as a tag failure rather than as malformed framing.
pub fn header(len: usize) -> [u8; HEADER_LEN] {
    let len = u16::try_from(len).expect("record length fits in u16");
    let [hi, lo] = len.to_be_bytes();
    [
        ContentType::ApplicationData.as_u8(),
        RECORD_VERSION[0],
        RECORD_VERSION[1],
        hi,
        lo,
    ]
}

/// Encrypts one record, returning the complete wire record including its header.
pub fn seal(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    seq: u64,
    content: &[u8],
    content_type: ContentType,
    padding: usize,
) -> Vec<u8> {
    let inner = inner_plaintext(content, content_type, padding);
    let aad = header(inner.len() + TAG_LEN);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            GenericArray::from_slice(&nonce(iv, seq)),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .expect("AES-GCM encryption of a bounded record cannot fail");

    let mut record = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    record.extend_from_slice(&aad);
    record.extend_from_slice(&ciphertext);
    record
}

/// Decrypts one complete wire record.
///
/// Verifies the AEAD tag before looking at any plaintext, then strips padding
/// to recover the true content type — the "authenticated release" the MPC
/// design depends on.
pub fn open(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    seq: u64,
    record: &[u8],
) -> Result<Record, Error> {
    if record.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::ShortRecord(record.len()));
    }
    let (aad, ciphertext) = record.split_at(HEADER_LEN);

    let declared = usize::from(u16::from_be_bytes([aad[3], aad[4]]));
    if declared != ciphertext.len() {
        return Err(Error::LengthMismatch {
            declared,
            actual: ciphertext.len(),
        });
    }

    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let inner = cipher
        .decrypt(
            GenericArray::from_slice(&nonce(iv, seq)),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::BadTag)?;

    // Strip zero padding; the last non-zero byte is the content type.
    let split = inner
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::NoContentType)?;

    Ok(Record {
        content: inner[..split].to_vec(),
        content_type: ContentType::from_u8(inner[split])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x11; KEY_LEN];
    const IV: [u8; IV_LEN] = [0x22; IV_LEN];

    #[test]
    fn header_declares_ciphertext_length_and_claims_application_data() {
        let h = header(0x1234);
        assert_eq!(h, [23, 0x03, 0x03, 0x12, 0x34]);
    }

    #[test]
    fn inner_plaintext_appends_type_then_padding() {
        let inner = inner_plaintext(b"hi", ContentType::Handshake, 3);
        assert_eq!(inner, b"hi\x16\x00\x00\x00");
    }

    #[test]
    fn seal_then_open_round_trips() {
        for (ct, padding) in [
            (ContentType::Handshake, 0),
            (ContentType::ApplicationData, 0),
            (ContentType::Alert, 7),
        ] {
            let record = seal(&KEY, &IV, 3, b"payload", ct, padding);
            let opened = open(&KEY, &IV, 3, &record).unwrap();
            assert_eq!(opened.content, b"payload");
            assert_eq!(opened.content_type, ct);
        }
    }

    #[test]
    fn padding_does_not_change_the_recovered_content() {
        let bare = open(
            &KEY,
            &IV,
            0,
            &seal(&KEY, &IV, 0, b"x", ContentType::Handshake, 0),
        )
        .unwrap();
        let padded = open(
            &KEY,
            &IV,
            0,
            &seal(&KEY, &IV, 0, b"x", ContentType::Handshake, 64),
        )
        .unwrap();
        assert_eq!(bare, padded);
    }

    #[test]
    fn wrong_sequence_number_fails_the_tag() {
        let record = seal(&KEY, &IV, 0, b"payload", ContentType::Handshake, 0);
        assert!(matches!(open(&KEY, &IV, 1, &record), Err(Error::BadTag)));
    }

    #[test]
    fn tampering_with_the_header_fails_the_tag() {
        // The header is the AAD, so flipping the version must be detected.
        let mut record = seal(&KEY, &IV, 0, b"payload", ContentType::Handshake, 0);
        record[2] ^= 0x01;
        assert!(matches!(open(&KEY, &IV, 0, &record), Err(Error::BadTag)));
    }

    #[test]
    fn tampering_with_the_ciphertext_fails_the_tag() {
        let mut record = seal(&KEY, &IV, 0, b"payload", ContentType::Handshake, 0);
        *record.last_mut().unwrap() ^= 0x01;
        assert!(matches!(open(&KEY, &IV, 0, &record), Err(Error::BadTag)));
    }

    #[test]
    fn truncated_and_mislabelled_records_are_rejected() {
        assert!(matches!(
            open(&KEY, &IV, 0, &[0u8; 4]),
            Err(Error::ShortRecord(4))
        ));

        let mut record = seal(&KEY, &IV, 0, b"payload", ContentType::Handshake, 0);
        record[4] = record[4].wrapping_add(1);
        assert!(matches!(
            open(&KEY, &IV, 0, &record),
            Err(Error::LengthMismatch { .. })
        ));
    }

    #[test]
    fn all_zero_inner_plaintext_has_no_content_type() {
        // Craft a record whose plaintext is entirely padding.
        let inner = [0u8; 8];
        let aad = header(inner.len() + TAG_LEN);
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&KEY));
        let ct = cipher
            .encrypt(
                GenericArray::from_slice(&nonce(&IV, 0)),
                Payload {
                    msg: &inner,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut record = aad.to_vec();
        record.extend_from_slice(&ct);

        assert!(matches!(
            open(&KEY, &IV, 0, &record),
            Err(Error::NoContentType)
        ));
    }
}

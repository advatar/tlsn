//! Wire-format and ML-KEM primitives for `SecP256r1MLKEM768`.
//!
//! This module deliberately does not claim threshold ML-KEM. The holder of
//! [`HybridClientKey`] performs ordinary ML-KEM decapsulation. Its output is
//! suitable for injection into the MPC TLS 1.3 key schedule as a private
//! input, but a future threshold construction should replace this holder.

use ml_kem::{
    kem::{Decapsulate, Kem, KeyExport},
    DecapsulationKey768, MlKem768,
};
use thiserror::Error;

/// Length of an uncompressed P-256 point.
pub const P256_POINT_LEN: usize = 65;
/// Length of an ML-KEM-768 encapsulation key.
pub const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext.
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// Length of a `SecP256r1MLKEM768` client key share.
pub const SECP256R1_MLKEM768_CLIENT_SHARE_LEN: usize =
    P256_POINT_LEN + MLKEM768_ENCAPSULATION_KEY_LEN;
/// Length of a `SecP256r1MLKEM768` server key share.
pub const SECP256R1_MLKEM768_SERVER_SHARE_LEN: usize = P256_POINT_LEN + MLKEM768_CIPHERTEXT_LEN;

/// Errors produced while handling hybrid TLS key shares.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HybridKeyError {
    /// The P-256 point is not the required uncompressed 65-byte encoding.
    #[error("invalid uncompressed P-256 point")]
    InvalidP256Point,
    /// The hybrid key share has an unexpected size.
    #[error("invalid SecP256r1MLKEM768 key-share length")]
    InvalidLength,
}

/// Client-side ML-KEM state for a hybrid TLS 1.3 exchange.
pub struct HybridClientKey {
    decapsulation_key: DecapsulationKey768,
}

impl HybridClientKey {
    /// Generates fresh ML-KEM-768 state.
    pub fn generate() -> Self {
        let (decapsulation_key, _) = MlKem768::generate_keypair();
        Self { decapsulation_key }
    }

    /// Encodes a TLS client share as `P-256 point || ML-KEM encapsulation key`.
    pub fn client_share(&self, p256_point: &[u8]) -> Result<Vec<u8>, HybridKeyError> {
        validate_p256_point(p256_point)?;
        let ek = self.decapsulation_key.encapsulation_key().to_bytes();
        let mut share = Vec::with_capacity(SECP256R1_MLKEM768_CLIENT_SHARE_LEN);
        share.extend_from_slice(p256_point);
        share.extend_from_slice(ek.as_slice());
        Ok(share)
    }

    /// Parses the server share and decapsulates its ML-KEM ciphertext.
    pub fn decapsulate_server_share(
        &self,
        share: &[u8],
    ) -> Result<HybridServerShare, HybridKeyError> {
        if share.len() != SECP256R1_MLKEM768_SERVER_SHARE_LEN {
            return Err(HybridKeyError::InvalidLength);
        }
        validate_p256_point(&share[..P256_POINT_LEN])?;
        let ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(&share[P256_POINT_LEN..])
            .map_err(|_| HybridKeyError::InvalidLength)?;
        let secret = self.decapsulation_key.decapsulate(&ciphertext);
        Ok(HybridServerShare {
            p256_point: share[..P256_POINT_LEN]
                .try_into()
                .expect("length checked above"),
            mlkem_secret: secret
                .as_slice()
                .try_into()
                .expect("ML-KEM secret is 32 bytes"),
        })
    }
}

/// Decoded server contribution to a hybrid exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridServerShare {
    /// Server's uncompressed P-256 public point.
    pub p256_point: [u8; P256_POINT_LEN],
    /// Decapsulated ML-KEM-768 shared secret.
    pub mlkem_secret: [u8; 32],
}

impl HybridServerShare {
    /// Concatenates the MPC-derived P-256 secret with the ML-KEM secret in the
    /// order required by `SecP256r1MLKEM768`.
    pub fn combined_secret(&self, p256_secret: [u8; 32]) -> [u8; 64] {
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&p256_secret);
        secret[32..].copy_from_slice(&self.mlkem_secret);
        secret
    }
}

fn validate_p256_point(point: &[u8]) -> Result<(), HybridKeyError> {
    if point.len() != P256_POINT_LEN || point.first() != Some(&0x04) {
        return Err(HybridKeyError::InvalidP256Point);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{
        kem::{Encapsulate, Key},
        EncapsulationKey768,
    };

    fn point(fill: u8) -> [u8; P256_POINT_LEN] {
        let mut point = [fill; P256_POINT_LEN];
        point[0] = 0x04;
        point
    }

    #[test]
    fn hybrid_share_round_trip_and_secret_order() {
        let client = HybridClientKey::generate();
        let client_share = client.client_share(&point(7)).unwrap();
        assert_eq!(client_share.len(), SECP256R1_MLKEM768_CLIENT_SHARE_LEN);

        let encoded_ek: Key<EncapsulationKey768> = client_share[P256_POINT_LEN..]
            .try_into()
            .expect("encapsulation key length is fixed");
        let ek = EncapsulationKey768::new(&encoded_ek).unwrap();
        let (ciphertext, server_secret) = ek.encapsulate();

        let server_point = point(9);
        let mut server_share = Vec::from(server_point);
        server_share.extend_from_slice(ciphertext.as_ref());
        let decoded = client.decapsulate_server_share(&server_share).unwrap();

        assert_eq!(decoded.p256_point, server_point);
        assert_eq!(decoded.mlkem_secret.as_slice(), server_secret.as_slice());
        let combined = decoded.combined_secret([3u8; 32]);
        assert_eq!(&combined[..32], &[3u8; 32]);
        assert_eq!(&combined[32..], server_secret.as_slice());
    }

    #[test]
    fn rejects_malformed_hybrid_shares() {
        let client = HybridClientKey::generate();
        assert_eq!(
            client.client_share(&[0u8; P256_POINT_LEN]).unwrap_err(),
            HybridKeyError::InvalidP256Point
        );
        assert_eq!(
            client.decapsulate_server_share(&[0u8; 3]).unwrap_err(),
            HybridKeyError::InvalidLength
        );
    }
}

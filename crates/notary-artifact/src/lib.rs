//! Portable, independently verifiable TLSNotary session artifacts.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Current portable artifact format.
pub const ARTIFACT_VERSION: &str = "tlsn.notary-artifact.v1";

/// The deterministic content covered by the notary signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactPayload {
    /// Artifact format identifier.
    pub version: String,
    /// Identifier used to pair the prover and notary session.
    pub session_id: String,
    /// Unix timestamp, in seconds, assigned by the notary.
    pub issued_at: u64,
    /// Output produced by the online TLSNotary verifier.
    pub verifier_output: Value,
}

/// A portable P-256 signed artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedArtifact {
    /// Signed payload.
    pub payload: ArtifactPayload,
    /// Signature algorithm.
    pub algorithm: String,
    /// SEC1-encoded notary public key, base64url without padding.
    pub public_key: String,
    /// Fixed-width P-256 signature, base64url without padding.
    pub signature: String,
}

/// Errors produced while signing or verifying portable artifacts.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// Artifact encoding was invalid.
    #[error("invalid artifact encoding: {0}")]
    Encoding(String),
    /// Artifact uses an unsupported version or algorithm.
    #[error("unsupported artifact format")]
    Unsupported,
    /// Artifact was not signed by the pinned notary key.
    #[error("artifact notary key does not match the trusted key")]
    WrongKey,
    /// Signature verification failed.
    #[error("artifact signature verification failed")]
    InvalidSignature,
}

/// Persistent P-256 signer used by a notary service.
#[derive(Clone)]
pub struct ArtifactSigner(SigningKey);

impl std::fmt::Debug for ArtifactSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactSigner")
            .finish_non_exhaustive()
    }
}

impl ArtifactSigner {
    /// Loads a signer from a 32-byte P-256 secret scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| ArtifactError::Encoding("invalid P-256 signing key".into()))
    }

    /// Creates an ephemeral signer. Production services should persist a key.
    pub fn random() -> Self {
        Self(SigningKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ))
    }

    /// Returns the SEC1-encoded public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Signs verifier output for a completed session.
    pub fn sign(
        &self,
        session_id: impl Into<String>,
        issued_at: u64,
        verifier_output: Value,
    ) -> Result<SignedArtifact, ArtifactError> {
        let payload = ArtifactPayload {
            version: ARTIFACT_VERSION.into(),
            session_id: session_id.into(),
            issued_at,
            verifier_output,
        };
        let message =
            serde_json::to_vec(&payload).map_err(|e| ArtifactError::Encoding(e.to_string()))?;
        let signature: Signature = self.0.sign(&message);
        Ok(SignedArtifact {
            payload,
            algorithm: "ES256".into(),
            public_key: URL_SAFE_NO_PAD.encode(self.public_key()),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

impl SignedArtifact {
    /// Verifies the signature and that it matches an explicitly trusted key.
    pub fn verify(&self, trusted_key: &[u8]) -> Result<(), ArtifactError> {
        if self.payload.version != ARTIFACT_VERSION || self.algorithm != "ES256" {
            return Err(ArtifactError::Unsupported);
        }
        let embedded_key = URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .map_err(|e| ArtifactError::Encoding(e.to_string()))?;
        if embedded_key != trusted_key {
            return Err(ArtifactError::WrongKey);
        }
        let key = VerifyingKey::from_sec1_bytes(trusted_key)
            .map_err(|_| ArtifactError::Encoding("invalid trusted P-256 key".into()))?;
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| ArtifactError::Encoding(e.to_string()))?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ArtifactError::InvalidSignature)?;
        let message = serde_json::to_vec(&self.payload)
            .map_err(|e| ArtifactError::Encoding(e.to_string()))?;
        key.verify(&message, &signature)
            .map_err(|_| ArtifactError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer(byte: u8) -> ArtifactSigner {
        ArtifactSigner::from_bytes(&[byte; 32]).unwrap()
    }

    #[test]
    fn round_trip_and_tamper_detection() {
        let signer = test_signer(7);
        let mut artifact = signer
            .sign(
                "session",
                42,
                serde_json::json!({"serverName": "example.com"}),
            )
            .unwrap();
        artifact.verify(&signer.public_key()).unwrap();

        artifact.payload.issued_at += 1;
        assert!(matches!(
            artifact.verify(&signer.public_key()),
            Err(ArtifactError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_wrong_pinned_key_and_signature() {
        let signer = test_signer(7);
        let other = test_signer(9);
        let mut artifact = signer.sign("session", 42, Value::Null).unwrap();
        assert!(matches!(
            artifact.verify(&other.public_key()),
            Err(ArtifactError::WrongKey)
        ));

        let mut signature = URL_SAFE_NO_PAD.decode(&artifact.signature).unwrap();
        signature[0] ^= 1;
        artifact.signature = URL_SAFE_NO_PAD.encode(signature);
        assert!(artifact.verify(&signer.public_key()).is_err());
    }
}

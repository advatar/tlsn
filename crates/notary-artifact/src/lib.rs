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
///
/// May optionally carry a post-quantum second signature (`pq_*`) over the SAME payload, forming a
/// downgrade-closed hybrid attestation. The three `pq_*` fields are present together or all absent.
/// They are ADDITIVE: a classical verifier ignores them and checks only the ES256 signature, so a
/// hybrid artifact stays backward-compatible with ES256-only consumers.
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
    /// Optional post-quantum signature algorithm (e.g. `ML-DSA-65`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_algorithm: Option<String>,
    /// Optional raw post-quantum notary public key, base64url without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
    /// Optional post-quantum signature over the same payload, base64url without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
}

/// Recursively rewrites `value` so that every object's keys are in sorted order.
///
/// Arrays keep their order — it is semantically meaningful — and scalars are
/// copied unchanged.
fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            let mut sorted = serde_json::Map::with_capacity(map.len());
            for (key, item) in entries {
                sorted.insert(key.clone(), canonical_value(item));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        scalar => scalar.clone(),
    }
}

/// The exact bytes covered by the ES256 signature and by any ML-DSA-65 signature.
///
/// # Why this exists
///
/// `verifier_output` is a [`Value`], and whether a `Value` map serializes with
/// sorted keys (`BTreeMap`) or in insertion order (`IndexMap`) is decided by
/// serde_json's `preserve_order` feature. That feature is set by *whole-graph
/// feature unification*, so a dependency elsewhere in the build can flip it out
/// from under this crate — in this workspace it arrives transitively via
/// `tlsn-examples` -> noir. Two builds of the same code would then derive
/// different messages from one artifact and reject each other's signatures.
///
/// Emitting keys in sorted order removes that dependence. Sorted order is the
/// fixpoint: an independent verifier that parses these bytes and re-serializes
/// them reproduces them byte-for-byte under *either* resolution. [`ArtifactSigner::sign`]
/// therefore also stores the canonical form in the artifact, so the bytes on the
/// wire already are the bytes that were signed.
pub fn signing_bytes(payload: &ArtifactPayload) -> Result<Vec<u8>, ArtifactError> {
    let canonical = ArtifactPayload {
        version: payload.version.clone(),
        session_id: payload.session_id.clone(),
        issued_at: payload.issued_at,
        verifier_output: canonical_value(&payload.verifier_output),
    };
    serde_json::to_vec(&canonical).map_err(|e| ArtifactError::Encoding(e.to_string()))
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
        // Store the canonical form, so the bytes on the wire are the bytes signed
        // and any verifier that re-derives the message agrees. See `signing_bytes`.
        let payload = ArtifactPayload {
            version: ARTIFACT_VERSION.into(),
            session_id: session_id.into(),
            issued_at,
            verifier_output: canonical_value(&verifier_output),
        };
        let message = signing_bytes(&payload)?;
        let signature: Signature = self.0.sign(&message);
        Ok(SignedArtifact {
            payload,
            algorithm: "ES256".into(),
            public_key: URL_SAFE_NO_PAD.encode(self.public_key()),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            pq_algorithm: None,
            pq_public_key: None,
            pq_signature: None,
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
        let message = signing_bytes(&self.payload)?;
        key.verify(&message, &signature)
            .map_err(|_| ArtifactError::InvalidSignature)
    }
}

/// Notary-side hybrid post-quantum signing (ML-DSA-65 / FIPS 204).
///
/// Gated behind the `pq-sign` feature so verify-only consumers (e.g. the mobile prover) never
/// compile `libcrux-ml-dsa`. A hybrid artifact carries BOTH the classical ES256 signature and an
/// ML-DSA-65 signature over the identical payload bytes, so a verifier that pins a post-quantum key
/// requires both to check (downgrade-closed), while a classical verifier ignores the `pq_*` fields.
#[cfg(feature = "pq-sign")]
mod pq {
    use super::{ArtifactError, SignedArtifact};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use libcrux_ml_dsa::ml_dsa_65::{MLDSA65SigningKey, generate_key_pair, sign};
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};

    /// FIPS 204 ML-DSA-65 secret-key length.
    const SECRET_KEY_BYTES: usize = 4_032;

    /// Deterministically derives an ML-DSA-65 keypair `(secret, public)` from a 32-byte seed.
    ///
    /// The seed is the only post-quantum secret a notary persists; the keypair is regenerated at
    /// startup, so the same seed always yields the same public key to pin downstream.
    #[must_use]
    pub fn generate_pq_keypair(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let key_pair = generate_key_pair(*seed);
        let public = key_pair.verification_key.as_slice().to_vec();
        let secret = key_pair.signing_key.as_slice().to_vec();
        (secret, public)
    }

    /// Adds an ML-DSA-65 signature to an already-signed artifact, making it a hybrid attestation.
    ///
    /// Signs EXACTLY the bytes the ES256 signature covers — `serde_json::to_vec(&payload)` — with an
    /// empty FIPS 204 signing context, matching the independent verifier. ML-DSA verification is
    /// deterministic in the signer's randomness, so hedged signing here still verifies downstream.
    pub fn attach_pq_signature(
        artifact: &mut SignedArtifact,
        pq_secret: &[u8],
        pq_public: &[u8],
    ) -> Result<(), ArtifactError> {
        let encoded: [u8; SECRET_KEY_BYTES] = pq_secret
            .try_into()
            .map_err(|_| ArtifactError::Encoding("invalid ML-DSA-65 secret key length".into()))?;
        let signing_key = MLDSA65SigningKey::new(encoded);
        // The same canonical bytes ES256 covers, so both signatures are over one
        // message and a downgrade is not possible by disagreeing on encoding.
        let message = super::signing_bytes(&artifact.payload)?;
        let mut randomness = [0_u8; 32];
        OsRng.fill_bytes(&mut randomness);
        let signature = sign(&signing_key, &message, &[], randomness)
            .map_err(|_| ArtifactError::Encoding("ML-DSA-65 signing failed".into()))?;
        artifact.pq_algorithm = Some("ML-DSA-65".into());
        artifact.pq_public_key = Some(URL_SAFE_NO_PAD.encode(pq_public));
        artifact.pq_signature = Some(URL_SAFE_NO_PAD.encode(signature.as_slice()));
        Ok(())
    }
}

#[cfg(feature = "pq-sign")]
pub use pq::{attach_pq_signature, generate_pq_keypair};

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

    #[cfg(feature = "pq-sign")]
    #[test]
    fn hybrid_artifact_verifies_both_signatures_over_the_same_message() {
        use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey, verify};

        let signer = test_signer(7);
        let (pq_secret, pq_public) = generate_pq_keypair(&[42; 32]);
        assert_eq!(pq_secret.len(), 4_032);
        assert_eq!(pq_public.len(), 1_952);

        let mut artifact = signer
            .sign(
                "session",
                42,
                serde_json::json!({"serverName": "example.com"}),
            )
            .unwrap();
        attach_pq_signature(&mut artifact, &pq_secret, &pq_public).unwrap();

        // Classical verification is untouched: an ES256-only verifier still accepts the artifact.
        artifact.verify(&signer.public_key()).unwrap();

        // The post-quantum signature checks over the SAME bytes ES256 covers, with an empty context —
        // exactly how an independent post-quantum verifier (VCIssuer) re-derives and verifies it.
        assert_eq!(artifact.pq_algorithm.as_deref(), Some("ML-DSA-65"));
        let embedded_pk = URL_SAFE_NO_PAD
            .decode(artifact.pq_public_key.as_ref().unwrap())
            .unwrap();
        assert_eq!(embedded_pk, pq_public);
        let message = serde_json::to_vec(&artifact.payload).unwrap();
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(artifact.pq_signature.as_ref().unwrap())
            .unwrap();
        let pk = MLDSA65VerificationKey::new(embedded_pk.as_slice().try_into().unwrap());
        let sig = MLDSA65Signature::new(sig_bytes.as_slice().try_into().unwrap());
        verify(&pk, &message, &[], &sig).expect("post-quantum signature verifies");

        // Tampering with the payload breaks the post-quantum signature too.
        let mut tampered = artifact.clone();
        tampered.payload.issued_at += 1;
        let tampered_message = serde_json::to_vec(&tampered.payload).unwrap();
        assert!(verify(&pk, &tampered_message, &[], &sig).is_err());
    }
}

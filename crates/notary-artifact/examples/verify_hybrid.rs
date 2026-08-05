//! Offline verifier for a hybrid (ES256 + ML-DSA-65) TLSNotary artifact.
//!
//! Reproduces exactly the crypto core of VCIssuer's `verify_tlsn_artifact`: it pins BOTH the
//! classical and the post-quantum notary keys, and checks both signatures over the identical
//! message bytes (`serde_json::to_vec(&payload)`) with an empty FIPS 204 signing context. Use it to
//! confirm a real artifact minted by the live notary is downgrade-closed and independently verifiable.
//!
//! Usage:
//!   cargo run -p tlsn-notary-artifact --features pq-sign --example verify_hybrid -- \
//!     <artifact.json> <trusted-es256-pubkey-b64url> <trusted-mldsa65-pubkey-b64url>

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey, verify};
use tlsn_notary_artifact::SignedArtifact;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("missing <artifact.json>")?;
    let trusted_es_b64u = args.next().ok_or("missing <trusted-es256-pubkey-b64url>")?;
    let trusted_pq_b64u = args
        .next()
        .ok_or("missing <trusted-mldsa65-pubkey-b64url>")?;

    let json = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let artifact: SignedArtifact =
        serde_json::from_str(&json).map_err(|e| format!("invalid artifact JSON: {e}"))?;

    // 1. Classical ES256 — the same check every ES256-only consumer performs.
    let trusted_es = URL_SAFE_NO_PAD
        .decode(trusted_es_b64u.trim())
        .map_err(|e| format!("bad ES256 key b64url: {e}"))?;
    artifact
        .verify(&trusted_es)
        .map_err(|e| format!("ES256 verification FAILED: {e}"))?;
    println!("ES256      ✅ verifies against the pinned classical notary key");

    // 2. Post-quantum ML-DSA-65 — downgrade-closed: the PQ fields MUST be present and must check
    //    against the pinned PQ key over the same payload bytes, with an empty context.
    let trusted_pq = URL_SAFE_NO_PAD
        .decode(trusted_pq_b64u.trim())
        .map_err(|e| format!("bad ML-DSA key b64url: {e}"))?;

    if artifact.pq_algorithm.as_deref() != Some("ML-DSA-65") {
        return Err("artifact is not hybrid: pqAlgorithm != ML-DSA-65 (downgrade refused)".into());
    }
    let embedded_pq = URL_SAFE_NO_PAD
        .decode(artifact.pq_public_key.as_deref().unwrap_or_default())
        .map_err(|e| format!("bad embedded PQ key: {e}"))?;
    if embedded_pq != trusted_pq {
        return Err("embedded PQ public key does not match the pinned notary PQ key".into());
    }
    let pq_sig = URL_SAFE_NO_PAD
        .decode(artifact.pq_signature.as_deref().unwrap_or_default())
        .map_err(|e| format!("bad PQ signature: {e}"))?;

    let message = serde_json::to_vec(&artifact.payload).map_err(|e| e.to_string())?;
    let pk = MLDSA65VerificationKey::new(
        trusted_pq
            .as_slice()
            .try_into()
            .map_err(|_| "PQ key wrong length")?,
    );
    let sig = MLDSA65Signature::new(
        pq_sig
            .as_slice()
            .try_into()
            .map_err(|_| "PQ signature wrong length")?,
    );
    verify(&pk, &message, &[], &sig).map_err(|_| "ML-DSA-65 verification FAILED".to_string())?;
    println!("ML-DSA-65  ✅ verifies against the pinned post-quantum notary key");
    println!(
        "hybrid OK  session={} issued_at={} (both signatures cover the same {} payload bytes)",
        artifact.payload.session_id,
        artifact.payload.issued_at,
        message.len()
    );
    Ok(())
}

//! Wire-format and serialization tests for the portable artifact.
//!
//! The in-module unit tests sign and verify a live struct inside one binary, so
//! they are always self-consistent and cannot catch a change to the *bytes* an
//! artifact travels as. These tests pin those bytes, because an independent
//! verifier (VCIssuer) re-derives the signed message from them.
//!
//! # A known portability hazard
//!
//! Both signatures cover `serde_json::to_vec(&payload)`, and
//! `ArtifactPayload::verifier_output` is a `serde_json::Value`. Whether a
//! `Value` map serializes with sorted keys (`BTreeMap`) or in insertion order
//! (`IndexMap`) is decided by serde_json's `preserve_order` feature — which is
//! set by *whole-graph feature unification*, not by this crate:
//!
//! ```text
//! cargo test -p tlsn-notary-artifact   -> {"apple":2,"zebra":1}   (sorted)
//! cargo test --workspace               -> {"zebra":1,"apple":2}   (insertion)
//! ```
//!
//! In this workspace `preserve_order` is pulled in transitively via
//! `tlsn-examples` -> noir. A notary and a verifier built with different feature
//! resolutions therefore compute different messages from the same artifact, and
//! a valid signature is rejected. `verify()` re-serializing `self.payload`
//! rather than checking the bytes as received is what exposes this.
//!
//! `reserialization_is_faithful_to_received_bytes` is the tripwire for that and
//! is `#[ignore]`d until the signing input is made canonical. Every other test
//! here is written to be order-independent so it holds under both resolutions.

use tlsn_notary_artifact::{ARTIFACT_VERSION, ArtifactError, ArtifactSigner, SignedArtifact};

/// A fixed signing key, so the pinned vectors below are reproducible.
const SIGNER_SEED: [u8; 32] = [7u8; 32];

const SESSION_ID: &str = "session-1";
const ISSUED_AT: u64 = 1_700_000_000;

fn signer() -> ArtifactSigner {
    ArtifactSigner::from_bytes(&SIGNER_SEED).expect("valid P-256 scalar")
}

/// Verifier output whose object keys are **already in sorted order**, so it
/// serializes identically under both `preserve_order` resolutions.
///
/// Needing this caveat at all is the hazard described in the module docs.
fn order_stable_output() -> serde_json::Value {
    serde_json::json!({"alpha": 1, "beta": 2})
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

/// The property that matters for portability: an artifact that has been through
/// JSON still verifies. The unit tests only ever verify a struct that never left
/// memory.
#[test]
fn json_round_trip_still_verifies() {
    let signer = signer();
    let artifact = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    let json = serde_json::to_string(&artifact).expect("artifact serializes");
    let parsed: SignedArtifact = serde_json::from_str(&json).expect("artifact deserializes");

    assert_eq!(parsed, artifact, "round trip must preserve every field");
    parsed
        .verify(&signer.public_key())
        .expect("a round-tripped artifact must still verify");
}

/// Pretty-printing is a plausible thing for a gateway to do; it must not change
/// what verifies.
#[test]
fn pretty_printed_json_still_verifies() {
    let signer = signer();
    let artifact = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    let pretty = serde_json::to_string_pretty(&artifact).expect("artifact serializes");
    let parsed: SignedArtifact = serde_json::from_str(&pretty).expect("artifact deserializes");

    parsed
        .verify(&signer.public_key())
        .expect("whitespace must not affect verification");
}

// ---------------------------------------------------------------------------
// Pinned bytes
// ---------------------------------------------------------------------------

/// Pins the exact signed message. A field rename, a reordered struct field, or a
/// changed `rename_all` would silently break every external verifier while the
/// in-module tests stayed green; this fails instead.
#[test]
fn signed_message_bytes_are_pinned() {
    let artifact = signer()
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    let message = serde_json::to_vec(&artifact.payload).expect("payload serializes");

    assert_eq!(
        String::from_utf8(message).expect("payload is UTF-8"),
        r#"{"version":"tlsn.notary-artifact.v1","sessionId":"session-1","issuedAt":1700000000,"verifierOutput":{"alpha":1,"beta":2}}"#,
        "the bytes both signatures cover — changing these breaks VCIssuer"
    );
}

/// Pins the full envelope, including that `algorithm` is `ES256`, the key is
/// SEC1 uncompressed base64url, and no `pq*` fields appear when absent.
///
/// The signature is pinned too: ECDSA here is RFC 6979 deterministic, so a
/// change means either the signed bytes or the signing primitive moved — both
/// worth investigating rather than blindly re-pinning.
#[test]
fn envelope_wire_format_is_pinned() {
    let artifact = signer()
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    let json = serde_json::to_string(&artifact).expect("artifact serializes");

    assert_eq!(
        json,
        concat!(
            r#"{"payload":{"version":"tlsn.notary-artifact.v1","sessionId":"session-1","#,
            r#""issuedAt":1700000000,"verifierOutput":{"alpha":1,"beta":2}},"#,
            r#""algorithm":"ES256","#,
            r#""publicKey":"BB4YUy_UdUwC8wQdnHXOszuD_9gax85P6ILMscmLxYlupGwxHE4v9A3ZajZT5uRURdMt_khuztdcepDGoYiBwKM","#,
            r#""signature":"Pk34IqQmPMmztgv4Fj48rFcOk34fBzwDD6CkKw-T343PdjUYtGlBJHYOUy0UxVrAcIcDgKXtduEuEr5RS_WfbA"}"#,
        )
    );
}

/// ECDSA signing must stay deterministic, or the pinned vector above is
/// meaningless and artifacts stop being reproducible from a seed.
#[test]
fn signing_is_deterministic() {
    let signer = signer();
    let first = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");
    let second = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    assert_eq!(first.signature, second.signature, "RFC 6979 determinism");
}

/// A SEC1 uncompressed P-256 point is 65 bytes; downstream consumers pin this.
#[test]
fn public_key_is_sec1_uncompressed() {
    let key = signer().public_key();
    assert_eq!(key.len(), 65);
    assert_eq!(key[0], 0x04, "uncompressed point prefix");
}

/// The `pq*` fields must be absent — not `null` — when there is no post-quantum
/// signature, so ES256-only consumers with strict schemas accept the artifact.
#[test]
fn pq_fields_are_omitted_when_absent() {
    let artifact = signer()
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    let json = serde_json::to_string(&artifact).expect("artifact serializes");

    assert!(!json.contains("pq"), "no pq* keys should appear: {json}");
    assert!(
        !json.contains("null"),
        "absent fields must be omitted: {json}"
    );
}

// ---------------------------------------------------------------------------
// Rejection
// ---------------------------------------------------------------------------

/// `deny_unknown_fields` is declared on both structs but never exercised.
/// Without this, dropping the attribute would silently let an attacker append
/// unsigned fields that a lenient consumer might read.
#[test]
fn unknown_fields_are_rejected() {
    let signer = signer();
    let artifact = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");
    let json = serde_json::to_string(&artifact).expect("artifact serializes");

    // An extra key in the envelope.
    let tampered = json.replace(r#""algorithm""#, r#""injected":1,"algorithm""#);
    assert!(
        serde_json::from_str::<SignedArtifact>(&tampered).is_err(),
        "unknown envelope field must be rejected"
    );

    // An extra key inside the signed payload.
    let tampered = json.replace(r#""version""#, r#""injected":1,"version""#);
    assert!(
        serde_json::from_str::<SignedArtifact>(&tampered).is_err(),
        "unknown payload field must be rejected"
    );
}

/// A missing required field must not deserialize into a default.
#[test]
fn missing_required_fields_are_rejected() {
    for missing in ["sessionId", "issuedAt", "verifierOutput", "version"] {
        let json = format!(
            r#"{{"payload":{{{}}},"algorithm":"ES256","publicKey":"AA","signature":"AA"}}"#,
            [
                (r#""version":"tlsn.notary-artifact.v1""#, "version"),
                (r#""sessionId":"s""#, "sessionId"),
                (r#""issuedAt":1"#, "issuedAt"),
                (r#""verifierOutput":null"#, "verifierOutput"),
            ]
            .iter()
            .filter(|(_, name)| *name != missing)
            .map(|(frag, _)| *frag)
            .collect::<Vec<_>>()
            .join(",")
        );

        assert!(
            serde_json::from_str::<SignedArtifact>(&json).is_err(),
            "payload without {missing} must be rejected"
        );
    }
}

/// A version this build does not implement must be refused before any signature
/// work — the downgrade-closed discipline the format depends on.
#[test]
fn foreign_version_is_unsupported() {
    let signer = signer();
    let mut artifact = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    assert_eq!(artifact.payload.version, ARTIFACT_VERSION);
    artifact.payload.version = "tlsn.notary-artifact.v2".into();

    assert!(
        matches!(
            artifact.verify(&signer.public_key()),
            Err(ArtifactError::Unsupported)
        ),
        "a future version must not be verified against v1 rules"
    );
}

/// Likewise for an unexpected signature algorithm.
#[test]
fn foreign_algorithm_is_unsupported() {
    let signer = signer();
    let mut artifact = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    artifact.algorithm = "ES384".into();

    assert!(matches!(
        artifact.verify(&signer.public_key()),
        Err(ArtifactError::Unsupported)
    ));
}

/// Tampering with the payload after signing must be caught even when the
/// artifact has been through JSON.
#[test]
fn payload_tampering_survives_no_round_trip() {
    let signer = signer();
    let artifact = signer
        .sign(SESSION_ID, ISSUED_AT, order_stable_output())
        .expect("signing succeeds");

    let json = serde_json::to_string(&artifact)
        .expect("artifact serializes")
        .replace(r#""sessionId":"session-1""#, r#""sessionId":"session-2""#);

    let parsed: SignedArtifact = serde_json::from_str(&json).expect("artifact deserializes");
    assert!(
        matches!(
            parsed.verify(&signer.public_key()),
            Err(ArtifactError::InvalidSignature)
        ),
        "a modified sessionId must invalidate the signature"
    );
}

// ---------------------------------------------------------------------------
// Known bug tripwire
// ---------------------------------------------------------------------------

/// Re-serializing a received payload must reproduce the bytes exactly as they
/// arrived, because that is the message the signature covers.
///
/// **Currently fails**, and is ignored rather than deleted. `verify()` calls
/// `serde_json::to_vec(&self.payload)`, so the message depends on how *this*
/// build orders `Value` map keys — which whole-graph feature unification
/// decides (see module docs). With `preserve_order` off, the keys below are
/// re-emitted sorted, producing a different message than the notary signed, and
/// a valid artifact is rejected.
///
/// Un-ignore once the signed input is canonical — either by verifying over the
/// received bytes instead of re-serializing, or by pinning a canonical
/// serialization of `verifier_output`.
#[test]
#[ignore = "known bug: signed message depends on serde_json/preserve_order; see module docs"]
fn reserialization_is_faithful_to_received_bytes() {
    // Keys deliberately not in sorted order.
    let payload_json = r#"{"version":"tlsn.notary-artifact.v1","sessionId":"s","issuedAt":1,"verifierOutput":{"zebra":1,"apple":2}}"#;
    let envelope = format!(
        r#"{{"payload":{payload_json},"algorithm":"ES256","publicKey":"AA","signature":"AA"}}"#
    );

    let parsed: SignedArtifact = serde_json::from_str(&envelope).expect("artifact deserializes");
    let reserialized = serde_json::to_string(&parsed.payload).expect("payload serializes");

    assert_eq!(
        reserialized, payload_json,
        "re-serialization must not reorder verifierOutput keys"
    );
}

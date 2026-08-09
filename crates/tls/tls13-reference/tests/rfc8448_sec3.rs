//! Validates the reference implementation against RFC 8448 section 3.
//!
//! The published trace fixes every intermediate value of a real handshake, so
//! these tests pin the key schedule, the transcript positions, the traffic-key
//! derivations, the `Finished` MACs and the record layer against an external
//! authority rather than against this crate's own output.
//!
//! Where a test asserts an `info` field it is checking the serialized
//! `HkdfLabel`, which localises label-encoding bugs; where it asserts a `hash`
//! field it is checking that the derivation was taken at the right transcript
//! position.

#[allow(dead_code)]
mod vectors {
    include!("vectors/rfc8448_sec3.rs");
}

use tlsn_tls13_reference::{
    ContentType, HASH_LEN, KeySchedule, Transcript,
    hkdf::{self, Expansion},
    record,
    traffic::TrafficSecret,
};

use vectors as v;

/// Hex-encodes for readable assertion failures.
fn h(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_of(msgs: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut t = Transcript::new();
    t.extend(msgs.iter().copied());
    t.hash()
}

/// The transcript through `ServerHello`, which fixes the handshake traffic
/// secrets.
fn hello_transcript() -> [u8; HASH_LEN] {
    hash_of(&[v::CLIENT_HELLO, v::SERVER_HELLO])
}

/// The transcript through the server's `CertificateVerify` — the context for
/// the *server's* `Finished`, which does not cover the `Finished` itself.
fn pre_server_finished_transcript() -> [u8; HASH_LEN] {
    hash_of(&[
        v::CLIENT_HELLO,
        v::SERVER_HELLO,
        v::ENCRYPTED_EXTENSIONS,
        v::CERTIFICATE,
        v::CERTIFICATE_VERIFY,
    ])
}

/// The transcript through the server's `Finished`, which fixes the application
/// traffic secrets and is the context for the *client's* `Finished`.
fn server_finished_transcript() -> [u8; HASH_LEN] {
    hash_of(&[
        v::CLIENT_HELLO,
        v::SERVER_HELLO,
        v::ENCRYPTED_EXTENSIONS,
        v::CERTIFICATE,
        v::CERTIFICATE_VERIFY,
        v::SERVER_FINISHED_MSG,
    ])
}

/// The full transcript through the client's `Finished`.
fn client_finished_transcript() -> [u8; HASH_LEN] {
    hash_of(&[
        v::CLIENT_HELLO,
        v::SERVER_HELLO,
        v::ENCRYPTED_EXTENSIONS,
        v::CERTIFICATE,
        v::CERTIFICATE_VERIFY,
        v::SERVER_FINISHED_MSG,
        v::CLIENT_FINISHED_MSG,
    ])
}

// ---------------------------------------------------------------------------
// Transcript positions
// ---------------------------------------------------------------------------

/// The transcript hashes the RFC feeds into each derivation must be
/// reproducible from the handshake messages themselves. This is what makes the
/// rest of the file meaningful: without it, the key schedule could be correct
/// while being driven at the wrong transcript positions.
#[test]
fn transcript_hashes_match_the_rfc_contexts() {
    assert_eq!(
        h(&hello_transcript()),
        h(v::C_HS_TRAFFIC.hash),
        "Hash(ClientHello..ServerHello)"
    );
    assert_eq!(h(&hello_transcript()), h(v::S_HS_TRAFFIC.hash));

    assert_eq!(
        h(&server_finished_transcript()),
        h(v::C_AP_TRAFFIC.hash),
        "Hash(ClientHello..server Finished)"
    );
    assert_eq!(h(&server_finished_transcript()), h(v::S_AP_TRAFFIC.hash));
    assert_eq!(h(&server_finished_transcript()), h(v::EXP_MASTER.hash));

    assert_eq!(
        h(&client_finished_transcript()),
        h(v::RES_MASTER.hash),
        "Hash(ClientHello..client Finished)"
    );
}

/// The two context-free derivations use `SHA-256("")`.
#[test]
fn derived_secrets_use_the_empty_transcript() {
    assert_eq!(h(&hkdf::empty_hash()), h(v::DERIVED_FOR_HANDSHAKE.hash));
    assert_eq!(h(&hkdf::empty_hash()), h(v::DERIVED_FOR_MASTER.hash));
}

/// The `finished_key` expansion takes a *zero-length* context — its `hash`
/// field is the `HkdfLabel` context, not the transcript hash that is later
/// HMAC'd. The transcript position for the `Finished` MAC is pinned instead by
/// [`finished_verify_data_matches_the_rfc`], which reproduces the RFC's
/// `verify_data` from a transcript this file computes.
#[test]
fn finished_key_derivation_has_no_context() {
    assert!(v::SERVER_FINISHED.hash.is_empty());
    assert!(v::CLIENT_FINISHED.hash.is_empty());
}

// ---------------------------------------------------------------------------
// Key schedule
// ---------------------------------------------------------------------------

/// Each `HKDF-Extract` and `Derive-Secret` step, in isolation, against the RFC.
#[test]
fn key_schedule_primitives_match_the_rfc() {
    // Early Secret = HKDF-Extract(0, 0).
    assert_eq!(
        h(&hkdf::extract(v::EARLY_EXTRACT.salt, v::EARLY_EXTRACT.ikm)),
        h(v::EARLY_EXTRACT.out),
        "early secret"
    );

    for (name, d) in [
        ("derived (handshake)", &v::DERIVED_FOR_HANDSHAKE),
        ("derived (master)", &v::DERIVED_FOR_MASTER),
        ("c hs traffic", &v::C_HS_TRAFFIC),
        ("s hs traffic", &v::S_HS_TRAFFIC),
        ("c ap traffic", &v::C_AP_TRAFFIC),
        ("s ap traffic", &v::S_AP_TRAFFIC),
        ("exp master", &v::EXP_MASTER),
        ("res master", &v::RES_MASTER),
    ] {
        // Recover the label from the RFC's own `info` bytes so the test data
        // stays the single source of truth: info = len(2) || llen(1) || label.
        let llen = usize::from(d.info[2]);
        let label = &d.info[3..3 + llen];
        let label = label
            .strip_prefix(hkdf::LABEL_PREFIX)
            .expect("every TLS 1.3 label carries the tls13 prefix");

        let Expansion { info, out } = hkdf::derive_secret(d.prk, label, d.hash);
        assert_eq!(h(&info), h(d.info), "{name}: HkdfLabel encoding");
        assert_eq!(h(&out), h(d.out), "{name}: expanded output");
    }

    // Handshake Secret = HKDF-Extract(derived, (EC)DHE).
    assert_eq!(
        h(v::DERIVED_FOR_HANDSHAKE.out),
        h(v::HANDSHAKE_EXTRACT.salt),
        "the handshake extract salt is the derived secret"
    );
    assert_eq!(
        h(&hkdf::extract(
            v::HANDSHAKE_EXTRACT.salt,
            v::HANDSHAKE_EXTRACT.ikm
        )),
        h(v::HANDSHAKE_EXTRACT.out),
        "handshake secret"
    );

    // Master Secret = HKDF-Extract(derived, 0).
    assert_eq!(
        h(&hkdf::extract(
            v::MASTER_EXTRACT.salt,
            v::MASTER_EXTRACT.ikm
        )),
        h(v::MASTER_EXTRACT.out),
        "master secret"
    );
    assert!(
        v::MASTER_EXTRACT.ikm.iter().all(|&b| b == 0),
        "the master extract IKM is all zeros"
    );
}

/// The whole schedule driven end to end through the public API, as a consumer
/// would, rather than primitive by primitive.
#[test]
fn full_key_schedule_reproduces_the_rfc() {
    let mut ks = KeySchedule::new();
    assert_eq!(h(ks.early_secret()), h(v::EARLY_EXTRACT.out));

    // The ECDHE shared secret is the handshake stage's IKM. This is the same
    // value the MPC implementation takes as its secret-shared `pms`.
    ks.derive_handshake_secret(v::HANDSHAKE_EXTRACT.ikm);
    assert_eq!(
        h(ks.handshake_secret().expect("derived above")),
        h(v::HANDSHAKE_EXTRACT.out)
    );

    let hs = ks
        .handshake_traffic_secrets(&hello_transcript())
        .expect("handshake stage entered");
    assert_eq!(h(hs.client.as_bytes()), h(v::C_HS_TRAFFIC.out));
    assert_eq!(h(hs.server.as_bytes()), h(v::S_HS_TRAFFIC.out));

    ks.derive_master_secret().expect("handshake stage entered");
    assert_eq!(
        h(ks.master_secret().expect("derived above")),
        h(v::MASTER_EXTRACT.out)
    );

    let app = ks
        .application_traffic_secrets(&server_finished_transcript())
        .expect("master stage entered");
    assert_eq!(h(app.client.as_bytes()), h(v::C_AP_TRAFFIC.out));
    assert_eq!(h(app.server.as_bytes()), h(v::S_AP_TRAFFIC.out));

    assert_eq!(
        h(&ks
            .exporter_master_secret(&server_finished_transcript())
            .expect("master stage entered")),
        h(v::EXP_MASTER.out)
    );
    assert_eq!(
        h(&ks
            .resumption_master_secret(&client_finished_transcript())
            .expect("master stage entered")),
        h(v::RES_MASTER.out)
    );
}

// ---------------------------------------------------------------------------
// Traffic keys and Finished
// ---------------------------------------------------------------------------

/// `key` and `iv` for all four traffic secrets, including their `HkdfLabel`s.
#[test]
fn traffic_keys_match_the_rfc() {
    for (name, tk) in [
        ("server handshake", &v::SERVER_HS_KEYS),
        ("client handshake", &v::CLIENT_HS_KEYS),
        ("server application", &v::SERVER_AP_KEYS),
        ("client application", &v::CLIENT_AP_KEYS),
    ] {
        let secret = TrafficSecret::new(tk.prk.try_into().expect("traffic secrets are 32 bytes"));

        let key = hkdf::expand_label(tk.prk, b"key", &[], tk.key.len());
        assert_eq!(h(&key.info), h(tk.key_info), "{name}: key HkdfLabel");
        assert_eq!(h(&key.out), h(tk.key), "{name}: key");
        assert_eq!(h(&secret.key()), h(tk.key), "{name}: key via TrafficSecret");

        let iv = hkdf::expand_label(tk.prk, b"iv", &[], tk.iv.len());
        assert_eq!(h(&iv.info), h(tk.iv_info), "{name}: iv HkdfLabel");
        assert_eq!(h(&iv.out), h(tk.iv), "{name}: iv");
        assert_eq!(h(&secret.iv()), h(tk.iv), "{name}: iv via TrafficSecret");
    }
}

/// The `finished_key` derivations and both `Finished` MACs.
#[test]
fn finished_verify_data_matches_the_rfc() {
    for (name, f, transcript) in [
        (
            "server",
            &v::SERVER_FINISHED,
            pre_server_finished_transcript(),
        ),
        ("client", &v::CLIENT_FINISHED, server_finished_transcript()),
    ] {
        let secret = TrafficSecret::new(f.prk.try_into().expect("traffic secrets are 32 bytes"));

        let fk = hkdf::expand_label(f.prk, b"finished", &[], HASH_LEN);
        assert_eq!(h(&fk.info), h(f.info), "{name}: finished HkdfLabel");
        assert_eq!(h(&fk.out), h(f.out), "{name}: finished_key");
        assert_eq!(h(&secret.finished_key()), h(f.out));

        assert_eq!(
            h(&secret.verify_data(&transcript)),
            h(f.verify_data),
            "{name}: verify_data"
        );
    }
}

/// The `Finished` messages on the wire must carry the `verify_data` the key
/// schedule produces, framed as a handshake message.
#[test]
fn finished_messages_carry_the_computed_verify_data() {
    for (name, msg, expected) in [
        ("server", v::SERVER_FINISHED_MSG, v::SERVER_FINISHED),
        ("client", v::CLIENT_FINISHED_MSG, v::CLIENT_FINISHED),
    ] {
        // Handshake header: type(1) = 20 (finished) || length(3).
        assert_eq!(msg[0], 20, "{name}: handshake type is finished");
        let len = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(len, HASH_LEN, "{name}: verify_data length");
        assert_eq!(msg.len(), 4 + HASH_LEN);
        assert_eq!(h(&msg[4..]), h(expected.verify_data), "{name}: verify_data");
    }
}

/// The handshake keys, in the shape the MPC implementation reports them.
#[test]
fn mpc_shaped_key_structs_match_the_rfc() {
    let mut ks = KeySchedule::new();
    ks.derive_handshake_secret(v::HANDSHAKE_EXTRACT.ikm);

    let hs = ks
        .handshake_keys(&hello_transcript())
        .expect("handshake stage entered");
    assert_eq!(h(&hs.client_write_key), h(v::CLIENT_HS_KEYS.key));
    assert_eq!(h(&hs.client_iv), h(v::CLIENT_HS_KEYS.iv));
    assert_eq!(h(&hs.client_finished_key), h(v::CLIENT_FINISHED.out));
    assert_eq!(h(&hs.server_write_key), h(v::SERVER_HS_KEYS.key));
    assert_eq!(h(&hs.server_iv), h(v::SERVER_HS_KEYS.iv));
    assert_eq!(h(&hs.server_finished_key), h(v::SERVER_FINISHED.out));

    ks.derive_master_secret().expect("handshake stage entered");
    let app = ks
        .application_keys(&server_finished_transcript())
        .expect("master stage entered");
    assert_eq!(h(&app.client_write_key), h(v::CLIENT_AP_KEYS.key));
    assert_eq!(h(&app.client_iv), h(v::CLIENT_AP_KEYS.iv));
    assert_eq!(h(&app.server_write_key), h(v::SERVER_AP_KEYS.key));
    assert_eq!(h(&app.server_iv), h(v::SERVER_AP_KEYS.iv));
}

// ---------------------------------------------------------------------------
// Record layer
// ---------------------------------------------------------------------------

/// Every protected record in the trace, decrypted and re-encrypted.
///
/// Re-encrypting and comparing byte-for-byte against the RFC's `complete
/// record` is the stronger half: it pins the inner-plaintext framing, the
/// additional data, the nonce construction and the absence of padding all at
/// once.
#[test]
fn records_decrypt_and_reencrypt_byte_for_byte() {
    struct Case {
        name: &'static str,
        rec: &'static v::Record,
        keys: &'static v::TrafficKeys,
        seq: u64,
        content_type: ContentType,
    }

    let cases = [
        Case {
            name: "server encrypted flight (EE, Certificate, CertificateVerify, Finished)",
            rec: &v::SERVER_FLIGHT_RECORD,
            keys: &v::SERVER_HS_KEYS,
            seq: 0,
            content_type: ContentType::Handshake,
        },
        Case {
            name: "client Finished",
            rec: &v::CLIENT_FINISHED_RECORD,
            keys: &v::CLIENT_HS_KEYS,
            seq: 0,
            content_type: ContentType::Handshake,
        },
        Case {
            name: "client application data",
            rec: &v::CLIENT_APPDATA_RECORD,
            keys: &v::CLIENT_AP_KEYS,
            seq: 0,
            content_type: ContentType::ApplicationData,
        },
        Case {
            // The server's first application-key record is the NewSessionTicket,
            // so its application data is sequence number 1.
            name: "server application data",
            rec: &v::SERVER_APPDATA_RECORD,
            keys: &v::SERVER_AP_KEYS,
            seq: 1,
            content_type: ContentType::ApplicationData,
        },
        Case {
            // close_notify, following the client's application data.
            name: "client alert",
            rec: &v::CLIENT_ALERT_RECORD,
            keys: &v::CLIENT_AP_KEYS,
            seq: 1,
            content_type: ContentType::Alert,
        },
    ];

    for Case {
        name,
        rec,
        keys,
        seq,
        content_type,
    } in cases
    {
        let key = keys.key.try_into().expect("AES-128 keys are 16 bytes");
        let iv = keys.iv.try_into().expect("TLS 1.3 IVs are 12 bytes");

        let opened = record::open(&key, &iv, seq, rec.complete)
            .unwrap_or_else(|e| panic!("{name}: decryption failed: {e}"));
        assert_eq!(h(&opened.content), h(rec.payload), "{name}: plaintext");
        assert_eq!(opened.content_type, content_type, "{name}: content type");

        let resealed = record::seal(&key, &iv, seq, rec.payload, content_type, 0);
        assert_eq!(h(&resealed), h(rec.complete), "{name}: re-encrypted record");
    }
}

/// The server's encrypted flight must contain exactly the handshake messages
/// the trace lists, in order — the property the follower's record relay has to
/// preserve.
#[test]
fn server_flight_contains_the_expected_handshake_messages() {
    let key = v::SERVER_HS_KEYS
        .key
        .try_into()
        .expect("AES-128 keys are 16 bytes");
    let iv = v::SERVER_HS_KEYS
        .iv
        .try_into()
        .expect("TLS 1.3 IVs are 12 bytes");

    let flight = record::open(&key, &iv, 0, v::SERVER_FLIGHT_RECORD.complete)
        .expect("server flight decrypts");

    let expected = [
        ("EncryptedExtensions", v::ENCRYPTED_EXTENSIONS),
        ("Certificate", v::CERTIFICATE),
        ("CertificateVerify", v::CERTIFICATE_VERIFY),
        ("Finished", v::SERVER_FINISHED_MSG),
    ];

    let mut rest = flight.content.as_slice();
    for (name, msg) in expected {
        assert!(
            rest.starts_with(msg),
            "{name} not found at the expected offset in the server flight"
        );
        rest = &rest[msg.len()..];
    }
    assert!(
        rest.is_empty(),
        "{} unexpected trailing bytes in the server flight",
        rest.len()
    );
}

/// A single coalesced record carrying the whole flight is the case that broke
/// the existing partial implementation, so pin it explicitly.
#[test]
fn server_flight_is_a_single_coalesced_record() {
    assert_eq!(
        v::SERVER_FLIGHT_RECORD.payload.len(),
        v::ENCRYPTED_EXTENSIONS.len()
            + v::CERTIFICATE.len()
            + v::CERTIFICATE_VERIFY.len()
            + v::SERVER_FINISHED_MSG.len(),
        "four handshake messages share one record"
    );
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

/// The trace must record each step, in order, with the RFC's own values — this
/// is the artifact used to localise an MPC disagreement.
#[test]
fn trace_records_the_rfc_derivation_chain() {
    let mut ks = KeySchedule::new();
    ks.derive_handshake_secret(v::HANDSHAKE_EXTRACT.ikm);
    let _ = ks
        .handshake_traffic_secrets(&hello_transcript())
        .expect("handshake stage entered");
    ks.derive_master_secret().expect("handshake stage entered");
    let _ = ks
        .application_traffic_secrets(&server_finished_transcript())
        .expect("master stage entered");

    let labels: Vec<_> = ks.trace().steps().iter().map(|s| s.label()).collect();
    assert_eq!(
        labels,
        [
            "early",
            "tls13 derived",
            "handshake",
            "tls13 c hs traffic",
            "tls13 s hs traffic",
            "tls13 derived",
            "master",
            "tls13 c ap traffic",
            "tls13 s ap traffic",
        ]
    );

    // Spot-check that recorded outputs are the RFC's, not just well-ordered.
    assert_eq!(
        h(ks.trace().find("early").unwrap().out()),
        h(v::EARLY_EXTRACT.out)
    );
    assert_eq!(
        h(ks.trace().find("tls13 s hs traffic").unwrap().out()),
        h(v::S_HS_TRAFFIC.out)
    );
    // "tls13 derived" occurs twice, for the handshake and master stages.
    let derived = ks.trace().find_all("tls13 derived");
    assert_eq!(derived.len(), 2);
    assert_eq!(h(derived[0].out()), h(v::DERIVED_FOR_HANDSHAKE.out));
    assert_eq!(h(derived[1].out()), h(v::DERIVED_FOR_MASTER.out));

    // The rendered form should be non-trivial and mention a label.
    assert!(ks.trace().render().contains("tls13 c hs traffic"));
}

// ---------------------------------------------------------------------------
// Boundary with M3 (distributed X25519)
// ---------------------------------------------------------------------------

/// This crate takes the ECDHE shared secret as an input and does **not**
/// compute X25519; verifying that `CLIENT_X25519 x SERVER_X25519` yields
/// `HANDSHAKE_EXTRACT.ikm` belongs to the distributed-ECDHE milestone.
///
/// The key pairs are retained here so that work has a known-answer test ready.
#[test]
fn ecdhe_inputs_are_recorded_for_the_x25519_milestone() {
    assert_eq!(v::CLIENT_X25519.private_key.len(), 32);
    assert_eq!(v::CLIENT_X25519.public_key.len(), 32);
    assert_eq!(v::SERVER_X25519.private_key.len(), 32);
    assert_eq!(v::SERVER_X25519.public_key.len(), 32);
    assert_eq!(
        v::HANDSHAKE_EXTRACT.ikm.len(),
        32,
        "the X25519 shared secret this crate consumes as an input"
    );
}

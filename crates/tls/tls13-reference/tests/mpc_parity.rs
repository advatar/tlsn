//! Cross-checks the oracle against the vectors the MPC key schedule already
//! passes.
//!
//! `crates/components/hmac-sha256/src/tls13.rs` has a working two-party key
//! schedule tested against `draft-ietf-tls-tls13-vectors-06`, a different
//! vector set from the RFC 8448 trace used elsewhere in this crate. Reproducing
//! those same outputs here establishes the property that makes this crate
//! useful as an oracle: **oracle and MPC agree**, on inputs neither derived
//! from the other.
//!
//! Concretely this pins the interface between the two implementations:
//!
//! | MPC (`Tls13KeySched`)      | Oracle (`KeySchedule`)             |
//! |----------------------------|------------------------------------|
//! | `alloc(vm, pms)`           | `derive_handshake_secret(pms)`     |
//! | `set_hello_hash(h)`        | `handshake_keys(&h)`               |
//! | `handshake_keys()`         | → `HandshakeKeys`                  |
//! | `continue_to_app_keys()`   | `derive_master_secret()`           |
//! | `set_handshake_hash(h)`    | `application_keys(&h)`             |
//! | `application_keys()`       | → `ApplicationKeys`                |
//!
//! If this test and the MPC test both pass, a disagreement between them can
//! only come from the MPC protocol layer, not from a differing reading of the
//! key schedule.

use tlsn_tls13_reference::KeySchedule;

/// Parses the RFC-style spaced hex used by the MPC test fixtures.
fn hex(s: &str) -> Vec<u8> {
    let compact: String = s.split_whitespace().collect();
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn h(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verbatim from the `test_tls13_key_sched` fixtures in
/// `crates/components/hmac-sha256/src/tls13.rs`, whose reference values come
/// from <https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors-06>.
mod mpc_fixture {
    pub const PMS: &str = "81 51 d1 46 4c 1b 55 53 36 23 b9 c2 24 6a 6a 0e 6e 7e 18 50 63 e1 4a fd af f0 b6 e1 c6 1a 86 42";
    pub const HELLO_HASH: &str = "c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d";
    pub const HANDSHAKE_HASH: &str = "f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf";

    pub const CKEY_HS: &str = "26 79 a4 3e 1d 76 78 40 34 ea 17 97 d5 ad 26 49";
    pub const CIV_HS: &str = "54 82 40 52 90 dd 0d 2f 81 c0 d9 42";
    pub const SKEY_HS: &str = "c6 6c b1 ae c5 19 df 44 c9 1e 10 99 55 11 ac 8b";
    pub const SIV_HS: &str = "f7 f6 88 4c 49 81 71 6c 2d 0d 29 a4";

    pub const CKEY_APP: &str = "88 b9 6a d6 86 c8 4b e5 5a ce 18 a5 9c ce 5c 87";
    pub const CIV_APP: &str = "b9 9d c5 8c d5 ff 5a b0 82 fd ad 19";
    pub const SKEY_APP: &str = "a6 88 eb b5 ac 82 6d 6f 42 d4 5c 0c c4 4b 9b 7d";
    pub const SIV_APP: &str = "c1 ca d4 42 5a 43 8b 5d e7 14 83 0a";
}

/// The oracle must reproduce the handshake and application traffic keys the MPC
/// implementation produces from the same pre-master secret and transcript
/// hashes.
#[test]
fn oracle_reproduces_the_mpc_key_schedule_vectors() {
    use mpc_fixture as f;

    let pms = hex(f::PMS);
    let hello_hash: [u8; 32] = hex(f::HELLO_HASH).try_into().expect("32-byte hash");
    let handshake_hash: [u8; 32] = hex(f::HANDSHAKE_HASH).try_into().expect("32-byte hash");

    let mut ks = KeySchedule::new();

    // MPC: `Tls13KeySched::alloc(vm, pms)`.
    ks.derive_handshake_secret(&pms);

    // MPC: `set_hello_hash` then `handshake_keys`.
    let hs = ks
        .handshake_keys(&hello_hash)
        .expect("handshake stage entered");
    assert_eq!(
        h(&hs.client_write_key),
        h(&hex(f::CKEY_HS)),
        "client hs key"
    );
    assert_eq!(h(&hs.client_iv), h(&hex(f::CIV_HS)), "client hs iv");
    assert_eq!(
        h(&hs.server_write_key),
        h(&hex(f::SKEY_HS)),
        "server hs key"
    );
    assert_eq!(h(&hs.server_iv), h(&hex(f::SIV_HS)), "server hs iv");

    // MPC: `continue_to_app_keys` then `set_handshake_hash` and
    // `application_keys`.
    ks.derive_master_secret().expect("handshake stage entered");
    let app = ks
        .application_keys(&handshake_hash)
        .expect("master stage entered");
    assert_eq!(
        h(&app.client_write_key),
        h(&hex(f::CKEY_APP)),
        "client app key"
    );
    assert_eq!(h(&app.client_iv), h(&hex(f::CIV_APP)), "client app iv");
    assert_eq!(
        h(&app.server_write_key),
        h(&hex(f::SKEY_APP)),
        "server app key"
    );
    assert_eq!(h(&app.server_iv), h(&hex(f::SIV_APP)), "server app iv");
}

/// The MPC implementation derives the leader's handshake keys by expanding the
/// unmasked traffic secret with `key`, `iv` and `finished` labels. Pin that the
/// oracle's `finished_key` comes from the same secret as its `key` and `iv`, so
/// a future MPC comparison can rely on all three together.
#[test]
fn finished_keys_come_from_the_same_traffic_secrets() {
    use mpc_fixture as f;

    let hello_hash: [u8; 32] = hex(f::HELLO_HASH).try_into().expect("32-byte hash");

    let mut ks = KeySchedule::new();
    ks.derive_handshake_secret(&hex(f::PMS));

    let secrets = ks
        .handshake_traffic_secrets(&hello_hash)
        .expect("handshake stage entered");
    let keys = ks
        .handshake_keys(&hello_hash)
        .expect("handshake stage entered");

    assert_eq!(h(&secrets.client.key()), h(&keys.client_write_key));
    assert_eq!(h(&secrets.client.iv()), h(&keys.client_iv));
    assert_eq!(
        h(&secrets.client.finished_key()),
        h(&keys.client_finished_key)
    );
    assert_eq!(h(&secrets.server.key()), h(&keys.server_write_key));
    assert_eq!(h(&secrets.server.iv()), h(&keys.server_iv));
    assert_eq!(
        h(&secrets.server.finished_key()),
        h(&keys.server_finished_key)
    );
}

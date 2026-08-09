# tlsn-tls13-reference

A single-party TLS 1.3 reference implementation, used as a **test oracle** for
the MPC backend. This is milestone **M1** of
[`docs/research/tls13-mpc-tls-backend.md`](../../../docs/research/tls13-mpc-tls-backend.md).

It answers one question precisely: *what should the MPC implementation have
produced?* Everything MPC is tested against it.

## Scope

The narrow profile the MPC backend targets first:

- cipher suite `TLS_AES_128_GCM_SHA256` (SHA-256, AES-128-GCM);
- 1-RTT, server-authenticated handshakes;
- no PSK, no 0-RTT, no resumption, no `HelloRetryRequest`, no `KeyUpdate`.

What it contains:

| Module       | Covers |
|--------------|--------|
| `hkdf`       | `HKDF-Extract`/`Expand`, `HkdfLabel`, `HKDF-Expand-Label`, `Derive-Secret` |
| `transcript` | the running handshake transcript hash |
| `schedule`   | the three-stage key schedule (early → handshake → master) |
| `traffic`    | traffic secrets → `key`/`iv`/`finished_key`, `verify_data`, record nonces |
| `record`     | `TLSInnerPlaintext`, additional data, AEAD seal/open |
| `trace`      | an ordered log of every derivation, renderable in RFC 8448's layout |

**Not for production.** No certificate validation, no zeroization — every
intermediate secret is deliberately retained, because exposing them is the point
of an oracle.

## What is verified

`cargo test -p tlsn-tls13-reference` — 43 tests, three layers:

1. **`tests/rfc8448_sec3.rs`** — the complete published handshake trace of
   RFC 8448 section 3. Pins the key schedule, the traffic keys, both `Finished`
   MACs, and every protected record (decrypted *and* re-encrypted byte-for-byte).

   Two assertions carry disproportionate weight:
   - **`info` fields** are the serialized `HkdfLabel`. Asserting them localises
     a label-encoding bug — the most common TLS 1.3 key-schedule error — to
     label construction rather than to the output.
   - **transcript hashes are recomputed from the handshake messages** in the
     trace, not taken from the RFC's `hash` fields. Without this the schedule
     could be arithmetically correct while being driven at the wrong transcript
     positions.

2. **`tests/mpc_parity.rs`** — the same key schedule against the
   `draft-ietf-tls-tls13-vectors-06` fixtures that
   `crates/components/hmac-sha256/src/tls13.rs` already passes. A second,
   independent vector set: oracle and MPC agree on inputs neither derived from
   the other, which is what makes the oracle trustworthy for M2.

3. **Unit tests** — HKDF block boundaries, nonce XOR semantics, key-schedule
   stage ordering, and record-layer negative cases (bad tag on a wrong sequence
   number, tampered header, tampered ciphertext, truncated record, all-padding
   plaintext).

## Regenerating the RFC 8448 vectors

`tests/vectors/rfc8448_sec3.rs` is **generated, not transcribed**, so it cannot
drift from the RFC through a copy error:

```sh
cd crates/tls/tls13-reference
curl -sO https://www.rfc-editor.org/rfc/rfc8448.txt
python3 tools/gen_rfc8448_vectors.py rfc8448.txt > tests/vectors/rfc8448_sec3.rs
rm rfc8448.txt
```

Two independent checks make silent corruption unlikely: every field's byte count
is compared against the `(N octets)` figure printed beside it in the RFC, and
every selected operation is matched against its expected party and operation
name, so any reflow of the source document fails loudly rather than shifting
values.

## Using it against the MPC implementation

The oracle's entry point takes the same input the MPC key schedule does — the
ECDHE shared secret, which MPC holds secret-shared as `pms`:

```rust
use tlsn_tls13_reference::KeySchedule;

let mut ks = KeySchedule::new();
ks.derive_handshake_secret(&ecdhe_shared_secret);   // MPC: alloc(vm, pms)
let hs = ks.handshake_keys(&hello_hash)?;           // MPC: set_hello_hash + handshake_keys
ks.derive_master_secret()?;                         // MPC: continue_to_app_keys
let app = ks.application_keys(&handshake_hash)?;    // MPC: set_handshake_hash + application_keys
```

`HandshakeKeys` and `ApplicationKeys` mirror the field names of their
`tlsn_hmac_sha256` counterparts, so the two can be compared field by field.

When they disagree, `ks.trace().render()` prints every derivation in RFC 8448's
layout — which says *which* step diverged, instead of only that a final key was
wrong.

## Boundary with later milestones

This crate consumes the ECDHE shared secret as an input; it does **not** compute
X25519. Verifying that `CLIENT_X25519 × SERVER_X25519` yields the trace's
handshake `IKM` belongs to **M3** (distributed X25519). Both key pairs are
retained in the generated vectors so that work starts with a known-answer test.

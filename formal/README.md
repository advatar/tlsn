# TLS 1.3 verification artifacts

This directory contains machine-checked models for the TLSNotary TLS 1.3
record layer. Each artifact states its abstraction boundary and must not be
used to claim properties outside that boundary.

## Symbolic protocol model

`tamarin/tls13_joint_aead.spthy` models the application-record path against a
Dolev--Yao network adversary that may also act as the prover. AES-GCM and the
joint MPC evaluation are idealized. XOR tag-share reconstruction is modeled
by the free constructor `fshare(tag, leader_share)`; algebraic XOR and bit-level
behavior belong to the later implementation-equivalence layer. The model
checks:

- executability of an honest application-record exchange;
- secrecy of the complete application traffic key;
- authenticated release of a server plaintext;
- uniqueness of `(traffic key, direction, generation, sequence)` use;
- rejection of a replay under the same read epoch.

Run it with:

```bash
./formal/verify.sh
```

The wrapper fails unless every required lemma is reported as verified. This
extra check matters because Tamarin can exit successfully after finding and
reporting a counterexample.

The model is only one layer of the verification argument. In particular, it
does not prove computational security of the release capsule, correctness of
the MPC implementation, Rust refinement, side-channel resistance, or the TLS
1.3 handshake.

## Epoch and nonce specification

`lean/Tls13Epoch.lean` proves that successful sequence reservation returns the
owned sequence, advances exactly once, preserves the traffic-secret
generation, rejects exhaustion, and gives distinct consecutive sequence
numbers. It also proves that RFC 8446 nonce derivation is injective for a fixed
96-bit IV.

These are theorems about the Lean specification. A separate refinement or
model-checking step is required to connect them to the Rust implementation.

Four Kani harnesses in `crates/mpc-tls/src/tls13.rs` model-check the actual
`ReadEpoch::reserve_sequence`, `WriteEpoch::reserve_sequence`, and
`make_tls13_nonce` implementations for all `u64` sequences and all 96-bit IVs.
They prove successful advancement, generation preservation, exhaustion without
wrap, and fixed-IV nonce injectivity. Kani verifies these isolated functions;
it does not establish whole-program refinement or concurrency properties.

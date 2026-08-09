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

`tamarin/tls13_handshake_transcript.spthy` is the handshake/transcript symbolic
boundary. It
models certificate signing, `CertificateVerify` transcript binding, application
epoch installation, record commitments, and presentation acceptance. It does
not yet model the concrete TLS 1.3 HKDF transcript or selective-disclosure
observational equivalence; those boundaries are covered by the dedicated
key-schedule and selective-disclosure theories below. Concrete Rust
HKDF/parser refinement remains open.

`tamarin/tls13_selective_disclosure.spthy` is a minimal observational-
equivalence model for selective disclosure: the two diff branches share the
same public projection while differing only in unrevealed bytes. It is a
sanity-check boundary, not yet the concrete transcript leakage model.

`tamarin/tls13_key_schedule.spthy` adds a symbolic TLS 1.3 key-schedule
boundary. It models HKDF-Extract and HKDF-Expand-Label as private constructors,
binds Finished verification to the transcript hash, and proves five
execution/order/context properties. This is not a bit-level proof of the Rust HKDF
implementation.

The reproduction wrapper checks five additional lemmas from this model:
handshake executability and agreement, application-epoch agreement,
presentation agreement, and server-identity binding.

`./formal/validate.sh` runs the executable MPC/reference equivalence tests for
GHASH, AES-GCM, and secret-nonce TLS 1.3 records, the HMAC/key-schedule and
TLS configuration suites, the public test build, and the focused end-to-end
TLS 1.3 fixture. Docker interoperability remains an explicit separate suite.

Run that suite with `./formal/interop.sh`; it covers nginx RSA, nginx ECDSA,
Apache RSA, Caddy RSA, and OpenSSL `s_server`.

The complete command matrix and expected evidence are recorded in
`formal/REPRODUCIBILITY.md`.

The symbolic-to-Rust mapping and open proof obligations are recorded in
`formal/REFINEMENT_BOUNDARY.md`.

## Epoch and nonce specification

`lean/Tls13Epoch.lean` proves that successful sequence reservation returns the
owned sequence, advances exactly once, preserves the traffic-secret
generation, rejects exhaustion, and gives distinct consecutive sequence
numbers. It also proves that RFC 8446 nonce derivation is injective for a fixed
96-bit IV.

These are theorems about the Lean specification. A separate refinement or
model-checking step is required to connect them to the Rust implementation.

`lean/Tls13HkdfLabel.lean` proves the TLS 1.3 HKDF label framing length and
prefix structure used by the Rust encoder. It intentionally does not claim
cryptographic HMAC correctness.

`lean/Tls13Sha384.lean` checks the SHA-384/AES-256 width domain: 48-byte
hashes, 32-byte traffic keys, 12-byte IVs, 16-byte GCM tags, and fixed TLS
label overhead. It is executed by `formal/verify.sh`.

Four Kani harnesses in `crates/mpc-tls/src/tls13.rs` model-check the actual
`ReadEpoch::reserve_sequence`, `WriteEpoch::reserve_sequence`, and
`make_tls13_nonce` implementations for all `u64` sequences and all 96-bit IVs.
They prove successful advancement, generation preservation, exhaustion without
wrap, and fixed-IV nonce injectivity. Kani verifies these isolated functions;
it does not establish whole-program refinement or concurrency properties.

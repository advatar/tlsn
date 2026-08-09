# MPZ SHA-384 circuit design

The next implementation must add a SHA-384 compression circuit to the pinned
MPZ circuit-data pipeline. The circuit signature should be:

```text
sha384_compress(msg: [u8; 128], state: [u64; 8]) -> [u64; 8]
```

The message block is 128 bytes because SHA-384 uses the SHA-512 schedule. The
state uses the SHA-384 initial constants and the first six words of the final
SHA-512 state are exposed as the digest state. The circuit must implement all
80 rounds with 64-bit wrapping addition, rotations `(28, 34, 39)`, `(14, 18,
41)`, and the SHA-512 schedule rotations `(1, 8, 7)` and `(19, 61, 6)`.

## Required integration points

1. Add `sha384.bin` generation/loading alongside MPZ's `sha256.bin`.
2. Add a circuit evaluator test against `sha2::compress512`.
3. Build secret-shared HMAC-SHA384 on the circuit, preserving the existing
   normal/reduced VM modes.
4. Add HKDF-Extract/Expand-Label vectors for the TLS 1.3 SHA-384 suite.
5. Generalize transcript and Finished widths to 48 bytes.
6. Only then enable `TLS_AES_256_GCM_SHA384` in the backend.

The standalone boolean circuit builder and its `sha2::compress512` equivalence
test now live in
`crates/components/hmac-sha256/src/tls13/sha384_circuit.rs`. It is not yet
wired into secret-shared HMAC/HKDF or production negotiation. A VM call
adapter now exists in `tls13/sha384_vm.rs`; it is intentionally kept unused
until the HMAC state machine and its width invariants are implemented.

## Verification gates

The milestone is not complete when the circuit merely evaluates. It must also
provide:

- circuit/reference equivalence against `sha2::compress512` over deterministic
  and randomized cases;
- HMAC-SHA384 and HKDF-Expand-Label vector checks in both MPC execution modes;
- formal width and domain-separation invariants for 48-byte hashes, Finished
  keys, and 32-byte AES-256 traffic keys;
- updated Tamarin key-schedule and record-layer claims for the SHA-384 suite;
- Lean/Kani checks for new key-width, nonce, epoch, and suite-selection state;
- the existing adversarial and interoperability suites extended to AES-256.

The current MPZ dependency contains only `sha256.bin`; no SHA-384 circuit is
silently substituted. Until this design is implemented and tested, AES-256
negotiation remains rejected.

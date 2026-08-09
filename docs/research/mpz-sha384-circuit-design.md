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

The current MPZ dependency contains only `sha256.bin`; no SHA-384 circuit is
silently substituted. Until this design is implemented and tested, AES-256
negotiation remains rejected.

# TLS 1.3 cipher-suite generalization

The current MPC backend intentionally supports only
`TLS_AES_128_GCM_SHA256`. The TLS core advertises additional TLS 1.3 suites,
but `MpcTlsLeader::set_cipher_suite` rejects them before key installation; this
is a fail-closed capability boundary, not an interoperability claim.

## Current dependency boundary

The pinned MPZ hash dependency exposes `mpz_hash::sha256` but no SHA-384 or
SHA-512 MPC compression functionality. Consequently, enabling
`TLS_AES_256_GCM_SHA384` requires a new secret-shared SHA-384/HMAC/HKDF path;
changing the AES key length alone would be incorrect because TLS 1.3 derives
the transcript hash, Finished key, traffic secret, and labels under SHA-384.

## Implementation order

1. Add and test a constant-time MPC SHA-384 compression primitive.
2. Generalize HMAC/HKDF and transcript/Finished widths from 32 to 48 bytes.
3. Parameterize AES-GCM key setup for 16- and 32-byte keys while retaining the
   existing 12-byte IV and 16-byte tag.
4. Add RFC vectors and two-party reference-equivalence tests.
5. Enable `TLS_AES_256_GCM_SHA384` only after end-to-end interop passes against
   the existing server matrix.
6. Implement ChaCha20-Poly1305 as a separate MPC circuit and authentication
   milestone; it cannot reuse AES-GCM circuits.

Until these steps are complete, the rejection in the handshake backend must be
preserved so an unsupported suite cannot be negotiated into a SHA-256-only
implementation.

The first groundwork milestone is now present in
`crates/components/hmac-sha256/src/tls13/sha384_reference.rs`: clear
SHA-384 HKDF-Extract, HKDF-Expand, and TLS 1.3 label encoding functions. They
are test-only reference oracles and are not used to process secret MPC state.

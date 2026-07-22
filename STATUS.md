# STATUS

## CR-001

- [x] Port the upstream TLS 1.3 HKDF/key-schedule groundwork into `crates/components/hmac-sha256` while preserving the current TLS 1.2 public API used by this checkout.
- [x] Add TLS 1.3 key-schedule tests alongside the existing TLS 1.2 coverage.
- [x] Verify the updated `tlsn-hmac-sha256` crate builds and its tests pass.
- [x] Add TLS 1.3 epoch/key types in `crates/mpc-tls` and preserve the current TLS 1.2 `SessionKeys` API used by `tlsn`.
- [x] Allocate and retain TLS 1.3 key-schedule state in `MpcTlsLeader` and `MpcTlsFollower` so later backend work can consume it.
- [x] Add a targeted `mpc-tls` TLS 1.3 key-layer test and verify `tlsn-mpc-tls` still builds.
- [x] Import the TLS 1.3 key-exchange scope/shared-secret helpers from the side workstream into `crates/components/key-exchange`.
- [x] Consume the retained TLS 1.3 key-schedule state from the `mpc-tls` backend methods so `ServerHello`, Finished, and traffic-mode transitions use the TLS 1.3 path.
- [x] Implement TLS 1.3 record protection in `mpc-tls` for the v0 workstream and add targeted tests for the handshake/application traffic transitions.
- [x] Export TLS 1.3 transcripts and finalized proof material from `crates/mpc-tls` instead of erroring on close.
- [x] Teach `crates/tlsn` to prove and verify TLS 1.3 application traffic without assuming the TLS 1.2 tag/IV layout.
- [x] Extend the handshake and attestation data model so TLS 1.3 certificate binding can be carried and verified end-to-end.
- [x] Add a TLS 1.3 end-to-end `tlsn` fixture test and verify the focused TLS 1.3 path locally.

## CR-002

- [x] Scaffold a browser demo workspace with static assets and a local Rust server.
- [x] Implement a WebSocket-backed notary service that runs the verifier role for a browser prover.
- [x] Implement a WebSocket TCP bridge for target TLS connections with conservative destination validation.
- [x] Add a browser client that drives `tlsn-wasm`, shows the transcript, and lets the user choose reveal ranges.
- [x] Add focused tests for session pairing and destination validation, plus usage documentation.
- [x] Verify the browser demo builds and the focused test suite passes locally.

Note: keep the eventual proof artifact shape compatible with wrapping in a W3C Verifiable Credential.

## CR-003

- [x] Add a shared developer launcher for the browser demo flow.
- [x] Add `make` and `npm` wrappers for the browser demo commands.
- [x] Document the wrapper usage and verify the command wiring locally.

## CR-004

- [x] Capture a staged plan for adding verifier webhooks and an optional EAS attestation flow to the browser demo without importing the full `tlsn-extension` stack.

## CR-005

- [x] Generalize the TLS 1.3 MPC HKDF boundary to accept the 64-byte `SecP256r1MLKEM768` hybrid shared secret without regressing the P-256 path.
- [x] Add the draft `SecP256r1MLKEM768` named-group code point and exact client/server wire-format primitives.
- [x] Add ML-KEM-768 key generation and decapsulation using RustCrypto's FIPS 203 implementation.
- [x] Add focused tests for hybrid share lengths, parsing, decapsulation, secret ordering, and malformed inputs.
- [x] Document the security boundary and the remaining handshake/threshold-ML-KEM work.
- [x] Verify the focused tests and affected-crate builds, then commit only CR-005 files.

The next PQ milestone is to make group selection configurable and carry the
ML-KEM private input through both MPC-TLS roles. A subsequent cryptographic
workstream must replace single-party decapsulation with threshold ML-KEM before
claiming post-quantum security against a prover or verifier.

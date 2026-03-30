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

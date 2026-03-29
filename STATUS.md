# STATUS

## CR-001

- [x] Port the upstream TLS 1.3 HKDF/key-schedule groundwork into `crates/components/hmac-sha256` while preserving the current TLS 1.2 public API used by this checkout.
- [x] Add TLS 1.3 key-schedule tests alongside the existing TLS 1.2 coverage.
- [x] Verify the updated `tlsn-hmac-sha256` crate builds and its tests pass.
- [x] Add TLS 1.3 epoch/key types in `crates/mpc-tls` and preserve the current TLS 1.2 `SessionKeys` API used by `tlsn`.
- [x] Allocate and retain TLS 1.3 key-schedule state in `MpcTlsLeader` and `MpcTlsFollower` so later backend work can consume it.
- [x] Add a targeted `mpc-tls` TLS 1.3 key-layer test and verify `tlsn-mpc-tls` still builds.

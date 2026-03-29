# STATUS

## CR-001

- [x] Port the upstream TLS 1.3 HKDF/key-schedule groundwork into `crates/components/hmac-sha256` while preserving the current TLS 1.2 public API used by this checkout.
- [x] Add TLS 1.3 key-schedule tests alongside the existing TLS 1.2 coverage.
- [x] Verify the updated `tlsn-hmac-sha256` crate builds and its tests pass.

# TLSNotaryMobile

`TLSNotaryMobile` is an experimental Swift Package backed by a Rust static
library. It provides the first iPhone vertical slice for selecting an HTTPS
page, replaying its current GET request, constructing a W3C VC-shaped TLSNotary
evidence payload, and binding that payload to a holder P-256 key.

## Build

The installed Rust toolchain needs these targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./packages/TLSNotaryMobile/build-xcframework.sh
cd packages/TLSNotaryMobile
swift test
```

Add `packages/TLSNotaryMobile` as a local package in Xcode. The package exposes
`TLSNotaryMobileClient`, `EvidenceRequest`, `SecureEnclaveHolderKey`, and an
iOS-only `WebEvidenceView`.

## Current security boundary

This milestone builds and signs the portable credential envelope, but does not
yet execute the TLSNotary prover from iOS. `WebEvidenceView` currently replays
the selected GET using `URLSession`; its response hash is not independently
verifiable unless a real notary attestation is supplied.

The next integration replaces that replay implementation with a Rust
`tlsn-sdk-core` session connected to the verifier and TCP relay. The resulting
notary attestation belongs in the `notaryAttestation` field before the holder
signature is created.

The exported envelope is not automatically a trusted EUDI credential. An
EUDI-recognized issuer can validate its embedded TLSNotary evidence and issue a
profiled credential through OpenID4VCI.

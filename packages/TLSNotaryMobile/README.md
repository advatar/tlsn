# TLSNotaryMobile

`TLSNotaryMobile` is an experimental Swift Package backed by a Rust static
library. It provides an iPhone vertical slice for selecting an HTTPS page,
running its current GET through a native TLSNotary prover, constructing a W3C
VC-shaped evidence payload, and binding that payload to a holder P-256 key.

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

Configure the client with the URL of the companion browser-demo notary/relay:

```swift
let client = try TLSNotaryMobileClient(
    notary: NotaryConfiguration(baseURL: URL(string: "https://notary.example")!),
    holderKey: try SecureEnclaveHolderKey()
)
WebEvidenceView(client: client)
```

## Current security boundary

The Rust engine now executes `tlsn-sdk-core` against the verifier and TCP relay,
reveals the complete HTTP exchange, and embeds the verifier's session output
before applying the holder signature. WKWebView cookies are copied into the
notarized GET, so those cookies and all revealed response data are disclosed to
the configured verifier. Use a trusted notary and narrowly scoped cookies.

The embedded verifier output is retrieved online from that notary service; it
is not yet a portable, notary-signed attestation that an offline verifier can
authenticate. The current credential therefore remains dependent on the
configured notary's identity and availability.

The exported envelope is not automatically a trusted EUDI credential. An
EUDI-recognized issuer can validate its embedded TLSNotary evidence and issue a
profiled credential through OpenID4VCI.

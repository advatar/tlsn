# STATUS

## CR-012 — TLS 1.3 formal verification and scientific paper

- [x] Define the initial protocol boundary, adversary model, security claims, assumptions, and trusted computing base.
- [x] Add a reproducible Tamarin model for joint TLS 1.3 application-record protection.
- [x] Machine-check record-layer executability, key secrecy, authenticated release, replay resistance, and nonce-uniqueness lemmas.
- [x] Extend the symbolic model through certificate/handshake authentication, transcript agreement, and commitment-based presentation acceptance.
- [x] Add a symbolic TLS 1.3 HKDF/Finished/application-secret boundary model.
- [ ] Prove concrete TLS 1.3 HKDF/parser refinement against the Rust implementation.
- [x] Document the fail-closed TLS 1.3 cipher-suite capability boundary and AES-256/ChaCha20 generalization plan.
- [x] Add a clear SHA-384 HKDF/HkdfLabel reference oracle for future MPC equivalence tests.
- [ ] Integrate the SHA-384 compression circuit into secret-shared HMAC/HKDF.
- [x] Add the SHA-384 streaming VM hasher and HMAC-SHA384 padded-key partial/HMAC scaffolding.
- [x] Execute two-party HMAC-SHA384 against a cleartext SHA-384 reference vector.
- [x] Execute two-party TLS 1.3 SHA-384 HKDF-Expand-Label against the reference oracle.
- [x] Implement secret-shared SHA-384 HKDF-Extract over single and hybrid IKM vectors, with reference equivalence coverage.
- [x] Integrate SHA-384 HKDF-Extract and Expand-Label into a secret-shared handshake-traffic derivation path, with two-party reference equivalence.
- [x] Derive secret-shared SHA-384 application traffic secrets and typed 32-byte AES-256 keys/12-byte IV views, with reference equivalence.
- [x] Compute secret-shared SHA-384 Finished MACs over transcript hashes, with reference equivalence.
- [x] Verify SHA-384 streaming compression and HMAC across multi-block inputs against clear references.
- [x] Add and test AES-256-GCM TLS 1.3 record encrypt/decrypt helpers with typed 32-byte epochs.
- [x] Expose the secret-shared SHA-384 application-key material API for MPC-TLS integration.
- [x] Add a typed SHA-384/AES-256 application epoch slot to the MPC-TLS session-key model.
- [x] Connect the MPZ SHA-384 application allocator to MPC-TLS epoch installation, with a two-party integration test.
- [ ] Integrate SHA-384 HKDF into a full TLS 1.3 key-schedule state machine with 48-byte Finished/transcript state.
- [x] Implement a standalone SHA-384 compression circuit and verify it against `sha2::compress512`.
- [x] Specify the MPZ SHA-384 circuit signature, constants/round structure, and integration points.
- [ ] Formally verify SHA-384 circuit/reference equivalence and HMAC/HKDF width/domain invariants.
- [x] Extend Tamarin/Lean/Kani artifacts with a suite-specific AES-256/SHA-384 symbolic key-schedule boundary.
- [ ] Extend Lean/Kani artifacts for AES-256 epochs and suite negotiation, and connect the circuit to the concrete state machine.
- [ ] Re-run adversarial tests and interoperability after enabling any additional TLS 1.3 suite.
- [ ] Compose handshake, Finished, epoch, record, and disclosure models into an end-to-end provenance theorem.
- [ ] Bind a transcript-derived session identity and `RecordId` through release and presentation for cross-session non-transferability.
- [x] Add a bounded selective-disclosure leakage-equivalence model.
- [x] Specify a review-ready computational proof target for the authenticated-release capsule and identify required construction hardening.
- [x] Add Lean specifications and Kani implementation checks for typed epochs, sequence ownership, exhaustion, and nonce derivation.
- [x] Establish executable equivalence checks between MPC AES/GHASH operations and the TLS 1.3 AES-GCM reference semantics.
- [x] Add adversarial tests for malformed, replayed, reordered, cross-epoch, and prematurely released records.
- [x] Provide one-command reproduction of formal results and core validation-table entries; Docker interoperability remains a separate explicit suite.
- [x] Draft a publication-quality paper whose claims link to exact proof artifacts and whose limitations distinguish symbolic, computational, and implementation assurance.
- [x] Create the initial cited manuscript, claim--evidence matrix, bibliography, and deterministic HTML/LaTeX build.
- [x] Run all proof, build, test, bibliography, and paper-render checks; commit only verified artifacts.

## CR-011 — sound TLS 1.3 joint record protection

- [x] Step A: remove complete application-traffic-key decoding and disable the unsound local AEAD path.
- [x] Step B: introduce typed read/write epochs that exclusively own their sequence numbers.
- [x] Add a distinct preprocessed GHASH key domain plus per-record secret-nonce joint encrypt,
      tag-compute, tag-verify, and OTP-masked decrypt operations for TLS 1.3 application records.
- [x] Bind AEAD key-install circuits directly to application key-schedule outputs in the initial VM graph.
- [x] Select only the negotiated protocol's GHASH key domain during record-layer setup.
- [x] Preallocate bounded TLS 1.3 record AES/J0 circuits against the application key/IV outputs.
- [x] Implement joint AEAD over secret-shared TLS 1.3 application traffic keys.
- [x] Correct the research document's blocker diagnosis and M3 group.
- [x] Fix TLS 1.3 interoperability against Caddy and OpenSSL `s_server`.
- [x] Cryptographically gate authenticated plaintext release without disclosing the follower tag share.
- [x] Re-enable and pass the focused TLS 1.3 fixture and interoperability tests.
- [x] Remove obsolete warnings that claimed TLS 1.3 joint AEAD was not wired.

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

## CR-006

- [x] Add an iOS-safe Rust FFI crate for URL/request validation and portable evidence-credential construction.
- [x] Add a Swift Package with async, memory-safe wrappers over the Rust ABI and holder-signature verification.
- [x] Add an iOS SwiftUI/WKWebView example that captures the selected URL and creates an evidence credential.
- [x] Add software and Secure Enclave holder keys with `did:jwk` identifiers.
- [x] Add an XCFramework build script and integration documentation for device, simulator, and macOS test targets.
- [x] Add Rust and Swift unit tests for validation, credential shape, signing, and FFI ownership.
- [x] Verify Rust tests, Swift tests, and an iOS Simulator package build, then commit only CR-006 files.

The next mobile milestone is to expose `tlsn-sdk-core` setup, request, and proof
operations through an asynchronous FFI handle and replace the `URLSession`
replay with a notary/relay-backed Rust connection. OpenID4VCI issuance remains
an issuer-service integration after the evidence proof is produced.

## CR-007

- [x] Add a native WebSocket IO adapter compatible with `tlsn-sdk-core` on iOS.
- [x] Expose an asynchronous Rust FFI operation that runs setup, HTTPS GET, transcript capture, and reveal against the notary/relay service.
- [x] Return the verified notary-session result to Swift and embed it in the holder-signed evidence credential.
- [x] Replace the Swift `URLSession` replay with the Rust notary operation while preserving WKWebView cookies.
- [x] Add callback lifetime/error tests and a local end-to-end notary integration test.
- [x] Rebuild the XCFramework, run Rust/Swift/iOS builds, document the trust boundary, and commit only CR-007 files.

The mobile credential currently embeds online verifier output, not a portable
notary-signed attestation. The next milestone is to define and sign a durable
evidence artifact, then add the issuer-facing OpenID4VCI exchange needed for an
EUDI wallet to accept a profiled credential.

## CR-008

- [x] Define a versioned, deterministic portable artifact containing the session identifier, issue time, and verifier output.
- [x] Sign completed artifacts with a persistent P-256 notary key and expose the corresponding public key.
- [x] Verify the artifact signature and pinned notary key in the Rust mobile boundary before credential construction.
- [x] Carry the signed artifact through the Swift API and require an explicitly trusted notary public key.
- [x] Add round-trip, wrong-key, and payload/signature tamper tests.
- [x] Rebuild the XCFramework, run Rust/browser-demo/Swift/iOS builds, document key provisioning, and commit only CR-008 files.

The next wallet milestone is an issuer adapter implementing an authorization
code or pre-authorized OpenID4VCI flow. It must validate the signed notary
artifact and map disclosed evidence into a supported EUDI credential profile;
the self-issued holder envelope alone is not wallet-trusted.

## CR-009

- [x] Add a standalone issuer service implementing OpenID4VCI 1.0 Final metadata and pre-authorized credential offers.
- [x] Accept only pinned-key, signature-valid TLSNotary artifacts and create short-lived, single-use issuance grants.
- [x] Implement OAuth authorization-server metadata, single-use pre-authorized-code token exchange, and nonce issuance.
- [x] Validate ES256 OpenID4VCI JWT key proofs against audience, nonce, and time before issuing.
- [x] Issue holder-bound JWT VC evidence credentials signed by a persistent issuer P-256 key.
- [x] Add a Swift issuer handoff that submits the verified artifact and opens the returned wallet offer URI.
- [x] Add discovery, replay, wrong-key, invalid-proof, and successful end-to-end flow tests.
- [x] Document local/EUDI integration boundaries, verify all targets, and commit only CR-009 files.

The next production milestone is to replace the in-memory grant store with a
transactional shared store, deploy behind HTTPS, add credential status and
revocation, and map the evidence credential into a wallet-supported EUDI
profile under an accredited issuer trust framework.

## CR-010

- [x] Replace the prototype issuer handoff contract with `../VCIssuer`'s evidence-ingestion endpoint.
- [x] Decode VCIssuer's `deep_link` authorization-code offer response in Swift.
- [x] Preserve the signed notary artifact as the issuer input and reject unconfigured handoff.
- [x] Add exact response-contract tests and update Swift integration documentation.
- [x] Run Swift and iOS Simulator builds and commit only CR-010 files.

## ActiveChain issue #169 — portable credential conformance

- [x] Replace the opaque holder-signed JSON wrapper with a versioned, bounded evidence envelope
      that preserves notary/server, transcript/disclosure, holder, schema, freshness/status, and
      assurance provenance without exposing the source transcript.
- [x] Make issuer-upgraded assurance structurally dependent on an issuer-authorization commitment;
      self-issued evidence must remain visibly non-regulated.
- [x] Publish deterministic positive and malformed vectors shared with wallet and ActiveChain
      adapters, and cover holder/signature/substitution/freshness failures with unit tests.
      The 17-case TSV is byte-identical in all three repositories (SHA-256
      `668f87d8` prefix) and its closed decision table is consumed by an affected Rust test.
- [x] Run normal affected Rust and Swift package tests and strict affected-target linting.
  - [x] Seven affected Rust tests, six Swift package tests, the complete five-slice XCFramework
        rebuild, and touched-crate Clippy pass locally; repository-wide/transitive
        Clippy remains blocked by pre-existing HMAC and C-ABI lints outside this change.

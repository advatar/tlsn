TLSNotary should add TLS 1.3 as a **new MPC-TLS backend**, not by incrementally patching the TLS 1.2 implementation. TLS 1.3 changes the handshake, key schedule, record nonces, transcript authentication, resumption, and key updates enough that a clean protocol-specific state machine is safer.

TLSNotary’s current public documentation still says it supports TLS 1.2, with inconsistent language about whether TLS 1.3 is merely on the roadmap or has no immediate implementation plan.  [oai_citation:0‡tlsnotary.org](https://tlsnotary.org/docs/faq/?utm_source=chatgpt.com) The need is now substantial because TLS 1.3 is widely deployed, while the existing extension and verifier architecture is already suitable for adding another MPC-TLS engine behind the same interfaces.  [oai_citation:1‡tlsnotary.org](https://tlsnotary.org/docs/extension/)

# Recommended TLS 1.3 profile

Do not attempt all of TLS 1.3 initially. Define a deliberately narrow profile:

```text
TLSNotary TLS 1.3 Profile v1

Handshake:
  - Full 1-RTT handshake only
  - Server authentication only
  - No PSK
  - No session resumption
  - No 0-RTT
  - No post-handshake client authentication
  - No renegotiation, which TLS 1.3 removed anyway
  - One connection per notarization session

Key exchange:
  - X25519 initially
  - secp256r1 later

Cipher suites:
  - TLS_AES_128_GCM_SHA256 initially
  - TLS_CHACHA20_POLY1305_SHA256 second
  - TLS_AES_256_GCM_SHA384 later

Application protocols:
  - HTTP/1.1 initially
  - HTTP/2 after transcript framing is stable
  - QUIC/HTTP/3 out of scope

Record behavior:
  - KeyUpdate rejected in v1
  - Record padding accepted
  - NewSessionTicket ignored or recorded, but never reused
```

This gives broad practical compatibility without immediately adding every difficult branch in RFC 8446. TLS 1.3 uses HKDF throughout its key schedule and independently derives handshake and application traffic secrets; its record protocol uses AEAD with sequence-derived nonces.  [oai_citation:2‡RFC Editor](https://www.rfc-editor.org/info/rfc8446/?utm_source=chatgpt.com)

# Core security invariant

The critical invariant is:

> Neither the prover nor verifier may ever obtain a complete server application traffic key.

If the prover learns the complete server traffic key, they can forge arbitrary “server responses.” If the verifier learns it, the verifier can decrypt all private response data.

Therefore, application traffic secrets, keys, IVs, and authentication operations must remain secret-shared:

```text
server_application_traffic_secret
    = SATS_P ⊕ SATS_V

server_write_key
    = K_P ⊕ K_V

server_write_iv
    = IV_P ⊕ IV_V
```

The notation is conceptual. The implementation may use XOR shares, arithmetic shares, garbled circuits, or authenticated shares according to the MPZ primitive involved.

The verifier should learn only:

- the authenticated server identity;
- negotiated TLS parameters;
- transcript commitments;
- record boundaries and permitted metadata;
- explicitly disclosed HTTP data.

# Proposed protocol

## 1. Session agreement

Before opening the target connection, prover and verifier agree on a signed session configuration:

```rust
pub struct Tls13SessionConfig {
    pub protocol_version: ProtocolVersion, // TLS13
    pub server_name: String,
    pub server_port: u16,

    pub allowed_groups: Vec<NamedGroup>,
    pub allowed_cipher_suites: Vec<Tls13CipherSuite>,
    pub allowed_alpn: Vec<Vec<u8>>,

    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub max_records: u32,

    pub allow_hello_retry_request: bool,
    pub allow_key_update: bool,
    pub allow_resumption: bool,
    pub allow_early_data: bool,

    pub verifier_nonce: [u8; 32],
    pub config_hash: [u8; 32],
}
```

The resulting proof must bind to `config_hash`, preventing a prover from negotiating a weaker or different profile than the verifier authorized.

## 2. ClientHello construction

The prover can construct most of `ClientHello`, but the verifier must contribute freshness.

Recommended construction:

```text
client_random =
    H("tlsn/client-random/v1" ||
      prover_random ||
      verifier_random ||
      session_id)
```

For X25519, jointly generate the client private scalar:

```text
x = x_P + x_V mod group_order
X = x · G
```

Neither party learns `x`. The public key share `X` is inserted into `ClientHello`.

A simpler prototype could allow the prover to generate the ephemeral ECDHE key and then use MPC only from the shared secret onward, but that requires a careful argument that prover knowledge of the client scalar cannot lead to unilateral derivation of traffic secrets. Since the server’s public share is public, it normally would. Therefore, **the client ECDHE scalar must be jointly generated or otherwise kept from the prover**.

## 3. ServerHello processing and distributed ECDH

The server returns its public key share `Y`.

The parties calculate:

```text
Z = x · Y
```

without revealing `x` or `Z`.

For X25519 this requires a two-party scalar multiplication primitive. This is probably the largest new asymmetric MPC component if MPZ does not already expose one.

Possible implementation strategies:

1. **Dedicated two-party X25519**
   - Best long-term performance.
   - Most cryptographic engineering.

2. **Generic Boolean circuit**
   - Fastest path to correctness.
   - Potentially expensive in browser WASM.

3. **Oblivious linear evaluation or specialized curve protocol**
   - Better performance.
   - More protocol design and audit burden.

Start with a generic circuit as a reference implementation, then replace it with specialized X25519 after interoperability tests pass.

## 4. MPC HKDF key schedule

Implement these operations as first-class MPZ components:

```rust
trait MpcHkdf {
    async fn extract(
        &mut self,
        salt: SecretShare,
        ikm: SecretShare,
    ) -> Result<SecretShare>;

    async fn expand_label(
        &mut self,
        secret: SecretShare,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<SecretShare>;

    async fn derive_secret(
        &mut self,
        secret: SecretShare,
        label: &[u8],
        transcript_hash: &[u8],
    ) -> Result<SecretShare>;
}
```

The TLS 1.3 schedule becomes:

```text
early_secret
  = HKDF-Extract(0, 0)                 // no PSK in v1

derived_early
  = Derive-Secret(early_secret, "derived", "")

handshake_secret
  = HKDF-Extract(derived_early, Z)

client_handshake_traffic_secret
  = Derive-Secret(handshake_secret,
                  "c hs traffic",
                  Hash(CH...SH))

server_handshake_traffic_secret
  = Derive-Secret(handshake_secret,
                  "s hs traffic",
                  Hash(CH...SH))

derived_handshake
  = Derive-Secret(handshake_secret, "derived", "")

master_secret
  = HKDF-Extract(derived_handshake, 0)

client_application_traffic_secret_0
  = Derive-Secret(master_secret,
                  "c ap traffic",
                  Hash(full_handshake))

server_application_traffic_secret_0
  = Derive-Secret(master_secret,
                  "s ap traffic",
                  Hash(full_handshake))
```

A useful optimization is that transcript hashes are public once the corresponding handshake messages have been authenticated and parsed. SHA-256 does not need to run in MPC unless some handshake field is intentionally hidden from the verifier.

## 5. Encrypted handshake records

Unlike TLS 1.2, most of the server’s TLS 1.3 handshake is encrypted after `ServerHello`, including:

- `EncryptedExtensions`;
- `Certificate`;
- `CertificateVerify`;
- `Finished`.

These records must be jointly decrypted and authenticated using the server handshake traffic secret.

However, these handshake messages do not normally contain user-private application data. Therefore, after MPC authentication, they can be released to both parties for ordinary parsing and certificate validation.

That produces a major optimization:

```text
MPC:
  authenticate and decrypt encrypted handshake record

Public computation:
  parse handshake
  validate certificate chain
  validate hostname
  validate CertificateVerify signature
  update public transcript hash
```

The MPC must only release plaintext after the GCM tag has been validated. Never stream unauthenticated plaintext to either party.

## 6. Server authentication

The verifier must independently enforce:

```text
certificate chain valid
AND hostname matches session.server_name
AND CertificateVerify signature valid
AND server Finished valid
AND negotiated suite/group/profile allowed
```

Do not let the prover simply report that certificate validation succeeded.

You have two viable models:

### Model A — verifier validates publicly

After authenticated decryption, both parties see the certificate and handshake messages. The verifier performs normal X.509 and signature validation locally.

This is the recommended MVP.

### Model B — zero-knowledge server authentication

The prover hides parts of the certificate chain or handshake from the verifier and proves correctness.

This is much more expensive and offers little privacy benefit in most TLSNotary uses because the target hostname is ordinarily already known to the verifier.

## 7. Client Finished

The client’s Finished message must be jointly computed:

```text
finished_key =
    HKDF-Expand-Label(
        client_handshake_traffic_secret,
        "finished",
        "",
        Hash.length
    )

verify_data =
    HMAC(finished_key, transcript_hash)
```

Neither party should receive the complete `finished_key`.

After the client Finished is accepted, derive application secrets and erase handshake secrets as soon as practical.

## 8. Application record protection

TLS 1.3 derives the nonce as:

```text
nonce = static_write_iv XOR padded_record_sequence_number
```

For each direction, maintain an independently committed sequence number:

```rust
pub struct Tls13RecordState {
    pub epoch: TrafficEpoch,
    pub sequence_number: u64,
    pub traffic_secret_commitment: Digest,
    pub key_commitment: Digest,
    pub iv_commitment: Digest,
}
```

Each authenticated record should produce an internal receipt:

```rust
pub struct AuthenticatedRecord {
    pub direction: Direction,
    pub epoch: TrafficEpoch,
    pub sequence_number: u64,
    pub ciphertext_digest: Digest,
    pub plaintext_commitment: Digest,
    pub content_type: ContentType,
    pub plaintext_len: u32,
}
```

For incoming server records:

```text
ciphertext
   ↓
joint AES-GCM authentication/decryption
   ↓
authenticated plaintext shares
   ↓
transcript commitment
   ↓
selective disclosure
```

For outgoing client records:

```text
request plaintext shares
   ↓
policy checks / transcript commitment
   ↓
joint AES-GCM encryption
   ↓
ciphertext sent to server
```

This retains TLSNotary’s essential property: the prover can choose the request plaintext, but cannot fabricate a valid server response.

# Transcript model

Do not bind proofs directly to raw TLS record layout. TLS records can fragment application bytes in different ways.

Maintain two layers:

```text
Transport transcript:
  exact TLS records
  epochs
  sequence numbers
  ciphertext hashes
  authentication results

Application transcript:
  ordered plaintext byte streams
  sent bytes
  received bytes
  HTTP parser boundaries
  disclosure commitments
```

Then produce a versioned proof object:

```rust
pub struct Tls13SessionProof {
    pub format_version: u16,
    pub protocol: ProtocolVersion,
    pub session_config_hash: Digest,

    pub server_name: String,
    pub server_identity: ServerIdentityEvidence,
    pub negotiated: NegotiatedTls13Parameters,

    pub handshake_transcript_hash: Digest,
    pub sent_transcript_commitment: Digest,
    pub recv_transcript_commitment: Digest,

    pub sent_len: u64,
    pub recv_len: u64,

    pub disclosure: DisclosureProof,
    pub verifier_attestation: Signature,
}
```

Avoid reusing a TLS 1.2 proof type with optional TLS 1.3 fields. A version-specific evidence object makes downgrade and interpretation errors less likely.

# Suggested crate structure

```text
tlsn/
├── tlsn-core/
│   ├── proof/
│   │   ├── tls12.rs
│   │   └── tls13.rs
│   └── transcript/
│
├── tlsn-tls-core/
│   ├── common/
│   ├── tls12/
│   └── tls13/
│       ├── config.rs
│       ├── handshake.rs
│       ├── key_schedule.rs
│       ├── record.rs
│       ├── transcript.rs
│       └── state.rs
│
├── tlsn-tls-client/
│   ├── tls12.rs
│   └── tls13.rs
│
└── tlsn-verifier/
    ├── tls12.rs
    └── tls13.rs

mpz/
├── mpz-hkdf/
├── mpz-hmac/
├── mpz-x25519/
├── mpz-aead/
│   ├── aes_gcm.rs
│   └── chacha20_poly1305.rs
└── mpz-tls13/
```

The TLS engine should depend on abstract cryptographic capabilities rather than a particular garbling implementation:

```rust
pub trait Tls13MpcProvider:
    MpcEcdhe
    + MpcHkdf
    + MpcHmac
    + MpcAead
    + MpcCommit
{
}
```

# State machine

Use a strict typestate or enum-driven state machine:

```rust
pub enum Tls13State {
    Start,
    ClientHelloSent,
    ServerHelloAuthenticated,
    HandshakeKeysDerived,
    ServerFlightAuthenticated,
    ServerIdentityVerified,
    ClientFinishedSent,
    Connected,
    Closing,
    Closed,
    Failed,
}
```

Every transition should bind the expected transcript hash and reject:

- unexpected messages;
- duplicate messages;
- unsupported extensions;
- unapproved cipher suites;
- illegal epoch transitions;
- sequence-number reuse;
- key changes outside an approved `KeyUpdate`.

# KeyUpdate

Leave `KeyUpdate` disabled initially. When added, perform:

```text
application_traffic_secret_(N+1)
  = HKDF-Expand-Label(
      application_traffic_secret_N,
      "traffic upd",
      "",
      Hash.length
    )
```

Then reset that direction’s record sequence number to zero and create a new transcript epoch.

A proof must state every traffic epoch used. Otherwise, an implementation bug could accidentally combine records authenticated under different keys.

# HelloRetryRequest

It is feasible but should be a second milestone. It changes transcript hashing by replacing the first `ClientHello` with a synthetic `message_hash` handshake message.

For the first release:

```text
allow_hello_retry_request = false
```

Ensure the first ClientHello offers the chosen supported group, preferably X25519, so common servers do not need a retry.

# Resumption and 0-RTT

Do not support either in the first version.

0-RTT introduces replay semantics, and PSK binders require computing a Finished-like MAC over a partially truncated ClientHello. RFC 8446 explicitly treats early data as replayable and places additional anti-replay obligations on applications.  [oai_citation:3‡RFC Editor](https://www.rfc-editor.org/info/rfc8446/?utm_source=chatgpt.com)

Later, resumption should require a verifier-bound ticket object:

```rust
pub struct NotarizedResumptionTicket {
    pub ticket_commitment: Digest,
    pub originating_session: Digest,
    pub verifier_id: VerifierId,
    pub server_name: String,
    pub cipher_suite: Tls13CipherSuite,
    pub expires_at: Timestamp,
    pub use_counter: u32,
}
```

Never silently reuse ordinary browser tickets in an MPC-TLS session.

# HTTP/2 and HTTP/3

TLS 1.3 support and HTTP/2 support should be separate projects.

HTTP/2 adds:

- binary framing;
- multiplexed streams;
- HPACK state;
- interleaved response data;
- connection-level control frames.

TLSNotary currently models constrained sent and received transcript sizes in verifier sessions.  [oai_citation:4‡tlsnotary.org](https://tlsnotary.org/docs/extension/verifier/) HTTP/2 requires disclosure proofs to identify stream IDs and reconstructed header blocks rather than merely byte ranges.

HTTP/3 is not just TLS 1.3 over a different socket. QUIC integrates TLS 1.3 keys into a separate packet protection protocol, so it needs a dedicated MPC-QUIC design. Keep it out of scope.

# Implementation milestones

## Milestone 1 — non-MPC TLS 1.3 reference engine

Build or adapt a deterministic TLS 1.3 client that supports only the selected profile.

Deliverables:

- RFC test-vector compatibility;
- local OpenSSL/BoringSSL/rustls interoperability;
- transcript hash tracing;
- key schedule tracing;
- AES-GCM record tests.

This becomes the oracle against which MPC execution is tested.

## Milestone 2 — MPC key schedule and record layer

Implement:

- shared HKDF-Extract;
- shared HKDF-Expand-Label;
- HMAC-SHA256;
- AES-128-GCM;
- sequence-derived nonce logic;
- authenticated-release semantics.

Use fixed secrets and RFC vectors before adding ECDHE.

## Milestone 3 — distributed X25519

Implement shared client key generation and shared-secret calculation.

Required tests:

- neither party alone derives `Z`;
- resulting public key is valid;
- low-order and invalid points are rejected according to the chosen X25519 rules;
- generated shared secret matches a conventional implementation;
- aborts do not expose reusable scalar shares.

## Milestone 4 — complete handshake

Add:

- ClientHello;
- ServerHello;
- encrypted server flight;
- X.509 validation;
- CertificateVerify;
- Finished;
- transition to application keys.

## Milestone 5 — TLSNotary proof integration

Add:

- TLS 1.3 proof format;
- transcript commitments;
- selective disclosure;
- verifier signatures;
- extension and WASM bindings.

## Milestone 6 — production hardening

Add:

- malformed-handshake fuzzing;
- cross-implementation testing;
- malicious prover tests;
- malicious verifier privacy tests;
- memory zeroization;
- abort consistency;
- resource limits;
- cryptographic review.

# Test matrix

At minimum:

```text
Servers:
  nginx/OpenSSL
  Apache/OpenSSL
  rustls
  BoringSSL
  Cloudflare-hosted endpoint
  AWS-hosted endpoint

Handshake cases:
  AES-128-GCM/SHA-256
  X25519
  fragmented handshake records
  fragmented application records
  record padding
  close_notify
  invalid certificate
  hostname mismatch
  invalid Finished
  invalid AEAD tag
  reordered record
  duplicated record
  truncated record
  unsupported PSK
  attempted 0-RTT
  attempted KeyUpdate
  attempted HelloRetryRequest

HTTP:
  GET
  POST
  cookies
  authorization header
  chunked response
  content-length response
  compressed response
  multi-record response
```

# Security properties to formally specify

Before coding, write these as protocol claims:

1. **Server provenance**  
   Any disclosed response byte is bound to an authenticated TLS 1.3 session with the named server.

2. **Response unforgeability**  
   A malicious prover cannot produce an accepted proof for response plaintext not authenticated under the server traffic key.

3. **Request binding**  
   The proof binds the response to the exact committed request stream.

4. **Verifier privacy**  
   The verifier learns no hidden application plaintext beyond lengths, permitted metadata, and disclosed fields.

5. **Prover privacy against aborts**  
   Selective aborts and malformed garbled circuits do not expose hidden plaintext or complete traffic secrets.

6. **Downgrade resistance**  
   A proof explicitly identifies TLS 1.3 and the negotiated suite; it cannot be interpreted as a TLS 1.2 proof or vice versa.

7. **Record-order integrity**  
   Reordering, duplication, omission, and cross-epoch substitution are detected.

DECO established that TLS provenance and selective proof techniques can be extended to TLS 1.3 in principle, but TLSNotary still needs an implementation-specific design matching its current two-party MPC, transcript commitment, extension, and verifier architecture.  [oai_citation:5‡arXiv](https://arxiv.org/abs/1909.00938?utm_source=chatgpt.com)

# Most important architectural decision

The best design is:

```text
Public TLS 1.3 state machine
        +
secret-shared traffic secrets
        +
MPC only for operations touching those secrets
        +
authenticated release of handshake plaintext
        +
committed application plaintext
```

Do **not** implement the entire TLS parser inside a giant MPC circuit. That would be slow, difficult to audit, and unnecessary. Use MPC narrowly for:

- distributed ECDHE;
- HKDF/HMAC over secret material;
- AEAD encrypt/decrypt and tag verification;
- commitment generation where needed.

Everything else should remain ordinary Rust with strict transcript binding.

The first production target should be **full-handshake X25519 + TLS_AES_128_GCM_SHA256 + HTTP/1.1**, with PSK, 0-RTT, KeyUpdate, HTTP/2, and QUIC explicitly rejected. That is a defensible, interoperable TLS 1.3 foundation rather than a partial implementation that accidentally accepts protocol branches it cannot securely notarize.

# TLS 1.3 MPC-TLS backend — assessment & research plan

**Status:** M1 delivered · M2 next · **Audience:** MPC-TLS engineer picking this up
**Companion:** [`tls13-mpc-tls-backend.proposal.md`](./tls13-mpc-tls-backend.proposal.md) — the original design brief.

---

## 0. Provenance & what this document is

The companion proposal is an **AI-generated design brief** (note its `[oai_citation:…]` markers). It is a
genuinely good starting point, but its crate/primitive names are *aspirational* and do not match this
repository. **This document is an engineering assessment of that brief plus a plan reconciled with the
actual `advatar/tlsn` + `mpz` code**, so the work can start against real modules rather than a sketch.

### Baseline already shipped (do not regress)

- **Real TLS 1.2 notarization works today.** The prover pins the *offered* TLS version to 1.2
  (`crates/tlsn/src/prover.rs`, `with_protocol_versions(&[&tls_client::version::TLS12])`), which makes
  dual-stack servers negotiate 1.2 so the existing MPC-TLS engine can split keys. A deployed notary
  gateway (`crates/browser-demo`) signs a portable `SignedArtifact` (`crates/notary-artifact`).
- **Hybrid post-quantum *attestation*** (ES256 + ML-DSA-65 over the same payload) is implemented in
  `crates/notary-artifact` behind the `pq-sign` feature. **This is orthogonal to the work below** — it
  is a property of the notary's *signature*, not of the TLS transport. TLS 1.3 work neither needs it nor
  changes it.

The 1.2 path is the fallback the 1.3 backend must not break. The hard-coded 1.2 pin should eventually
become a per-`ProverConfig` option once 1.3 is real.

---

## 1. Verdict on the brief

**Agree with the thesis and the core architecture.** In particular these calls are correct and are the
ones I would make:

- **A separate 1.3 state machine, not an incremental patch of the 1.2 path.** 1.3's encrypted handshake,
  HKDF key schedule, and record protection differ enough that the current half-patched attempt is exactly
  the trap to avoid (see §2).
- **"MPC only for operations touching secret-shared traffic secrets; authenticated *release* of handshake
  plaintext for public parsing / certificate validation."** This is the crux and it is right: 1.3
  handshake messages (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`) carry no
  user-private data, so MPC is needed only for the AEAD auth + key schedule, never the whole parser.
- **The client ECDHE scalar must be jointly generated / kept from the prover.** Subtle and important: if
  the prover knows `x` and the server share `Y` is public, the prover alone computes `Z = x·Y` and can
  forge "server" responses, breaking the entire provenance guarantee.
- **Narrow v1 profile** (1-RTT, server-auth only, no PSK/0-RTT/resumption, reject `KeyUpdate`/HRR) and a
  **version-specific, downgrade-resistant proof object.** Both sound; the downgrade point mirrors the
  downgrade-closed discipline already used in the hybrid-PQ attestation.

**Caveats / where the brief is optimistic:**

1. **Effort is understated.** This is a multi-month, research-grade effort ending in a **cryptographic
   audit** — not an incremental feature.
2. **The two-party X25519 is the real lift**, and the brief's "start with a generic Boolean circuit"
   reference path is likely *impractically* slow (a 255-bit Montgomery ladder as a garbled Boolean circuit
   is enormous, and worse in browser WASM). Prefer curve/field arithmetic over `mpz-fields` + `mpz-ole`.
3. **The proposed `mpz-hkdf` / `mpz-hmac` / `mpz-x25519` / `mpz-aead` crates do not exist.** They must be
   *built on* the existing `mpz-*` toolbox (see §3). Treat the brief's crate tree as illustration only.
4. **Classical KEM only.** The brief's key exchange is X25519/P-256; it does not address PQ TLS transport
   (e.g. `X25519MLKEM768`). That is a separate future topic and independent of our hybrid-PQ *attestation*.

---

## 2. Current TLS 1.3 state in this fork (what actually needs fixing)

There is already a partial, **non-functional** 1.3 path. The rewrite should replace it, not extend it.

- `crates/mpc-tls/src/tls13.rs` — incremental 1.3 leader/follower code. The **follower never receives the
  server handshake records** (the leader captures them but does not relay; the follower's
  `tls13_recv_records` is empty), so…
- `crates/core/src/transcript/tls.rs` — `validate_tls13_finished` always errors
  **"server finished was not observed in the transcript."** This is the concrete symptom.
- `crates/tlsn/tests/tls13_matrix.rs`, `crates/tlsn/tests/tls13_interop.rs` — fixtures/tests exist but do
  not exercise a working path.

> Diagnosis (2026-08): the leader parses the coalesced 1.3 server flight fine (a separate one-line
> coalescing bug in the validator was found and reverted); the blocker is that the **follower scans zero
> records**. A clean leader↔follower record-relay + state machine is the fix, which is why a fresh backend
> is the right call.

---

## 3. Reconciliation — where each piece lands in THIS repo

| Brief's proposal | Reality in `advatar/tlsn` + `mpz` |
|---|---|
| new `tlsn-tls-core/tls13/` engine | extend **`crates/mpc-tls`** (`leader.rs`, `follower.rs`, `record_layer/`, a **new** `tls13/` state machine replacing today's `tls13.rs`) + the TLS types in **`crates/tls/{core,client}`** |
| `mpz-hkdf`, `mpz-hmac` | build `MpcHkdf`/`MpcHmac` on **`mpz-garble(-core)`** + **`mpz-circuits`** (SHA-256 circuit) + **`mpz-share-conversion`**; transcript hashes are public once messages are authenticated, so hashing is mostly *not* in MPC |
| `mpz-aead` (AES-GCM / ChaCha20-Poly1305) | the 1.2 path already does joint AES-GCM in `crates/mpc-tls`; reuse/generalize it via **`mpz-garble`** + **`mpz-circuits`** rather than a new crate |
| `mpz-x25519` distributed ECDH | **`mpz-fields`** + **`mpz-ole`** (oblivious linear evaluation) + **`mpz-ot`** — a field/OLE-based two-party scalar-mult, **not** a Boolean garbled ladder |
| `Tls13SessionConfig` / `config_hash` binding | new config type in `crates/mpc-tls` + bind into the proof; verifier nonce already has an analogue in the session flow |
| `Tls13SessionProof` version-specific proof | extend **`crates/core/src/transcript/`** (`proof.rs`, `commit.rs`) and the portable **`crates/notary-artifact`** `SignedArtifact` — reuse its existing versioning + downgrade-closed discipline; **do not** overload the 1.2 proof with optional 1.3 fields |
| verifier server-auth (X.509 + `CertificateVerify` + `Finished`) | **`crates/verifier`** / `crates/tlsn` verifier side + `crates/tls/core` cert validation — Model A (public validation after authenticated release) is the MVP |

### Proposed architecture (the one call that matters)

```mermaid
flowchart TB
    subgraph Public["Public Rust — no secrets (crates/mpc-tls tls13 state machine, crates/tls)"]
      SM["typestate 1.3 state machine<br/>ClientHello → ServerHello → …→ Connected"]
      PARSE["parse handshake · X.509 chain ·<br/>hostname · CertificateVerify · transcript hash"]
    end
    subgraph MPC["MPC islands — touch secret-shared material only (mpz-*)"]
      ECDHE["distributed X25519<br/>mpz-fields + mpz-ole + mpz-ot"]
      KS["MPC HKDF / HMAC key schedule<br/>mpz-garble + mpz-circuits"]
      AEAD["joint AES-GCM auth+decrypt / encrypt<br/>mpz-garble (as in the 1.2 path)"]
    end
    subgraph Proof["Evidence (crates/core/transcript + crates/notary-artifact)"]
      TX["transport + application transcript"]
      P["version-specific Tls13 proof<br/>downgrade-resistant"]
    end
    SM --> ECDHE --> KS --> AEAD
    AEAD -->|"release plaintext ONLY after GCM tag verified"| PARSE
    PARSE --> SM
    AEAD --> TX --> P
```

The invariant throughout: **neither prover nor verifier ever holds the complete server application traffic
key** (`server_application_traffic_secret` stays secret-shared). MPC is used narrowly for ECDHE, the
HKDF/HMAC over secret material, and AEAD; everything else is ordinary Rust with strict transcript binding.

---

## 4. Milestones (reconciled with the codebase)

Adapted from the brief's M1–M6, pointed at real modules.

1. **M1 — non-MPC 1.3 reference engine (the oracle). ✅ Delivered:
   [`crates/tls/tls13-reference`](../../crates/tls/tls13-reference).** Single-party key schedule,
   transcript, traffic keys, `Finished` and record layer for the narrow profile, with per-step tracing.
   43 tests, validated on two independent vector sets:
   - the full **RFC 8448 §3** handshake trace — key schedule, traffic keys, both `Finished` MACs, and
     every protected record decrypted *and* re-encrypted byte-for-byte. Vectors are **generated** from
     the RFC text by `tools/gen_rfc8448_vectors.py`, not transcribed, and every field is length-checked
     against the `(N octets)` count the RFC prints beside it;
   - **`draft-ietf-tls-tls13-vectors-06`** — the same fixtures `crates/components/hmac-sha256`'s MPC key
     schedule already passes, so oracle and MPC are confirmed to agree on inputs neither derived from the
     other.

   Two deliberate choices worth knowing before building on it. `info` (the serialized `HkdfLabel`) is
   asserted alongside every output, so a label-encoding bug — the most common TLS 1.3 key-schedule error,
   and exactly what MPC's `make_hkdf_label` must match — is localised rather than surfacing as a wrong
   key. And transcript hashes are **recomputed from the handshake messages** in the trace rather than
   read from the RFC's `hash` fields, so the *transcript positions* are pinned too, not just the
   arithmetic.

   Scope note: this is the key schedule and record layer, not a networked client. It takes the ECDHE
   shared secret as an input — the same value MPC holds secret-shared as `pms`, which is the right
   oracle/MPC boundary — and deliberately does **not** implement X25519 (see M3). Certificate validation
   and socket handling are absent by design; `crates/tls/client` already has those.
2. **M2 — MPC key schedule + record layer.** `MpcHkdf`, `MpcHmac`, AEAD, sequence-derived nonces,
   authenticated-release semantics — on `mpz-garble`/`mpz-circuits`/`mpz-share-conversion`, validated on
   RFC vectors with fixed secrets before ECDHE.
3. **M3 — distributed X25519 (the crux).** Shared client-scalar generation + shared-secret compute on
   `mpz-fields` + `mpz-ole`. Tests: neither party alone derives `Z`; valid public key; low-order/invalid
   point rejection; matches a reference X25519; aborts leak no reusable scalar share.
   A known-answer test is ready: the RFC 8448 client and server X25519 key pairs are retained as
   `CLIENT_X25519` / `SERVER_X25519` in M1's generated vectors, and their shared secret is the
   `HANDSHAKE_EXTRACT.ikm` the oracle already consumes. Note X25519 is **not** in the workspace dependency
   set today, so M3 adds it.
4. **M4 — full handshake** in `crates/mpc-tls` (new `tls13/`): ClientHello/ServerHello, encrypted server
   flight with authenticated release, X.509 + `CertificateVerify` + `Finished`, transition to app keys.
   Retire `crates/mpc-tls/src/tls13.rs`; make `crates/tlsn/tests/tls13_{matrix,interop}.rs` pass for real.
5. **M5 — proof integration.** Version-specific 1.3 proof in `crates/core/transcript` +
   `crates/notary-artifact`; transcript commitments; selective disclosure; verifier signature; WASM
   (`crates/wasm`) + iOS (`crates/ios`) bindings. Keep the 1.2 proof path intact.
6. **M6 — production hardening + audit.** Malformed-handshake fuzzing, cross-implementation interop
   (nginx/Apache/rustls/BoringSSL/Cloudflare/AWS), malicious-prover and malicious-verifier tests,
   zeroization, resource limits, and an external cryptographic review.

---

## 5. Security properties to formalize

The fork already carries a formal-methods discipline (Lean/Tamarin) used for the issuer and for the
hybrid-PQ attestation. Specify these as protocol claims **before** coding (per the brief's list):
server provenance · response unforgeability · request binding · verifier privacy · prover privacy against
aborts · **downgrade resistance** (a proof is unambiguously 1.3 and cannot be read as 1.2, or vice versa —
same discipline as the hybrid-PQ downgrade-closed proofs) · record-order integrity.

---

## 6. Effort & risk (honest)

Multi-month, research-grade. The dominant costs and risks:

- **Two-party X25519** at the right security level is the single biggest new asymmetric-MPC component and
  the main audit surface.
- **Browser-WASM performance** (`crates/wasm`) is a real constraint — favour field/OLE arithmetic over
  large Boolean circuits.
- **Malicious-security model**: the concrete `mpz` protocols (semi-honest vs authenticated/malicious) drive
  both correctness and the audit; do not assume the `MpcHkdf`/`MpcAead` traits are the hard part — the
  concrete protocols behind them are.
- Ends in an **external cryptographic review** before any production use.

Because this is core TLSNotary infrastructure (not application-specific), it is a strong candidate to
develop in the open and potentially contribute upstream, rather than living only in this fork.

---

## 7. TL;DR for the picker-upper

**M1 is done** — [`crates/tls/tls13-reference`](../../crates/tls/tls13-reference) is the oracle; read its
README first, it documents how to diff MPC output against it and what `trace().render()` gives you.

Next is **M2** (MPC key schedule/record on the existing `mpz` toolbox), then **M3** (distributed X25519 —
the crux). M2 is now a comparison task rather than an interpretation task: the oracle's `HandshakeKeys` /
`ApplicationKeys` mirror the `tlsn_hmac_sha256` field names, and `mpc_parity.rs` already shows the two
implementations agreeing on the existing fixtures, so new MPC work can be asserted directly against the
oracle instead of against hand-copied vectors.

Beyond that: replace `crates/mpc-tls/src/tls13.rs` with a clean typestate machine; add a
**version-specific** 1.3 proof next to `crates/notary-artifact` rather than overloading the 1.2 one; keep
the shipped 1.2 path working throughout. The design brief in the companion file is sound on architecture;
treat its crate/primitive names as illustrative and map them to the table in §3.

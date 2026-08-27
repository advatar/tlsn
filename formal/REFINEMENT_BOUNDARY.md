# Concrete refinement boundary

The formal theories and the Rust implementation intentionally meet at a
documented boundary. This table prevents a symbolic theorem from being read as
a whole-program theorem.

| Symbolic term/property | Concrete implementation evidence | Remaining refinement obligation |
| --- | --- | --- |
| `hkdf_extract(salt, ikm)` | `crates/components/hmac-sha256/src/kdf/extract.rs` and its MPC tests | Prove the two-party circuit computes the same byte function for every allowed input and preserves secrecy |
| `hkdf_expand_label(secret, label, context)` | RFC-byte Kani harnesses, Lean framing proof, negotiated transcript validation, MPC/reference tests | Whole-program secrecy/noninterference of the MPC execution |
| `finished_mac(finished_key, transcript_hash)` | Exact Rust transcript retention, independent leader/follower digest recomputation, typed Finished callbacks | X.509/parser correctness beyond the callback boundary |
| `ApplicationSecretInstalled` after Finished | Typed Rust state transition, unified Tamarin provenance theorem, integration tests | Whole-program control-flow refinement including crashes/concurrency |
| Secret `traffic_secret` and application keys | MPZ VM references and secret-shared key allocation | Prove noninterference/no-clear decode over all reachable execution traces |
| `encrypt_handshake`/record AEAD abstraction | Joint AES-GCM/GHASH tests, authenticated-release capsule tests, retained exact inner-plaintext VM references, and interop matrix | Prove malicious security and noninterference of the complete MPZ/capsule execution |
| `Released(..., plaintext)` consumed by attestation | Joint decryption constructs `ciphertext XOR keystream` as a VM reference only after tag verification; TLS 1.3 reveal/hash commitments consume that translated reference and verify the content-type/padding suffix; mutation and signed-presentation tests cover the concrete handoff | Machine-check the whole Rust control-flow refinement rather than the tested release-to-commit seam alone |
| Presented disclosure projection | Session-bound `RecordId`, exact authenticated-plaintext references, concrete commitments/capsules, signed TLS 1.3 presentation test, unified Tamarin theorem, bounded diff model | Full malicious-verifier privacy and production serialization noninterference |

The evidence is deliberately layered: Tamarin proves symbolic transition
properties and end-to-end provenance; Lean proves structural invariants; Kani
proves concrete Rust width, nonce, HKDF-label, SHA-384 primitive, and
compression-refinement properties; Rust tests and interop exercise joint MPC
executions. This is not a proof of malicious security for the complete MPZ
runtime, X.509 stack, serialization, scheduler, or operating environment.

The release-to-commit regression is intentionally equality-sensitive. It keeps
the authenticated TLS inner plaintext as a VM output, translates that output
into the post-MPC proof VM, and makes both selective reveal and hash commitment
use the translated reference. A verifier also decodes and checks the claimed
content-type/padding suffix, so a prover cannot change the application-data
boundary while retaining an authenticated prefix. The adversarial test replaces
a same-length received record payload and requires the exact-reference check to
fail; the fixture-backed attestation test then signs those commitments and
verifies a complete TLS 1.3 presentation with an independent provider.

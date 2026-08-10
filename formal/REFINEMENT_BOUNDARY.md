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
| `encrypt_handshake`/record AEAD abstraction | Joint AES-GCM/GHASH tests and interop matrix | Prove concrete circuit semantics and capsule composition match the abstract authenticated-release model |
| Presented disclosure projection | Session-bound `RecordId`, concrete commitments/capsules, unified Tamarin theorem, bounded diff model | Full malicious-verifier privacy and production serialization noninterference |

The evidence is deliberately layered: Tamarin proves symbolic transition
properties and end-to-end provenance; Lean proves structural invariants; Kani
proves concrete Rust width, nonce, HKDF-label, SHA-384 primitive, and
compression-refinement properties; Rust tests and interop exercise joint MPC
executions. This is not a proof of malicious security for the complete MPZ
runtime, X.509 stack, serialization, scheduler, or operating environment.

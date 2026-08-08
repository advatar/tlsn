# Concrete refinement boundary

The formal theories and the Rust implementation intentionally meet at a
documented boundary. This table prevents a symbolic theorem from being read as
a whole-program theorem.

| Symbolic term/property | Concrete implementation evidence | Remaining refinement obligation |
| --- | --- | --- |
| `hkdf_extract(salt, ikm)` | `crates/components/hmac-sha256/src/kdf/extract.rs` and its MPC tests | Prove the two-party circuit computes the same byte function for every allowed input and preserves secrecy |
| `hkdf_expand_label(secret, label, context)` | `kdf/expand.rs`, `kdf/expand/label.rs`, RFC-derived vectors | Prove label encoding bounds, transcript-context wiring, and circuit/reference equivalence compositionally |
| `finished_mac(finished_key, transcript_hash)` | TLS 1.3 handshake functionality and HMAC tests | Prove parser state and Finished acceptance implement the symbolic event ordering |
| `ApplicationSecretInstalled` after Finished | `mpc-tls` handshake/application transition tests | Prove no alternate Rust state transition can install application traffic keys |
| Secret `traffic_secret` and application keys | MPZ VM references and secret-shared key allocation | Prove noninterference/no-clear decode over all reachable execution traces |
| `encrypt_handshake`/record AEAD abstraction | Joint AES-GCM/GHASH tests and interop matrix | Prove concrete circuit semantics and capsule composition match the abstract authenticated-release model |
| Presented disclosure projection | Existing disclosure/attestation APIs and minimal Tamarin diff model | Define the production leakage function and prove serialization/refinement equivalence |

The existing evidence is deliberately mixed: Tamarin proves properties of the
symbolic transition systems; Lean and Kani prove local state/nonce facts; Rust
tests check selected reference vectors and executions. A future end-to-end
refinement proof must connect these layers without adding an unstated trusted
assumption.

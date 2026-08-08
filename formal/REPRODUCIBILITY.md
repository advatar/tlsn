# TLS 1.3 verification reproducibility record

This record describes the checks used for the research branch. Commands are
run from the repository root and are intentionally serial.

| Layer | Command | Expected evidence |
| --- | --- | --- |
| Symbolic record, handshake, selective disclosure, key schedule | `./formal/verify.sh` | 5 + 5 + 1 + 4 verified Tamarin results; Lean and Kani pass |
| HKDF reference vectors and MPC HMAC | `cargo test -p tlsn-hmac-sha256 --quiet` | 22 tests pass, including TLS 1.3 `c hs traffic`, `s hs traffic`, and `c ap traffic` vectors |
| Record/reference equivalence | `cargo test -p tlsn-mpc-tls --quiet` | 31 tests pass |
| TLS configuration | `cargo test -p tlsn-core config::tls::tests --quiet` | 3 tests pass |
| End-to-end TLS 1.3 | `cargo test -p tlsn --test test test_tls13 -- --test-threads=1` | Focused fixture passes |
| Interoperability | `./formal/interop.sh` | nginx RSA/ECDSA, Apache RSA, Caddy RSA, OpenSSL `s_server` pass |
| Manuscript | `./paper/build.sh` | HTML and LaTeX render with bibliography resolution |

The symbolic theories deliberately abstract cryptographic primitives and the
production parser/circuit implementation. Passing this record therefore
establishes reproducibility of the stated evidence, not a whole-program
security theorem.

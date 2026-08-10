# TLS 1.3 verification reproducibility record

This record describes the checks used for the research branch. Commands are
run from the repository root and are intentionally serial.

| Layer | Command | Expected evidence |
| --- | --- | --- |
| Symbolic record, handshake, selective disclosure, key schedule, AES-256, composition | `./formal/verify.sh` | 5 + 5 + 1 + 5 + 3 + 4 verified Tamarin results; Lean passes; Kani proves concrete epoch, label, suite, transcript-width, SHA-384 primitive, and compression obligations |
| HKDF reference vectors and MPC HMAC | `cargo test -p tlsn-hmac-sha256 --quiet` | 36 tests pass, including 12 focused SHA-384/reference tests |
| Record/reference equivalence | `cargo test -p tlsn-mpc-tls --quiet` | 36 tests pass |
| TLS configuration | `cargo test -p tlsn-core config::tls::tests --quiet` | 3 tests pass |
| End-to-end TLS 1.3 | `cargo test --release -p tlsn --test test test_tls13 -- --test-threads=1` | Focused fixture passes |
| Interoperability | `./formal/interop.sh` | nginx RSA/ECDSA, Apache RSA, Caddy RSA, OpenSSL `s_server` pass |
| Manuscript | `./paper/build.sh` | HTML and LaTeX render with bibliography resolution |

The TLS 1.3 key-schedule benchmark is run with
`cargo bench -p tlsn-hmac-sha256 --bench tls13 -- --noplot`. The reference run
used arm64 Mac17,6, 18 logical CPUs, and Rust 1.97.1; it reported approximately
20.824 ms for `tls13_normal` and 15.646 ms for `tls13_reduced` (Criterion, 10
samples per mode). Benchmark numbers are machine-dependent.

The symbolic theories deliberately abstract cryptographic primitives and the
production parser/circuit implementation. Passing this record therefore
establishes reproducibility of the stated evidence, not a whole-program
security theorem.

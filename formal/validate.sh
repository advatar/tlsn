#!/usr/bin/env bash
set -euo pipefail

# Keep this serial: the fixture uses shared build and test resources.
cargo test -p tlsn-mpc-tls --quiet
cargo test -p tlsn-hmac-sha256 --quiet
cargo test -p tlsn-core config::tls::tests --quiet
cargo check -p tlsn --tests
cargo test -p tlsn --lib mutated_tls13_recv_record_cannot_replace_authenticated_plaintext --quiet
cargo test --release -p tlsn --test test test_tls13 -- --test-threads=1
cargo test --release -p tlsn --test tls13_attestation -- --test-threads=1

printf 'MPC/reference, key-schedule, release-to-commit, fixture, and TLS 1.3 attestation validation passed\n'

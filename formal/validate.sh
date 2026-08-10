#!/usr/bin/env bash
set -euo pipefail

# Keep this serial: the fixture uses shared build and test resources.
cargo test -p tlsn-mpc-tls --quiet
cargo test -p tlsn-hmac-sha256 --quiet
cargo test -p tlsn-core config::tls::tests --quiet
cargo check -p tlsn --tests
cargo test --release -p tlsn --test test test_tls13 -- --test-threads=1

printf 'MPC/reference, key-schedule, compile, and TLS 1.3 fixture validation passed\n'

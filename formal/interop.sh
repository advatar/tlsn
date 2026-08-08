#!/usr/bin/env bash
set -euo pipefail

# Runs the five Docker-backed TLS 1.3 cases serially and cleans the compose
# stack on exit. The underlying harness enables the explicit test gates.
./crates/tlsn/tests/interop/run.sh

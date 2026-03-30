#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../../../.." && pwd)

cleanup() {
  docker compose -f "$SCRIPT_DIR/docker-compose.yml" down -v >/dev/null 2>&1 || true
}

trap cleanup EXIT

docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build
sleep 5

cd "$REPO_ROOT"
TLSN_RUN_DOCKER_INTEROP=1 cargo test -p tlsn --test tls13_interop -- --ignored tls13_interop_nginx_rsa
TLSN_RUN_DOCKER_INTEROP=1 cargo test -p tlsn --test tls13_interop -- --ignored tls13_interop_nginx_ecdsa
TLSN_RUN_DOCKER_INTEROP=1 cargo test -p tlsn --test tls13_interop -- --ignored tls13_interop_apache_rsa

if [[ "${TLSN_RUN_CADDY_INTEROP:-}" == "1" ]]; then
  TLSN_RUN_DOCKER_INTEROP=1 TLSN_RUN_CADDY_INTEROP=1 \
    cargo test -p tlsn --test tls13_interop -- --ignored tls13_interop_caddy_rsa
fi

if [[ "${TLSN_RUN_OPENSSL_SSERVER:-}" == "1" ]]; then
  TLSN_RUN_DOCKER_INTEROP=1 TLSN_RUN_OPENSSL_SSERVER=1 \
    cargo test -p tlsn --test tls13_interop -- --ignored tls13_interop_openssl_rsa
fi

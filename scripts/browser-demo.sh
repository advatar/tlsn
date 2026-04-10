#!/bin/sh

set -eu

DEMO_ALLOW_HOSTS="${DEMO_ALLOW_HOSTS:-example.com www.google.com}"
DEMO_ALLOW_PORTS="${DEMO_ALLOW_PORTS:-443}"
DEMO_SKIP_WASM_BUILD="${DEMO_SKIP_WASM_BUILD:-0}"

if [ "$DEMO_SKIP_WASM_BUILD" != "1" ]; then
    ./crates/wasm/build.sh
fi

set -- cargo run -p tlsn-browser-demo -- "$@"

for host in $DEMO_ALLOW_HOSTS; do
    set -- "$@" --allow-host "$host"
done

for port in $DEMO_ALLOW_PORTS; do
    set -- "$@" --allow-port "$port"
done

exec "$@"

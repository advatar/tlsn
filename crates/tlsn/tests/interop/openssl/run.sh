#!/bin/sh
set -eu

log=/tmp/openssl-s-server.log
openssl s_server \
  -accept 443 \
  -WWW \
  -tls1_3 \
  -cert /certs/rsa/end.cert \
  -key /certs/rsa/end.key \
  -cert_chain /certs/rsa/end.chain >"$log" 2>&1 &
server_pid=$!

tail -f "$log" &
tail_pid=$!

while kill -0 "$server_pid" 2>/dev/null; do
  if grep -q '^FILE:index.html$' "$log"; then
    # OpenSSL's -WWW mode leaves the connection open after the response. End
    # this single-shot fixture server so the client observes the response EOF.
    sleep 1
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    kill "$tail_pid" 2>/dev/null || true
    exit 0
  fi
  sleep 0.1
done

kill "$tail_pid" 2>/dev/null || true
wait "$server_pid"

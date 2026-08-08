# TLS 1.3 Interop Harness

This directory contains the Docker-backed TLS 1.3 interop harness for `tlsn`.

## Stable default matrix

The default runner exercises the cases that currently pass end to end in the
repo's supported TLS 1.3 scope:

- nginx with RSA certificate
- nginx with ECDSA certificate
- Apache httpd with RSA certificate
- Caddy with RSA certificate
- raw OpenSSL `s_server` with RSA certificate

Run it from the repo root with:

```bash
./crates/tlsn/tests/interop/run.sh
```

The OpenSSL fixture serves a small file and exits after the response because
`s_server -WWW` otherwise keeps the socket open indefinitely.

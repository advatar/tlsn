# TLS 1.3 Interop Harness

This directory contains the Docker-backed TLS 1.3 interop harness for `tlsn`.

## Stable default matrix

The default runner exercises the cases that currently pass end to end in the
repo's supported TLS 1.3 scope:

- nginx with RSA certificate
- nginx with ECDSA certificate
- Apache httpd with RSA certificate

Run it from the repo root with:

```bash
./crates/tlsn/tests/interop/run.sh
```

## Optional cases

Two additional harnesses are present but are not enabled by default:

- Caddy: `TLSN_RUN_CADDY_INTEROP=1 ./crates/tlsn/tests/interop/run.sh`
- raw OpenSSL `s_server`: `TLSN_RUN_OPENSSL_SSERVER=1 ./crates/tlsn/tests/interop/run.sh`

Those are useful for surfacing EOF and close-path compatibility issues, but they
are not part of the default green bar yet.

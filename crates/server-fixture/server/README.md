# tlsn-server-fixture

Inspired by `httpbin.org`.

# Quickstart

```bash
cargo run --release
```

## Setting the port

Set the enviroment variable `PORT` to configured the port the server runs on.

```bash
PORT=3001 cargo run --release
```

## TLS profiles

The fixture can be started with different TLS certificate and client-auth
profiles:

```bash
TLSN_SERVER_CERT_PROFILE=rsa TLSN_SERVER_CLIENT_AUTH=none cargo run --release
```

Supported values:

- `TLSN_SERVER_CERT_PROFILE`: `default`, `rsa`, `ecdsa`
- `TLSN_SERVER_CLIENT_AUTH`: `none`, `optional`, `required`
- `TLSN_SERVER_ALPN`: comma-separated ALPN list such as `http/1.1,h2`

## Logging

Enable server logs by setting the log level:

```bash
RUST_LOG=info cargo run --release
```

## Testing

You can test the server works using curl:

```bash
curl https://0.0.0.0:3000/formats/html --insecure
```

Notice the `--insecure` flag, which will ignore that the server presents a self-signed cert.

# Formats

## JSON

The `/json` endpoint provides JSON data fixtures. You can pass the `size` query parameter to select between the 3 available payload sizes which are 1Kb, 4Kb, 8Kb.

```bash
curl https://0.0.0.0:3000/formats/json?size=4 --insecure
```

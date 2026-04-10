# Browser Demo

This crate hosts a browser-first TLSNotary demo:

- a static single-page app
- a local notary service that runs the verifier role
- a WebSocket TCP bridge that forwards raw TLS bytes to the target origin

## Build the WASM package

From the repository root:

```bash
./crates/wasm/build.sh
```

That produces the browser package in `crates/wasm/pkg/`.

## Run the demo server

For public HTTPS targets on port 443:

```bash
cargo run -p tlsn-browser-demo -- \
  --allow-host example.com \
  --allow-host .example.com
```

Shortcuts:

```bash
make browser-demo
npm run demo
```

Both shortcuts build `tlsn-wasm` first, then start the server with default allowlist entries for `example.com` and `www.google.com`.

For local testing against loopback or private addresses, opt in explicitly:

```bash
cargo run -p tlsn-browser-demo -- \
  --allow-host localhost \
  --allow-port 4000 \
  --allow-loopback \
  --allow-private-ips
```

Then open <http://127.0.0.1:3000>.

Local shortcuts:

```bash
make browser-demo-local
npm run demo:local
```

Help / command wiring check:

```bash
make browser-demo-help
npm run demo:help
```

## Notes

- The browser app currently supports `https://` GET requests.
- The demo uses `tlsn-wasm` in the browser and `tlsn-sdk-core::SdkVerifier` on the server.
- The TCP bridge uses a conservative destination policy. Production deployments should keep the host and port allowlist tight.

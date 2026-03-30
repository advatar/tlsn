<p align="center">
    <img src="./tlsn-banner.png" width=1280 />
</p>

![MIT licensed][mit-badge]
![Apache licensed][apache-badge]
[![Build Status][actions-badge]][actions-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache-badge]: https://img.shields.io/github/license/saltstack/salt
[actions-badge]: https://github.com/tlsnotary/tlsn/actions/workflows/ci.yml/badge.svg?branch=main
[actions-url]: https://github.com/tlsnotary/tlsn/actions?query=workflow%3Aci+branch%3Amain

[Website](https://tlsnotary.org) |
[Documentation](https://tlsnotary.org/docs/intro) |
[API Docs](https://tlsnotary.github.io/tlsn) |
[Discord](https://discord.gg/9XwESXtcN7)

# TLSNotary

**Data provenance and privacy with secure multi-party computation**

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes.

## License
All crates in this repository are licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Versions

For evaluation, we recommend using [tagged releases](https://github.com/tlsnotary/tlsn/releases) rather than the latest `main` branch, as the project is under active development.

## Fork Contribution Scope

This fork currently carries a TLS 1.3 workstream on top of upstream
[`tlsnotary/tlsn`](https://github.com/tlsnotary/tlsn) `main`. Relative to
upstream `main` at `15a7c55`, the contributions in this checkout are:

- TLS 1.3 HKDF and key-schedule groundwork in `crates/components/hmac-sha256`
  while preserving the existing TLS 1.2-facing API used elsewhere in the
  workspace.
- TLS 1.3 shared-secret and scope helpers in
  `crates/components/key-exchange`.
- TLS 1.3 epoch/key tracking, Finished handling, traffic-secret transitions,
  and record protection in `crates/mpc-tls`.
- End-to-end TLS 1.3 prove/verify plumbing, transcript export, and TLS 1.3
  certificate binding across `crates/tlsn`, `crates/core`, and
  `crates/tls/client`.
- Local TLS 1.3 fixture coverage plus a Docker-backed interop harness for
  `nginx` and `Apache`, with opt-in `Caddy` and `openssl s_server` cases.

The current TLS 1.3 scope in this fork is intentionally narrow:

- Full 1-RTT handshakes only.
- `TLS_AES_128_GCM_SHA256` only.
- P-256 key share path.
- No PSK, resumption, 0-RTT, or key update support.
- Local and focused interop coverage exists, but broad "works in the wild"
  claims still require a wider real-server compatibility sweep.

See [STATUS.md](./STATUS.md) for the completed checklist and [CR-001.md](./CR-001.md)
for the original implementation plan.

## Directory

- [examples](./crates/examples/): Examples on how to use the TLSNotary protocol.
- [tlsn](./crates/tlsn/): The TLSNotary library.

This repository contains the source code for the Rust implementation of the TLSNotary protocol. For additional tools and implementations related to TLSNotary, visit <https://github.com/tlsnotary>. This includes repositories such as [`tlsn-extension`](https://github.com/tlsnotary/tlsn-extension), among others.


## Development

> [!IMPORTANT]
> **Note on Rust-to-WASM Compilation**: This project requires compiling Rust into WASM, which needs [`clang`](https://clang.llvm.org/) version 16.0.0 or newer. MacOS users, be aware that Xcode's default `clang` might be older. If you encounter the error `No available targets are compatible with triple "wasm32-unknown-unknown"`, it's likely due to an outdated `clang`. Updating `clang` to a newer version should resolve this issue.
> 
> For MacOS aarch64 users, if Apple's default `clang` isn't working, try installing `llvm` via Homebrew (`brew install llvm`). You can then prioritize the Homebrew `clang` over the default macOS version by modifying your `PATH`. Add the following line to your shell configuration file (e.g., `.bashrc`, `.zshrc`):
> ```sh
> export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
> ```

If you run into this error:
```
Could not find directory of OpenSSL installation, and this `-sys` crate cannot
  proceed without this knowledge. If OpenSSL is installed and this crate had
  trouble finding it,  you can set the `OPENSSL_DIR` environment variable for the
  compilation process.
```
Make sure you have the development packages of OpenSSL installed (`libssl-dev` on Ubuntu or `openssl-devel` on Fedora).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md).

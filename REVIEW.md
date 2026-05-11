# Code Review: tlsn

Review date: 2026-05-11
Tracker: https://github.com/advatar/Tracker/issues/53
Scope: top-level app folder `tlsn` and nested project manifests under this folder, excluding generated dependency/build directories such as `.git`, `node_modules`, `target`, `.build`, `dist`, and virtual environments.

## Executive Summary

- Overall risk from this sweep: **High**
- Findings by severity: High 2, Medium 3, Low 1
- Source footprint: 295 source files by extension scan (Rust 275, Shell 10, JavaScript 4, HTML 4, Python 1, CSS 1)
- Test footprint: 21 test-like files detected
- CI footprint: 7 GitHub Actions workflow files detected
- Git posture: clean before review generation
- Pattern scan budget used: 364 text/source files scanned

## Architecture Snapshot

Detected project and build surfaces:
- `Cargo.toml`
- `crates/attestation/Cargo.toml`
- `crates/browser-demo/Cargo.toml`
- `crates/components/cipher/Cargo.toml`
- `crates/components/deap/Cargo.toml`
- `crates/components/hmac-sha256/Cargo.toml`
- `crates/components/key-exchange/Cargo.toml`
- `crates/core/Cargo.toml`
- `crates/data-fixtures/Cargo.toml`
- `crates/examples/Cargo.toml`
- `crates/formats/Cargo.toml`
- `crates/harness/core/Cargo.toml`
- `crates/harness/executor/Cargo.toml`
- `crates/harness/plot/Cargo.toml`
- `crates/harness/runner/Cargo.toml`
- `crates/mpc-tls/Cargo.toml`
- `crates/sdk-core/Cargo.toml`
- `crates/server-fixture/certs/Cargo.toml`
- `crates/server-fixture/server/Cargo.toml`
- `crates/tls/client/Cargo.toml`

Nested manifest owners sampled:
- `.`
- `crates/attestation`
- `crates/browser-demo`
- `crates/components/cipher`
- `crates/components/deap`
- `crates/components/hmac-sha256`
- `crates/components/key-exchange`
- `crates/core`
- `crates/data-fixtures`
- `crates/examples`
- `crates/formats`
- `crates/harness/core`
- `crates/harness/executor`
- `crates/harness/plot`
- `crates/harness/runner`
- `crates/mpc-tls`
- `crates/sdk-core`
- `crates/server-fixture/certs`
- `crates/server-fixture/server`
- `crates/tls/client`

Package scripts sampled:
- No JavaScript package scripts detected.

Local instruction/status files:
- `AGENTS.md`
- `STATUS.md`

## Findings

### 1. [High] Dynamic code or shell execution needs input-boundary review

These APIs are legitimate in tooling, but they become high-risk when command strings or evaluated input can be influenced by users, files, networks, or model output. Scanner count: 2.

Evidence:
- crates/tls/client/examples/internal/bogo_shim.rs:626 `fn exec(opts: &Options, mut sess: Connection, count: usize) {`
- crates/tls/client/examples/internal/bogo_shim.rs:1137 `exec(&opts, sess, i);`
### 2. [Medium] Potential credential/config material needs a focused secret audit

Names commonly used for credentials or sensitive tokens appear in app-owned files. Some hits may be fixtures or placeholders, but every example should be verified, documented as fake, or moved to secret management. Values are redacted here. Scanner count: 669.

Evidence:
- crates/attestation/src/lib.rs:108 `//! [`Secrets`] which contains all private information. This pair can be stored`
- crates/attestation/src/lib.rs:125 `//! A Prover can use an [`Attestation`] and the corresponding [`Secrets`] to`
- crates/attestation/src/lib.rs:129 `//! # use tlsn_attestation::{Attestation, CryptoProvider, Secrets, presentation::Presentation};`
- crates/attestation/src/lib.rs:133 `//! # let secrets: Secrets = unimplemented!();`
- crates/attestation/src/lib.rs:135 `//! let (_sent_len, recv_len) = secrets.transcript().len();`
- crates/attestation/src/lib.rs:138 `//! let mut builder = secrets.transcript_proof_builder();`
- crates/attestation/src/lib.rs:149 `//! let identity_proof = secrets.identity_proof();`
- crates/attestation/src/lib.rs:205 `mod secrets;`
### 3. [High] Private key or certificate material appears in the tree

Key and certificate material should usually be generated or injected outside source control. If these are fixtures, mark them unmistakably as test-only and keep them away from production paths. Scanner count: 2.

Evidence:
- crates/tls/client/src/sign.rs:91 `/// Both SEC1 (PEM section starting with 'BEGIN EC PRIVATE KEY') and PKCS8`
- crates/tls/client/src/sign.rs:92 `/// (PEM section starting with 'BEGIN PRIVATE KEY') encodings are supported.`
### 4. [Medium] Many nested project manifests increase ownership and verification complexity

This app folder contains many buildable surfaces. Document ownership and canonical verification commands so fixes do not verify the wrong package.

Evidence:
- Cargo.toml
- crates/attestation/Cargo.toml
- crates/browser-demo/Cargo.toml
- crates/components/cipher/Cargo.toml
- crates/components/deap/Cargo.toml
- crates/components/hmac-sha256/Cargo.toml
- crates/components/key-exchange/Cargo.toml
- crates/core/Cargo.toml
### 5. [Medium] Runtime failure shortcuts are common enough to deserve hardening

Force unwraps, panics, unwraps, expect calls, and fatal errors should be converted to typed errors around IO, persistence, parsing, and user-driven paths. Scanner count: 1624.

Evidence:
- crates/attestation/src/builder.rs:261 `.unwrap()`
- crates/attestation/src/builder.rs:268 `provider.signer.set_secp256k1(&[42u8; 32]).unwrap();`
- crates/attestation/src/builder.rs:282 `.unwrap();`
- crates/attestation/src/builder.rs:287 `.unwrap();`
- crates/attestation/src/builder.rs:302 `.unwrap();`
- crates/attestation/src/builder.rs:307 `.unwrap();`
- crates/attestation/src/builder.rs:320 `.unwrap();`
- crates/attestation/src/builder.rs:323 `provider.signer.set_secp256r1(&[42u8; 32]).unwrap();`
### 6. [Low] TODO/FIXME debt is high enough to obscure release readiness

Deferred markers are numerous enough that release-critical work can be lost unless the backlog is triaged into issues. Scanner count: 20.

Evidence:
- crates/attestation/src/proof.rs:91 `// TODO: Support creating a proof for a subset of fields instead of the entire`
- crates/attestation/src/request.rs:72 `// TODO: improve the O(M*N) complexity of this check.`
- crates/formats/src/json/commit.rs:158 `// TODO: Commit each value separately, but we need a strategy for handling`
- crates/harness/static/comlink.mjs:229 `// FIXME: ES6 Proxy Handler `set` methods are supposed to return a`
- crates/tls/client/examples/internal/bogo_shim.rs:314 `// TODO: add support for Ed448`
- crates/tls/client/examples/internal/bogo_shim.rs:597 `quit(":FIXME:")`
- crates/tls/client/src/backend/standard.rs:266 `// TODO: do we assume already having probed the TLS server by this point`
- crates/tls/client/src/backend/standard.rs:269 `// TODO can we just return the CipherSuite enum?`

## Testing and Build Posture

Detected tests:
- `crates/attestation/tests/api.rs`
- `crates/harness/core/src/test.rs`
- `crates/harness/executor/src/test.rs`
- `crates/tls/client/tests/api.rs`
- `crates/tls/client/tests/common/mod.rs`
- `crates/tls/core/src/msgs/enums_test.rs`
- `crates/tls/core/src/msgs/handshake_test.rs`
- `crates/tls/core/src/msgs/message_test.rs`
- `crates/tlsn/tests/interop/README.md`
- `crates/tlsn/tests/interop/apache/httpd.conf`
- `crates/tlsn/tests/interop/caddy/Caddyfile`
- `crates/tlsn/tests/interop/docker-compose.yml`

Detected CI workflows:
- `.github/workflows/bench.yml`
- `.github/workflows/ci.yml`
- `.github/workflows/claude-assistant.yml`
- `.github/workflows/rebase.yml`
- `.github/workflows/regression.yml`
- `.github/workflows/releng.yml`
- `.github/workflows/rustdoc.yml`

Inferred verification commands to standardize:
- JavaScript: run the owning package-manager install/build/test scripts from the relevant `package.json`.
- Rust: run `cargo test` or workspace-specific checks from each Cargo workspace root.

## Review Limitations

- This was a broad static review across many local apps, not a full manual product walkthrough.
- Generated directories and dependency trees were pruned so findings focus on app-owned source.
- Secret-like values were not reproduced; examples are redacted or limited to path/line evidence.
- Pattern scanning is capped per app to keep the cross-repository sweep tractable; high-risk folders need focused follow-up review.

## Recommended Next Steps

1. Resolve every High finding first, especially secret material, tracked generated output, and dynamic execution paths.
2. Add or tighten the app's canonical CI workflow so build and tests run on every push.
3. Convert inferred build/test commands into documented commands in the app README or STATUS file.
4. Add smoke tests around app launch, persistence, API boundaries, and security-sensitive adapters.
5. Re-run this review after cleanup and replace this file with a human-reviewed release checklist.

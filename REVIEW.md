# Code Review: tlsn

Review date: 2026-05-11  
Tracker: https://github.com/advatar/Tracker/issues/53  
Scope: top-level app folder `tlsn` and nested project manifests under this folder, excluding generated dependency/build directories such as `.git`, `node_modules`, `target`, `.build`, `dist`, and virtual environments.

## Executive Summary

- Overall risk from this sweep: **High**
- Findings by severity: High 3, Medium 2, Low 1
- Source footprint: 295 source files by extension scan (Rust 275, Shell 10, HTML 4, JavaScript 4, CSS 1, Python 1)
- Test footprint: 21 test-like files detected
- CI footprint: 7 GitHub Actions workflow files detected
- Git posture: clean before review generation

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

These APIs are legitimate in tooling, but they become high-risk when any part of the command or evaluated input crosses a user, network, file, or model boundary. Scanner count: 2.

Evidence:
- crates/tls/client/examples/internal/bogo_shim.rs:626 `fn exec(opts: &Options, mut sess: Connection, count: usize) {`
- crates/tls/client/examples/internal/bogo_shim.rs:1137 `exec(&opts, sess, i);`
### 2. [High] Potential credential/config material needs a focused secret audit

The scanner found names commonly used for credentials or sensitive tokens. Some hits may be placeholders, but every example should be verified, documented as fake, or moved to secret management. Values are intentionally redacted in this review. Scanner count: 669.

Evidence:
- crates/core/src/lib.rs:22 `transcript::{PartialTranscript, TranscriptCommitment, TranscriptSecret},`
- crates/core/src/lib.rs:30 `/// Transcript commitment secrets.`
- crates/core/src/lib.rs:31 `pub transcript_secrets: Vec<TranscriptSecret>,`
- crates/core/src/transcript.rs:39 `TranscriptCommitRequest, TranscriptCommitment, TranscriptCommitmentKind, TranscriptSecret,`
- crates/core/src/webpki.rs:25 `pub struct PrivateKeyDer(pub Vec<u8>);`
- crates/core/src/webpki.rs:27 `impl PrivateKeyDer {`
- crates/core/src/webpki.rs:30 `let der = webpki_types::PrivateKeyDer::from_pem_slice(pem).map_err(|_| PemError {})?;`
- crates/core/src/webpki.rs:32 `Ok(Self(der.secret_der().to_vec()))`
### 3. [High] Private key or certificate material appears in the tree

Key and certificate material should generally be generated or injected outside source control. If these are fixtures, label them unmistakably and keep them scoped to tests. Scanner count: 2.

Evidence:
- crates/tls/client/src/sign.rs:91 `/// Both SEC1 (PEM section starting with 'BEGIN EC PRIVATE KEY') and PKCS8`
- crates/tls/client/src/sign.rs:92 `/// (PEM section starting with 'BEGIN PRIVATE KEY') encodings are supported.`
### 4. [Medium] Many nested project manifests increase ownership and verification complexity

This app folder contains many buildable surfaces. The review should result in an ownership map and a small set of canonical commands so fixes do not verify the wrong package.

Evidence:
- Cargo.toml
- crates/attestation/Cargo.toml
- crates/browser-demo/Cargo.toml
- crates/components/cipher/Cargo.toml
- crates/components/deap/Cargo.toml
- crates/components/hmac-sha256/Cargo.toml
- crates/components/key-exchange/Cargo.toml
- crates/core/Cargo.toml
- crates/data-fixtures/Cargo.toml
- crates/examples/Cargo.toml
- crates/formats/Cargo.toml
- crates/harness/core/Cargo.toml
### 5. [Medium] Runtime failure shortcuts are common enough to deserve hardening

Force unwraps, panics, unwraps, and fatal errors are useful during prototyping but should be converted to typed errors around user-driven and IO-driven paths. Scanner count: 1624.

Evidence:
- crates/core/src/merkle.rs:105 `value: self.tree.root().expect("tree should not be empty"),`
- crates/core/src/merkle.rs:135 `*indices.last().unwrap() < self.tree.leaves_len(),`
- crates/core/src/transcript.rs:119 `.expect("data is same length as index"),`
- crates/core/src/transcript.rs:601 `let bytes = bincode::serialize(&partial_transcript).unwrap();`
- crates/core/src/transcript.rs:618 `let bytes = bincode::serialize(&partial_transcript).unwrap();`
- crates/core/src/transcript.rs:630 `let end = partial_transcript.sent_idx.iter().next_back().unwrap().end;`
- crates/core/src/transcript.rs:634 `let bytes = bincode::serialize(&partial_transcript).unwrap();`
- crates/core/src/transcript.rs:665 `.unwrap();`
### 6. [Low] TODO/FIXME debt is high enough to obscure release readiness

The number of deferred markers is large enough that release-critical work can be lost unless the backlog is triaged. Scanner count: 20.

Evidence:
- crates/formats/src/json/commit.rs:158 `// TODO: Commit each value separately, but we need a strategy for handling`
- crates/harness/static/comlink.mjs:229 `// FIXME: ES6 Proxy Handler `set` methods are supposed to return a`
- crates/tls/client/tests/api.rs:2528 `let encryption_overhead = 20; // FIXME: see issue #991`
- crates/tls/client/test-ca/build-a-pki.sh:93 `# TODO: add support for Ed448`
- crates/tls/client/test-ca/build-a-pki.sh:126 `# TODO: add support for Ed448`
- crates/tls/client/examples/internal/bogo_shim.rs:314 `// TODO: add support for Ed448`
- crates/tls/client/examples/internal/bogo_shim.rs:597 `quit(":FIXME:")`
- crates/tls/client/src/sign.rs:119 `// TODO: Add support for Ed448`

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
- JavaScript: run the package-manager install/build/test scripts from the relevant `package.json` owners.
- Rust: run `cargo test` or workspace-specific checks from each Cargo workspace root.

## Review Limitations

- This was a broad static review across many local apps, not a full manual product walkthrough.
- Generated directories and dependency trees were pruned so findings focus on app-owned source.
- Secret-like values were not reproduced; examples are redacted or limited to path/line evidence.
- Build commands were inferred from manifests and scripts; each app should document one canonical local verification command.

## Recommended Next Steps

1. Resolve every High finding first, especially secret material, tracked generated output, and dynamic execution paths.
2. Add or tighten the app's canonical CI workflow so build and tests run on every push.
3. Convert inferred build/test commands into documented commands in the app README or STATUS file.
4. Add smoke tests around app launch, persistence, API boundaries, and security-sensitive adapters.
5. Re-run this review after cleanup and replace this file with a human-reviewed release checklist.

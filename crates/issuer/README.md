# TLSNotary OpenID4VCI Issuer

This service implements the OpenID4VCI 1.0 Final pre-authorized-code flow for
TLSNotary evidence. It validates a portable artifact against a pinned notary
key before creating a short-lived credential offer. A wallet exchanges the
single-use code, obtains a nonce, presents an ES256 JWT key proof, and receives
a holder-bound `jwt_vc_json` credential.

## Run locally

Use stable 32-byte P-256 secret scalars for both services:

```sh
export TLSN_NOTARY_SIGNING_KEY="$(openssl rand -hex 32)"
export TLSN_ISSUER_SIGNING_KEY="$(openssl rand -hex 32)"
```

Start the notary and read `artifact_public_key` from
`http://127.0.0.1:3000/api/health`. Decode that base64url SEC1 key and provide
its hex encoding as `TLSN_TRUSTED_NOTARY_KEY`, then run:

```sh
cargo run -p tlsn-issuer
```

The issuer listens on `127.0.0.1:3030`. Its discovery documents are:

- `/.well-known/openid-credential-issuer`
- `/.well-known/oauth-authorization-server`
- `/jwks.json`

Submit a signed artifact to `POST /api/evidence`. The response contains both a
credential offer by value and an `openid-credential-offer://` wallet URI.

## Trust boundary

This is a conformant development adapter, not an accredited EUDI issuer. An EU
wallet can only treat the resulting credential as trusted when the issuer key
and credential profile are admitted by the applicable national trust framework
and the deployment meets the EUDI security, certification, status, and
revocation requirements. The current in-memory grants are intentionally
single-instance and should be moved to a transactional shared store before
horizontal production deployment.

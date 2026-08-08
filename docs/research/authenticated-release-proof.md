# Computational argument for authenticated release

**Status:** proof draft for cryptographic review; not a peer-reviewed theorem

## Construction

For one incoming TLS 1.3 record, let the jointly computed 128-bit GCM tag be
`T = T_L xor T_F`. The prover/leader receives `T_L`; the verifier/follower
retains `T_F`. The verifier holds a uniformly sampled plaintext mask `R` and
sends:

```text
pad_i = HMAC-SHA256(T_F, "tlsn tls13 authenticated release pad" || uint32(i))
C     = R xor truncate(pad_0 || pad_1 || ...)
D     = HMAC-SHA256(T_F,
                    "tlsn tls13 authenticated release commitment" ||
                    uint64(len(R)) || R)
capsule = (C, D)
```

Given a public record tag `t`, the prover computes the candidate follower
share `t xor T_L`, decrypts `C`, and accepts the result only if `D` verifies.
The verifier does not send `T_F` for a gated TLS 1.3 record.

## Security experiment

The authenticated-release experiment gives an adversarial prover control of
the network, ciphertext, AAD, record ordering, and claimed public tags. It may
observe valid server ciphertext/tag pairs and interact with the joint AEAD
protocol for the bounded number of preprocessed records. It wins if it recovers
the verifier mask for a ciphertext/AAD/nonce tuple for which it has no valid
GCM tag, before compromise or prover/verifier collusion.

This experiment establishes release gating. Provenance additionally depends
on the TLS handshake, server certificate verification, transcript binding,
and malicious security of every invoked MPC subprotocol.

## Required assumptions

1. The leader's `OneTimePadShared` mask is sampled uniformly and independently
   for every record. Consequently, the follower tag share is uniform from the
   malicious leader's view until the complete valid tag is known.
2. HMAC-SHA256 is a PRF for uniformly random 128-bit keys, including under the
   two domain-separated message families above.
3. GCM is strongly unforgeable within the TLS 1.3 invocation limits and every
   `(traffic key, nonce)` pair is unique.
4. The MPC AES, GHASH, share conversion, and decode protocols are correct,
   private, and maliciously secure for their assigned roles.
5. The follower creates at most one capsule for each preallocated verification
   slot and samples a fresh plaintext mask for every slot.
6. HMAC input encodings are injective: fixed ASCII domains, fixed-width
   big-endian counters/lengths, and no ambiguous concatenation.

Assumption 4 is currently the largest unproved part of the trusted computing
base. Tests of MPZ operations do not replace a malicious-security proof.

## Game sequence

### Game 0: implementation-facing release experiment

Run the experiment with real GCM tag sharing and the HMAC capsule. The
adversary wins by recovering `R` for a record without a valid tag.

### Game 1: replace HMAC outputs with random functions

Replace both domain-separated HMAC families with independent random functions.
The distinguishing gap is bounded by their multi-user PRF advantages. Domain
separation is necessary because the same `T_F` keys both families.

### Game 2: condition on distinct follower shares

For `q` independently masked verification slots, follower-share collision
probability is at most `q(q-1) / 2^129`, assuming uniform 128-bit shares. Under
this condition, capsules from other slots provide no information about the
target mask.

### Game 3: replace the target pad with a one-time pad

In the random-function game the target pad is uniform, so `C` is independent
of `R`. A candidate key different from `T_F` produces an independent candidate
mask and commitment value.

### Game 4: bound false capsule acceptance

For a wrong candidate share, matching the 256-bit random-function commitment
has probability at most `2^-256` per opening attempt. Guessing the correct
uniform 128-bit follower share costs at most `2^-128` per attempt. If the
adversary obtains the complete valid GCM tag, the record is outside the win
condition.

For `q_o` capsule-opening attempts and `q` slots, the informal bound is:

```text
Adv_release
  <= Adv_HMAC-PRF(pad) + Adv_HMAC-PRF(commitment)
   + Adv_GCM-forgery
   + Adv_MPC
   + q(q-1) / 2^129
   + q_o / 2^128
   + q_o / 2^256.
```

This expression is a proof target, not yet a published reduction. A final
version must define all games, oracles, corruption timing, query bounds, and
the exact composition theorem for the MPC layer.

## Stronger tag-agreement limitation

The initial Tamarin model falsified the stronger statement that the tag
submitted in a verification attempt must equal the server's transmitted tag.
A malicious prover can retain a genuine tag for a genuine ciphertext and use
that tag to recover the capsule key even if it supplied a different tag to the
modeled verification interface. This does not release forged plaintext, but it
means exact tag agreement must be established by transcript verification or a
changed protocol. The paper must not silently strengthen authenticated
plaintext release into exact submitted-tag agreement.

## Recommended hardening

- Derive a dedicated per-record release key inside MPC from the authenticated
  comparison result and explicit session/epoch/sequence context. This removes
  the nonstandard step of directly using a GCM tag share as an HMAC key.
- Bind session identifier, direction, traffic-secret generation, sequence,
  AAD hash, ciphertext hash, and claimed tag into both HMAC domains.
- Make tag equality an explicit MPC output bit that gates key release, rather
  than relying only on the prover's ability to reconstruct a share.
- Obtain independent review of the game-based proof and the underlying MPZ
  malicious-security assumptions before publication claims implementation
  security.


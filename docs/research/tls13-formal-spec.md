# Formal-verification specification for TLSNotary TLS 1.3

**Status:** work in progress; no blanket formal-verification claim

## Scope

The target is the narrow TLS 1.3 profile implemented by this repository:
TLS 1.3 with `TLS_AES_128_GCM_SHA256`, server authentication, bounded
application records, and two-party MPC between a prover/leader and a
verifier/follower. Resumption, 0-RTT, `KeyUpdate`, post-quantum transport,
side-channel resistance, and general TLS 1.3 implementations are outside the
initial theorem boundary.

The verification is divided into independently stated layers. A proof at one
layer is not evidence that the layers below it are correct.

## Participants and adversaries

- The origin server is honest unless its TLS application traffic key is
  explicitly compromised.
- The prover controls its host and the network between itself and the server.
  It may reorder, replay, truncate, synthesize, or replace protocol messages
  and may abort at any point.
- The verifier may be considered malicious in a separate confidentiality
  theorem. The initial authenticated-release theorem assumes the verifier
  follows the release-capsule construction while keeping its share private.
- Prover and verifier do not collude during the notarized session. Collusion
  trivially reconstructs secrets shared between them.
- Cryptographic side channels, compromised endpoints, RNG failure, and denial
  of service are excluded from the first symbolic model and must be reported
  as limitations.

## Security claims

### C1: application-key secrecy

Neither non-colluding MPC party learns a complete TLS 1.3 application traffic
key. The symbolic theorem treats the joint AEAD operation as ideal; an
implementation-refinement argument must separately establish that VM values
are never decoded or leaked through serialization.

### C2: authenticated server-plaintext release

If the prover obtains plaintext for an incoming application record, then an
honest server previously authenticated the same ciphertext, AAD, direction,
traffic-secret generation, sequence number, and plaintext under some valid
tag, unless the server traffic key was compromised.

The stronger claim that the tag submitted to the verifier must equal that
server tag is false for the current capsule abstraction: a malicious prover
that retains the genuine tag for a genuine ciphertext can use it to open the
capsule even after submitting a different tag. This does not authenticate a
forged ciphertext or plaintext, but exact tag agreement must either be
enforced elsewhere in transcript verification or added to the construction
before it is claimed.

### C3: nonce uniqueness

For each traffic key and direction, a `(generation, sequence)` pair is used
for at most one record. Sequence numbers start at zero on key installation,
advance once per attempted record operation, never wrap, and are never shared
between read and write epochs.

### C4: transcript agreement

Every record included in a successfully verified TLSNotary proof agrees with
the authenticated TLS record and its direction, order, content type, and
plaintext commitment. This claim requires a later model covering transcript
commitment and proof verification; it is not proved by the initial record
model.

### C5: selective-disclosure confidentiality

The verifier learns no unrevealed application bytes beyond public lengths,
directions, timing, explicitly revealed ranges, and other declared leakage.
This is an observational-equivalence goal and is deferred until the exact
leakage function is specified.

## Authenticated-release construction

For an incoming record, the parties compute additive GCM tag shares
`t = t_L xor t_F`. The prover knows `t_L` and the public record tag `t`. The
verifier encrypts its plaintext OTP mask in a domain-separated HMAC capsule
keyed by `t_F` and does not disclose `t_F`. The prover derives the candidate
key `t xor t_L`; capsule opening therefore succeeds only when the public tag
matches the jointly computed tag, subject to the computational assumptions
below.

The symbolic model represents the capsule as ideal symmetric encryption. A
publishable security claim additionally requires a computational argument
that covers use of a GCM tag share as HMAC key material, related/multiple
shares, commitment unforgeability, replay, chosen inputs, and aborts. If the
tag share cannot be justified as suitable key material, the construction must
derive a dedicated release key within MPC instead.

## Assumptions and trusted computing base

The initial symbolic results assume:

1. ideal authenticated encryption and ideal private/correct MPC evaluation;
2. uncompromised server application traffic keys;
3. fresh verifier OTP masks and protocol randomness;
4. no prover/verifier collusion;
5. injective, unambiguous serialization of modeled tuples;
6. faithful correspondence between implementation events and model events.

The trusted computing base currently includes Tamarin and Maude, the model
itself, Rust's compiler and runtime, the MPZ VM and circuits, cryptographic
dependencies, the operating system and RNG, and the unverified refinement
boundary connecting Rust execution to symbolic events. Later artifacts should
reduce and enumerate this boundary rather than implying it has disappeared.

## Evidence taxonomy

- **Symbolic proof:** a Tamarin lemma closed for the modeled transition system.
- **Computational argument:** a reduction under named cryptographic
  assumptions, independently reviewed.
- **Implementation proof:** machine-checked invariants or refinement of Rust
  code/specification.
- **Validation:** tests, fuzzing, differential checks, and interoperability.

The paper and documentation must use these terms precisely. Passing one class
does not permit substituting the phrase “formally verified implementation.”

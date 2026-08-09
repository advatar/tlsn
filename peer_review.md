I reviewed the research draft as a **paper/technical-security argument**, not merely as prose. tls13\-tlsnotary.html

Overall, this is a strong draft. The most important thing it gets right is **epistemic discipline**: it repeatedly distinguishes symbolic proof, computational assumptions, implementation invariants, testing, and full implementation refinement. I would not weaken that. In fact, that separation is probably the paper's strongest research contribution beyond the TLS 1.3 engineering itself.

## The core contribution is convincing

The central security invariant is exactly the right one:

> **The prover must never obtain a complete server application traffic key.**

The architecture follows naturally from that:

```text
TLS 1.3 server
      │
      │ encrypted TLS records
      ▼
┌─────────────┐        ┌─────────────┐
│   Prover    │◀─ MPC ─▶│  Verifier   │
│ key share   │        │ key share   │
└─────────────┘        └─────────────┘
       │                       │
       └──── joint AES-GCM ────┘
                  │
            authentication
                  │
                  ▼
         plaintext release
```

Keeping the application traffic keys **and IVs as MPC VM references**, maintaining independent typed epochs, consuming sequence numbers exactly once, rejecting exhaustion rather than wrapping, and constructing

```text
nonce = IV XOR (0^32 || uint64(seq))
```

is a clean adaptation of the TLSNotary provenance invariant to TLS 1.3. tls13\-tlsnotary.html

This is much stronger than simply saying "we added TLS 1.3 support."

---

# The best part of the paper: the failed theorem

I would actually **emphasize this more**.

The discovery that the stronger tag-agreement theorem is false is an excellent result:

> a prover can retain the genuine tag for a genuine ciphertext, submit another tag, and subsequently use the genuine tag to open the capsule.

Therefore:

```text
Authenticated plaintext
        ≠
Agreement with submitted tag
```

and the theorem has correctly been weakened to provenance of plaintext under **some valid server-authenticated tag**. tls13\-tlsnotary.html

That's exactly the sort of thing formal methods are supposed to uncover.

I would make this a named result, perhaps:

### Finding 1 — Authenticated Release Does Not Imply Submitted-Tag Agreement

Then show a tiny attack trace.

```text
Server produces:

    C, T_valid

Prover retains T_valid

Prover submits:

    C, T_fake

Later capsule opening uses:

    T_valid

→ plaintext can be authenticated
→ but T_submitted ≠ T_valid
```

Right now this important result is buried inside the formal-analysis narrative. It deserves much greater prominence.

---

# My biggest concern: the capsule

The weakest cryptographic component is exactly the one the paper itself identifies:

> "The tag-share capsule is nonstandard and should preferably be replaced by an explicitly context-bound release key derived inside MPC."

I strongly agree.

This is where a reviewer is likely to concentrate fire.

Currently the logic appears approximately:

```text
T = T_P XOR T_V

prover knows:
    public T
    T_P

therefore candidate:
    T_V = T XOR T_P

T_V → HMAC-based capsule key
             ↓
        verifier mask
```

The argument then relies on PRF behavior, follower-share uniformity, collision bounds, wrong-key commitment rejection, etc.

It may be secure, but it creates a **new cryptographic construction** that the paper now has to defend.

I would make replacing this construction a priority.

Something conceptually closer to:

```text
K_release =
    MPC-KDF(
        authenticated_record_result,
        transcript/session context,
        direction,
        epoch,
        sequence,
        ciphertext hash
    )
```

would give you a much cleaner statement:

> plaintext is released iff the joint computation establishes authentication for this exact TLS record context.

It also potentially eliminates the semantic gap exposed by the failed tag-agreement theorem.

The context should bind at least:

```text
protocol/version
session/transcript identifier
direction
traffic-secret generation
sequence number
AAD
ciphertext digest
authentication result
```

Then there is no free-floating "tag share as capability" to reason about.

---

# A second important issue: record provenance versus TLS-session provenance

The paper is careful here, but the title and abstract come close to making a stronger impression than the evidence warrants.

The record-layer theorem essentially establishes:

```text
authenticated record
       +
secret server key
       +
ideal AEAD/MPC
       ↓
server-originating plaintext
```

But transferable TLS provenance really requires a longer chain:

```text
certificate
    ↓
server identity
    ↓
TLS handshake
    ↓
transcript
    ↓
Finished
    ↓
application traffic secret
    ↓
epoch
    ↓
record key / IV
    ↓
record
    ↓
released plaintext
    ↓
presentation / selective disclosure
```

You have Tamarin models covering several pieces of this chain, but **you don't yet have the refinement theorem joining all those pieces to the concrete Rust implementation**. tls13\-tlsnotary.html

The paper says this correctly. I would make the chain visually explicit because it explains immediately why:

> "formally verified TLSNotary"

is **not yet the claim**.

---

# The four Tamarin models need a composition story

You currently have four useful models:

1. record layer,
2. handshake/transcript,
3. key schedule/Finished,
4. selective-disclosure observational equivalence.

Individually, that's good.

But a reviewer can reasonably ask:

> What proves that the output assumed by model 2 is the object consumed by model 3, which is the object assumed by model 1?

At the moment the paper essentially answers:

**nothing yet.**

That's acceptable for this stage, but I'd formalize the missing composition theorem.

For example:

```text
HandshakeAgreement
        ∧
FinishedAcceptance
        ∧
ApplicationSecretInstallation
        ∧
EpochBinding
        ∧
RecordAuthentication
        ∧
DisclosureBinding

⇒ PresentedByteHasServerProvenance
```

Call this the **end-to-end provenance theorem**.

Then explicitly mark:

```text
Status: OPEN
```

and show which lemmas already discharge which premises.

That would transform "we have several models" into a coherent verification roadmap.

---

# The threat model needs one additional distinction

You say:

> The prover controls the network-facing TLS client and may deviate arbitrarily.

Good.

But I would distinguish:

```text
malicious TLS endpoint behavior

from

malicious notarization protocol behavior
```

because the prover simultaneously occupies several conceptual roles:

```text
network scheduler
TLS client
MPC participant
presentation creator
proof submitter
```

Different attacks happen at different boundaries.

A table would help:

| Role | Malicious? | Protected property |
|---|---|---|
| Network | Yes | transcript/record integrity |
| TLS client | Yes | server provenance |
| MPC leader | Yes | key secrecy/authenticated release |
| Verifier | No, currently | — |
| Server | Honest wrt TLS key | TLS authentication |
| Presenter | Yes | selective disclosure integrity |

This would make the malicious-verifier omission much easier to understand.

---

# Concurrency is more important than the draft makes it sound

Concurrency is listed as future work, but I think it deserves elevation.

Your local theorem:

```text
sequence consumed exactly once
```

is excellent.

But the actual security property is closer to:

```text
(session, direction, generation, seq)
```

being globally unique for every AEAD invocation associated with a traffic key.

A correct `reserve()` function isn't sufficient if asynchronous tasks can:

```text
reserve
cancel
retry
duplicate VM work
cross epochs
restore state
replay serialized work
```

in ways the abstract state machine doesn't model.

I'd therefore define a **Record Identifier** explicitly:

```text
RecordId {
    session_id,
    direction,
    generation,
    sequence
}
```

and eventually make this identity flow through MPC allocation, capsule/release derivation, transcript commitment, and presentation.

That would help both implementation safety and formal refinement.

---

# Kani + Lean is a particularly good choice

The combination here is compelling:

```text
Lean
 ↓
abstract mathematical invariant

Kani
 ↓
actual Rust implementation over exhaustive bounded state

Tamarin
 ↓
protocol/security property

Interop/tests
 ↓
real-world compatibility
```

The paper should perhaps sell this **layered verification methodology** more aggressively.

You're not merely using three verification tools. Each one is answering a different question.

A figure showing:

```text
                 END-TO-END CLAIM
                       ▲
                       │  missing refinement
                       │
             ┌─────────┴─────────┐
             │                   │
          Tamarin             Lean
       protocol model      state theorem
             │                   │
             │                   ▼
             │                 Kani
             │             Rust functions
             │                   │
             └─────────┬─────────┘
                       ▼
                 Rust / MPZ
                       │
                       ▼
               interoperability
```

would make the contribution much easier to understand.

---

# I'd change one sentence in the abstract

The abstract currently says:

> "Tamarin models prove five record-layer properties, five handshake/transcript properties, five key-schedule/Finished properties..."

Technically fine, but counting lemmas sounds slightly like verification-by-volume.

I'd instead lead with the important semantic properties:

**Tamarin establishes symbolic key secrecy, authenticated plaintext release, record-slot uniqueness, handshake/transcript agreement, Finished-before-application-secret installation, and a bounded selective-disclosure equivalence property.**

Then give the lemma count later in the evaluation/reproducibility section.

That reads more like a research result.

---

# Your claim–evidence matrix is excellent, but one row is too strong

This row:

> Released plaintext has server provenance → Tamarin theorem

is potentially misleading because the missing-evidence column says:

> Computational MPC composition; handshake binding

If handshake binding is missing at the concrete level, I'd phrase the claim as:

**Released plaintext has server provenance within the symbolic model**

or:

**Authenticated release implies modeled server provenance**

Then reserve:

**Concrete released plaintext has TLS server provenance**

for the eventual end-to-end theorem.

Tiny wording difference; large reviewer-defense difference.

---

# One missing property I'd add

I would explicitly state and eventually prove:

### Cross-session non-transferability

An authenticated release artifact from:

```text
Session A
```

must not be usable in:

```text
Session B
```

even where the same server, cipher suite, request, plaintext, or sequence number occurs.

This becomes especially important if you're redesigning the capsule around a release key.

The release context should therefore include a cryptographically bound session identity derived from the handshake/transcript, rather than an application-assigned UUID.

You then get:

```text
K_release =
KDF(
    MPC_secret,
    "tlsnotary 1.3 release",
    transcript_hash,
    direction,
    generation,
    seq,
    H(AAD),
    H(ciphertext)
)
```

conceptually.

That is a considerably easier primitive to reason about than the current tag-share capsule.

---

# Publication positioning

I would **not** pitch this as:

> TLSNotary now supports TLS 1.3.

Nor:

> formally verified TLS 1.3 TLSNotary.

The draft correctly avoids both.

I'd pitch it closer to:

> **A verified-by-layers architecture for TLS 1.3 notarization that preserves TLSNotary's key-secrecy provenance invariant.**

The genuinely interesting result isn't simply TLS 1.3 interoperability. It's:

```text
TLS 1.3
+
two-party record protection
+
malicious prover
+
no complete server traffic key
+
authenticated plaintext release
+
machine-checked protocol/state properties
```

That is a substantial contribution.

## What I'd do next

My priorities would be:

1. **Replace the tag-share capsule** with context-bound authenticated release computed inside MPC.
2. Define `SessionId` and `RecordId` formally and bind everything to them.
3. Write the missing **end-to-end provenance composition theorem**, even if initially marked OPEN.
4. Extend the state/refinement story to concurrency and cancellation.
5. Establish AES/GHASH circuit ↔ reference equivalence.
6. Establish concrete HKDF/HkdfLabel ↔ RFC 8446 refinement.
7. Bind concrete X.509/server authentication and transcript parsing to the symbolic handshake model.
8. Add malicious-verifier confidentiality as the second major theorem track.

If you accomplish **1–4**, I think the paper becomes substantially more interesting than "TLSNotary TLS 1.3 support." It becomes a paper about how to construct and verify a TLS 1.3 notarization protocol while preserving the fundamental provenance boundary—and, importantly, it already contains a nice formal-methods result where verification discovered that an intuitively plausible stronger authentication theorem was false. tls13\-tlsnotary.html
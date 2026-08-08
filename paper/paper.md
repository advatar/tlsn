---
title: "Toward Formally Verified TLS 1.3 Notarization: Joint Record Protection and Authenticated Release"
author:
  - "Anonymous authors (research draft)"
date: "2026"
abstract: |
  TLS notarization lets a client prove the provenance of selectively disclosed
  web data without server modification. Existing TLSNotary deployments target
  TLS 1.2, while TLS 1.3 changes the key schedule, record nonce construction,
  and encrypted-handshake boundary. We describe an implementation of bounded
  two-party TLS 1.3 application-record protection in which traffic keys remain
  secret-shared and server plaintext is released through a capsule gated by a
  jointly computed GCM tag. We separate assurance into symbolic protocol
  analysis, computational assumptions, machine-checked state invariants, and
  empirical validation. Tamarin models prove five record-layer properties,
  five handshake/transcript properties, and a bounded selective-disclosure
  observational-equivalence property under explicit abstractions.
  The record-layer properties are proved under ideal AEAD and MPC assumptions.
  Lean proves sequence and
  nonce invariants, and Kani checks the corresponding Rust functions over all
  64-bit sequences and 96-bit IVs. The analysis also identifies a limitation:
  authenticated plaintext release does not by itself imply equality with the
  tag submitted to the verifier. Concrete HKDF/parser refinement, MPC-
  composition, and implementation-refinement proofs remain open; consequently
  we do not claim a fully formally verified implementation.
geometry: margin=1in
fontsize: 10pt
link-citations: true
---

# Introduction

TLS authenticates communication between a client and server but does not give
the client a transferable proof of response provenance. TLSNotary addresses
this gap by splitting TLS computations between a prover and verifier and later
supporting selective disclosure [@tlsnotary-docs]. Related systems such as DECO
also use collaborative cryptography to prove facts about TLS-protected web data
without server modification [@deco2020].

TLS 1.3 requires a new analysis boundary. Its record layer uses AEAD throughout,
derives a per-record nonce by XORing a padded 64-bit sequence number with the
static IV, and resets independently maintained read/write sequences on key
changes [@rfc8446]. In a notarization protocol, revealing the complete server
application key to the prover destroys provenance: the prover could generate
arbitrary ciphertext/tag pairs that appear to originate at the server.

This work makes four contributions:

1. A bounded joint AES-GCM application-record design that retains application
   keys and IVs as secret-shared MPC values.
2. An authenticated-release capsule that withholds the verifier's plaintext
   mask unless the prover can reconstruct the verifier's GCM tag share.
3. Reproducible Tamarin, Lean, and Kani artifacts with explicitly separated
   theorem boundaries.
4. An empirical TLS 1.3 interoperability evaluation and an analysis of proof
   gaps that remain before a full formal-verification claim is warranted.

# Background and related work

TLS 1.3 specifies AEAD record protection, independent 64-bit read/write
sequences, and nonce derivation from the static write IV [@rfc8446]. GCM's
security critically depends on key/IV uniqueness [@nist-gcm], and its security
bounds require care because flaws have appeared in earlier analyses
[@iwata2012].

DECO established a prominent cryptographic approach to proving provenance of
TLS data without trusted hardware or server changes [@deco2020]. TLSNotary uses
MPC to split TLS session operations between a prover and verifier
[@tlsnotary-docs]. The public TLSNotary documentation currently describes TLS
1.3 as future work, making the implementation and analysis here an experimental
research contribution rather than a statement about an upstream release.

Tamarin models protocols as multiset-rewriting systems and proves trace or
observational-equivalence properties in a symbolic model [@tamarin2013]. Its
results are relative to the supplied model and equational theory, and protocol
verification is undecidable in general; automation may not terminate
[@tamarin-manual]. We therefore report exact modeled assumptions and do not
equate symbolic proof with computational or implementation security.

# System and threat model

The prover controls the network-facing TLS client and may deviate arbitrarily.
The verifier participates in MPC and retains secret shares. The initial release
theorem considers a malicious prover and honest verifier. Parties do not
collude, the server application key is uncompromised, randomness is fresh, and
the invoked MPC and AEAD functionalities are ideal. A separate malicious-
verifier confidentiality theorem is future work.

The evaluated profile is TLS 1.3 with
`TLS_AES_128_GCM_SHA256`, server authentication, bounded application records,
and no 0-RTT, resumption, or `KeyUpdate` claim. Denial of service and side
channels are outside the initial theorem boundary.

# Construction

Application traffic keys and IVs remain references in the MPC VM. Typed read
and write epochs own independent sequence numbers. A record consumes its
sequence immediately before AEAD evaluation; exhaustion returns an error
instead of wrapping. The 96-bit nonce is `IV xor (0^32 || uint64(sequence))`.

For incoming records, both parties mask the candidate plaintext. The verifier
releases its mask in an HMAC-based capsule keyed by its secret GCM tag share.
The complete tag is the XOR of leader and follower shares. Given the public
record tag and its own share, the prover derives the candidate follower share;
only the authentic candidate opens and validates the capsule under the stated
PRF and share-uniformity assumptions. The detailed game sequence and proposed
hardening are maintained in the accompanying computational-proof artifact.

# Formal analysis

## Symbolic model

The record-layer Tamarin model idealizes AEAD plaintext and authentication,
private MPC evaluation, and additive tag-share reconstruction. It gives the
adversary network control and the leader tag share but withholds the follower
share. Five required lemmas close automatically:

| Lemma | Result | Boundary |
|---|---:|---|
| Honest execution | Verified | Existence of one releasable record |
| Application-key secrecy | Verified | Absent explicit key compromise |
| Authenticated plaintext release | Verified | Ideal AEAD/MPC; malicious prover |
| Nonce tuple uniqueness | Verified | Modeled read-slot state |
| Read-slot single use | Verified | One verification attempt per slot |

The original stronger tag-agreement lemma was falsified. A prover retaining a
genuine tag for a genuine ciphertext can use it to open a capsule after
submitting another tag. The final theorem therefore establishes that released
plaintext corresponds to a server-authenticated ciphertext under some valid
tag, not equality with the submitted tag.

A second Tamarin model covers the symbolic handshake/transcript boundary. It
closes five additional lemmas for handshake executability and agreement,
application-epoch agreement, presentation agreement, and server-identity
binding. The model treats the concrete TLS 1.3 HKDF and certificate parser as
abstract interfaces; it therefore does not establish those implementation
details.

A third model isolates the TLS 1.3 key-schedule boundary. It represents
HKDF-Extract and HKDF-Expand-Label as private symbolic constructors, derives
the traffic secret using a labeled transcript context, and requires Finished
verification before application-secret installation. Four lemmas close: an
executable Finished path, emission-before-acceptance, acceptance before
application-secret installation, and transcript-context binding. These are
protocol-boundary claims; they do not replace test-vector or bit-level
refinement proofs for the production HKDF code.

A fourth, deliberately minimal, diff model checks that changing unrevealed
bytes while keeping the public projection fixed is observationally invisible.
This is a boundary test for the disclosure interface, not a proof of the
production circuit or serialization format.

## State and implementation invariants

Lean proves that the abstract epoch reservation operation returns the owned
sequence, advances it exactly once, preserves the key generation, rejects
exhaustion, and cannot return a wrapped sequence. It also proves nonce
injectivity for a fixed IV using XOR cancellation.

Four Kani harnesses model-check the actual Rust read/write reservation methods
and nonce function for all `u64` values and all 96-bit IVs. These checks connect
the stated local invariants to the implementation but do not constitute a
whole-program refinement proof.

## Computational argument

The current proof draft uses game hops replacing the domain-separated
HMAC-SHA256 families with random functions, conditions on distinct uniform
128-bit follower shares, replaces the release pad with a one-time pad, and
bounds wrong-key commitment acceptance. For `q` slots and `q_o` opening
attempts, the target bound includes HMAC PRF advantage, GCM forgery advantage,
MPC failure advantage, `q(q-1)/2^129` share collisions, `q_o/2^128` key
guessing, and `q_o/2^256` commitment acceptance. This is not yet an externally
reviewed reduction.

# Implementation and evaluation

The implementation is in Rust and builds on MPZ components for garbled
circuits, share conversion, and finite-field operations. AES/J0 circuits are
preallocated for bounded application records. Unused allocations are assigned
and committed during finalization so both VM parties terminate consistently.

Current validation includes unit tests, an end-to-end TLS 1.3 notarization
fixture, a five-case certificate/client-authentication matrix, and
interoperability with nginx, Apache httpd, Caddy, and OpenSSL `s_server`.
Performance measurements and reproducible hardware/software details remain to
be collected before submission.

The Docker-backed interoperability matrix was rerun on the verification
branch. All five cases passed: nginx RSA, nginx ECDSA, Apache RSA, Caddy RSA,
and OpenSSL `s_server`. The exact command is `./formal/interop.sh`; the focused
fixture and core validation are run by `./formal/validate.sh`.

# Claim--evidence matrix

| Claim | Evidence now | Missing evidence |
|---|---|---|
| Keys are not intentionally decoded | Code audit; symbolic secrecy | Whole-program information-flow/refinement proof |
| Released plaintext has server provenance | Tamarin theorem | Computational MPC composition; handshake binding |
| Epoch sequences do not wrap or repeat locally | Lean and Kani | Concurrent whole-program refinement |
| Fixed-IV nonce derivation is injective | Lean and Kani | Circuit/reference equivalence |
| Full proof transcript is authentic | Tamarin handshake/transcript model plus end-to-end tests | Concrete HKDF/parser refinement |
| Selective disclosure preserves the public projection | Minimal Tamarin observational-equivalence model | Production leakage function and serialization refinement |

The interoperation result is evidence of compatibility, not a security proof;
the server implementations are honest test peers and do not exercise the
malicious-party experiments.

# Limitations and research agenda

The strongest missing result is a composable malicious-security theorem for
the concrete MPZ protocols and release capsule. The symbolic models do not yet
cover concrete TLS handshake HKDF/parser refinement, X.509 validation,
production transcript commitments, proof serialization, malicious verifier, side channels,
concurrency, or crashes. AES and GHASH circuit equivalence is tested but not
machine-proved. The tag-share capsule is nonstandard and should preferably be
replaced by an explicitly context-bound release key derived inside MPC.

Accordingly, the correct current claim is a machine-checked symbolic
record-layer model plus locally verified state invariants—not a formally
verified TLSNotary implementation.

# Reproducibility

The repository contains the Tamarin theories, Lean specification, Kani
harnesses, and `formal/verify.sh`, which fails unless every required lemma is
reported as verified. On the reference machine, the wrapper runs Tamarin
1.12.0, Maude 3.5.1, Lean 4.32.2, and Kani 0.67. The executable validation
suite reports 27 MPC tests, 22 HMAC tests, 3 core configuration tests, and the
TLS 1.3 integration fixture; the explicit Docker interoperability suite passes
nginx (RSA and ECDSA), Apache (RSA), Caddy (RSA), and OpenSSL `s_server`.
These counts are reproducibility anchors, not a claim of exhaustive coverage.

# Conclusion

TLS 1.3 notarization can retain the central TLSNotary provenance invariant by
keeping application keys secret-shared and gating plaintext release on joint
record authentication. Layered verification exposed both useful positive
results and a subtle boundary between plaintext authenticity and exact tag
agreement. Completing handshake/transcript proofs, computational MPC
composition, circuit equivalence, and malicious-verifier privacy remains
necessary before claiming end-to-end formal verification.

# References

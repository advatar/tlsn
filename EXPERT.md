## Overall take

This is the right direction, and the “layout coincidence” is a genuinely useful simplification.

Reusing the existing joint AES-GCM machinery is preferable to introducing a second TLS 1.3-specific AEAD implementation, provided you treat it as **reuse of the AES-GCM primitive**, not reuse of the TLS 1.2 record-state semantics. The nonce mapping is sound for AES-GCM’s 96-bit nonce:

```text
TLS 1.2 circuit input:
    fixed_iv[0..4] || explicit_nonce[0..8]

TLS 1.3 mapping:
    write_iv[0..4] || (write_iv[4..12] XOR seq_be)
```

That reconstructs exactly:

```text
write_iv XOR (0^32 || seq_be)
```

which is the RFC 8446 construction. TLS 1.3 maintains independent read and write sequence numbers, resets them to zero whenever the corresponding traffic key changes, and requires the first record under each traffic key to use sequence number zero.  [oai_citation:0‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8446?utm_source=chatgpt.com)

The current plaintext-key decoding is indeed a protocol-breaking issue, not merely an implementation weakness. If the prover learns the complete server application key, server-response provenance no longer holds.

My main advice is: **do not make nonce uniqueness the caller’s responsibility. Make it an invariant of the record layer’s type and state machine.**

---

# 1. Epoch and sequence management

Your worry is justified, but I would frame the invariant slightly differently:

> A `(direction, traffic-key identity, sequence number)` tuple may be consumed at most once.

“Epoch” alone is too ambiguous. In TLS 1.3 there are at least:

- early-data keys, where supported;
- handshake traffic keys;
- application traffic secret generation 0;
- application traffic secret generation 1, 2, … after `KeyUpdate`.

Read and write directions also evolve independently.

## Record layer must own sequence numbers

Do not expose this API:

```rust
encrypt_record(key, iv, seq, plaintext)
```

or even:

```rust
record_layer.set_encrypt(keys);
record_layer.encrypt(seq, plaintext);
```

The TLS state machine should never supply the sequence number.

Use something closer to:

```rust
pub struct WriteEpoch {
    id: EpochId,
    key: SecretKeyRef,
    iv: SecretIvRef,
    next_seq: u64,
    state: EpochState,
}

impl WriteEpoch {
    pub async fn encrypt_next(
        &mut self,
        plaintext: SecretBytes,
        aad: PublicBytes,
    ) -> Result<Ciphertext, RecordError>;
}
```

Inside `encrypt_next`:

1. Check the epoch is active.
2. Check `next_seq != u64::MAX`, or reject before wrap.
3. Reserve the current sequence number.
4. Increment or permanently burn it.
5. Construct the nonce.
6. Run joint AEAD.
7. Return the ciphertext.

The caller never selects or resets `seq`.

## Atomic key transition

Avoid independent calls such as:

```rust
set_encrypt(key, iv);
reset_encrypt_sequence();
```

That creates an intermediate invalid state.

Installation should be atomic:

```rust
pub struct TrafficKeys {
    pub key: SecretKeyRef,
    pub iv: SecretIvRef,
    pub secret_commitment: Digest,
}

pub fn install_write_epoch(
    &mut self,
    transition: WriteEpochTransition,
) -> Result<EpochId>;
```

For example:

```rust
pub enum WriteEpochTransition {
    HandshakeToApplication {
        keys: TrafficKeys,
    },
    KeyUpdate {
        previous_epoch: EpochId,
        next_generation: u64,
        keys: TrafficKeys,
    },
}
```

The record layer should reject:

- installation of the same epoch twice;
- transition from the wrong predecessor;
- generation rollback;
- reinstalling an old key identity;
- encrypting after an epoch has been retired.

## Bind epoch identity to key material

Do not identify an epoch solely as `Handshake` or `Application`.

Use an identity such as:

```rust
pub struct EpochId {
    direction: Direction,
    kind: EpochKind,
    generation: u64,
    key_commitment: Digest,
    iv_commitment: Digest,
}
```

The commitments do not reveal the keys but stop accidental aliasing of two state objects.

For application traffic:

```text
client/application/0
server/application/0
client/application/1
server/application/1
```

must be distinct state domains.

## Burn nonces on failure

For encryption, once an AEAD computation begins with a `(key, nonce)`, that nonce should be considered consumed even when:

- MPC aborts;
- the peer disconnects;
- ciphertext transmission fails;
- a later TLS-state check fails.

Do not retry encryption using the same sequence number.

The safest rule is:

> Any failed joint encryption aborts that TLS connection.

That may be conservative, but it avoids needing transactional rollback across distributed MPC state.

## Important nuance about the stale-key bug

Using the wrong epoch does not automatically mean GCM nonce reuse. It becomes nonce reuse only if the same key is used again with a sequence number previously consumed under that key.

For example:

```text
handshake key, seq 0    used once
application key, seq 0  used once
```

is safe because the keys differ.

But this is dangerous:

```text
handshake key, seq 0    used
switch mistakenly resets counter
handshake key, seq 0    used again
```

So the dangerous operation is not “sequence reset” by itself. It is:

```text
reset sequence without proving installation of a fresh traffic key
```

Make those inseparable.

---

# 2. Authenticated release must be cryptographically enforced

This is probably the most important unresolved point after key secrecy.

An API convention saying:

```text
decrypt
then verify tag
then release
```

is insufficient if either party can reconstruct plaintext before verification completes.

AES-GCM decryption computes CTR plaintext independently of tag validity. Therefore, the MPC architecture must prevent the prover from obtaining the final plaintext reconstruction material until the tag has been accepted.

TLS 1.3 defines decryption as one operation whose result is either authenticated plaintext or failure; on failure, the connection must terminate with `bad_record_mac`.  [oai_citation:1‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8446?utm_source=chatgpt.com)

## Desired construction

Conceptually:

```text
P = ciphertext XOR keystream
expected_tag = GHASH(...) XOR E_K(J0)
valid = constant_time_equal(expected_tag, received_tag)

release P only if valid == 1
```

But “release” must be implemented through cryptographic gating.

A good structure is:

```text
plaintext = plaintext_share_prover XOR plaintext_share_verifier
```

The prover may possess its own share before verification, but the verifier must not release its reconstruction share—or a one-time-pad opening—until the tag-validity result is established.

The output type should encode this:

```rust
pub struct PendingPlaintext {
    prover_share: SecretShareRef,
    verifier_mask: OneTimePadShared,
    authentication: PendingTagVerification,
}

pub struct AuthenticatedPlaintext {
    bytes: PrivateBytes,
}
```

Only one function should convert between them:

```rust
impl PendingPlaintext {
    pub async fn authenticate_and_release(
        self,
        vm: &mut Vm,
        received_tag: &[u8; 16],
    ) -> Result<AuthenticatedPlaintext, BadRecordMac>;
}
```

There should be no generic `decode()` available on `PendingPlaintext`.

## Verify the direction of OTP sharing

The phrase “`j0` delivered as `OneTimePadShared`” deserves scrutiny.

You need to confirm exactly:

- who receives which share;
- whether either party can reconstruct `E_K(J0)` early;
- whether the prover can derive the expected tag before the verifier authorizes release;
- whether the same OTP machinery is reused across records;
- whether aborts reveal reconstruction masks.

The correct security question is not merely “does `verify_tags()` run first?” It is:

> Before `verify_tags()` returns success, does the malicious prover’s complete view computationally hide the record plaintext?

That should become a dedicated adversarial test.

## Batch verification creates extra risk

If `verify_tags` verifies several records after plaintext processing has already proceeded, ensure no later processing leaks information derived from unauthenticated plaintext.

For example, before authentication succeeds, do not:

- parse `TLSInnerPlaintext`;
- inspect the content type;
- remove padding;
- feed handshake bytes into the transcript;
- dispatch application data;
- derive subsequent keys from a Finished message;
- vary network behavior based on plaintext.

The authenticated-release boundary should occur before all TLS semantic processing.

---

# 3. Public sequence numbers are fine—with one qualification

Yes, marking `seq` public is cryptographically reasonable.

The TLS sequence number is implicit rather than transmitted, but both endpoints know it from record order. It is not intended as a secret. RFC 8446 relies on independently maintained record order and separate read/write counters.  [oai_citation:2‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8446?utm_source=chatgpt.com)

The XOR:

```text
secret IV tail XOR public seq
```

produces a secret nonce reference. It does not reveal the IV merely because the other operand is public.

The qualification is **metadata privacy**.

A verifier participating in every record-layer operation probably already observes:

- record count;
- record lengths;
- direction;
- timing.

In that model, exposing the sequence number adds nothing meaningful. TLSNotary itself describes the verifier as participating in the MPC-TLS connection while hidden application data remains private.  [oai_citation:3‡TLSNotary](https://tlsnotary.org/docs/extension/verifier/?utm_source=chatgpt.com)

Still, document the leakage explicitly:

```text
Public metadata:
- record direction
- ordinal/sequence number
- ciphertext length
- timing, subject to transport behavior
```

That prevents future claims that record count is hidden.

## Prefer constants over allocated public VM values

If the VM supports circuit constants or public immutable inputs, use those rather than a mutable allocated value that is later assigned and committed.

You want:

```rust
let seq_ref = vm.public_constant(seq.to_be_bytes());
```

rather than an object whose lifecycle allows:

- reassignment;
- disagreement between parties;
- use before commitment;
- accidental reuse with a different value.

Also bind `seq` to the `EpochId` in any transcript or operation identifier.

---

# 4. The TLS 1.3 AAD details need exact treatment

Your AAD observation is correct, but make the type and length semantics very explicit.

For TLS 1.3:

```text
additional_data =
    TLSCiphertext.opaque_type        // application_data = 23
    || legacy_record_version         // 0x0303
    || TLSCiphertext.length          // ciphertext + tag length
```

The length is the length of `encrypted_record`, meaning the AEAD ciphertext including the authentication tag—not plaintext length. RFC 8446 defines the record header as AEAD additional data.  [oai_citation:4‡IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc8446?utm_source=chatgpt.com)

A safe helper would take the final encrypted length:

```rust
fn tls13_aad(encrypted_record_len: u16) -> [u8; 5] {
    [
        23,
        0x03,
        0x03,
        (encrypted_record_len >> 8) as u8,
        encrypted_record_len as u8,
    ]
}
```

Avoid passing a generic `len` without making its unit/type unambiguous.

Use a new type:

```rust
pub struct CiphertextLength(u16);
```

so plaintext length cannot accidentally be supplied.

---

# 5. Validate the J0/counter assumptions carefully

For a 96-bit GCM nonce:

```text
J0 = nonce || 0x00000001
```

CTR encryption of the plaintext begins with:

```text
inc32(J0) = nonce || 0x00000002
```

So your note that counter block 1 is reserved for tag masking and plaintext keystream starts at counter 2 is correct.

However, I would add tests that do not just compare final AEAD outputs. Test the internal blocks:

```text
J0
E_K(J0)
counter block 2
counter block 3
```

for both TLS 1.2 and TLS 1.3 paths.

This guards against subtle disagreements about whether `assign_counters(2..)` interprets the supplied values as:

- raw counter values;
- block offsets;
- pre-increment values;
- post-increment values.

The layout match is valuable, but it is also exactly the kind of clever reuse that future maintainers may misunderstand.

Add a comment containing the equations, not merely “TLS 1.3 nonce compatibility.”

---

# 6. Keep TLS 1.2 and TLS 1.3 framing separate

Reuse the lower-level AEAD machinery, but do not create one highly parameterized record-layer function with booleans such as:

```rust
encrypt_record(is_tls13, has_explicit_nonce, include_seq_in_aad, ...)
```

Prefer:

```rust
trait JointAead {
    // Primitive operations only.
}

struct Tls12RecordProtector<A: JointAead> {
    aead: A,
    // TLS 1.2 state
}

struct Tls13RecordProtector<A: JointAead> {
    aead: A,
    // TLS 1.3 epoch state
}
```

They may share:

- AES key schedule;
- CTR keystream generation;
- GHASH;
- tag comparison;
- authenticated-release machinery.

They should not share:

- nonce construction;
- AAD construction;
- sequence lifecycle;
- record framing;
- epoch transitions.

That preserves the optimization without importing TLS 1.2 assumptions into TLS 1.3.

---

# 7. Malicious versus semi-honest security is release-blocking

You are right that this question determines what security claim can be made.

There are several distinct malicious behaviors to consider:

1. **Incorrect circuit execution**  
   One party tries to cause a false AES, GHASH, XOR, or comparison result.

2. **Inconsistent inputs**  
   A party supplies different key shares, IV shares, ciphertext, tag, or AAD across subprotocols.

3. **Selective failure**  
   A party learns information from whether the other side aborts.

4. **Premature decoding**  
   A party obtains outputs before authentication or consistency checks.

5. **State equivocation**  
   A party uses different epoch or sequence identities in different MPC components.

6. **OT/OLE attacks**  
   The underlying oblivious-transfer or correlated-randomness protocol is secure only for honest-but-curious participants.

Do not collapse all of this into “is garbling malicious-secure?”

Even if the garbled-circuit protocol is malicious-secure, composition can still fail if:

- an input is not committed consistently;
- plaintext reconstruction happens outside the secure computation;
- tag validity is accepted from one party rather than jointly established;
- VM references can be rebound;
- transcript state is not authenticated.

I could not verify from the publicly indexed material which exact active-security guarantees the current MPZ stack provides. Until that is established from the implementation and protocol documentation, describe the TLS 1.3 path as:

```text
functionally correct joint execution under the assumed MPZ adversary model
```

not:

```text
secure against a malicious prover
```

## Create a security-assumption inventory

For every primitive, record:

| Component | Required property |
|---|---|
| Garbled circuits | malicious security or explicit semi-honest assumption |
| OT extension | sender/receiver security under chosen inputs |
| OLE/VOLE | active consistency, if used |
| VM input assignment | binding and non-equivocation |
| Decode/reveal | authorized recipient and timing |
| Shared AES | neither party learns full key |
| GHASH | authenticated, consistent inputs |
| Tag comparison | maliciously robust equality result |
| OTP release | no reconstruction before valid tag |
| Commitments | binding and domain-separated |

This should be part of the PR, not postponed to a later audit.

---

# 8. Tests I would require before removing `Tls13Unsafe`

Your current equivalence tests are good primitive tests. They are not yet protocol-security tests.

Add these.

## Nonce-state tests

```text
- first record under every epoch uses sequence 0
- second record uses sequence 1
- read and write counters are independent
- handshake and application counters are independent
- KeyUpdate resets only the affected direction
- reinstalling the same key commitment is rejected
- resetting sequence without a fresh key is impossible
- sequence overflow aborts before AEAD invocation
- failed encryption burns the sequence number or kills connection
- concurrent encrypt calls cannot reserve the same sequence
```

That last test matters if async record writes are possible.

## Epoch-confusion tests

Inject faults:

```text
- server Finished encrypted under handshake keys
- first application record encrypted under application keys
- delayed handshake record after application-key installation
- duplicate set_encrypt call
- stale epoch handle used after transition
- client write transition without server read transition
- KeyUpdate in only one direction
```

The expected result must be deterministic rejection, not merely “eventual tag mismatch.”

## Authenticated-release tests

A malicious prover should be unable to distinguish chosen plaintexts when:

```text
- tag is invalid
- AAD is invalid
- ciphertext is modified
- sequence number is wrong
- epoch is wrong
- verifier aborts before tag approval
```

Instrument the VM and assert that no decode/open/reconstruction operation involving plaintext occurs before `valid == true`.

A static audit test could search for forbidden calls:

```text
vm.decode(...)
```

on types carrying:

- traffic keys;
- write IVs;
- pending plaintext;
- GHASH subkeys;
- `E_K(J0)`.

## Forgery test

The most valuable end-to-end regression test is:

1. Run a real server handshake.
2. Let the malicious prover attempt to substitute chosen response plaintext.
3. Attempt to create a matching ciphertext/tag using everything visible to the prover.
4. Assert the verifier rejects.
5. Assert no full server key or reusable tag material is present in prover memory or decoded VM outputs.

## Differential tests

Compare against at least two independent TLS implementations, such as rustls and OpenSSL, for:

- record ciphertext;
- nonce;
- AAD;
- tag;
- padding;
- fragmented records;
- zero-length application content where permitted;
- alert and handshake inner content types.

---

# 9. Performance: lazy allocation is acceptable for the first secure version

Losing preprocessing overlap is unfortunate, but it is not a reason to weaken state separation.

Correctness first:

```text
derive application traffic keys
→ install epoch
→ allocate nonce-bound joint AEAD
→ process record
```

Afterward, regain overlap with **nonce-independent preprocessing**.

Possible split:

```text
Offline:
- garbled AES/GHASH material
- OTs
- multiplication triples/OLE correlations
- generic circuit allocation

Online:
- bind key references
- bind secret nonce reference
- bind ciphertext/AAD
- evaluate
```

The fact that a current keystream object is bound to one nonce reference may be an implementation limitation rather than a cryptographic requirement. Later, refactor the AEAD engine into:

```rust
PreparedAesGcm
    + per-record SecretNonceBinding
    + per-record PublicAadBinding
```

But do not optimize this until the authenticated release path is demonstrably correct.

---

# Recommended implementation order

I would change the order slightly:

1. **Remove all complete-key decoding**, even if TLS 1.3 remains unusable afterward.
2. Introduce typed `ReadEpoch` and `WriteEpoch` objects that exclusively own counters.
3. Add atomic traffic-key installation and epoch retirement.
4. Wire joint CTR encryption/decryption with the secret TLS 1.3 nonce.
5. Wire TLS 1.3-specific AAD.
6. Wire GHASH and `E_K(J0)`.
7. Implement cryptographically gated authenticated release.
8. Add malicious-state and nonce-reuse tests.
9. Audit the MPZ adversary model and state the actual guarantee.
10. Only then remove `Tls13Unsafe`.

## Bottom line

The primitive reuse is elegant and technically sound. The biggest risk is not the nonce byte mapping; it is **distributed state management around that mapping**.

I would approve the approach under these conditions:

- sequence numbers are private to the record layer;
- fresh-key installation and counter reset are one atomic operation;
- epoch identities are explicit, directional, generational, and bound to key commitments;
- failed encryption consumes the nonce or terminates the connection;
- plaintext reconstruction is cryptographically impossible before tag acceptance;
- the security claim is limited to the verified MPZ adversary model;
- TLS 1.3 reuses AES-GCM internals but has its own record protector and state machine.

The concise design rule is:

```text
Never pass a sequence number into AEAD.
Ask an active traffic epoch to consume its next nonce.
```

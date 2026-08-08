/-!
Machine-checked state invariants for TLS 1.3 directional epochs.

This is a mathematical specification, not yet a refinement proof for the Rust
`ReadEpoch` and `WriteEpoch` types. The refinement boundary is explicit in
`docs/research/tls13-formal-spec.md`.
-/

namespace Tls13

def sequenceLimit : Nat := 2 ^ 64

structure Epoch where
  generation : Nat
  nextSequence : Nat

def reserve (epoch : Epoch) : Option (Nat × Epoch) :=
  if epoch.nextSequence < sequenceLimit then
    some (epoch.nextSequence, { epoch with nextSequence := epoch.nextSequence + 1 })
  else
    none

theorem reserve_success (epoch : Epoch) (h : epoch.nextSequence < sequenceLimit) :
    reserve epoch =
      some (epoch.nextSequence, { epoch with nextSequence := epoch.nextSequence + 1 }) := by
  simp [reserve, h]

theorem reserve_returns_owned_sequence
    (epoch next : Epoch) (sequence : Nat)
    (h : reserve epoch = some (sequence, next)) :
    sequence = epoch.nextSequence := by
  unfold reserve at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    rcases h with ⟨rfl, rfl⟩
    rfl
  · contradiction

theorem reserve_advances_exactly_once
    (epoch next : Epoch) (sequence : Nat)
    (h : reserve epoch = some (sequence, next)) :
    next.nextSequence = epoch.nextSequence + 1 := by
  unfold reserve at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    rcases h with ⟨rfl, rfl⟩
    rfl
  · contradiction

theorem reserve_preserves_generation
    (epoch next : Epoch) (sequence : Nat)
    (h : reserve epoch = some (sequence, next)) :
    next.generation = epoch.generation := by
  unfold reserve at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    rcases h with ⟨rfl, rfl⟩
    rfl
  · contradiction

theorem reserve_never_returns_wrapped_sequence
    (epoch next : Epoch) (sequence : Nat)
    (h : reserve epoch = some (sequence, next)) :
    sequence < sequenceLimit := by
  unfold reserve at h
  split at h <;> simp_all

theorem exhausted_epoch_rejects (epoch : Epoch)
    (h : sequenceLimit ≤ epoch.nextSequence) :
    reserve epoch = none := by
  simp [reserve, Nat.not_lt.mpr h]

theorem consecutive_reservations_are_distinct
    (epoch next final : Epoch) (first second : Nat)
    (h₁ : reserve epoch = some (first, next))
    (h₂ : reserve next = some (second, final)) :
    first ≠ second := by
  have first_eq := reserve_returns_owned_sequence epoch next first h₁
  have next_eq := reserve_advances_exactly_once epoch next first h₁
  have second_eq := reserve_returns_owned_sequence next final second h₂
  omega

/- RFC 8446 section 5.3: a 96-bit IV is split into a 32-bit prefix and
   64-bit suffix; the padded sequence is XORed into the suffix. -/
def nonce (iv : BitVec 32 × BitVec 64) (sequence : BitVec 64) :
    BitVec 32 × BitVec 64 :=
  (iv.1, iv.2 ^^^ sequence)

theorem xor_left_cancel {width : Nat} (left a b : BitVec width)
    (h : left ^^^ a = left ^^^ b) : a = b := by
  have h₂ := congrArg (fun value => left ^^^ value) h
  simpa [← BitVec.xor_assoc] using h₂

theorem nonce_injective_for_fixed_iv
    (iv : BitVec 32 × BitVec 64) (a b : BitVec 64)
    (h : nonce iv a = nonce iv b) : a = b := by
  have suffix_eq : iv.2 ^^^ a = iv.2 ^^^ b := congrArg Prod.snd h
  exact xor_left_cancel iv.2 a b suffix_eq

theorem distinct_sequences_produce_distinct_nonces
    (iv : BitVec 32 × BitVec 64) (a b : BitVec 64)
    (h : a ≠ b) : nonce iv a ≠ nonce iv b := by
  intro nonce_eq
  exact h (nonce_injective_for_fixed_iv iv a b nonce_eq)

end Tls13

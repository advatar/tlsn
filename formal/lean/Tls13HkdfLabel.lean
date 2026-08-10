/-!
Machine-checked framing specification for TLS 1.3 HKDF-Expand-Label.

This proves the structural part of the Rust `make_hkdf_label` encoder: the
two-byte output length, one-byte prefixed-label length, literal `tls13 `
prefix, one-byte context length, and context bytes. Cryptographic HMAC
correctness remains outside this file.
-/

namespace Tls13

def labelPrefix : List UInt8 := [116, 108, 115, 49, 51, 32] -- "tls13 "

def u16Bytes (n : Nat) : List UInt8 :=
  [UInt8.ofNat (n / 256), UInt8.ofNat n]

def u8Byte (n : Nat) : List UInt8 := [UInt8.ofNat n]

def hkdfLabel (label context : List UInt8) (outputLength : Nat) : List UInt8 :=
  u16Bytes outputLength ++
    u8Byte (labelPrefix.length + label.length) ++
    labelPrefix ++ label ++
    u8Byte context.length ++ context

theorem labelPrefix_length : labelPrefix.length = 6 := by
  rfl

theorem hkdfLabel_length (label context : List UInt8) (outputLength : Nat) :
    (hkdfLabel label context outputLength).length =
      2 + 1 + 6 + label.length + 1 + context.length := by
  simp [hkdfLabel, u16Bytes, u8Byte, labelPrefix_length, Nat.add_assoc,
    Nat.add_comm, Nat.add_left_comm]

theorem hkdfLabel_starts_with_length_and_prefix
    (label context : List UInt8) (outputLength : Nat) :
    (hkdfLabel label context outputLength).take 3 =
      (u16Bytes outputLength ++ u8Byte (labelPrefix.length + label.length)).take 3 := by
  simp [hkdfLabel, u16Bytes, u8Byte, List.take_append]

theorem hkdfLabel_output_length_bytes
    (label context : List UInt8) (outputLength : Nat) :
    (hkdfLabel label context outputLength).take 2 = u16Bytes outputLength := by
  simp [hkdfLabel, u16Bytes]

theorem hkdfLabel_prefixed_label_length_byte
    (label context : List UInt8) (outputLength : Nat) :
    (hkdfLabel label context outputLength)[2]? =
      some (UInt8.ofNat (labelPrefix.length + label.length)) := by
  simp [hkdfLabel, u16Bytes, u8Byte]

theorem hkdfLabel_context_length_byte
    (label context : List UInt8) (outputLength : Nat) :
    (hkdfLabel label context outputLength).drop
        (u16Bytes outputLength ++
          u8Byte (labelPrefix.length + label.length) ++
          labelPrefix ++ label).length =
      u8Byte context.length ++ context := by
  simp [hkdfLabel]

end Tls13

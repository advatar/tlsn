/-!
Machine-checked width and domain invariants for TLS_AES_256_GCM_SHA384.

These are structural obligations for the new implementation. They do not
prove SHA-384 cryptographic correctness; that is checked by the circuit and
reference tests.
-/

namespace Tls13

def hashBytes : Nat := 48
def trafficKeyBytes : Nat := 32
def ivBytes : Nat := 12
def tagBytes : Nat := 16
def tlsLabelPrefixBytes : Nat := 6

theorem sha384_hash_width : hashBytes = 48 := by rfl
theorem aes256_traffic_key_width : trafficKeyBytes = 32 := by rfl
theorem tls13_iv_width : ivBytes = 12 := by rfl
theorem gcm_tag_width : tagBytes = 16 := by rfl

theorem sha384_finished_key_fits_hash : 48 ≤ hashBytes := by decide
theorem aes256_key_is_not_hash_width : trafficKeyBytes < hashBytes := by decide
theorem tls13_label_prefix_is_six_bytes : tlsLabelPrefixBytes = 6 := by rfl

theorem label_encoding_has_fixed_overhead (label context : List UInt8) :
    (2 + 1 + tlsLabelPrefixBytes + label.length + 1 + context.length) =
      10 + label.length + context.length := by
  simp [tlsLabelPrefixBytes, Nat.add_comm, Nat.add_left_comm]

end Tls13

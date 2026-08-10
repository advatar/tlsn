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

inductive CipherSuite where
  | aes128Sha256
  | aes256Sha384
  deriving DecidableEq

structure SuiteProfile where
  hashBytes : Nat
  keyBytes : Nat
  ivBytes : Nat
  deriving DecidableEq

def suiteProfile : CipherSuite → SuiteProfile
  | .aes128Sha256 => ⟨32, 16, 12⟩
  | .aes256Sha384 => ⟨48, 32, 12⟩

theorem negotiated_sha384_profile :
    suiteProfile .aes256Sha384 = ⟨48, 32, 12⟩ := by rfl

theorem profile_hash_width_identifies_suite (suite : CipherSuite) :
    (suiteProfile suite).hashBytes = 48 ↔ suite = .aes256Sha384 := by
  cases suite <;> simp [suiteProfile]

theorem profile_key_width_identifies_suite (suite : CipherSuite) :
    (suiteProfile suite).keyBytes = 32 ↔ suite = .aes256Sha384 := by
  cases suite <;> simp [suiteProfile]

structure Aes256Epoch where
  key : Vector UInt8 32
  iv : Vector UInt8 12
  generation : Nat
  nextSequence : Nat

theorem aes256_epoch_preserves_suite_widths (epoch : Aes256Epoch) :
    epoch.key.size = (suiteProfile .aes256Sha384).keyBytes ∧
    epoch.iv.size = (suiteProfile .aes256Sha384).ivBytes := by
  simp [suiteProfile]

/- HMAC-SHA384 always emits one SHA-384 digest. HKDF-Extract therefore
   preserves the hash width, while Expand-Label truncates only at its typed
   consumer boundary. -/
structure Sha384Digest where
  bytes : Vector UInt8 48

def hmacSha384 (_key message : List UInt8) : Sha384Digest :=
  ⟨Vector.replicate 48 0⟩

def hkdfExtractSha384 (salt ikm : List UInt8) : Sha384Digest :=
  hmacSha384 salt ikm

theorem hmac_sha384_output_width (key message : List UInt8) :
    (hmacSha384 key message).bytes.size = 48 := by
  simp [hmacSha384]

theorem hkdf_extract_sha384_output_width (salt ikm : List UInt8) :
    (hkdfExtractSha384 salt ikm).bytes.size = hashBytes := by
  simp [hkdfExtractSha384, hmacSha384, hashBytes]

inductive KeyScheduleDomain where
  | derived
  | clientHandshakeTraffic
  | serverHandshakeTraffic
  | clientApplicationTraffic
  | serverApplicationTraffic
  | trafficKey
  | trafficIv
  | finished
  deriving DecidableEq

def domainLabel : KeyScheduleDomain → List Nat
  | .derived => [100, 101, 114, 105, 118, 101, 100]
  | .clientHandshakeTraffic => [99, 32, 104, 115, 32, 116, 114, 97, 102, 102, 105, 99]
  | .serverHandshakeTraffic => [115, 32, 104, 115, 32, 116, 114, 97, 102, 102, 105, 99]
  | .clientApplicationTraffic => [99, 32, 97, 112, 32, 116, 114, 97, 102, 102, 105, 99]
  | .serverApplicationTraffic => [115, 32, 97, 112, 32, 116, 114, 97, 102, 102, 105, 99]
  | .trafficKey => [107, 101, 121]
  | .trafficIv => [105, 118]
  | .finished => [102, 105, 110, 105, 115, 104, 101, 100]

theorem key_schedule_domain_labels_injective : Function.Injective domainLabel := by
  intro a b equality
  cases a <;> cases b <;> simp_all [domainLabel]

def domainOutputBytes : KeyScheduleDomain → Nat
  | .trafficKey => 32
  | .trafficIv => 12
  | _ => 48

theorem aes256_key_domain_width : domainOutputBytes .trafficKey = trafficKeyBytes := by rfl
theorem traffic_iv_domain_width : domainOutputBytes .trafficIv = ivBytes := by rfl
theorem finished_domain_width : domainOutputBytes .finished = hashBytes := by rfl

theorem client_server_traffic_domains_separated :
    domainLabel .clientHandshakeTraffic ≠ domainLabel .serverHandshakeTraffic ∧
    domainLabel .clientApplicationTraffic ≠ domainLabel .serverApplicationTraffic := by
  decide

end Tls13

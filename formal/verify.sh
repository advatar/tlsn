#!/usr/bin/env bash
set -euo pipefail

model="formal/tamarin/tls13_joint_aead.spthy"
proof_output="$(mktemp /tmp/tlsn-tamarin-proof.XXXXXX)"
handshake_proof_output="$(mktemp /tmp/tlsn-tamarin-handshake-proof.XXXXXX)"
trap 'rm -f "$proof_output" "$handshake_proof_output"' EXIT

lean formal/lean/Tls13Epoch.lean
cargo kani -p tlsn-mpc-tls --quiet --output-format terse

tamarin-prover --prove --quiet "$model" | tee "$proof_output"

lemmas=(
  honest_execution
  application_key_secrecy
  authenticated_plaintext_release
  nonce_tuple_unique
  read_slot_single_use
)

for lemma in "${lemmas[@]}"; do
  if ! grep -Eq "^[[:space:]]+${lemma} .*: verified" "$proof_output"; then
    printf 'required Tamarin lemma was not verified: %s\n' "$lemma" >&2
    exit 1
  fi
done

printf 'verified %d required Tamarin lemmas\n' "${#lemmas[@]}"

tamarin-prover --prove --quiet \
  formal/tamarin/tls13_handshake_transcript.spthy \
  | tee "$handshake_proof_output"

handshake_lemmas=(
  handshake_executable
  handshake_agreement
  application_epoch_agreement
  presentation_agreement
  server_identity_is_bound
)

for lemma in "${handshake_lemmas[@]}"; do
  if ! grep -Eq "^[[:space:]]+${lemma} .*: verified" "$handshake_proof_output"; then
    printf 'required handshake Tamarin lemma was not verified: %s\n' "$lemma" >&2
    exit 1
  fi
done

printf 'verified %d required handshake/transcript Tamarin lemmas\n' \
  "${#handshake_lemmas[@]}"

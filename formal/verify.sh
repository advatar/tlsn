#!/usr/bin/env bash
set -euo pipefail

model="formal/tamarin/tls13_joint_aead.spthy"
proof_output="$(mktemp /tmp/tlsn-tamarin-proof.XXXXXX)"
handshake_proof_output="$(mktemp /tmp/tlsn-tamarin-handshake-proof.XXXXXX)"
selective_proof_output="$(mktemp /tmp/tlsn-tamarin-selective-proof.XXXXXX)"
schedule_proof_output="$(mktemp /tmp/tlsn-tamarin-schedule-proof.XXXXXX)"
trap 'rm -f "$proof_output" "$handshake_proof_output" "$selective_proof_output" "$schedule_proof_output"' EXIT

lean formal/lean/Tls13Epoch.lean
lean formal/lean/Tls13HkdfLabel.lean
lean formal/lean/Tls13Sha384.lean
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

tamarin-prover --diff --prove --quiet \
  formal/tamarin/tls13_selective_disclosure.spthy \
  | tee "$selective_proof_output"

if ! grep -Eq "Observational_equivalence .*verified" \
  "$selective_proof_output"; then
  printf 'selective-disclosure observational equivalence was not verified\n' >&2
  exit 1
fi

printf 'verified selective-disclosure observational equivalence\n'

tamarin-prover --prove --quiet \
  formal/tamarin/tls13_key_schedule.spthy \
  | tee "$schedule_proof_output"

schedule_lemmas=(
  finished_is_executable
  finished_acceptance_requires_emission
  application_secret_requires_finished
  application_secret_context_is_transcript_bound
  application_secret_has_tls13_label_and_context
)

for lemma in "${schedule_lemmas[@]}"; do
  if ! grep -Eq "^[[:space:]]+${lemma} .*: verified" "$schedule_proof_output"; then
    printf 'required key-schedule Tamarin lemma was not verified: %s\n' "$lemma" >&2
    exit 1
  fi
done

printf 'verified %d TLS 1.3 key-schedule/Finished lemmas\n' \
  "${#schedule_lemmas[@]}"

use mpc_tls::SessionKeys;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::iter::RangeIterator;
use rangeset::ops::Set;
use rangeset::set::RangeSet;
use tlsn_core::{
    VerifierOutput,
    config::prove::ProveRequest,
    connection::{HandshakeData, ServerName, TlsVersion},
    transcript::{
        ContentType, Direction, PartialTranscript, Record, TlsTranscript, TranscriptCommitment,
    },
    webpki::ServerCertVerifier,
};

use crate::{
    Error, Result,
    transcript_internal::{
        TranscriptRefs,
        auth::{commit_public_plaintext, verify_plaintext},
        commit::hash::verify_hash,
    },
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &SessionKeys,
    cert_verifier: &ServerCertVerifier,
    tls_transcript: &TlsTranscript,
    request: ProveRequest,
    handshake: Option<(ServerName, HandshakeData)>,
    transcript: Option<PartialTranscript>,
) -> Result<VerifierOutput> {
    let ciphertext_sent = collect_ciphertext(tls_transcript.sent());
    let ciphertext_recv = collect_ciphertext(tls_transcript.recv());
    let full_transcript = (tls_transcript.version() == &TlsVersion::V1_3)
        .then(|| tls_transcript.to_transcript())
        .transpose()
        .map_err(|e| {
            Error::internal()
                .with_msg("verification failed: tls13 transcript is incomplete")
                .with_source(e)
        })?;
    let (expected_sent_len, expected_recv_len) = if let Some(full_transcript) = &full_transcript {
        full_transcript.len()
    } else {
        (ciphertext_sent.len(), ciphertext_recv.len())
    };

    let transcript = if let Some((auth_sent, auth_recv)) = request.reveal() {
        let Some(transcript) = transcript else {
            return Err(Error::internal().with_msg(
                "verification failed: prover requested to reveal data but did not send transcript",
            ));
        };

        if transcript.len_sent() != expected_sent_len
            || transcript.len_received() != expected_recv_len
        {
            return Err(
                Error::internal().with_msg("verification failed: transcript length mismatch")
            );
        }

        if transcript.sent_authed() != auth_sent {
            return Err(Error::internal().with_msg("verification failed: sent auth data mismatch"));
        }

        if transcript.received_authed() != auth_recv {
            return Err(
                Error::internal().with_msg("verification failed: received auth data mismatch")
            );
        }

        transcript
    } else {
        PartialTranscript::new(expected_sent_len, expected_recv_len)
    };

    let server_name = if let Some((name, cert_data)) = handshake {
        if &cert_data.binding != tls_transcript.certificate_binding() {
            return Err(
                Error::internal().with_msg("verification failed: handshake binding mismatch")
            );
        }

        cert_data
            .verify(
                cert_verifier,
                tls_transcript.time(),
                tls_transcript.server_ephemeral_key(),
                &name,
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed: certificate verification failed")
                    .with_source(e)
            })?;

        Some(name)
    } else {
        None
    };

    let (mut commit_sent, mut commit_recv) = (RangeSet::default(), RangeSet::default());
    if let Some(commit_config) = request.transcript_commit() {
        commit_config
            .iter_hash()
            .for_each(|(direction, idx, _)| match direction {
                Direction::Sent => commit_sent.union_mut(idx),
                Direction::Received => commit_recv.union_mut(idx),
            });
    }

    if let Some(full_transcript) = &full_transcript {
        for range in transcript.sent_authed().iter() {
            if transcript.sent_unsafe()[range.clone()] != full_transcript.sent()[range] {
                return Err(Error::internal()
                    .with_msg("verification failed: sent transcript reveal mismatch"));
            }
        }

        for range in transcript.received_authed().iter() {
            if transcript.received_unsafe()[range.clone()] != full_transcript.received()[range] {
                return Err(Error::internal()
                    .with_msg("verification failed: received transcript reveal mismatch"));
            }
        }
    }

    let (sent_refs, sent_proof) = if tls_transcript.version() == &TlsVersion::V1_3 {
        let full_transcript = full_transcript
            .as_ref()
            .expect("tls13 transcript should be present");
        (
            commit_public_plaintext(
                vm,
                full_transcript.sent(),
                &commit_sent.union(transcript.sent_authed()).into_set(),
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed during sent plaintext verification")
                    .with_source(e)
            })?,
            None,
        )
    } else {
        let (refs, proof) = verify_plaintext(
            vm,
            keys.client_write_key,
            keys.client_write_iv,
            transcript.sent_unsafe(),
            &ciphertext_sent,
            tls_transcript
                .sent()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData),
            transcript.sent_authed(),
            &commit_sent,
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("verification failed during sent plaintext verification")
                .with_source(e)
        })?;
        (refs, Some(proof))
    };
    let (recv_refs, recv_proof) = if tls_transcript.version() == &TlsVersion::V1_3 {
        let full_transcript = full_transcript
            .as_ref()
            .expect("tls13 transcript should be present");
        (
            commit_public_plaintext(
                vm,
                full_transcript.received(),
                &commit_recv.union(transcript.received_authed()).into_set(),
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed during received plaintext verification")
                    .with_source(e)
            })?,
            None,
        )
    } else {
        let (refs, proof) = verify_plaintext(
            vm,
            keys.server_write_key,
            keys.server_write_iv,
            transcript.received_unsafe(),
            &ciphertext_recv,
            tls_transcript
                .recv()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData),
            transcript.received_authed(),
            &commit_recv,
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("verification failed during received plaintext verification")
                .with_source(e)
        })?;
        (refs, Some(proof))
    };

    let transcript_refs = TranscriptRefs {
        sent: sent_refs,
        recv: recv_refs,
    };

    let mut transcript_commitments = Vec::new();
    let mut hash_commitments = None;
    if let Some(commit_config) = request.transcript_commit()
        && commit_config.has_hash()
    {
        hash_commitments = Some(
            verify_hash(vm, &transcript_refs, commit_config.iter_hash().cloned()).map_err(|e| {
                Error::internal()
                    .with_msg("verification failed during hash commitment setup")
                    .with_source(e)
            })?,
        );
    }

    vm.execute_all(ctx).await.map_err(|e| {
        Error::internal()
            .with_msg("verification failed during zk execution")
            .with_source(e)
    })?;

    if let Some(sent_proof) = sent_proof {
        sent_proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("verification failed: sent plaintext proof invalid")
                .with_source(e)
        })?;
    }
    if let Some(recv_proof) = recv_proof {
        recv_proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("verification failed: received plaintext proof invalid")
                .with_source(e)
        })?;
    }

    if let Some(hash_commitments) = hash_commitments {
        for commitment in hash_commitments.try_recv().map_err(|e| {
            Error::internal()
                .with_msg("verification failed during hash commitment finalization")
                .with_source(e)
        })? {
            transcript_commitments.push(TranscriptCommitment::Hash(commitment));
        }
    }

    Ok(VerifierOutput {
        server_name,
        transcript: request.reveal().is_some().then_some(transcript),
        transcript_commitments,
    })
}

fn collect_ciphertext<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    records
        .into_iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .for_each(|record| {
            ciphertext.extend_from_slice(&record.ciphertext);
        });
    ciphertext
}

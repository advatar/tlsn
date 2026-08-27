mod support;

use support::{Tls13TestCase, run_tls13_case_with_artifacts};
use tlsn::{
    attestation::{
        Attestation, AttestationConfig, CryptoProvider,
        presentation::PresentationOutput,
        request::{Request, RequestConfig},
        signing::SignatureAlgId,
    },
    connection::TlsVersion,
    transcript::Direction,
    webpki::{CertificateDer, RootCertStore, ServerCertVerifier},
};
use tlsn_server_fixture::{FixtureClientAuth, FixtureConfig, bind_with_config};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::io::duplex;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_signed_attestation_presentation_verifies_independently() {
    let (client_socket, server_socket) = duplex(2 << 16);
    let server_task = tokio::spawn(bind_with_config(
        server_socket.compat(),
        FixtureConfig::default().client_auth(FixtureClientAuth::Optional),
    ));

    let artifacts = run_tls13_case_with_artifacts(
        Tls13TestCase {
            server_name: SERVER_DOMAIN,
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            client_auth: None,
            request_path: "/bytes?size=128",
            request_headers: Vec::new(),
        },
        client_socket.compat(),
    )
    .await;
    server_task.await.unwrap().unwrap();

    assert_eq!(artifacts.connection_info.version, TlsVersion::V1_3);
    let (sent_len, recv_len) = artifacts.transcript.len();

    let mut issuer_provider = CryptoProvider::default();
    issuer_provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

    let request_config = RequestConfig::default();
    let mut request_builder = Request::builder(&request_config);
    request_builder
        .server_name(artifacts.server_name.clone())
        .handshake_data(artifacts.handshake_data)
        .transcript(artifacts.transcript)
        .transcript_commitments(
            artifacts.prover_output.transcript_secrets,
            artifacts.prover_output.transcript_commitments,
        );
    let (request, secrets) = request_builder.build(&issuer_provider).unwrap();

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();
    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request.clone())
        .unwrap();
    attestation_builder
        .connection_info(artifacts.connection_info.clone())
        .server_ephemeral_key(artifacts.server_ephemeral_key)
        .transcript_commitments(artifacts.verifier_output.transcript_commitments);
    let attestation = attestation_builder.build(&issuer_provider).unwrap();
    request.validate(&attestation, &issuer_provider).unwrap();

    let mut transcript_proof_builder = secrets.transcript_proof_builder();
    transcript_proof_builder
        .reveal(&(0..sent_len), Direction::Sent)
        .unwrap()
        .reveal(&(0..recv_len), Direction::Received)
        .unwrap();
    let transcript_proof = transcript_proof_builder.build().unwrap();

    let mut presentation_builder = attestation.presentation_builder(&issuer_provider);
    presentation_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation = presentation_builder.build().unwrap();

    let independent_provider = CryptoProvider {
        cert: ServerCertVerifier::new(&RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .unwrap(),
        ..CryptoProvider::default()
    };
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation.verify(&independent_provider).unwrap();

    assert_eq!(server_name.unwrap(), artifacts.server_name);
    assert_eq!(connection_info, artifacts.connection_info);
    let transcript = transcript.unwrap();
    assert_eq!(transcript.sent_unsafe(), secrets.transcript().sent());
    assert_eq!(
        transcript.received_unsafe(),
        secrets.transcript().received()
    );
}

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{ServerName, TlsVersion},
    hash::HashAlgId,
    prover::Prover,
    transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitmentKind},
    verifier::{Verifier, VerifierOutput},
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
};
use tlsn_core::ProverOutput;
use tokio_util::compat::TokioAsyncReadCompatExt;

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of application records sent from prover to server
const MAX_SENT_RECORDS: usize = 8;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 15;
// Maximum number of application records received by prover from server
const MAX_RECV_RECORDS: usize = 8;

#[derive(Clone)]
pub struct Tls13TestCase {
    pub server_name: &'static str,
    pub roots: Vec<CertificateDer>,
    pub client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
    pub request_path: &'static str,
    pub request_headers: Vec<(&'static str, &'static str)>,
}

impl Tls13TestCase {
    pub fn tls_client_config(&self) -> TlsClientConfig {
        let mut builder = TlsClientConfig::builder()
            .server_name(ServerName::Dns(self.server_name.try_into().unwrap()))
            .root_store(RootCertStore {
                roots: self.roots.clone(),
            });

        if let Some(client_auth) = self.client_auth.clone() {
            builder = builder.client_auth(client_auth);
        }

        builder.build().unwrap()
    }

    pub fn request_bytes(&self) -> Vec<u8> {
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.request_path, self.server_name
        );

        for (name, value) in &self.request_headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }

        request.push_str("\r\n");

        request.into_bytes()
    }
}

pub async fn run_tls13_case<S>(case: Tls13TestCase, server_socket: S) -> VerifierOutput
where
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(socket_0.compat());
    let mut session_v = Session::new(socket_1.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: case.roots.clone(),
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let ((_full_transcript, _prover_output), verifier_output) = tokio::join!(
        run_prover(prover, case.clone(), server_socket),
        run_verifier(verifier)
    );

    session_p_handle.close();
    session_v_handle.close();

    let partial_transcript = verifier_output.transcript.as_ref().unwrap();
    let ServerName::Dns(server_name) = verifier_output.server_name.as_ref().unwrap();

    assert_eq!(server_name.as_str(), case.server_name);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript.sent_authed().iter().next().unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript.received_authed().iter().next().unwrap(),
        0..10
    );

    verifier_output
}

async fn run_prover<S>(
    prover: Prover,
    case: Tls13TestCase,
    server_socket: S,
) -> (Transcript, ProverOutput)
where
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    let prover = prover
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_sent_records(MAX_SENT_RECORDS)
                        .max_recv_data(MAX_RECV_DATA)
                        .max_recv_records_online(MAX_RECV_RECORDS)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    let (mut tls_connection, prover_fut) = prover
        .connect(case.tls_client_config(), server_socket)
        .unwrap();
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(&case.request_bytes())
        .await
        .unwrap();

    let mut response = Vec::with_capacity(1024);
    tls_connection.read_to_end(&mut response).await.unwrap();
    assert!(!response.is_empty());

    let mut prover = prover_task.await.unwrap().unwrap();
    assert_eq!(*prover.tls_transcript().version(), TlsVersion::V1_3);

    let sent_tx_len = prover.transcript().sent().len();
    let recv_tx_len = prover.transcript().received().len();

    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    let kind = TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    };
    commit_builder
        .commit_with_kind(&(0..sent_tx_len), Direction::Sent, kind)
        .unwrap();
    commit_builder
        .commit_with_kind(&(0..recv_tx_len), Direction::Received, kind)
        .unwrap();
    commit_builder
        .commit_with_kind(&(1..sent_tx_len - 1), Direction::Sent, kind)
        .unwrap();
    commit_builder
        .commit_with_kind(&(1..recv_tx_len - 1), Direction::Received, kind)
        .unwrap();

    let transcript_commit = commit_builder.build().unwrap();

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    prove_builder.server_identity();
    prove_builder.reveal_sent(&(0..10)).unwrap();
    prove_builder.reveal_recv(&(0..10)).unwrap();
    prove_builder.transcript_commit(transcript_commit);

    let config = prove_builder.build().unwrap();
    let transcript = prover.transcript().clone();
    let output = prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();

    (transcript, output)
}

async fn run_verifier(verifier: Verifier) -> VerifierOutput {
    let verifier = verifier
        .commit()
        .await
        .unwrap()
        .accept()
        .await
        .unwrap()
        .run()
        .await
        .unwrap();

    let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
    verifier.close().await.unwrap();

    output
}

mod support;

use support::{Tls13TestCase, run_tls13_case};
use tlsn::webpki::CertificateDer;
use tlsn_server_fixture::{FixtureClientAuth, FixtureConfig, bind_with_config};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::io::duplex;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_tls13() {
    let _ = tracing_subscriber::fmt::try_init();

    let (client_socket, server_socket) = duplex(2 << 16);
    let server_task = tokio::spawn(bind_with_config(
        server_socket.compat(),
        FixtureConfig::default().client_auth(FixtureClientAuth::Optional),
    ));

    let verifier_output = run_tls13_case(
        Tls13TestCase {
            server_name: SERVER_DOMAIN,
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            client_auth: None,
            request_path: "/bytes?size=1024",
            request_headers: Vec::new(),
        },
        client_socket.compat(),
    )
    .await;

    server_task.await.unwrap().unwrap();
    assert!(verifier_output.transcript.is_some());
}

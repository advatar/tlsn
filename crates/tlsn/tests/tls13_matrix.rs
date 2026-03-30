mod support;

use support::{Tls13TestCase, run_tls13_case};
use tlsn::webpki::{CertificateDer, PrivateKeyDer};
use tlsn_server_fixture::{FixtureCertProfile, FixtureClientAuth, FixtureConfig, bind_with_config};
use tlsn_server_fixture_certs::{CA_CERT_DER, CLIENT_CERT_DER, CLIENT_KEY_DER, SERVER_DOMAIN};
use tokio::io::duplex;
use tokio_util::compat::TokioAsyncReadCompatExt;

async fn run_fixture_case(fixture_config: FixtureConfig, case: Tls13TestCase) {
    let (client_socket, server_socket) = duplex(2 << 16);
    let server_task = tokio::spawn(bind_with_config(server_socket.compat(), fixture_config));

    run_tls13_case(case, client_socket.compat()).await;

    server_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tls13_fixture_default_without_client_auth_request() {
    let _ = tracing_subscriber::fmt::try_init();

    run_fixture_case(
        FixtureConfig::default().client_auth(FixtureClientAuth::None),
        Tls13TestCase {
            server_name: SERVER_DOMAIN,
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            client_auth: None,
            request_path: "/formats/json?size=1",
            request_headers: Vec::new(),
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tls13_fixture_default_with_optional_client_auth_request() {
    let _ = tracing_subscriber::fmt::try_init();

    run_fixture_case(
        FixtureConfig::default().client_auth(FixtureClientAuth::Optional),
        Tls13TestCase {
            server_name: SERVER_DOMAIN,
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            client_auth: None,
            request_path: "/formats/json?size=1",
            request_headers: Vec::new(),
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tls13_fixture_default_with_required_client_auth() {
    let _ = tracing_subscriber::fmt::try_init();

    run_fixture_case(
        FixtureConfig::default().client_auth(FixtureClientAuth::Required),
        Tls13TestCase {
            server_name: SERVER_DOMAIN,
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            client_auth: Some((
                vec![CertificateDer(CLIENT_CERT_DER.to_vec())],
                PrivateKeyDer(CLIENT_KEY_DER.to_vec()),
            )),
            request_path: "/formats/json?size=1",
            request_headers: Vec::new(),
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tls13_fixture_rsa_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    let cert_profile = FixtureCertProfile::Rsa;
    run_fixture_case(
        FixtureConfig::default()
            .cert_profile(cert_profile)
            .client_auth(FixtureClientAuth::None),
        Tls13TestCase {
            server_name: cert_profile.server_name(),
            roots: vec![CertificateDer(cert_profile.ca_cert_der().to_vec())],
            client_auth: None,
            request_path: "/formats/json?size=1",
            request_headers: Vec::new(),
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn tls13_fixture_ecdsa_chain() {
    let _ = tracing_subscriber::fmt::try_init();

    let cert_profile = FixtureCertProfile::Ecdsa;
    run_fixture_case(
        FixtureConfig::default()
            .cert_profile(cert_profile)
            .client_auth(FixtureClientAuth::None),
        Tls13TestCase {
            server_name: cert_profile.server_name(),
            roots: vec![CertificateDer(cert_profile.ca_cert_der().to_vec())],
            client_auth: None,
            request_path: "/formats/json?size=1",
            request_headers: Vec::new(),
        },
    )
    .await;
}

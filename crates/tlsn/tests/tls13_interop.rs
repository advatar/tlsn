mod support;

use support::{Tls13TestCase, run_tls13_case};
use tlsn::webpki::CertificateDer;
use tlsn_server_fixture::FixtureCertProfile;
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep};
use tokio_util::compat::TokioAsyncReadCompatExt;

fn docker_interop_enabled() -> bool {
    std::env::var_os("TLSN_RUN_DOCKER_INTEROP").is_some()
}

fn raw_openssl_enabled() -> bool {
    std::env::var_os("TLSN_RUN_OPENSSL_SSERVER").is_some()
}

fn caddy_enabled() -> bool {
    std::env::var_os("TLSN_RUN_CADDY_INTEROP").is_some()
}

async fn run_docker_case(port: u16, roots: Vec<CertificateDer>) {
    let mut last_err = None;
    let mut socket = None;

    for _ in 0..20 {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => {
                socket = Some(stream);
                break;
            }
            Err(err) => {
                last_err = Some(err);
                sleep(Duration::from_millis(500)).await;
            }
        }
    }

    let socket = socket.unwrap_or_else(|| {
        panic!(
            "failed to connect to localhost:{port}: {}",
            last_err.unwrap()
        )
    });

    run_tls13_case(
        Tls13TestCase {
            server_name: "localhost",
            roots,
            client_auth: None,
            request_path: "/",
            request_headers: Vec::new(),
        },
        socket.compat(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TLSN_RUN_DOCKER_INTEROP=1 and docker compose interop stack"]
async fn tls13_interop_nginx_rsa() {
    if !docker_interop_enabled() {
        return;
    }

    run_docker_case(
        30443,
        vec![CertificateDer(
            FixtureCertProfile::Rsa.ca_cert_der().to_vec(),
        )],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TLSN_RUN_DOCKER_INTEROP=1 and docker compose interop stack"]
async fn tls13_interop_nginx_ecdsa() {
    if !docker_interop_enabled() {
        return;
    }

    run_docker_case(
        30444,
        vec![CertificateDer(
            FixtureCertProfile::Ecdsa.ca_cert_der().to_vec(),
        )],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TLSN_RUN_DOCKER_INTEROP=1 and docker compose interop stack"]
async fn tls13_interop_caddy_rsa() {
    if !docker_interop_enabled() || !caddy_enabled() {
        return;
    }

    run_docker_case(
        30445,
        vec![CertificateDer(
            FixtureCertProfile::Rsa.ca_cert_der().to_vec(),
        )],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TLSN_RUN_DOCKER_INTEROP=1 and docker compose interop stack"]
async fn tls13_interop_apache_rsa() {
    if !docker_interop_enabled() {
        return;
    }

    run_docker_case(
        30446,
        vec![CertificateDer(
            FixtureCertProfile::Rsa.ca_cert_der().to_vec(),
        )],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TLSN_RUN_DOCKER_INTEROP=1 and docker compose interop stack"]
async fn tls13_interop_openssl_rsa() {
    if !docker_interop_enabled() || !raw_openssl_enabled() {
        return;
    }

    run_docker_case(
        30447,
        vec![CertificateDer(
            FixtureCertProfile::Rsa.ca_cert_der().to_vec(),
        )],
    )
    .await;
}

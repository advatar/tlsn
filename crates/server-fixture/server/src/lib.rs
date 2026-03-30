use std::{
    collections::HashMap,
    io::BufReader,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Query, State},
    response::Html,
    routing::get,
    Json, Router,
};
use tower_http::trace::TraceLayer;

use futures::{channel::oneshot, AsyncRead, AsyncWrite};
use futures_rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig},
    TlsAcceptor,
};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    Request, StatusCode,
};
use hyper_util::rt::TokioIo;

use serde_json::Value;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tower_service::Service;

use axum::extract::FromRequest;
use hyper::header;

use tlsn_server_fixture_certs::*;
use tracing::info;

pub const DEFAULT_FIXTURE_PORT: u16 = 3000;
const TEST_CA_SERVER_DOMAIN: &str = "testserver.com";
const RSA_CA_CERT_DER: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tls/client/test-ca/rsa/ca.der"
));
const RSA_END_FULLCHAIN_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tls/client/test-ca/rsa/end.fullchain"
));
const RSA_END_KEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tls/client/test-ca/rsa/end.key"
));
const ECDSA_CA_CERT_DER: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tls/client/test-ca/ecdsa/ca.der"
));
const ECDSA_END_FULLCHAIN_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tls/client/test-ca/ecdsa/end.fullchain"
));
const ECDSA_END_KEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tls/client/test-ca/ecdsa/end.key"
));

/// TLS certificate profile served by the fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureCertProfile {
    /// The original self-signed test-server.io certificate fixture.
    Default,
    /// The RSA chain reused from the tls client test CA.
    Rsa,
    /// The ECDSA chain reused from the tls client test CA.
    Ecdsa,
}

impl FixtureCertProfile {
    /// Returns the expected DNS name for this certificate profile.
    pub fn server_name(self) -> &'static str {
        match self {
            Self::Default => SERVER_DOMAIN,
            Self::Rsa | Self::Ecdsa => TEST_CA_SERVER_DOMAIN,
        }
    }

    /// Returns the root CA used to validate this certificate profile.
    pub fn ca_cert_der(self) -> &'static [u8] {
        match self {
            Self::Default => CA_CERT_DER,
            Self::Rsa => RSA_CA_CERT_DER,
            Self::Ecdsa => ECDSA_CA_CERT_DER,
        }
    }
}

impl std::str::FromStr for FixtureCertProfile {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "default" => Ok(Self::Default),
            "rsa" => Ok(Self::Rsa),
            "ecdsa" => Ok(Self::Ecdsa),
            _ => Err(anyhow::anyhow!("unknown server cert profile: {value}")),
        }
    }
}

/// Client-auth behavior for the fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureClientAuth {
    /// Do not send a TLS CertificateRequest.
    None,
    /// Request but do not require a client certificate.
    Optional,
    /// Require a client certificate.
    Required,
}

impl std::str::FromStr for FixtureClientAuth {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err(anyhow::anyhow!("unknown client auth mode: {value}")),
        }
    }
}

/// TLS configuration for the fixture server.
#[derive(Debug, Clone)]
pub struct FixtureConfig {
    cert_profile: FixtureCertProfile,
    client_auth: FixtureClientAuth,
    alpn_protocols: Vec<Vec<u8>>,
}

impl Default for FixtureConfig {
    fn default() -> Self {
        Self {
            cert_profile: FixtureCertProfile::Default,
            client_auth: FixtureClientAuth::Optional,
            alpn_protocols: Vec::new(),
        }
    }
}

impl FixtureConfig {
    /// Creates a config from environment variables used by the fixture binary.
    pub fn from_env() -> anyhow::Result<Self> {
        let cert_profile = std::env::var("TLSN_SERVER_CERT_PROFILE")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(FixtureCertProfile::Default);
        let client_auth = std::env::var("TLSN_SERVER_CLIENT_AUTH")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(FixtureClientAuth::Optional);
        let alpn_protocols = std::env::var("TLSN_SERVER_ALPN")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .filter(|proto| !proto.is_empty())
                    .map(|proto| proto.as_bytes().to_vec())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            cert_profile,
            client_auth,
            alpn_protocols,
        })
    }

    /// Sets the certificate profile.
    pub fn cert_profile(mut self, cert_profile: FixtureCertProfile) -> Self {
        self.cert_profile = cert_profile;
        self
    }

    /// Sets the client-auth mode.
    pub fn client_auth(mut self, client_auth: FixtureClientAuth) -> Self {
        self.client_auth = client_auth;
        self
    }

    /// Sets the ALPN protocols advertised by the fixture.
    pub fn alpn_protocols(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    /// Returns the active certificate profile.
    pub fn cert_profile_ref(&self) -> FixtureCertProfile {
        self.cert_profile
    }
}

struct AppState {
    shutdown: Option<oneshot::Sender<()>>,
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/bytes", get(bytes))
        .route("/formats/json", get(json))
        .route("/formats/html", get(html))
        .route("/protected", get(protected_route))
        .route("/elster", get(elster_route))
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(Mutex::new(state)))
}

/// Bind the server to the given socket using the provided TLS config.
pub async fn bind_with_config<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
    fixture_config: FixtureConfig,
) -> anyhow::Result<()> {
    let config = build_server_config(&fixture_config)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let conn = acceptor.accept(socket).await?;

    let io = TokioIo::new(conn.compat());

    let (sender, receiver) = oneshot::channel();
    let state = AppState {
        shutdown: Some(sender),
    };
    let tower_service = app(state);

    let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
    });

    tokio::select! {
        _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, hyper_service) => {},
        _ = receiver => {},
    }

    Ok(())
}

/// Bind the server to the given socket with the default TLS config.
pub async fn bind<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
) -> anyhow::Result<()> {
    bind_with_config(socket, FixtureConfig::default()).await
}

struct FixtureIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_auth_ca: &'static [u8],
}

fn build_server_config(fixture_config: &FixtureConfig) -> anyhow::Result<ServerConfig> {
    let FixtureIdentity {
        certs,
        key,
        client_auth_ca,
    } = fixture_identity(fixture_config.cert_profile)?;

    let mut config = match fixture_config.client_auth {
        FixtureClientAuth::None => ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
        FixtureClientAuth::Optional => {
            let verifier = make_client_cert_verifier(client_auth_ca, true)?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        }
        FixtureClientAuth::Required => {
            let verifier = make_client_cert_verifier(client_auth_ca, false)?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        }
    };

    config.alpn_protocols = fixture_config.alpn_protocols.clone();

    Ok(config)
}

fn make_client_cert_verifier(
    ca_cert_der: &'static [u8],
    allow_unauthenticated: bool,
) -> anyhow::Result<Arc<dyn futures_rustls::rustls::server::danger::ClientCertVerifier>> {
    let mut root_store = RootCertStore::empty();
    root_store.add(ca_cert_der.into())?;

    let builder = WebPkiClientVerifier::builder(root_store.into());
    let verifier = if allow_unauthenticated {
        builder.allow_unauthenticated().build()?
    } else {
        builder.build()?
    };

    Ok(verifier)
}

fn fixture_identity(cert_profile: FixtureCertProfile) -> anyhow::Result<FixtureIdentity> {
    match cert_profile {
        FixtureCertProfile::Default => Ok(FixtureIdentity {
            certs: vec![CertificateDer::from(SERVER_CERT_DER)],
            key: PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into()),
            client_auth_ca: CA_CERT_DER,
        }),
        FixtureCertProfile::Rsa => Ok(FixtureIdentity {
            certs: parse_pem_chain(RSA_END_FULLCHAIN_PEM)?,
            key: parse_pkcs8_key(RSA_END_KEY_PEM)?,
            client_auth_ca: RSA_CA_CERT_DER,
        }),
        FixtureCertProfile::Ecdsa => Ok(FixtureIdentity {
            certs: parse_pem_chain(ECDSA_END_FULLCHAIN_PEM)?,
            key: parse_pkcs8_key(ECDSA_END_KEY_PEM)?,
            client_auth_ca: ECDSA_CA_CERT_DER,
        }),
    }
}

fn parse_pem_chain(pem: &'static [u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    Ok(rustls_pemfile::certs(&mut BufReader::new(pem))?
        .into_iter()
        .map(CertificateDer::from)
        .collect())
}

fn parse_pkcs8_key(pem: &'static [u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(pem))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing pkcs8 private key"))?;

    Ok(PrivateKeyDer::Pkcs8(key.into()))
}

async fn bytes(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Bytes, StatusCode> {
    info!("Handling /bytes with params: {:?}", params);

    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Ok(Bytes::from(vec![0x42u8; size]))
}

/// parse the JSON data from the file content
fn get_json_value(filecontent: &str) -> Result<Json<Value>, StatusCode> {
    Ok(Json(serde_json::from_str(filecontent).map_err(|e| {
        eprintln!("Failed to parse JSON data: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

async fn json(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    info!("Handling /json with params: {:?}", params);

    let size = params
        .get("size")
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(1);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    match size {
        1 => get_json_value(include_str!("data/1kb.json")),
        4 => get_json_value(include_str!("data/4kb.json")),
        8 => get_json_value(include_str!("data/8kb.json")),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn html(
    State(state): State<Arc<Mutex<AppState>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<&'static str> {
    info!("Handling /html with params: {:?}", params);

    if params.contains_key("shutdown") {
        _ = state.lock().unwrap().shutdown.take().unwrap().send(());
    }

    Html(include_str!("data/4kb.html"))
}

struct AuthenticatedUser;

impl<B> FromRequest<B> for AuthenticatedUser
where
    B: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(
        req: axum::extract::Request,
        _state: &B,
    ) -> Result<Self, Self::Rejection> {
        // Expected token (hardcoded for simplicity in the demo)
        let expected_token = "random_auth_token";

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());

        if let Some(auth_token) = auth_header {
            let token = auth_token.trim_start_matches("Bearer ");
            if token == expected_token {
                return Ok(AuthenticatedUser);
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Invalid or missing token"))
    }
}

async fn protected_route(_: AuthenticatedUser) -> Result<Json<Value>, StatusCode> {
    info!("Handling /protected");

    get_json_value(include_str!("data/protected_data.json"))
}

async fn elster_route(_: AuthenticatedUser) -> Result<Json<Value>, StatusCode> {
    info!("Handling /elster");

    get_json_value(include_str!("data/elster.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    fn get_app() -> Router {
        let (sender, _) = oneshot::channel();
        let state = AppState {
            shutdown: Some(sender),
        };
        app(state)
    }

    #[tokio::test]
    async fn hello_world() {
        let response = get_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Hello, World!");
    }

    #[tokio::test]
    async fn json() {
        let response = get_app()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/formats/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body.get("id").unwrap().as_number().unwrap().as_u64(),
            Some(1234567890)
        );
    }
}

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{
        Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tlsn_sdk_core::{SdkVerifier, VerifierConfig, VerifierOutput};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    sync::Mutex,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower::ServiceBuilder;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing::{error, info, warn};

const BRIDGE_BUFFER_SIZE: usize = 1 << 20;
const IO_CHUNK_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub static_dir: PathBuf,
    pub wasm_pkg_dir: PathBuf,
    pub destination_policy: DestinationPolicy,
    pub verifier_config: VerifierConfig,
}

impl AppConfig {
    pub fn default_static_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")
    }

    pub fn default_wasm_pkg_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../wasm/pkg")
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthResponse {
    pub status: &'static str,
    pub wasm_pkg_present: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub allow_loopback: bool,
    pub allow_private_ips: bool,
}

#[derive(Debug, Clone)]
struct AppState {
    sessions: Arc<SessionStore>,
    destination_policy: DestinationPolicy,
    verifier_config: VerifierConfig,
    health: HealthResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<VerifierOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, SessionSnapshot>>,
}

impl SessionStore {
    pub async fn start(&self, session_id: &str) -> Result<(), SessionStoreError> {
        let mut inner = self.inner.lock().await;
        if inner.contains_key(session_id) {
            return Err(SessionStoreError::Duplicate(session_id.to_string()));
        }

        inner.insert(
            session_id.to_string(),
            SessionSnapshot {
                status: SessionStatus::Running,
                output: None,
                error: None,
            },
        );

        Ok(())
    }

    pub async fn complete(&self, session_id: &str, output: VerifierOutput) {
        let mut inner = self.inner.lock().await;
        inner.insert(
            session_id.to_string(),
            SessionSnapshot {
                status: SessionStatus::Complete,
                output: Some(output),
                error: None,
            },
        );
    }

    pub async fn fail(&self, session_id: &str, error: String) {
        let mut inner = self.inner.lock().await;
        inner.insert(
            session_id.to_string(),
            SessionSnapshot {
                status: SessionStatus::Failed,
                output: None,
                error: Some(error),
            },
        );
    }

    pub async fn get(&self, session_id: &str) -> Option<SessionSnapshot> {
        let inner = self.inner.lock().await;
        inner.get(session_id).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStoreError {
    Duplicate(String),
}

impl std::fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStoreError::Duplicate(session_id) => {
                write!(f, "session `{session_id}` already exists")
            }
        }
    }
}

impl std::error::Error for SessionStoreError {}

#[derive(Debug, Clone, Default)]
pub struct DestinationPolicy {
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: BTreeSet<u16>,
    pub allow_loopback: bool,
    pub allow_private_ips: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedDestination {
    pub host: String,
    pub port: u16,
    pub address: SocketAddr,
}

impl DestinationPolicy {
    pub fn allows_host(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }

        if self.allowed_hosts.is_empty() {
            return false;
        }

        let host = host.to_ascii_lowercase();
        self.allowed_hosts.iter().any(|candidate| {
            let candidate = candidate.trim().to_ascii_lowercase();
            if let Some(suffix) = candidate.strip_prefix('.') {
                host == suffix || host.ends_with(&candidate)
            } else {
                host == candidate
            }
        })
    }

    pub fn allows_port(&self, port: u16) -> bool {
        port != 0 && (self.allowed_ports.is_empty() || self.allowed_ports.contains(&port))
    }

    pub fn allows_socket_addr(&self, address: SocketAddr) -> bool {
        match address.ip() {
            IpAddr::V4(ip) => {
                if !self.allow_loopback && ip.is_loopback() {
                    return false;
                }
                if !self.allow_private_ips
                    && (ip.is_private()
                        || ip.is_link_local()
                        || ip.is_broadcast()
                        || ip.is_multicast()
                        || ip.is_unspecified()
                        || ip.is_documentation())
                {
                    return false;
                }

                true
            }
            IpAddr::V6(ip) => {
                if !self.allow_loopback && ip.is_loopback() {
                    return false;
                }
                if !self.allow_private_ips
                    && (ip.is_unspecified()
                        || ip.is_multicast()
                        || ip.is_unicast_link_local()
                        || is_unique_local_v6(ip))
                {
                    return false;
                }

                true
            }
        }
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<ResolvedDestination> {
        if !self.allows_host(host) {
            bail!("host `{host}` is not permitted by the bridge policy");
        }

        if !self.allows_port(port) {
            bail!("port `{port}` is not permitted by the bridge policy");
        }

        let resolved: Vec<SocketAddr> = lookup_host((host, port))
            .await
            .with_context(|| format!("failed to resolve `{host}:{port}`"))?
            .filter(|address| self.allows_socket_addr(*address))
            .collect();

        let address = resolved
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no resolved address for `{host}:{port}` passed policy checks"))?;

        Ok(ResolvedDestination {
            host: host.to_string(),
            port,
            address,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TcpBridgeQuery {
    host: String,
    port: u16,
}

pub fn app(config: AppConfig) -> Router {
    let health = HealthResponse {
        status: "ok",
        wasm_pkg_present: config.wasm_pkg_dir.join("tlsn_wasm.js").exists(),
        allowed_hosts: config.destination_policy.allowed_hosts.clone(),
        allowed_ports: config.destination_policy.allowed_ports.iter().copied().collect(),
        allow_loopback: config.destination_policy.allow_loopback,
        allow_private_ips: config.destination_policy.allow_private_ips,
    };

    let state = AppState {
        sessions: Arc::new(SessionStore::default()),
        destination_policy: config.destination_policy,
        verifier_config: config.verifier_config,
        health,
    };

    let static_index = config.static_dir.join("index.html");
    let static_files = ServeDir::new(config.static_dir)
        .not_found_service(ServeFile::new(static_index))
        .append_index_html_on_directories(true);
    let wasm_pkg_files = ServeDir::new(config.wasm_pkg_dir);

    let headers = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-embedder-policy"),
            HeaderValue::from_static("require-corp"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store"),
        ));

    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/sessions/{session_id}", get(session_handler))
        .route("/ws/notary/{session_id}", get(notary_ws_handler))
        .route("/ws/tcp", get(tcp_ws_handler))
        .nest_service("/pkg", wasm_pkg_files)
        .fallback_service(static_files)
        .with_state(state)
        .layer(headers)
        .layer(TraceLayer::new_for_http())
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(state.health)
}

async fn session_handler(
    Path(session_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<SessionSnapshot>, StatusCode> {
    state
        .sessions
        .get(&session_id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn notary_ws_handler(
    Path(session_id): Path<String>,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(err) = state.sessions.start(&session_id).await {
        warn!("rejecting duplicate notary session `{session_id}`: {err}");
        return api_error(StatusCode::CONFLICT, err.to_string());
    }

    ws.max_frame_size(BRIDGE_BUFFER_SIZE)
        .max_message_size(BRIDGE_BUFFER_SIZE)
        .on_upgrade(move |socket| async move {
            if let Err(err) = run_notary_session(state, session_id.clone(), socket).await {
                error!("notary session `{session_id}` failed: {err:#}");
            }
        })
}

async fn tcp_ws_handler(
    Query(query): Query<TcpBridgeQuery>,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    match state.destination_policy.resolve(&query.host, query.port).await {
        Ok(destination) => ws
            .max_frame_size(BRIDGE_BUFFER_SIZE)
            .max_message_size(BRIDGE_BUFFER_SIZE)
            .on_upgrade(move |socket| async move {
                if let Err(err) = run_tcp_bridge(destination, socket).await {
                    error!("tcp bridge failed: {err:#}");
                }
            }),
        Err(err) => api_error(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

async fn run_notary_session(
    state: AppState,
    session_id: String,
    socket: WebSocket,
) -> Result<()> {
    match run_verifier(socket, state.verifier_config.clone()).await {
        Ok(output) => {
            info!("notary session `{session_id}` completed");
            state.sessions.complete(&session_id, output).await;
            Ok(())
        }
        Err(err) => {
            state.sessions.fail(&session_id, err.to_string()).await;
            Err(err)
        }
    }
}

async fn run_verifier(socket: WebSocket, verifier_config: VerifierConfig) -> Result<VerifierOutput> {
    let (browser_side, verifier_side) = tokio::io::duplex(BRIDGE_BUFFER_SIZE);
    let (browser_reader, browser_writer) = tokio::io::split(browser_side);
    let (ws_sender, ws_receiver) = socket.split();

    let browser_to_verifier = tokio::spawn(pump_websocket_to_io(ws_receiver, browser_writer));
    let verifier_to_browser = tokio::spawn(pump_io_to_websocket(browser_reader, ws_sender));

    let mut verifier = SdkVerifier::new(verifier_config);
    verifier
        .connect(verifier_side.compat())
        .await
        .context("failed to connect verifier to browser session")?;
    let output = verifier.verify().await.context("verifier failed")?;

    browser_to_verifier
        .await
        .context("browser_to_verifier task panicked")?
        .context("browser_to_verifier task failed")?;
    verifier_to_browser
        .await
        .context("verifier_to_browser task panicked")?
        .context("verifier_to_browser task failed")?;

    Ok(output)
}

async fn run_tcp_bridge(destination: ResolvedDestination, socket: WebSocket) -> Result<()> {
    info!(
        "bridging websocket to {}:{} via {}",
        destination.host, destination.port, destination.address
    );

    let stream = TcpStream::connect(destination.address)
        .await
        .with_context(|| format!("failed to connect to {}", destination.address))?;
    let (tcp_reader, tcp_writer) = stream.into_split();
    let (ws_sender, ws_receiver) = socket.split();

    let client_to_server = tokio::spawn(pump_websocket_to_io(ws_receiver, tcp_writer));
    let server_to_client = tokio::spawn(pump_io_to_websocket(tcp_reader, ws_sender));

    client_to_server
        .await
        .context("client_to_server task panicked")?
        .context("client_to_server task failed")?;
    server_to_client
        .await
        .context("server_to_client task panicked")?
        .context("server_to_client task failed")?;

    Ok(())
}

async fn pump_websocket_to_io<Rx, Writer>(mut receiver: Rx, mut writer: Writer) -> Result<()>
where
    Rx: futures::Stream<Item = Result<Message, axum::Error>> + Unpin,
    Writer: AsyncWriteExt + Unpin,
{
    while let Some(message) = receiver.next().await {
        match message.context("websocket receive error")? {
            Message::Binary(bytes) => {
                writer
                    .write_all(&bytes)
                    .await
                    .context("failed to forward websocket frame to IO")?;
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Text(_) => bail!("text websocket frames are not supported"),
        }
    }

    writer.shutdown().await.context("failed to close IO writer")?;
    Ok(())
}

async fn pump_io_to_websocket<Reader, Tx>(mut reader: Reader, mut sender: Tx) -> Result<()>
where
    Reader: AsyncReadExt + Unpin,
    Tx: futures::Sink<Message, Error = axum::Error> + Unpin,
{
    let mut buffer = vec![0u8; IO_CHUNK_SIZE];

    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .context("failed to read from IO stream")?;
        if read == 0 {
            break;
        }

        sender
            .send(Message::Binary(buffer[..read].to_vec().into()))
            .await
            .context("failed to send websocket binary frame")?;
    }

    sender
        .send(Message::Close(None))
        .await
        .context("failed to close websocket stream")?;
    Ok(())
}

fn api_error(status: StatusCode, error: String) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
        })),
    )
        .into_response()
}

fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_policy() -> DestinationPolicy {
        DestinationPolicy {
            allowed_hosts: vec!["example.com".to_string(), ".example.net".to_string()],
            allowed_ports: BTreeSet::from([443]),
            allow_loopback: false,
            allow_private_ips: false,
        }
    }

    #[test]
    fn destination_policy_matches_exact_and_suffix_hosts() {
        let policy = base_policy();

        assert!(policy.allows_host("example.com"));
        assert!(policy.allows_host("api.example.net"));
        assert!(policy.allows_host("example.net"));
        assert!(!policy.allows_host("example.org"));
    }

    #[test]
    fn destination_policy_requires_explicit_host_allowlist() {
        let policy = DestinationPolicy {
            allowed_hosts: Vec::new(),
            allowed_ports: BTreeSet::from([443]),
            allow_loopback: false,
            allow_private_ips: false,
        };

        assert!(!policy.allows_host("example.com"));
    }

    #[test]
    fn destination_policy_rejects_private_addresses_by_default() {
        let policy = base_policy();

        assert!(!policy.allows_socket_addr(SocketAddr::from((
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            443,
        ))));
        assert!(!policy.allows_socket_addr(SocketAddr::from((
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            443,
        ))));
        assert!(policy.allows_socket_addr(SocketAddr::from((
            std::net::Ipv4Addr::new(93, 184, 216, 34),
            443,
        ))));
    }

    #[test]
    fn destination_policy_can_opt_into_local_destinations() {
        let mut policy = base_policy();
        policy.allow_loopback = true;
        policy.allow_private_ips = true;

        assert!(policy.allows_socket_addr(SocketAddr::from((
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            443,
        ))));
        assert!(policy.allows_socket_addr(SocketAddr::from((
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            443,
        ))));
    }

    #[tokio::test]
    async fn session_store_rejects_duplicate_running_sessions() {
        let store = SessionStore::default();

        store.start("abc").await.expect("first session should start");
        let duplicate = store.start("abc").await.expect_err("duplicate should fail");
        assert_eq!(duplicate, SessionStoreError::Duplicate("abc".to_string()));
    }

    #[tokio::test]
    async fn session_store_persists_completed_results() {
        let store = SessionStore::default();
        store.start("abc").await.expect("session should start");

        store
            .complete(
                "abc",
                VerifierOutput {
                    server_name: Some("example.com".to_string()),
                    connection_info: tlsn_sdk_core::ConnectionInfo {
                        time: 1,
                        version: tlsn_sdk_core::TlsVersion::V1_3,
                        transcript_length: tlsn_sdk_core::TranscriptLength { sent: 10, recv: 20 },
                    },
                    transcript: None,
                },
            )
            .await;

        let snapshot = store.get("abc").await.expect("snapshot should exist");
        assert!(matches!(snapshot.status, SessionStatus::Complete));
        assert_eq!(
            snapshot
                .output
                .and_then(|output| output.server_name)
                .as_deref(),
            Some("example.com")
        );
    }
}

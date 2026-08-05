//! Headless native TLSNotary prover, for proving the real (non-demo) notary gateway end to end.
//!
//! Mirrors the mobile prover in `src/notarize.rs`: connects to a running notary gateway
//! (`crates/browser-demo`) over `/ws/notary/{id}` (MPC-TLS) and `/ws/tcp` (proxy to the target),
//! notarises a real HTTPS GET, then polls `/api/sessions/{id}` for the signed artifact and verifies
//! it against the pinned notary public key.
//!
//! Usage:
//!   cargo run -p tlsn-ios --example notarize_cli -- \
//!     https://example.com/ http://127.0.0.1:7047/ <trusted-notary-pubkey-base64url>

use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tlsn_notary_artifact::SignedArtifact;
use tlsn_sdk_core::{HttpRequest, ProverConfig, Reveal, SdkProver};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use url::Url;

const BRIDGE_CAPACITY: usize = 1 << 20;
const POLL_ATTEMPTS: usize = 80;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: notarize_cli <https-target-url> <notary-url> <trusted-pubkey-base64url>");
        std::process::exit(2);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    match runtime.block_on(run(&args[1], &args[2], &args[3])) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    }
}

async fn run(target_url: &str, notary_url: &str, trusted_pubkey_b64u: &str) -> Result<(), String> {
    let target = Url::parse(target_url).map_err(|_| "invalid target URL".to_string())?;
    if target.scheme() != "https" {
        return Err("only HTTPS target URLs can be notarized".to_string());
    }
    let host = target
        .host_str()
        .ok_or_else(|| "target URL has no host".to_string())?;
    let port = target.port_or_known_default().unwrap_or(443);
    let notary = validate_notary_url(notary_url)?;
    let session_id = format!("{:032x}", rand::random::<u128>());

    let notary_ws = websocket_endpoint(&notary, &format!("ws/notary/{session_id}"))?;
    let server_ws = websocket_endpoint(
        &notary,
        &format!("ws/tcp?host={}&port={port}", percent_encode(host)),
    )?;

    eprintln!("→ notary  {notary_ws}");
    eprintln!("→ proxy   {server_ws}");
    eprintln!("→ target  {target}  (session {session_id})");

    let notary_io = connect_websocket_io(notary_ws.as_str()).await?;
    // Match the mobile prover's proven limits; the notary must be run with the same.
    let mut prover = SdkProver::new(
        ProverConfig::builder(host)
            .max_sent_data(32 * 1024)
            .max_recv_data(512 * 1024)
            .build(),
    )
    .map_err(|e| e.to_string())?;
    prover.setup(notary_io).await.map_err(|e| e.to_string())?;

    let server_io = connect_websocket_io(server_ws.as_str()).await?;
    let mut http_request = HttpRequest::get(request_target(&target));
    for (name, value) in [
        ("Host", target_host_header(&target)),
        ("Accept", "*/*".to_string()),
        ("Accept-Encoding", "identity".to_string()),
        ("Connection", "close".to_string()),
        ("User-Agent", "TLSNotaryNativeCLI/0.1".to_string()),
    ] {
        http_request = http_request.header(name, value.into_bytes());
    }

    let response = prover
        .send_request(server_io, http_request)
        .await
        .map_err(|e| e.to_string())?;
    let transcript = prover.transcript().map_err(|e| e.to_string())?;
    prover
        .reveal(
            Reveal::new()
                .sent(0..transcript.sent.len())
                .recv(0..transcript.recv.len())
                .server_identity(true),
        )
        .await
        .map_err(|e| e.to_string())?;

    let snapshot = poll_session(&notary, &session_id).await?;
    let artifact_value = snapshot
        .get("artifact")
        .cloned()
        .ok_or_else(|| "notary completed without a signed artifact".to_string())?;
    let artifact: SignedArtifact = serde_json::from_value(artifact_value.clone())
        .map_err(|e| format!("invalid signed notary artifact: {e}"))?;
    let trusted_key = URL_SAFE_NO_PAD
        .decode(trusted_pubkey_b64u)
        .map_err(|e| format!("invalid trusted notary public key: {e}"))?;
    artifact
        .verify(&trusted_key)
        .map_err(|e| format!("notary artifact verification FAILED: {e}"))?;
    if artifact.payload.session_id != session_id {
        return Err("notary artifact session identifier mismatch".to_string());
    }

    println!("OK  http_status={}", response.status);
    println!("OK  artifact.version={}", artifact.payload.version);
    println!("OK  artifact.session_id matches ({session_id})");
    println!("OK  artifact.public_key={}", artifact.public_key);
    println!("OK  signature verified against the pinned notary key");
    println!(
        "OK  response_body_prefix={:?}",
        String::from_utf8_lossy(&response.body.unwrap_or_default())
            .chars()
            .take(80)
            .collect::<String>()
    );
    Ok(())
}

async fn connect_websocket_io(url: &str) -> Result<Compat<DuplexStream>, String> {
    let (websocket, _) = connect_async(url)
        .await
        .map_err(|e| format!("failed to connect websocket {url}: {e}"))?;
    let (websocket_sink, websocket_stream) = websocket.split();
    let (application, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
    let (bridge_reader, bridge_writer) = tokio::io::split(bridge);
    tokio::spawn(pump_io_to_websocket(bridge_reader, websocket_sink));
    tokio::spawn(pump_websocket_to_io(websocket_stream, bridge_writer));
    Ok(application.compat())
}

async fn pump_io_to_websocket<R, S>(mut reader: R, mut sink: S)
where
    R: tokio::io::AsyncRead + Unpin,
    S: futures::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                if sink
                    .send(Message::Binary(buffer[..read].to_vec().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = sink.close().await;
}

async fn pump_websocket_to_io<S, W>(mut stream: S, mut writer: W)
where
    S: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(message) = stream.next().await {
        match message {
            Ok(Message::Binary(bytes)) => {
                if writer.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
            Ok(Message::Text(_)) | Ok(Message::Frame(_)) => break,
        }
    }
    let _ = writer.shutdown().await;
}

async fn poll_session(notary: &Url, session_id: &str) -> Result<Value, String> {
    let endpoint = notary
        .join(&format!("api/sessions/{session_id}"))
        .map_err(|e| e.to_string())?;
    let client = reqwest::Client::new();
    for _ in 0..POLL_ATTEMPTS {
        let response = client
            .get(endpoint.clone())
            .send()
            .await
            .map_err(|e| format!("failed to poll notary: {e}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        let value: Value = response.json().await.map_err(|e| e.to_string())?;
        match value.get("status").and_then(Value::as_str) {
            Some("running") => tokio::time::sleep(Duration::from_millis(250)).await,
            Some("complete") => return Ok(value),
            Some("failed") => {
                return Err(value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("notary verification failed")
                    .to_string());
            }
            _ => return Err("invalid notary session response".to_string()),
        }
    }
    Err("timed out waiting for notary verification".to_string())
}

fn validate_notary_url(value: &str) -> Result<Url, String> {
    let mut url = Url::parse(value).map_err(|_| "invalid notary URL".to_string())?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(local && url.scheme() == "http") {
        return Err("notary URL must use HTTPS (HTTP is allowed for loopback)".to_string());
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn websocket_endpoint(base: &Url, path: &str) -> Result<Url, String> {
    let mut url = base.join(path).map_err(|e| e.to_string())?;
    url.set_scheme(if base.scheme() == "https" { "wss" } else { "ws" })
        .map_err(|_| "invalid websocket scheme".to_string())?;
    Ok(url)
}

fn request_target(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn target_host_header(url: &Url) -> String {
    match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    }
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

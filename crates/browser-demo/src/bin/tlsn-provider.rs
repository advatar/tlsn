//! Native, one-shot notarized LLM POST. Secrets arrive on stdin, never argv.
use anyhow::{Context, Result, bail, ensure};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    time::Duration,
};
use tlsn_sdk_core::{Body, HttpRequest, NetworkSetting, ProverConfig, Reveal, SdkProver};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use url::Url;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    notary_url: String,
    target_url: String,
    allowed_hosts: Vec<String>,
    api_key: String,
    nonce: String,
    request: Value,
    request_body: String,
}

#[tokio::main]
async fn main() {
    // Do not initialize tracing: SDK diagnostics are not part of the evidence channel.
    if run_cli().await.is_err() {
        eprintln!("TLSNotary provider proof failed");
        std::process::exit(1);
    }
}

async fn run_cli() -> Result<()> {
    let mut bytes = Vec::new();
    io::stdin().take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "input too large");
    let input: Input = serde_json::from_slice(&bytes)?;
    let artifact = tokio::time::timeout(Duration::from_secs(300), notarize(input)).await??;
    println!("{}", json!({"artifact": artifact}));
    Ok(())
}

fn target(input: &Input) -> Result<Url> {
    let url = Url::parse(&input.target_url)?;
    ensure!(
        url.scheme() == "https" && url.port_or_known_default() == Some(443),
        "HTTPS:443 required"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid target URL"
    );
    let host = url.host_str().context("missing hostname")?;
    ensure!(
        input.allowed_hosts.iter().any(|allowed| allowed == host),
        "provider not allowlisted"
    );
    ensure!(
        url.path() == "/v1/chat/completions",
        "unsupported provider route"
    );
    ensure!(
        !input.api_key.is_empty() && !input.api_key.contains(['\r', '\n']),
        "invalid credential"
    );
    ensure!(
        input.nonce.len() == 64 && input.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid nonce"
    );
    ensure!(
        input.request.is_object()
            && input.request.get("stream").and_then(Value::as_bool) != Some(true),
        "nonstreaming JSON required"
    );
    Ok(url)
}

/// Reveal framing, nonce, and exact JSON body, but never Authorization's value.
fn disclosure(sent: &[u8], recv_len: usize) -> Result<Reveal> {
    let end = sent
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("missing request headers")?;
    let mut cursor = 0;
    let mut hidden = None;
    for line in sent[..end].split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            if line[..colon].eq_ignore_ascii_case(b"authorization") {
                ensure!(hidden.is_none(), "duplicate authorization");
                hidden = Some(cursor + colon + 1..cursor + line.len());
            }
        }
        cursor += line.len() + 2;
    }
    let hidden = hidden.context("missing authorization")?;
    Ok(Reveal::new()
        .sent(0..hidden.start)
        .sent(hidden.end..sent.len())
        .recv(0..recv_len)
        .server_identity(true))
}

async fn notarize(input: Input) -> Result<Value> {
    let target = target(&input)?;
    let host = target.host_str().unwrap();
    let mut notary = Url::parse(&input.notary_url)?;
    let local = matches!(notary.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    ensure!(
        notary.scheme() == "https" || (local && notary.scheme() == "http"),
        "secure notary URL required"
    );
    ensure!(
        notary.username().is_empty()
            && notary.password().is_none()
            && notary.query().is_none()
            && notary.fragment().is_none(),
        "invalid notary URL"
    );
    if !notary.path().ends_with('/') {
        notary.set_path(&format!("{}/", notary.path()));
    }
    let session = format!("{:032x}", rand::random::<u128>());
    let ws_url = |path: &str| -> Result<Url> {
        let mut url = notary.join(path)?;
        url.set_scheme(if notary.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| anyhow::anyhow!("invalid scheme"))?;
        Ok(url)
    };
    ensure!(
        serde_json::from_str::<Value>(&input.request_body)? == input.request,
        "request body mismatch"
    );
    ensure!(
        input.request_body.len() <= 12 * 1024 && input.api_key.len() <= 4096,
        "request exceeds notarization budget"
    );
    // Size preprocessing to this request, rather than multiplying a full 16 KiB budget
    // across every potential record. Record-count negotiation retains the SDK default.
    let sent_budget = input.request_body.len() + input.api_key.len() + host.len() + 512;
    ensure!(
        sent_budget <= 16 * 1024,
        "request exceeds notarization budget"
    );
    eprintln!("TLSN_STAGE:setup");
    let verifier_io = connect_websocket_io(ws_url(&format!("ws/notary/{session}"))?.as_str())
        .await
        .map_err(anyhow::Error::msg)?;
    let mut prover = SdkProver::new(
        ProverConfig::builder(host)
            .tls_version(tlsn_sdk_core::TlsVersion::V1_3)
            .max_sent_data(sent_budget)
            .max_recv_data(4 * 1024)
            .network(NetworkSetting::Latency)
            .build(),
    )?;
    prover.setup(verifier_io).await?;
    eprintln!("TLSN_STAGE:request");
    let server_io = connect_websocket_io(ws_url(&format!("ws/tcp?host={host}&port=443"))?.as_str())
        .await
        .map_err(anyhow::Error::msg)?;
    let request_bytes = input.request_body.into_bytes();
    ensure!(
        request_bytes.len() <= 12 * 1024,
        "request exceeds notarization budget"
    );
    let request = HttpRequest::post(target.path())
        .header("host", host.as_bytes().to_vec())
        .header(
            "authorization",
            format!("Bearer {}", input.api_key).into_bytes(),
        )
        .header("content-type", b"application/json".to_vec())
        .header("accept", b"application/json".to_vec())
        .header("accept-encoding", b"identity".to_vec())
        .header("connection", b"close".to_vec())
        .header("x-vir-proof-nonce", input.nonce.into_bytes())
        .body(Body::Raw(request_bytes));
    let response = prover.send_request(server_io, request).await?;
    ensure!(response.status == 200, "provider rejected request");
    eprintln!("TLSN_STAGE:disclosure");
    let transcript = prover.transcript()?;
    ensure!(
        !transcript
            .recv
            .windows(input.api_key.len())
            .any(|window| window == input.api_key.as_bytes()),
        "provider echoed the credential; refusing disclosure"
    );
    prover
        .reveal(disclosure(&transcript.sent, transcript.recv.len())?)
        .await?;
    eprintln!("TLSN_STAGE:artifact");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    for _ in 0..80 {
        let response = client
            .get(notary.join(&format!("api/sessions/{session}"))?)
            .send()
            .await?;
        if response.status() == 404 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        ensure!(response.status().is_success(), "notary poll failed");
        let snapshot: Value = response.json().await?;
        match snapshot["status"].as_str() {
            Some("running") => tokio::time::sleep(Duration::from_millis(250)).await,
            Some("complete") => {
                let artifact = snapshot.get("artifact").context("missing artifact")?;
                ensure!(
                    artifact["payload"]["sessionId"] == session,
                    "session mismatch"
                );
                // VIR independently checks both signatures, pinned keys and all transcript bindings.
                return Ok(artifact.clone());
            }
            _ => bail!("notary failed"),
        }
    }
    bail!("notary poll timed out")
}

const BRIDGE_CAPACITY: usize = 64 * 1024;
async fn connect_websocket_io(url: &str) -> Result<Compat<DuplexStream>, String> {
    let (websocket, _) = connect_async(url)
        .await
        .map_err(|e| format!("failed to connect websocket: {e}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_https_or_off_policy_provider_before_mpc() {
        let mut input = Input {
            notary_url: "http://127.0.0.1:3000".into(),
            target_url: "https://api.openai.com/v1/chat/completions".into(),
            allowed_hosts: vec!["api.openai.com".into()],
            api_key: "secret".into(),
            nonce: "ab".repeat(32),
            request: json!({"model":"test"}),
            request_body: "{\"model\":\"test\"}".into(),
        };
        assert!(target(&input).is_ok());
        for url in [
            "http://api.openai.com/v1/chat/completions",
            "https://evil.example/v1/chat/completions",
            "https://api.openai.com/v1/chat/completions?x=1",
            "https://user@api.openai.com/v1/chat/completions",
            "https://api.openai.com/v1/responses",
        ] {
            input.target_url = url.into();
            assert!(target(&input).is_err());
        }
    }
    #[test]
    fn authorization_value_is_never_disclosed() {
        let sent = b"POST /v1/chat/completions HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer SECRET\r\ncontent-length: 2\r\n\r\n{}";
        let reveal = disclosure(sent, 10).unwrap();
        let mut disclosed = sent.to_vec();
        for (i, byte) in disclosed.iter_mut().enumerate() {
            if !reveal.sent.iter().any(|r| r.contains(&i)) {
                *byte = 0;
            }
        }
        assert!(!String::from_utf8_lossy(&disclosed).contains("SECRET"));
        assert!(String::from_utf8_lossy(&disclosed).ends_with("{}"));
        assert!(reveal.server_identity);
    }
    #[test]
    fn missing_or_duplicate_auth_is_rejected() {
        assert!(disclosure(b"POST / HTTP/1.1\r\n\r\n", 0).is_err());
        assert!(
            disclosure(
                b"POST / HTTP/1.1\r\nAuthorization: one\r\nAuthorization: two\r\n\r\n",
                0
            )
            .is_err()
        );
    }
}

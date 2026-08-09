//! Asynchronous native TLSNotary operation for mobile clients.

use std::{
    collections::HashMap,
    ffi::{c_char, c_void, CStr},
    sync::OnceLock,
    time::Duration,
};

use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
    Engine as _,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tlsn_notary_artifact::SignedArtifact;
use tlsn_sdk_core::{
    compute_reveal, Handler, HandlerAction, HandlerParams, HandlerPart, HandlerType, HttpRequest,
    ProverConfig, Reveal, SdkProver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use url::Url;

use crate::{error_json, into_c_string, MAX_INPUT_BYTES};

const BRIDGE_CAPACITY: usize = 1 << 20;
const POLL_ATTEMPTS: usize = 80;

/// Completion callback for [`tlsn_mobile_notarize`].
///
/// The result is a JSON C string owned by the caller and must be released with
/// `tlsn_mobile_string_free`.
pub type TlsnMobileCallback = extern "C" fn(*mut c_void, *mut c_char);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotarizeRequest {
    url: String,
    notary_url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    max_recv_data: Option<usize>,
    trusted_notary_public_key: String,
    /// RFC 6901 JSON Pointers (e.g. `/account/status`) the holder chose to disclose from a JSON
    /// response. Empty ⇒ the whole transcript is revealed (backwards-compatible default).
    #[serde(default)]
    disclosed_fields: Vec<String>,
}

/// Convert an RFC 6901 JSON Pointer (`/account/status`, `/items/0/id`) to the dot-notation path the
/// sdk-core JSON handler expects (`account.status`, `items.0.id`). Per RFC 6901, `~1` decodes to `/`
/// and then `~0` decodes to `~`.
///
/// A JSON key that contains a literal `.` is ambiguous in dot-notation and will not resolve; the
/// notarization then fails loudly (the field extractor errors on the unknown path) rather than
/// silently disclosing the wrong span.
fn json_pointer_to_dot_path(pointer: &str) -> String {
    pointer
        .trim_start_matches('/')
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>()
        .join(".")
}

/// Build the reveal handlers for a selective disclosure: reveal only the chosen response JSON fields
/// plus the structural framing needed to interpret the partial transcript — the request line, the
/// response status code, and the response `Content-Type`. Only the response body is field-selected;
/// request headers (e.g. cookies) are never revealed.
fn disclosure_handlers(disclosed_fields: &[String]) -> Vec<Handler> {
    let mut handlers = vec![
        Handler {
            handler_type: HandlerType::Sent,
            part: HandlerPart::StartLine,
            action: HandlerAction::Reveal,
            params: None,
        },
        Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::StatusCode,
            action: HandlerAction::Reveal,
            params: None,
        },
        Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Headers,
            action: HandlerAction::Reveal,
            params: Some(HandlerParams {
                key: Some("content-type".to_owned()),
                ..Default::default()
            }),
        },
    ];
    for field in disclosed_fields {
        handlers.push(Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::Body,
            action: HandlerAction::Reveal,
            params: Some(HandlerParams {
                content_type: Some("json".to_owned()),
                path: Some(json_pointer_to_dot_path(field)),
                ..Default::default()
            }),
        });
    }
    handlers
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NotarizeResponse {
    session_id: String,
    response_status: u16,
    response_body: String,
    notary_attestation: Value,
}

/// Starts a complete TLSNotary GET operation on the shared Rust runtime.
///
/// This function copies `request_json` before returning. Exactly one callback
/// is made when the operation completes. Returns `0` if arguments are invalid
/// and no operation was started, otherwise returns a non-zero operation ID.
#[no_mangle]
pub extern "C" fn tlsn_mobile_notarize(
    request_json: *const c_char,
    callback: Option<TlsnMobileCallback>,
    context: *mut c_void,
) -> u64 {
    let Some(callback) = callback else {
        return 0;
    };
    if request_json.is_null() {
        callback(context, into_c_string(error_json("request is null")));
        return 0;
    }

    // SAFETY: the ABI contract requires a non-null, NUL-terminated C string.
    let request = unsafe { CStr::from_ptr(request_json) }.to_bytes();
    if request.len() > MAX_INPUT_BYTES {
        callback(context, into_c_string(error_json("request exceeds 2 MiB")));
        return 0;
    }
    let request = request.to_vec();
    let operation_id = rand::random::<u64>().max(1);
    let context = context as usize;

    runtime().spawn(async move {
        let result = match serde_json::from_slice::<NotarizeRequest>(&request) {
            Ok(request) => run(request)
                .await
                .and_then(|response| serde_json::to_string(&response).map_err(|e| e.to_string())),
            Err(_) => Err("invalid notarization request JSON".to_string()),
        };
        let output = result.unwrap_or_else(|error| error_json(&error));
        callback(context as *mut c_void, into_c_string(output));
    });

    operation_id
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tlsn-mobile")
            .build()
            .expect("mobile Tokio runtime initializes")
    })
}

async fn run(request: NotarizeRequest) -> Result<NotarizeResponse, String> {
    let target = Url::parse(&request.url).map_err(|_| "invalid target URL".to_string())?;
    if target.scheme() != "https" {
        return Err("only HTTPS target URLs can be notarized".to_string());
    }
    let host = target
        .host_str()
        .ok_or_else(|| "target URL has no host".to_string())?;
    let port = target.port_or_known_default().unwrap_or(443);
    let notary = validate_notary_url(&request.notary_url)?;
    let session_id = format!("{:032x}", rand::random::<u128>());

    let notary_ws = websocket_endpoint(&notary, &format!("ws/notary/{session_id}"))?;
    let server_ws = websocket_endpoint(
        &notary,
        &format!("ws/tcp?host={}&port={port}", percent_encode(host)),
    )?;

    let notary_io = connect_websocket_io(notary_ws.as_str()).await?;
    let mut prover = SdkProver::new(
        ProverConfig::builder(host)
            .max_sent_data(32 * 1024)
            .max_recv_data(request.max_recv_data.unwrap_or(512 * 1024))
            .build(),
    )
    .map_err(|e| e.to_string())?;
    prover.setup(notary_io).await.map_err(|e| e.to_string())?;

    let server_io = connect_websocket_io(server_ws.as_str()).await?;
    let mut http_request = HttpRequest::get(request_target(&target));
    let mut headers = request.headers;
    headers
        .entry("Host".to_string())
        .or_insert_with(|| target_host_header(&target));
    headers
        .entry("Accept".to_string())
        .or_insert_with(|| "*/*".to_string());
    headers
        .entry("Accept-Encoding".to_string())
        .or_insert_with(|| "identity".to_string());
    headers
        .entry("Connection".to_string())
        .or_insert_with(|| "close".to_string());
    headers
        .entry("User-Agent".to_string())
        .or_insert_with(|| "TLSNotaryMobile/0.1".to_string());
    for (name, value) in headers {
        http_request = http_request.header(name, value.into_bytes());
    }

    let response = prover
        .send_request(server_io, http_request)
        .await
        .map_err(|e| e.to_string())?;
    let transcript = prover.transcript().map_err(|e| e.to_string())?;
    let reveal = if request.disclosed_fields.is_empty() {
        // No field selection ⇒ reveal the whole exchange (backwards-compatible default).
        Reveal::new()
            .sent(0..transcript.sent.len())
            .recv(0..transcript.recv.len())
            .server_identity(true)
    } else {
        // Selective disclosure: reveal only the chosen JSON fields of the response (plus the request
        // line, status, and Content-Type framing). The notary then co-signs a genuinely redacted
        // partial transcript — everything unselected, including cookies, stays hidden.
        let handlers = disclosure_handlers(&request.disclosed_fields);
        // Unlike the full-reveal branch above, this does not call `.server_identity(true)`:
        // `compute_reveal` already binds the server identity into the Reveal it returns (sdk-core
        // handler/mod.rs), so a redacted proof still names the server it came from.
        compute_reveal(&transcript.sent, &transcript.recv, &handlers)
            .map_err(|e| format!("selective reveal failed: {e}"))?
            .reveal
    };
    prover.reveal(reveal).await.map_err(|e| e.to_string())?;

    let snapshot = poll_session(&notary, &session_id).await?;
    let artifact_value = snapshot
        .get("artifact")
        .cloned()
        .ok_or_else(|| "notary completed without a signed artifact".to_string())?;
    let artifact: SignedArtifact = serde_json::from_value(artifact_value.clone())
        .map_err(|e| format!("invalid signed notary artifact: {e}"))?;
    let trusted_key = URL_SAFE_NO_PAD
        .decode(&request.trusted_notary_public_key)
        .map_err(|e| format!("invalid trusted notary public key: {e}"))?;
    artifact
        .verify(&trusted_key)
        .map_err(|e| format!("notary artifact verification failed: {e}"))?;
    if artifact.payload.session_id != session_id {
        return Err("notary artifact session identifier mismatch".to_string());
    }

    Ok(NotarizeResponse {
        session_id,
        response_status: response.status,
        response_body: BASE64.encode(response.body.unwrap_or_default()),
        notary_attestation: artifact_value,
    })
}

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
    url.set_scheme(if base.scheme() == "https" {
        "wss"
    } else {
        "ws"
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_mobile_endpoints() {
        let notary = validate_notary_url("https://notary.example/base").unwrap();
        assert_eq!(
            websocket_endpoint(&notary, "ws/notary/123")
                .unwrap()
                .as_str(),
            "wss://notary.example/base/ws/notary/123"
        );
    }

    #[test]
    fn only_loopback_may_use_plain_http() {
        assert!(validate_notary_url("http://127.0.0.1:3000").is_ok());
        assert!(validate_notary_url("http://notary.example").is_err());
    }

    #[test]
    fn json_pointer_to_dot_path_decodes_rfc6901() {
        assert_eq!(json_pointer_to_dot_path("/account"), "account");
        assert_eq!(
            json_pointer_to_dot_path("/account/status"),
            "account.status"
        );
        assert_eq!(json_pointer_to_dot_path("/items/0/id"), "items.0.id");
        // `~1` -> `/`
        assert_eq!(json_pointer_to_dot_path("/a~1b"), "a/b");
        // `~0` -> `~`
        assert_eq!(json_pointer_to_dot_path("/a~0b"), "a~b");
        // Order matters: `~1` is decoded BEFORE `~0`, so `~01` becomes the literal `~1`, not `/`.
        // This case fails if the two replacements are swapped.
        assert_eq!(json_pointer_to_dot_path("/a~01b"), "a~1b");
    }

    #[test]
    fn disclosure_handlers_reveal_only_framing_and_selected_response_fields() {
        let handlers =
            disclosure_handlers(&["/account/status".to_owned(), "/holder/name".to_owned()]);
        // Three framing handlers + one Recv/Body handler per selected field.
        assert_eq!(handlers.len(), 5);

        // Framing: request line (Sent), response status (Recv), response Content-Type (Recv).
        assert!(handlers
            .iter()
            .any(|h| h.handler_type == HandlerType::Sent && h.part == HandlerPart::StartLine));
        assert!(handlers
            .iter()
            .any(|h| h.handler_type == HandlerType::Recv && h.part == HandlerPart::StatusCode));
        assert!(handlers.iter().any(|h| h.handler_type == HandlerType::Recv
            && h.part == HandlerPart::Headers
            && h.params.as_ref().and_then(|p| p.key.as_deref()) == Some("content-type")));

        // Leakage guard: the request body and request headers (cookies) are NEVER revealed.
        assert!(!handlers
            .iter()
            .any(|h| h.handler_type == HandlerType::Sent && h.part == HandlerPart::Headers));
        assert!(!handlers
            .iter()
            .any(|h| h.handler_type == HandlerType::Sent && h.part == HandlerPart::Body));

        // Exactly the selected response-body paths, in dot-notation.
        let body_paths: Vec<String> = handlers
            .iter()
            .filter(|h| h.handler_type == HandlerType::Recv && h.part == HandlerPart::Body)
            .filter_map(|h| h.params.as_ref().and_then(|p| p.path.clone()))
            .collect();
        assert_eq!(
            body_paths,
            vec!["account.status".to_owned(), "holder.name".to_owned()]
        );
    }
}

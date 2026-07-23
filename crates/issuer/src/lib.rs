//! OpenID4VCI 1.0 issuer adapter for portable TLSNotary artifacts.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Form, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use tlsn_notary_artifact::SignedArtifact;

/// Credential configuration identifier exposed in issuer metadata.
pub const CREDENTIAL_CONFIGURATION_ID: &str = "TLSNotaryEvidenceCredential";
/// OpenID4VCI pre-authorized grant identifier.
pub const PRE_AUTHORIZED_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

const GRANT_LIFETIME: u64 = 300;
const TOKEN_LIFETIME: u64 = 300;
const NONCE_LIFETIME: u64 = 300;

/// Issuer service configuration.
#[derive(Clone)]
pub struct IssuerConfig {
    /// Externally visible issuer URL, without a trailing slash.
    pub issuer: String,
    /// SEC1-encoded public key of the trusted TLSNotary service.
    pub trusted_notary_key: Vec<u8>,
    /// Persistent P-256 issuer credential-signing key.
    pub signing_key: SigningKey,
}

#[derive(Clone)]
struct AppState {
    config: IssuerConfig,
    store: Arc<Mutex<Store>>,
}

#[derive(Default)]
struct Store {
    offers: HashMap<String, OfferGrant>,
    codes: HashMap<String, OfferGrant>,
    tokens: HashMap<String, TokenGrant>,
    nonces: HashMap<String, u64>,
}

#[derive(Clone)]
struct OfferGrant {
    artifact: SignedArtifact,
    expires_at: u64,
    code: String,
}

#[derive(Clone)]
struct TokenGrant {
    artifact: SignedArtifact,
    expires_at: u64,
}

/// Creates the OpenID4VCI issuer router.
pub fn app(config: IssuerConfig) -> Router {
    let state = AppState {
        config,
        store: Arc::new(Mutex::new(Store::default())),
    };
    Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route("/api/evidence", post(prepare_evidence))
        .route("/jwks.json", get(jwks))
        .route("/credential-offer/{offer_id}", get(credential_offer))
        .route("/token", post(token))
        .route("/nonce", post(nonce))
        .route("/credential", post(credential))
        .with_state(state)
}

async fn issuer_metadata(State(state): State<AppState>) -> Json<Value> {
    let issuer = &state.config.issuer;
    Json(json!({
        "credential_issuer": issuer,
        "credential_endpoint": format!("{issuer}/credential"),
        "nonce_endpoint": format!("{issuer}/nonce"),
        "credential_configurations_supported": {
            CREDENTIAL_CONFIGURATION_ID: {
                "format": "jwt_vc_json",
                "scope": CREDENTIAL_CONFIGURATION_ID,
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "credential_definition": {
                    "type": ["VerifiableCredential", CREDENTIAL_CONFIGURATION_ID]
                },
                "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                },
                "credential_metadata": {
                    "display": [{
                        "name": "TLSNotary Web Evidence",
                        "locale": "en",
                        "description": "Issuer-validated evidence from a notarized HTTPS session"
                    }]
                }
            }
        }
    }))
}

async fn authorization_server_metadata(State(state): State<AppState>) -> Json<Value> {
    let issuer = &state.config.issuer;
    Json(json!({
        "issuer": issuer,
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "grant_types_supported": [PRE_AUTHORIZED_GRANT],
        "token_endpoint_auth_methods_supported": ["none"],
        "pre-authorized_grant_anonymous_access_supported": true
    }))
}

async fn jwks(State(state): State<AppState>) -> Json<Value> {
    let mut jwk = jwk_from_verifying_key(state.config.signing_key.verifying_key());
    jwk["kid"] = Value::String("tlsn-issuer-1".into());
    jwk["use"] = Value::String("sig".into());
    jwk["alg"] = Value::String("ES256".into());
    Json(json!({"keys": [jwk]}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSubmission {
    artifact: SignedArtifact,
}

async fn prepare_evidence(
    State(state): State<AppState>,
    Json(input): Json<EvidenceSubmission>,
) -> Result<Json<Value>, ApiError> {
    input
        .artifact
        .verify(&state.config.trusted_notary_key)
        .map_err(|_| ApiError::bad_request("invalid_notary_artifact"))?;

    let offer_id = random_token();
    let code = random_token();
    let grant = OfferGrant {
        artifact: input.artifact,
        expires_at: now() + GRANT_LIFETIME,
        code: code.clone(),
    };
    let offer = offer_value(&state.config.issuer, &code);
    let offer_uri = format!("{}/credential-offer/{offer_id}", state.config.issuer);
    let wallet_uri = format!(
        "openid-credential-offer://?credential_offer_uri={}",
        percent_encode(&offer_uri)
    );
    let mut store = state.store.lock().expect("issuer store lock");
    store.offers.insert(offer_id, grant.clone());
    store.codes.insert(code, grant);

    Ok(Json(json!({
        "credential_offer": offer,
        "credential_offer_uri": offer_uri,
        "wallet_uri": wallet_uri,
        "expires_in": GRANT_LIFETIME
    })))
}

async fn credential_offer(
    State(state): State<AppState>,
    Path(offer_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut store = state.store.lock().expect("issuer store lock");
    prune(&mut store);
    let grant = store
        .offers
        .get(&offer_id)
        .ok_or_else(|| ApiError::not_found("invalid_credential_offer"))?;
    Ok(Json(offer_value(&state.config.issuer, &grant.code)))
}

fn offer_value(issuer: &str, code: &str) -> Value {
    json!({
        "credential_issuer": issuer,
        "credential_configuration_ids": [CREDENTIAL_CONFIGURATION_ID],
        "grants": {
            PRE_AUTHORIZED_GRANT: {"pre-authorized_code": code}
        }
    })
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: String,
}

async fn token(
    State(state): State<AppState>,
    Form(input): Form<TokenRequest>,
) -> Result<Json<Value>, ApiError> {
    if input.grant_type != PRE_AUTHORIZED_GRANT {
        return Err(ApiError::bad_request("unsupported_grant_type"));
    }
    let mut store = state.store.lock().expect("issuer store lock");
    prune(&mut store);
    let grant = store
        .codes
        .remove(&input.pre_authorized_code)
        .ok_or_else(|| ApiError::bad_request("invalid_grant"))?;
    let access_token = random_token();
    store.tokens.insert(
        access_token.clone(),
        TokenGrant {
            artifact: grant.artifact,
            expires_at: now() + TOKEN_LIFETIME,
        },
    );
    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME,
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID
        }]
    })))
}

async fn nonce(State(state): State<AppState>) -> Json<Value> {
    let nonce = random_token();
    state
        .store
        .lock()
        .expect("issuer store lock")
        .nonces
        .insert(nonce.clone(), now() + NONCE_LIFETIME);
    Json(json!({"c_nonce": nonce, "expires_in": NONCE_LIFETIME}))
}

#[derive(Deserialize)]
struct CredentialRequest {
    credential_configuration_id: String,
    proofs: HashMap<String, Vec<String>>,
}

async fn credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CredentialRequest>,
) -> Result<Json<Value>, ApiError> {
    if input.credential_configuration_id != CREDENTIAL_CONFIGURATION_ID {
        return Err(ApiError::bad_request("unsupported_credential_type"));
    }
    let access_token = bearer(&headers)?;
    let proof = input
        .proofs
        .get("jwt")
        .and_then(|proofs| proofs.first())
        .ok_or_else(|| ApiError::bad_request("invalid_proof"))?;

    let mut store = state.store.lock().expect("issuer store lock");
    prune(&mut store);
    let grant = store
        .tokens
        .remove(access_token)
        .ok_or_else(|| ApiError::unauthorized("invalid_token"))?;
    let holder_jwk = verify_key_proof(proof, &state.config.issuer, &mut store.nonces)?;
    let issued = issue_credential(&state.config, &grant.artifact, holder_jwk)?;
    Ok(Json(json!({
        "credentials": [{"credential": issued}]
    })))
}

fn verify_key_proof(
    jwt: &str,
    expected_audience: &str,
    nonces: &mut HashMap<String, u64>,
) -> Result<Value, ApiError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(ApiError::bad_request("invalid_proof"));
    }
    let header: Value = decode_json(parts[0])?;
    if header["alg"] != "ES256" || header["typ"] != "openid4vci-proof+jwt" {
        return Err(ApiError::bad_request("invalid_proof"));
    }
    let jwk = header
        .get("jwk")
        .cloned()
        .ok_or_else(|| ApiError::bad_request("invalid_proof"))?;
    let key = verifying_key_from_jwk(&jwk)?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or_else(|| ApiError::bad_request("invalid_proof"))?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| ApiError::bad_request("invalid_proof"))?;

    let claims: Value = decode_json(parts[1])?;
    if claims["aud"] != expected_audience {
        return Err(ApiError::bad_request("invalid_proof"));
    }
    let issued_at = claims["iat"]
        .as_u64()
        .ok_or_else(|| ApiError::bad_request("invalid_proof"))?;
    if issued_at.abs_diff(now()) > 300 {
        return Err(ApiError::bad_request("invalid_proof"));
    }
    let nonce = claims["nonce"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("invalid_nonce"))?;
    match nonces.remove(nonce) {
        Some(expiry) if expiry >= now() => Ok(jwk),
        _ => Err(ApiError::bad_request("invalid_nonce")),
    }
}

fn issue_credential(
    config: &IssuerConfig,
    artifact: &SignedArtifact,
    holder_jwk: Value,
) -> Result<String, ApiError> {
    let issued_at = now();
    let header = json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": "tlsn-issuer-1",
        "jwk": jwk_from_verifying_key(config.signing_key.verifying_key())
    });
    let payload = json!({
        "iss": config.issuer,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + 86400,
        "jti": random_token(),
        "cnf": {"jwk": holder_jwk},
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", CREDENTIAL_CONFIGURATION_ID],
            "issuer": config.issuer,
            "credentialSubject": {"tlsNotaryArtifact": artifact}
        }
    });
    sign_jwt(&config.signing_key, &header, &payload)
}

fn sign_jwt(key: &SigningKey, header: &Value, payload: &Value) -> Result<String, ApiError> {
    let header =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).map_err(|_| ApiError::server_error())?);
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).map_err(|_| ApiError::server_error())?);
    let signing_input = format!("{header}.{payload}");
    let signature: Signature = key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn verifying_key_from_jwk(jwk: &Value) -> Result<VerifyingKey, ApiError> {
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(ApiError::bad_request("invalid_proof"));
    }
    let x = decode_coordinate(&jwk["x"])?;
    let y = decode_coordinate(&jwk["y"])?;
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend(x);
    point.extend(y);
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| ApiError::bad_request("invalid_proof"))
}

fn decode_coordinate(value: &Value) -> Result<Vec<u8>, ApiError> {
    let bytes = value
        .as_str()
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .ok_or_else(|| ApiError::bad_request("invalid_proof"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request("invalid_proof"));
    }
    Ok(bytes)
}

fn jwk_from_verifying_key(key: &VerifyingKey) -> Value {
    let point = key.to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed key")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed key"))
    })
}

fn decode_json(value: &str) -> Result<Value, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request("invalid_proof"))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::bad_request("invalid_proof"))
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("invalid_token"))
}

fn prune(store: &mut Store) {
    let now = now();
    store.offers.retain(|_, grant| grant.expires_at >= now);
    store.codes.retain(|_, grant| grant.expires_at >= now);
    store.tokens.retain(|_, grant| grant.expires_at >= now);
    store.nonces.retain(|_, expiry| *expiry >= now);
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_secs()
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    error: &'static str,
}

impl ApiError {
    fn bad_request(error: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error,
        }
    }

    fn unauthorized(error: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error,
        }
    }

    fn not_found(error: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error,
        }
    }

    fn server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.error}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;
    use tlsn_notary_artifact::ArtifactSigner;

    fn setup() -> (Router, ArtifactSigner, SigningKey) {
        let notary = ArtifactSigner::from_bytes(&[7; 32]).unwrap();
        let issuer_key = SigningKey::from_slice(&[9; 32]).unwrap();
        let router = app(IssuerConfig {
            issuer: "https://issuer.example".into(),
            trusted_notary_key: notary.public_key(),
            signing_key: issuer_key.clone(),
        });
        (router, notary, issuer_key)
    }

    fn artifact(signer: &ArtifactSigner) -> SignedArtifact {
        signer
            .sign(
                "session-1",
                now(),
                json!({"serverName": "example.com", "transcript": null}),
            )
            .unwrap()
    }

    async fn json_body(response: Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn prepare(router: &Router, artifact: SignedArtifact) -> Value {
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/evidence")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"artifact": artifact})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    #[tokio::test]
    async fn discovery_matches_openid4vci_final_shape() {
        let (router, _, _) = setup();
        let response = router
            .oneshot(
                Request::get("/.well-known/openid-credential-issuer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let metadata = json_body(response).await;
        assert_eq!(metadata["credential_issuer"], "https://issuer.example");
        assert_eq!(
            metadata["credential_configurations_supported"][CREDENTIAL_CONFIGURATION_ID]["format"],
            "jwt_vc_json"
        );
        assert_eq!(
            metadata["credential_configurations_supported"][CREDENTIAL_CONFIGURATION_ID]["proof_types_supported"]
                ["jwt"]["proof_signing_alg_values_supported"][0],
            "ES256"
        );
    }

    #[tokio::test]
    async fn rejects_artifact_from_untrusted_notary() {
        let (router, _, _) = setup();
        let wrong = ArtifactSigner::from_bytes(&[8; 32]).unwrap();
        let response = router
            .oneshot(
                Request::post("/api/evidence")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"artifact": artifact(&wrong)})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn pre_authorized_flow_is_single_use_and_holder_bound() {
        let (router, notary, issuer_key) = setup();
        let offer = prepare(&router, artifact(&notary)).await;
        let code = offer["credential_offer"]["grants"][PRE_AUTHORIZED_GRANT]["pre-authorized_code"]
            .as_str()
            .unwrap();
        let form = format!(
            "grant_type={}&pre-authorized_code={}",
            percent_encode(PRE_AUTHORIZED_GRANT),
            percent_encode(code)
        );
        let token_response = router
            .clone()
            .oneshot(
                Request::post("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(token_response.status(), StatusCode::OK);
        let token = json_body(token_response).await["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let replay = router
            .clone()
            .oneshot(
                Request::post("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

        let nonce_response = router
            .clone()
            .oneshot(Request::post("/nonce").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let nonce = json_body(nonce_response).await["c_nonce"]
            .as_str()
            .unwrap()
            .to_string();
        let wallet_key = SigningKey::from_slice(&[11; 32]).unwrap();
        let wallet_jwk = jwk_from_verifying_key(wallet_key.verifying_key());
        let proof = sign_jwt(
            &wallet_key,
            &json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "jwk": wallet_jwk
            }),
            &json!({
                "aud": "https://issuer.example",
                "iat": now(),
                "nonce": nonce
            }),
        )
        .unwrap();
        let credential_response = router
            .clone()
            .oneshot(
                Request::post("/credential")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID,
                            "proofs": {"jwt": [proof]}
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(credential_response.status(), StatusCode::OK);
        let credential = json_body(credential_response).await["credentials"][0]["credential"]
            .as_str()
            .unwrap()
            .to_string();
        let parts: Vec<_> = credential.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        issuer_key
            .verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        let claims: Value = decode_json(parts[1]).unwrap();
        assert_eq!(claims["cnf"]["jwk"], wallet_jwk);
        assert_eq!(
            claims["vc"]["credentialSubject"]["tlsNotaryArtifact"]["payload"]["sessionId"],
            "session-1"
        );
    }

    #[test]
    fn rejects_wrong_audience_and_replayed_nonce() {
        let wallet_key = SigningKey::from_slice(&[11; 32]).unwrap();
        let wrong_audience_nonce = "wrong-audience";
        let wrong_audience_proof = sign_jwt(
            &wallet_key,
            &json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "jwk": jwk_from_verifying_key(wallet_key.verifying_key())
            }),
            &json!({
                "aud": "https://wrong.example",
                "iat": now(),
                "nonce": wrong_audience_nonce
            }),
        )
        .unwrap();
        let mut nonces = HashMap::from([(wrong_audience_nonce.to_string(), now() + 60)]);
        assert!(
            verify_key_proof(&wrong_audience_proof, "https://issuer.example", &mut nonces).is_err()
        );
        assert!(nonces.contains_key(wrong_audience_nonce));

        let replayed_nonce = "single-use";
        let valid_proof = sign_jwt(
            &wallet_key,
            &json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "jwk": jwk_from_verifying_key(wallet_key.verifying_key())
            }),
            &json!({
                "aud": "https://issuer.example",
                "iat": now(),
                "nonce": replayed_nonce
            }),
        )
        .unwrap();
        nonces.insert(replayed_nonce.to_string(), now() + 60);
        verify_key_proof(&valid_proof, "https://issuer.example", &mut nonces).unwrap();
        assert!(verify_key_proof(&valid_proof, "https://issuer.example", &mut nonces).is_err());
    }
}

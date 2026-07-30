//! Stable C ABI used by the TLSNotary Swift package.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![forbid(unsafe_op_in_unsafe_fn)]

use std::{
    ffi::{c_char, CStr, CString},
    panic::{catch_unwind, AssertUnwindSafe},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

mod notarize;

pub use notarize::{tlsn_mobile_notarize, TlsnMobileCallback};

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_DISCLOSURES: usize = 128;
const PORTABLE_EVIDENCE_VERSION: u32 = 1;
const DEFAULT_FRESHNESS_SECONDS: i64 = 300;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceRequest {
    url: String,
    method: String,
    retrieved_at: String,
    response_body: String,
    disclosed_fields: Vec<String>,
    holder: String,
    #[serde(default)]
    notary_attestation: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FfiError<'a> {
    error: &'a str,
}

/// Returns the ABI version implemented by this library.
#[no_mangle]
pub extern "C" fn tlsn_mobile_abi_version() -> u32 {
    1
}

/// Constructs an unsigned TLSNotary evidence credential from a UTF-8 JSON
/// request. The returned string must be released with
/// [`tlsn_mobile_string_free`]. Errors are returned as `{ "error": "..." }`.
///
/// A null input returns a JSON error. Panics are contained at the ABI boundary.
#[no_mangle]
pub extern "C" fn tlsn_mobile_create_evidence(request_json: *const c_char) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| create_from_pointer(request_json)))
        .unwrap_or_else(|_| error_json("internal Rust panic"));
    into_c_string(result)
}

/// Releases a string returned by this library.
///
/// Passing null is allowed.
#[no_mangle]
pub unsafe extern "C" fn tlsn_mobile_string_free(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: callers may only pass an owned pointer returned by
        // `CString::into_raw` from this library, as documented above.
        drop(unsafe { CString::from_raw(value) });
    }
}

fn create_from_pointer(request_json: *const c_char) -> String {
    if request_json.is_null() {
        return error_json("request is null");
    }

    // SAFETY: the ABI contract requires a non-null, NUL-terminated C string.
    let bytes = unsafe { CStr::from_ptr(request_json) }.to_bytes();
    if bytes.len() > MAX_INPUT_BYTES {
        return error_json("request exceeds 2 MiB");
    }

    let Ok(request) = serde_json::from_slice::<EvidenceRequest>(bytes) else {
        return error_json("invalid evidence request JSON");
    };

    match create_evidence(request) {
        Ok(value) => serde_json::to_string(&value).expect("JSON values serialize"),
        Err(message) => error_json(message),
    }
}

fn create_evidence(request: EvidenceRequest) -> Result<Value, &'static str> {
    let url = Url::parse(&request.url).map_err(|_| "invalid URL")?;
    if url.scheme() != "https" {
        return Err("only HTTPS URLs can be notarized");
    }
    let origin = url.origin().ascii_serialization();
    if origin == "null" || url.host_str().is_none() {
        return Err("URL must have a network host");
    }
    if !request.method.eq_ignore_ascii_case("GET") {
        return Err("initial mobile flow supports GET only");
    }
    if request.holder.trim().is_empty() {
        return Err("holder identifier is required");
    }
    if request.retrieved_at.trim().is_empty() {
        return Err("retrieval time is required");
    }
    if request.disclosed_fields.len() > MAX_DISCLOSURES {
        return Err("too many disclosed fields");
    }

    let response_body = STANDARD
        .decode(request.response_body.as_bytes())
        .map_err(|_| "response body is not valid base64")?;
    if response_body.len() > MAX_INPUT_BYTES {
        return Err("response body exceeds 2 MiB");
    }
    let retrieved_at = chrono::DateTime::parse_from_rfc3339(&request.retrieved_at)
        .map_err(|_| "retrieval time is not RFC 3339")?;
    let fresh_until = retrieved_at
        .checked_add_signed(chrono::Duration::seconds(DEFAULT_FRESHNESS_SECONDS))
        .ok_or("freshness interval overflows")?;
    let mut disclosed_fields = request.disclosed_fields;
    disclosed_fields.sort();
    if disclosed_fields.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("disclosed fields must be unique");
    }

    let attestation = serde_json::to_vec(&request.notary_attestation)
        .map_err(|_| "notary attestation cannot be canonicalized")?;
    let disclosures = serde_json::to_vec(&disclosed_fields)
        .map_err(|_| "disclosed fields cannot be canonicalized")?;
    let schema = b"dev.advatar.tlsn.evidence.1";
    let status = b"active";
    let portable_evidence = json!({
        "version": PORTABLE_EVIDENCE_VERSION,
        "notaryIdentityCommitment": commitment("notary-identity", &attestation),
        "serverIdentityCommitment": commitment("server-identity", origin.as_bytes()),
        "transcriptCommitment": commitment("transcript", &response_body),
        "disclosedFieldsCommitment": commitment("disclosed-fields", &disclosures),
        "holderBindingCommitment": commitment("holder-binding", request.holder.as_bytes()),
        "schemaCommitment": commitment("schema", schema),
        "observedAt": request.retrieved_at,
        "freshUntil": fresh_until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "statusCommitment": commitment("status", status),
        "assurance": "holderSelfIssued",
        "issuerAuthorizationCommitment": Value::Null,
    });

    let response_hash = blake3::hash(&response_body).to_hex();
    Ok(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "TlsNotaryEvidenceCredential"],
        "issuer": request.holder,
        "validFrom": request.retrieved_at,
        "credentialSubject": {
            "id": request.holder,
            "origin": origin,
            "url": url.as_str(),
            "httpMethod": "GET",
            "responseBodyHash": format!("blake3:{response_hash}"),
            "disclosedFields": disclosed_fields,
        },
        "evidence": [{
            "type": "TlsNotaryEvidence",
            "notaryAttestation": request.notary_attestation,
            "portableEvidence": portable_evidence,
        }]
    }))
}

fn commitment(domain: &str, value: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ADVAtAR-TLS-CREDENTIAL-COMMITMENT-V1");
    hasher.update(&(domain.len() as u32).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
    let mut bytes = [0_u8; 48];
    hasher.finalize_xof().fill(&mut bytes);
    hex::encode(bytes)
}

fn error_json(error: &str) -> String {
    serde_json::to_string(&FfiError { error }).expect("error serializes")
}

fn into_c_string(value: String) -> *mut c_char {
    CString::new(value)
        .unwrap_or_else(|_| CString::new(error_json("response contains NUL")).unwrap())
        .into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> String {
        json!({
            "url": url,
            "method": "GET",
            "retrievedAt": "2026-07-22T12:00:00Z",
            "responseBody": STANDARD.encode("{\"account\":\"verified\"}"),
            "disclosedFields": ["/account"],
            "holder": "did:key:test-holder",
            "notaryAttestation": {"signature": "test"}
        })
        .to_string()
    }

    #[test]
    fn builds_evidence_credential() {
        let input = CString::new(request("https://example.com/account")).unwrap();
        let output = tlsn_mobile_create_evidence(input.as_ptr());
        assert!(!output.is_null());
        let value: Value = unsafe { CStr::from_ptr(output) }
            .to_str()
            .map(serde_json::from_str)
            .unwrap()
            .unwrap();
        unsafe { tlsn_mobile_string_free(output) };

        assert_eq!(value["credentialSubject"]["origin"], "https://example.com");
        assert_eq!(
            value["evidence"][0]["notaryAttestation"]["signature"],
            "test"
        );
        assert!(value["credentialSubject"]["responseBodyHash"]
            .as_str()
            .unwrap()
            .starts_with("blake3:"));
        let portable = &value["evidence"][0]["portableEvidence"];
        assert_eq!(portable["version"], 1);
        assert_eq!(portable["assurance"], "holderSelfIssued");
        assert!(portable["issuerAuthorizationCommitment"].is_null());
        for field in [
            "notaryIdentityCommitment",
            "serverIdentityCommitment",
            "transcriptCommitment",
            "disclosedFieldsCommitment",
            "holderBindingCommitment",
            "schemaCommitment",
            "statusCommitment",
        ] {
            assert_eq!(portable[field].as_str().unwrap().len(), 96);
        }
        assert_eq!(portable["freshUntil"], "2026-07-22T12:05:00Z");
    }

    #[test]
    fn commitments_are_deterministic_and_bind_holder_and_transcript() {
        let original =
            serde_json::from_str::<EvidenceRequest>(&request("https://example.com")).unwrap();
        let first = create_evidence(original).unwrap();
        let second = create_evidence(
            serde_json::from_str::<EvidenceRequest>(&request("https://example.com")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            first["evidence"][0]["portableEvidence"],
            second["evidence"][0]["portableEvidence"]
        );

        let mut changed: Value = serde_json::from_str(&request("https://example.com")).unwrap();
        changed["holder"] = "did:key:other-holder".into();
        changed["responseBody"] = STANDARD.encode("different").into();
        let changed = create_evidence(serde_json::from_value(changed).unwrap()).unwrap();
        assert_ne!(
            first["evidence"][0]["portableEvidence"]["holderBindingCommitment"],
            changed["evidence"][0]["portableEvidence"]["holderBindingCommitment"]
        );
        assert_ne!(
            first["evidence"][0]["portableEvidence"]["transcriptCommitment"],
            changed["evidence"][0]["portableEvidence"]["transcriptCommitment"]
        );
    }

    #[test]
    fn rejects_duplicate_disclosures_and_malformed_time_or_body() {
        for (field, value, expected) in [
            (
                "retrievedAt",
                json!("not-a-time"),
                "retrieval time is not RFC 3339",
            ),
            (
                "responseBody",
                json!("%%%"),
                "response body is not valid base64",
            ),
            (
                "disclosedFields",
                json!(["/account", "/account"]),
                "disclosed fields must be unique",
            ),
        ] {
            let mut input: Value = serde_json::from_str(&request("https://example.com")).unwrap();
            input[field] = value;
            let parsed = serde_json::from_value(input).unwrap();
            assert_eq!(create_evidence(parsed), Err(expected));
        }
    }

    #[test]
    fn portable_evidence_conformance_matrix_is_closed_and_consistent() {
        let vector = include_str!("../../../testing/vectors/tls-portable-evidence-v1.tsv");
        let mut lines = vector.lines();
        assert_eq!(
            lines.next(),
            Some("case\tversion\tcommitments\tobserved\tfresh_until\tassurance\tissuer_authorization\texpected\treason")
        );
        let mut cases = 0;
        for line in lines {
            let columns = line.split('\t').collect::<Vec<_>>();
            assert_eq!(columns.len(), 9, "malformed vector row: {line}");
            let assurance_valid = matches!(
                columns[5],
                "tls_notarized_evidence"
                    | "holder_self_issued"
                    | "issuer_upgraded"
                    | "regulated_attestation"
            );
            let elevated = matches!(columns[5], "issuer_upgraded" | "regulated_attestation");
            let authorization_valid = if elevated {
                columns[6] == "nonzero_digest384"
            } else {
                columns[6] == "absent"
            };
            let accepted = columns[1] == "1"
                && columns[2] == "nonzero_digest384"
                && columns[3] == "past"
                && columns[4] == "future"
                && assurance_valid
                && authorization_valid;
            assert_eq!(accepted, columns[7] == "accept", "case {}", columns[0]);
            cases += 1;
        }
        assert_eq!(cases, 17);
    }

    #[test]
    fn rejects_non_https_and_bad_methods() {
        let non_https: EvidenceRequest =
            serde_json::from_str(&request("http://example.com")).unwrap();
        assert_eq!(
            create_evidence(non_https).unwrap_err(),
            "only HTTPS URLs can be notarized"
        );

        let mut value: Value = serde_json::from_str(&request("https://example.com")).unwrap();
        value["method"] = "POST".into();
        let post = serde_json::from_value(value).unwrap();
        assert_eq!(
            create_evidence(post).unwrap_err(),
            "initial mobile flow supports GET only"
        );
    }

    #[test]
    fn null_pointer_is_contained() {
        let output = tlsn_mobile_create_evidence(std::ptr::null());
        let value = unsafe { CStr::from_ptr(output) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { tlsn_mobile_string_free(output) };
        assert_eq!(value, r#"{"error":"request is null"}"#);
    }
}

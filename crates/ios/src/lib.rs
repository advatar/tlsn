//! Stable C ABI used by the TLSNotary Swift package.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![forbid(unsafe_op_in_unsafe_fn)]

use std::{
    ffi::{c_char, CStr, CString},
    panic::{catch_unwind, AssertUnwindSafe},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

mod notarize;

pub use notarize::{TlsnMobileCallback, tlsn_mobile_notarize};

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_DISCLOSURES: usize = 128;

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

    let response_hash = blake3::hash(request.response_body.as_bytes()).to_hex();
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
            "disclosedFields": request.disclosed_fields,
        },
        "evidence": [{
            "type": "TlsNotaryEvidence",
            "notaryAttestation": request.notary_attestation,
        }]
    }))
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
            "responseBody": "{\"account\":\"verified\"}",
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

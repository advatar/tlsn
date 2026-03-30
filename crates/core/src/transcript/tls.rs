//! TLS transcript.

use crate::{
    connection::{
        CertBinding, CertBindingV1_2, CertBindingV1_3, ServerEphemKey, ServerSignature, TlsVersion,
        VerifyData,
    },
    transcript::{Direction, Transcript},
    webpki::CertificateDer,
};
use tls_core::msgs::{
    alert::AlertMessagePayload,
    codec::{Codec, Reader},
    enums::{AlertDescription, ProtocolVersion},
    handshake::{HandshakeMessagePayload, HandshakePayload},
};

/// TLS record content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentType {
    /// Change cipher spec protocol.
    ChangeCipherSpec,
    /// Alert protocol.
    Alert,
    /// Handshake protocol.
    Handshake,
    /// Application data protocol.
    ApplicationData,
    /// Heartbeat protocol.
    Heartbeat,
    /// Unknown protocol.
    Unknown(u8),
}

impl From<ContentType> for tls_core::msgs::enums::ContentType {
    fn from(content_type: ContentType) -> Self {
        match content_type {
            ContentType::ChangeCipherSpec => tls_core::msgs::enums::ContentType::ChangeCipherSpec,
            ContentType::Alert => tls_core::msgs::enums::ContentType::Alert,
            ContentType::Handshake => tls_core::msgs::enums::ContentType::Handshake,
            ContentType::ApplicationData => tls_core::msgs::enums::ContentType::ApplicationData,
            ContentType::Heartbeat => tls_core::msgs::enums::ContentType::Heartbeat,
            ContentType::Unknown(id) => tls_core::msgs::enums::ContentType::Unknown(id),
        }
    }
}

impl From<tls_core::msgs::enums::ContentType> for ContentType {
    fn from(content_type: tls_core::msgs::enums::ContentType) -> Self {
        match content_type {
            tls_core::msgs::enums::ContentType::ChangeCipherSpec => ContentType::ChangeCipherSpec,
            tls_core::msgs::enums::ContentType::Alert => ContentType::Alert,
            tls_core::msgs::enums::ContentType::Handshake => ContentType::Handshake,
            tls_core::msgs::enums::ContentType::ApplicationData => ContentType::ApplicationData,
            tls_core::msgs::enums::ContentType::Heartbeat => ContentType::Heartbeat,
            tls_core::msgs::enums::ContentType::Unknown(id) => ContentType::Unknown(id),
        }
    }
}

/// A transcript of TLS records sent and received by the prover.
#[derive(Debug, Clone)]
pub struct TlsTranscript {
    time: u64,
    version: TlsVersion,
    server_cert_chain: Option<Vec<CertificateDer>>,
    server_signature: Option<ServerSignature>,
    certificate_binding: CertBinding,
    tls13_records_authenticated: bool,
    sent: Vec<Record>,
    recv: Vec<Record>,
}

/// TLS 1.3 proof metadata captured by the notary transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tls13ProofMetadata {
    /// Whether the TLS 1.3 records were authenticated during transcript capture.
    pub records_authenticated: bool,
}

impl TlsTranscript {
    /// Creates a new TLS transcript.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time: u64,
        version: TlsVersion,
        server_cert_chain: Option<Vec<CertificateDer>>,
        server_signature: Option<ServerSignature>,
        certificate_binding: CertBinding,
        tls13_records_authenticated: bool,
        verify_data: VerifyData,
        sent: Vec<Record>,
        recv: Vec<Record>,
    ) -> Result<Self, TlsTranscriptError> {
        let mut sent_iter = sent.iter();
        let mut recv_iter = recv.iter();
        let wire_version = match version {
            TlsVersion::V1_2 => ProtocolVersion::TLSv1_2,
            TlsVersion::V1_3 => ProtocolVersion::TLSv1_3,
        };

        match version {
            TlsVersion::V1_2 => {
                // Make sure the client finished verify data message was sent first.
                if let Some(record) = sent_iter.next() {
                    let payload =
                        record
                            .plaintext
                            .as_ref()
                            .ok_or(TlsTranscriptError::validation(
                                "client finished message was hidden from the follower",
                            ))?;

                    let mut reader = Reader::init(payload);
                    let payload = HandshakeMessagePayload::read_version(&mut reader, wire_version)
                        .ok_or(TlsTranscriptError::validation(
                            "first record sent was not a handshake message",
                        ))?;

                    let HandshakePayload::Finished(vd) = payload.payload else {
                        return Err(TlsTranscriptError::validation(
                            "first record sent was not a client finished message",
                        ));
                    };

                    if vd.0 != verify_data.client_finished {
                        return Err(TlsTranscriptError::validation(
                            "inconsistent client finished verify data",
                        ));
                    }
                } else {
                    return Err(TlsTranscriptError::validation(
                        "client finished was not sent",
                    ));
                }

                // Make sure the server finished verify data message was received first.
                if let Some(record) = recv_iter.next() {
                    let payload =
                        record
                            .plaintext
                            .as_ref()
                            .ok_or(TlsTranscriptError::validation(
                                "server finished message was hidden from the follower",
                            ))?;

                    let mut reader = Reader::init(payload);
                    let payload = HandshakeMessagePayload::read_version(&mut reader, wire_version)
                        .ok_or(TlsTranscriptError::validation(
                            "first record received was not a handshake message",
                        ))?;

                    let HandshakePayload::Finished(vd) = payload.payload else {
                        return Err(TlsTranscriptError::validation(
                            "first record received was not a server finished message",
                        ));
                    };

                    if vd.0 != verify_data.server_finished {
                        return Err(TlsTranscriptError::validation(
                            "inconsistent server finished verify data",
                        ));
                    }
                } else {
                    return Err(TlsTranscriptError::validation(
                        "server finished was not received",
                    ));
                }
            }
            TlsVersion::V1_3 => {
                validate_tls13_finished(
                    sent.iter(),
                    wire_version,
                    verify_data.client_finished.as_slice(),
                    "client",
                )?;
                validate_tls13_finished(
                    recv.iter(),
                    wire_version,
                    verify_data.server_finished.as_slice(),
                    "server",
                )?;
            }
        }

        match version {
            TlsVersion::V1_2 => {
                // Verify last record sent was either application data or close notify.
                if let Some(record) = sent_iter.next_back() {
                    match record.typ {
                        ContentType::ApplicationData => {}
                        ContentType::Alert => validate_close_notify(record, "sent")?,
                        typ => {
                            return Err(TlsTranscriptError::validation(format!(
                                "sent unexpected record content type: {typ:?}"
                            )))
                        }
                    }
                }

                // Verify last record received was either application data or close notify.
                if let Some(record) = recv_iter.next_back() {
                    match record.typ {
                        ContentType::ApplicationData => {}
                        ContentType::Alert => validate_close_notify(record, "received")?,
                        typ => {
                            return Err(TlsTranscriptError::validation(format!(
                                "received unexpected record content type: {typ:?}"
                            )))
                        }
                    }
                }

                // Ensure all other records were application data.
                for record in sent_iter {
                    if record.typ != ContentType::ApplicationData {
                        return Err(TlsTranscriptError::validation(format!(
                            "sent unexpected record content type: {:?}",
                            record.typ
                        )));
                    }
                }

                for record in recv_iter {
                    if record.typ != ContentType::ApplicationData {
                        return Err(TlsTranscriptError::validation(format!(
                            "received unexpected record content type: {:?}",
                            record.typ
                        )));
                    }
                }
            }
            TlsVersion::V1_3 => {
                validate_tls13_record_types(sent.iter(), "sent")?;
                validate_tls13_record_types(recv.iter(), "received")?;
            }
        }

        Ok(Self {
            time,
            version,
            server_cert_chain,
            server_signature,
            certificate_binding,
            tls13_records_authenticated,
            sent,
            recv,
        })
    }

    /// Returns the start time of the connection.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// Returns the TLS protocol version.
    pub fn version(&self) -> &TlsVersion {
        &self.version
    }

    /// Returns the server certificate chain.
    pub fn server_cert_chain(&self) -> Option<&[CertificateDer]> {
        self.server_cert_chain.as_deref()
    }

    /// Returns the server signature.
    pub fn server_signature(&self) -> Option<&ServerSignature> {
        self.server_signature.as_ref()
    }

    /// Returns the server ephemeral key used in the TLS handshake.
    pub fn server_ephemeral_key(&self) -> &ServerEphemKey {
        match &self.certificate_binding {
            CertBinding::V1_2(CertBindingV1_2 {
                server_ephemeral_key,
                ..
            }) => server_ephemeral_key,
            CertBinding::V1_3(CertBindingV1_3 {
                server_ephemeral_key,
                ..
            }) => server_ephemeral_key,
        }
    }

    /// Returns the certificate binding data.
    pub fn certificate_binding(&self) -> &CertBinding {
        &self.certificate_binding
    }

    /// Returns TLS 1.3 proof metadata, if this is a TLS 1.3 transcript.
    pub fn tls13_proof_metadata(&self) -> Option<Tls13ProofMetadata> {
        matches!(self.version, TlsVersion::V1_3).then_some(Tls13ProofMetadata {
            records_authenticated: self.tls13_records_authenticated,
        })
    }

    /// Returns the sent records.
    pub fn sent(&self) -> &[Record] {
        &self.sent
    }

    /// Returns the received records.
    pub fn recv(&self) -> &[Record] {
        &self.recv
    }

    /// Returns the application data transcript.
    pub fn to_transcript(&self) -> Result<Transcript, TlsTranscriptError> {
        let mut sent = Vec::new();
        let mut recv = Vec::new();

        for record in self
            .sent
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(ErrorRepr::Incomplete {
                    direction: Direction::Sent,
                    seq: record.seq,
                })?
                .clone();
            sent.extend_from_slice(&plaintext);
        }

        for record in self
            .recv
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(ErrorRepr::Incomplete {
                    direction: Direction::Received,
                    seq: record.seq,
                })?
                .clone();
            recv.extend_from_slice(&plaintext);
        }

        Ok(Transcript::new(sent, recv))
    }
}

fn validate_tls13_finished<'a>(
    records: impl IntoIterator<Item = &'a Record>,
    wire_version: ProtocolVersion,
    expected_verify_data: &[u8],
    side: &str,
) -> Result<(), TlsTranscriptError> {
    for record in records {
        let Some(payload) = record.plaintext.as_ref() else {
            continue;
        };

        let mut reader = Reader::init(payload);
        let Some(payload) = HandshakeMessagePayload::read_version(&mut reader, wire_version) else {
            continue;
        };

        let HandshakePayload::Finished(vd) = payload.payload else {
            continue;
        };

        if vd.0 != expected_verify_data {
            return Err(TlsTranscriptError::validation(format!(
                "inconsistent {side} finished verify data",
            )));
        }

        return Ok(());
    }

    Err(TlsTranscriptError::validation(format!(
        "{side} finished was not observed in the transcript",
    )))
}

fn validate_close_notify(record: &Record, side: &str) -> Result<(), TlsTranscriptError> {
    let payload = record
        .plaintext
        .as_ref()
        .ok_or(TlsTranscriptError::validation(
            "alert content was hidden from the follower",
        ))?;

    let mut reader = Reader::init(payload);
    let payload = AlertMessagePayload::read(&mut reader)
        .ok_or(TlsTranscriptError::validation("alert message was malformed"))?;

    let AlertDescription::CloseNotify = payload.description else {
        return Err(TlsTranscriptError::validation(format!(
            "{side} alert that is not close notify",
        )));
    };

    Ok(())
}

fn validate_tls13_record_types<'a>(
    records: impl IntoIterator<Item = &'a Record>,
    side: &str,
) -> Result<(), TlsTranscriptError> {
    for record in records {
        match record.typ {
            ContentType::Handshake | ContentType::ApplicationData => {}
            ContentType::Alert => validate_close_notify(record, side)?,
            typ => {
                return Err(TlsTranscriptError::validation(format!(
                    "{side} unexpected record content type: {typ:?}",
                )))
            }
        }
    }

    Ok(())
}

/// A TLS record.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Record {
    /// Sequence number.
    pub seq: u64,
    /// Content type.
    pub typ: ContentType,
    /// Plaintext.
    pub plaintext: Option<Vec<u8>>,
    /// Explicit nonce.
    pub explicit_nonce: Vec<u8>,
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
    /// Tag.
    pub tag: Option<Vec<u8>>,
}

opaque_debug::implement!(Record);

#[derive(Debug, thiserror::Error)]
#[error("TLS transcript error: {0}")]
pub struct TlsTranscriptError(#[from] ErrorRepr);

impl TlsTranscriptError {
    fn validation(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Validation(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("incomplete transcript ({direction}): seq {seq}")]
    Incomplete { direction: Direction, seq: u64 },
}

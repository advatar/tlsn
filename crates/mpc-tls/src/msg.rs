use serde::{Deserialize, Serialize};
use tls_core::{
    key::PublicKey,
    msgs::enums::{ContentType, ProtocolVersion},
};
use tlsn_core::transcript::Record;

use crate::record_layer::{DecryptMode, EncryptMode};

/// MPC-TLS protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Message {
    SetProtocolVersion(SetProtocolVersion),
    SetClientRandom(SetClientRandom),
    StartHandshake(StartHandshake),
    SetServerRandom(SetServerRandom),
    SetServerKey(SetServerKey),
    ClientFinishedVd(ClientFinishedVd),
    ServerFinishedVd(ServerFinishedVd),
    Tls13HelloHash(Tls13HelloHash),
    Tls13HandshakeHash(Tls13HandshakeHash),
    Tls13CertVerify(Tls13CertVerify),
    Tls13ClientFinishedVd(Tls13ClientFinishedVd),
    Tls13ServerFinishedVd(Tls13ServerFinishedVd),
    Tls13SendRecord(Tls13RecordMessage),
    Tls13RecvRecord(Tls13RecordMessage),
    Encrypt(Encrypt),
    Decrypt(Decrypt),
    StartTraffic,
    Flush { is_decrypting: bool },
    CloseConnection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetProtocolVersion {
    pub(crate) version: ProtocolVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetClientRandom {
    pub(crate) random: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StartHandshake {
    pub(crate) time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetServerRandom {
    pub(crate) random: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SetServerKey {
    pub(crate) key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Decrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) mode: DecryptMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Encrypt {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) len: usize,
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) mode: EncryptMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ClientFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ServerFinishedVd {
    pub handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Tls13HelloHash {
    pub(crate) hello_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Tls13HandshakeHash {
    pub(crate) handshake_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Tls13CertVerify {
    pub(crate) transcript_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Tls13ClientFinishedVd {
    pub(crate) handshake_hash: [u8; 32],
    pub(crate) verify_data: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Tls13ServerFinishedVd {
    pub(crate) verify_data: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Tls13RecordMessage {
    pub(crate) record: Record,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct CloseConnection;

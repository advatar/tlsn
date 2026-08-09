//! The TLS 1.3 key schedule (RFC 8446 section 7.1).
//!
//! The schedule is the three-stage chain below. Each `Derive-Secret` is taken
//! at a specific transcript position, and getting those positions wrong is the
//! second most common TLS 1.3 implementation bug after `HkdfLabel` encoding —
//! so the position each method expects is documented on the method.
//!
//! ```text
//!              0
//!              |
//!              v
//!    PSK ->  HKDF-Extract = Early Secret
//!              |
//!              +-> Derive-Secret(., "ext binder" | "res binder", "")
//!              +-> Derive-Secret(., "c e traffic", ClientHello)
//!              +-> Derive-Secret(., "e exp master", ClientHello)
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!  (EC)DHE -> HKDF-Extract = Handshake Secret
//!              |
//!              +-> Derive-Secret(., "c hs traffic", ClientHello..ServerHello)
//!              +-> Derive-Secret(., "s hs traffic", ClientHello..ServerHello)
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!        0 -> HKDF-Extract = Master Secret
//!              |
//!              +-> Derive-Secret(., "c ap traffic", ClientHello..server Finished)
//!              +-> Derive-Secret(., "s ap traffic", ClientHello..server Finished)
//!              +-> Derive-Secret(., "exp master",   ClientHello..server Finished)
//!              +-> Derive-Secret(., "res master",   ClientHello..client Finished)
//! ```

use crate::{
    Error, HASH_LEN, IV_LEN, KEY_LEN,
    hkdf::{self, Expansion},
    trace::{Step, Trace},
    traffic::TrafficSecret,
};

/// A client/server pair of traffic secrets derived at the same transcript
/// position.
#[derive(Debug, Clone)]
pub struct DirectionalSecrets {
    /// `client_..._traffic_secret`.
    pub client: TrafficSecret,
    /// `server_..._traffic_secret`.
    pub server: TrafficSecret,
}

/// Handshake traffic keys.
///
/// Field names mirror `tlsn_hmac_sha256::HandshakeKeys` so oracle and MPC
/// outputs can be compared field by field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeKeys {
    /// Client write key.
    pub client_write_key: [u8; KEY_LEN],
    /// Client write IV.
    pub client_iv: [u8; IV_LEN],
    /// Client `finished_key`.
    pub client_finished_key: [u8; HASH_LEN],
    /// Server write key.
    pub server_write_key: [u8; KEY_LEN],
    /// Server write IV.
    pub server_iv: [u8; IV_LEN],
    /// Server `finished_key`.
    pub server_finished_key: [u8; HASH_LEN],
}

/// Application traffic keys.
///
/// Field names mirror `tlsn_hmac_sha256::ApplicationKeys`, whose fields are VM
/// references rather than bytes; decode those before comparing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationKeys {
    /// Client write key.
    pub client_write_key: [u8; KEY_LEN],
    /// Client write IV.
    pub client_iv: [u8; IV_LEN],
    /// Server write key.
    pub server_write_key: [u8; KEY_LEN],
    /// Server write IV.
    pub server_iv: [u8; IV_LEN],
}

/// The TLS 1.3 key schedule, driven one stage at a time.
///
/// Stages must be entered in order; doing otherwise returns [`Error::Stage`]
/// rather than silently deriving from a zero secret.
#[derive(Debug, Clone)]
pub struct KeySchedule {
    early_secret: [u8; HASH_LEN],
    handshake_secret: Option<[u8; HASH_LEN]>,
    master_secret: Option<[u8; HASH_LEN]>,
    trace: Trace,
}

impl KeySchedule {
    /// Starts a PSK-less schedule, as used by a 1-RTT handshake.
    ///
    /// The Early Secret is `HKDF-Extract(0, 0)`: both the salt and the PSK are
    /// `Hash.length` zero bytes.
    pub fn new() -> Self {
        Self::with_psk(&[0u8; HASH_LEN])
    }

    /// Starts a schedule from an external or resumption PSK.
    ///
    /// Outside the narrow profile, but the Early Secret is the same extract
    /// either way, so supporting it costs nothing and keeps the zero-PSK case
    /// from being a special case.
    pub fn with_psk(psk: &[u8]) -> Self {
        let salt = [0u8; HASH_LEN];
        let early_secret = hkdf::extract(&salt, psk);

        let mut trace = Trace::new();
        trace.record(Step::Extract {
            secret: "early",
            salt: salt.to_vec(),
            ikm: psk.to_vec(),
            out: early_secret.to_vec(),
        });

        Self {
            early_secret,
            handshake_secret: None,
            master_secret: None,
            trace,
        }
    }

    /// The Early Secret.
    pub fn early_secret(&self) -> &[u8; HASH_LEN] {
        &self.early_secret
    }

    /// The Handshake Secret, once [`KeySchedule::derive_handshake_secret`] has
    /// run.
    pub fn handshake_secret(&self) -> Option<&[u8; HASH_LEN]> {
        self.handshake_secret.as_ref()
    }

    /// The Master Secret, once [`KeySchedule::derive_master_secret`] has run.
    pub fn master_secret(&self) -> Option<&[u8; HASH_LEN]> {
        self.master_secret.as_ref()
    }

    /// The recorded derivation trace.
    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Enters the handshake stage:
    /// `HKDF-Extract(Derive-Secret(Early, "derived", ""), (EC)DHE)`.
    ///
    /// `ecdhe_shared_secret` is the raw ECDH output — for X25519, the 32-byte
    /// shared secret. This is the same value the MPC implementation receives as
    /// its secret-shared `pms`, which makes this method the boundary between
    /// oracle and MPC.
    pub fn derive_handshake_secret(&mut self, ecdhe_shared_secret: &[u8]) -> &mut Self {
        let derived = self.derive("derived", &self.early_secret.clone(), &hkdf::empty_hash());
        let handshake_secret = hkdf::extract(&derived, ecdhe_shared_secret);

        self.trace.record(Step::Extract {
            secret: "handshake",
            salt: derived.to_vec(),
            ikm: ecdhe_shared_secret.to_vec(),
            out: handshake_secret.to_vec(),
        });

        self.handshake_secret = Some(handshake_secret);
        self
    }

    /// The handshake traffic secrets.
    ///
    /// `hello_hash` must be `Transcript-Hash(ClientHello..ServerHello)`.
    pub fn handshake_traffic_secrets(
        &mut self,
        hello_hash: &[u8; HASH_LEN],
    ) -> Result<DirectionalSecrets, Error> {
        let hs = self
            .handshake_secret
            .ok_or(Error::Stage("handshake secret not derived"))?;

        Ok(DirectionalSecrets {
            client: TrafficSecret::new(self.derive("c hs traffic", &hs, hello_hash)),
            server: TrafficSecret::new(self.derive("s hs traffic", &hs, hello_hash)),
        })
    }

    /// The handshake traffic keys, shaped like the MPC implementation's output.
    ///
    /// `hello_hash` must be `Transcript-Hash(ClientHello..ServerHello)`.
    pub fn handshake_keys(&mut self, hello_hash: &[u8; HASH_LEN]) -> Result<HandshakeKeys, Error> {
        let s = self.handshake_traffic_secrets(hello_hash)?;
        Ok(HandshakeKeys {
            client_write_key: s.client.key(),
            client_iv: s.client.iv(),
            client_finished_key: s.client.finished_key(),
            server_write_key: s.server.key(),
            server_iv: s.server.iv(),
            server_finished_key: s.server.finished_key(),
        })
    }

    /// Enters the master stage:
    /// `HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0)`.
    ///
    /// Independent of the transcript, so it may be computed as soon as the
    /// handshake secret exists — which is what the MPC implementation does to
    /// overlap this with waiting for the server's flight.
    pub fn derive_master_secret(&mut self) -> Result<&mut Self, Error> {
        let hs = self
            .handshake_secret
            .ok_or(Error::Stage("handshake secret not derived"))?;

        let derived = self.derive("derived", &hs, &hkdf::empty_hash());
        let master_secret = hkdf::extract(&derived, &[0u8; HASH_LEN]);

        self.trace.record(Step::Extract {
            secret: "master",
            salt: derived.to_vec(),
            ikm: vec![0u8; HASH_LEN],
            out: master_secret.to_vec(),
        });

        self.master_secret = Some(master_secret);
        Ok(self)
    }

    /// The application traffic secrets.
    ///
    /// `handshake_hash` must be
    /// `Transcript-Hash(ClientHello..server Finished)` — note this is the
    /// **server's** Finished, not the client's.
    pub fn application_traffic_secrets(
        &mut self,
        handshake_hash: &[u8; HASH_LEN],
    ) -> Result<DirectionalSecrets, Error> {
        let ms = self
            .master_secret
            .ok_or(Error::Stage("master secret not derived"))?;

        Ok(DirectionalSecrets {
            client: TrafficSecret::new(self.derive("c ap traffic", &ms, handshake_hash)),
            server: TrafficSecret::new(self.derive("s ap traffic", &ms, handshake_hash)),
        })
    }

    /// The application traffic keys, shaped like the MPC implementation's
    /// output.
    ///
    /// `handshake_hash` must be `Transcript-Hash(ClientHello..server Finished)`.
    pub fn application_keys(
        &mut self,
        handshake_hash: &[u8; HASH_LEN],
    ) -> Result<ApplicationKeys, Error> {
        let s = self.application_traffic_secrets(handshake_hash)?;
        Ok(ApplicationKeys {
            client_write_key: s.client.key(),
            client_iv: s.client.iv(),
            server_write_key: s.server.key(),
            server_iv: s.server.iv(),
        })
    }

    /// The exporter master secret.
    ///
    /// `handshake_hash` must be `Transcript-Hash(ClientHello..server Finished)`.
    pub fn exporter_master_secret(
        &mut self,
        handshake_hash: &[u8; HASH_LEN],
    ) -> Result<[u8; HASH_LEN], Error> {
        let ms = self
            .master_secret
            .ok_or(Error::Stage("master secret not derived"))?;
        Ok(self.derive("exp master", &ms, handshake_hash))
    }

    /// The resumption master secret.
    ///
    /// `client_finished_hash` must be
    /// `Transcript-Hash(ClientHello..client Finished)` — a later transcript
    /// position than the application secrets use.
    pub fn resumption_master_secret(
        &mut self,
        client_finished_hash: &[u8; HASH_LEN],
    ) -> Result<[u8; HASH_LEN], Error> {
        let ms = self
            .master_secret
            .ok_or(Error::Stage("master secret not derived"))?;
        Ok(self.derive("res master", &ms, client_finished_hash))
    }

    /// Runs one `Derive-Secret` and records it.
    fn derive(&mut self, label: &str, prk: &[u8], context: &[u8]) -> [u8; HASH_LEN] {
        let Expansion { info, out } = hkdf::derive_secret(prk, label.as_bytes(), context);

        self.trace.record(Step::Expand {
            label: format!("tls13 {label}"),
            prk: prk.to_vec(),
            context: context.to_vec(),
            info,
            out: out.clone(),
        });

        out.try_into()
            .expect("Derive-Secret produces HASH_LEN bytes")
    }
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_must_be_entered_in_order() {
        let mut ks = KeySchedule::new();
        assert!(matches!(
            ks.handshake_traffic_secrets(&[0; HASH_LEN]),
            Err(Error::Stage(_))
        ));
        assert!(matches!(ks.derive_master_secret(), Err(Error::Stage(_))));

        ks.derive_handshake_secret(&[1u8; 32]);
        assert!(ks.handshake_traffic_secrets(&[0; HASH_LEN]).is_ok());
        // Application secrets still need the master stage.
        assert!(matches!(
            ks.application_traffic_secrets(&[0; HASH_LEN]),
            Err(Error::Stage(_))
        ));

        ks.derive_master_secret().unwrap();
        assert!(ks.application_traffic_secrets(&[0; HASH_LEN]).is_ok());
    }

    #[test]
    fn client_and_server_secrets_differ() {
        let mut ks = KeySchedule::new();
        ks.derive_handshake_secret(&[1u8; 32]);
        let s = ks.handshake_traffic_secrets(&[9; HASH_LEN]).unwrap();
        assert_ne!(s.client.as_bytes(), s.server.as_bytes());
    }

    #[test]
    fn transcript_position_changes_the_secrets() {
        let mut ks = KeySchedule::new();
        ks.derive_handshake_secret(&[1u8; 32]);
        let a = ks.handshake_traffic_secrets(&[1; HASH_LEN]).unwrap();
        let b = ks.handshake_traffic_secrets(&[2; HASH_LEN]).unwrap();
        assert_ne!(a.client.as_bytes(), b.client.as_bytes());
    }

    #[test]
    fn master_secret_is_transcript_independent() {
        // Two schedules with the same ECDHE input must agree on the master
        // secret regardless of when it is derived.
        let mut early = KeySchedule::new();
        early.derive_handshake_secret(&[3u8; 32]);
        early.derive_master_secret().unwrap();

        let mut late = KeySchedule::new();
        late.derive_handshake_secret(&[3u8; 32]);
        let _ = late.handshake_traffic_secrets(&[7; HASH_LEN]).unwrap();
        late.derive_master_secret().unwrap();

        assert_eq!(early.master_secret(), late.master_secret());
    }

    #[test]
    fn trace_records_every_step_in_order() {
        let mut ks = KeySchedule::new();
        ks.derive_handshake_secret(&[1u8; 32]);
        ks.derive_master_secret().unwrap();

        let labels: Vec<_> = ks.trace().steps().iter().map(|s| s.label()).collect();
        assert_eq!(
            labels,
            [
                "early",
                "tls13 derived",
                "handshake",
                "tls13 derived",
                "master"
            ]
        );
    }
}

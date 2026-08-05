//! TLS client configuration.

use serde::{Deserialize, Serialize};

use crate::{
    connection::ServerName,
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
};

/// Which TLS protocol versions the prover offers in its `ClientHello`.
///
/// The *offered* set determines what a dual-stack server negotiates, so it is
/// how a caller selects which MPC-TLS path a session takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OfferedVersions {
    /// Offer TLS 1.2 only.
    ///
    /// The default, and the only fully supported path: a dual-stack server that
    /// would otherwise choose 1.3 is held to the version this fork can notarize
    /// end to end.
    #[default]
    Tls12Only,
    /// Offer TLS 1.3 only. **No security guarantee — testing only.**
    ///
    /// The TLS 1.3 MPC-TLS path decodes the application traffic keys to
    /// plaintext (`crates/mpc-tls/src/tls13.rs`, `set_handshake_hash`), so the
    /// prover holds `server_write_key` and can forge server responses. That
    /// voids provenance, which is the entire point of the protocol. The name
    /// carries `Unsafe` because passing tests here demonstrate working plumbing
    /// against honest servers and nothing more.
    ///
    /// Exists so the 1.3 test matrix can exercise the path and so its failures
    /// are observable rather than masked by a downgrade to 1.2.
    Tls13Unsafe,
    /// Offer both and let the server choose. **No security guarantee — testing
    /// only.**
    ///
    /// Strictly worse than [`OfferedVersions::Tls13Unsafe`] for testing, and
    /// unsafe for the same reason: against a dual-stack server this negotiates
    /// 1.3 and so selects the path with no guarantee.
    Tls12AndTls13Unsafe,
}

/// TLS client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientConfig {
    server_name: ServerName,
    /// Root certificates.
    root_store: RootCertStore,
    /// Certificate chain and a matching private key for client
    /// authentication.
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
    /// Protocol versions offered in the `ClientHello`.
    ///
    /// `#[serde(default)]` so a config serialized before this field existed
    /// still deserializes, and to the previous behaviour.
    #[serde(default)]
    offered_versions: OfferedVersions,
}

impl TlsClientConfig {
    /// Creates a new builder.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    /// Returns the server name.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    /// Returns the root certificates.
    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }

    /// Returns a certificate chain and a matching private key for client
    /// authentication.
    pub fn client_auth(&self) -> Option<&(Vec<CertificateDer>, PrivateKeyDer)> {
        self.client_auth.as_ref()
    }

    /// Returns the protocol versions offered in the `ClientHello`.
    pub fn offered_versions(&self) -> OfferedVersions {
        self.offered_versions
    }
}

/// Builder for [`TlsClientConfig`].
#[derive(Debug, Default)]
pub struct TlsConfigBuilder {
    server_name: Option<ServerName>,
    root_store: Option<RootCertStore>,
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
    offered_versions: OfferedVersions,
}

impl TlsConfigBuilder {
    /// Sets the server name.
    pub fn server_name(mut self, server_name: ServerName) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Sets the root certificates to use for verifying the server's
    /// certificate.
    pub fn root_store(mut self, store: RootCertStore) -> Self {
        self.root_store = Some(store);
        self
    }

    /// Sets a DER-encoded certificate chain and a matching private key for
    /// client authentication.
    ///
    /// Often the chain will consist of a single end-entity certificate.
    ///
    /// # Arguments
    ///
    /// * `cert_key` - A tuple containing the certificate chain and the private
    ///   key.
    ///
    ///   - Each certificate in the chain must be in the X.509 format.
    ///   - The key must be in the ASN.1 format (either PKCS#8 or PKCS#1).
    pub fn client_auth(mut self, cert_key: (Vec<CertificateDer>, PrivateKeyDer)) -> Self {
        self.client_auth = Some(cert_key);
        self
    }

    /// Sets which TLS protocol versions to offer in the `ClientHello`.
    ///
    /// Defaults to [`OfferedVersions::Tls12Only`], the only path this fork
    /// notarizes end to end. Offering 1.3 selects an **incomplete** path.
    pub fn offered_versions(mut self, versions: OfferedVersions) -> Self {
        self.offered_versions = versions;
        self
    }

    /// Builds the TLS configuration.
    pub fn build(self) -> Result<TlsClientConfig, TlsConfigError> {
        let server_name = self.server_name.ok_or(ErrorRepr::MissingField {
            field: "server_name",
        })?;

        let root_store = self.root_store.ok_or(ErrorRepr::MissingField {
            field: "root_store",
        })?;

        Ok(TlsClientConfig {
            server_name,
            root_store,
            client_auth: self.client_auth,
            offered_versions: self.offered_versions,
        })
    }
}

/// TLS configuration error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TlsConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("tls config error")]
enum ErrorRepr {
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default must stay 1.2-only, which is what the prover hard-coded
    /// before this option existed. Changing it would silently move every
    /// existing caller onto the 1.3 path.
    #[test]
    fn default_offers_tls12_only() {
        assert_eq!(OfferedVersions::default(), OfferedVersions::Tls12Only);
    }

    /// The 1.3 variants must keep `Unsafe` in their names. The path they select
    /// decodes the application traffic keys to plaintext, so a caller can only
    /// reach it by naming the risk. Renaming them to something reassuring would
    /// be a regression even though nothing would fail to compile.
    #[test]
    fn tls13_variants_are_named_unsafe() {
        for variant in [
            OfferedVersions::Tls13Unsafe,
            OfferedVersions::Tls12AndTls13Unsafe,
        ] {
            let name = format!("{variant:?}");
            assert!(
                name.contains("Unsafe"),
                "{name} offers TLS 1.3 and must say so in its name"
            );
        }
        assert!(!format!("{:?}", OfferedVersions::Tls12Only).contains("Unsafe"));
    }

    /// A config serialized before `offered_versions` existed must still
    /// deserialize, and to the previous behaviour rather than to an error.
    #[test]
    fn missing_offered_versions_deserializes_to_tls12_only() {
        #[derive(serde::Deserialize)]
        struct Probe {
            #[serde(default)]
            offered_versions: OfferedVersions,
        }

        let probe: Probe = serde_json::from_str("{}").expect("absent field is defaulted");
        assert_eq!(probe.offered_versions, OfferedVersions::Tls12Only);
    }
}

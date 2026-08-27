//! TLSNotary MPC-TLS protocol implementation.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod decode;
mod error;
pub(crate) mod follower;
pub(crate) mod leader;
mod msg;
mod record_layer;
mod tls13;
pub(crate) mod utils;

pub use config::{Config, ConfigBuilder, ConfigBuilderError};
pub use error::MpcTlsError;
pub use follower::MpcTlsFollower;
pub use leader::MpcTlsLeader;
pub use tls13::{
    Epoch, ReadEpoch, Tls13ApplicationKeys, Tls13HandshakeKeys, Tls13SessionKeys,
    Tls13Sha384ApplicationKeys, Tls13Sha384HandshakeKeys, WriteEpoch,
};

use std::{future::Future, pin::Pin, sync::Arc};

use mpz_memory_core::{
    binary::{Binary, U8},
    Array, Vector,
};
use mpz_vm_core::Vm as VmTrait;

use tokio::sync::Mutex;

pub(crate) type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'static>>;
/// Virtual machine type.
pub type Vm = Arc<Mutex<dyn VmTrait<Binary> + Send + Sync + 'static>>;

/// VM reference to a TLS 1.3 record's exact inner plaintext.
#[derive(Debug, Clone, Copy)]
pub struct Tls13PlaintextRef {
    direction: tlsn_core::transcript::Direction,
    sequence: u64,
    inner_plaintext: Vector<U8>,
}

impl Tls13PlaintextRef {
    #[doc(hidden)]
    pub fn new(
        direction: tlsn_core::transcript::Direction,
        sequence: u64,
        inner_plaintext: Vector<U8>,
    ) -> Self {
        Self {
            direction,
            sequence,
            inner_plaintext,
        }
    }

    /// Returns the record direction.
    pub fn direction(&self) -> tlsn_core::transcript::Direction {
        self.direction
    }

    /// Returns the application-epoch sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact TLS inner plaintext, including content type and padding.
    pub fn inner_plaintext(&self) -> Vector<U8> {
        self.inner_plaintext
    }

    /// Returns the same record identity with a translated VM reference.
    #[doc(hidden)]
    pub fn with_inner_plaintext(self, inner_plaintext: Vector<U8>) -> Self {
        Self {
            inner_plaintext,
            ..self
        }
    }
}

/// Shared collection of authenticated TLS 1.3 plaintext references.
#[derive(Debug, Clone, Default)]
pub struct Tls13PlaintextRefs(Arc<std::sync::Mutex<Vec<Tls13PlaintextRef>>>);

impl Tls13PlaintextRefs {
    pub(crate) fn push(&self, reference: Tls13PlaintextRef) {
        self.0
            .lock()
            .expect("plaintext reference lock is not poisoned")
            .push(reference);
    }

    /// Returns a snapshot of all record references in protocol order.
    pub fn records(&self) -> Vec<Tls13PlaintextRef> {
        self.0
            .lock()
            .expect("plaintext reference lock is not poisoned")
            .clone()
    }

    /// Replaces the references after translating them into another VM address space.
    #[doc(hidden)]
    pub fn replace(&self, records: Vec<Tls13PlaintextRef>) {
        *self
            .0
            .lock()
            .expect("plaintext reference lock is not poisoned") = records;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Leader,
    Follower,
}

/// TLS session keys.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Client write IV.
    pub client_write_iv: Array<U8, 4>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Server write IV.
    pub server_write_iv: Array<U8, 4>,
    /// Server write MAC key.
    pub server_write_mac_key: Array<U8, 16>,
    /// Exact TLS 1.3 plaintext references retained across MPC finalization.
    pub tls13_plaintext_refs: Tls13PlaintextRefs,
}

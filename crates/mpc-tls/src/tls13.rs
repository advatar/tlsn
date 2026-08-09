pub(crate) mod nonce;

use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Aes256Gcm, NewAead};
use hmac::{Hmac, Mac};
use hmac_sha256::{Mode, Role as KeyScheduleRole, Tls13KeySched};
use hmac_sha256::Sha384ApplicationKeys;
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt,
};
use mpz_vm_core::Vm as VmTrait;
use sha2::Sha256;
use tls_core::msgs::{
    base::Payload,
    enums::{ContentType, ProtocolVersion},
    message::{OpaqueMessage, PlainMessage},
};
use tlsn_core::transcript::{ContentType as TranscriptContentType, Record};
use tracing::debug;

use crate::{record_layer::RecordLayer, MpcTlsError, Role, Vm};

type HmacSha256 = Hmac<Sha256>;

/// TLS 1.3 traffic epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Epoch {
    /// Handshake traffic keys.
    Handshake,
    /// Application traffic keys.
    Application,
}

/// A TLS 1.3 write-key epoch with an exclusively owned record sequence number.
#[derive(Debug)]
pub struct WriteEpoch<K, I> {
    epoch: Epoch,
    generation: u64,
    key: K,
    iv: I,
    next_sequence: u64,
}

impl<K, I> WriteEpoch<K, I> {
    pub(crate) fn key(&self) -> K where K: Copy { self.key }
    pub(crate) fn iv(&self) -> I where I: Copy { self.iv }
    fn new(epoch: Epoch, generation: u64, key: K, iv: I) -> Self {
        Self {
            epoch,
            generation,
            key,
            iv,
            next_sequence: 0,
        }
    }

    /// Returns the traffic epoch kind.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the application-traffic-secret generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the sequence number that the next record will consume.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    fn reserve_sequence(&mut self) -> Result<u64, MpcTlsError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| MpcTlsError::hs("tls13 write sequence exhausted"))?;
        Ok(sequence)
    }
}

impl<K, I> ReadEpoch<K, I> {
    pub(crate) fn key(&self) -> K where K: Copy { self.key }
    pub(crate) fn iv(&self) -> I where I: Copy { self.iv }
}

/// A TLS 1.3 read-key epoch with an exclusively owned record sequence number.
#[derive(Debug)]
pub struct ReadEpoch<K, I> {
    epoch: Epoch,
    generation: u64,
    key: K,
    iv: I,
    next_sequence: u64,
}

impl<K, I> ReadEpoch<K, I> {
    fn new(epoch: Epoch, generation: u64, key: K, iv: I) -> Self {
        Self {
            epoch,
            generation,
            key,
            iv,
            next_sequence: 0,
        }
    }

    /// Returns the traffic epoch kind.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the application-traffic-secret generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the sequence number that the next record will consume.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    fn reserve_sequence(&mut self) -> Result<u64, MpcTlsError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| MpcTlsError::hs("tls13 read sequence exhausted"))?;
        Ok(sequence)
    }
}

/// TLS 1.3 handshake traffic keys revealed to the leader.
#[derive(Debug)]
pub struct Tls13HandshakeKeys {
    /// Client-to-server write epoch.
    pub client: WriteEpoch<[u8; 16], [u8; 12]>,
    /// Client finished key.
    pub client_finished_key: [u8; 32],
    /// Server-to-client read epoch.
    pub server: ReadEpoch<[u8; 16], [u8; 12]>,
    /// Server finished key.
    pub server_finished_key: [u8; 32],
}

/// TLS 1.3 SHA-384 handshake epochs. Traffic keys are released after the
/// ServerHello; Finished keys remain secret-shared.
#[derive(Debug)]
pub struct Tls13Sha384HandshakeKeys {
    /// Client-to-server write epoch.
    pub client: WriteEpoch<[u8; 32], [u8; 12]>,
    /// Client Finished key.
    pub client_finished_key: Array<U8, 48>,
    /// Server-to-client read epoch.
    pub server: ReadEpoch<[u8; 32], [u8; 12]>,
    /// Server Finished key.
    pub server_finished_key: Array<U8, 48>,
}

/// TLS 1.3 application traffic keys kept secret-shared.
#[derive(Debug)]
pub struct Tls13ApplicationKeys {
    /// Client-to-server write epoch.
    pub client: WriteEpoch<Array<U8, 16>, Array<U8, 12>>,
    /// Server-to-client read epoch.
    pub server: ReadEpoch<Array<U8, 16>, Array<U8, 12>>,
}

/// TLS 1.3 SHA-384/AES-256 application keys retained in MPC form.
#[derive(Debug)]
pub struct Tls13Sha384ApplicationKeys {
    /// Client-to-server write epoch.
    pub client: WriteEpoch<Array<U8, 32>, Array<U8, 12>>,
    /// Server-to-client read epoch.
    pub server: ReadEpoch<Array<U8, 32>, Array<U8, 12>>,
}

/// TLS 1.3 session key material tracked by MPC-TLS.
#[derive(Debug, Default)]
pub struct Tls13SessionKeys {
    /// Handshake traffic keys revealed to the leader after `ServerHello`.
    pub handshake: Option<Tls13HandshakeKeys>,
    /// SHA-384 handshake keys retained in MPC form.
    pub sha384_handshake: Option<Tls13Sha384HandshakeKeys>,
    /// Application traffic keys retained in MPC form.
    pub application: Option<Tls13ApplicationKeys>,
    /// SHA-384/AES-256 application keys, when that suite is selected.
    pub sha384_application: Option<Tls13Sha384ApplicationKeys>,
}

pub(crate) struct Tls13KeyState {
    inner: Tls13KeySched,
    keys: Tls13SessionKeys,
    /// Shared ECDHE input retained for a later SHA-384 schedule selection.
    sha384_shared_secret: Option<Array<U8, 32>>,
    sha384_handshake_material: Option<hmac_sha256::Sha384HandshakeKeys>,
    sha384_application_material: Option<Sha384ApplicationKeys>,
    sha384_client_finished: Option<hmac_sha256::DeferredFinishedSha384>,
    sha384_server_finished: Option<hmac_sha256::DeferredFinishedSha384>,
}

impl Tls13KeyState {
    pub(crate) fn new(mode: Mode, role: Role) -> Self {
        let key_schedule_role = match role {
            Role::Leader => KeyScheduleRole::Leader,
            Role::Follower => KeyScheduleRole::Follower,
        };

        Self {
            inner: Tls13KeySched::new(mode, key_schedule_role),
            keys: Tls13SessionKeys::default(),
            sha384_shared_secret: None,
            sha384_handshake_material: None,
            sha384_application_material: None,
            sha384_client_finished: None,
            sha384_server_finished: None,
        }
    }

    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn VmTrait<Binary>,
        pms: Array<U8, 32>,
    ) -> Result<(), MpcTlsError> {
        self.sha384_shared_secret = Some(pms);
        let mut handshake = hmac_sha256::Sha384HandshakeKeys::alloc_from_shared_secret_deferred(
            hmac_sha256::Mode::Normal,
            vm,
            pms,
        )
        .map_err(MpcTlsError::from)?;
        handshake.set_context(vm).map_err(MpcTlsError::from)?;
        self.sha384_client_finished = Some(
            hmac_sha256::DeferredFinishedSha384::alloc(
                vm,
                handshake.client_finished().map_err(MpcTlsError::from)?,
            )
            .map_err(MpcTlsError::from)?,
        );
        self.sha384_server_finished = Some(
            hmac_sha256::DeferredFinishedSha384::alloc(
                vm,
                handshake.server_finished().map_err(MpcTlsError::from)?,
            )
            .map_err(MpcTlsError::from)?,
        );
        let mut application = Sha384ApplicationKeys::alloc_from_shared_secret_deferred(
            hmac_sha256::Mode::Normal,
            vm,
            pms,
        )
        .map_err(MpcTlsError::from)?;
        application.set_context(vm).map_err(MpcTlsError::from)?;
        self.sha384_handshake_material = Some(handshake);
        self.sha384_application_material = Some(application);
        self.inner.alloc(vm, pms).map_err(MpcTlsError::from)
    }

    /// Installs SHA-384 handshake epochs using circuits preallocated before VM
    /// setup.
    pub(crate) async fn set_sha384_hello_hash(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
        transcript_hash: [u8; 48],
    ) -> Result<(), MpcTlsError> {
        let material = self
            .sha384_handshake_material
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("SHA-384 handshake schedule is not allocated"))?;
        material
            .set_transcript(vm, &transcript_hash)
            .map_err(MpcTlsError::from)?;
        let mut client_key = vm
            .decode(material.client_key().map_err(MpcTlsError::from)?)
            .map_err(MpcTlsError::hs)?;
        let mut client_iv = vm
            .decode(material.client_iv().map_err(MpcTlsError::from)?)
            .map_err(MpcTlsError::hs)?;
        let mut server_key = vm
            .decode(material.server_key().map_err(MpcTlsError::from)?)
            .map_err(MpcTlsError::hs)?;
        let mut server_iv = vm
            .decode(material.server_iv().map_err(MpcTlsError::from)?)
            .map_err(MpcTlsError::hs)?;
        mpz_vm_core::Execute::execute_all(vm, ctx)
            .await
            .map_err(MpcTlsError::hs)?;
        self.keys.sha384_handshake = Some(Tls13Sha384HandshakeKeys {
            client: WriteEpoch::new(Epoch::Handshake, 0, client_key.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 client handshake key is unavailable"))?, client_iv.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 client handshake IV is unavailable"))?),
            client_finished_key: material.client_finished().map_err(MpcTlsError::from)?,
            server: ReadEpoch::new(Epoch::Handshake, 0, server_key.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 server handshake key is unavailable"))?, server_iv.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 server handshake IV is unavailable"))?),
            server_finished_key: material.server_finished().map_err(MpcTlsError::from)?,
        });
        Ok(())
    }

    /// Installs SHA-384 handshake epochs from the retained shared ECDHE input.
    pub(crate) async fn set_sha384_handshake_hash(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
        transcript_hash: [u8; 48],
    ) -> Result<(), MpcTlsError> {
        let application = self
            .sha384_application_material
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("SHA-384 application schedule is not allocated"))?;
        application
            .set_transcript(vm, &transcript_hash)
            .map_err(MpcTlsError::from)?;
        mpz_vm_core::Execute::execute_all(vm, ctx)
            .await
            .map_err(MpcTlsError::hs)?;
        debug!("SHA-384 application schedule execution complete");
        let client_key = application.client_key().map_err(MpcTlsError::from)?;
        let client_iv = application.client_iv().map_err(MpcTlsError::from)?;
        let server_key = application.server_key().map_err(MpcTlsError::from)?;
        let server_iv = application.server_iv().map_err(MpcTlsError::from)?;
        self.install_sha384_application_keys(
            client_key,
            client_iv,
            server_key,
            server_iv,
        );
        Ok(())
    }

    pub(crate) fn allocated_application_keys(
        &mut self,
    ) -> Result<hmac_sha256::ApplicationKeys, MpcTlsError> {
        self.inner
            .allocated_application_keys()
            .map_err(MpcTlsError::from)
    }

    pub(crate) fn allocated_sha384_application_keys(
        &self,
    ) -> Result<(Array<U8, 32>, Array<U8, 12>, Array<U8, 32>, Array<U8, 12>), MpcTlsError> {
        let material = self
            .sha384_application_material
            .as_ref()
            .ok_or_else(|| MpcTlsError::state("SHA-384 application schedule is not allocated"))?;
        Ok((
            material.client_key().map_err(MpcTlsError::from)?,
            material.client_iv().map_err(MpcTlsError::from)?,
            material.server_key().map_err(MpcTlsError::from)?,
            material.server_iv().map_err(MpcTlsError::from)?,
        ))
    }

    pub(crate) async fn set_hello_hash(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
        hello_hash: [u8; 32],
    ) -> Result<(), MpcTlsError> {
        self.inner.set_hello_hash(hello_hash)?;
        self.flush_all(ctx, vm).await?;

        self.keys.handshake = self
            .inner
            .handshake_keys()
            .ok()
            .map(|keys| Tls13HandshakeKeys {
                client: WriteEpoch::new(Epoch::Handshake, 0, keys.client_write_key, keys.client_iv),
                client_finished_key: keys.client_finished_key,
                server: ReadEpoch::new(Epoch::Handshake, 0, keys.server_write_key, keys.server_iv),
                server_finished_key: keys.server_finished_key,
            });

        self.inner.continue_to_app_keys()?;
        self.flush_all(ctx, vm).await?;

        Ok(())
    }

    pub(crate) async fn set_handshake_hash(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
        handshake_hash: [u8; 32],
    ) -> Result<(), MpcTlsError> {
        self.inner.set_handshake_hash(handshake_hash)?;
        self.flush_all(ctx, vm).await?;
        debug!("TLS 1.3 key schedule application outputs complete");

        let keys = self.inner.application_keys()?;

        // The application traffic keys are deliberately NOT decoded. They were,
        // until this commit, and that voided the entire point of the protocol: a
        // prover holding `server_write_key` can encrypt anything it likes under the
        // server's key and present it as the server's response.
        //
        // They stay VM references, as the TLS 1.2 path has always kept them, and
        // records are protected by joint AEAD instead. Anything that needs a
        // plaintext key here is a bug, not a missing feature.
        self.keys.application = Some(Tls13ApplicationKeys {
            client: WriteEpoch::new(Epoch::Application, 0, keys.client_write_key, keys.client_iv),
            server: ReadEpoch::new(Epoch::Application, 0, keys.server_write_key, keys.server_iv),
        });

        Ok(())
    }

    /// Derives and installs SHA-384/AES-256 application epochs from a
    /// secret-shared master secret. This is the suite-specific path used once
    /// TLS_AES_256_GCM_SHA384 negotiation is wired into the handshake.
    pub(crate) async fn set_sha384_application_keys(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
        master_secret: Array<U8, 48>,
        transcript_hash: [u8; 48],
    ) -> Result<(), MpcTlsError> {
        let mut material = Sha384ApplicationKeys::alloc(vm, master_secret.into(), &transcript_hash)
            .map_err(MpcTlsError::from)?;
        material.set_context(vm).map_err(MpcTlsError::from)?;
        mpz_vm_core::Execute::execute_all(vm, ctx)
            .await
            .map_err(MpcTlsError::hs)?;
        self.install_sha384_application_keys(
            material.client_key().map_err(MpcTlsError::from)?,
            material.client_iv().map_err(MpcTlsError::from)?,
            material.server_key().map_err(MpcTlsError::from)?,
            material.server_iv().map_err(MpcTlsError::from)?,
        );
        Ok(())
    }

    /// Derives and installs SHA-384 handshake epochs from a secret-shared
    /// handshake secret without decoding key material.
    #[allow(dead_code)]
    pub(crate) async fn set_sha384_handshake_keys(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
        handshake_secret: Array<U8, 48>,
        transcript_hash: [u8; 48],
    ) -> Result<(), MpcTlsError> {
        let mut material = hmac_sha256::Sha384HandshakeKeys::alloc(
            vm,
            handshake_secret.into(),
            &transcript_hash,
        )
        .map_err(MpcTlsError::from)?;
        material.set_context(vm).map_err(MpcTlsError::from)?;
        self.sha384_client_finished = Some(
            hmac_sha256::DeferredFinishedSha384::alloc(
                vm,
                material.client_finished().map_err(MpcTlsError::from)?,
            )
            .map_err(MpcTlsError::from)?,
        );
        self.sha384_server_finished = Some(
            hmac_sha256::DeferredFinishedSha384::alloc(
                vm,
                material.server_finished().map_err(MpcTlsError::from)?,
            )
            .map_err(MpcTlsError::from)?,
        );
        let mut client_key = vm.decode(material.client_key().map_err(MpcTlsError::from)?).map_err(MpcTlsError::hs)?;
        let mut client_iv = vm.decode(material.client_iv().map_err(MpcTlsError::from)?).map_err(MpcTlsError::hs)?;
        let mut server_key = vm.decode(material.server_key().map_err(MpcTlsError::from)?).map_err(MpcTlsError::hs)?;
        let mut server_iv = vm.decode(material.server_iv().map_err(MpcTlsError::from)?).map_err(MpcTlsError::hs)?;
        mpz_vm_core::Execute::execute_all(vm, ctx)
            .await
            .map_err(MpcTlsError::hs)?;
        self.keys.sha384_handshake = Some(Tls13Sha384HandshakeKeys {
            client: WriteEpoch::new(
                Epoch::Handshake,
                0,
                client_key.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 client handshake key is unavailable"))?,
                client_iv.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 client handshake IV is unavailable"))?,
            ),
            client_finished_key: material.client_finished().map_err(MpcTlsError::from)?,
            server: ReadEpoch::new(
                Epoch::Handshake,
                0,
                server_key.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 server handshake key is unavailable"))?,
                server_iv.try_recv().map_err(MpcTlsError::hs)?.ok_or_else(|| MpcTlsError::hs("SHA-384 server handshake IV is unavailable"))?,
            ),
            server_finished_key: material.server_finished().map_err(MpcTlsError::from)?,
        });
        Ok(())
    }

    /// Computes public SHA-384 Finished verify data from a retained Finished
    /// key; the key itself never leaves the VM.
    #[allow(dead_code)]
    pub(crate) async fn sha384_finished_vd(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
        transcript_hash: [u8; 48],
        server: bool,
    ) -> Result<[u8; 48], MpcTlsError> {
        let finished = if server {
            self.sha384_server_finished.as_mut()
        } else {
            self.sha384_client_finished.as_mut()
        }
        .ok_or_else(|| MpcTlsError::state("SHA-384 Finished circuit is not allocated"))?;
        finished
            .set_transcript(vm, transcript_hash)
            .map_err(MpcTlsError::from)?;
        let output = finished.output();
        let mut decoded = vm.decode(output).map_err(MpcTlsError::hs)?;
        mpz_vm_core::Execute::execute_all(vm, ctx)
            .await
            .map_err(MpcTlsError::hs)?;
        decoded
            .try_recv()
            .map_err(MpcTlsError::hs)?
            .ok_or_else(|| MpcTlsError::hs("SHA-384 Finished verify data is not decoded"))
    }

    /// Installs typed SHA-384/AES-256 application views without decoding keys.
    #[allow(dead_code)]
    pub(crate) fn install_sha384_application_keys(
        &mut self,
        client_key: Array<U8, 32>,
        client_iv: Array<U8, 12>,
        server_key: Array<U8, 32>,
        server_iv: Array<U8, 12>,
    ) {
        self.keys.sha384_application = Some(Tls13Sha384ApplicationKeys {
            client: WriteEpoch::new(Epoch::Application, 0, client_key, client_iv),
            server: ReadEpoch::new(Epoch::Application, 0, server_key, server_iv),
        });
    }

    #[allow(dead_code)]
    pub(crate) fn session_keys(&self) -> &Tls13SessionKeys {
        &self.keys
    }

    pub(crate) fn server_finished_vd(
        &self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 32], MpcTlsError> {
        let keys = self
            .keys
            .handshake
            .as_ref()
            .ok_or_else(|| MpcTlsError::hs("tls13 handshake keys are not available"))?;

        finished_verify_data(keys.server_finished_key, handshake_hash)
    }

    pub(crate) fn client_finished_vd(
        &self,
        handshake_hash: [u8; 32],
    ) -> Result<[u8; 32], MpcTlsError> {
        let keys = self
            .keys
            .handshake
            .as_ref()
            .ok_or_else(|| MpcTlsError::hs("tls13 handshake keys are not available"))?;

        finished_verify_data(keys.client_finished_key, handshake_hash)
    }

    pub(crate) fn encrypt_record(
        &mut self,
        epoch: Epoch,
        msg: PlainMessage,
    ) -> Result<(OpaqueMessage, Record), MpcTlsError> {
        match epoch {
            Epoch::Handshake => {
                if let Some(keys) = self.keys.handshake.as_mut() {
                    encrypt_tls13_record(&mut keys.client, msg)
                } else if let Some(keys) = self.keys.sha384_handshake.as_mut() {
                    encrypt_tls13_record_256(&mut keys.client, msg)
                } else {
                    Err(MpcTlsError::hs("tls13 handshake keys are not available"))
                }
            }
            Epoch::Application => Err(MpcTlsError::hs(
                "tls13 application records must use the asynchronous joint AEAD path",
            )),
        }
    }

    pub(crate) fn decrypt_record(
        &mut self,
        epoch: Epoch,
        msg: OpaqueMessage,
    ) -> Result<(PlainMessage, Record), MpcTlsError> {
        match epoch {
            Epoch::Handshake => {
                if let Some(keys) = self.keys.handshake.as_mut() {
                    decrypt_tls13_record(&mut keys.server, msg)
                } else if let Some(keys) = self.keys.sha384_handshake.as_mut() {
                    decrypt_tls13_record_256(&mut keys.server, msg)
                } else {
                    Err(MpcTlsError::hs("tls13 handshake keys are not available"))
                }
            }
            Epoch::Application => Err(MpcTlsError::hs(
                "tls13 application records must use the asynchronous joint AEAD path",
            )),
        }
    }

    pub(crate) async fn encrypt_application_record(
        &mut self,
        ctx: &mut Context,
        vm: Vm,
        record_layer: &mut RecordLayer,
        typ: ContentType,
        plaintext: Option<Vec<u8>>,
        plaintext_len: usize,
    ) -> Result<Option<(OpaqueMessage, Record)>, MpcTlsError> {
        let (sequence, iv) = if let Some(epoch) = self.keys.application.as_mut() {
            (epoch.client.reserve_sequence()?, epoch.client.iv)
        } else if let Some(epoch) = self.keys.sha384_application.as_mut() {
            (epoch.client.reserve_sequence()?, epoch.client.iv)
        } else {
            return Err(MpcTlsError::hs(
                "tls13 application write epoch is not available",
            ));
        };
        let body_len = plaintext_len
            .checked_add(1)
            .ok_or_else(|| MpcTlsError::hs("tls13 plaintext length overflow"))?;
        let record_plaintext = plaintext.clone();
        let body = plaintext.map(|mut plaintext| {
            plaintext.push(typ.get_u8());
            plaintext
        });
        let aad = make_tls13_aad(body_len + 16).to_vec();
        let (ciphertext, tag) = record_layer
            .encrypt_tls13(ctx, vm, iv, sequence, body, body_len, aad)
            .await?;
        let Some(tag) = tag else {
            return Ok(None);
        };
        let mut payload = ciphertext.clone();
        payload.extend_from_slice(&tag);
        let record = Record {
            seq: sequence,
            typ: TranscriptContentType::from(typ),
            plaintext: record_plaintext,
            explicit_nonce: Vec::new(),
            ciphertext,
            tag: Some(tag),
        };

        Ok(Some((
            OpaqueMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(payload),
            },
            record,
        )))
    }

    pub(crate) async fn decrypt_application_record(
        &mut self,
        ctx: &mut Context,
        vm: Vm,
        record_layer: &mut RecordLayer,
        msg: OpaqueMessage,
    ) -> Result<Option<(PlainMessage, Record)>, MpcTlsError> {
        if msg.typ != ContentType::ApplicationData || msg.version != ProtocolVersion::TLSv1_2 {
            return Err(MpcTlsError::hs("unexpected TLS 1.3 record header"));
        }
        let (sequence, iv) = if let Some(epoch) = self.keys.application.as_mut() {
            (epoch.server.reserve_sequence()?, epoch.server.iv)
        } else if let Some(epoch) = self.keys.sha384_application.as_mut() {
            (epoch.server.reserve_sequence()?, epoch.server.iv)
        } else {
            return Err(MpcTlsError::hs(
                "tls13 application read epoch is not available",
            ));
        };
        let mut ciphertext = msg.payload.0;
        if ciphertext.len() < 16 {
            return Err(MpcTlsError::hs(
                "tls13 record payload is shorter than the tag",
            ));
        }
        let tag = ciphertext.split_off(ciphertext.len() - 16);
        let aad = make_tls13_aad(ciphertext.len() + 16).to_vec();
        let plaintext = record_layer
            .decrypt_tls13(ctx, vm, iv, sequence, ciphertext.clone(), aad, tag.clone())
            .await?;
        let Some(mut plaintext) = plaintext else {
            return Ok(None);
        };
        let typ = unpad_tls13(&mut plaintext)?;
        let record = Record {
            seq: sequence,
            typ: TranscriptContentType::from(typ),
            plaintext: Some(plaintext.clone()),
            explicit_nonce: Vec::new(),
            ciphertext,
            tag: Some(tag),
        };

        Ok(Some((
            PlainMessage {
                typ,
                version: ProtocolVersion::TLSv1_3,
                payload: Payload::new(plaintext),
            },
            record,
        )))
    }

    async fn flush_all(
        &mut self,
        ctx: &mut Context,
        vm: &mut (dyn VmTrait<Binary> + Send),
    ) -> Result<(), MpcTlsError> {
        while self.inner.wants_flush() {
            self.inner.flush(vm)?;
            mpz_vm_core::Execute::execute_all(vm, ctx)
                .await
                .map_err(MpcTlsError::hs)?;
        }

        Ok(())
    }
}

fn finished_verify_data(
    finished_key: [u8; 32],
    handshake_hash: [u8; 32],
) -> Result<[u8; 32], MpcTlsError> {
    let mut mac = HmacSha256::new_from_slice(&finished_key).map_err(MpcTlsError::hs)?;
    mac.update(&handshake_hash);

    Ok(mac
        .finalize()
        .into_bytes()
        .as_slice()
        .try_into()
        .expect("sha256 hmac output is 32 bytes"))
}

fn encrypt_tls13_record(
    epoch: &mut WriteEpoch<[u8; 16], [u8; 12]>,
    msg: PlainMessage,
) -> Result<(OpaqueMessage, Record), MpcTlsError> {
    let typ = msg.typ;
    let plaintext = msg.payload.0;
    let mut payload = plaintext.clone();
    payload.push(typ.get_u8());

    let total_len = payload.len() + 16;
    let aad = make_tls13_aad(total_len);
    let cipher = Aes128Gcm::new_from_slice(&epoch.key)
        .map_err(|_| MpcTlsError::hs("tls13 aes-gcm key initialization failed"))?;
    // Reserve immediately before invoking AEAD. From this point onward the
    // (traffic key, sequence) tuple is burned even if encryption fails.
    let seq = epoch.reserve_sequence()?;
    let nonce = make_tls13_nonce(epoch.iv, seq);
    let tag = cipher
        .encrypt_in_place_detached((&nonce).into(), &aad, &mut payload)
        .map_err(|_| MpcTlsError::hs("tls13 record encryption failed"))?;
    let record = Record {
        seq,
        typ: TranscriptContentType::from(typ),
        plaintext: Some(plaintext),
        explicit_nonce: Vec::new(),
        ciphertext: payload.clone(),
        tag: Some(tag.to_vec()),
    };
    payload.extend_from_slice(&tag);

    Ok((
        OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        },
        record,
    ))
}

fn decrypt_tls13_record(
    epoch: &mut ReadEpoch<[u8; 16], [u8; 12]>,
    msg: OpaqueMessage,
) -> Result<(PlainMessage, Record), MpcTlsError> {
    if msg.typ != ContentType::ApplicationData || msg.version != ProtocolVersion::TLSv1_2 {
        return Err(MpcTlsError::hs("unexpected TLS 1.3 record header"));
    }

    let payload_bytes = msg.payload.0;
    let mut payload = payload_bytes;
    if payload.len() < 16 {
        return Err(MpcTlsError::hs(
            "tls13 record payload is shorter than the tag",
        ));
    }

    let tag = payload.split_off(payload.len() - 16);
    let ciphertext = payload.clone();
    let aad = make_tls13_aad(payload.len() + 16);
    let cipher = Aes128Gcm::new_from_slice(&epoch.key)
        .map_err(|_| MpcTlsError::hs("tls13 aes-gcm key initialization failed"))?;
    // Authentication consumes the peer's record number even on failure. A
    // failed record is fatal to the TLS connection and must never be retried.
    let seq = epoch.reserve_sequence()?;
    let nonce = make_tls13_nonce(epoch.iv, seq);
    cipher
        .decrypt_in_place_detached((&nonce).into(), &aad, &mut payload, tag.as_slice().into())
        .map_err(|_| MpcTlsError::hs("tls13 record authentication failed"))?;

    let typ = unpad_tls13(&mut payload)?;
    let plaintext = payload;
    let record = Record {
        seq,
        typ: TranscriptContentType::from(typ),
        plaintext: Some(plaintext.clone()),
        explicit_nonce: Vec::new(),
        ciphertext,
        tag: Some(tag),
    };

    Ok((
        PlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(plaintext),
        },
        record,
    ))
}

/// AES-256-GCM TLS 1.3 record encryption path.
///
/// This is kept separate from the legacy AES-128 helper until suite
/// negotiation and secret-shared AES-256 key installation are wired into the
/// handshake state machine.
fn encrypt_tls13_record_256(
    epoch: &mut WriteEpoch<[u8; 32], [u8; 12]>,
    msg: PlainMessage,
) -> Result<(OpaqueMessage, Record), MpcTlsError> {
    let typ = msg.typ;
    let plaintext = msg.payload.0;
    let mut payload = plaintext.clone();
    payload.push(typ.get_u8());
    let total_len = payload.len() + 16;
    let aad = make_tls13_aad(total_len);
    let cipher = Aes256Gcm::new_from_slice(&epoch.key)
        .map_err(|_| MpcTlsError::hs("tls13 aes-256-gcm key initialization failed"))?;
    let seq = epoch.reserve_sequence()?;
    let nonce = make_tls13_nonce(epoch.iv, seq);
    let tag = cipher
        .encrypt_in_place_detached((&nonce).into(), &aad, &mut payload)
        .map_err(|_| MpcTlsError::hs("tls13 aes-256-gcm record encryption failed"))?;
    let record = Record {
        seq,
        typ: TranscriptContentType::from(typ),
        plaintext: Some(plaintext),
        explicit_nonce: Vec::new(),
        ciphertext: payload.clone(),
        tag: Some(tag.to_vec()),
    };
    payload.extend_from_slice(&tag);
    Ok((OpaqueMessage { typ: ContentType::ApplicationData, version: ProtocolVersion::TLSv1_2, payload: Payload::new(payload) }, record))
}

/// AES-256-GCM TLS 1.3 record decryption path.
fn decrypt_tls13_record_256(
    epoch: &mut ReadEpoch<[u8; 32], [u8; 12]>,
    msg: OpaqueMessage,
) -> Result<(PlainMessage, Record), MpcTlsError> {
    if msg.typ != ContentType::ApplicationData || msg.version != ProtocolVersion::TLSv1_2 {
        return Err(MpcTlsError::hs("unexpected TLS 1.3 record header"));
    }
    let mut payload = msg.payload.0;
    if payload.len() < 16 { return Err(MpcTlsError::hs("tls13 record payload is shorter than the tag")); }
    let tag = payload.split_off(payload.len() - 16);
    let ciphertext = payload.clone();
    let aad = make_tls13_aad(payload.len() + 16);
    let cipher = Aes256Gcm::new_from_slice(&epoch.key)
        .map_err(|_| MpcTlsError::hs("tls13 aes-256-gcm key initialization failed"))?;
    let seq = epoch.reserve_sequence()?;
    let nonce = make_tls13_nonce(epoch.iv, seq);
    cipher.decrypt_in_place_detached((&nonce).into(), &aad, &mut payload, tag.as_slice().into())
        .map_err(|_| MpcTlsError::hs("tls13 aes-256-gcm record authentication failed"))?;
    let typ = unpad_tls13(&mut payload)?;
    let plaintext = payload;
    let record = Record { seq, typ: TranscriptContentType::from(typ), plaintext: Some(plaintext.clone()), explicit_nonce: Vec::new(), ciphertext, tag: Some(tag) };
    Ok((PlainMessage { typ, version: ProtocolVersion::TLSv1_3, payload: Payload::new(plaintext) }, record))
}

fn make_tls13_nonce(iv: [u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = iv;
    for (byte, seq) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *byte ^= seq;
    }

    nonce
}

fn make_tls13_aad(len: usize) -> [u8; 5] {
    [
        ContentType::ApplicationData.get_u8(),
        0x03,
        0x03,
        (len >> 8) as u8,
        len as u8,
    ]
}

fn unpad_tls13(payload: &mut Vec<u8>) -> Result<ContentType, MpcTlsError> {
    loop {
        match payload.pop() {
            Some(0) => {}
            Some(content_type) => {
                let typ = ContentType::from(content_type);
                if matches!(typ, ContentType::Unknown(0)) {
                    return Err(MpcTlsError::hs("illegal tls13 inner plaintext"));
                }

                return Ok(typ);
            }
            None => return Err(MpcTlsError::hs("empty tls13 inner plaintext")),
        }
    }
}

#[cfg(kani)]
mod verification {
    use super::{make_tls13_nonce, Epoch, ReadEpoch, WriteEpoch};

    #[kani::proof]
    fn write_reservation_returns_owned_sequence_and_advances_once() {
        let next_sequence: u64 = kani::any();
        kani::assume(next_sequence < u64::MAX);
        let mut epoch = WriteEpoch::new(Epoch::Application, 7, (), ());
        epoch.next_sequence = next_sequence;

        let reserved = epoch.reserve_sequence().unwrap();

        assert_eq!(reserved, next_sequence);
        assert_eq!(epoch.next_sequence, next_sequence + 1);
        assert_eq!(epoch.generation, 7);
    }

    #[kani::proof]
    fn read_reservation_returns_owned_sequence_and_advances_once() {
        let next_sequence: u64 = kani::any();
        kani::assume(next_sequence < u64::MAX);
        let mut epoch = ReadEpoch::new(Epoch::Application, 11, (), ());
        epoch.next_sequence = next_sequence;

        let reserved = epoch.reserve_sequence().unwrap();

        assert_eq!(reserved, next_sequence);
        assert_eq!(epoch.next_sequence, next_sequence + 1);
        assert_eq!(epoch.generation, 11);
    }

    #[kani::proof]
    fn exhausted_epochs_reject_without_wrapping() {
        let mut write = WriteEpoch::new(Epoch::Application, 0, (), ());
        let mut read = ReadEpoch::new(Epoch::Application, 0, (), ());
        write.next_sequence = u64::MAX;
        read.next_sequence = u64::MAX;

        assert!(write.reserve_sequence().is_err());
        assert!(read.reserve_sequence().is_err());
        assert_eq!(write.next_sequence, u64::MAX);
        assert_eq!(read.next_sequence, u64::MAX);
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn nonce_derivation_is_injective_for_a_fixed_iv() {
        let iv: [u8; 12] = kani::any();
        let first: u64 = kani::any();
        let second: u64 = kani::any();
        kani::assume(first != second);

        assert_ne!(make_tls13_nonce(iv, first), make_tls13_nonce(iv, second));
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt_tls13_record, decrypt_tls13_record_256, encrypt_tls13_record, encrypt_tls13_record_256, ReadEpoch, Tls13KeyState, WriteEpoch};
    use crate::{Epoch, Role};
    use hmac_sha256::Mode;
    use mpz_common::{context::test_st_context, Context};
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_memory_core::correlated::Delta;
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::{
        memory::{binary::{Binary, U8}, Array, MemoryExt, ViewExt},
        Execute, Vm,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use tls_core::msgs::{
        base::Payload,
        enums::{ContentType, ProtocolVersion},
        message::{OpaqueMessage, PlainMessage},
    };
    use tlsn_core::transcript::ContentType as TranscriptContentType;

    fn mock_vm() -> (Garbler<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Garbler::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    async fn configure(
        vm: &mut (dyn Vm<Binary> + Send),
        state: &mut Tls13KeyState,
        ctx: &mut Context,
        pms: [u8; 32],
        hello_hash: [u8; 32],
        handshake_hash: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let secret: Array<_, 32> = vm.alloc().unwrap();
        vm.mark_public(secret).unwrap();
        vm.assign(secret, pms).unwrap();
        vm.commit(secret).unwrap();

        state.alloc(vm, secret)?;
        state.set_hello_hash(ctx, vm, hello_hash).await?;
        let _ = state.set_handshake_hash(ctx, vm, handshake_hash).await?;

        Ok(())
    }

    #[tokio::test]
    async fn tls13_key_state_tracks_epochs() {
        let (
            pms,
            hello_hash,
            handshake_hash,
            ckey_hs,
            civ_hs,
            skey_hs,
            siv_hs,
            ckey_app,
            civ_app,
            skey_app,
            siv_app,
        ) = test_fixtures();

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader_vm, mut follower_vm) = mock_vm();

        let mut leader = Tls13KeyState::new(Mode::Normal, Role::Leader);
        let mut follower = Tls13KeyState::new(Mode::Normal, Role::Follower);

        tokio::try_join!(
            configure(
                &mut leader_vm,
                &mut leader,
                &mut ctx_a,
                pms,
                hello_hash,
                handshake_hash
            ),
            configure(
                &mut follower_vm,
                &mut follower,
                &mut ctx_b,
                pms,
                hello_hash,
                handshake_hash
            ),
        )
        .unwrap();

        let handshake = leader
            .session_keys()
            .handshake
            .as_ref()
            .expect("leader should learn handshake keys");
        assert_eq!(handshake.client.epoch(), Epoch::Handshake);
        assert_eq!(handshake.client.key, ckey_hs);
        assert_eq!(handshake.client.iv, civ_hs);
        assert_eq!(handshake.server.epoch(), Epoch::Handshake);
        assert_eq!(handshake.server.key, skey_hs);
        assert_eq!(handshake.server.iv, siv_hs);
        assert_ne!(handshake.client_finished_key, [0u8; 32]);
        assert_ne!(handshake.server_finished_key, [0u8; 32]);

        assert!(
            follower.session_keys().handshake.is_none(),
            "follower should not learn revealed handshake keys"
        );

        let leader_keys = leader
            .session_keys()
            .application
            .as_ref()
            .expect("application keys should be set");
        let follower_keys = follower
            .session_keys()
            .application
            .as_ref()
            .expect("application keys should be set");

        let mut leader_ckey = leader_vm.decode(leader_keys.client.key).unwrap();
        let mut leader_civ = leader_vm.decode(leader_keys.client.iv).unwrap();
        let mut leader_skey = leader_vm.decode(leader_keys.server.key).unwrap();
        let mut leader_siv = leader_vm.decode(leader_keys.server.iv).unwrap();
        let mut follower_ckey = follower_vm.decode(follower_keys.client.key).unwrap();
        let mut follower_civ = follower_vm.decode(follower_keys.client.iv).unwrap();
        let mut follower_skey = follower_vm.decode(follower_keys.server.key).unwrap();
        let mut follower_siv = follower_vm.decode(follower_keys.server.iv).unwrap();

        tokio::try_join!(
            leader_vm.execute_all(&mut ctx_a),
            follower_vm.execute_all(&mut ctx_b)
        )
        .unwrap();

        assert_eq!(leader_keys.client.epoch(), Epoch::Application);
        assert_eq!(leader_keys.server.epoch(), Epoch::Application);
        assert_eq!(leader_ckey.try_recv().unwrap().unwrap(), ckey_app,);
        assert_eq!(leader_civ.try_recv().unwrap().unwrap(), civ_app,);
        assert_eq!(leader_skey.try_recv().unwrap().unwrap(), skey_app,);
        assert_eq!(leader_siv.try_recv().unwrap().unwrap(), siv_app,);

        assert_eq!(follower_ckey.try_recv().unwrap().unwrap(), ckey_app,);
        assert_eq!(follower_civ.try_recv().unwrap().unwrap(), civ_app,);
        assert_eq!(follower_skey.try_recv().unwrap().unwrap(), skey_app,);
        assert_eq!(follower_siv.try_recv().unwrap().unwrap(), siv_app,);

        let finished = leader.server_finished_vd(handshake_hash).unwrap();
        assert_ne!(finished, [0u8; 32]);
    }

    #[test]
    fn aes256_tls13_record_round_trip() {
        let message = PlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(b"sha384 circuit path".to_vec()),
        };
        let key = [0x42u8; 32];
        let iv = [0x24u8; 12];
        let mut writer = WriteEpoch::new(Epoch::Application, 0, key, iv);
        let (wire, sent) = encrypt_tls13_record_256(&mut writer, message.clone()).unwrap();
        assert_eq!(sent.seq, 0);
        let mut reader = ReadEpoch::new(Epoch::Application, 0, key, iv);
        let (received, record) = decrypt_tls13_record_256(&mut reader, wire).unwrap();
        assert_eq!(record.seq, 0);
        assert_eq!(received.payload.0, message.payload.0);
        assert_eq!(received.typ, message.typ);
    }

    #[tokio::test]
    async fn sha384_application_material_installs_typed_epochs() {
        let master = [0x33u8; 48];
        let transcript = [0x44u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut vm_a, mut vm_b) = mock_vm();
        let setup = |vm: &mut (dyn Vm<Binary> + Send)| {
            let master_ref: Array<U8, 48> = vm.alloc().unwrap();
            vm.mark_public(master_ref).unwrap();
            vm.assign(master_ref, master).unwrap();
            vm.commit(master_ref).unwrap();
            master_ref
        };
        let master_a = setup(&mut vm_a);
        let master_b = setup(&mut vm_b);
        let mut state_a = Tls13KeyState::new(Mode::Normal, Role::Leader);
        let mut state_b = Tls13KeyState::new(Mode::Normal, Role::Follower);
        tokio::try_join!(
            state_a.set_sha384_application_keys(&mut ctx_a, &mut vm_a, master_a, transcript),
            state_b.set_sha384_application_keys(&mut ctx_b, &mut vm_b, master_b, transcript),
        ).unwrap();
        let state = state_a;
        let keys = state.session_keys().sha384_application.as_ref().unwrap();
        assert_eq!(keys.client.epoch(), Epoch::Application);
        assert_eq!(keys.server.epoch(), Epoch::Application);
        assert_eq!(keys.client.next_sequence(), 0);
        assert_eq!(keys.server.next_sequence(), 0);
    }

    #[tokio::test]
    async fn sha384_finished_callback_returns_public_verify_data() {
        let secret = [0x33u8; 48];
        let transcript = [0x44u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut vm_a, mut vm_b) = mock_vm();
        let setup = |vm: &mut (dyn Vm<Binary> + Send)| {
            let secret_ref: Array<U8, 48> = vm.alloc().unwrap();
            vm.mark_public(secret_ref).unwrap();
            vm.assign(secret_ref, secret).unwrap();
            vm.commit(secret_ref).unwrap();
            secret_ref
        };
        let secret_a = setup(&mut vm_a);
        let secret_b = setup(&mut vm_b);
        let mut state_a = Tls13KeyState::new(Mode::Normal, Role::Leader);
        let mut state_b = Tls13KeyState::new(Mode::Normal, Role::Follower);
        tokio::try_join!(
            state_a.set_sha384_handshake_keys(&mut ctx_a, &mut vm_a, secret_a, transcript),
            state_b.set_sha384_handshake_keys(&mut ctx_b, &mut vm_b, secret_b, transcript),
        ).unwrap();
        let (client, server) = tokio::try_join!(
            state_a.sha384_finished_vd(&mut ctx_a, &mut vm_a, transcript, false),
            state_b.sha384_finished_vd(&mut ctx_b, &mut vm_b, transcript, false),
        ).unwrap();
        assert_eq!(client, server);
        assert_eq!(client.len(), 48);
    }

    #[test]
    fn tls13_record_roundtrip_preserves_inner_type() {
        let key = from_hex_str("88 b9 6a d6 86 c8 4b e5 5a ce 18 a5 9c ce 5c 87");
        let iv = from_hex_str("b9 9d c5 8c d5 ff 5a b0 82 fd ad 19");
        let plain = PlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(b"hello tls13".to_vec()),
        };

        let mut write_epoch = WriteEpoch::new(Epoch::Application, 0, key, iv);
        let (encrypted, record) = encrypt_tls13_record(&mut write_epoch, plain.clone()).unwrap();
        assert_eq!(encrypted.typ, ContentType::ApplicationData);
        assert_eq!(encrypted.version, ProtocolVersion::TLSv1_2);
        assert_eq!(record.typ, TranscriptContentType::ApplicationData);

        let mut read_epoch = ReadEpoch::new(Epoch::Application, 0, key, iv);
        let (decrypted, decrypted_record) =
            decrypt_tls13_record(&mut read_epoch, encrypted).unwrap();
        assert_eq!(decrypted.typ, plain.typ);
        assert_eq!(decrypted.version, ProtocolVersion::TLSv1_3);
        assert_eq!(decrypted.payload.0, plain.payload.0);
        assert_eq!(decrypted_record.typ, TranscriptContentType::ApplicationData);
        assert_eq!(write_epoch.next_sequence(), 1);
        assert_eq!(read_epoch.next_sequence(), 1);
    }

    #[test]
    fn malformed_short_record_is_rejected_before_sequence_consumption() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let malformed = OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(vec![0u8; 15]),
        };
        let mut read_epoch = ReadEpoch::new(Epoch::Application, 0, key, iv);

        assert!(decrypt_tls13_record(&mut read_epoch, malformed).is_err());
        assert_eq!(read_epoch.next_sequence(), 0);
    }

    #[test]
    fn bad_tag_consumes_sequence_and_replay_fails_at_the_next_sequence() {
        let key = [0x33u8; 16];
        let iv = [0x44u8; 12];
        let plain = PlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(b"one-shot record".to_vec()),
        };
        let mut write_epoch = WriteEpoch::new(Epoch::Application, 0, key, iv);
        let (encrypted, _) = encrypt_tls13_record(&mut write_epoch, plain).unwrap();

        let mut bad_tag = encrypted.clone();
        let last = bad_tag.payload.0.len() - 1;
        bad_tag.payload.0[last] ^= 1;
        let mut read_epoch = ReadEpoch::new(Epoch::Application, 0, key, iv);
        assert!(decrypt_tls13_record(&mut read_epoch, bad_tag).is_err());
        assert_eq!(read_epoch.next_sequence(), 1);

        assert!(decrypt_tls13_record(&mut read_epoch, encrypted).is_err());
        assert_eq!(read_epoch.next_sequence(), 2);
    }

    #[test]
    fn reordered_records_fail_under_their_owned_sequence_numbers() {
        let key = [0x55u8; 16];
        let iv = [0x66u8; 12];
        let make_plain = |body| PlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(body),
        };
        let mut write_epoch = WriteEpoch::new(Epoch::Application, 0, key, iv);
        let (first, _) =
            encrypt_tls13_record(&mut write_epoch, make_plain(b"first".to_vec())).unwrap();
        let (second, _) =
            encrypt_tls13_record(&mut write_epoch, make_plain(b"second".to_vec())).unwrap();

        let mut read_epoch = ReadEpoch::new(Epoch::Application, 0, key, iv);
        assert!(decrypt_tls13_record(&mut read_epoch, second).is_err());
        assert!(decrypt_tls13_record(&mut read_epoch, first).is_err());
        assert_eq!(read_epoch.next_sequence(), 2);
    }

    #[test]
    fn wrong_epoch_header_is_rejected_without_opening_payload() {
        let message = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(vec![0u8; 16]),
        };
        let mut read_epoch = ReadEpoch::new(Epoch::Application, 0, [0u8; 16], [0u8; 12]);

        assert!(decrypt_tls13_record(&mut read_epoch, message).is_err());
        assert_eq!(read_epoch.next_sequence(), 0);
    }

    #[test]
    fn directional_epochs_own_independent_sequences_and_reset_on_install() {
        let mut write = WriteEpoch::new(Epoch::Application, 0, [1u8; 16], [2u8; 12]);
        let mut read = ReadEpoch::new(Epoch::Application, 0, [3u8; 16], [4u8; 12]);

        assert_eq!(write.reserve_sequence().unwrap(), 0);
        assert_eq!(write.reserve_sequence().unwrap(), 1);
        assert_eq!(read.reserve_sequence().unwrap(), 0);
        assert_eq!(write.next_sequence(), 2);
        assert_eq!(read.next_sequence(), 1);

        let replacement = WriteEpoch::new(Epoch::Application, 1, [5u8; 16], [6u8; 12]);
        assert_eq!(replacement.generation(), 1);
        assert_eq!(replacement.next_sequence(), 0);
    }

    #[test]
    fn directional_epochs_reject_sequence_wrap() {
        let mut write = WriteEpoch::new(Epoch::Application, 0, [1u8; 16], [2u8; 12]);
        write.next_sequence = u64::MAX;
        assert!(write.reserve_sequence().is_err());
        assert_eq!(write.next_sequence(), u64::MAX);

        let mut read = ReadEpoch::new(Epoch::Application, 0, [3u8; 16], [4u8; 12]);
        read.next_sequence = u64::MAX;
        assert!(read.reserve_sequence().is_err());
        assert_eq!(read.next_sequence(), u64::MAX);
    }

    #[allow(clippy::type_complexity)]
    fn test_fixtures() -> (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 16],
        [u8; 12],
        [u8; 16],
        [u8; 12],
        [u8; 16],
        [u8; 12],
        [u8; 16],
        [u8; 12],
    ) {
        // Reference values from draft-ietf-tls-tls13-vectors-06 used by the
        // hmac-sha256 TLS 1.3 tests.
        (
            from_hex_str(
                "81 51 d1 46 4c 1b 55 53 36 23 b9 c2 24 6a 6a 0e 6e 7e 18 50 63 e1 4a fd af f0 b6 e1 c6 1a 86 42",
            ),
            from_hex_str("c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d"),
            from_hex_str("f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            from_hex_str("26 79 a4 3e 1d 76 78 40 34 ea 17 97 d5 ad 26 49"),
            from_hex_str("54 82 40 52 90 dd 0d 2f 81 c0 d9 42"),
            from_hex_str("c6 6c b1 ae c5 19 df 44 c9 1e 10 99 55 11 ac 8b"),
            from_hex_str("f7 f6 88 4c 49 81 71 6c 2d 0d 29 a4"),
            from_hex_str("88 b9 6a d6 86 c8 4b e5 5a ce 18 a5 9c ce 5c 87"),
            from_hex_str("b9 9d c5 8c d5 ff 5a b0 82 fd ad 19"),
            from_hex_str("a6 88 eb b5 ac 82 6d 6f 42 d4 5c 0c c4 4b 9b 7d"),
            from_hex_str("c1 ca d4 42 5a 43 8b 5d e7 14 83 0a"),
        )
    }

    fn from_hex_str<const N: usize>(s: &str) -> [u8; N] {
        s.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

use crate::{
    error::MpcTlsError,
    msg::{
        ClientFinishedVd, Decrypt, Encrypt, Message, ServerFinishedVd, SetClientRandom,
        SetProtocolVersion, SetServerKey, SetServerRandom, StartHandshake, Tls13CertVerify,
        Tls13ClientFinishedVd, Tls13HandshakeHash, Tls13HelloHash, Tls13RecordMessage,
        Tls13ServerFinishedVd,
    },
    record_layer::{
        aead::MpcAesGcm, DecryptMode as RecordDecryptMode, EncryptMode as RecordEncryptMode,
        RecordLayer,
    },
    tls13::{Epoch, Tls13KeyState},
    utils::opaque_into_parts,
    Config, Role, SessionKeys, Vm,
};
use async_trait::async_trait;
use hmac_sha256::{MpcPrf, PrfOutput};
use ke::KeyExchange;
use key_exchange::{self as ke, MpcKeyExchange};
use mpz_common::{Context, Flush};
use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::DecodeFutureTyped;
use mpz_ole::{Receiver as OLEReceiver, Sender as OLESender};
use mpz_ot::{
    rcot::{RCOTReceiver, RCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use mpz_vm_core::prelude::*;
use serio::SinkExt;
use std::collections::VecDeque;
use tls_client::{
    Backend, BackendError, BackendNotifier, BackendNotify, DecryptMode as BackendDecryptMode,
    EncryptMode as BackendEncryptMode,
};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        base::Payload,
        enums::{CipherSuite, ContentType, NamedGroup, ProtocolVersion},
        handshake::{DigitallySignedStruct, Random},
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
    verify::verify_sig_determine_alg,
};
use tlsn_core::{
    connection::{
        CertBinding, CertBindingV1_2, CertBindingV1_3, ServerSignature, SignatureAlgorithm,
        TlsVersion, VerifyData,
    },
    transcript::{Record, TlsTranscript},
    webpki::CertificateDer,
};
use tracing::{debug, instrument, trace, warn};

/// MPC-TLS leader.
#[derive(Debug)]
pub struct MpcTlsLeader {
    config: Config,
    state: State,

    /// When set, notifies the backend that there are TLS messages which need to
    /// be decrypted.
    notifier: BackendNotifier,
    /// Whether the record layer is decrypting application data.
    is_decrypting: bool,
    tls13_encrypt_epoch: Option<Epoch>,
    tls13_decrypt_epoch: Option<Epoch>,
    tls13_incoming: VecDeque<PlainMessage>,
    tls13_outgoing: VecDeque<OpaqueMessage>,
    tls13_sent_records: Vec<Record>,
    tls13_recv_records: Vec<Record>,
}

impl MpcTlsLeader {
    /// Creates a new leader instance.
    pub fn new<CS, CR>(
        config: Config,
        ctx: Context,
        vm: Vm,
        cot_send: (CS, CS, CS),
        cot_recv: CR,
    ) -> Self
    where
        CS: RCOTSender<Block> + Flush + Send + Sync + 'static,
        CR: RCOTReceiver<bool, Block> + Flush + Send + Sync + 'static,
    {
        let mut rng = rand::rng();

        let ke = Box::new(MpcKeyExchange::new(
            key_exchange::Role::Leader,
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.0)),
            )),
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv),
            ))),
        )) as Box<dyn KeyExchange + Send + Sync>;

        let prf = MpcPrf::new(config.prf);
        let tls13 = Tls13KeyState::new(config.prf, Role::Leader);

        let encrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.1)),
            )),
            Role::Leader,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.2)),
            )),
            Role::Leader,
        );

        let record_layer = RecordLayer::new(Role::Leader, encrypter, decrypter);

        let is_decrypting = !config.defer_decryption;
        Self {
            config,
            state: State::Init {
                ctx,
                vm,
                ke,
                prf,
                tls13,
                record_layer,
            },
            notifier: BackendNotifier::new(),
            is_decrypting,
            tls13_encrypt_epoch: None,
            tls13_decrypt_epoch: None,
            tls13_incoming: VecDeque::new(),
            tls13_outgoing: VecDeque::new(),
            tls13_sent_records: Vec::new(),
            tls13_recv_records: Vec::new(),
        }
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let State::Init {
            ctx,
            vm,
            mut ke,
            mut prf,
            mut tls13,
            mut record_layer,
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in init state to allocate"));
        };

        let mut vm_lock = vm
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        let client_random = Random::new().expect("rng is available");

        // Allocate.
        let pms = ke.alloc(&mut (*vm_lock))?;
        let PrfOutput { keys, cf_vd, sf_vd } = prf.alloc(&mut (*vm_lock), pms)?;
        tls13.alloc(&mut (*vm_lock), pms)?;
        record_layer.set_keys(
            keys.client_write_key,
            keys.client_iv,
            keys.server_write_key,
            keys.server_iv,
        )?;

        let cf_vd = vm_lock.decode(cf_vd).map_err(MpcTlsError::alloc)?;
        let sf_vd = vm_lock.decode(sf_vd).map_err(MpcTlsError::alloc)?;

        let server_write_mac_key = record_layer.alloc(
            &mut (*vm_lock),
            self.config.max_sent_records,
            self.config.max_recv_records_online,
            self.config.max_sent,
            self.config.max_recv_online,
            self.config.max_recv,
        )?;

        let keys: SessionKeys = SessionKeys {
            client_write_key: keys.client_write_key,
            client_write_iv: keys.client_iv,
            server_write_key: keys.server_write_key,
            server_write_iv: keys.server_iv,
            server_write_mac_key,
        };

        self.state = State::Setup {
            ctx,
            vm,
            ke,
            prf,
            tls13,
            record_layer,
            cf_vd_fut: cf_vd,
            sf_vd_fut: sf_vd,
            client_random,
        };

        Ok(keys)
    }

    /// Preprocesses the connection.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let State::Setup {
            mut ctx,
            vm,
            mut ke,
            mut prf,
            tls13,
            mut record_layer,
            cf_vd_fut,
            sf_vd_fut,
            client_random,
            ..
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in setup state to preprocess"));
        };

        let mut vm_lock = vm
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        let (ke, record_layer, _) = ctx
            .try_join3(
                async move |ctx| {
                    ke.setup(ctx)
                        .await
                        .map(|_| ke)
                        .map_err(MpcTlsError::preprocess)
                },
                async move |ctx| {
                    record_layer
                        .preprocess(ctx)
                        .await
                        .map(|_| record_layer)
                        .map_err(MpcTlsError::preprocess)
                },
                async move |ctx| {
                    vm_lock
                        .preprocess(ctx)
                        .await
                        .map_err(MpcTlsError::preprocess)?;
                    vm_lock.flush(ctx).await.map_err(MpcTlsError::preprocess)?;

                    Ok::<_, MpcTlsError>(())
                },
            )
            .await
            .map_err(MpcTlsError::preprocess)??;

        ctx.io_mut()
            .send(Message::SetClientRandom(SetClientRandom {
                random: client_random.0,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        prf.set_client_random(client_random.0)?;

        self.state = State::Handshake {
            ctx,
            vm,
            ke,
            prf,
            tls13,
            record_layer,
            cf_vd_fut,
            sf_vd_fut,
            cf_vd: None,
            sf_vd: None,
            time: None,
            protocol_version: None,
            cipher_suite: None,
            client_random,
            server_random: None,
            server_cert_details: None,
            server_key: None,
            server_kx_details: None,
            tls13_server_signature: None,
            tls13_cert_verify_transcript_hash: None,
        };

        Ok(())
    }

    /// Closes the connection.
    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    pub async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        let (
            mut ctx,
            vm,
            mut record_layer,
            cf_vd,
            sf_vd,
            time,
            protocol_version,
            client_random,
            server_random,
            server_cert_details,
            server_key,
            server_kx_details,
            tls13_server_signature,
            tls13_cert_verify_transcript_hash,
        ) = match self.state.take() {
            State::Active {
                ctx,
                vm,
                record_layer,
                cf_vd,
                sf_vd,
                time,
                protocol_version,
                client_random,
                server_random,
                server_cert_details,
                server_key,
                server_kx_details,
                tls13_server_signature,
                tls13_cert_verify_transcript_hash,
                ..
            } => (
                ctx,
                vm,
                record_layer,
                cf_vd,
                sf_vd,
                time,
                protocol_version,
                client_random,
                server_random,
                server_cert_details,
                server_key,
                server_kx_details,
                tls13_server_signature,
                tls13_cert_verify_transcript_hash,
            ),
            State::Handshake {
                ctx,
                vm,
                record_layer,
                cf_vd,
                sf_vd,
                time,
                protocol_version,
                client_random,
                server_random,
                server_cert_details,
                server_key,
                server_kx_details,
                tls13_server_signature,
                tls13_cert_verify_transcript_hash,
                ..
            } => (
                ctx,
                vm,
                record_layer,
                cf_vd,
                sf_vd,
                time.ok_or(MpcTlsError::state("handshake time not set"))?,
                protocol_version.ok_or(MpcTlsError::state("protocol version not set"))?,
                client_random,
                server_random.ok_or(MpcTlsError::state("server random not set"))?,
                server_cert_details.ok_or(MpcTlsError::state("server cert details not set"))?,
                server_key.ok_or(MpcTlsError::state("server key not set"))?,
                server_kx_details,
                tls13_server_signature,
                tls13_cert_verify_transcript_hash,
            ),
            _ => {
                return Err(MpcTlsError::state(
                    "must be in handshake or active state to close connection",
                ))
            }
        };

        debug!("closing connection");

        ctx.io_mut().send(Message::CloseConnection).await?;

        let cf_vd = cf_vd.ok_or(MpcTlsError::state("client finished verify data not set"))?;
        let sf_vd = sf_vd.ok_or(MpcTlsError::state("server finished verify data not set"))?;

        let server_cert_chain = server_cert_details
            .cert_chain()
            .iter()
            .map(|cert| CertificateDer(cert.0.clone()))
            .collect();
        let server_ephemeral_key = server_key
            .try_into()
            .expect("only supported key scheme should have been accepted");

        let (
            version,
            server_signature,
            handshake_data,
            tls13_records_authenticated,
            sent_records,
            recv_records,
        ) = match protocol_version {
            ProtocolVersion::TLSv1_2 => {
                debug!("committing tls12 transcript");

                let (sent_records, recv_records) =
                    record_layer.commit(&mut ctx, vm.clone()).await?;

                debug!("committed tls12 transcript");

                if !record_layer.is_empty() {
                    debug!("notifying client to process remaining messages");
                    self.notifier.set();
                }

                let server_kx_details =
                    server_kx_details.ok_or(MpcTlsError::state("server kx details not set"))?;

                let mut sig_msg = Vec::new();
                sig_msg.extend_from_slice(&client_random.0);
                sig_msg.extend_from_slice(&server_random.0);
                sig_msg.extend_from_slice(server_kx_details.kx_params());

                let server_signature_alg = verify_sig_determine_alg(
                    &server_cert_details.cert_chain()[0],
                    &sig_msg,
                    server_kx_details.kx_sig(),
                )
                .expect("only supported signature should have been accepted");

                let server_signature = ServerSignature {
                    alg: server_signature_alg.into(),
                    sig: server_kx_details.kx_sig().sig.0.clone(),
                };

                (
                    TlsVersion::V1_2,
                    server_signature,
                    CertBinding::V1_2(CertBindingV1_2 {
                        client_random: client_random.0,
                        server_random: server_random.0,
                        server_ephemeral_key,
                    }),
                    false,
                    sent_records,
                    recv_records,
                )
            }
            ProtocolVersion::TLSv1_3 => {
                let tls13_server_signature = tls13_server_signature
                    .ok_or(MpcTlsError::state("tls13 server signature not set"))?;
                let tls13_cert_verify_transcript_hash = tls13_cert_verify_transcript_hash.ok_or(
                    MpcTlsError::state("tls13 certificate verify transcript hash not set"),
                )?;

                (
                    TlsVersion::V1_3,
                    tls13_server_signature,
                    CertBinding::V1_3(CertBindingV1_3 {
                        server_ephemeral_key,
                        cert_verify_transcript_hash: tls13_cert_verify_transcript_hash,
                    }),
                    true,
                    std::mem::take(&mut self.tls13_sent_records),
                    std::mem::take(&mut self.tls13_recv_records),
                )
            }
            version => {
                return Err(MpcTlsError::state(format!(
                    "unsupported version: {version:?}"
                )))
            }
        };

        let transcript = TlsTranscript::new(
            time,
            version,
            Some(server_cert_chain),
            Some(server_signature),
            handshake_data,
            tls13_records_authenticated,
            VerifyData {
                client_finished: cf_vd,
                server_finished: sf_vd,
            },
            sent_records,
            recv_records,
        )
        .map_err(MpcTlsError::other)?;

        self.state = State::Closed {
            ctx,
            vm,
            record_layer,
            transcript,
        };

        Ok(())
    }

    /// Returns if incoming messages are decrypted.
    pub fn is_decrypting(&self) -> bool {
        self.is_decrypting
    }
}

#[async_trait]
impl Backend for MpcTlsLeader {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        let State::Handshake {
            ctx,
            protocol_version,
            ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set protocol version").into(),
            );
        };

        trace!("setting protocol version: {:?}", version);

        *protocol_version = Some(version);
        ctx.io_mut()
            .send(Message::SetProtocolVersion(SetProtocolVersion { version }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        let State::Handshake { cipher_suite, .. } = &mut self.state else {
            return Err(
                MpcTlsError::state("must be in handshake state to set cipher suite").into(),
            );
        };

        if matches!(suite, SupportedCipherSuite::Tls13(_))
            && suite.suite() != CipherSuite::TLS13_AES_128_GCM_SHA256
        {
            return Err(BackendError::UnsupportedCiphersuite(suite.suite()));
        }

        trace!("setting cipher suite: {:?}", suite);

        *cipher_suite = Some(suite.suite());

        Ok(())
    }

    async fn set_encrypt(&mut self, mode: BackendEncryptMode) -> Result<(), BackendError> {
        let protocol_version = match &self.state {
            State::Handshake {
                protocol_version, ..
            } => *protocol_version,
            State::Active {
                protocol_version, ..
            } => Some(*protocol_version),
            _ => None,
        };

        if protocol_version == Some(ProtocolVersion::TLSv1_3) {
            self.tls13_encrypt_epoch = Some(match mode {
                BackendEncryptMode::EarlyData => {
                    return Err(BackendError::InvalidConfig(
                        "tls13 early data is out of scope".into(),
                    ))
                }
                BackendEncryptMode::Handshake => Epoch::Handshake,
                BackendEncryptMode::Application => Epoch::Application,
            });
        }

        Ok(())
    }

    async fn set_decrypt(&mut self, mode: BackendDecryptMode) -> Result<(), BackendError> {
        let protocol_version = match &self.state {
            State::Handshake {
                protocol_version, ..
            } => *protocol_version,
            State::Active {
                protocol_version, ..
            } => Some(*protocol_version),
            _ => None,
        };

        if protocol_version == Some(ProtocolVersion::TLSv1_3) {
            self.tls13_decrypt_epoch = Some(match mode {
                BackendDecryptMode::Handshake => Epoch::Handshake,
                BackendDecryptMode::Application => Epoch::Application,
            });
        }

        Ok(())
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        let State::Handshake { client_random, .. } = &self.state else {
            return Err(
                MpcTlsError::state("must be in handshake state to get client random").into(),
            );
        };

        Ok(*client_random)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        let State::Handshake { ke, .. } = &self.state else {
            return Err(
                MpcTlsError::state("must be in handshake state to get client key share").into(),
            );
        };

        let pk = ke
            .client_key()
            .map_err(|err| BackendError::InvalidState(err.to_string()))?;

        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        let State::Handshake {
            ctx,
            prf,
            server_random,
            time,
            ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set server random").into(),
            );
        };

        let now = web_time::UNIX_EPOCH
            .elapsed()
            .expect("system time is available")
            .as_secs();

        *time = Some(now);

        ctx.io_mut()
            .send(Message::StartHandshake(StartHandshake { time: now }))
            .await
            .map_err(MpcTlsError::from)?;

        ctx.io_mut()
            .send(Message::SetServerRandom(SetServerRandom {
                random: random.0,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        prf.set_server_random(random.0).map_err(MpcTlsError::hs)?;
        *server_random = Some(random);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        let State::Handshake {
            ctx,
            vm,
            ke,
            protocol_version,
            server_key,
            ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set server key share").into(),
            );
        };

        if key.group != NamedGroup::secp256r1 {
            return Err(BackendError::InvalidServerKey);
        }

        ctx.io_mut()
            .send(Message::SetServerKey(SetServerKey { key: key.clone() }))
            .await
            .map_err(MpcTlsError::hs)?;

        *server_key = Some(key);

        if protocol_version == &Some(ProtocolVersion::TLSv1_3) {
            let server_key = server_key
                .clone()
                .ok_or_else(|| MpcTlsError::hs("server key was not stored"))?;

            ke.set_server_key(
                p256::PublicKey::from_sec1_bytes(&server_key.key).map_err(MpcTlsError::hs)?,
            )
            .map_err(|err| BackendError::InvalidState(err.to_string()))?;
            ke.compute_shares(ctx).await.map_err(MpcTlsError::hs)?;

            let mut vm_lock = vm
                .try_lock()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?;
            ke.assign(&mut (*vm_lock)).map_err(MpcTlsError::hs)?;
            vm_lock.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
            ke.finalize().await.map_err(MpcTlsError::hs)?;
        }

        Ok(())
    }

    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        let State::Handshake {
            server_cert_details,
            ..
        } = &mut self.state
        else {
            return Err(MpcTlsError::state(
                "must be in handshake state to set server cert details",
            )
            .into());
        };

        *server_cert_details = Some(cert_details);

        Ok(())
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        let State::Handshake {
            server_kx_details, ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set server kx details").into(),
            );
        };

        *server_kx_details = Some(kx_details);

        Ok(())
    }

    async fn set_tls13_server_cert_verify(
        &mut self,
        cert_verify: DigitallySignedStruct,
        handshake_hash: Vec<u8>,
    ) -> Result<(), BackendError> {
        let transcript_hash: [u8; 32] = handshake_hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("tls13 cert verify hash is not 32 bytes"))?;

        let State::Handshake {
            ctx,
            protocol_version,
            tls13_server_signature,
            tls13_cert_verify_transcript_hash,
            ..
        } = &mut self.state
        else {
            return Err(MpcTlsError::state(
                "must be in handshake state to set tls13 certificate verify details",
            )
            .into());
        };

        if protocol_version != &Some(ProtocolVersion::TLSv1_3) {
            return Ok(());
        }

        *tls13_server_signature = Some(ServerSignature {
            alg: tls13_signature_scheme(cert_verify.scheme)?,
            sig: cert_verify.sig.0.clone(),
        });
        *tls13_cert_verify_transcript_hash = Some(transcript_hash);

        ctx.io_mut()
            .send(Message::Tls13CertVerify(Tls13CertVerify {
                transcript_hash,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    async fn set_tls13_handshake_hash(
        &mut self,
        handshake_hash: Vec<u8>,
    ) -> Result<(), BackendError> {
        let hash: [u8; 32] = handshake_hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("tls13 handshake hash is not 32 bytes"))?;

        let State::Handshake {
            ctx,
            vm,
            tls13,
            protocol_version,
            ..
        } = &mut self.state
        else {
            return Ok(());
        };

        if protocol_version == &Some(ProtocolVersion::TLSv1_3) {
            ctx.io_mut()
                .send(Message::Tls13HandshakeHash(Tls13HandshakeHash {
                    handshake_hash: hash,
                }))
                .await
                .map_err(MpcTlsError::from)?;

            let mut vm = vm
                .try_lock()
                .map_err(|_| MpcTlsError::hs("VM lock is held"))?;
            tls13
                .set_handshake_hash(ctx, &mut *vm, hash)
                .await
                .map_err(MpcTlsError::hs)?;
        }

        Ok(())
    }

    async fn set_hs_hash_client_key_exchange(
        &mut self,
        _hash: Vec<u8>,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("server hello handshake hash is not 32 bytes"))?;

        let State::Handshake {
            ctx,
            vm,
            tls13,
            protocol_version,
            ..
        } = &mut self.state
        else {
            return Ok(());
        };

        if protocol_version == &Some(ProtocolVersion::TLSv1_3) {
            ctx.io_mut()
                .send(Message::Tls13HelloHash(Tls13HelloHash { hello_hash: hash }))
                .await
                .map_err(MpcTlsError::from)?;

            let mut vm = vm
                .try_lock()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?;
            tls13
                .set_hello_hash(ctx, &mut *vm, hash)
                .await
                .map_err(MpcTlsError::hs)?;
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("server finished handshake hash is not 32 bytes"))?;
        debug!("computing server finished verify data");

        match &mut self.state {
            State::Handshake {
                ctx,
                tls13,
                sf_vd,
                protocol_version: Some(ProtocolVersion::TLSv1_3),
                ..
            } => {
                let vd = tls13.server_finished_vd(hash).map_err(MpcTlsError::hs)?;
                *sf_vd = Some(vd.to_vec());
                ctx.io_mut()
                    .send(Message::Tls13ServerFinishedVd(Tls13ServerFinishedVd {
                        verify_data: vd,
                    }))
                    .await
                    .map_err(MpcTlsError::from)?;

                Ok(vd.to_vec())
            }
            State::Active {
                ctx,
                vm,
                prf,
                sf_vd_fut,
                sf_vd,
                protocol_version: ProtocolVersion::TLSv1_2,
                ..
            } => {
                ctx.io_mut()
                    .send(Message::ServerFinishedVd(ServerFinishedVd {
                        handshake_hash: hash,
                    }))
                    .await
                    .map_err(MpcTlsError::from)?;

                let mut vm = vm
                    .try_lock()
                    .map_err(|_| MpcTlsError::other("VM lock is held"))?;
                prf.set_sf_hash(hash).map_err(MpcTlsError::hs)?;

                while prf.wants_flush() {
                    prf.flush(&mut *vm).map_err(MpcTlsError::hs)?;
                    vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
                }

                let vd = sf_vd_fut
                    .try_recv()
                    .map_err(MpcTlsError::hs)?
                    .ok_or_else(|| MpcTlsError::hs("sf_vd is not decoded"))?;

                *sf_vd = Some(vd.to_vec());

                Ok(vd.to_vec())
            }
            _ => Err(MpcTlsError::state(
                "must be in a tls13 handshake or tls12 active state to get server finished vd",
            )
            .into()),
        }
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("client finished handshake hash is not 32 bytes"))?;
        debug!("computing client finished verify data");

        match &mut self.state {
            State::Handshake {
                ctx,
                tls13,
                cf_vd,
                protocol_version: Some(ProtocolVersion::TLSv1_3),
                ..
            } => {
                let vd = tls13.client_finished_vd(hash).map_err(MpcTlsError::hs)?;
                *cf_vd = Some(vd.to_vec());
                ctx.io_mut()
                    .send(Message::Tls13ClientFinishedVd(Tls13ClientFinishedVd {
                        handshake_hash: hash,
                        verify_data: vd,
                    }))
                    .await
                    .map_err(MpcTlsError::from)?;

                Ok(vd.to_vec())
            }
            State::Active {
                ctx,
                vm,
                prf,
                cf_vd_fut,
                cf_vd,
                protocol_version: ProtocolVersion::TLSv1_2,
                ..
            } => {
                ctx.io_mut()
                    .send(Message::ClientFinishedVd(ClientFinishedVd {
                        handshake_hash: hash,
                    }))
                    .await
                    .map_err(MpcTlsError::hs)?;

                let mut vm = vm
                    .try_lock()
                    .map_err(|_| MpcTlsError::hs("VM lock is held"))?;
                prf.set_cf_hash(hash).map_err(MpcTlsError::hs)?;

                while prf.wants_flush() {
                    prf.flush(&mut *vm).map_err(MpcTlsError::hs)?;
                    vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;
                }

                let vd = cf_vd_fut
                    .try_recv()
                    .map_err(MpcTlsError::hs)?
                    .ok_or_else(|| MpcTlsError::hs("cf_vd is not decoded"))?;

                *cf_vd = Some(vd.to_vec());

                Ok(vd.to_vec())
            }
            _ => Err(MpcTlsError::state(
                "must be in a tls13 handshake or tls12 active state to get client finished vd",
            )
            .into()),
        }
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        let State::Handshake {
            mut ctx,
            vm,
            mut ke,
            mut prf,
            tls13,
            mut record_layer,
            cf_vd_fut,
            sf_vd_fut,
            cf_vd,
            sf_vd,
            time,
            protocol_version,
            client_random,
            server_random,
            server_cert_details,
            server_key,
            server_kx_details,
            tls13_server_signature,
            tls13_cert_verify_transcript_hash,
            ..
        } = self.state.take()
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to prepare encryption").into(),
            );
        };

        debug!("preparing encryption");

        let time = time.ok_or_else(|| MpcTlsError::hs("time is not set"))?;
        let protocol_version =
            protocol_version.ok_or_else(|| MpcTlsError::hs("protocol version is not set"))?;
        let server_random =
            server_random.ok_or_else(|| MpcTlsError::hs("server random is not set"))?;
        let server_cert_details =
            server_cert_details.ok_or_else(|| MpcTlsError::hs("server cert details is not set"))?;
        let server_key = server_key.ok_or_else(|| MpcTlsError::hs("server key is not set"))?;

        if protocol_version != ProtocolVersion::TLSv1_3 {
            let server_kx_details =
                server_kx_details.ok_or_else(|| MpcTlsError::hs("server kx details is not set"))?;

            ke.set_server_key(
                p256::PublicKey::from_sec1_bytes(&server_key.key).map_err(MpcTlsError::hs)?,
            )
            .map_err(|err| BackendError::InvalidState(err.to_string()))?;

            ke.compute_shares(&mut ctx).await.map_err(MpcTlsError::hs)?;

            {
                let mut vm_lock = vm
                    .try_lock()
                    .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                ke.assign(&mut (*vm_lock)).map_err(MpcTlsError::hs)?;

                while prf.wants_flush() {
                    prf.flush(&mut *vm_lock).map_err(MpcTlsError::hs)?;
                    vm_lock
                        .execute_all(&mut ctx)
                        .await
                        .map_err(MpcTlsError::hs)?;
                }

                ke.finalize().await.map_err(MpcTlsError::hs)?;
                record_layer.setup(&mut ctx).await?;
            }

            debug!("encryption prepared");

            self.state = State::Active {
                ctx,
                vm,
                _ke: ke,
                prf,
                tls13,
                record_layer,
                cf_vd_fut,
                sf_vd_fut,
                cf_vd,
                sf_vd,
                time,
                protocol_version,
                client_random,
                server_random,
                server_cert_details,
                server_key,
                server_kx_details: Some(server_kx_details),
                tls13_server_signature,
                tls13_cert_verify_transcript_hash,
            };
        } else {
            debug!("tls13 encryption prepared");

            self.state = State::Active {
                ctx,
                vm,
                _ke: ke,
                prf,
                tls13,
                record_layer,
                cf_vd_fut,
                sf_vd_fut,
                cf_vd,
                sf_vd,
                time,
                protocol_version,
                client_random,
                server_random,
                server_cert_details,
                server_key,
                server_kx_details: None,
                tls13_server_signature,
                tls13_cert_verify_transcript_hash,
            };
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        match &mut self.state {
            State::Handshake {
                ctx,
                tls13,
                protocol_version: Some(ProtocolVersion::TLSv1_3),
                ..
            }
            | State::Active {
                ctx,
                tls13,
                protocol_version: ProtocolVersion::TLSv1_3,
                ..
            } => {
                let epoch = self.tls13_decrypt_epoch.ok_or_else(|| {
                    MpcTlsError::hs("tls13 decrypt epoch was not configured before decryption")
                })?;
                let (plain, record) = tls13.decrypt_record(epoch, msg).map_err(MpcTlsError::hs)?;
                ctx.io_mut()
                    .send(Message::Tls13RecvRecord(Tls13RecordMessage {
                        record: record.clone(),
                    }))
                    .await
                    .map_err(MpcTlsError::from)?;
                self.tls13_recv_records.push(record);
                self.tls13_incoming.push_back(plain);
                return Ok(());
            }
            _ => {}
        }

        let (ctx, record_layer) = match &mut self.state {
            State::Handshake {
                ctx, record_layer, ..
            } => (ctx, record_layer),
            State::Active {
                ctx, record_layer, ..
            } => (ctx, record_layer),
            _ => {
                return Err(MpcTlsError::state(format!(
                    "can not push incoming message in state: {}",
                    self.state
                ))
                .into())
            }
        };

        let OpaqueMessage {
            typ,
            version,
            payload,
        } = msg;
        let (explicit_nonce, ciphertext, tag) = opaque_into_parts(payload.0)?;

        debug!(
            "received incoming message, type: {:?}, len: {}",
            typ,
            ciphertext.len()
        );

        let mode = match typ {
            ContentType::ApplicationData => RecordDecryptMode::Private,
            _ => RecordDecryptMode::Public,
        };

        record_layer.push_decrypt(
            typ,
            version,
            explicit_nonce.clone(),
            ciphertext.clone(),
            tag.clone(),
            mode,
        )?;

        ctx.io_mut()
            .send(Message::Decrypt(Decrypt {
                typ,
                version,
                explicit_nonce,
                ciphertext,
                tag,
                mode,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn next_incoming(&mut self) -> Result<Option<PlainMessage>, BackendError> {
        if let Some(record) = self.tls13_incoming.pop_front() {
            debug!(
                "processing incoming message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );

            return Ok(Some(record));
        }

        let record_layer = match &mut self.state {
            State::Handshake { record_layer, .. } => record_layer,
            State::Active { record_layer, .. } => record_layer,
            State::Closed { record_layer, .. } => record_layer,
            _ => {
                return Err(MpcTlsError::state(format!(
                    "can not pull next incoming message in state: {}",
                    self.state
                ))
                .into())
            }
        };

        let record = record_layer.next_decrypted().map(|record| PlainMessage {
            typ: record.typ,
            version: record.version,
            payload: Payload::new(
                record
                    .plaintext
                    .expect("leader should always know plaintext"),
            ),
        });

        if let Some(record) = &record {
            debug!(
                "processing incoming message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );
        }

        Ok(record)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), BackendError> {
        match &mut self.state {
            State::Handshake {
                ctx,
                tls13,
                protocol_version: Some(ProtocolVersion::TLSv1_3),
                ..
            }
            | State::Active {
                ctx,
                tls13,
                protocol_version: ProtocolVersion::TLSv1_3,
                ..
            } => {
                let epoch = self.tls13_encrypt_epoch.ok_or_else(|| {
                    MpcTlsError::hs("tls13 encrypt epoch was not configured before encryption")
                })?;
                let (opaque, record) = tls13.encrypt_record(epoch, msg).map_err(MpcTlsError::hs)?;
                ctx.io_mut()
                    .send(Message::Tls13SendRecord(Tls13RecordMessage {
                        record: record.clone(),
                    }))
                    .await
                    .map_err(MpcTlsError::from)?;
                self.tls13_sent_records.push(record);
                self.tls13_outgoing.push_back(opaque);
                return Ok(());
            }
            _ => {}
        }

        let (ctx, record_layer) = match &mut self.state {
            State::Handshake {
                ctx, record_layer, ..
            } => (ctx, record_layer),
            State::Active {
                ctx, record_layer, ..
            } => (ctx, record_layer),
            _ => {
                return Err(MpcTlsError::state(format!(
                    "can not push outgoing message in state: {}",
                    self.state
                ))
                .into())
            }
        };

        debug!(
            "encrypting outgoing message, type: {:?}, len: {}",
            msg.typ,
            msg.payload.0.len()
        );

        let PlainMessage {
            typ,
            version,
            payload,
        } = msg;
        let plaintext = payload.0;

        let mode = match typ {
            ContentType::ApplicationData => RecordEncryptMode::Private,
            _ => RecordEncryptMode::Public,
        };

        record_layer.push_encrypt(typ, version, plaintext.len(), Some(plaintext.clone()), mode)?;

        ctx.io_mut()
            .send(Message::Encrypt(Encrypt {
                typ,
                version,
                len: plaintext.len(),
                plaintext: match mode {
                    RecordEncryptMode::Private => None,
                    RecordEncryptMode::Public => Some(plaintext),
                },
                mode,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn next_outgoing(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        if let Some(record) = self.tls13_outgoing.pop_front() {
            debug!(
                "sending outgoing message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );

            return Ok(Some(record));
        }

        let record_layer = match &mut self.state {
            State::Handshake { record_layer, .. } => record_layer,
            State::Active { record_layer, .. } => record_layer,
            State::Closed { record_layer, .. } => record_layer,
            _ => {
                return Err(MpcTlsError::state(format!(
                    "can not pull next outgoing message in state: {}",
                    self.state
                ))
                .into())
            }
        };

        let record = record_layer.next_encrypted().map(|record| {
            let mut payload = record.explicit_nonce;
            payload.extend_from_slice(&record.ciphertext);
            payload.extend_from_slice(&record.tag.expect("leader should always know tag"));
            OpaqueMessage {
                typ: record.typ,
                version: record.version,
                payload: Payload::new(payload),
            }
        });

        if let Some(record) = &record {
            debug!(
                "sending outgoing message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );
        }

        Ok(record)
    }

    async fn start_traffic(&mut self) -> Result<(), BackendError> {
        match &mut self.state {
            State::Handshake {
                ctx,
                protocol_version: Some(ProtocolVersion::TLSv1_3),
                ..
            } => {
                ctx.io_mut()
                    .send(Message::StartTraffic)
                    .await
                    .map_err(MpcTlsError::from)?;
            }
            State::Active {
                ctx, record_layer, ..
            } => {
                record_layer.start_traffic();
                ctx.io_mut()
                    .send(Message::StartTraffic)
                    .await
                    .map_err(MpcTlsError::from)?;
            }
            _ => {
                return Err(MpcTlsError::state(format!(
                    "can not start traffic in state: {}",
                    self.state
                ))
                .into())
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn flush(&mut self) -> Result<(), BackendError> {
        let (ctx, vm, record_layer) = match &mut self.state {
            State::Handshake {
                protocol_version: Some(ProtocolVersion::TLSv1_3),
                ..
            } => {
                debug!("tls13 record layer is not ready, skipping flush");
                return Ok(());
            }
            State::Handshake { .. } => {
                warn!("record layer is not ready, skipping flush");
                return Ok(());
            }
            State::Active {
                ctx,
                vm,
                record_layer,
                ..
            } => (ctx, vm, record_layer),
            State::Closed {
                ctx,
                vm,
                record_layer,
                ..
            } => (ctx, vm, record_layer),
            _ => {
                return Err(MpcTlsError::state(format!(
                    "can not flush record layer in state: {}",
                    self.state
                ))
                .into())
            }
        };

        if !record_layer.wants_flush() {
            debug!("record layer is empty, skipping flush");
            return Ok(());
        }

        debug!("flushing record layer");

        ctx.io_mut()
            .send(Message::Flush {
                is_decrypting: self.is_decrypting,
            })
            .await
            .map_err(MpcTlsError::from)?;

        record_layer
            .flush(ctx, vm.clone(), self.is_decrypting)
            .await
            .map_err(BackendError::from)
    }

    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        Ok(self.notifier.get())
    }

    fn is_empty(&self) -> Result<bool, BackendError> {
        let record_layer_empty = match &self.state {
            State::Handshake { record_layer, .. } => record_layer.is_empty(),
            State::Active { record_layer, .. } => record_layer.is_empty(),
            State::Closed { record_layer, .. } => record_layer.is_empty(),
            _ => true,
        };

        Ok(record_layer_empty && self.tls13_incoming.is_empty() && self.tls13_outgoing.is_empty())
    }

    async fn server_closed(&mut self) -> Result<(), BackendError> {
        self.close_connection().await.map_err(BackendError::from)
    }

    fn enable_decryption(&mut self, enable: bool) -> Result<(), BackendError> {
        self.is_decrypting = enable;

        if enable {
            self.notifier.set();
        } else {
            self.notifier.clear();
        }

        Ok(())
    }

    fn finish(&mut self) -> Option<(Context, TlsTranscript)> {
        match self.state.take() {
            State::Closed {
                ctx, transcript, ..
            } => Some((ctx, transcript)),
            state => {
                self.state = state;
                None
            }
        }
    }
}

fn tls13_signature_scheme(
    scheme: tls_core::msgs::enums::SignatureScheme,
) -> Result<SignatureAlgorithm, BackendError> {
    use tls_core::msgs::enums::SignatureScheme as Scheme;

    match scheme {
        Scheme::ECDSA_NISTP256_SHA256 => Ok(SignatureAlgorithm::ECDSA_NISTP256_SHA256),
        Scheme::ECDSA_NISTP384_SHA384 => Ok(SignatureAlgorithm::ECDSA_NISTP384_SHA384),
        Scheme::ED25519 => Ok(SignatureAlgorithm::ED25519),
        Scheme::RSA_PKCS1_SHA256 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256),
        Scheme::RSA_PKCS1_SHA384 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384),
        Scheme::RSA_PKCS1_SHA512 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512),
        Scheme::RSA_PSS_SHA256 => Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        Scheme::RSA_PSS_SHA384 => Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        Scheme::RSA_PSS_SHA512 => Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
        scheme => Err(BackendError::InvalidConfig(format!(
            "unsupported tls13 signature scheme: {scheme:?}"
        ))),
    }
}

enum State {
    Init {
        ctx: Context,
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        tls13: Tls13KeyState,
        record_layer: RecordLayer,
    },
    Setup {
        ctx: Context,
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        tls13: Tls13KeyState,
        record_layer: RecordLayer,
        cf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        client_random: Random,
    },
    Handshake {
        ctx: Context,
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        tls13: Tls13KeyState,
        record_layer: RecordLayer,
        cf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        cf_vd: Option<Vec<u8>>,
        sf_vd: Option<Vec<u8>>,
        time: Option<u64>,
        protocol_version: Option<ProtocolVersion>,
        cipher_suite: Option<CipherSuite>,
        client_random: Random,
        server_random: Option<Random>,
        server_cert_details: Option<ServerCertDetails>,
        server_key: Option<PublicKey>,
        server_kx_details: Option<ServerKxDetails>,
        tls13_server_signature: Option<ServerSignature>,
        tls13_cert_verify_transcript_hash: Option<[u8; 32]>,
    },
    Active {
        ctx: Context,
        vm: Vm,
        _ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        #[allow(dead_code)]
        tls13: Tls13KeyState,
        record_layer: RecordLayer,
        cf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        cf_vd: Option<Vec<u8>>,
        sf_vd: Option<Vec<u8>>,
        time: u64,
        protocol_version: ProtocolVersion,
        client_random: Random,
        server_random: Random,
        server_cert_details: ServerCertDetails,
        server_key: PublicKey,
        server_kx_details: Option<ServerKxDetails>,
        tls13_server_signature: Option<ServerSignature>,
        tls13_cert_verify_transcript_hash: Option<[u8; 32]>,
    },
    Closed {
        ctx: Context,
        vm: Vm,
        record_layer: RecordLayer,
        transcript: TlsTranscript,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init { .. } => f.debug_struct("Init").finish_non_exhaustive(),
            Self::Setup { .. } => f.debug_struct("Setup").finish_non_exhaustive(),
            Self::Handshake { .. } => f.debug_struct("Handshake").finish_non_exhaustive(),
            Self::Active { .. } => f.debug_struct("Active").finish_non_exhaustive(),
            Self::Closed { .. } => f.debug_struct("Closed").finish_non_exhaustive(),
            Self::Error => write!(f, "Error"),
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init { .. } => write!(f, "Init"),
            Self::Setup { .. } => write!(f, "Setup"),
            Self::Handshake { .. } => write!(f, "Handshake"),
            Self::Active { .. } => write!(f, "Active"),
            Self::Closed { .. } => write!(f, "Closed"),
            Self::Error => write!(f, "Error"),
        }
    }
}

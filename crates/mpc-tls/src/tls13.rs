use aes_gcm::{aead::AeadInPlace, Aes128Gcm, NewAead};
use hmac::{Hmac, Mac};
use hmac_sha256::{Mode, Role as KeyScheduleRole, Tls13KeySched};
use mpz_common::Context;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt,
};
use mpz_vm_core::{Execute, Vm as VmTrait};
use sha2::Sha256;
use tls_core::msgs::{
    base::Payload,
    enums::{ContentType, ProtocolVersion},
    message::{OpaqueMessage, PlainMessage},
};
use tlsn_core::transcript::{ContentType as TranscriptContentType, Record};

use crate::{MpcTlsError, Role};

type HmacSha256 = Hmac<Sha256>;

/// TLS 1.3 traffic epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Epoch {
    /// Handshake traffic keys.
    Handshake,
    /// Application traffic keys.
    Application,
}

/// TLS 1.3 handshake traffic keys revealed to the leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tls13HandshakeKeys {
    /// The epoch these keys belong to.
    pub epoch: Epoch,
    /// Client write key.
    pub client_write_key: [u8; 16],
    /// Client write IV.
    pub client_write_iv: [u8; 12],
    /// Client finished key.
    pub client_finished_key: [u8; 32],
    /// Client sequence number.
    pub client_sequence: u64,
    /// Server write key.
    pub server_write_key: [u8; 16],
    /// Server write IV.
    pub server_write_iv: [u8; 12],
    /// Server finished key.
    pub server_finished_key: [u8; 32],
    /// Server sequence number.
    pub server_sequence: u64,
}

/// TLS 1.3 application traffic keys kept secret-shared.
#[derive(Debug, Clone)]
pub struct Tls13ApplicationKeys {
    /// The epoch these keys belong to.
    pub epoch: Epoch,
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Client write IV.
    pub client_write_iv: Array<U8, 12>,
    /// Client sequence number.
    pub client_sequence: u64,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Server write IV.
    pub server_write_iv: Array<U8, 12>,
    /// Server sequence number.
    pub server_sequence: u64,
}

/// TLS 1.3 session key material tracked by MPC-TLS.
#[derive(Debug, Clone, Default)]
pub struct Tls13SessionKeys {
    /// Handshake traffic keys revealed to the leader after `ServerHello`.
    pub handshake: Option<Tls13HandshakeKeys>,
    /// Application traffic keys retained in MPC form.
    pub application: Option<Tls13ApplicationKeys>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tls13ClearApplicationKeys {
    client_write_key: [u8; 16],
    client_write_iv: [u8; 12],
    client_sequence: u64,
    server_write_key: [u8; 16],
    server_write_iv: [u8; 12],
    server_sequence: u64,
}

pub(crate) struct Tls13KeyState {
    inner: Tls13KeySched,
    keys: Tls13SessionKeys,
    clear_application: Option<Tls13ClearApplicationKeys>,
}

impl Tls13KeyState {
    pub(crate) fn new(mode: Mode, role: Role) -> Self {
        let role = match role {
            Role::Leader => KeyScheduleRole::Leader,
            Role::Follower => KeyScheduleRole::Follower,
        };

        Self {
            inner: Tls13KeySched::new(mode, role),
            keys: Tls13SessionKeys::default(),
            clear_application: None,
        }
    }

    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn VmTrait<Binary>,
        pms: Array<U8, 32>,
    ) -> Result<(), MpcTlsError> {
        self.inner.alloc(vm, pms).map_err(MpcTlsError::from)
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
                epoch: Epoch::Handshake,
                client_write_key: keys.client_write_key,
                client_write_iv: keys.client_iv,
                client_finished_key: keys.client_finished_key,
                client_sequence: 0,
                server_write_key: keys.server_write_key,
                server_write_iv: keys.server_iv,
                server_finished_key: keys.server_finished_key,
                server_sequence: 0,
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

        let keys = self.inner.application_keys()?;
        let mut client_key = vm.decode(keys.client_write_key).map_err(MpcTlsError::hs)?;
        let mut client_iv = vm.decode(keys.client_iv).map_err(MpcTlsError::hs)?;
        let mut server_key = vm.decode(keys.server_write_key).map_err(MpcTlsError::hs)?;
        let mut server_iv = vm.decode(keys.server_iv).map_err(MpcTlsError::hs)?;

        Execute::execute_all(vm, ctx)
            .await
            .map_err(MpcTlsError::hs)?;

        self.keys.application = Some(Tls13ApplicationKeys {
            epoch: Epoch::Application,
            client_write_key: keys.client_write_key,
            client_write_iv: keys.client_iv,
            client_sequence: 0,
            server_write_key: keys.server_write_key,
            server_write_iv: keys.server_iv,
            server_sequence: 0,
        });
        self.clear_application = Some(Tls13ClearApplicationKeys {
            client_write_key: client_key
                .try_recv()
                .map_err(MpcTlsError::hs)?
                .ok_or_else(|| MpcTlsError::hs("tls13 client application key not decoded"))?,
            client_write_iv: client_iv
                .try_recv()
                .map_err(MpcTlsError::hs)?
                .ok_or_else(|| MpcTlsError::hs("tls13 client application iv not decoded"))?,
            client_sequence: 0,
            server_write_key: server_key
                .try_recv()
                .map_err(MpcTlsError::hs)?
                .ok_or_else(|| MpcTlsError::hs("tls13 server application key not decoded"))?,
            server_write_iv: server_iv
                .try_recv()
                .map_err(MpcTlsError::hs)?
                .ok_or_else(|| MpcTlsError::hs("tls13 server application iv not decoded"))?,
            server_sequence: 0,
        });

        Ok(())
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
                let keys = self
                    .keys
                    .handshake
                    .as_mut()
                    .ok_or_else(|| MpcTlsError::hs("tls13 handshake keys are not available"))?;

                encrypt_tls13_record(
                    keys.client_write_key,
                    keys.client_write_iv,
                    &mut keys.client_sequence,
                    msg,
                )
            }
            Epoch::Application => {
                let keys = self
                    .clear_application
                    .as_mut()
                    .ok_or_else(|| MpcTlsError::hs("tls13 application keys are not available"))?;

                encrypt_tls13_record(
                    keys.client_write_key,
                    keys.client_write_iv,
                    &mut keys.client_sequence,
                    msg,
                )
            }
        }
    }

    pub(crate) fn decrypt_record(
        &mut self,
        epoch: Epoch,
        msg: OpaqueMessage,
    ) -> Result<(PlainMessage, Record), MpcTlsError> {
        match epoch {
            Epoch::Handshake => {
                let keys = self
                    .keys
                    .handshake
                    .as_mut()
                    .ok_or_else(|| MpcTlsError::hs("tls13 handshake keys are not available"))?;

                decrypt_tls13_record(
                    keys.server_write_key,
                    keys.server_write_iv,
                    &mut keys.server_sequence,
                    msg,
                )
            }
            Epoch::Application => {
                let keys = self
                    .clear_application
                    .as_mut()
                    .ok_or_else(|| MpcTlsError::hs("tls13 application keys are not available"))?;

                decrypt_tls13_record(
                    keys.server_write_key,
                    keys.server_write_iv,
                    &mut keys.server_sequence,
                    msg,
                )
            }
        }
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
    key: [u8; 16],
    iv: [u8; 12],
    sequence: &mut u64,
    msg: PlainMessage,
) -> Result<(OpaqueMessage, Record), MpcTlsError> {
    let seq = *sequence;
    let typ = msg.typ;
    let plaintext = msg.payload.0;
    let mut payload = plaintext.clone();
    payload.push(typ.get_u8());

    let total_len = payload.len() + 16;
    let aad = make_tls13_aad(total_len);
    let nonce = make_tls13_nonce(iv, seq);
    *sequence = sequence
        .checked_add(1)
        .ok_or_else(|| MpcTlsError::hs("tls13 write sequence overflow"))?;

    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|_| MpcTlsError::hs("tls13 aes-gcm key initialization failed"))?;
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
    key: [u8; 16],
    iv: [u8; 12],
    sequence: &mut u64,
    msg: OpaqueMessage,
) -> Result<(PlainMessage, Record), MpcTlsError> {
    if msg.typ != ContentType::ApplicationData || msg.version != ProtocolVersion::TLSv1_2 {
        return Err(MpcTlsError::hs("unexpected TLS 1.3 record header"));
    }

    let seq = *sequence;
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
    let nonce = make_tls13_nonce(iv, seq);
    *sequence = sequence
        .checked_add(1)
        .ok_or_else(|| MpcTlsError::hs("tls13 read sequence overflow"))?;

    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|_| MpcTlsError::hs("tls13 aes-gcm key initialization failed"))?;
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

#[cfg(test)]
mod tests {
    use super::{decrypt_tls13_record, encrypt_tls13_record, Tls13KeyState};
    use crate::{Epoch, Role};
    use hmac_sha256::Mode;
    use mpz_common::{context::test_st_context, Context};
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_memory_core::correlated::Delta;
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::{
        memory::{binary::Binary, Array, MemoryExt, ViewExt},
        Execute, Vm,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use tls_core::msgs::{
        base::Payload,
        enums::{ContentType, ProtocolVersion},
        message::PlainMessage,
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
        state.set_handshake_hash(ctx, vm, handshake_hash).await?;

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
            .expect("leader should learn handshake keys");
        assert_eq!(handshake.epoch, Epoch::Handshake);
        assert_eq!(handshake.client_write_key, ckey_hs);
        assert_eq!(handshake.client_write_iv, civ_hs);
        assert_eq!(handshake.server_write_key, skey_hs);
        assert_eq!(handshake.server_write_iv, siv_hs);
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

        let mut leader_ckey = leader_vm.decode(leader_keys.client_write_key).unwrap();
        let mut leader_civ = leader_vm.decode(leader_keys.client_write_iv).unwrap();
        let mut leader_skey = leader_vm.decode(leader_keys.server_write_key).unwrap();
        let mut leader_siv = leader_vm.decode(leader_keys.server_write_iv).unwrap();
        let mut follower_ckey = follower_vm.decode(follower_keys.client_write_key).unwrap();
        let mut follower_civ = follower_vm.decode(follower_keys.client_write_iv).unwrap();
        let mut follower_skey = follower_vm.decode(follower_keys.server_write_key).unwrap();
        let mut follower_siv = follower_vm.decode(follower_keys.server_write_iv).unwrap();

        tokio::try_join!(
            leader_vm.execute_all(&mut ctx_a),
            follower_vm.execute_all(&mut ctx_b)
        )
        .unwrap();

        assert_eq!(leader_keys.epoch, Epoch::Application);
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
    fn tls13_record_roundtrip_preserves_inner_type() {
        let key = from_hex_str("88 b9 6a d6 86 c8 4b e5 5a ce 18 a5 9c ce 5c 87");
        let iv = from_hex_str("b9 9d c5 8c d5 ff 5a b0 82 fd ad 19");
        let plain = PlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: Payload::new(b"hello tls13".to_vec()),
        };

        let mut write_seq = 0;
        let (encrypted, record) =
            encrypt_tls13_record(key, iv, &mut write_seq, plain.clone()).unwrap();
        assert_eq!(encrypted.typ, ContentType::ApplicationData);
        assert_eq!(encrypted.version, ProtocolVersion::TLSv1_2);
        assert_eq!(record.typ, TranscriptContentType::ApplicationData);

        let mut read_seq = 0;
        let (decrypted, decrypted_record) =
            decrypt_tls13_record(key, iv, &mut read_seq, encrypted).unwrap();
        assert_eq!(decrypted.typ, plain.typ);
        assert_eq!(decrypted.version, ProtocolVersion::TLSv1_3);
        assert_eq!(decrypted.payload.0, plain.payload.0);
        assert_eq!(decrypted_record.typ, TranscriptContentType::ApplicationData);
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

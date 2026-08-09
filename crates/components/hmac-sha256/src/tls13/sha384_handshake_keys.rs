//! Typed secret-shared SHA-384 TLS 1.3 handshake key material.

use mpz_vm_core::{memory::{binary::{Binary, U8}, Array, Vector}, prelude::MemoryExt, Vm};
use crate::FError;
use super::{hkdf384::{HkdfExpand384, EMPTY_HASH_SHA384, zero_hash}, hkdf_extract384::HkdfExtract384};
use crate::Mode;

/// SHA-384 handshake traffic keys, IVs, and Finished keys.
#[derive(Debug)]
pub struct Sha384HandshakeKeys {
    client_traffic: HkdfExpand384,
    server_traffic: HkdfExpand384,
    client_key: HkdfExpand384,
    client_iv: HkdfExpand384,
    client_finished: HkdfExpand384,
    server_key: HkdfExpand384,
    server_iv: HkdfExpand384,
    server_finished: HkdfExpand384,
}

impl Sha384HandshakeKeys {
    /// Allocates the TLS 1.3 no-PSK SHA-384 schedule from a shared ECDHE
    /// secret. This performs `early_secret`, `derived_secret`, and
    /// `handshake_secret` before expanding the traffic keys.
    pub fn alloc_from_shared_secret(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        shared_secret: Array<U8, 32>,
        transcript_hash: &[u8; 48],
    ) -> Result<Self, FError> {
        let empty_salt = vm.alloc_vec(0).map_err(FError::vm)?;
        let empty_ikm = zero_hash(vm)?;
        let early = HkdfExtract384::alloc(mode, vm, empty_salt, &[empty_ikm])?;
        let mut derived = HkdfExpand384::alloc(vm, early.output().into(), b"derived", 48, 48)?;
        derived.set_context(vm, &EMPTY_HASH_SHA384)?;
        let handshake = HkdfExtract384::alloc(
            mode,
            vm,
            derived.output()?.into(),
            &[shared_secret.into()],
        )?;
        let mut keys = Self::alloc_deferred(vm, handshake.output().into())?;
        keys.set_transcript(vm, transcript_hash)?;
        Ok(keys)
    }

    /// Preallocates the no-PSK schedule before the ServerHello transcript is
    /// available.
    pub fn alloc_from_shared_secret_deferred(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        shared_secret: Array<U8, 32>,
    ) -> Result<Self, FError> {
        let empty_salt = vm.alloc_vec(0).map_err(FError::vm)?;
        let empty_ikm = zero_hash(vm)?;
        let early = HkdfExtract384::alloc(mode, vm, empty_salt, &[empty_ikm])?;
        let mut derived = HkdfExpand384::alloc(vm, early.output().into(), b"derived", 48, 48)?;
        derived.set_context(vm, &EMPTY_HASH_SHA384)?;
        let handshake = HkdfExtract384::alloc(
            mode,
            vm,
            derived.output()?.into(),
            &[shared_secret.into()],
        )?;
        Self::alloc_deferred(vm, handshake.output().into())
    }

    /// Allocates handshake material from a secret-shared handshake secret.
    pub fn alloc(
        vm: &mut dyn Vm<Binary>,
        handshake_secret: Vector<U8>,
        transcript_hash: &[u8; 48],
    ) -> Result<Self, FError> {
        let mut keys = Self::alloc_deferred(vm, handshake_secret)?;
        keys.set_transcript(vm, transcript_hash)?;
        Ok(keys)
    }

    fn alloc_deferred(
        vm: &mut dyn Vm<Binary>,
        handshake_secret: Vector<U8>,
    ) -> Result<Self, FError> {
        let client_traffic = HkdfExpand384::alloc(vm, handshake_secret, b"c hs traffic", 48, 48)?;
        let server_traffic = HkdfExpand384::alloc(vm, handshake_secret, b"s hs traffic", 48, 48)?;
        let client_key = HkdfExpand384::alloc(vm, client_traffic.output()?.into(), b"key", 32, 0)?;
        let client_iv = HkdfExpand384::alloc(vm, client_traffic.output()?.into(), b"iv", 12, 0)?;
        let client_finished = HkdfExpand384::alloc(vm, client_traffic.output()?.into(), b"finished", 48, 0)?;
        let server_key = HkdfExpand384::alloc(vm, server_traffic.output()?.into(), b"key", 32, 0)?;
        let server_iv = HkdfExpand384::alloc(vm, server_traffic.output()?.into(), b"iv", 12, 0)?;
        let server_finished = HkdfExpand384::alloc(vm, server_traffic.output()?.into(), b"finished", 48, 0)?;
        Ok(Self { client_traffic, server_traffic, client_key, client_iv, client_finished, server_key, server_iv, server_finished })
    }

    /// Assigns the public ServerHello transcript to the preallocated traffic
    /// secret expansions.
    pub fn set_transcript(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        transcript_hash: &[u8; 48],
    ) -> Result<(), FError> {
        self.client_traffic.set_context(vm, transcript_hash)?;
        self.server_traffic.set_context(vm, transcript_hash)?;
        Ok(())
    }

    /// Allocates empty contexts for all handshake labels.
    pub fn set_context(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        self.client_key.set_context(vm, &[])?;
        self.client_iv.set_context(vm, &[])?;
        self.client_finished.set_context(vm, &[])?;
        self.server_key.set_context(vm, &[])?;
        self.server_iv.set_context(vm, &[])?;
        self.server_finished.set_context(vm, &[])?;
        Ok(())
    }

    /// Returns the client handshake key view.
    pub fn client_key(&self) -> Result<Array<U8, 32>, FError> { self.client_key.output_view() }
    /// Returns the client handshake IV view.
    pub fn client_iv(&self) -> Result<Array<U8, 12>, FError> { self.client_iv.output_view() }
    /// Returns the client Finished-key view.
    pub fn client_finished(&self) -> Result<Array<U8, 48>, FError> { self.client_finished.output_view() }
    /// Returns the server handshake key view.
    pub fn server_key(&self) -> Result<Array<U8, 32>, FError> { self.server_key.output_view() }
    /// Returns the server handshake IV view.
    pub fn server_iv(&self) -> Result<Array<U8, 12>, FError> { self.server_iv.output_view() }
    /// Returns the server Finished-key view.
    pub fn server_finished(&self) -> Result<Array<U8, 48>, FError> { self.server_finished.output_view() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::mock_vm, tls13::sha384_reference::{hkdf_expand_label_sha384, hkdf_extract_sha384}};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{memory::MemoryExt, prelude::ViewExt, Execute};

    #[tokio::test]
    async fn handshake_keys_match_reference() {
        let secret = [0x33u8; 48];
        let transcript = [0x44u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();
        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let secret_ref = vm.alloc_vec(secret.len()).unwrap();
            vm.mark_public(secret_ref).unwrap();
            vm.assign(secret_ref, secret.to_vec()).unwrap();
            vm.commit(secret_ref).unwrap();
            let mut keys = Sha384HandshakeKeys::alloc(vm, secret_ref, &transcript).unwrap();
            keys.set_context(vm).unwrap();
            (
                vm.decode(keys.client_key().unwrap()).unwrap(),
                vm.decode(keys.client_iv().unwrap()).unwrap(),
                vm.decode(keys.client_finished().unwrap()).unwrap(),
            )
        };
        let (mut lk, mut li, mut lf) = run(&mut leader);
        let (mut fk, mut fi, mut ff) = run(&mut follower);
        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let key = lk.try_recv().unwrap().unwrap();
        let iv = li.try_recv().unwrap().unwrap();
        let finished = lf.try_recv().unwrap().unwrap();
        assert_eq!(key, fk.try_recv().unwrap().unwrap());
        assert_eq!(iv, fi.try_recv().unwrap().unwrap());
        assert_eq!(finished, ff.try_recv().unwrap().unwrap());
        let traffic = hkdf_expand_label_sha384(&secret, b"c hs traffic", &transcript, 48);
        assert_eq!(key.to_vec(), hkdf_expand_label_sha384(&traffic, b"key", &[], 32));
        assert_eq!(iv.to_vec(), hkdf_expand_label_sha384(&traffic, b"iv", &[], 12));
        assert_eq!(finished.to_vec(), hkdf_expand_label_sha384(&traffic, b"finished", &[], 48));
    }

    #[tokio::test]
    async fn handshake_schedule_from_shared_secret_matches_tls13_reference() {
        let pms = [0x21u8; 32];
        let transcript = [0x42u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();
        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let pms_ref = vm.alloc().unwrap();
            vm.mark_public(pms_ref).unwrap();
            vm.assign(pms_ref, pms).unwrap();
            vm.commit(pms_ref).unwrap();
            let mut keys = Sha384HandshakeKeys::alloc_from_shared_secret(
                crate::Mode::Normal,
                vm,
                pms_ref,
                &transcript,
            ).unwrap();
            keys.set_context(vm).unwrap();
            vm.decode(keys.client_key().unwrap()).unwrap()
        };
        let mut left = run(&mut leader);
        let mut right = run(&mut follower);
        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let actual = left.try_recv().unwrap().unwrap();
        assert_eq!(actual, right.try_recv().unwrap().unwrap());
        let early = hkdf_extract_sha384(&[], &[0u8; 48]);
        let derived = hkdf_expand_label_sha384(&early, b"derived", &EMPTY_HASH_SHA384, 48);
        let handshake = hkdf_extract_sha384(&derived, &pms);
        let traffic = hkdf_expand_label_sha384(&handshake, b"c hs traffic", &transcript, 48);
        assert_eq!(actual.to_vec(), hkdf_expand_label_sha384(&traffic, b"key", &[], 32));
    }
}

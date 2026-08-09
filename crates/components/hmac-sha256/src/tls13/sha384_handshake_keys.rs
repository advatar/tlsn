//! Typed secret-shared SHA-384 TLS 1.3 handshake key material.

use mpz_vm_core::{memory::{binary::{Binary, U8}, Array, Vector}, Vm};
use crate::FError;
use super::hkdf384::HkdfExpand384;

/// SHA-384 handshake traffic keys, IVs, and Finished keys.
#[derive(Debug)]
pub(crate) struct Sha384HandshakeKeys {
    client_key: HkdfExpand384,
    client_iv: HkdfExpand384,
    client_finished: HkdfExpand384,
    server_key: HkdfExpand384,
    server_iv: HkdfExpand384,
    server_finished: HkdfExpand384,
}

impl Sha384HandshakeKeys {
    /// Allocates handshake material from a secret-shared handshake secret.
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        handshake_secret: Vector<U8>,
        transcript_hash: &[u8; 48],
    ) -> Result<Self, FError> {
        let mut client_traffic = HkdfExpand384::alloc(vm, handshake_secret, b"c hs traffic", 48)?;
        let mut server_traffic = HkdfExpand384::alloc(vm, handshake_secret, b"s hs traffic", 48)?;
        client_traffic.set_context(vm, transcript_hash)?;
        server_traffic.set_context(vm, transcript_hash)?;
        let client_key = HkdfExpand384::alloc(vm, client_traffic.output()?.into(), b"key", 32)?;
        let client_iv = HkdfExpand384::alloc(vm, client_traffic.output()?.into(), b"iv", 12)?;
        let client_finished = HkdfExpand384::alloc(vm, client_traffic.output()?.into(), b"finished", 48)?;
        let server_key = HkdfExpand384::alloc(vm, server_traffic.output()?.into(), b"key", 32)?;
        let server_iv = HkdfExpand384::alloc(vm, server_traffic.output()?.into(), b"iv", 12)?;
        let server_finished = HkdfExpand384::alloc(vm, server_traffic.output()?.into(), b"finished", 48)?;
        Ok(Self { client_key, client_iv, client_finished, server_key, server_iv, server_finished })
    }

    /// Allocates empty contexts for all handshake labels.
    pub(crate) fn set_context(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        self.client_key.set_context(vm, &[])?;
        self.client_iv.set_context(vm, &[])?;
        self.client_finished.set_context(vm, &[])?;
        self.server_key.set_context(vm, &[])?;
        self.server_iv.set_context(vm, &[])?;
        self.server_finished.set_context(vm, &[])?;
        Ok(())
    }

    pub(crate) fn client_key(&self) -> Result<Array<U8, 32>, FError> { self.client_key.output_view() }
    pub(crate) fn client_iv(&self) -> Result<Array<U8, 12>, FError> { self.client_iv.output_view() }
    pub(crate) fn client_finished(&self) -> Result<Array<U8, 48>, FError> { self.client_finished.output_view() }
    pub(crate) fn server_key(&self) -> Result<Array<U8, 32>, FError> { self.server_key.output_view() }
    pub(crate) fn server_iv(&self) -> Result<Array<U8, 12>, FError> { self.server_iv.output_view() }
    pub(crate) fn server_finished(&self) -> Result<Array<U8, 48>, FError> { self.server_finished.output_view() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::mock_vm, tls13::sha384_reference::hkdf_expand_label_sha384};
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
}

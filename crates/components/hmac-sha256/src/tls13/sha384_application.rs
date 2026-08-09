//! Secret-shared SHA-384 TLS 1.3 application traffic key derivation.

use mpz_vm_core::{memory::{binary::{Binary, U8}, Array, Vector}, prelude::MemoryExt, Vm};
use crate::FError;
use super::hkdf384::HkdfExpand384;
use super::hkdf_extract384::HkdfExtract384;
use crate::Mode;

/// Secret-shared TLS 1.3 application key material for SHA-384 suites.
#[derive(Debug)]
pub struct Sha384ApplicationKeys {
    client_secret: HkdfExpand384,
    server_secret: HkdfExpand384,
    client_key: HkdfExpand384,
    client_iv: HkdfExpand384,
    server_key: HkdfExpand384,
    server_iv: HkdfExpand384,
}

impl Sha384ApplicationKeys {
    /// Allocates the complete no-PSK TLS 1.3 SHA-384 schedule from shared
    /// ECDHE input, including the post-handshake application master secret.
    pub fn alloc_from_shared_secret(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        shared_secret: Array<U8, 32>,
        transcript_hash: &[u8; 48],
    ) -> Result<Self, crate::FError> {
        let empty = vm.alloc_vec(0).map_err(crate::FError::vm)?;
        let empty_ikm = vm.alloc_vec(0).map_err(crate::FError::vm)?;
        let early = HkdfExtract384::alloc(mode, vm, empty, &[empty_ikm])?;
        let mut derived = HkdfExpand384::alloc(vm, early.output().into(), b"derived", 48)?;
        derived.set_context(vm, &[])?;
        let handshake = HkdfExtract384::alloc(mode, vm, derived.output()?.into(), &[shared_secret.into()])?;
        let mut handshake_derived = HkdfExpand384::alloc(vm, handshake.output().into(), b"derived", 48)?;
        handshake_derived.set_context(vm, &[])?;
        let empty_ikm = vm.alloc_vec(0).map_err(crate::FError::vm)?;
        let master = HkdfExtract384::alloc(mode, vm, handshake_derived.output()?.into(), &[empty_ikm])?;
        Self::alloc(vm, master.output().into(), transcript_hash)
    }

    /// Allocates application traffic secrets and typed AES-256 key/IV views.
    pub fn alloc(
        vm: &mut dyn Vm<Binary>,
        master_secret: Vector<U8>,
        transcript_hash: &[u8; 48],
    ) -> Result<Self, FError> {
        let client_secret = HkdfExpand384::alloc(vm, master_secret, b"c ap traffic", 48)?;
        let server_secret = HkdfExpand384::alloc(vm, master_secret, b"s ap traffic", 48)?;
        let mut client_secret = client_secret;
        let mut server_secret = server_secret;
        client_secret.set_context(vm, transcript_hash)?;
        server_secret.set_context(vm, transcript_hash)?;
        let client_key = HkdfExpand384::alloc(vm, client_secret.output()?.into(), b"key", 32)?;
        let client_iv = HkdfExpand384::alloc(vm, client_secret.output()?.into(), b"iv", 12)?;
        let server_key = HkdfExpand384::alloc(vm, server_secret.output()?.into(), b"key", 32)?;
        let server_iv = HkdfExpand384::alloc(vm, server_secret.output()?.into(), b"iv", 12)?;
        Ok(Self { client_secret, server_secret, client_key, client_iv, server_key, server_iv })
    }

    /// Completes allocation of the key and IV expansions in the VM.
    pub fn set_context(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        self.client_key.set_context(vm, &[])?;
        self.client_iv.set_context(vm, &[])?;
        self.server_key.set_context(vm, &[])?;
        self.server_iv.set_context(vm, &[])?;
        Ok(())
    }

    /// Returns the secret-shared client write key view.
    pub fn client_key(&self) -> Result<Array<U8, 32>, FError> { self.client_key.output_view() }
    /// Returns the secret-shared client write IV view.
    pub fn client_iv(&self) -> Result<Array<U8, 12>, FError> { self.client_iv.output_view() }
    /// Returns the secret-shared server write key view.
    pub fn server_key(&self) -> Result<Array<U8, 32>, FError> { self.server_key.output_view() }
    /// Returns the secret-shared server write IV view.
    pub fn server_iv(&self) -> Result<Array<U8, 12>, FError> { self.server_iv.output_view() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::mock_vm, tls13::sha384_reference::hkdf_expand_label_sha384};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{memory::MemoryExt, prelude::ViewExt, Execute};

    #[tokio::test]
    async fn application_keys_match_sha384_reference() {
        let master = [0x33u8; 48];
        let transcript = [0x44u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();
        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let master_ref = vm.alloc_vec(master.len()).unwrap();
            vm.mark_public(master_ref).unwrap();
            vm.assign(master_ref, master.to_vec()).unwrap();
            vm.commit(master_ref).unwrap();
            let mut keys = Sha384ApplicationKeys::alloc(vm, master_ref, &transcript).unwrap();
            keys.set_context(vm).unwrap();
            (
                vm.decode(keys.client_key().unwrap()).unwrap(),
                vm.decode(keys.client_iv().unwrap()).unwrap(),
                vm.decode(keys.server_key().unwrap()).unwrap(),
                vm.decode(keys.server_iv().unwrap()).unwrap(),
            )
        };
        let (mut lck, mut lci, mut lsk, mut lsi) = run(&mut leader);
        let (mut fck, mut fci, mut fsk, mut fsi) = run(&mut follower);
        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let ck = lck.try_recv().unwrap().unwrap();
        let ci = lci.try_recv().unwrap().unwrap();
        let sk = lsk.try_recv().unwrap().unwrap();
        let si = lsi.try_recv().unwrap().unwrap();
        assert_eq!(ck, fck.try_recv().unwrap().unwrap());
        assert_eq!(ci, fci.try_recv().unwrap().unwrap());
        assert_eq!(sk, fsk.try_recv().unwrap().unwrap());
        assert_eq!(si, fsi.try_recv().unwrap().unwrap());
        let client_secret = hkdf_expand_label_sha384(&master, b"c ap traffic", &transcript, 48);
        let server_secret = hkdf_expand_label_sha384(&master, b"s ap traffic", &transcript, 48);
        assert_eq!(ck.to_vec(), hkdf_expand_label_sha384(&client_secret, b"key", &[], 32));
        assert_eq!(ci.to_vec(), hkdf_expand_label_sha384(&client_secret, b"iv", &[], 12));
        assert_eq!(sk.to_vec(), hkdf_expand_label_sha384(&server_secret, b"key", &[], 32));
        assert_eq!(si.to_vec(), hkdf_expand_label_sha384(&server_secret, b"iv", &[], 12));
    }
}

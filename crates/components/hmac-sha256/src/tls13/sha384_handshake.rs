//! Secret-shared SHA-384 TLS 1.3 handshake-traffic derivation.

use mpz_vm_core::{memory::{binary::{Binary, U8}, Vector}, Vm};

use crate::{FError, Mode};
use super::{hkdf384::HkdfExpand384, hkdf_extract384::HkdfExtract384};

/// The two SHA-384 handshake traffic secrets.
#[derive(Debug)]
pub(crate) struct Sha384HandshakeTraffic {
    pub(crate) client: HkdfExpand384,
    pub(crate) server: HkdfExpand384,
}

impl Sha384HandshakeTraffic {
    /// Allocates the SHA-384 handshake traffic expansions from hybrid IKM.
    pub(crate) fn alloc(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        zero_salt: Vector<U8>,
        ikm: &[Vector<U8>],
    ) -> Result<Self, FError> {
        let handshake_secret = HkdfExtract384::alloc(mode, vm, zero_salt, ikm)?;
        let secret: Vector<U8> = handshake_secret.output().into();
        Ok(Self {
            client: HkdfExpand384::alloc(vm, secret, b"c hs traffic", 48)?,
            server: HkdfExpand384::alloc(vm, secret, b"s hs traffic", 48)?,
        })
    }

    /// Sets the public transcript hash context on both traffic expansions.
    pub(crate) fn set_transcript_hash(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        transcript_hash: &[u8; 48],
    ) -> Result<(), FError> {
        self.client.set_context(vm, transcript_hash)?;
        self.server.set_context(vm, transcript_hash)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::mock_vm, tls13::sha384_reference::{hkdf_expand_label_sha384, hkdf_extract_sha384}};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{memory::MemoryExt, prelude::ViewExt, Execute};

    #[tokio::test]
    async fn handshake_traffic_matches_sha384_reference() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        let transcript = [0x44u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let salt = vm.alloc_vec(0).unwrap();
            let mut refs = Vec::new();
            for part in [first, second] {
                let r = vm.alloc_vec(part.len()).unwrap();
                vm.mark_public(r).unwrap();
                vm.assign(r, part.to_vec()).unwrap();
                vm.commit(r).unwrap();
                refs.push(r);
            }
            let mut traffic = Sha384HandshakeTraffic::alloc(Mode::Normal, vm, salt, &refs).unwrap();
            traffic.set_transcript_hash(vm, &transcript).unwrap();
            (vm.decode(traffic.client.output().unwrap()).unwrap(), vm.decode(traffic.server.output().unwrap()).unwrap())
        };

        let (mut lc, mut ls) = run(&mut leader);
        let (mut fc, mut fs) = run(&mut follower);
        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let client = lc.try_recv().unwrap().unwrap();
        let server = ls.try_recv().unwrap().unwrap();
        assert_eq!(client, fc.try_recv().unwrap().unwrap());
        assert_eq!(server, fs.try_recv().unwrap().unwrap());
        let mut ikm = first.to_vec();
        ikm.extend_from_slice(&second);
        let hs = hkdf_extract_sha384(&[], &ikm);
        assert_eq!(client.to_vec(), hkdf_expand_label_sha384(&hs, b"c hs traffic", &transcript, 48));
        assert_eq!(server.to_vec(), hkdf_expand_label_sha384(&hs, b"s hs traffic", &transcript, 48));
    }
}

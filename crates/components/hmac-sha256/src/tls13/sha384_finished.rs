//! Secret-shared SHA-384 TLS 1.3 Finished computation.

use mpz_vm_core::{memory::{binary::{Binary, U8}, Array, Vector}, Vm};
use crate::{FError, Mode};
use super::{hkdf384::HkdfExpand384, hmac384::hmac_sha384_message};

/// Allocates a SHA-384 Finished MAC over a public transcript hash.
pub(crate) fn finished_sha384(
    _mode: Mode,
    vm: &mut dyn Vm<Binary>,
    traffic_secret: Vector<U8>,
    transcript_hash: Vector<U8>,
) -> Result<Array<U8, 48>, FError> {
    let mut finished = HkdfExpand384::alloc(vm, traffic_secret, b"finished", 48)?;
    finished.set_context(vm, &[])?;
    hmac_sha384_message(vm, finished.output()?.into(), &[transcript_hash])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::mock_vm, tls13::sha384_reference::{hkdf_expand_label_sha384, hkdf_extract_sha384}};
    use hmac::{Hmac, Mac};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{memory::MemoryExt, prelude::ViewExt, Execute};
    use sha2::Sha384;

    #[tokio::test]
    async fn finished_sha384_matches_reference() {
        let ikm = [0x11u8; 64];
        let transcript = [0x44u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();
        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let salt = vm.alloc_vec(0).unwrap();
            let ikm_ref = vm.alloc_vec(ikm.len()).unwrap();
            vm.mark_public(ikm_ref).unwrap();
            vm.assign(ikm_ref, ikm.to_vec()).unwrap();
            vm.commit(ikm_ref).unwrap();
            let transcript_ref = vm.alloc_vec(transcript.len()).unwrap();
            vm.mark_public(transcript_ref).unwrap();
            vm.assign(transcript_ref, transcript.to_vec()).unwrap();
            vm.commit(transcript_ref).unwrap();
            let hs = super::super::hkdf_extract384::HkdfExtract384::alloc(Mode::Normal, vm, salt, &[ikm_ref]).unwrap();
            finished_sha384(Mode::Normal, vm, hs.output().into(), transcript_ref).unwrap()
        };
        let mut lo = { let r = run(&mut leader); leader.decode(r).unwrap() };
        let mut fo = { let r = run(&mut follower); follower.decode(r).unwrap() };
        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let actual = lo.try_recv().unwrap().unwrap();
        assert_eq!(actual, fo.try_recv().unwrap().unwrap());
        let hs = hkdf_extract_sha384(&[], &ikm);
        let fk = hkdf_expand_label_sha384(&hs, b"finished", &[], 48);
        let mut mac = Hmac::<Sha384>::new_from_slice(&fk).unwrap();
        mac.update(&transcript);
        assert_eq!(actual.to_vec(), mac.finalize().into_bytes().to_vec());
    }
}

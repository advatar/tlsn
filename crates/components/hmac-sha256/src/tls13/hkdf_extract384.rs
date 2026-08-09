//! Secret-shared SHA-384 HKDF-Extract.

use mpz_vm_core::{
    memory::{binary::{Binary, U8}, Array, Vector},
    Vm,
};

use crate::{FError, Mode};
use super::hmac384::hmac_sha384_message;

/// HKDF-Extract using HMAC-SHA384 and one or more secret-shared IKM vectors.
#[derive(Debug)]
pub(crate) struct HkdfExtract384 {
    output: Array<U8, 48>,
    complete: bool,
    _mode: Mode,
}

impl HkdfExtract384 {
    /// Allocates HKDF-Extract with a secret-shared salt and IKM.
    pub(crate) fn alloc(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        salt: Vector<U8>,
        ikm: &[Vector<U8>],
    ) -> Result<Self, FError> {
        let output = hmac_sha384_message(vm, salt, ikm)?;
        Ok(Self { output, complete: false, _mode: mode })
    }

    pub(crate) fn output(&self) -> Array<U8, 48> { self.output }

    pub(crate) fn flush(&mut self, _vm: &mut dyn Vm<Binary>) { self.complete = true; }

    pub(crate) fn is_complete(&self) -> bool { self.complete }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::mock_vm, tls13::sha384_reference::hkdf_extract_sha384};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{memory::MemoryExt, prelude::ViewExt, Execute};

    #[tokio::test]
    async fn sha384_extract_matches_reference_for_hybrid_ikm() {
        let salt = [0x55u8; 48];
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let salt_ref = vm.alloc_vec(salt.len()).unwrap();
            vm.mark_public(salt_ref).unwrap();
            vm.assign(salt_ref, salt.to_vec()).unwrap();
            vm.commit(salt_ref).unwrap();
            let first_ref = vm.alloc_vec(first.len()).unwrap();
            vm.mark_public(first_ref).unwrap();
            vm.assign(first_ref, first.to_vec()).unwrap();
            vm.commit(first_ref).unwrap();
            let second_ref = vm.alloc_vec(second.len()).unwrap();
            vm.mark_public(second_ref).unwrap();
            vm.assign(second_ref, second.to_vec()).unwrap();
            vm.commit(second_ref).unwrap();
            let extract = HkdfExtract384::alloc(Mode::Normal, vm, salt_ref, &[first_ref, second_ref]).unwrap();
            vm.decode(extract.output()).unwrap()
        };

        let mut leader_out = run(&mut leader);
        let mut follower_out = run(&mut follower);
        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let actual = leader_out.try_recv().unwrap().unwrap();
        assert_eq!(actual, follower_out.try_recv().unwrap().unwrap());
        let mut ikm = first.to_vec();
        ikm.extend_from_slice(&second);
        assert_eq!(actual.to_vec(), hkdf_extract_sha384(&salt, &ikm));
    }
}

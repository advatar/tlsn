//! HMAC-SHA384 construction over the secret-shared SHA-384 state.

use std::sync::Arc;

use mpz_circuits::circuits::xor;
use mpz_vm_core::{
    memory::{binary::{Binary, U8}, Array, MemoryExt, Vector},
    Call, CallableExt, Vm,
    prelude::ViewExt,
};

use crate::FError;
use super::sha384::Sha384;

const BLOCK_SIZE: usize = 128;
const IPAD: [u8; BLOCK_SIZE] = [0x36; BLOCK_SIZE];
const OPAD: [u8; BLOCK_SIZE] = [0x5c; BLOCK_SIZE];

/// Computes HMAC-SHA384 from an already allocated outer partial and inner digest.
pub(crate) fn hmac_sha384(
    vm: &mut dyn Vm<Binary>,
    mut outer_partial: Sha384,
    inner_local: Array<U8, 48>,
) -> Result<Array<U8, 48>, FError> {
    outer_partial.update(&inner_local.into());
    outer_partial.compress(vm).map_err(FError::vm)?;
    outer_partial.finalize(vm).map_err(FError::vm)
}

/// Computes one HMAC-SHA384 padded-key partial state.
pub(crate) fn compute_partial(
    vm: &mut dyn Vm<Binary>,
    key: Vector<U8>,
    mask: [u8; BLOCK_SIZE],
) -> Result<Sha384, FError> {
    if key.len() > BLOCK_SIZE {
        return Err(FError::state("SHA-384 HMAC key exceeds 128-byte block"));
    }
    let padding_ref: Vector<U8> = vm.alloc_vec(BLOCK_SIZE - key.len()).map_err(FError::vm)?;
    vm.mark_public(padding_ref).map_err(FError::vm)?;
    vm.assign(padding_ref, vec![0; BLOCK_SIZE - key.len()]).map_err(FError::vm)?;
    vm.commit(padding_ref).map_err(FError::vm)?;

    let mask_ref: Array<U8, BLOCK_SIZE> = vm.alloc().map_err(FError::vm)?;
    vm.mark_public(mask_ref).map_err(FError::vm)?;
    vm.assign(mask_ref, mask).map_err(FError::vm)?;
    vm.commit(mask_ref).map_err(FError::vm)?;

    let xor = Arc::new(xor(8 * BLOCK_SIZE));
    let call = Call::builder(xor)
        .arg(key)
        .arg(padding_ref)
        .arg(mask_ref)
        .build()
        .map_err(FError::vm)?;
    let key_padded: Vector<U8> = vm.call(call).map_err(FError::vm)?;

    let mut sha = Sha384::new_with_init(vm).map_err(FError::vm)?;
    sha.update(&key_padded);
    sha.compress(vm).map_err(FError::vm)?;
    Ok(sha)
}

pub(crate) fn ipad_partial(vm: &mut dyn Vm<Binary>, key: Vector<U8>) -> Result<Sha384, FError> {
    compute_partial(vm, key, IPAD)
}

pub(crate) fn opad_partial(vm: &mut dyn Vm<Binary>, key: Vector<U8>) -> Result<Sha384, FError> {
    compute_partial(vm, key, OPAD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mock_vm;
    use hmac::{Hmac, Mac};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{memory::MemoryExt, Execute};
    use sha2::Sha384;

    #[tokio::test]
    async fn hmac_sha384_matches_clear_reference() {
        let key = [0x11u8; 48];
        let msg = [0x22u8; 37];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let key_ref = vm.alloc_vec(key.len()).unwrap();
            vm.mark_public(key_ref).unwrap();
            vm.assign(key_ref, key.to_vec()).unwrap();
            vm.commit(key_ref).unwrap();

            let msg_ref = vm.alloc_vec(msg.len()).unwrap();
            vm.mark_public(msg_ref).unwrap();
            vm.assign(msg_ref, msg.to_vec()).unwrap();
            vm.commit(msg_ref).unwrap();

            let mut inner = ipad_partial(vm, key_ref).unwrap();
            inner.update(&msg_ref);
            inner.compress(vm).unwrap();
            let inner_local = inner.finalize(vm).unwrap();
            let outer = opad_partial(vm, key_ref).unwrap();
            let output = hmac_sha384(vm, outer, inner_local).unwrap();
            vm.decode(output).unwrap()
        };
        let mut leader_decoded = run(&mut leader);
        let mut follower_decoded = run(&mut follower);

        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let actual = leader_decoded.try_recv().unwrap().unwrap();
        assert_eq!(actual, follower_decoded.try_recv().unwrap().unwrap());

        let mut reference = Hmac::<Sha384>::new_from_slice(&key).unwrap();
        reference.update(&msg);
        let expected: [u8; 48] = reference.finalize().into_bytes().into();
        assert_eq!(actual, expected);
    }
}

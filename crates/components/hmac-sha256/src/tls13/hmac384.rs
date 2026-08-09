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

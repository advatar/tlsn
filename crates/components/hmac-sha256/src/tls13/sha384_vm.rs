//! VM adapter for the SHA-384 compression circuit.

use std::sync::{Arc, LazyLock};

use mpz_circuits_core::Circuit;
use mpz_vm_core::{
    memory::{binary::{Binary, U64}, Array, Slice},
    Call, CallableExt, Vm, VmError,
    prelude::{MemoryExt, ViewExt},
};

use super::sha384_circuit::sha384_compress_circuit;

pub(crate) static SHA384_COMPRESS: LazyLock<Arc<Circuit>> =
    LazyLock::new(|| Arc::new(sha384_compress_circuit()));

/// Calls one secret-shared SHA-512 compression block for SHA-384.
pub(crate) fn compress(
    vm: &mut dyn Vm<Binary>,
    block: Slice,
    state: Array<U64, 8>,
) -> Result<Array<U64, 8>, VmError> {
    let call = Call::builder(SHA384_COMPRESS.clone())
        .arg(block)
        .arg(state)
        .build()
        .expect("SHA-384 compression circuit has 1024+512 input bits");
    vm.call(call)
}

/// Allocates the SHA-384 initial state as public VM words.
pub(crate) fn initial_state(vm: &mut dyn Vm<Binary>) -> Result<Array<U64, 8>, VmError> {
    let state = vm.alloc()?;
    vm.mark_public(state)?;
    vm.assign(state, [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ])?;
    vm.commit(state)?;
    Ok(state)
}

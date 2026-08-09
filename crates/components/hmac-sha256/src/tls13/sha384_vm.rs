//! VM adapter for the SHA-384 compression circuit.

use std::sync::{Arc, LazyLock};

use mpz_circuits_core::Circuit;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U64},
        Array, Slice,
    },
    prelude::{MemoryExt, ViewExt},
    Call, CallableExt, Vm, VmError,
};

pub(crate) static SHA384_COMPRESS: LazyLock<Arc<Circuit>> = LazyLock::new(|| {
    Arc::new(
        bincode::deserialize(include_bytes!("../../data/sha384.bin"))
            .expect("embedded SHA-384 circuit data must be valid"),
    )
});

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
    vm.assign(
        state,
        [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ],
    )?;
    vm.commit(state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::SHA384_COMPRESS;
    use mpz_circuits_core::evaluate;

    #[test]
    fn embedded_sha384_circuit_matches_reference() {
        let message = std::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let initial = [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ];
        let output: [u64; 8] = evaluate!(SHA384_COMPRESS, message, initial).unwrap();
        let mut expected = initial;
        sha2::compress512(&mut expected, &[message.into()]);
        assert_eq!(output, expected);
    }
}

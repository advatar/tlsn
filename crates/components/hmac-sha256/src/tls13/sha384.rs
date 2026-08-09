//! Secret-shared streaming SHA-384 built on the local compression circuit.

use std::{array::from_fn, sync::{Arc, LazyLock}};

use mpz_circuits_core::{Circuit, CircuitBuilder};
use mpz_circuits_core::itybity::ToBits;
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    memory::{binary::{Binary, U8, U64}, Array, Slice, ToRaw, Vector},
    Vm, VmError, CallableExt, Call,
};

use super::sha384_vm::initial_state;

const BLOCK_SIZE: usize = 1024;

static SERIALIZE_STATE: LazyLock<Arc<Circuit>> = LazyLock::new(|| {
    let mut builder = CircuitBuilder::new();
    for word_index in 0..8 {
        let word: [_; 64] = from_fn(|_| builder.add_input());
        if word_index < 6 {
            for byte in word.chunks_exact(8).rev() {
                for &bit in byte {
                    let output = builder.add_id_gate(bit);
                    builder.add_output(output);
                }
            }
        }
    }
    Arc::new(builder.build().unwrap())
});

#[derive(Debug, Clone)]
struct Block { data: Vec<Slice>, len: usize }

/// Streaming secret-shared SHA-384 state.
#[derive(Debug, Clone)]
pub(crate) struct Sha384 {
    state: Option<Array<U64, 8>>,
    blocks: Vec<Block>,
    processed: usize,
}

impl Sha384 {
    pub(crate) fn new() -> Self { Self { state: None, blocks: Vec::new(), processed: 0 } }

    pub(crate) fn new_with_init(vm: &mut dyn Vm<Binary>) -> Result<Self, VmError> {
        let mut hasher = Self::new();
        hasher.state = Some(initial_state(vm)?);
        Ok(hasher)
    }

    pub(crate) fn update(&mut self, data: &Vector<U8>) { self.update_slice(data.to_raw()); }

    fn update_slice(&mut self, mut data: Slice) {
        if data.len() == 0 { return; }
        if let Some(block) = self.blocks.last_mut() {
            if block.len < BLOCK_SIZE {
                let diff = BLOCK_SIZE - block.len;
                let (left, right) = data.split_at(diff.min(data.len()));
                block.data.push(left); block.len += left.len(); data = right;
            }
        }
        while data.len() > 0 {
            let (left, right) = data.split_at(BLOCK_SIZE.min(data.len()));
            self.blocks.push(Block { data: vec![left], len: left.len() });
            data = right;
        }
    }

    pub(crate) fn compress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), VmError> {
        let pos = self.blocks.iter().position(|b| b.len != BLOCK_SIZE).unwrap_or(self.blocks.len());
        let mut state = match self.state { Some(s) => s, None => initial_state(vm)? };
        for block in self.blocks.drain(..pos) {
            let mut call = Call::builder(super::sha384_vm::SHA384_COMPRESS.clone());
            for slice in block.data { call = call.arg(slice); }
            let call = call.arg(state).build().expect("SHA-384 block has 1024-bit input");
            state = vm.call(call)?;
        }
        self.processed += pos;
        self.state = Some(state);
        Ok(())
    }

    pub(crate) fn finalize(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 48>, VmError> {
        let mut hasher = self.clone();
        let len = self.processed * BLOCK_SIZE + self.blocks.iter().map(|b| b.len).sum::<usize>();
        let total_len = (len + 1 + 128).next_multiple_of(BLOCK_SIZE);
        let padding_len = total_len - len;
        let padding = vm.alloc_raw(padding_len)?;
        vm.mark_public_raw(padding)?;
        let mut bits = BitVec::repeat(false, padding_len);
        bits.set(7, true);
        let bit_len = (len as u128).to_be_bytes();
        bits[padding_len - 128..]
            .iter_mut().zip(bit_len.iter().flat_map(|b| b.iter_lsb0()))
            .for_each(|(a, bit)| a.commit(bit));
        vm.assign_raw(padding, bits)?; vm.commit_raw(padding)?;
        hasher.update_slice(padding); hasher.compress(vm)?;
        let state = hasher.state.expect("finalized state");
        let call = Call::builder(SERIALIZE_STATE.clone()).arg(state).build().unwrap();
        vm.call(call)
    }
}

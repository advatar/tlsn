//! AES-256 counter-mode cipher backed by the MPZ Boolean circuit.

use crate::{Cipher, CtrBlock, Keystream};
use async_trait::async_trait;
use mpz_memory_core::{binary::{Binary, U8}, Array};
use mpz_vm_core::{prelude::*, Call, Vm};
use std::fmt::Debug;
use hmac_sha256::AES256_ENCRYPT;
use super::{AesError, error::ErrorKind};

/// Secret-shared AES-256 encryption in counter mode.
#[derive(Default, Debug)]
pub struct Aes256 { key: Option<Array<U8, 32>>, iv: Option<Array<U8, 4>> }

impl Aes256 {
    fn zeros<const N: usize>(vm: &mut dyn Vm<Binary>) -> Result<Array<U8, N>, AesError> {
        let value = vm.alloc().map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.mark_public(value).map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.assign(value, [0u8; N]).map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.commit(value).map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        Ok(value)
    }
    fn encrypt(&self, vm: &mut dyn Vm<Binary>, nonce: Array<U8, 8>, counter: Array<U8, 4>, block: Array<U8, 16>) -> Result<Array<U8, 16>, AesError> {
        let key = self.key.ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        let iv = self.iv.ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))?;
        vm.call(Call::builder(AES256_ENCRYPT.clone()).arg(key).arg(iv).arg(nonce).arg(counter).arg(block).build().map_err(|e| AesError::new(ErrorKind::Vm, e))?).map_err(|e| AesError::new(ErrorKind::Vm, e))
    }
}

#[async_trait]
impl Cipher for Aes256 {
    type Error = AesError;
    type Key = Array<U8, 32>;
    type Iv = Array<U8, 4>;
    type Nonce = Array<U8, 8>;
    type Counter = Array<U8, 4>;
    type Block = Array<U8, 16>;
    fn set_key(&mut self, key: Self::Key) { self.key = Some(key); }
    fn set_iv(&mut self, iv: Self::Iv) { self.iv = Some(iv); }
    fn key(&self) -> Option<&Self::Key> { self.key.as_ref() }
    fn iv(&self) -> Option<&Self::Iv> { self.iv.as_ref() }
    fn alloc_block(&mut self, vm: &mut dyn Vm<Binary>, input: Self::Block) -> Result<Self::Block, Self::Error> { let nonce = Self::zeros(vm)?; let counter = Self::zeros(vm)?; self.encrypt(vm, nonce, counter, input) }
    fn alloc_ctr_block(&mut self, vm: &mut dyn Vm<Binary>) -> Result<CtrBlock<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        let nonce = vm.alloc().map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        let counter = vm.alloc().map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.mark_public(nonce).map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.mark_public(counter).map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        let block = Self::zeros(vm)?;
        let output = self.encrypt(vm, nonce, counter, block)?;
        Ok(CtrBlock { explicit_nonce: nonce, counter, output })
    }
    fn alloc_ctr_block_with_nonce(&mut self, vm: &mut dyn Vm<Binary>, nonce: Self::Nonce) -> Result<CtrBlock<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        let counter = vm.alloc().map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.mark_public(counter).map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        let block = Self::zeros(vm)?;
        let output = self.encrypt(vm, nonce, counter, block)?;
        Ok(CtrBlock { explicit_nonce: nonce, counter, output })
    }
    fn alloc_keystream_with_nonce(&mut self, vm: &mut dyn Vm<Binary>, len: usize, nonce: Self::Nonce) -> Result<Keystream<Self::Nonce, Self::Counter, Self::Block>, Self::Error> { Ok(Keystream::new(&(0..len.div_ceil(16)).map(|_| self.alloc_ctr_block_with_nonce(vm, nonce)).collect::<Result<Vec<_>, _>>()?)) }
    fn alloc_keystream(&mut self, vm: &mut dyn Vm<Binary>, len: usize) -> Result<Keystream<Self::Nonce, Self::Counter, Self::Block>, Self::Error> { Ok(Keystream::new(&(0..len.div_ceil(16)).map(|_| self.alloc_ctr_block(vm)).collect::<Result<Vec<_>, _>>()?)) }
}

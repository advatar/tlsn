//! AES-256 counter-mode cipher backed by the MPZ Boolean circuit.

use super::{error::ErrorKind, AesError};
use crate::{Cipher, CtrBlock, Keystream};
use async_trait::async_trait;
use hmac_sha256::{AES256_KS, AES256_POST_KS};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array,
};
use mpz_vm_core::{prelude::*, Call, Vm};
use std::fmt::Debug;

/// Secret-shared AES-256 encryption in counter mode.
#[derive(Default, Debug)]
pub struct Aes256 {
    key: Option<Array<U8, 32>>,
    key_schedule: Option<Array<U8, 240>>,
    iv: Option<Array<U8, 4>>,
}

impl Aes256 {
    fn alloc_key_schedule(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 240>, AesError> {
        let key = self
            .key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        vm.call(
            Call::builder(AES256_KS.clone())
                .arg(key)
                .build()
                .map_err(|e| AesError::new(ErrorKind::Vm, e))?,
        )
        .map_err(|e| AesError::new(ErrorKind::Vm, e))
    }

    fn key_schedule(&mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 240>, AesError> {
        if self.key_schedule.is_none() {
            self.key_schedule = Some(self.alloc_key_schedule(vm)?);
        }
        Ok(*self.key_schedule.as_ref().expect("key schedule was set"))
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
    fn set_key(&mut self, key: Self::Key) {
        self.key = Some(key);
        self.key_schedule = None;
    }
    fn set_iv(&mut self, iv: Self::Iv) {
        self.iv = Some(iv);
    }
    fn key(&self) -> Option<&Self::Key> {
        self.key.as_ref()
    }
    fn iv(&self) -> Option<&Self::Iv> {
        self.iv.as_ref()
    }
    fn alloc_block(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        input: Self::Block,
    ) -> Result<Self::Block, Self::Error> {
        let key_schedule = self.key_schedule(vm)?;
        vm.call(
            Call::builder(AES256_POST_KS.clone())
                .arg(key_schedule)
                .arg(input)
                .build()
                .map_err(|e| AesError::new(ErrorKind::Vm, e))?,
        )
        .map_err(|e| AesError::new(ErrorKind::Vm, e))
    }
    fn alloc_ctr_block(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<CtrBlock<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        let nonce = vm.alloc().map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        let counter = vm.alloc().map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.mark_public(nonce)
            .map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.mark_public(counter)
            .map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        let iv = self
            .iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))?;
        let key_schedule = self.key_schedule(vm)?;
        let output = vm
            .call(
                Call::builder(AES256_POST_KS.clone())
                    .arg(key_schedule)
                    .arg(iv)
                    .arg(nonce)
                    .arg(counter)
                    .build()
                    .map_err(|e| AesError::new(ErrorKind::Vm, e))?,
            )
            .map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        Ok(CtrBlock {
            explicit_nonce: nonce,
            counter,
            output,
        })
    }
    fn alloc_ctr_block_with_nonce(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        nonce: Self::Nonce,
    ) -> Result<CtrBlock<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        let counter = vm.alloc().map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        vm.mark_public(counter)
            .map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        let iv = self
            .iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))?;
        let key_schedule = self.key_schedule(vm)?;
        let output = vm
            .call(
                Call::builder(AES256_POST_KS.clone())
                    .arg(key_schedule)
                    .arg(iv)
                    .arg(nonce)
                    .arg(counter)
                    .build()
                    .map_err(|e| AesError::new(ErrorKind::Vm, e))?,
            )
            .map_err(|e| AesError::new(ErrorKind::Vm, e))?;
        Ok(CtrBlock {
            explicit_nonce: nonce,
            counter,
            output,
        })
    }
    fn alloc_keystream_with_nonce(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        len: usize,
        nonce: Self::Nonce,
    ) -> Result<Keystream<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        Ok(Keystream::new(
            &(0..len.div_ceil(16))
                .map(|_| self.alloc_ctr_block_with_nonce(vm, nonce))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
    fn alloc_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        len: usize,
    ) -> Result<Keystream<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        Ok(Keystream::new(
            &(0..len.div_ceil(16))
                .map(|_| self.alloc_ctr_block(vm))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

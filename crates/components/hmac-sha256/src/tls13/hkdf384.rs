//! One-block TLS 1.3 HKDF-Expand-Label over secret-shared SHA-384.

use mpz_vm_core::{memory::{binary::{Binary, U8}, Array, MemoryExt, Vector}, prelude::ViewExt, Vm};
use crate::FError;
use super::hmac384::{hmac_sha384, ipad_partial, opad_partial};

pub(crate) const EMPTY_HASH_SHA384: [u8; 48] = [
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
];

pub(crate) fn zero_hash(vm: &mut dyn Vm<Binary>) -> Result<Vector<U8>, FError> {
    let zero = vm.alloc_vec(48).map_err(FError::vm)?;
    vm.mark_public(zero).map_err(FError::vm)?;
    vm.assign(zero, vec![0; 48]).map_err(FError::vm)?;
    vm.commit(zero).map_err(FError::vm)?;
    Ok(zero)
}

/// SHA-384 TLS 1.3 expansion (all current traffic/key/IV labels fit one block).
#[derive(Debug)]
pub(crate) struct HkdfExpand384 {
    info: Vector<U8>,
    label: &'static [u8],
    context_len: usize,
    output_len: usize,
    output: Option<Array<U8, 48>>,
    context_set: bool,
}

impl HkdfExpand384 {
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        secret: Vector<U8>,
        label: &'static [u8],
        output_len: usize,
        context_len: usize,
    ) -> Result<Self, FError> {
        if output_len > 48 { return Err(FError::state("SHA-384 expansion exceeds one block")); }
        if context_len > u8::MAX as usize || label.len() + 6 > u8::MAX as usize {
            return Err(FError::state("HKDF label/context exceeds TLS 1.3 encoding"));
        }
        let info_len = 2 + 1 + 6 + label.len() + 1 + context_len;
        let info = vm.alloc_vec(info_len).map_err(FError::vm)?;
        vm.mark_public(info).map_err(FError::vm)?;
        let suffix = vm.alloc_vec(1).map_err(FError::vm)?;
        vm.mark_public(suffix).map_err(FError::vm)?;
        vm.assign(suffix, vec![1]).map_err(FError::vm)?;
        vm.commit(suffix).map_err(FError::vm)?;
        let mut inner = ipad_partial(vm, secret).map_err(|e| e)?;
        inner.update(&info);
        inner.update(&suffix);
        inner.compress(vm).map_err(FError::vm)?;
        let inner_local = inner.finalize(vm).map_err(FError::vm)?;
        let outer = opad_partial(vm, secret).map_err(|e| e)?;
        let output = Some(hmac_sha384(vm, outer, inner_local).map_err(|e| e)?);
        Ok(Self { info, label, context_len, output_len, output, context_set: false })
    }

    pub(crate) fn set_context(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        context: &[u8],
    ) -> Result<(), FError> {
        if self.context_set { return Err(FError::state("HKDF context already set")); }
        if context.len() != self.context_len {
            return Err(FError::state("HKDF context length does not match allocation"));
        }
        let mut info = Vec::with_capacity(self.info.len());
        info.extend_from_slice(&(self.output_len as u16).to_be_bytes());
        info.push((self.label.len() + 6) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(self.label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        vm.assign(self.info, info).map_err(FError::vm)?;
        vm.commit(self.info).map_err(FError::vm)?;
        self.context_set = true;
        Ok(())
    }

    pub(crate) fn output(&self) -> Result<Array<U8, 48>, FError> {
        self.output.ok_or_else(|| FError::state("HKDF output is not ready"))
    }

    pub(crate) fn output_view<const N: usize>(&self) -> Result<Array<U8, N>, FError> {
        if N > 48 { return Err(FError::state("HKDF output view exceeds SHA-384 output")); }
        let output: Vector<U8> = self.output
            .ok_or_else(|| FError::state("HKDF output is not ready"))?
            .into();
        output.get(0..N)
            .ok_or_else(|| FError::state("invalid HKDF output view"))?
            .try_into()
            .map_err(|_| FError::state("invalid HKDF output view"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::sha384_reference::hkdf_expand_label_sha384;
    use crate::test_utils::mock_vm;
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{memory::MemoryExt, Execute};

    #[tokio::test]
    async fn tls13_sha384_expand_matches_reference() {
        let secret = [0x33u8; 48];
        let context = [0x44u8; 48];
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let run = |vm: &mut (dyn Vm<Binary> + Send)| {
            let secret_ref = vm.alloc_vec(secret.len()).unwrap();
            vm.mark_public(secret_ref).unwrap();
            vm.assign(secret_ref, secret.to_vec()).unwrap();
            vm.commit(secret_ref).unwrap();
            let mut expand = HkdfExpand384::alloc(vm, secret_ref, b"c ap traffic", 48, 48).unwrap();
            expand.set_context(vm, &context).unwrap();
            vm.decode(expand.output().unwrap()).unwrap()
        };
        let mut leader_out = run(&mut leader);
        let mut follower_out = run(&mut follower);
        tokio::try_join!(
            async { leader.execute_all(&mut ctx_a).await },
            async { follower.execute_all(&mut ctx_b).await },
        ).unwrap();
        let actual = leader_out.try_recv().unwrap().unwrap();
        assert_eq!(actual, follower_out.try_recv().unwrap().unwrap());
        let expected: [u8; 48] = hkdf_expand_label_sha384(&secret, b"c ap traffic", &context, 48).try_into().unwrap();
        assert_eq!(actual, expected);
    }
}

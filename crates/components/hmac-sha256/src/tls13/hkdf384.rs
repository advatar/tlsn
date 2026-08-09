//! One-block TLS 1.3 HKDF-Expand-Label over secret-shared SHA-384.

use mpz_vm_core::{memory::{binary::{Binary, U8}, Array, MemoryExt, Vector}, prelude::ViewExt, Vm};
use crate::FError;
use super::hmac384::{hmac_sha384, ipad_partial, opad_partial};

/// SHA-384 TLS 1.3 expansion (all current traffic/key/IV labels fit one block).
#[derive(Debug)]
pub(crate) struct HkdfExpand384 {
    outer: Option<super::sha384::Sha384>,
    label: &'static [u8],
    output_len: usize,
    output: Option<Array<U8, 48>>,
}

impl HkdfExpand384 {
    pub(crate) fn alloc(
        vm: &mut dyn Vm<Binary>,
        secret: Vector<U8>,
        label: &'static [u8],
        output_len: usize,
    ) -> Result<Self, FError> {
        if output_len > 48 { return Err(FError::state("SHA-384 expansion exceeds one block")); }
        Ok(Self { outer: Some(opad_partial(vm, secret).map_err(|e| e)?), label, output_len, output: None })
    }

    pub(crate) fn set_context(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        secret: Vector<U8>,
        context: &[u8],
    ) -> Result<(), FError> {
        if self.output.is_some() { return Err(FError::state("HKDF context already set")); }
        if context.len() > u8::MAX as usize || self.label.len() + 6 > u8::MAX as usize {
            return Err(FError::state("HKDF label/context exceeds TLS 1.3 encoding"));
        }
        let mut info = Vec::with_capacity(2 + 1 + 6 + self.label.len() + 1 + context.len() + 1);
        info.extend_from_slice(&(self.output_len as u16).to_be_bytes());
        info.push((self.label.len() + 6) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(self.label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        info.push(1);
        let info_ref = vm.alloc_vec(info.len()).map_err(FError::vm)?;
        vm.mark_public(info_ref).map_err(FError::vm)?;
        vm.assign(info_ref, info).map_err(FError::vm)?;
        vm.commit(info_ref).map_err(FError::vm)?;
        let mut inner = ipad_partial(vm, secret).map_err(|e| e)?;
        inner.update(&info_ref);
        inner.compress(vm).map_err(FError::vm)?;
        let inner_local = inner.finalize(vm).map_err(FError::vm)?;
        let outer = self.outer.take().ok_or_else(|| FError::state("HKDF outer state unavailable"))?;
        self.output = Some(hmac_sha384(vm, outer, inner_local).map_err(|e| e)?);
        Ok(())
    }

    pub(crate) fn output(&self) -> Result<Array<U8, 48>, FError> {
        self.output.ok_or_else(|| FError::state("HKDF output is not ready"))
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
            let mut expand = HkdfExpand384::alloc(vm, secret_ref, b"c ap traffic", 48).unwrap();
            expand.set_context(vm, secret_ref, &context).unwrap();
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

//! In-VM derivation of the TLS 1.3 per-record nonce.

use std::sync::Arc;

use mpz_circuits::circuits::xor;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, Vector, ViewExt,
};
use mpz_vm_core::{prelude::*, CallBuilder, Vm};

use crate::error::MpcTlsError;

/// Splits a TLS 1.3 IV and derives the nonce for one record, without revealing
/// either.
///
/// RFC 8446 section 5.3 builds the nonce by left-padding the 64-bit sequence
/// number to the IV length and XORing it with the static IV. The sequence number
/// therefore only reaches the **trailing 8 bytes**, so the leading 4 bytes of
/// every nonce in a connection equal the leading 4 bytes of the IV. That is
/// exactly the split AES-CTR already wants — its counter block is
/// `iv(4) || nonce(8) || counter(4)` — which is why TLS 1.3 can reuse the same
/// cipher as TLS 1.2 with no new circuit.
///
/// Returns `(iv_prefix, nonce)`: `iv_prefix` is constant for the connection and
/// goes to `Cipher::set_iv`, while `nonce` changes per record and goes to
/// `Cipher::alloc_keystream_with_nonce`.
///
/// Nothing here is decoded. The IV stays secret-shared, the sequence number is
/// public, and XOR with a public value leaves the result secret — which is the
/// whole point: the prover must never hold the traffic keys in the clear.
// Not yet called: the 1.3 record layer still decrypts locally with decoded keys.
// This is wired in when that path moves to joint AEAD, and is tested against the
// RFC construction in the meantime so the derivation is not the unknown then.
#[allow(dead_code)]
pub(crate) fn split_iv_and_derive_nonce(
    vm: &mut dyn Vm<Binary>,
    iv: Array<U8, 12>,
    seq: u64,
) -> Result<(Array<U8, 4>, Array<U8, 8>), MpcTlsError> {
    let iv: Vector<U8> = iv.into();

    let prefix: Array<U8, 4> = iv
        .get(0..4)
        .ok_or_else(|| MpcTlsError::hs("tls13 iv is shorter than 4 bytes"))?
        .try_into()
        .map_err(|_| MpcTlsError::hs("tls13 iv prefix is not 4 bytes"))?;

    let tail = iv
        .get(4..12)
        .ok_or_else(|| MpcTlsError::hs("tls13 iv is shorter than 12 bytes"))?;

    // The sequence number is public: it is implied by record order, so revealing
    // it discloses nothing that an observer does not already know.
    let seq_ref: Array<U8, 8> = vm.alloc().map_err(MpcTlsError::hs)?;
    vm.mark_public(seq_ref).map_err(MpcTlsError::hs)?;
    vm.assign(seq_ref, seq.to_be_bytes())
        .map_err(MpcTlsError::hs)?;
    vm.commit(seq_ref).map_err(MpcTlsError::hs)?;

    let call = CallBuilder::new(Arc::new(xor(64)))
        .arg(tail)
        .arg(seq_ref)
        .build()
        .map_err(MpcTlsError::hs)?;
    let nonce: Vector<U8> = vm.call(call).map_err(MpcTlsError::hs)?;
    let nonce: Array<U8, 8> = nonce
        .try_into()
        .map_err(|_| MpcTlsError::hs("tls13 nonce is not 8 bytes"))?;

    Ok((prefix, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::Execute;

    /// The reference construction, matching `tlsn_tls13_reference::traffic::nonce`
    /// and RFC 8446 section 5.3.
    fn reference_nonce(iv: [u8; 12], seq: u64) -> [u8; 12] {
        let mut nonce = iv;
        let seq = seq.to_be_bytes();
        for (n, s) in nonce[4..].iter_mut().zip(seq) {
            *n ^= s;
        }
        nonce
    }

    /// The in-VM derivation must reproduce the reference nonce, for sequence
    /// numbers that exercise no carry, a single byte, and every byte.
    #[tokio::test]
    async fn derived_nonce_matches_the_reference() {
        for (iv, seq) in [
            ([0u8; 12], 0u64),
            ([0xaa; 12], 1),
            ([0x5c; 12], 0x0102_0304_0506_0708),
            ([0xff; 12], u64::MAX),
        ] {
            let (mut ctx_a, mut ctx_b) = test_st_context(8);
            let mut gen = IdealVm::new();
            let mut ev = IdealVm::new();

            let run = |vm: &mut IdealVm| {
                let iv_ref: Array<U8, 12> = vm.alloc().unwrap();
                vm.mark_public(iv_ref).unwrap();
                vm.assign(iv_ref, iv).unwrap();
                vm.commit(iv_ref).unwrap();

                let (prefix, nonce) = split_iv_and_derive_nonce(vm, iv_ref, seq).unwrap();
                (vm.decode(prefix).unwrap(), vm.decode(nonce).unwrap())
            };

            let (p_gen, n_gen) = run(&mut gen);
            let (p_ev, n_ev) = run(&mut ev);

            let ((p_gen, n_gen), (p_ev, n_ev)) = tokio::try_join!(
                async {
                    gen.execute_all(&mut ctx_a).await.unwrap();
                    Ok::<_, std::convert::Infallible>((p_gen.await.unwrap(), n_gen.await.unwrap()))
                },
                async {
                    ev.execute_all(&mut ctx_b).await.unwrap();
                    Ok::<_, std::convert::Infallible>((p_ev.await.unwrap(), n_ev.await.unwrap()))
                }
            )
            .unwrap();

            assert_eq!(p_gen, p_ev, "both parties derive the same iv prefix");
            assert_eq!(n_gen, n_ev, "both parties derive the same nonce");

            let expected = reference_nonce(iv, seq);
            assert_eq!(
                &p_gen,
                &expected[..4],
                "iv prefix (iv={iv:02x?}, seq={seq})"
            );
            assert_eq!(
                &n_gen,
                &expected[4..],
                "nonce tail (iv={iv:02x?}, seq={seq})"
            );
        }
    }

    /// The prefix must be independent of the sequence number — that invariant is
    /// what lets `set_iv` be called once per connection rather than per record.
    #[tokio::test]
    async fn iv_prefix_does_not_depend_on_the_sequence_number() {
        let iv = [0x31u8; 12];
        assert_eq!(
            reference_nonce(iv, 0)[..4],
            reference_nonce(iv, u64::MAX)[..4]
        );
        // And the tail must change, or the nonce would repeat across records.
        assert_ne!(
            reference_nonce(iv, 0)[4..],
            reference_nonce(iv, u64::MAX)[4..]
        );
    }
}

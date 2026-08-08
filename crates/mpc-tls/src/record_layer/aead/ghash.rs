mod compute;
mod verify;

pub(crate) use compute::{ComputeTagData, ComputeTags};
pub(crate) use verify::{VerifyTagData, VerifyTags};

use std::{fmt::Debug, ops::Add};

use async_trait::async_trait;
use mpz_common::{future::Output, Context, Flush};
use mpz_core::Block;
use mpz_fields::{gf2_128::Gf2_128, Field};
use mpz_share_conversion::{AdditiveToMultiplicative, MultiplicativeToAdditive};
use serde::{Deserialize, Serialize};

use crate::record_layer::aead::AeadError;

/// Maximum exponent used in GHASH.
const MAX_POWER: usize = 1026;

#[async_trait]
pub(crate) trait Ghash {
    /// Allocates resources needed for GHASH.
    fn alloc(&mut self, keys: usize) -> Result<(), GhashError>;

    /// Preprocesses GHASH.
    async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), GhashError>;

    /// Sets the additive key share for the hash function.
    fn set_keys(&mut self, keys: Vec<Vec<u8>>) -> Result<(), GhashError>;

    /// Sets up GHASH, computing the key shares.
    async fn setup(&mut self, ctx: &mut Context) -> Result<(), GhashError>;

    /// Computes the GHASH tag share.
    fn compute(&self, key_index: usize, input: &[u8]) -> Result<Vec<u8>, GhashError>;
}

/// MPC GHASH implementation.
pub(crate) struct MpcGhash<C> {
    state: State,
    converter: C,
    alloc: bool,
}

#[derive(Debug)]
enum State {
    Init,
    SetKeys { keys: Vec<Gf2_128> },
    Ready { shares: Vec<Vec<Gf2_128>> },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

impl<C> MpcGhash<C> {
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `converter` - GF2_128 share converter.
    pub(crate) fn new(converter: C) -> Self {
        Self {
            state: State::Init,
            converter,
            alloc: false,
        }
    }
}

#[async_trait]
impl<C> Ghash for MpcGhash<C>
where
    C: AdditiveToMultiplicative<Gf2_128> + Flush + Send,
    C: MultiplicativeToAdditive<Gf2_128> + Flush + Send,
{
    fn alloc(&mut self, keys: usize) -> Result<(), GhashError> {
        if !self.alloc {
            // Odd powers are computed using M2A, even powers are computed
            // locally. We need one extra A2M conversion in the beginning.
            // Both M2A and A2M, each require a single OLE.
            AdditiveToMultiplicative::<Gf2_128>::alloc(&mut self.converter, keys)
                .map_err(GhashError::conversion)?;

            // -1 because the odd power H^1 is already known at this point.
            MultiplicativeToAdditive::<Gf2_128>::alloc(
                &mut self.converter,
                keys * ((MAX_POWER / 2) - 1),
            )
            .map_err(GhashError::conversion)?;

            self.alloc = true;
        }

        Ok(())
    }

    async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), GhashError> {
        self.converter
            .flush(ctx)
            .await
            .map_err(GhashError::conversion)
    }

    fn set_keys(&mut self, keys: Vec<Vec<u8>>) -> Result<(), GhashError> {
        let State::Init = self.state.take() else {
            return Err(GhashError::state("keys already set"));
        };

        let keys = keys
            .into_iter()
            .map(|key| {
                let key: [u8; 16] =
                    key.try_into()
                        .map_err(|key: Vec<u8>| ErrorRepr::KeyLength {
                            expected: 16,
                            actual: key.len(),
                        })?;
                Ok(Gf2_128::new(u128::from_be_bytes(key).reverse_bits()))
            })
            .collect::<Result<Vec<_>, GhashError>>()?;

        self.state = State::SetKeys { keys };

        Ok(())
    }

    async fn setup(&mut self, ctx: &mut Context) -> Result<(), GhashError> {
        let State::SetKeys { keys: add_keys } = self.state.take() else {
            return Err(GhashError::state("cannot setup before keys are set"));
        };

        let mut mult_key = self
            .converter
            .queue_to_multiplicative(&add_keys)
            .map_err(GhashError::conversion)?;

        self.converter
            .flush(ctx)
            .await
            .map_err(GhashError::conversion)?;

        let mult_keys = mult_key
            .try_recv()
            .map_err(GhashError::conversion)?
            .expect("share should be computed")
            .shares;

        let odd_shares = mult_keys
            .iter()
            .flat_map(|mult_key| {
                (0..MAX_POWER)
                    .scan(*mult_key, |acc, _| {
                        let power_n = *acc;
                        *acc = power_n * *mult_key;
                        Some(power_n)
                    })
                    .skip(2)
                    .step_by(2)
            })
            .collect::<Vec<_>>();

        // Compute the additive shares of the odd powers.
        let mut add_shares_odd = self
            .converter
            .queue_to_additive(&odd_shares)
            .map_err(GhashError::conversion)?;

        self.converter
            .flush(ctx)
            .await
            .map_err(GhashError::conversion)?;

        let add_shares_odd = add_shares_odd
            .try_recv()
            .map_err(GhashError::conversion)?
            .expect("share should be computed")
            .shares;

        let odd_count = (MAX_POWER / 2) - 1;
        let shares = add_keys
            .into_iter()
            .zip(add_shares_odd.chunks_exact(odd_count))
            .map(|(key, odd)| compute_shares(key, odd))
            .collect();

        self.state = State::Ready { shares };

        Ok(())
    }

    fn compute(&self, key_index: usize, input: &[u8]) -> Result<Vec<u8>, GhashError> {
        let State::Ready { shares } = &self.state else {
            return Err(GhashError::state("key shares are not computed"));
        };
        let shares = shares
            .get(key_index)
            .ok_or_else(|| GhashError::state("GHASH key index is not configured"))?;

        // Divide by block length and round up.
        let block_count = input.len() / 16 + !input.len().is_multiple_of(16) as usize;

        if block_count > MAX_POWER {
            return Err(ErrorRepr::InputLength {
                len: block_count,
                max: MAX_POWER * 16,
            }
            .into());
        }

        let mut input = input.to_vec();

        // Pad input to a multiple of 16 bytes.
        input.resize(block_count * 16, 0);

        // Convert input to blocks.
        let blocks = input
            .chunks_exact(16)
            .map(|chunk| {
                let mut block = [0u8; 16];
                block.copy_from_slice(chunk);
                Block::from(block)
            })
            .collect::<Vec<Block>>();

        let offset = shares.len() - blocks.len();
        let tag: Block = blocks
            .iter()
            .zip(shares.iter().rev().skip(offset))
            .fold(Gf2_128::zero(), |acc, (block, share)| {
                acc + Gf2_128::from(block.reverse_bits()) * *share
            })
            .into();

        Ok(tag.reverse_bits().to_bytes().to_vec())
    }
}

/// Computes shares of powers of H.
///
/// # Arguments
///
/// * `key` - Additive share of H.
/// * `odd_powers` - Additive shares of odd powers of H starting at H^3.
fn compute_shares(key: Gf2_128, odd_powers: &[Gf2_128]) -> Vec<Gf2_128> {
    let mut shares = Vec::with_capacity(MAX_POWER);

    // H^1
    shares.push(key);

    let mut odd_idx = 0;
    for i in 2..=MAX_POWER {
        if i % 2 == 0 {
            // Even power, compute by squaring the square root power.
            let base = shares[i / 2 - 1];
            shares.push(base * base);
        } else {
            // Odd power.
            shares.push(odd_powers[odd_idx]);
            odd_idx += 1;
        }
    }

    shares
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TagShare([u8; 16]);

impl Add for TagShare {
    type Output = Vec<u8>;

    fn add(self, rhs: Self) -> Self::Output {
        self.0
            .iter()
            .zip(rhs.0)
            .map(|(a, b)| *a ^ b)
            .collect::<Vec<_>>()
    }
}

/// Builds padded data for GHASH.
fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
    let associated_data_bitlen = (aad.len() as u64) * 8;
    let text_bitlen = (ciphertext.len() as u64) * 8;

    let len_block = ((associated_data_bitlen as u128) << 64) + (text_bitlen as u128);

    // Pad data to be a multiple of 16 bytes.
    let aad_padded_block_count = (aad.len() / 16) + !aad.len().is_multiple_of(16) as usize;
    aad.resize(aad_padded_block_count * 16, 0);

    let ciphertext_padded_block_count =
        (ciphertext.len() / 16) + !ciphertext.len().is_multiple_of(16) as usize;
    ciphertext.resize(ciphertext_padded_block_count * 16, 0);

    let mut data: Vec<u8> = Vec::with_capacity(aad.len() + ciphertext.len() + 16);
    data.extend(aad);
    data.extend(ciphertext);
    data.extend_from_slice(&len_block.to_be_bytes());

    data
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct GhashError(#[from] ErrorRepr);

impl GhashError {
    fn conversion<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::ShareConversion(error.into()))
    }

    fn state(reason: impl ToString) -> Self {
        Self(ErrorRepr::State(reason.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("ghash error: {0}")]
enum ErrorRepr {
    #[error("share conversion error: {0}")]
    ShareConversion(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("invalid state: {0}")]
    State(String),
    #[error("incorrect key length, expected: {expected}, actual: {actual}")]
    KeyLength { expected: usize, actual: usize },
    #[error("input length exceeds maximum: {len} > {max}")]
    InputLength { len: usize, max: usize },
}

impl From<GhashError> for AeadError {
    fn from(value: GhashError) -> Self {
        AeadError::tag(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghash_rc::{
        universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
        GHash as GhashReference,
    };
    use mpz_common::context::test_st_context;
    use mpz_core::Block;
    use mpz_fields::{gf2_128::Gf2_128, UniformRand};
    use mpz_share_conversion::ideal::{
        ideal_share_convert, IdealShareConvertReceiver, IdealShareConvertSender,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn create_pair() -> (
        MpcGhash<IdealShareConvertSender<Gf2_128>>,
        MpcGhash<IdealShareConvertReceiver<Gf2_128>>,
    ) {
        let (convert_a, convert_b) = ideal_share_convert(Block::ZERO);

        let (mut sender, mut receiver) = (MpcGhash::new(convert_a), MpcGhash::new(convert_b));
        sender.alloc(1).unwrap();
        receiver.alloc(1).unwrap();

        (sender, receiver)
    }

    #[test]
    fn test_compute_shares() {
        let mut rng = StdRng::seed_from_u64(0);

        let key = Gf2_128::rand(&mut rng);
        let expected_powers: Vec<_> = (0..MAX_POWER)
            .scan(key, |acc, _| {
                let power_n = *acc;
                *acc = power_n * key;
                Some(power_n)
            })
            .collect();

        let odd_powers = expected_powers
            .iter()
            .skip(2)
            .step_by(2)
            .cloned()
            .collect::<Vec<_>>();

        let powers = compute_shares(key, &odd_powers);

        assert_eq!(powers, expected_powers);
    }

    #[tokio::test]
    async fn test_ghash_output() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        let message: Vec<u8> = (0..16).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();
        sender
            .set_keys(vec![sender_key.to_be_bytes().to_vec()])
            .unwrap();
        receiver
            .set_keys(vec![receiver_key.to_be_bytes().to_vec()])
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        let sender_share = sender.compute(0, &message).unwrap();
        let receiver_share = receiver.compute(0, &message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_output_padded() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        // Message length is not a multiple of the block length.
        let message: Vec<u8> = (0..14).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();

        sender
            .set_keys(vec![sender_key.to_be_bytes().to_vec()])
            .unwrap();
        receiver
            .set_keys(vec![receiver_key.to_be_bytes().to_vec()])
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        let sender_share = sender.compute(0, &message).unwrap();
        let receiver_share = receiver.compute(0, &message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &message));
    }

    #[tokio::test]
    async fn test_ghash_long_message() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        // A longer message.
        let long_message: Vec<u8> = (0..30).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();

        sender
            .set_keys(vec![sender_key.to_be_bytes().to_vec()])
            .unwrap();
        receiver
            .set_keys(vec![receiver_key.to_be_bytes().to_vec()])
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        let sender_share = sender.compute(0, &long_message).unwrap();
        let receiver_share = receiver.compute(0, &long_message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &long_message));
    }

    #[tokio::test]
    async fn test_ghash_repeated() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut rng = StdRng::seed_from_u64(0);
        let h: u128 = rng.random();
        let sender_key: u128 = rng.random();
        let receiver_key: u128 = h ^ sender_key;

        // Two messages.
        let first_message: Vec<u8> = (0..14).map(|_| rng.random()).collect();
        let second_message: Vec<u8> = (0..32).map(|_| rng.random()).collect();

        let (mut sender, mut receiver) = create_pair();

        sender
            .set_keys(vec![sender_key.to_be_bytes().to_vec()])
            .unwrap();
        receiver
            .set_keys(vec![receiver_key.to_be_bytes().to_vec()])
            .unwrap();

        tokio::try_join!(sender.setup(&mut ctx_a), receiver.setup(&mut ctx_b)).unwrap();

        // Compute and check first message.
        let sender_share = sender.compute(0, &first_message).unwrap();
        let receiver_share = receiver.compute(0, &first_message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &first_message));

        // Compute and check second message.
        let sender_share = sender.compute(0, &second_message).unwrap();
        let receiver_share = receiver.compute(0, &second_message).unwrap();

        let tag = sender_share
            .iter()
            .zip(receiver_share.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();

        assert_eq!(tag, ghash_reference_impl(h, &second_message));
    }

    fn ghash_reference_impl(h: u128, message: &[u8]) -> Vec<u8> {
        let mut ghash = GhashReference::new(&h.to_be_bytes().into());
        ghash.update_padded(message);
        let mac = ghash.finalize();
        mac.to_vec()
    }
}

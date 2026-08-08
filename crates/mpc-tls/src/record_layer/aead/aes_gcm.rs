use std::{collections::VecDeque, future::Future, sync::Arc};

use cipher::{aes::Aes128, Cipher, CtrBlock, Keystream};
use mpz_circuits::circuits::xor;
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    binary::{Binary, U8},
    Vector,
};
use mpz_share_conversion::ShareConvert;
use mpz_vm_core::{prelude::*, CallBuilder, Vm};
use tracing::instrument;

use crate::{
    decode::OneTimePadShared,
    record_layer::{
        aead::{
            ghash::{ComputeTagData, ComputeTags, Ghash, MpcGhash, VerifyTagData, VerifyTags},
            AeadError, Block, Ctr, Nonce,
        },
        TagData,
    },
    Role,
};

const START_CTR: u32 = 2;

struct Tls13Record {
    leader_input: Vector<U8>,
    follower_input: Vector<U8>,
    output: Vector<U8>,
    j0: OneTimePadShared<[u8; 16]>,
}

#[allow(clippy::type_complexity)]
enum State {
    Init {
        ghash: Box<dyn Ghash + Send + Sync>,
    },
    Setup {
        input: Vector<U8>,
        keystream: Keystream<Nonce, Ctr, Block>,
        j0s: Vec<(CtrBlock<Nonce, Ctr, Block>, OneTimePadShared<[u8; 16]>)>,
        ghash_key_shares: Vec<OneTimePadShared<[u8; 16]>>,
        ghash: Box<dyn Ghash + Send + Sync>,
        ghash_key: Array<U8, 16>,
        tls13_records: VecDeque<Tls13Record>,
    },
    Ready {
        input: Vector<U8>,
        keystream: Keystream<Nonce, Ctr, Block>,
        j0s: Vec<(CtrBlock<Nonce, Ctr, Block>, OneTimePadShared<[u8; 16]>)>,
        ghash: Arc<dyn Ghash + Send + Sync>,
        ghash_key: Array<U8, 16>,
        tls13_records: VecDeque<Tls13Record>,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

pub(crate) struct MpcAesGcm {
    role: Role,
    aes: Aes128,
    tls13_aes: Aes128,
    state: State,
}

impl MpcAesGcm {
    /// Creates a new AES-GCM instance.
    pub(crate) fn new<C>(converter: C, role: Role) -> Self
    where
        C: ShareConvert<Gf2_128> + Flush + Send + Sync + 'static,
    {
        Self {
            role,
            aes: Aes128::default(),
            tls13_aes: Aes128::default(),
            state: State::Init {
                ghash: Box::new(MpcGhash::new(converter)),
            },
        }
    }

    /// Allocates resources.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine to allocate in.
    /// * `records` - Number of records to allocate.
    /// * `len` - Length of the input text in bytes.
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        records: usize,
        len: usize,
    ) -> Result<(), AeadError> {
        let State::Init { mut ghash } = self.state.take() else {
            return Err(AeadError::state("must be in init state to allocate"));
        };

        let zero_block: Array<U8, 16> = vm.alloc()?;
        vm.mark_public(zero_block)?;
        vm.assign(zero_block, [0u8; 16])?;
        vm.commit(zero_block)?;

        ghash.alloc(2)?;
        let ghash_key = self.aes.alloc_block(vm, zero_block)?;
        let ghash_key_share = OneTimePadShared::<[u8; 16]>::new(self.role, ghash_key, vm)?;

        // Allocate J0 secret sharing for GHASH.
        let mut j0s = Vec::with_capacity(records);
        for _ in 0..records {
            let j0 = self.aes.alloc_ctr_block(vm)?;
            let j0_shared = OneTimePadShared::<[u8; 16]>::new(self.role, j0.output, vm)?;

            j0s.push((j0, j0_shared));
        }

        // Allocate encryption/decryption.

        // Round up the length to the nearest multiple of the block size.
        let len = 16 * len.div_ceil(16);

        let input = vm.alloc_vec::<U8>(len)?;
        match self.role {
            Role::Leader => {
                vm.mark_private(input)?;
            }
            Role::Follower => {
                vm.mark_blind(input)?;
            }
        }

        let keystream = self.aes.alloc_keystream(vm, len)?;

        self.state = State::Setup {
            input,
            keystream,
            j0s,
            ghash,
            ghash_key_shares: vec![ghash_key_share],
            ghash_key,
            tls13_records: VecDeque::new(),
        };

        Ok(())
    }

    /// Binds the TLS 1.3 AES/GHASH domain to a freshly shared application key.
    pub(crate) fn prepare_tls13_key(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        key: Array<U8, 16>,
    ) -> Result<(), AeadError> {
        let State::Setup {
            ghash_key_shares, ..
        } = &mut self.state
        else {
            return Err(AeadError::state(
                "must be in setup state to prepare TLS 1.3 key",
            ));
        };
        self.tls13_aes.set_key(key);
        let zero: Array<U8, 16> = vm.alloc()?;
        vm.mark_public(zero)?;
        vm.assign(zero, [0u8; 16])?;
        vm.commit(zero)?;
        let ghash_key = self.tls13_aes.alloc_block(vm, zero)?;
        ghash_key_shares.push(OneTimePadShared::<[u8; 16]>::new(self.role, ghash_key, vm)?);
        Ok(())
    }

    /// Preallocates bounded TLS 1.3 record circuits in the initial VM graph.
    pub(crate) fn alloc_tls13_records(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        iv: Array<U8, 12>,
        records: usize,
        max_len: usize,
    ) -> Result<(), AeadError> {
        use crate::tls13::nonce::split_iv_and_derive_nonce;

        let State::Setup { tls13_records, .. } = &mut self.state else {
            return Err(AeadError::state(
                "must be in setup state to allocate TLS 1.3 records",
            ));
        };
        let padded_len = 16 * max_len.div_ceil(16);
        for sequence in 0..records as u64 {
            let (prefix, nonce) = split_iv_and_derive_nonce(vm, iv, sequence)
                .map_err(|err| AeadError::cipher(err.to_string()))?;
            self.tls13_aes.set_iv(prefix);
            let keystream = self
                .tls13_aes
                .alloc_keystream_with_nonce(vm, padded_len, nonce)?;
            let leader_input = vm.alloc_vec::<U8>(padded_len)?;
            let follower_input = vm.alloc_vec::<U8>(padded_len)?;
            match self.role {
                Role::Leader => {
                    vm.mark_private(leader_input)?;
                    vm.mark_blind(follower_input)?;
                }
                Role::Follower => {
                    vm.mark_blind(leader_input)?;
                    vm.mark_private(follower_input)?;
                }
            }
            let input: Vector<U8> = vm.call(
                CallBuilder::new(Arc::new(xor(padded_len * 8)))
                    .arg(leader_input)
                    .arg(follower_input)
                    .build()
                    .map_err(|err| AeadError::cipher(err.to_string()))?,
            )?;
            let output = keystream.apply(vm, input)?;
            let mut ctr = START_CTR..;
            keystream.assign_counters(vm, move || {
                ctr.next().expect("range is unbounded").to_be_bytes()
            })?;

            let j0 = self.tls13_aes.alloc_ctr_block_with_nonce(vm, nonce)?;
            let j0_shared = OneTimePadShared::<[u8; 16]>::new(self.role, j0.output, vm)?;
            assign_j0_counter(vm, j0)?;
            tls13_records.push_back(Tls13Record {
                leader_input,
                follower_input,
                output,
                j0: j0_shared,
            });
        }

        Ok(())
    }

    /// Applies a keystream to one TLS 1.3 record body, keeping the traffic keys
    /// secret-shared.
    ///
    /// The 1.3 counterpart to [`MpcAesGcm::apply_keystream`]. That one draws from
    /// the pooled keystream allocated in [`MpcAesGcm::alloc`] and assigns a public
    /// explicit nonce; here the nonce is a secret reference (`iv XOR seq`), so the
    /// keystream is allocated for this record alone and only the counters are
    /// assigned.
    ///
    /// Returns `(input, output)`. The caller assigns the plaintext to `input` — the
    /// leader only, since it is marked private — commits it, and decodes `output`.
    /// Counters start at 2 because block 1 is reserved for J0, as in TLS 1.2.
    #[allow(dead_code)]
    pub(crate) fn apply_keystream_tls13(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        nonce: Nonce,
        len: usize,
    ) -> Result<(Vector<U8>, Vector<U8>), AeadError> {
        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;
        let padding_len = padded_len - len;

        let mut input = vm.alloc_vec::<U8>(padded_len)?;
        match self.role {
            Role::Leader => vm.mark_private(input)?,
            Role::Follower => vm.mark_blind(input)?,
        }

        let keystream = self
            .tls13_aes
            .alloc_keystream_with_nonce(vm, padded_len, nonce)?;
        let mut output = keystream.apply(vm, input)?;

        let mut ctr = START_CTR..;
        keystream.assign_counters(vm, move || {
            ctr.next().expect("range is unbounded").to_be_bytes()
        })?;

        if padding_len > 0 {
            let padding = input.split_off(input.len() - padding_len);
            // As in the 1.2 path, the padding is not marked public, so only the
            // prover assigns it.
            if let Role::Leader = self.role {
                vm.assign(padding, vec![0; padding_len])?;
            }
            vm.commit(padding)?;
            output.truncate(len);
        }

        Ok((input, output))
    }

    /// Allocates one record's worth of TLS 1.3 material against a secret nonce.
    ///
    /// TLS 1.2 allocates everything up front in [`MpcAesGcm::alloc`]: one long
    /// keystream, sliced per record, plus a pool of J0 blocks whose public nonces
    /// are filled in as records arrive. TLS 1.3 cannot share a keystream that way,
    /// because each record's nonce is a distinct secret value (`iv XOR seq`) and a
    /// keystream is bound to one nonce reference. And its application keys only
    /// exist once the handshake hash is set, after `alloc` has already run.
    ///
    /// So 1.3 allocates per record, at record time, once the length is known. That
    /// trades away the preprocessing overlap 1.2 enjoys in exchange for keeping the
    /// traffic keys secret-shared, which is the property that matters.
    ///
    /// Returns the keystream for the record body and the J0 block used for its tag.
    #[allow(clippy::type_complexity)]
    #[allow(dead_code)]
    pub(crate) fn alloc_record_tls13(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        nonce: Nonce,
        len: usize,
    ) -> Result<
        (
            Keystream<Nonce, Ctr, Block>,
            CtrBlock<Nonce, Ctr, Block>,
            OneTimePadShared<[u8; 16]>,
        ),
        AeadError,
    > {
        let keystream = self.tls13_aes.alloc_keystream_with_nonce(vm, len, nonce)?;

        let j0 = self.tls13_aes.alloc_ctr_block_with_nonce(vm, nonce)?;
        let j0_shared = OneTimePadShared::<[u8; 16]>::new(self.role, j0.output, vm)?;

        Ok((keystream, j0, j0_shared))
    }

    pub(crate) async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), AeadError> {
        let State::Setup { ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in setup state to preprocess"));
        };

        ghash.preprocess(ctx).await?;

        Ok(())
    }

    pub(crate) fn set_key(&mut self, key: Array<U8, 16>) {
        self.aes.set_key(key);
        self.tls13_aes.set_key(key);
    }

    pub(crate) fn set_iv(&mut self, iv: Array<U8, 4>) {
        self.aes.set_iv(iv);
        self.tls13_aes.set_iv(iv);
    }

    pub(crate) async fn setup(&mut self, ctx: &mut Context) -> Result<(), AeadError> {
        self.setup_key_domain(ctx, 0).await
    }

    /// Sets up the TLS 1.3 application-key GHASH domain without waiting for
    /// the unused TLS 1.2 key schedule.
    pub(crate) async fn setup_tls13(&mut self, ctx: &mut Context) -> Result<(), AeadError> {
        self.setup_key_domain(ctx, 1).await
    }

    async fn setup_key_domain(
        &mut self,
        ctx: &mut Context,
        key_index: usize,
    ) -> Result<(), AeadError> {
        let State::Setup {
            input,
            keystream,
            j0s,
            mut ghash_key_shares,
            mut ghash,
            ghash_key,
            tls13_records,
        } = self.state.take()
        else {
            return Err(AeadError::state("must be in setup state to set up"));
        };

        let key_share = ghash_key_shares
            .get_mut(key_index)
            .ok_or_else(|| AeadError::state("GHASH key domain was not allocated"))?;
        let key = key_share.await.map_err(AeadError::tag)?.to_vec();
        ghash.set_keys(vec![key])?;
        ghash.setup(ctx).await?;

        self.state = State::Ready {
            input,
            keystream,
            j0s,
            ghash: Arc::from(ghash),
            ghash_key,
            tls13_records,
        };

        Ok(())
    }

    /// Takes one preprocessed TLS 1.3 record slot.
    pub(crate) fn take_tls13_record(
        &mut self,
        len: usize,
    ) -> Result<
        (
            Vector<U8>,
            Vector<U8>,
            Vector<U8>,
            OneTimePadShared<[u8; 16]>,
        ),
        AeadError,
    > {
        let State::Ready { tls13_records, .. } = &mut self.state else {
            return Err(AeadError::state(
                "must be in ready state to take a TLS 1.3 record",
            ));
        };
        let Tls13Record {
            leader_input,
            follower_input,
            mut output,
            j0,
        } = tls13_records
            .pop_front()
            .ok_or_else(|| AeadError::state("no preallocated TLS 1.3 records remain"))?;
        if len > output.len() {
            return Err(AeadError::cipher(
                "TLS 1.3 record exceeds its preallocated length",
            ));
        }
        output.truncate(len);
        Ok((leader_input, follower_input, output, j0))
    }

    /// Drains input references for unused preallocated TLS 1.3 records.
    pub(crate) fn drain_tls13_inputs(
        &mut self,
    ) -> Result<Vec<(Vector<U8>, Vector<U8>)>, AeadError> {
        let State::Ready { tls13_records, .. } = &mut self.state else {
            return Err(AeadError::state(
                "must be in ready state to drain TLS 1.3 records",
            ));
        };
        Ok(tls13_records
            .drain(..)
            .map(|record| (record.leader_input, record.follower_input))
            .collect())
    }

    /// Returns `len` bytes of input and output text.
    ///
    /// The outer context is responsible for assigning to the input text.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `len` - Number of bytes to take.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn apply_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<(Vector<U8>, Vector<U8>), AeadError> {
        let State::Ready {
            input, keystream, ..
        } = &mut self.state
        else {
            return Err(AeadError::state(
                "must be in ready state to apply keystream",
            ));
        };

        let explicit_nonce: [u8; 8] = explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
            AeadError::cipher(format!(
                "explicit nonce length: expected {}, got {}",
                8,
                nonce.len()
            ))
        })?;

        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;
        let padding_len = padded_len - len;

        if padded_len > input.len() {
            return Err(AeadError::cipher(format!(
                "input length exceeds allocated: {} > {}",
                padded_len,
                input.len()
            )));
        }

        let mut input = input.split_off(input.len() - padded_len);
        let keystream = keystream.consume(padded_len)?;
        let mut output = keystream.apply(vm, input)?;

        // Assign counter block inputs.
        let mut ctr = START_CTR..;
        keystream.assign(vm, explicit_nonce, move || {
            ctr.next().expect("range is unbounded").to_be_bytes()
        })?;

        // Assign zeroes to the padding.
        if padding_len > 0 {
            let padding = input.split_off(input.len() - padding_len);
            // To simplify the impl, we don't mark the padding as public, that's why only
            // the prover assigns it.
            if let Role::Leader = self.role {
                vm.assign(padding, vec![0; padding_len])?;
            }
            vm.commit(padding)?;
            output.truncate(len);
        }

        Ok((input, output))
    }

    /// Returns `len` bytes of keystream.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `len` - Number of bytes to take.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn take_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<Vector<U8>, AeadError> {
        let State::Ready {
            input, keystream, ..
        } = &mut self.state
        else {
            return Err(AeadError::state("must be in ready state to take keystream"));
        };

        let explicit_nonce: [u8; 8] = explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
            AeadError::cipher(format!(
                "explicit nonce length: expected {}, got {}",
                8,
                nonce.len()
            ))
        })?;

        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;

        if padded_len > input.len() {
            return Err(AeadError::cipher(format!(
                "input length exceeds allocated: {} > {}",
                padded_len,
                input.len()
            )));
        }

        let keystream = keystream.consume(len)?;

        // Assign counter block inputs.
        let mut ctr = START_CTR..;
        keystream.assign(vm, explicit_nonce, move || {
            ctr.next().expect("range is unbounded").to_be_bytes()
        })?;

        Ok(keystream.to_vector(vm, len)?)
    }

    /// Returns the VM reference to the GHASH key.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn ghash_key(&mut self) -> Result<Array<U8, 16>, AeadError> {
        let key = match self.state {
            State::Setup { ghash_key, .. } => ghash_key,
            State::Ready { ghash_key, .. } => ghash_key,
            _ => {
                return Err(AeadError::state(
                    "must be in setup or ready state to return ghash key",
                ))
            }
        };

        Ok(key)
    }

    /// Computes tags for the provided ciphertext. See
    /// [`verify_tags`](MpcAesGcm::verify_tags) for a method that verifies
    /// tags instead.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `ciphertext` - Ciphertext to compute the tag for.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn compute_tags<C>(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        ciphertexts: Vec<C>,
        data: Vec<TagData>,
    ) -> Result<ComputeTags, AeadError>
    where
        C: Future<Output = Result<Vec<u8>, AeadError>> + Send + Sync + 'static,
    {
        let State::Ready { j0s, ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in ready state to compute tags"));
        };

        if ciphertexts.len() != data.len() {
            return Err(AeadError::tag("ciphertext and data length mismatch"));
        } else if ciphertexts.len() > j0s.len() {
            return Err(AeadError::tag("ciphertext length exceeds allocated"));
        }

        let mut tag_data = Vec::with_capacity(ciphertexts.len());
        for (ciphertext, data) in ciphertexts.into_iter().zip(data) {
            let explicit_nonce: [u8; 8] =
                data.explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
                    AeadError::cipher(format!(
                        "explicit nonce length: expected {}, got {}",
                        8,
                        nonce.len()
                    ))
                })?;
            let (j0, j0_shared) = j0s.pop().expect("j0 length was checked");

            assign_j0(vm, j0, explicit_nonce)?;

            tag_data.push(ComputeTagData {
                j0: j0_shared,
                ciphertext: Box::pin(ciphertext),
                aad: data.aad,
            });
        }

        let tags = ComputeTags::new(self.role, tag_data, ghash.clone(), 0);

        Ok(tags)
    }

    /// Computes a TLS 1.3 tag using a preprocessed J0 share.
    pub(crate) fn compute_tag_tls13_preallocated<C>(
        &mut self,
        ciphertext: C,
        aad: Vec<u8>,
        j0: OneTimePadShared<[u8; 16]>,
    ) -> Result<ComputeTags, AeadError>
    where
        C: Future<Output = Result<Vec<u8>, AeadError>> + Send + Sync + 'static,
    {
        let State::Ready { ghash, .. } = &mut self.state else {
            return Err(AeadError::state(
                "must be in ready state to compute TLS 1.3 tag",
            ));
        };
        Ok(ComputeTags::new(
            self.role,
            vec![ComputeTagData {
                j0,
                ciphertext: Box::pin(ciphertext),
                aad,
            }],
            ghash.clone(),
            0,
        ))
    }

    /// Verifies the tags for the provided ciphertexts.
    ///
    /// Ciphertexts are only authenticated from the leader's perspective.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `data` - Tag data associated with `tags`.
    /// * `ciphertexts` - Ciphertexts to verify the tags for.
    /// * `tags` - Tags to verify.
    pub(crate) fn verify_tags(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        data: Vec<TagData>,
        ciphertexts: Vec<Vec<u8>>,
        tags: Vec<Vec<u8>>,
    ) -> Result<VerifyTags, AeadError> {
        let State::Ready { j0s, ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in ready state to verify tags"));
        };

        if ciphertexts.len() != data.len() {
            return Err(AeadError::tag("ciphertext and data length mismatch"));
        } else if ciphertexts.len() != tags.len() {
            return Err(AeadError::tag("ciphertext and tag length mismatch"));
        } else if ciphertexts.len() > j0s.len() {
            return Err(AeadError::tag("ciphertext length exceeds allocated"));
        }

        let mut tag_data = Vec::with_capacity(ciphertexts.len());
        for ((ciphertext, data), tag) in ciphertexts.into_iter().zip(data).zip(tags) {
            let explicit_nonce: [u8; 8] =
                data.explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
                    AeadError::cipher(format!(
                        "explicit nonce length: expected {}, got {}",
                        8,
                        nonce.len()
                    ))
                })?;
            let (j0, j0_shared) = j0s.pop().expect("j0 length was checked");

            assign_j0(vm, j0, explicit_nonce)?;

            tag_data.push(VerifyTagData {
                j0: j0_shared,
                ciphertext,
                aad: data.aad,
                tag,
                release: None,
            });
        }

        let tags = VerifyTags::new(self.role, tag_data, ghash.clone(), 0);

        Ok(tags)
    }

    /// Verifies a TLS 1.3 tag using a preprocessed J0 share.
    pub(crate) fn verify_tag_tls13_preallocated(
        &mut self,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        tag: Vec<u8>,
        j0: OneTimePadShared<[u8; 16]>,
        release: Option<Vec<u8>>,
    ) -> Result<VerifyTags, AeadError> {
        let State::Ready { ghash, .. } = &mut self.state else {
            return Err(AeadError::state(
                "must be in ready state to verify TLS 1.3 tag",
            ));
        };
        Ok(VerifyTags::new(
            self.role,
            vec![VerifyTagData {
                j0,
                ciphertext,
                aad,
                tag,
                release,
            }],
            ghash.clone(),
            0,
        ))
    }
}

fn assign_j0(
    vm: &mut dyn Vm<Binary>,
    j0: CtrBlock<Nonce, Ctr, Block>,
    explicit_nonce: [u8; 8],
) -> Result<(), AeadError> {
    vm.assign(j0.explicit_nonce, explicit_nonce)?;
    vm.commit(j0.explicit_nonce)?;
    vm.assign(j0.counter, 1u32.to_be_bytes())?;
    vm.commit(j0.counter)?;

    Ok(())
}

/// Assigns a J0 block's counter, leaving its nonce alone.
///
/// The TLS 1.3 counterpart to [`assign_j0`]. There the nonce is a public value
/// read off the wire and assigned here; in TLS 1.3 it is `iv XOR seq`, computed
/// inside the VM and already committed by whoever derived it, so assigning it
/// again would double-commit. Only the counter — always 1 for J0, per NIST
/// SP 800-38D — is set here.
#[allow(dead_code)]
fn assign_j0_counter(
    vm: &mut dyn Vm<Binary>,
    j0: CtrBlock<Nonce, Ctr, Block>,
) -> Result<(), AeadError> {
    vm.assign(j0.counter, 1u32.to_be_bytes())?;
    vm.commit(j0.counter)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        aead::{AeadInPlace, NewAead},
        Aes128Gcm,
    };
    use mpz_common::context::test_st_context;
    use mpz_core::Block;
    use mpz_ideal_vm::IdealVm;
    use mpz_memory_core::binary::U8;
    use mpz_share_conversion::ideal::ideal_share_convert;
    use rand::{rngs::StdRng, SeedableRng};
    use rstest::*;

    static SHORT_MSG: &[u8] = b"hello world";
    static LONG_MSG: &[u8] = b"this message exceeds one block in length";

    #[derive(Clone, Copy)]
    struct Vars {
        key: Array<U8, 16>,
        iv: Array<U8, 4>,
    }

    #[rstest]
    #[case::short(SHORT_MSG, 1)]
    #[case::long(LONG_MSG, 1)]
    #[case::short_multiple(SHORT_MSG, 3)]
    #[case::long_multiple(LONG_MSG, 3)]
    #[tokio::test]
    async fn test_aes_gcm_encrypt(#[case] msg: &[u8], #[case] count: usize) {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let key = [42u8; 16];
        let iv = [0u8; 4];

        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);

        leader.alloc(&mut vm_0, count, 256).unwrap();
        follower.alloc(&mut vm_1, count, 256).unwrap();

        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        for i in 0u64..count as u64 {
            let explicit_nonce = i.to_be_bytes().to_vec();
            let (msg_0, ct_0) = leader
                .apply_keystream(&mut vm_0, explicit_nonce.clone(), msg.len())
                .unwrap();
            let (msg_1, ct_1) = follower
                .apply_keystream(&mut vm_1, explicit_nonce.clone(), msg.len())
                .unwrap();

            vm_0.assign(msg_0, msg.to_vec()).unwrap();
            vm_0.commit(msg_0).unwrap();

            vm_1.commit(msg_1).unwrap();

            let ct_0 = vm_0.decode(ct_0).unwrap();
            let ct_1 = vm_1.decode(ct_1).unwrap();

            run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

            let ct_0 = ct_0.await.unwrap();
            let ct_1 = ct_1.await.unwrap();

            let (expected, _) = expected(&key, &iv, &explicit_nonce, msg, &[]);
            assert_eq!(ct_0, expected);
            assert_eq!(ct_1, expected);
        }
    }

    #[rstest]
    #[case::short(SHORT_MSG, 1)]
    #[case::long(LONG_MSG, 1)]
    #[case::short_multiple(SHORT_MSG, 3)]
    #[case::long_multiple(LONG_MSG, 3)]
    #[tokio::test]
    async fn test_aes_gcm_decrypt(#[case] msg: &[u8], #[case] count: usize) {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let key = [42u8; 16];
        let iv = [0u8; 4];

        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);

        leader.alloc(&mut vm_0, count, 256).unwrap();
        follower.alloc(&mut vm_1, count, 256).unwrap();

        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        for i in 0u64..count as u64 {
            let explicit_nonce = i.to_be_bytes().to_vec();
            let (ct, _) = expected(&key, &iv, &explicit_nonce, msg, &[]);

            let (ct_0, msg_0) = leader
                .apply_keystream(&mut vm_0, explicit_nonce.clone(), ct.len())
                .unwrap();
            let (ct_1, msg_1) = follower
                .apply_keystream(&mut vm_1, explicit_nonce.clone(), ct.len())
                .unwrap();

            vm_0.assign(ct_0, ct.clone()).unwrap();
            vm_0.commit(ct_0).unwrap();

            vm_1.commit(ct_1).unwrap();

            let msg_0 = vm_0.decode(msg_0).unwrap();
            let msg_1 = vm_1.decode(msg_1).unwrap();

            run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

            let msg_0 = msg_0.await.unwrap();
            let msg_1 = msg_1.await.unwrap();

            assert_eq!(&msg_0, msg);
            assert_eq!(&msg_1, msg);
        }
    }

    /// Joint AES-GCM driven by a TLS 1.3 secret nonce must produce the same
    /// ciphertext as a local AES-128-GCM using `nonce = iv XOR seq`.
    ///
    /// This is the property that lets the 1.3 record layer stop decoding the
    /// traffic keys: the 12-byte IV stays a secret-shared VM reference, the nonce
    /// is derived from it inside the VM, and neither party ever holds the key in
    /// the clear — yet the output matches the reference cipher byte for byte.
    #[rstest]
    #[case::short_seq0(SHORT_MSG, 0)]
    #[case::long_seq0(LONG_MSG, 0)]
    #[case::long_seq5(LONG_MSG, 5)]
    #[case::long_seq_high(LONG_MSG, 0x0102_0304_0506_0708)]
    #[tokio::test]
    async fn test_aes_gcm_tls13_secret_nonce(#[case] msg: &[u8], #[case] seq: u64) {
        use crate::tls13::nonce::split_iv_and_derive_nonce;

        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let key = [42u8; 16];
        let iv: [u8; 12] = [9u8; 12];

        let mut vm_0 = IdealVm::new();
        let mut vm_1 = IdealVm::new();

        // Both parties hold the key and the full 12-byte IV as VM references.
        // Marked public here only because IdealVm needs a concrete value; the
        // point under test is that neither is ever decoded.
        let setup = |vm: &mut IdealVm| {
            let key_ref = vm.alloc::<Array<U8, 16>>().unwrap();
            vm.mark_public(key_ref).unwrap();
            vm.assign(key_ref, key).unwrap();
            vm.commit(key_ref).unwrap();

            let iv_ref = vm.alloc::<Array<U8, 12>>().unwrap();
            vm.mark_public(iv_ref).unwrap();
            vm.assign(iv_ref, iv).unwrap();
            vm.commit(iv_ref).unwrap();

            let (prefix, nonce) = split_iv_and_derive_nonce(vm, iv_ref, seq).unwrap();
            (key_ref, prefix, nonce)
        };

        let (key_0, prefix_0, nonce_0) = setup(&mut vm_0);
        let (key_1, prefix_1, nonce_1) = setup(&mut vm_1);

        let mut rng = StdRng::seed_from_u64(0);
        let (c_0, c_1) = ideal_share_convert(Block::random(&mut rng));
        let mut leader = MpcAesGcm::new(c_0, Role::Leader);
        let mut follower = MpcAesGcm::new(c_1, Role::Follower);

        leader.set_key(key_0);
        leader.set_iv(prefix_0);
        follower.set_key(key_1);
        follower.set_iv(prefix_1);

        let (msg_0, ct_0) = leader
            .apply_keystream_tls13(&mut vm_0, nonce_0, msg.len())
            .unwrap();
        let (msg_1, ct_1) = follower
            .apply_keystream_tls13(&mut vm_1, nonce_1, msg.len())
            .unwrap();

        vm_0.assign(msg_0, msg.to_vec()).unwrap();
        vm_0.commit(msg_0).unwrap();
        vm_1.commit(msg_1).unwrap();

        let ct_0 = vm_0.decode(ct_0).unwrap();
        let ct_1 = vm_1.decode(ct_1).unwrap();

        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        let ct_0 = ct_0.await.unwrap();
        let ct_1 = ct_1.await.unwrap();

        // The reference nonce, per RFC 8446 section 5.3.
        let mut reference_nonce = iv;
        for (n, s) in reference_nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }
        let (want, _) = expected(&key, &reference_nonce[..4], &reference_nonce[4..], msg, &[]);

        assert_eq!(ct_0, want, "leader ciphertext (seq={seq})");
        assert_eq!(ct_1, want, "follower ciphertext (seq={seq})");
        assert_ne!(ct_0, msg, "the keystream must actually have been applied");
    }

    fn create_vm(key: [u8; 16], iv: [u8; 4]) -> ((impl Vm<Binary>, Vars), (impl Vm<Binary>, Vars)) {
        let mut vm_0 = IdealVm::new();
        let mut vm_1 = IdealVm::new();

        let key_ref_0 = vm_0.alloc::<Array<U8, 16>>().unwrap();
        vm_0.mark_public(key_ref_0).unwrap();
        vm_0.assign(key_ref_0, key).unwrap();
        vm_0.commit(key_ref_0).unwrap();

        let key_ref_1 = vm_1.alloc::<Array<U8, 16>>().unwrap();
        vm_1.mark_public(key_ref_1).unwrap();
        vm_1.assign(key_ref_1, key).unwrap();
        vm_1.commit(key_ref_1).unwrap();

        let iv_ref_0 = vm_0.alloc::<Array<U8, 4>>().unwrap();
        vm_0.mark_public(iv_ref_0).unwrap();
        vm_0.assign(iv_ref_0, iv).unwrap();
        vm_0.commit(iv_ref_0).unwrap();

        let iv_ref_1 = vm_1.alloc::<Array<U8, 4>>().unwrap();
        vm_1.mark_public(iv_ref_1).unwrap();
        vm_1.assign(iv_ref_1, iv).unwrap();
        vm_1.commit(iv_ref_1).unwrap();

        (
            (
                vm_0,
                Vars {
                    key: key_ref_0,
                    iv: iv_ref_0,
                },
            ),
            (
                vm_1,
                Vars {
                    key: key_ref_1,
                    iv: iv_ref_1,
                },
            ),
        )
    }

    fn create_pair(vars_0: Vars, vars_1: Vars) -> (MpcAesGcm, MpcAesGcm) {
        let mut rng = StdRng::seed_from_u64(0);
        let (c_0, c_1) = ideal_share_convert(Block::random(&mut rng));
        let mut leader = MpcAesGcm::new(c_0, Role::Leader);
        let mut follower = MpcAesGcm::new(c_1, Role::Follower);

        leader.set_key(vars_0.key);
        leader.set_iv(vars_0.iv);

        follower.set_key(vars_1.key);
        follower.set_iv(vars_1.iv);

        (leader, follower)
    }

    async fn run_vms(
        vm_0: &mut (dyn Vm<Binary> + Send),
        ctx_0: &mut Context,
        vm_1: &mut (dyn Vm<Binary> + Send),
        ctx_1: &mut Context,
    ) {
        tokio::join!(
            async {
                vm_0.execute_all(ctx_0).await.unwrap();
            },
            async {
                vm_1.execute_all(ctx_1).await.unwrap();
            }
        );
    }

    fn expected(
        key: &[u8],
        iv: &[u8],
        explicit_nonce: &[u8],
        msg: &[u8],
        aad: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let key: [u8; 16] = key.try_into().unwrap();
        let aes = Aes128Gcm::new(&key.into());

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(iv);
        nonce[4..].copy_from_slice(explicit_nonce);

        let mut payload = msg.to_vec();
        let tag = aes
            .encrypt_in_place_detached(&nonce.into(), aad, &mut payload)
            .unwrap();

        (payload, tag.to_vec())
    }
}

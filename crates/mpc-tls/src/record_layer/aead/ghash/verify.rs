use std::sync::Arc;

use async_trait::async_trait;
use futures::{stream::FuturesOrdered, StreamExt};
use hmac::{Hmac, Mac};
use mpz_common::{Context, Task};
use serde::{Deserialize, Serialize};
use serio::{stream::IoStreamExt, SinkExt};
use sha2::Sha256;

use crate::{
    decode::OneTimePadShared,
    record_layer::aead::{
        ghash::{build_ghash_data, Ghash, TagShare},
        AeadError,
    },
    Role,
};

pub(crate) struct VerifyTagData {
    pub(crate) j0: OneTimePadShared<[u8; 16]>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) release: Option<Vec<u8>>,
    pub(crate) release_context: Vec<u8>,
}

#[must_use = "verify tags operation must be awaited"]
pub(crate) struct VerifyTags {
    role: Role,
    data: Vec<VerifyTagData>,
    /// MPC implementation to use for computing GHASH.
    ghash: Arc<dyn Ghash + Send + Sync>,
    key_index: usize,
}

impl VerifyTags {
    pub(crate) fn new(
        role: Role,
        data: Vec<VerifyTagData>,
        ghash: Arc<dyn Ghash + Send + Sync>,
        key_index: usize,
    ) -> Self {
        Self {
            role,
            data,
            ghash,
            key_index,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ReleaseCapsule {
    ciphertext: Vec<u8>,
    commitment: [u8; 32],
}

fn release_pad(tag_share: &[u8; 16], key_index: usize, context: &[u8], len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(len);
    for counter in 0u32.. {
        let mut mac = Hmac::<Sha256>::new_from_slice(tag_share).expect("HMAC accepts any key size");
        mac.update(b"tlsn tls13 authenticated release pad");
        mac.update(&(key_index as u64).to_be_bytes());
        mac.update(&(context.len() as u64).to_be_bytes());
        mac.update(context);
        mac.update(&counter.to_be_bytes());
        output.extend_from_slice(&mac.finalize().into_bytes());
        if output.len() >= len {
            output.truncate(len);
            return output;
        }
    }
    unreachable!("the unbounded counter produces enough output")
}

fn release_commitment(
    tag_share: &[u8; 16],
    key_index: usize,
    context: &[u8],
    release: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(tag_share).expect("HMAC accepts any key size");
    mac.update(b"tlsn tls13 authenticated release commitment");
    mac.update(&(key_index as u64).to_be_bytes());
    mac.update(&(context.len() as u64).to_be_bytes());
    mac.update(context);
    mac.update(&(release.len() as u64).to_be_bytes());
    mac.update(release);
    mac.finalize().into_bytes().into()
}

fn seal_release(
    tag_share: &[u8; 16],
    key_index: usize,
    context: &[u8],
    release: Vec<u8>,
) -> ReleaseCapsule {
    let pad = release_pad(tag_share, key_index, context, release.len());
    let ciphertext = release.iter().zip(pad).map(|(a, b)| a ^ b).collect();
    ReleaseCapsule {
        ciphertext,
        commitment: release_commitment(tag_share, key_index, context, &release),
    }
}

fn prepare_release_message(
    tag_shares: &[TagShare],
    key_index: usize,
    releases: Vec<Option<Vec<u8>>>,
    contexts: &[Vec<u8>],
) -> (Vec<Option<TagShare>>, Vec<Option<ReleaseCapsule>>) {
    tag_shares
        .iter()
        .zip(releases)
        .zip(contexts)
        .map(|((share, release), context)| match release {
            Some(release) => (None, Some(seal_release(&share.0, key_index, context, release))),
            None => (Some(share.clone()), None),
        })
        .unzip()
}

fn open_release(
    expected_tag_share: &[u8; 16],
    key_index: usize,
    context: &[u8],
    capsule: ReleaseCapsule,
) -> Result<Vec<u8>, AeadError> {
    let pad = release_pad(expected_tag_share, key_index, context, capsule.ciphertext.len());
    let release = capsule
        .ciphertext
        .into_iter()
        .zip(pad)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();
    if capsule.commitment != release_commitment(expected_tag_share, key_index, context, &release) {
        return Err(AeadError::tag("failed to verify tag for release"));
    }
    Ok(release)
}

#[async_trait]
impl Task for VerifyTags {
    type Output = Result<Vec<Vec<u8>>, AeadError>;

    async fn run(self, ctx: &mut Context) -> Self::Output {
        let Self {
            role,
            mut data,
            ghash,
            key_index,
        } = self;

        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut j0_shares = Vec::with_capacity(data.len());
        {
            let mut futs = FuturesOrdered::from_iter(data.iter_mut().map(|data| &mut data.j0));
            while let Some(j0_share) = futs.next().await.transpose().map_err(AeadError::tag)? {
                j0_shares.push(j0_share);
            }
        }

        let mut tag_shares = Vec::with_capacity(data.len());
        let mut tags = Vec::with_capacity(data.len());
        let mut releases = Vec::with_capacity(data.len());
        let mut release_contexts = Vec::with_capacity(data.len());

        for (mut tag_share, data) in j0_shares.into_iter().zip(data) {
            let ghash_share = ghash
                .compute(key_index, &build_ghash_data(data.aad, data.ciphertext))
                .map_err(AeadError::tag)?;
            tag_share
                .iter_mut()
                .zip(ghash_share)
                .for_each(|(a, b)| *a ^= b);

            tag_shares.push(TagShare(tag_share));
            tags.push(data.tag);
            releases.push(data.release);
            release_contexts.push(data.release_context);
        }

        let io = ctx.io_mut();
        match role {
            Role::Leader => {
                let (peer_tag_shares, capsules): (
                    Vec<Option<TagShare>>,
                    Vec<Option<ReleaseCapsule>>,
                ) = io.expect_next().await.map_err(AeadError::tag)?;

                if peer_tag_shares.len() != tag_shares.len() || capsules.len() != tag_shares.len() {
                    return Err(AeadError::tag("follower tag shares length mismatch"));
                }

                let mut released = Vec::new();
                for ((((leader_share, follower_share), tag), capsule), context) in tag_shares
                    .into_iter()
                    .zip(peer_tag_shares)
                    .zip(tags)
                    .zip(capsules)
                    .zip(release_contexts)
                {
                    let expected_follower_share: [u8; 16] = tag
                        .iter()
                        .zip(leader_share.0)
                        .map(|(tag, share)| tag ^ share)
                        .collect::<Vec<_>>()
                        .try_into()
                        .map_err(|_| AeadError::tag("invalid TLS tag length"))?;
                    if let Some(capsule) = capsule {
                        if follower_share.is_some() {
                            return Err(AeadError::tag(
                                "follower disclosed a gated TLS 1.3 tag share",
                            ));
                        }
                        released.push(open_release(&expected_follower_share, key_index, &context, capsule)?);
                    } else {
                        let follower_share = follower_share
                            .ok_or_else(|| AeadError::tag("follower tag share is missing"))?;
                        if expected_follower_share != follower_share.0 {
                            return Err(AeadError::tag("failed to verify tags"));
                        }
                    }
                }
                Ok(released)
            }
            Role::Follower => {
                let (peer_tag_shares, capsules) =
                    prepare_release_message(&tag_shares, key_index, releases, &release_contexts);
                io.send((peer_tag_shares, capsules))
                    .await
                    .map_err(AeadError::tag)?;
                Ok(Vec::new())
            }
        }
    }

    async fn run_boxed(self: Box<Self>, ctx: &mut Context) -> Self::Output {
        self.run(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::{open_release, prepare_release_message, seal_release};
    use crate::record_layer::aead::ghash::TagShare;

    #[test]
    fn authenticated_release_opens_only_with_the_expected_tag_share() {
        let tag_share = [7u8; 16];
        let release = vec![42u8; 97];
        let context = b"session-a/received/0/4";
        let capsule = seal_release(&tag_share, 7, context, release.clone());
        assert_eq!(open_release(&tag_share, 7, context, capsule).unwrap(), release);

        let capsule = seal_release(&tag_share, 7, context, release);
        assert!(open_release(&tag_share, 8, context, capsule).is_err());

        let capsule = seal_release(&tag_share, 7, context, vec![42u8; 97]);
        let mut wrong_share = tag_share;
        wrong_share[0] ^= 1;
        assert!(open_release(&wrong_share, 7, context, capsule).is_err());

        let capsule = seal_release(&tag_share, 7, context, vec![42u8; 97]);
        assert!(open_release(&tag_share, 7, b"session-b/received/0/4", capsule).is_err());
    }

    #[test]
    fn gated_release_withholds_the_raw_tag_share() {
        let tag_shares = vec![TagShare([7u8; 16]), TagShare([9u8; 16])];
        let contexts = vec![b"record-0".to_vec(), b"record-1".to_vec()];
        let (peer_tag_shares, capsules) =
            prepare_release_message(&tag_shares, 7, vec![Some(vec![42u8; 97]), None], &contexts);

        assert!(peer_tag_shares[0].is_none());
        assert!(capsules[0].is_some());
        assert_eq!(peer_tag_shares[1].as_ref().unwrap().0, [9u8; 16]);
        assert!(capsules[1].is_none());
    }
}

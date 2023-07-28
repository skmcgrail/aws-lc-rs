// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::{Aad, Algorithm, AlgorithmID, Nonce, Tag};
use crate::iv::FixedLength;
use std::mem::MaybeUninit;

use crate::aead::aead_ctx::AeadCtx;
use crate::cipher::aes::{AES_128_KEY_LEN, AES_256_KEY_LEN};
use crate::error::Unspecified;
use aws_lc::EVP_AEAD_CTX_seal_scatter;
use std::ptr::null;

use super::{NONCE_LEN, TAG_LEN};

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_separate(
    key: &AeadCtx,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(Nonce, Tag), Unspecified> {
    let aead_ctx = key.as_ptr();

    let aad_slice = aad.as_ref();
    let mut tag = [0u8; TAG_LEN];
    let mut out_tag_len = MaybeUninit::<usize>::uninit();
    {
        let nonce = nonce.as_ref();
        if 1 != unsafe {
            EVP_AEAD_CTX_seal_scatter(
                aead_ctx,
                in_out.as_mut_ptr(),
                tag.as_mut_ptr(),
                out_tag_len.as_mut_ptr(),
                tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                in_out.len(),
                null(),
                0usize,
                aad_slice.as_ptr(),
                aad_slice.len(),
            )
        } {
            return Err(Unspecified);
        }
    }
    debug_assert_eq!(unsafe { out_tag_len.assume_init() }, tag.len());
    Ok((nonce, Tag(tag)))
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_separate_randnonce(
    key: &AeadCtx,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(Nonce, Tag), Unspecified> {
    let aead_ctx = key.as_ptr();

    let aad_slice = aad.as_ref();
    let mut tag_buffer = [0u8; TAG_LEN + NONCE_LEN];

    let mut out_tag_len = MaybeUninit::<usize>::uninit();

    if 1 != unsafe {
        EVP_AEAD_CTX_seal_scatter(
            aead_ctx,
            in_out.as_mut_ptr(),
            tag_buffer.as_mut_ptr(),
            out_tag_len.as_mut_ptr(),
            TAG_LEN + NONCE_LEN,
            null(),
            0,
            in_out.as_ptr(),
            in_out.len(),
            null(),
            0usize,
            aad_slice.as_ptr(),
            aad_slice.len(),
        )
    } {
        return Err(Unspecified);
    }

    let nonce = Nonce(FixedLength::<NONCE_LEN>::try_from(
        &tag_buffer[TAG_LEN..TAG_LEN + NONCE_LEN],
    )?);

    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&tag_buffer[..TAG_LEN]);

    Ok((nonce, Tag(tag)))
}

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_128_GCM: Algorithm = Algorithm {
    init: init_128_aead,
    key_len: AES_128_KEY_LEN,
    id: AlgorithmID::AES_128_GCM,
    max_input_len: u64::MAX,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_256_GCM: Algorithm = Algorithm {
    init: init_256_aead,
    key_len: AES_256_KEY_LEN,
    id: AlgorithmID::AES_256_GCM,
    max_input_len: u64::MAX,
};

#[inline]
fn init_128_aead(key: &[u8]) -> Result<AeadCtx, Unspecified> {
    AeadCtx::aes_128_gcm(key)
}

#[inline]
fn init_256_aead(key: &[u8]) -> Result<AeadCtx, Unspecified> {
    AeadCtx::aes_256_gcm(key)
}

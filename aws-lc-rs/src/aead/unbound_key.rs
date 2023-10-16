// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use super::{AeadCtx, Algorithm, MAX_KEY_LEN};
use crate::aead::{Nonce, Tag, MAX_TAG_LEN, NONCE_LEN, TAG_LEN};
use crate::{error::Unspecified, hkdf};
use aws_lc::{EVP_AEAD_CTX_open, EVP_AEAD_CTX_seal};
use aws_lc::{EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal_scatter};
use core::fmt::Debug;
use core::ops::RangeFrom;
use std::mem::MaybeUninit;

/// An AEAD key without a designated role or nonce sequence.
pub struct UnboundKey {
    inner: AeadCtx,
    algorithm: &'static Algorithm,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    /// # Errors
    /// `error::Unspecified` if `key_bytes.len() != algorithm.key_len()`.
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        Ok(Self {
            inner: (algorithm.init)(key_bytes)?,
            algorithm,
        })
    }

    /// The key's AEAD algorithm.
    #[inline]
    #[must_use]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    #[inline]
    pub(crate) fn open_within<'in_out>(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        let in_prefix_len = ciphertext_and_tag.start;
        let ciphertext_and_tag_len = in_out.len().checked_sub(in_prefix_len).ok_or(Unspecified)?;
        let ciphertext_len = ciphertext_and_tag_len
            .checked_sub(TAG_LEN)
            .ok_or(Unspecified)?;

        self.open_combined(nonce, aad, &mut in_out[in_prefix_len..])?;

        // shift the plaintext to the left
        in_out.copy_within(in_prefix_len..in_prefix_len + ciphertext_len, 0);

        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    #[inline]
    pub(crate) fn open_combined(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        unsafe {
            let aead_ctx = self.inner.as_ref();
            let nonce = nonce.as_ref();

            let plaintext_len = in_out.len().checked_sub(TAG_LEN).ok_or(Unspecified)?;
            self.check_per_nonce_max_bytes(plaintext_len)?;

            let mut out_len = MaybeUninit::<usize>::uninit();
            if 1 != EVP_AEAD_CTX_open(
                *aead_ctx.as_const(),
                in_out.as_mut_ptr(),
                out_len.as_mut_ptr(),
                plaintext_len,
                nonce.as_ptr(),
                NONCE_LEN,
                in_out.as_ptr(),
                plaintext_len + TAG_LEN,
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(Unspecified);
            }

            Ok(())
        }
    }

    #[inline]
    pub(crate) fn open_separate_gather(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_ciphertext: &[u8],
        in_tag: &[u8],
        out_plaintext: &mut [u8],
    ) -> Result<(), Unspecified> {
        self.check_per_nonce_max_bytes(in_ciphertext.len())?;

        // ensure that the lengths match
        {
            let actual = in_ciphertext.len();
            let expected = out_plaintext.len();

            if actual != expected {
                return Err(Unspecified);
            }
        }

        unsafe {
            let aead_ctx = self.inner.as_ref();
            let nonce = nonce.as_ref();

            if 1 != EVP_AEAD_CTX_open_gather(
                *aead_ctx.as_const(),
                out_plaintext.as_mut_ptr(),
                nonce.as_ptr(),
                nonce.len(),
                in_ciphertext.as_ptr(),
                in_ciphertext.len(),
                in_tag.as_ptr(),
                in_tag.len(),
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(Unspecified);
            }
            Ok(())
        }
    }

    #[inline]
    pub(crate) fn seal_combined<InOut>(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        unsafe {
            let aead_ctx = self.inner.as_ref();
            let nonce = nonce.as_ref();

            let plaintext_len = in_out.as_mut().len();

            self.check_per_nonce_max_bytes(plaintext_len)?;

            in_out.extend([0u8; TAG_LEN].iter());

            let mut out_len = MaybeUninit::<usize>::uninit();
            let mut_in_out = in_out.as_mut();

            if 1 != EVP_AEAD_CTX_seal(
                *aead_ctx.as_const(),
                mut_in_out.as_mut_ptr(),
                out_len.as_mut_ptr(),
                plaintext_len + TAG_LEN,
                nonce.as_ptr(),
                NONCE_LEN,
                mut_in_out.as_ptr(),
                plaintext_len,
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(Unspecified);
            }

            Ok(())
        }
    }

    #[inline]
    pub(crate) fn seal_separate(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified> {
        let mut tag = [0; MAX_TAG_LEN];
        self.seal_separate_scatter(nonce, aad, in_out, &[], &mut tag)?;
        Ok(Tag(tag))
    }

    #[inline]
    pub(crate) fn seal_separate_scatter(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified> {
        // ensure that the extra lengths match
        {
            let actual = extra_in.len() + MAX_TAG_LEN;
            let expected = extra_out_and_tag.len();

            if actual != expected {
                return Err(Unspecified);
            }
        }

        unsafe {
            let aead_ctx = self.inner.as_ref();
            let nonce = nonce.as_ref();
            let mut out_tag_len = extra_out_and_tag.len();

            self.check_per_nonce_max_bytes(in_out.len() + extra_in.len())?;

            if 1 != EVP_AEAD_CTX_seal_scatter(
                *aead_ctx.as_const(),
                in_out.as_mut_ptr(),
                extra_out_and_tag.as_mut_ptr(),
                &mut out_tag_len,
                extra_out_and_tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                in_out.len(),
                extra_in.as_ptr(),
                extra_in.len(),
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(Unspecified);
            }
            Ok(())
        }
    }

    #[inline]
    fn check_per_nonce_max_bytes(&self, in_out_len: usize) -> Result<(), Unspecified> {
        if in_out_len as u64 > self.algorithm.max_input_len {
            return Err(Unspecified);
        }
        Ok(())
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}

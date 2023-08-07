// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::cipher::chacha;

use crate::cipher::aes::{AES_128_KEY_LEN, AES_256_KEY_LEN};
use crate::error::Unspecified;
use aws_lc::{
    evp_aead_direction_t, evp_aead_direction_t_evp_aead_open, evp_aead_direction_t_evp_aead_seal,
    EVP_AEAD_CTX_cleanup, EVP_AEAD_CTX_init, EVP_AEAD_CTX_init_with_direction, EVP_AEAD_CTX_zero,
    EVP_aead_aes_128_gcm, EVP_aead_aes_128_gcm_randnonce, EVP_aead_aes_128_gcm_tls12,
    EVP_aead_aes_128_gcm_tls13, EVP_aead_aes_256_gcm, EVP_aead_aes_256_gcm_randnonce,
    EVP_aead_aes_256_gcm_tls12, EVP_aead_aes_256_gcm_tls13, EVP_aead_chacha20_poly1305,
    EVP_AEAD_CTX,
};
use std::mem::MaybeUninit;
use std::ptr::null_mut;

pub(crate) enum AeadDirection {
    Open,
    Seal,
}

impl From<AeadDirection> for evp_aead_direction_t {
    fn from(value: AeadDirection) -> Self {
        match value {
            AeadDirection::Open => evp_aead_direction_t_evp_aead_open,
            AeadDirection::Seal => evp_aead_direction_t_evp_aead_seal,
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    variant_size_differences,
    non_camel_case_types
)]
pub(crate) enum AeadCtx {
    AES_128_GCM(EVP_AEAD_CTX),
    AES_256_GCM(EVP_AEAD_CTX),

    AES_128_GCM_RANDNONCE(EVP_AEAD_CTX),
    AES_256_GCM_RANDNONCE(EVP_AEAD_CTX),

    AES_128_GCM_TLS12(EVP_AEAD_CTX),
    AES_256_GCM_TLS12(EVP_AEAD_CTX),

    AES_128_GCM_TLS13(EVP_AEAD_CTX),
    AES_256_GCM_TLS13(EVP_AEAD_CTX),

    CHACHA20_POLY1305(EVP_AEAD_CTX),
}

unsafe impl Send for AeadCtx {}
unsafe impl Sync for AeadCtx {}

impl AeadCtx {
    pub(crate) fn aes_128_gcm(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_128_GCM(AeadCtx::aes_128_context(
            EVP_aead_aes_128_gcm,
            key_bytes,
            tag_len,
            None,
        )?))
    }

    pub(crate) fn aes_256_gcm(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_256_GCM(AeadCtx::aes_256_context(
            EVP_aead_aes_256_gcm,
            key_bytes,
            tag_len,
            None,
        )?))
    }

    pub(crate) fn aes_128_gcm_randnonce(
        key_bytes: &[u8],
        tag_len: usize,
        nonce_len: usize,
    ) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_128_GCM_RANDNONCE(AeadCtx::aes_128_context(
            EVP_aead_aes_128_gcm_randnonce,
            key_bytes,
            tag_len + nonce_len,
            None,
        )?))
    }

    pub(crate) fn aes_256_gcm_randnonce(
        key_bytes: &[u8],
        tag_len: usize,
        nonce_len: usize,
    ) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_256_GCM_RANDNONCE(AeadCtx::aes_256_context(
            EVP_aead_aes_256_gcm_randnonce,
            key_bytes,
            tag_len + nonce_len,
            None,
        )?))
    }

    pub(crate) fn aes_128_gcm_tls12(
        key_bytes: &[u8],
        tag_len: usize,
        direction: AeadDirection,
    ) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_128_GCM_TLS12(AeadCtx::aes_128_context(
            EVP_aead_aes_128_gcm_tls12,
            key_bytes,
            tag_len,
            Some(direction),
        )?))
    }

    pub(crate) fn aes_256_gcm_tls12(
        key_bytes: &[u8],
        tag_len: usize,
        direction: AeadDirection,
    ) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_256_GCM_TLS12(AeadCtx::aes_256_context(
            EVP_aead_aes_256_gcm_tls12,
            key_bytes,
            tag_len,
            Some(direction),
        )?))
    }

    pub(crate) fn aes_128_gcm_tls13(
        key_bytes: &[u8],
        tag_len: usize,
        direction: AeadDirection,
    ) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_128_GCM_TLS13(AeadCtx::aes_128_context(
            EVP_aead_aes_128_gcm_tls13,
            key_bytes,
            tag_len,
            Some(direction),
        )?))
    }

    pub(crate) fn aes_256_gcm_tls13(
        key_bytes: &[u8],
        tag_len: usize,
        direction: AeadDirection,
    ) -> Result<Self, Unspecified> {
        Ok(AeadCtx::AES_256_GCM_TLS13(AeadCtx::aes_256_context(
            EVP_aead_aes_256_gcm_tls13,
            key_bytes,
            tag_len,
            Some(direction),
        )?))
    }

    pub(crate) fn chacha20(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        if chacha::KEY_LEN != key_bytes.len() {
            return Err(Unspecified);
        }
        Ok(AeadCtx::CHACHA20_POLY1305(AeadCtx::build_context(
            EVP_aead_chacha20_poly1305,
            key_bytes,
            tag_len,
            None,
        )?))
    }

    fn aes_128_context(
        aead: unsafe extern "C" fn() -> *const aws_lc::evp_aead_st,
        key_bytes: &[u8],
        tag_len: usize,
        direction: Option<AeadDirection>,
    ) -> Result<EVP_AEAD_CTX, Unspecified> {
        if AES_128_KEY_LEN != key_bytes.len() {
            return Err(Unspecified);
        }
        AeadCtx::build_context(aead, key_bytes, tag_len, direction)
    }

    fn aes_256_context(
        aead: unsafe extern "C" fn() -> *const aws_lc::evp_aead_st,
        key_bytes: &[u8],
        tag_len: usize,
        direction: Option<AeadDirection>,
    ) -> Result<EVP_AEAD_CTX, Unspecified> {
        if AES_256_KEY_LEN != key_bytes.len() {
            return Err(Unspecified);
        }
        AeadCtx::build_context(aead, key_bytes, tag_len, direction)
    }

    fn build_context(
        aead_fn: unsafe extern "C" fn() -> *const aws_lc::evp_aead_st,
        key_bytes: &[u8],
        tag_len: usize,
        direction: Option<AeadDirection>,
    ) -> Result<EVP_AEAD_CTX, Unspecified> {
        let mut aead_ctx = MaybeUninit::<EVP_AEAD_CTX>::uninit();
        let aead = unsafe { aead_fn() };

        if 1 != match direction {
            Some(direction) => unsafe {
                EVP_AEAD_CTX_init_with_direction(
                    aead_ctx.as_mut_ptr(),
                    aead,
                    key_bytes.as_ptr(),
                    key_bytes.len(),
                    tag_len,
                    direction.into(),
                )
            },
            None => unsafe {
                EVP_AEAD_CTX_init(
                    aead_ctx.as_mut_ptr(),
                    aead,
                    key_bytes.as_ptr(),
                    key_bytes.len(),
                    tag_len,
                    null_mut(),
                )
            },
        } {
            return Err(Unspecified);
        }
        Ok(unsafe { aead_ctx.assume_init() })
    }
}

impl AsMut<EVP_AEAD_CTX> for AeadCtx {
    fn as_mut(&mut self) -> &mut EVP_AEAD_CTX {
        match self {
            AeadCtx::AES_128_GCM(ctx)
            | AeadCtx::AES_256_GCM(ctx)
            | AeadCtx::AES_128_GCM_RANDNONCE(ctx)
            | AeadCtx::AES_256_GCM_RANDNONCE(ctx)
            | AeadCtx::AES_128_GCM_TLS12(ctx)
            | AeadCtx::AES_256_GCM_TLS12(ctx)
            | AeadCtx::AES_128_GCM_TLS13(ctx)
            | AeadCtx::AES_256_GCM_TLS13(ctx)
            | AeadCtx::CHACHA20_POLY1305(ctx) => ctx,
        }
    }
}

impl AsRef<EVP_AEAD_CTX> for AeadCtx {
    fn as_ref(&self) -> &EVP_AEAD_CTX {
        match self {
            AeadCtx::AES_128_GCM(ctx)
            | AeadCtx::AES_256_GCM(ctx)
            | AeadCtx::AES_128_GCM_RANDNONCE(ctx)
            | AeadCtx::AES_256_GCM_RANDNONCE(ctx)
            | AeadCtx::AES_128_GCM_TLS12(ctx)
            | AeadCtx::AES_256_GCM_TLS12(ctx)
            | AeadCtx::AES_128_GCM_TLS13(ctx)
            | AeadCtx::AES_256_GCM_TLS13(ctx)
            | AeadCtx::CHACHA20_POLY1305(ctx) => ctx,
        }
    }
}

impl Drop for AeadCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_AEAD_CTX_cleanup(self.as_mut());
            EVP_AEAD_CTX_zero(self.as_mut());
        }
    }
}

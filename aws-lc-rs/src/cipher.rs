// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Block and Stream Cipher for Encryption and Decryption.
//!
//! # 🛑 Read Before Using
//!
//! This module provides access to block and stream cipher algorithms.
//! The modes provided here only provide confidentiality, but **do not**
//! provide integrity or authentication verification of ciphertext.
//!
//! These algorithms are provided solely for applications requring them
//! in order to maintain backwards compatability in legacy applications.
//!
//! If you are developing new applications requring data encryption see
//! the algorithms provided in [`aead`](crate::aead).
//!
//! # Examples
//! ```
//! use aws_lc_rs::cipher::{UnboundCipherKey, DecryptingKey, EncryptingKey, AES_128_CTR};
//!
//! let mut plaintext = Vec::from("This is a secret message!");
//!
//! let key_bytes: &[u8] = &[
//!     0xff, 0x0b, 0xe5, 0x84, 0x64, 0x0b, 0x00, 0xc8, 0x90, 0x7a, 0x4b, 0xbf, 0x82, 0x7c, 0xb6,
//!     0xd1,
//! ];
//!
//! let key = UnboundCipherKey::new(&AES_128_CTR, key_bytes).unwrap();
//! let encrypting_key = EncryptingKey::new(key).unwrap();
//! let iv = encrypting_key.encrypt(&mut plaintext).unwrap();
//!
//! let key = UnboundCipherKey::new(&AES_128_CTR, key_bytes).unwrap();
//! let decrypting_key = DecryptingKey::new(key, iv);
//! let plaintext = decrypting_key.decrypt(&mut plaintext).unwrap();
//! ```
//!

#![allow(clippy::module_name_repetitions)]

pub(crate) mod aes;
pub(crate) mod block;
pub(crate) mod chacha;

use crate::cipher::aes::{encrypt_block_aes, Aes128Key, Aes256Key};
use crate::cipher::block::Block;
use crate::cipher::chacha::ChaCha20Key;
use crate::error::Unspecified;
use crate::iv::{FixedLength, NonceIV};
use aws_lc::{
    AES_cbc_encrypt, AES_ctr128_encrypt, AES_set_decrypt_key, AES_set_encrypt_key, AES_DECRYPT,
    AES_ENCRYPT, AES_KEY,
};
use std::mem::{size_of, transmute, MaybeUninit};
use std::os::raw::c_uint;
use std::ptr;
use zeroize::Zeroize;

pub(crate) enum SymmetricCipherKey {
    Aes128 {
        raw_key: Aes128Key,
        enc_key: AES_KEY,
        dec_key: AES_KEY,
    },
    Aes256 {
        raw_key: Aes256Key,
        enc_key: AES_KEY,
        dec_key: AES_KEY,
    },
    ChaCha20 {
        raw_key: ChaCha20Key,
    },
}

unsafe impl Send for SymmetricCipherKey {}
// The AES_KEY value is only used as a `*const AES_KEY` in calls to `AES_encrypt`.
unsafe impl Sync for SymmetricCipherKey {}

impl Drop for SymmetricCipherKey {
    fn drop(&mut self) {
        // Aes128Key, Aes256Key and ChaCha20Key implement Drop separately.
        match self {
            SymmetricCipherKey::Aes128 {
                enc_key, dec_key, ..
            }
            | SymmetricCipherKey::Aes256 {
                enc_key, dec_key, ..
            } => unsafe {
                #[allow(clippy::transmute_ptr_to_ptr)]
                let enc_bytes: &mut [u8; size_of::<AES_KEY>()] = transmute(enc_key);
                enc_bytes.zeroize();
                #[allow(clippy::transmute_ptr_to_ptr)]
                let dec_bytes: &mut [u8; size_of::<AES_KEY>()] = transmute(dec_key);
                dec_bytes.zeroize();
            },
            SymmetricCipherKey::ChaCha20 { .. } => {}
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum PaddingStrategy {
    NoPadding,
    PKCS7,
}

impl OperatingMode {
    fn add_padding<InOut>(self, block_len: usize, in_out: &mut InOut) -> Result<(), Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        match self {
            OperatingMode::Block(strategy) => match strategy {
                PaddingStrategy::PKCS7 => {
                    let in_out_len = in_out.as_mut().len();
                    // This implements PKCS#7 padding scheme, used by aws-lc if we were using EVP_CIPHER API's
                    let remainder = in_out_len % block_len;
                    if remainder == 0 {
                        let block_size: u8 = block_len.try_into().map_err(|_| Unspecified)?;
                        in_out.extend(vec![block_size; block_len].iter());
                    } else {
                        let padding_size = block_len - remainder;
                        let v: u8 = padding_size.try_into().map_err(|_| Unspecified)?;
                        // Heap allocation :(
                        in_out.extend(vec![v; padding_size].iter());
                    }
                }
                PaddingStrategy::NoPadding => {}
            },
            OperatingMode::Stream => {}
        }
        Ok(())
    }

    fn remove_padding(self, block_len: usize, in_out: &mut [u8]) -> Result<&mut [u8], Unspecified> {
        match self {
            OperatingMode::Block(strategy) => match strategy {
                PaddingStrategy::PKCS7 => {
                    let block_size: u8 = block_len.try_into().map_err(|_| Unspecified)?;

                    if in_out.is_empty() || in_out.len() < block_len {
                        return Err(Unspecified);
                    }

                    let padding: u8 = in_out[in_out.len() - 1];
                    if padding == 0 || padding > block_size {
                        return Err(Unspecified);
                    }

                    for item in in_out.iter().skip(in_out.len() - padding as usize) {
                        if *item != padding {
                            return Err(Unspecified);
                        }
                    }

                    let final_len = in_out.len() - padding as usize;
                    Ok(&mut in_out[0..final_len])
                }
                PaddingStrategy::NoPadding => Ok(in_out),
            },
            OperatingMode::Stream => Ok(in_out),
        }
    }
}

#[derive(Clone, Copy)]
enum OperatingMode {
    Block(PaddingStrategy),
    Stream,
}

/// A cipher configuration description.
pub struct CipherConfig<const KEY_LEN: usize, const IV_LEN: usize, const BLOCK_LEN: usize>(
    OperatingMode,
);

/// The number of bytes in an AES 128-bit key
pub const AES_128_KEY_LEN: usize = 16;

/// The number of bytes in an AES 256-bit key
pub const AES_256_KEY_LEN: usize = 32;

/// The number of bytes for an AES initalization vector (IV)
pub const AES_IV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

pub enum BlockCipher {
    Aes128,
    Aes256,
}

pub const AES_128: BlockCipher = BlockCipher::Aes128;
pub const AES_256: BlockCipher = BlockCipher::Aes256;

pub struct UnboundCipherKey {
    cipher: &'static BlockCipher,
    key_bytes: SymmetricCipherKey,
}

impl UnboundCipherKey {
    pub fn new(
        cipher: &'static BlockCipher,
        key_bytes: &[u8],
    ) -> Result<UnboundCipherKey, Unspecified> {
        todo!()
    }
}

pub trait GenericEncryptingBlockCipherKey<T> {
    fn encrypt_with_padding<InOut>(self, in_out: &mut InOut) -> Result<T, Unspecified>
    where
        InOut: AsRef<[u8]> + for<'a> Extend<&'a u8>;

    fn encrypt_no_padding<InOut>(self, in_out: &mut InOut) -> Result<T, Unspecified>
    where
        InOut: AsRef<[u8]>;
}

pub trait GenericDecryptingBlockCipherKey {
    fn decrypt_padded<'a>(self, in_out: &'a mut [u8]) -> Result<&'a mut [u8], Unspecified>;

    fn decrypt_unpadded<InOut>(self, in_out: &mut [u8]) -> Result<(), Unspecified>
    where
        InOut: AsRef<[u8]> + for<'a> Extend<&'a u8>;
}

pub trait EncryptingBlockCipherKey: GenericEncryptingBlockCipherKey<()> {}

pub trait DecryptingBlockCipherKey: GenericDecryptingBlockCipherKey {}

pub trait EncryptingBlockCipherKeyIv: GenericEncryptingBlockCipherKey<NonceIV> {}

pub trait DecryptingBlockCipherKeyIv: GenericDecryptingBlockCipherKey {}

pub mod ecb {
    use crate::error::Unspecified;

    use super::{
        DecryptingBlockCipherKey, EncryptingBlockCipherKey, GenericDecryptingBlockCipherKey,
        GenericEncryptingBlockCipherKey, UnboundCipherKey,
    };

    pub struct EncryptingEcbKey {
        key: UnboundCipherKey,
    }

    impl EncryptingEcbKey {
        pub fn new(key: UnboundCipherKey) -> Result<EncryptingEcbKey, Unspecified> {
            todo!()
        }
    }

    impl EncryptingBlockCipherKey for EncryptingEcbKey {}

    impl GenericEncryptingBlockCipherKey<()> for EncryptingEcbKey {
        fn encrypt_with_padding<InOut>(self, in_out: &mut InOut) -> Result<(), Unspecified>
        where
            InOut: AsRef<[u8]> + for<'a> Extend<&'a u8>,
        {
            todo!()
        }

        fn encrypt_no_padding<InOut>(self, in_out: &mut InOut) -> Result<(), Unspecified>
        where
            InOut: AsRef<[u8]>,
        {
            todo!()
        }
    }

    pub struct DecryptingEcbKey {
        key: UnboundCipherKey,
    }

    impl DecryptingEcbKey {
        pub fn new(key: UnboundCipherKey) -> Result<DecryptingEcbKey, Unspecified> {
            todo!()
        }
    }

    impl DecryptingBlockCipherKey for DecryptingEcbKey {}

    impl GenericDecryptingBlockCipherKey for DecryptingEcbKey {
        fn decrypt_padded<'a>(self, in_out: &'a mut [u8]) -> Result<&'a mut [u8], Unspecified> {
            todo!()
        }

        fn decrypt_unpadded<InOut>(self, in_out: &mut [u8]) -> Result<(), Unspecified>
        where
            InOut: AsRef<[u8]> + for<'a> Extend<&'a u8>,
        {
            todo!()
        }
    }
}

pub mod cbc {
    use crate::{error::Unspecified, iv::NonceIV};

    use super::{
        DecryptingBlockCipherKeyIv, EncryptingBlockCipherKeyIv, GenericDecryptingBlockCipherKey,
        GenericEncryptingBlockCipherKey, UnboundCipherKey,
    };

    pub struct EncryptingCbcKey {
        key: UnboundCipherKey,
    }

    impl EncryptingCbcKey {
        pub fn new(key: UnboundCipherKey) -> Result<EncryptingCbcKey, Unspecified> {
            todo!()
        }
    }

    impl EncryptingBlockCipherKeyIv for EncryptingCbcKey {}

    impl GenericEncryptingBlockCipherKey<NonceIV> for EncryptingCbcKey {
        fn encrypt_with_padding<InOut>(self, in_out: &mut InOut) -> Result<NonceIV, Unspecified>
        where
            InOut: AsRef<[u8]> + for<'a> Extend<&'a u8>,
        {
            todo!()
        }

        fn encrypt_no_padding<InOut>(self, in_out: &mut InOut) -> Result<NonceIV, Unspecified>
        where
            InOut: AsRef<[u8]>,
        {
            todo!()
        }
    }

    pub struct DecryptingCbcKey {
        key: UnboundCipherKey,
    }

    impl DecryptingCbcKey {
        pub fn new(key: UnboundCipherKey, iv: NonceIV) -> Result<DecryptingCbcKey, Unspecified> {
            todo!()
        }
    }

    impl DecryptingBlockCipherKeyIv for DecryptingCbcKey {}

    impl GenericDecryptingBlockCipherKey for DecryptingCbcKey {
        fn decrypt_padded<'a>(self, in_out: &'a mut [u8]) -> Result<&'a mut [u8], Unspecified> {
            todo!()
        }

        fn decrypt_unpadded<InOut>(self, in_out: &mut [u8]) -> Result<(), Unspecified>
        where
            InOut: AsRef<[u8]> + for<'a> Extend<&'a u8>,
        {
            todo!()
        }
    }
}

pub trait EncryptingStreamBlockCipherKeyIv {
    fn encrypt(self, in_out: &mut [u8]) -> Result<NonceIV, Unspecified>;
}

pub trait DecryptingStreamBlockCipherKeyIv {
    fn decrypt(self, in_out: &mut [u8]) -> Result<(), Unspecified>;
}

pub mod ctr {
    use crate::{error::Unspecified, iv::NonceIV};

    use super::{
        DecryptingStreamBlockCipherKeyIv, EncryptingStreamBlockCipherKeyIv, UnboundCipherKey,
    };

    pub struct EncryptingCtrKey {
        key: UnboundCipherKey,
    }

    impl EncryptingCtrKey {
        pub fn new(key: UnboundCipherKey) -> Result<EncryptingCtrKey, Unspecified> {
            todo!()
        }
    }

    impl EncryptingStreamBlockCipherKeyIv for EncryptingCtrKey {
        fn encrypt(self, in_out: &mut [u8]) -> Result<NonceIV, Unspecified> {
            todo!()
        }
    }

    pub struct DecryptingCtrKey {
        key: UnboundCipherKey,
    }

    impl DecryptingCtrKey {
        pub fn new(key: UnboundCipherKey, iv: NonceIV) -> Result<DecryptingCtrKey, Unspecified> {
            todo!()
        }
    }

    impl DecryptingStreamBlockCipherKeyIv for DecryptingCtrKey {
        fn decrypt(self, in_out: &mut [u8]) -> Result<(), Unspecified> {
            todo!()
        }
    }
}

fn aes_ctr128_encrypt(key: &AES_KEY, iv: &mut [u8], block_buffer: &mut [u8], in_out: &mut [u8]) {
    let mut num = MaybeUninit::<u32>::new(0);

    unsafe {
        AES_ctr128_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            key,
            iv.as_mut_ptr(),
            block_buffer.as_mut_ptr(),
            num.as_mut_ptr(),
        );
    };

    Zeroize::zeroize(block_buffer);
}

fn aes_cbc_encrypt(key: &AES_KEY, iv: &mut [u8], in_out: &mut [u8]) {
    unsafe {
        AES_cbc_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            key,
            iv.as_mut_ptr(),
            AES_ENCRYPT,
        );
    }
}

fn aes_cbc_decrypt(key: &AES_KEY, iv: &mut [u8], in_out: &mut [u8]) {
    unsafe {
        AES_cbc_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            key,
            iv.as_mut_ptr(),
            AES_DECRYPT,
        );
    }
}

impl SymmetricCipherKey {
    pub(crate) fn aes128(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 16 {
            return Err(Unspecified);
        }

        unsafe {
            let mut enc_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                enc_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let enc_key = enc_key.assume_init();

            let mut dec_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_decrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                dec_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let dec_key = dec_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 16]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 16);
            Ok(SymmetricCipherKey::Aes128 {
                raw_key: Aes128Key(kb.assume_init()),
                enc_key,
                dec_key,
            })
        }
    }

    pub(crate) fn aes256(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 32 {
            return Err(Unspecified);
        }
        unsafe {
            let mut enc_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_encrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                enc_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let enc_key = enc_key.assume_init();

            let mut dec_key = MaybeUninit::<AES_KEY>::uninit();
            #[allow(clippy::cast_possible_truncation)]
            if 0 != AES_set_decrypt_key(
                key_bytes.as_ptr(),
                (key_bytes.len() * 8) as c_uint,
                dec_key.as_mut_ptr(),
            ) {
                return Err(Unspecified);
            }
            let dec_key = dec_key.assume_init();

            let mut kb = MaybeUninit::<[u8; 32]>::uninit();
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::Aes256 {
                raw_key: Aes256Key(kb.assume_init()),
                enc_key,
                dec_key,
            })
        }
    }

    pub(crate) fn chacha20(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() != 32 {
            return Err(Unspecified);
        }
        let mut kb = MaybeUninit::<[u8; 32]>::uninit();
        unsafe {
            ptr::copy_nonoverlapping(key_bytes.as_ptr(), kb.as_mut_ptr().cast(), 32);
            Ok(SymmetricCipherKey::ChaCha20 {
                raw_key: ChaCha20Key(kb.assume_init()),
            })
        }
    }

    #[inline]
    pub(super) fn key_bytes(&self) -> &[u8] {
        match self {
            SymmetricCipherKey::Aes128 { raw_key, .. } => &raw_key.0,
            SymmetricCipherKey::Aes256 { raw_key, .. } => &raw_key.0,
            SymmetricCipherKey::ChaCha20 { raw_key, .. } => &raw_key.0,
        }
    }

    #[allow(dead_code)]
    #[inline]
    pub(crate) fn encrypt_block(&self, block: Block) -> Block {
        match self {
            SymmetricCipherKey::Aes128 { enc_key, .. }
            | SymmetricCipherKey::Aes256 { enc_key, .. } => encrypt_block_aes(enc_key, block),
            SymmetricCipherKey::ChaCha20 { .. } => panic!("Unsupported algorithm!"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::cipher::{ctr, ecb};

    use super::{cbc, UnboundCipherKey, AES_128};

    #[test]
    fn test_cbc() {
        let key = &[0u8; 16];

        let unbound_key = UnboundCipherKey::new(&AES_128, key).unwrap();

        let ek = cbc::EncryptingCbcKey::new(unbound_key).unwrap();

        let mut data = Vec::from("Hello World!");

        // Required to import the trait
        use super::GenericEncryptingBlockCipherKey;
        let iv = ek.encrypt_with_padding(&mut data).unwrap();

        let unbound_key = UnboundCipherKey::new(&AES_128, key).unwrap();
        let mut dk = cbc::DecryptingCbcKey::new(unbound_key, iv).unwrap();

        // Required to import the trait
        use super::GenericDecryptingBlockCipherKey;
        let _data = dk.decrypt_padded(&mut data).unwrap();
    }

    #[test]
    fn test_ctr() {
        let key = &[0u8; 16];

        let unbound_key = UnboundCipherKey::new(&AES_128, key).unwrap();

        let ek = ctr::EncryptingCtrKey::new(unbound_key).unwrap();

        let mut data = Vec::from("Hello World!");

        // Required to import the trait
        use super::EncryptingStreamBlockCipherKeyIv;
        let iv = ek.encrypt(&mut data).unwrap();

        let unbound_key = UnboundCipherKey::new(&AES_128, key).unwrap();
        let mut dk = ctr::DecryptingCtrKey::new(unbound_key, iv).unwrap();

        // Required to import the trait
        use super::DecryptingStreamBlockCipherKeyIv;
        let _data = dk.decrypt(&mut data).unwrap();
    }

    #[test]
    fn test_ecb() {
        let key = &[0u8; 16];

        let unbound_key = UnboundCipherKey::new(&AES_128, key).unwrap();

        let ek = ecb::EncryptingEcbKey::new(unbound_key).unwrap();

        let mut data = Vec::from("Hello World!");

        // Required to import the trait
        use super::GenericEncryptingBlockCipherKey;
        ek.encrypt_with_padding(&mut data).unwrap();

        let unbound_key = UnboundCipherKey::new(&AES_128, key).unwrap();
        let dk = ecb::DecryptingEcbKey::new(unbound_key).unwrap();

        // Required to import the trait
        use super::GenericDecryptingBlockCipherKey;
        let _data = dk.decrypt_padded(&mut data).unwrap();
    }

    #[test]
    fn generalized_usage() {
        fn general_encryptor_for_keyiv(
            ek: impl super::EncryptingBlockCipherKeyIv,
            data: &mut Vec<u8>,
        ) -> Result<crate::iv::NonceIV, crate::error::Unspecified> {
            ek.encrypt_with_padding(data)
        }

        fn general_decryptor_for_keyiv<'a>(
            ek: impl super::DecryptingBlockCipherKeyIv,
            data: &'a mut Vec<u8>,
        ) -> Result<&'a mut [u8], crate::error::Unspecified> {
            ek.decrypt_padded(data)
        }
    }
}

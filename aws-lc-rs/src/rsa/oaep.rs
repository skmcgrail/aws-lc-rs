// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::{fmt::Debug, ptr::null_mut};

use aws_lc::{
    EVP_PKEY_CTX_new, EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md,
    EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt,
    EVP_PKEY_encrypt_init, EVP_PKEY_up_ref, EVP_marshal_private_key, EVP_marshal_public_key,
    EVP_parse_public_key, EVP_sha1, EVP_sha256, EVP_sha384, EVP_sha512, EVP_MD, EVP_PKEY,
    EVP_PKEY_CTX, RSA_PKCS1_OAEP_PADDING,
};

use crate::{
    buffer::Buffer,
    cbb::LcCBB,
    cbs,
    encoding::{AsDer, Pkcs8V1Der, RsaPublicKeyX509Der},
    error::{KeyRejected, Unspecified},
    fips::indicator_check,
    ptr::LcPtr,
};

use super::key::{generate_rsa_evp_pkey, is_rsa_evp_pkey, KeySize, PKCS8_FIXED_CAPACITY_BUFFER};

/// RSA-OAEP with SHA1 Hash and SHA1 MGF1
pub const OAEP_SHA1_MGF1SHA1: EncryptionAlgorithm = EncryptionAlgorithm {
    id: EncryptionAlgorithmId::OaepSha1Mgf1sha1,
    oaep_hash_fn: EVP_sha1,
    mgf1_hash_fn: EVP_sha1,
};

/// RSA-OAEP with SHA256 Hash and SHA256 MGF1
pub const OAEP_SHA256_MGF1SHA256: EncryptionAlgorithm = EncryptionAlgorithm {
    id: EncryptionAlgorithmId::OaepSha256Mgf1sha256,
    oaep_hash_fn: EVP_sha256,
    mgf1_hash_fn: EVP_sha256,
};

/// RSA-OAEP with SHA384 Hash and SHA384  MGF1
pub const OAEP_SHA384_MGF1SHA384: EncryptionAlgorithm = EncryptionAlgorithm {
    id: EncryptionAlgorithmId::OaepSha384Mgf1sha384,
    oaep_hash_fn: EVP_sha384,
    mgf1_hash_fn: EVP_sha384,
};

/// RSA-OAEP with SHA512 Hash and SHA512 MGF1
pub const OAEP_SHA512_MGF1SHA512: EncryptionAlgorithm = EncryptionAlgorithm {
    id: EncryptionAlgorithmId::OaepSha512Mgf1sha512,
    oaep_hash_fn: EVP_sha512,
    mgf1_hash_fn: EVP_sha512,
};

/// RSA Encryption Algorithm Identifier
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptionAlgorithmId {
    /// RSA-OAEP with SHA1 Hash and SHA1 MGF1
    OaepSha1Mgf1sha1,

    /// RSA-OAEP with SHA256 Hash and SHA256 MGF1
    OaepSha256Mgf1sha256,

    /// RSA-OAEP with SHA384 Hash and SHA384 MGF1
    OaepSha384Mgf1sha384,

    /// RSA-OAEP with SHA512 Hash and SHA512 MGF1
    OaepSha512Mgf1sha512,
}

type OaepHashFn = unsafe extern "C" fn() -> *const EVP_MD;
type Mgf1HashFn = unsafe extern "C" fn() -> *const EVP_MD;

/// An RSA Encryption Algorithm.
pub struct EncryptionAlgorithm {
    id: EncryptionAlgorithmId,
    oaep_hash_fn: OaepHashFn,
    mgf1_hash_fn: Mgf1HashFn,
}

impl EncryptionAlgorithm {
    /// Returns the algorithm's associated identifier.
    #[must_use]
    pub fn id(&self) -> EncryptionAlgorithmId {
        self.id
    }

    #[inline]
    fn oaep_hash_fn(&self) -> OaepHashFn {
        self.oaep_hash_fn
    }

    #[inline]
    fn mgf1_hash_fn(&self) -> Mgf1HashFn {
        self.mgf1_hash_fn
    }
}

impl Debug for EncryptionAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

/// An RSA Private Key used for decrypting ciphertext encrypted by [`PublicEncryptingKey`].
pub struct PrivateDecryptingKey {
    key: LcPtr<EVP_PKEY>,
    size: KeySize,
}

impl PrivateDecryptingKey {
    fn new(key: LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        if !is_rsa_evp_pkey(&key) {
            return Err(Unspecified);
        };
        let size = KeySize::from_evp_pkey(&key)?;
        Ok(Self { key, size })
    }

    /// Generate a new RSA private key for use with asymmetrical encryption.
    ///
    /// # Errors
    /// * `Unspeicifed` for any error that occurs during the generation of the RSA keypair.
    pub fn generate(size: KeySize) -> Result<Self, Unspecified> {
        Self::new(generate_rsa_evp_pkey(size)?)
    }

    /// Construct a `PrivateDecryptingKey` from the pvoided PKCS#8 (v1) document.
    ///
    /// # Errors
    /// * `Unspeicifed` for any error that occurs during deserialization of this key from PKCS#8.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let evp_pkey = LcPtr::try_from(pkcs8)?;
            super::key::validate_rsa_pkey(&evp_pkey)?;
            Self::new(evp_pkey).map_err(|_| KeyRejected::unexpected_error())
        }
    }

    /// Returns the corresponding [`KeySize`].
    #[must_use]
    pub fn key_size(&self) -> KeySize {
        self.size
    }

    /// Retrieves the `PublicEncryptingKey` corresponding with this `PrivateDecryptingKey`.
    ///
    /// # Errors
    /// * `Unspeicifed` for any error that occurs computing the public key.
    pub fn public_key(&self) -> Result<PublicEncryptingKey, Unspecified> {
        if 1 != unsafe { EVP_PKEY_up_ref(*self.key) } {
            return Err(Unspecified);
        };
        PublicEncryptingKey::new(LcPtr::new(*self.key)?)
    }

    /// Decrypts the contents in `ciphertext` and writes the corresponding plaintext to `output`.
    ///
    /// # Errors
    /// * `Unspeicifed` for any error that occurs while decrypting `ciphertext`.
    pub fn decrypt<'output>(
        &self,
        algorithm: &'static EncryptionAlgorithm,
        ciphertext: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.key, null_mut()) })?;

        if 1 != unsafe { EVP_PKEY_decrypt_init(*pkey_ctx) } {
            return Err(Unspecified);
        }

        configure_oaep_crypto_operation(
            &pkey_ctx,
            algorithm.oaep_hash_fn(),
            algorithm.mgf1_hash_fn(),
        )?;

        let mut out_len = output.len();

        if 1 != indicator_check!(unsafe {
            EVP_PKEY_decrypt(
                *pkey_ctx,
                output.as_mut_ptr(),
                &mut out_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        }) {
            return Err(Unspecified);
        };

        Ok(&mut output[..out_len])
    }
}

impl AsDer<Pkcs8V1Der<'static>> for PrivateDecryptingKey {
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        let mut buffer = [0u8; PKCS8_FIXED_CAPACITY_BUFFER];
        let mut cbb = LcCBB::new_fixed(&mut buffer);

        if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), *self.key.as_const()) } {
            return Err(Unspecified);
        }
        let out_len = cbb.finish()?;

        Ok(Buffer::take_from_slice(&mut buffer[..out_len]))
    }
}

/// An RSA Public Key used for decrypting ciphertext encrypted by [`PublicEncryptingKey`].
pub struct PublicEncryptingKey {
    key: LcPtr<EVP_PKEY>,
    size: KeySize,
}

impl PublicEncryptingKey {
    fn new(key: LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        if !is_rsa_evp_pkey(&key) {
            return Err(Unspecified);
        };
        let size = KeySize::from_evp_pkey(&key)?;
        Ok(Self { key, size })
    }

    /// Construct a `PublicEncryptingKey` from X.509 `SubjectPublicKeyInfo` DER encoded bytes.
    ///
    /// # Errors
    /// * `Unspeicifed` for any error that occurs deserializing from bytes.
    pub fn from_der(value: &[u8]) -> Result<PublicEncryptingKey, Unspecified> {
        let mut der = unsafe { cbs::build_CBS(value) };
        let key = LcPtr::new(unsafe { EVP_parse_public_key(&mut der) })?;
        Self::new(key)
    }

    /// Returns the corresponding [`KeySize`].
    #[must_use]
    pub fn key_size(&self) -> KeySize {
        self.size
    }

    /// Encrypts the contents in `plaintext` and writes the corresponding ciphertext to `output`.
    ///
    /// # Errors
    /// * `Unspeicifed` for any error that occurs while decrypting `ciphertext`.
    pub fn encrypt<'output>(
        &self,
        algorithm: &'static EncryptionAlgorithm,
        plaintext: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.key, null_mut()) })?;

        if 1 != unsafe { EVP_PKEY_encrypt_init(*pkey_ctx) } {
            return Err(Unspecified);
        }

        configure_oaep_crypto_operation(
            &pkey_ctx,
            algorithm.oaep_hash_fn(),
            algorithm.mgf1_hash_fn(),
        )?;

        let mut out_len = output.len();

        if 1 != indicator_check!(unsafe {
            EVP_PKEY_encrypt(
                *pkey_ctx,
                output.as_mut_ptr(),
                &mut out_len,
                plaintext.as_ptr(),
                plaintext.len(),
            )
        }) {
            return Err(Unspecified);
        };

        Ok(&mut output[..out_len])
    }
}

fn configure_oaep_crypto_operation(
    evp_pkey_ctx: &LcPtr<EVP_PKEY_CTX>,
    oaep_hash_fn: OaepHashFn,
    mgf1_hash_fn: Mgf1HashFn,
) -> Result<(), Unspecified> {
    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_padding(**evp_pkey_ctx, RSA_PKCS1_OAEP_PADDING) } {
        return Err(Unspecified);
    };

    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_oaep_md(**evp_pkey_ctx, oaep_hash_fn()) } {
        return Err(Unspecified);
    };

    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(**evp_pkey_ctx, mgf1_hash_fn()) } {
        return Err(Unspecified);
    };

    Ok(())
}

impl AsDer<RsaPublicKeyX509Der<'static>> for PublicEncryptingKey {
    /// Serialize this `PublicEncryptingKey` to a X.509 `SubjectPublicKeyInfo` structure as DER encoded bytes.
    ///
    /// # Errors
    /// * `Unspeicifed` for any error that occurs serializing to bytes.
    fn as_der(&self) -> Result<RsaPublicKeyX509Der<'static>, Unspecified> {
        // TODO: Determine proper initial_capacity

        let mut der = LcCBB::new(1024);

        if 1 != unsafe { EVP_marshal_public_key(der.as_mut_ptr(), *self.key) } {
            return Err(Unspecified);
        };

        der.into_buffer()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encoding::AsDer,
        rsa::{
            key::KeySize,
            oaep::{
                OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384,
                OAEP_SHA512_MGF1SHA512,
            },
            EncryptionAlgorithmId,
        },
    };

    use super::{PrivateDecryptingKey, PublicEncryptingKey};

    #[test]
    fn encryption_algorithm_id() {
        assert_eq!(
            OAEP_SHA1_MGF1SHA1.id(),
            EncryptionAlgorithmId::OaepSha1Mgf1sha1
        );
        assert_eq!(
            OAEP_SHA256_MGF1SHA256.id(),
            EncryptionAlgorithmId::OaepSha256Mgf1sha256
        );
        assert_eq!(
            OAEP_SHA384_MGF1SHA384.id(),
            EncryptionAlgorithmId::OaepSha384Mgf1sha384
        );
        assert_eq!(
            OAEP_SHA512_MGF1SHA512.id(),
            EncryptionAlgorithmId::OaepSha512Mgf1sha512
        );
    }

    #[test]
    fn encryption_algorithm_debug() {
        assert_eq!("OaepSha1Mgf1sha1", format!("{OAEP_SHA1_MGF1SHA1:?}"));
    }

    #[test]
    fn generate() {
        let private_key = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("generation");

        let pkcs8v1 = private_key.as_der().expect("encoded");

        let private_key = PrivateDecryptingKey::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

        let public_key = private_key.public_key().expect("public key");

        drop(private_key);

        let public_key_der = public_key.as_der().expect("encoded");

        let _public_key = PublicEncryptingKey::from_der(public_key_der.as_ref()).expect("decoded");
    }

    macro_rules! round_trip_algorithm {
        ($name:ident, $alg:expr, $keysize:expr) => {
            #[test]
            fn $name() {
                const MESSAGE: &[u8] = b"Hello World!";

                let private_key = PrivateDecryptingKey::generate($keysize).expect("generation");

                assert_eq!(private_key.key_size(), $keysize);

                let public_key = private_key.public_key().expect("public key");

                assert_eq!(public_key.key_size(), $keysize);

                let mut ciphertext = vec![0u8; private_key.key_size().len()];

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut())
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.key_size().len()];

                let plaintext = private_key
                    .decrypt($alg, ciphertext, &mut plaintext)
                    .expect("decryption");

                assert_eq!(MESSAGE, plaintext);
            }
        };
    }

    round_trip_algorithm!(
        rsa2048_oaep_sha1_mgf1sha1,
        &OAEP_SHA1_MGF1SHA1,
        KeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha1_mgf1sha1,
        &OAEP_SHA1_MGF1SHA1,
        KeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha1_mgf1sha1,
        &OAEP_SHA1_MGF1SHA1,
        KeySize::Rsa8192
    );

    round_trip_algorithm!(
        rsa2048_oaep_sha256_mgf1sha256,
        &OAEP_SHA256_MGF1SHA256,
        KeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha256_mgf1sha256,
        &OAEP_SHA256_MGF1SHA256,
        KeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha256_mgf1sha256,
        &OAEP_SHA256_MGF1SHA256,
        KeySize::Rsa8192
    );

    round_trip_algorithm!(
        rsa2048_oaep_sha384_mgf1sha384,
        &OAEP_SHA384_MGF1SHA384,
        KeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha384_mgf1sha384,
        &OAEP_SHA384_MGF1SHA384,
        KeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha384_mgf1sha384,
        &OAEP_SHA384_MGF1SHA384,
        KeySize::Rsa8192
    );

    round_trip_algorithm!(
        rsa2048_oaep_sha512_mgf1sha512,
        &OAEP_SHA512_MGF1SHA512,
        KeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha512_mgf1sha512,
        &OAEP_SHA512_MGF1SHA512,
        KeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha512_mgf1sha512,
        &OAEP_SHA512_MGF1SHA512,
        KeySize::Rsa8192
    );
}

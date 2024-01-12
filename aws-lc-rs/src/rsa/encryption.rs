// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{
    encoding::{AsDer, Pkcs8V1Der, RsaPublicKeyX509Der},
    error::{KeyRejected, Unspecified},
    fips::indicator_check,
    ptr::LcPtr,
};
#[cfg(feature = "fips")]
use aws_lc::RSA_check_fips;
use aws_lc::{
    EVP_PKEY_CTX_new, EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_oaep_md,
    EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt,
    EVP_PKEY_encrypt_init, EVP_PKEY_up_ref, EVP_sha1, EVP_sha256, EVP_sha384, EVP_sha512, EVP_MD,
    EVP_PKEY, EVP_PKEY_CTX, RSA_PKCS1_OAEP_PADDING,
};
use std::{fmt::Debug, ptr::null_mut};

use super::key::{generate_rsa_key, rsa_key_size_enum, RsaEvpPkey, UsageContext};

/// RSA-OAEP with SHA1 Hash and SHA1 MGF1
pub const OAEP_SHA1_MGF1SHA1: EncryptionAlgorithm = EncryptionAlgorithm::OAEP(OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha1Mgf1sha1,
    oaep_hash_fn: EVP_sha1,
    mgf1_hash_fn: EVP_sha1,
});

/// RSA-OAEP with SHA256 Hash and SHA256 MGF1
pub const OAEP_SHA256_MGF1SHA256: EncryptionAlgorithm = EncryptionAlgorithm::OAEP(OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha256Mgf1sha256,
    oaep_hash_fn: EVP_sha256,
    mgf1_hash_fn: EVP_sha256,
});

/// RSA-OAEP with SHA384 Hash and SHA384  MGF1
pub const OAEP_SHA384_MGF1SHA384: EncryptionAlgorithm = EncryptionAlgorithm::OAEP(OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha384Mgf1sha384,
    oaep_hash_fn: EVP_sha384,
    mgf1_hash_fn: EVP_sha384,
});

/// RSA-OAEP with SHA512 Hash and SHA512 MGF1
pub const OAEP_SHA512_MGF1SHA512: EncryptionAlgorithm = EncryptionAlgorithm::OAEP(OaepAlgorithm {
    id: EncryptionAlgorithmId::OaepSha512Mgf1sha512,
    oaep_hash_fn: EVP_sha512,
    mgf1_hash_fn: EVP_sha512,
});

/// RSA Encryption Algorithm Identifier
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
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

pub struct OaepAlgorithm {
    id: EncryptionAlgorithmId,
    oaep_hash_fn: OaepHashFn,
    mgf1_hash_fn: Mgf1HashFn,
}

impl OaepAlgorithm {
    #[must_use]
    fn id(&self) -> EncryptionAlgorithmId {
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

impl Debug for OaepAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

/// An RSA Encryption Algorithm.
#[allow(clippy::module_name_repetitions)]
#[non_exhaustive]
#[derive(Debug)]
pub enum EncryptionAlgorithm {
    /// RSA-OAEP Encryption
    OAEP(OaepAlgorithm),
}

impl EncryptionAlgorithm {
    /// Returns the algorithm's associated identifier.
    #[must_use]
    pub fn id(&self) -> EncryptionAlgorithmId {
        match self {
            EncryptionAlgorithm::OAEP(a) => a.id(),
        }
    }
}

rsa_key_size_enum!(EncryptionKeySize);

/// An RSA private key used for decrypting ciphertext encrypted by a [`PublicEncryptingKey`].
pub struct PrivateDecryptingKey(RsaEvpPkey);

impl PrivateDecryptingKey {
    fn new(key: LcPtr<EVP_PKEY>) -> Result<Self, Unspecified> {
        Ok(Self(RsaEvpPkey::new(key, UsageContext::Decryption)?))
    }

    /// Generate a new RSA private key for use with asymmetrical encryption.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs during the generation of the RSA keypair.
    pub fn generate(size: EncryptionKeySize) -> Result<Self, Unspecified> {
        let key = generate_rsa_key(size.bit_len(), false)?;
        Self::new(key)
    }

    /// Generate a RSA `KeyPair` of the specified key-strength.
    ///
    /// Supports the following key sizes:
    /// * `EncryptionKeySize::Rsa2048`
    /// * `EncryptionKeySize::Rsa3072`
    /// * `EncryptionKeySize::Rsa4096`
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    #[cfg(feature = "fips")]
    pub fn generate_fips(size: EncryptionKeySize) -> Result<Self, Unspecified> {
        let key = generate_rsa_key(size.bit_len(), true)?;
        Self::new(key)
    }

    /// Construct a `PrivateDecryptingKey` from the provided PKCS#8 (v1) document.
    ///
    /// Supports RSA key sizes between 2048 and 8192 (inclusive).
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs during deserialization of this key from PKCS#8.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        let evp_pkey = LcPtr::try_from(pkcs8)?;
        Self::new(evp_pkey).map_err(|_| KeyRejected::unexpected_error())
    }

    /// Returns a boolean indicator if this RSA key is an approved FIPS 140-3 key.
    #[cfg(feature = "fips")]
    #[must_use]
    pub fn is_valid_fips_key(&self) -> bool {
        let rsa_key = if let Ok(key) = self.0.key.get_rsa() {
            key
        } else {
            return false;
        };

        1 == unsafe { RSA_check_fips(*rsa_key) }
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.0.key_size()
    }

    /// Retrieves the `PublicEncryptingKey` corresponding with this `PrivateDecryptingKey`.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs computing the public key.
    pub fn public_key(&self) -> Result<PublicEncryptingKey, Unspecified> {
        if 1 != unsafe { EVP_PKEY_up_ref(*self.0.key) } {
            return Err(Unspecified);
        };
        Ok(PublicEncryptingKey(RsaEvpPkey::new(
            LcPtr::new(*self.0.key)?,
            UsageContext::Encryption,
        )?))
    }

    /// Decrypts the contents in `ciphertext` and writes the corresponding plaintext to `output`.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs while decrypting `ciphertext`.
    pub fn decrypt<'output>(
        &self,
        algorithm: &'static EncryptionAlgorithm,
        ciphertext: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.0.key, null_mut()) })?;

        if 1 != unsafe { EVP_PKEY_decrypt_init(*pkey_ctx) } {
            return Err(Unspecified);
        }

        match algorithm {
            EncryptionAlgorithm::OAEP(oaep) => {
                configure_oaep_crypto_operation(
                    &pkey_ctx,
                    oaep.oaep_hash_fn(),
                    oaep.mgf1_hash_fn(),
                )?;
            }
        }

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

impl Debug for PrivateDecryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrivateDecryptingKey").finish()
    }
}

impl AsDer<Pkcs8V1Der<'static>> for PrivateDecryptingKey {
    fn as_der(&self) -> Result<Pkcs8V1Der<'static>, Unspecified> {
        AsDer::<Pkcs8V1Der<'_>>::as_der(&self.0)
    }
}

/// An RSA public key used for encrypting plaintext that is decrypted by a [`PrivateDecryptingKey`].
pub struct PublicEncryptingKey(RsaEvpPkey);

impl PublicEncryptingKey {
    /// Construct a `PublicEncryptingKey` from X.509 `SubjectPublicKeyInfo` DER encoded bytes.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs deserializing from bytes.
    pub fn from_der(value: &[u8]) -> Result<PublicEncryptingKey, Unspecified> {
        Ok(Self(RsaEvpPkey::from_rfc5280_public_key_der(
            value,
            UsageContext::Encryption,
        )?))
    }

    /// Returns the RSA key size in bytes.
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.0.key_size()
    }

    /// Encrypts the contents in `plaintext` and writes the corresponding ciphertext to `output`.
    ///
    /// # Errors
    /// * `Unspecified` for any error that occurs while decrypting `ciphertext`.
    pub fn encrypt<'output>(
        &self,
        algorithm: &'static EncryptionAlgorithm,
        plaintext: &[u8],
        output: &'output mut [u8],
    ) -> Result<&'output mut [u8], Unspecified> {
        let pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.0.key, null_mut()) })?;

        if 1 != unsafe { EVP_PKEY_encrypt_init(*pkey_ctx) } {
            return Err(Unspecified);
        }

        match algorithm {
            EncryptionAlgorithm::OAEP(oaep) => {
                configure_oaep_crypto_operation(
                    &pkey_ctx,
                    oaep.oaep_hash_fn(),
                    oaep.mgf1_hash_fn(),
                )?;
            }
        }

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

impl Debug for PublicEncryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicEncryptingKey").finish()
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
    /// * `Unspecified` for any error that occurs serializing to bytes.
    fn as_der(&self) -> Result<RsaPublicKeyX509Der<'static>, Unspecified> {
        AsDer::<RsaPublicKeyX509Der<'_>>::as_der(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encoding::AsDer,
        rsa::{
            encryption::{
                EncryptionKeySize, OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256,
                OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
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
        assert_eq!("OAEP(OaepSha1Mgf1sha1)", format!("{OAEP_SHA1_MGF1SHA1:?}"));
    }

    macro_rules! generate_encode_decode {
        ($name:ident, $size:expr) => {
            #[test]
            fn $name() {
                let private_key = PrivateDecryptingKey::generate($size).expect("generation");

                let pkcs8v1 = private_key.as_der().expect("encoded");

                let private_key =
                    PrivateDecryptingKey::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

                let public_key = private_key.public_key().expect("public key");

                drop(private_key);

                let public_key_der = public_key.as_der().expect("encoded");

                let _public_key =
                    PublicEncryptingKey::from_der(public_key_der.as_ref()).expect("decoded");
            }
        };
    }

    generate_encode_decode!(rsa2048_generate_encode_decode, EncryptionKeySize::Rsa2048);
    generate_encode_decode!(rsa3072_generate_encode_decode, EncryptionKeySize::Rsa3072);
    generate_encode_decode!(rsa4096_generate_encode_decode, EncryptionKeySize::Rsa4096);
    generate_encode_decode!(rsa8192_generate_encode_decode, EncryptionKeySize::Rsa8192);

    macro_rules! generate_fips_encode_decode {
        ($name:ident, $size:expr) => {
            #[cfg(feature = "fips")]
            #[test]
            fn $name() {
                let private_key = PrivateDecryptingKey::generate_fips($size).expect("generation");

                assert_eq!(true, private_key.is_valid_fips_key());

                let pkcs8v1 = private_key.as_der().expect("encoded");

                let private_key =
                    PrivateDecryptingKey::from_pkcs8(pkcs8v1.as_ref()).expect("decoded");

                let public_key = private_key.public_key().expect("public key");

                drop(private_key);

                let public_key_der = public_key.as_der().expect("encoded");

                let _public_key =
                    PublicEncryptingKey::from_der(public_key_der.as_ref()).expect("decoded");
            }
        };
        ($name:ident, $size:expr, false) => {
            #[cfg(feature = "fips")]
            #[test]
            fn $name() {
                let _ = PrivateDecryptingKey::generate_fips($size)
                    .expect_err("should fail for key size");
            }
        };
    }

    generate_fips_encode_decode!(
        rsa2048_generate_fips_encode_decode,
        EncryptionKeySize::Rsa2048
    );
    generate_fips_encode_decode!(
        rsa3072_generate_fips_encode_decode,
        EncryptionKeySize::Rsa3072
    );
    generate_fips_encode_decode!(
        rsa4096_generate_fips_encode_decode,
        EncryptionKeySize::Rsa4096
    );
    generate_fips_encode_decode!(
        rsa8192_generate_fips_encode_decode,
        EncryptionKeySize::Rsa8192,
        false
    );

    macro_rules! round_trip_algorithm {
        ($name:ident, $alg:expr, $keysize:expr) => {
            #[test]
            fn $name() {
                const MESSAGE: &[u8] = b"Hello World!";

                let private_key = PrivateDecryptingKey::generate($keysize).expect("generation");

                assert_eq!(private_key.key_size(), $keysize.len());

                let public_key = private_key.public_key().expect("public key");

                assert_eq!(public_key.key_size(), $keysize.len());

                let mut ciphertext = vec![0u8; private_key.key_size()];

                let ciphertext = public_key
                    .encrypt($alg, MESSAGE, ciphertext.as_mut())
                    .expect("encrypted");

                let mut plaintext = vec![0u8; private_key.key_size()];

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
        EncryptionKeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa3072_oaep_sha1_mgf1sha1,
        &OAEP_SHA1_MGF1SHA1,
        EncryptionKeySize::Rsa3072
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha1_mgf1sha1,
        &OAEP_SHA1_MGF1SHA1,
        EncryptionKeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha1_mgf1sha1,
        &OAEP_SHA1_MGF1SHA1,
        EncryptionKeySize::Rsa8192
    );

    round_trip_algorithm!(
        rsa2048_oaep_sha256_mgf1sha256,
        &OAEP_SHA256_MGF1SHA256,
        EncryptionKeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa3072_oaep_sha256_mgf1sha256,
        &OAEP_SHA256_MGF1SHA256,
        EncryptionKeySize::Rsa3072
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha256_mgf1sha256,
        &OAEP_SHA256_MGF1SHA256,
        EncryptionKeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha256_mgf1sha256,
        &OAEP_SHA256_MGF1SHA256,
        EncryptionKeySize::Rsa8192
    );

    round_trip_algorithm!(
        rsa2048_oaep_sha384_mgf1sha384,
        &OAEP_SHA384_MGF1SHA384,
        EncryptionKeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa3072_oaep_sha384_mgf1sha384,
        &OAEP_SHA384_MGF1SHA384,
        EncryptionKeySize::Rsa3072
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha384_mgf1sha384,
        &OAEP_SHA384_MGF1SHA384,
        EncryptionKeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha384_mgf1sha384,
        &OAEP_SHA384_MGF1SHA384,
        EncryptionKeySize::Rsa8192
    );

    round_trip_algorithm!(
        rsa2048_oaep_sha512_mgf1sha512,
        &OAEP_SHA512_MGF1SHA512,
        EncryptionKeySize::Rsa2048
    );
    round_trip_algorithm!(
        rsa3072_oaep_sha512_mgf1sha512,
        &OAEP_SHA512_MGF1SHA512,
        EncryptionKeySize::Rsa3072
    );
    round_trip_algorithm!(
        rsa4096_oaep_sha512_mgf1sha512,
        &OAEP_SHA512_MGF1SHA512,
        EncryptionKeySize::Rsa4096
    );
    round_trip_algorithm!(
        rsa8192_oaep_sha512_mgf1sha512,
        &OAEP_SHA512_MGF1SHA512,
        EncryptionKeySize::Rsa8192
    );
}

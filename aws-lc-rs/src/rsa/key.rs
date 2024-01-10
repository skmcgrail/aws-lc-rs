// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use super::{
    encoding,
    signature::{compute_rsa_signature, RsaEncoding, RsaPadding},
    RsaParameters,
};
#[cfg(feature = "ring-io")]
use crate::io;
#[cfg(feature = "ring-io")]
use crate::ptr::ConstPointer;
use crate::{
    cbb::LcCBB,
    digest::{self},
    error::{KeyRejected, Unspecified},
    fips::indicator_check,
    hex,
    pkcs8::Document,
    ptr::{DetachableLcPtr, LcPtr, Pointer},
    rand,
    sealed::Sealed,
};
#[cfg(feature = "fips")]
use aws_lc::RSA_check_fips;
use aws_lc::{
    EVP_DigestSignInit, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_set_rsa_keygen_bits, EVP_PKEY_assign_RSA,
    EVP_PKEY_bits, EVP_PKEY_id, EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_PKEY_new, EVP_PKEY_size,
    EVP_marshal_private_key, RSA_get0_d, RSA_new, RSA_set0_key, RSA_size, EVP_PKEY, EVP_PKEY_CTX,
    EVP_PKEY_RSA,
};
#[cfg(feature = "ring-io")]
use aws_lc::{RSA_get0_e, RSA_get0_n};
use core::{
    fmt::{self, Debug, Formatter},
    ptr::null_mut,
};
use mirai_annotations::verify_unreachable;
#[cfg(feature = "ring-io")]
use untrusted::Input;
use zeroize::Zeroize;

// Based on a measurement of a PKCS#8 v1 document containing an RSA-8192 key with an additional 1% capacity buffer
// rounded to an even 64-bit words (4678 + 1% + padding ≈ 4728).
pub(super) const PKCS8_FIXED_CAPACITY_BUFFER: usize = 4728;

macro_rules! rsa_key_size_enum {
    ($name:ident) => {
        /// RSA key-size constants.
        #[allow(clippy::len_without_is_empty)]
        #[non_exhaustive]
        #[derive(Clone, Copy, Debug, PartialEq)]
        pub enum $name {
            /// 2048-bit key
            Rsa2048,

            /// 3072-bit key
            Rsa3072,

            /// 4096-bit key
            Rsa4096,

            /// 8192-bit key
            Rsa8192,
        }

        impl $name {
            /// Returns the size of the key in bytes [`KeySize`].
            #[inline]
            #[must_use]
            pub fn len(self) -> usize {
                match self {
                    Self::Rsa2048 => 256,
                    Self::Rsa3072 => 384,
                    Self::Rsa4096 => 512,
                    Self::Rsa8192 => 1024,
                }
            }

            /// Returns the bits of this [`KeySize`].
            #[inline]
            fn bit_len(self) -> i32 {
                match self {
                    Self::Rsa2048 => 2048,
                    Self::Rsa3072 => 3072,
                    Self::Rsa4096 => 4096,
                    Self::Rsa8192 => 8192,
                }
            }
        }
    };
}

pub(super) use rsa_key_size_enum;

rsa_key_size_enum!(SignatureKeySize);

/// An RSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct KeyPair {
    // https://github.com/aws/aws-lc/blob/ebaa07a207fee02bd68fe8d65f6b624afbf29394/include/openssl/evp.h#L295
    // An |EVP_PKEY| object represents a public or private RSA key. A given object may be
    // used concurrently on multiple threads by non-mutating functions, provided no
    // other thread is concurrently calling a mutating function. Unless otherwise
    // documented, functions which take a |const| pointer are non-mutating and
    // functions which take a non-|const| pointer are mutating.
    pub(super) rsa_evp_pkey: RsaEvpPkey,
    pub(super) serialized_public_key: PublicKey,
}

impl Sealed for KeyPair {}
unsafe impl Send for KeyPair {}
unsafe impl Sync for KeyPair {}

impl KeyPair {
    unsafe fn new(evp_pkey: LcPtr<EVP_PKEY>) -> Result<Self, KeyRejected> {
        Self::from_rsa_evp_pkey(
            RsaEvpPkey::new(evp_pkey, UsageContext::SignatureGeneration)
                .map_err(|_| KeyRejected::unspecified())?,
        )
    }

    fn from_rsa_evp_pkey(rsa_evp_pkey: RsaEvpPkey) -> Result<Self, KeyRejected> {
        let serialized_public_key = unsafe { PublicKey::new(&rsa_evp_pkey)? };
        Ok(KeyPair {
            rsa_evp_pkey,
            serialized_public_key,
        })
    }

    /// Generate an RSA `KeyPair` of the specified key-strength.
    ///
    /// # Errors
    /// * `Unspecified`: Any key generation failure.
    pub fn generate(size: SignatureKeySize) -> Result<Self, Unspecified> {
        let private_key = generate_rsa_key(size.bit_len())?;
        unsafe { Self::new(private_key).map_err(|_| Unspecified) }
    }

    /// Parses an unencrypted PKCS#8-encoded RSA private key.
    ///
    /// Only two-prime (not multi-prime) keys are supported. The public modulus
    /// (n) must be at least 2047 bits. The public modulus must be no larger
    /// than 4096 bits. It is recommended that the public modulus be exactly
    /// 2048 or 3072 bits. The public exponent must be at least 65537.
    ///
    /// The following will generate a 2048-bit RSA private key of the correct form using
    /// OpenSSL's command line tool:
    ///
    /// ```sh
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:2048 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform der > rsa-2048-private-key.pk8
    /// ```
    ///
    /// The following will generate a 3072-bit RSA private key of the correct form:
    ///
    /// ```sh
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:3072 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform der > rsa-3072-private-key.pk8
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are stored in
    /// the Base64 “PEM” format without the PKCS#8 wrapper. Such keys can be
    /// converted to binary PKCS#8 form using the OpenSSL command line tool like
    /// this:
    ///
    /// ```sh
    /// openssl pkcs8 -topk8 -nocrypt -outform der \
    ///     -in rsa-2048-private-key.pem > rsa-2048-private-key.pk8
    /// ```
    ///
    /// Base64 (“PEM”) PKCS#8-encoded keys can be converted to the binary PKCS#8
    /// form like this:
    ///
    /// ```sh
    /// openssl pkcs8 -nocrypt -outform der \
    ///     -in rsa-2048-private-key.pem > rsa-2048-private-key.pk8
    /// ```
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an RSA private key or if the key is otherwise
    /// not acceptable.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        let key = RsaEvpPkey::from_pkcs8(pkcs8, UsageContext::SignatureGeneration)?;
        Self::from_rsa_evp_pkey(key)
    }

    /// Parses a DER-encoded `RSAPrivateKey` structure (RFC 8017).
    ///
    /// # Errors
    /// `error:KeyRejected` on error.
    pub fn from_der(input: &[u8]) -> Result<Self, KeyRejected> {
        let key =
            RsaEvpPkey::from_rfc8017_private_key_der(input, UsageContext::SignatureGeneration)?;
        Self::from_rsa_evp_pkey(key)
    }

    /// Serializes this key-pair to a PKCS#8 (v1) document.
    ///
    /// # Errors
    /// * `Unspecified`: any error encountered while serializing the key.
    pub fn to_pkcs8v1(&self) -> Result<Document, Unspecified> {
        let bytes = self.rsa_evp_pkey.to_pkcs8v1()?;
        Ok(Document::new(bytes))
    }

    /// Returns a boolean indicator if this RSA key is an approved FIPS 140-3 key.
    #[cfg(feature = "fips")]
    #[must_use]
    pub fn is_valid_fips_key(&self) -> bool {
        self.rsa_evp_pkey.is_valid_fips_key()
    }

    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    // # FIPS
    // The following conditions must be met:
    // * RSA Key Sizes: 2048, 3072, 4096
    // * Digest Algorithms: SHA256, SHA384, SHA512
    //
    /// # Errors
    /// `error::Unspecified` on error.
    /// With "fips" feature enabled, errors if digest length is greater than `u32::MAX`.
    pub fn sign(
        &self,
        padding_alg: &'static dyn RsaEncoding,
        _rng: &dyn rand::SecureRandom,
        msg: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Unspecified> {
        let encoding = padding_alg.encoding();

        let mut md_ctx = digest::digest_ctx::DigestContext::new_uninit();
        let mut pctx = null_mut::<EVP_PKEY_CTX>();
        let digest = digest::match_digest_type(&encoding.digest_algorithm().id);

        if 1 != unsafe {
            EVP_DigestSignInit(
                md_ctx.as_mut_ptr(),
                &mut pctx,
                *digest,
                null_mut(),
                *self.rsa_evp_pkey.key,
            )
        } {
            return Err(Unspecified);
        }

        if let RsaPadding::RSA_PKCS1_PSS_PADDING = encoding.padding() {
            // AWS-LC owns pctx, check for null and then immediately detach so we don't drop it.
            let pctx = DetachableLcPtr::new(pctx)?.detach();
            super::signature::configure_rsa_pkcs1_pss_padding(pctx)?;
        }

        let max_len = super::signature::get_signature_length(&mut md_ctx)?;

        debug_assert!(signature.len() >= max_len);

        let computed_signature = compute_rsa_signature(&mut md_ctx, msg, signature)?;

        debug_assert!(computed_signature.len() >= signature.len());

        Ok(())
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    #[must_use]
    pub fn public_modulus_len(&self) -> usize {
        // This was already validated to be an RSA key so this can't fail
        match self.rsa_evp_pkey.key.get_rsa() {
            Ok(rsa) => {
                // https://github.com/awslabs/aws-lc/blob/main/include/openssl/rsa.h#L99
                unsafe { (RSA_size(*rsa)) as usize }
            }
            Err(_) => verify_unreachable!(),
        }
    }
}

impl Debug for KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaKeyPair {{ public_key: {:?} }}",
            self.serialized_public_key
        ))
    }
}

impl crate::signature::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.serialized_public_key
    }
}

/// A serialized RSA public key.
#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct PublicKey {
    key: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    modulus: Box<[u8]>,
    #[cfg(feature = "ring-io")]
    exponent: Box<[u8]>,
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(feature = "ring-io")]
        self.modulus.zeroize();
        #[cfg(feature = "ring-io")]
        self.exponent.zeroize();
    }
}

impl PublicKey {
    pub(super) unsafe fn new(rsa_evp_pkey: &RsaEvpPkey) -> Result<Self, ()> {
        let pubkey = rsa_evp_pkey.key.get_rsa().map_err(|_| ())?;
        let key = encoding::rfc8017::encode_public_key_der(&pubkey.as_const())?;
        #[cfg(feature = "ring-io")]
        {
            let modulus = ConstPointer::new(RSA_get0_n(*pubkey))?;
            let modulus = modulus.to_be_bytes().into_boxed_slice();
            let exponent = ConstPointer::new(RSA_get0_e(*pubkey))?;
            let exponent = exponent.to_be_bytes().into_boxed_slice();
            Ok(PublicKey {
                key,
                modulus,
                exponent,
            })
        }

        #[cfg(not(feature = "ring-io"))]
        Ok(PublicKey { key })
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "RsaPublicKey(\"{}\")",
            hex::encode(self.key.as_ref())
        ))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

#[cfg(feature = "ring-io")]
impl PublicKey {
    /// The public modulus (n).
    #[must_use]
    pub fn modulus(&self) -> io::Positive<'_> {
        io::Positive::new_non_empty_without_leading_zeros(Input::from(self.modulus.as_ref()))
    }

    /// The public exponent (e).
    #[must_use]
    pub fn exponent(&self) -> io::Positive<'_> {
        io::Positive::new_non_empty_without_leading_zeros(Input::from(self.exponent.as_ref()))
    }
}

/// Low-level API for the verification of RSA signatures.
///
/// When the public key is in DER-encoded PKCS#1 ASN.1 format, it is
/// recommended to use `aws_lc_rs::signature::verify()` with
/// `aws_lc_rs::signature::RSA_PKCS1_*`, because `aws_lc_rs::signature::verify()`
/// will handle the parsing in that case. Otherwise, this function can be used
/// to pass in the raw bytes for the public key components as
/// `untrusted::Input` arguments.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone)]
pub struct PublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    /// The public modulus, encoded in big-endian bytes without leading zeros.
    pub n: B,
    /// The public exponent, encoded in big-endian bytes without leading zeros.
    pub e: B,
}

impl<B: AsRef<[u8]> + Debug> Debug for PublicKeyComponents<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKeyComponents")
            .field("n", &self.n)
            .field("e", &self.e)
            .finish()
    }
}

impl<B: Copy + AsRef<[u8]> + Debug> Copy for PublicKeyComponents<B> {}

impl<B> PublicKeyComponents<B>
where
    B: AsRef<[u8]> + Debug,
{
    #[allow(non_snake_case)]
    #[inline]
    unsafe fn build_RSA(&self) -> Result<LcPtr<EVP_PKEY>, ()> {
        let n_bytes = self.n.as_ref();
        if n_bytes.is_empty() || n_bytes[0] == 0u8 {
            return Err(());
        }
        let n_bn = DetachableLcPtr::try_from(n_bytes)?;

        let e_bytes = self.e.as_ref();
        if e_bytes.is_empty() || e_bytes[0] == 0u8 {
            return Err(());
        }
        let e_bn = DetachableLcPtr::try_from(e_bytes)?;

        let rsa = DetachableLcPtr::new(RSA_new())?;
        if 1 != RSA_set0_key(*rsa, *n_bn, *e_bn, null_mut()) {
            return Err(());
        }
        n_bn.detach();
        e_bn.detach();

        let pkey = LcPtr::new(EVP_PKEY_new())?;
        if 1 != EVP_PKEY_assign_RSA(*pkey, *rsa) {
            return Err(());
        }
        rsa.detach();

        Ok(pkey)
    }

    /// Verifies that `signature` is a valid signature of `message` using `self`
    /// as the public key. `params` determine what algorithm parameters
    /// (padding, digest algorithm, key length range, etc.) are used in the
    /// verification.
    ///
    /// # Errors
    /// `error::Unspecified` if `message` was not verified.
    pub fn verify(
        &self,
        params: &RsaParameters,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        unsafe {
            let rsa = self.build_RSA()?;
            super::signature::verify_rsa_signature(
                params.digest_algorithm(),
                params.padding(),
                &rsa,
                message,
                signature,
                params.bit_size_range(),
            )
        }
    }
}

pub(super) fn generate_rsa_key(size: core::ffi::c_int) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let evp_pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*evp_pkey_ctx) } {
        return Err(Unspecified);
    };

    if 1 != unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(*evp_pkey_ctx, size) } {
        return Err(Unspecified);
    };

    let mut pkey: *mut EVP_PKEY = null_mut();

    if 1 != indicator_check!(unsafe { EVP_PKEY_keygen(*evp_pkey_ctx, &mut pkey) }) {
        return Err(Unspecified);
    };

    Ok(LcPtr::new(pkey)?)
}

#[derive(Clone, Copy)]
#[non_exhaustive]
pub(super) enum UsageContext {
    SignatureGeneration,
    SignatureVerification,
    Encryption,
    Decryption,
}

impl UsageContext {
    pub(super) fn validate_key_usage(
        &self,
        key: &LcPtr<EVP_PKEY>,
    ) -> Result<RsaEvpPkeyType, KeyRejected> {
        if EVP_PKEY_RSA != unsafe { EVP_PKEY_id(**key) } {
            return Err(KeyRejected::wrong_algorithm());
        }

        let key_type = get_rsa_evp_pkey_type(key)?;

        // If we only have a public-key EVP_PKEY then the RSA key can't be an operation
        // context that requires the private key.
        if let (
            UsageContext::SignatureGeneration | UsageContext::Decryption,
            RsaEvpPkeyType::Public,
        ) = (self, key_type)
        {
            return Err(KeyRejected::unspecified());
        }

        let key_size = unsafe { EVP_PKEY_bits(**key) };

        match self {
            UsageContext::SignatureVerification => {
                // Our API has 1024 as the absolute lower-bound for RSA verification.
                // This can be further restricted to 2048 by the configured signature algorithm.
                if !(1024..=8192).contains(&key_size) {
                    return Err(KeyRejected::unsupported_size());
                }
            }
            UsageContext::SignatureGeneration
            | UsageContext::Encryption
            | UsageContext::Decryption => {
                // For generation and encryption/decryption limit to keys that are 2048 or higher.
                if !(2048..=8192).contains(&key_size) {
                    return Err(KeyRejected::unsupported_size());
                }
            }
        }

        Ok(key_type)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RsaEvpPkeyType {
    Private,
    Public,
}

pub(super) struct RsaEvpPkey {
    pub(super) key: LcPtr<EVP_PKEY>,
    typ: RsaEvpPkeyType,
}

impl RsaEvpPkey {
    pub fn new(key: LcPtr<EVP_PKEY>, usage: UsageContext) -> Result<Self, KeyRejected> {
        let typ = usage.validate_key_usage(&key)?;
        Ok(Self { key, typ })
    }

    pub fn from_pkcs8(pkcs8: &[u8], usage: UsageContext) -> Result<Self, KeyRejected> {
        let evp_pkey = LcPtr::try_from(pkcs8)?;
        // Safety: Self::new validates that what we parsed a RSA key of a supported size
        Self::new(evp_pkey, usage)
    }

    pub fn to_pkcs8v1(&self) -> Result<Box<[u8]>, Unspecified> {
        if self.typ == RsaEvpPkeyType::Public {
            verify_unreachable!();
        }

        let mut buffer = vec![0u8; PKCS8_FIXED_CAPACITY_BUFFER];
        let out_len = {
            let mut cbb = LcCBB::new_fixed(<&mut [u8; PKCS8_FIXED_CAPACITY_BUFFER]>::try_from(
                buffer.as_mut_slice(),
            )?);

            if 1 != unsafe { EVP_marshal_private_key(cbb.as_mut_ptr(), *self.key.as_const()) } {
                return Err(Unspecified);
            }
            cbb.finish()?
        };

        buffer.truncate(out_len);

        Ok(buffer.into_boxed_slice())
    }

    pub fn from_rfc8017_private_key_der(
        input: &[u8],
        usage: UsageContext,
    ) -> Result<Self, KeyRejected> {
        let pkey = encoding::rfc8017::decode_private_key_der(input)
            .map_err(|_| KeyRejected::unspecified())?;
        Self::new(pkey, usage)
    }

    #[allow(dead_code)]
    pub fn from_rfc8017_public_key_der(
        input: &[u8],
        usage: UsageContext,
    ) -> Result<Self, KeyRejected> {
        let pkey = encoding::rfc8017::decode_public_key_der(input)
            .map_err(|_| KeyRejected::unspecified())?;
        Self::new(pkey, usage)
    }

    pub fn from_rfc5280_public_key_der(
        value: &[u8],
        usage: UsageContext,
    ) -> Result<RsaEvpPkey, KeyRejected> {
        let key = encoding::rfc5280::decode_public_key_der(value)
            .map_err(|_| KeyRejected::unspecified())?;
        // Safety: Self::new validates that what we just parsed is an RSA key of a supported size
        Self::new(key, usage)
    }

    #[cfg(feature = "fips")]
    #[must_use]
    pub fn is_valid_fips_key(&self) -> bool {
        let rsa_key = if let Ok(key) = self.key.get_rsa() {
            key
        } else {
            return false;
        };

        1 == unsafe { RSA_check_fips(*rsa_key) }
    }

    pub fn key_size(&self) -> usize {
        // Safety: RSA modulous byte sizes supported fit an usize
        unsafe { EVP_PKEY_size(self.key.as_const_ptr()) }
            .try_into()
            .expect("modulous should fit in usize")
    }
}

impl Debug for RsaEvpPkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaEvpPkey").finish_non_exhaustive()
    }
}

fn get_rsa_evp_pkey_type(key: &LcPtr<EVP_PKEY>) -> Result<RsaEvpPkeyType, KeyRejected> {
    let rsa = key.get_rsa()?;
    Ok(if unsafe { RSA_get0_d(*rsa) }.is_null() {
        RsaEvpPkeyType::Public
    } else {
        RsaEvpPkeyType::Private
    })
}

#[cfg(test)]
mod tests {
    use super::KeyPair;

    #[test]
    fn generate_key() {
        let keypair =
            KeyPair::generate(super::SignatureKeySize::Rsa2048).expect("generate successful");
        let document = keypair.to_pkcs8v1().expect("serialize keypair");
        let _ = KeyPair::from_pkcs8(document.as_ref()).expect("deserialize key");
    }
}

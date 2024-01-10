/// [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)
///
/// PKCS #1: RSA Cryptography Specifications Version 2.2
pub mod rfc8017 {
    use crate::{
        cbs,
        error::Unspecified,
        ptr::{ConstPointer, DetachableLcPtr, LcPtr},
    };
    use aws_lc::{
        EVP_PKEY_assign_RSA, EVP_PKEY_new, RSA_parse_private_key, RSA_parse_public_key,
        RSA_public_key_to_bytes, EVP_PKEY, RSA,
    };
    use core::ptr::null_mut;

    /// DER encode a RSA public key to `RSAPublicKey` structure.
    pub unsafe fn encode_public_key_der(pubkey: &ConstPointer<RSA>) -> Result<Box<[u8]>, ()> {
        let mut pubkey_bytes = null_mut::<u8>();
        let mut outlen: usize = 0;
        if 1 != RSA_public_key_to_bytes(&mut pubkey_bytes, &mut outlen, **pubkey) {
            return Err(());
        }
        let pubkey_bytes = LcPtr::new(pubkey_bytes)?;
        let pubkey_slice = pubkey_bytes.as_slice(outlen);
        let pubkey_vec = Vec::from(pubkey_slice);
        Ok(pubkey_vec.into_boxed_slice())
    }

    /// Decode a DER encoded `RSAPublicKey` structure.
    #[inline]
    pub fn decode_public_key_der(public_key: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
        let mut cbs = unsafe { cbs::build_CBS(public_key) };

        let rsa = DetachableLcPtr::new(unsafe { RSA_parse_public_key(&mut cbs) })?;

        let pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_RSA(*pkey, *rsa) } {
            return Err(Unspecified);
        }

        rsa.detach();

        Ok(pkey)
    }

    /// Decodes a DER encoded `RSAPrivateKey` structure.
    #[inline]
    pub fn decode_private_key_der(private_key: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
        let mut cbs = unsafe { cbs::build_CBS(private_key) };

        let rsa = DetachableLcPtr::new(unsafe { RSA_parse_private_key(&mut cbs) })?;

        let pkey = LcPtr::new(unsafe { EVP_PKEY_new() })?;

        if 1 != unsafe { EVP_PKEY_assign_RSA(*pkey, *rsa) } {
            return Err(Unspecified);
        }

        rsa.detach();

        Ok(pkey)
    }
}

/// [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)
///
/// Encodings that use the `SubjectPublicKeyInfo` structure.
pub mod rfc5280 {
    use crate::{cbs, error::Unspecified, ptr::LcPtr};
    use aws_lc::{EVP_parse_public_key, EVP_PKEY};

    pub fn decode_public_key_der(value: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
        let mut der = unsafe { cbs::build_CBS(value) };
        Ok(LcPtr::new(unsafe { EVP_parse_public_key(&mut der) })?)
    }
}

// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error;

pub struct FixedLength<const L: usize>([u8; L]);

impl<const L: usize> FixedLength<L> {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    /// # Errors
    /// `error::Unspecified` when byte slice length is not `L`
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        let value: &[u8; L] = value.try_into()?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    #[must_use]
    pub fn assume_unique_for_key(value: [u8; L]) -> Self {
        Self(value)
    }
}

impl<const L: usize> AsRef<[u8; L]> for FixedLength<L> {
    #[inline]
    fn as_ref(&self) -> &[u8; L] {
        &self.0
    }
}

impl<const L: usize> From<&[u8; L]> for FixedLength<L> {
    #[inline]
    fn from(bytes: &[u8; L]) -> Self {
        FixedLength(bytes.to_owned())
    }
}

impl<const L: usize> From<[u8; L]> for FixedLength<L> {
    #[inline]
    fn from(bytes: [u8; L]) -> Self {
        FixedLength(bytes)
    }
}

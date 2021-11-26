// Smoldot
// Copyright (C) 2019-2021  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use super::Error;
use crate::util;

use alloc::vec::Vec;
use core::{cmp, fmt, iter, slice};

/// A consensus log item for BABE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BabeConsensusLogRef<'a> {
    /// The epoch has changed. This provides information about the _next_
    /// epoch - information about the _current_ epoch (i.e. the one we've just
    /// entered) should already be available earlier in the chain.
    NextEpochData(BabeNextEpochRef<'a>),
    /// Disable the authority with given index.
    OnDisabled(u32),
    /// The epoch has changed, and the epoch after the current one will
    /// enact different epoch configurations.
    NextConfigData(BabeNextConfig),
}

impl<'a> BabeConsensusLogRef<'a> {
    /// Decodes a [`BabeConsensusLogRef`] from a slice of bytes.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, Error> {
        Ok(match slice.get(0) {
            Some(1) => {
                BabeConsensusLogRef::NextEpochData(BabeNextEpochRef::from_slice(&slice[1..])?)
            }
            Some(2) => {
                let n = u32::from_le_bytes(
                    <[u8; 4]>::try_from(&slice[1..]).map_err(|_| Error::DigestItemDecodeError)?,
                );
                BabeConsensusLogRef::OnDisabled(n)
            }
            Some(3) => {
                // The Babe configuration info starts with a version number that is always `1`
                // at the moment.
                if slice.len() < 2 || slice[1] != 1 {
                    return Err(Error::BadBabeNextConfigVersion);
                }
                BabeConsensusLogRef::NextConfigData(BabeNextConfig::from_slice(&slice[2..])?)
            }
            Some(_) => return Err(Error::BadBabeConsensusRefType),
            None => return Err(Error::TooShort),
        })
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
        let index = iter::once(match self {
            BabeConsensusLogRef::NextEpochData(_) => [1],
            BabeConsensusLogRef::OnDisabled(_) => [2],
            BabeConsensusLogRef::NextConfigData(_) => [3],
        });

        let body = match self {
            BabeConsensusLogRef::NextEpochData(digest) => either::Left(either::Left(
                digest.scale_encoding().map(either::Left).map(either::Left),
            )),
            BabeConsensusLogRef::OnDisabled(digest) => either::Left(either::Right(iter::once(
                either::Left(either::Right(digest.to_le_bytes())),
            ))),
            BabeConsensusLogRef::NextConfigData(digest) => either::Right(
                iter::once(either::Right(either::Left([1]))).chain(
                    digest
                        .scale_encoding()
                        .map(either::Right)
                        .map(either::Right),
                ),
            ),
        };

        index.map(either::Left).chain(body.map(either::Right))
    }
}

impl<'a> From<&'a BabeConsensusLog> for BabeConsensusLogRef<'a> {
    fn from(a: &'a BabeConsensusLog) -> Self {
        match a {
            BabeConsensusLog::NextEpochData(v) => BabeConsensusLogRef::NextEpochData(v.into()),
            BabeConsensusLog::OnDisabled(v) => BabeConsensusLogRef::OnDisabled(*v),
            BabeConsensusLog::NextConfigData(v) => BabeConsensusLogRef::NextConfigData(*v),
        }
    }
}

/// A consensus log item for BABE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BabeConsensusLog {
    /// The epoch has changed. This provides information about the _next_
    /// epoch - information about the _current_ epoch (i.e. the one we've just
    /// entered) should already be available earlier in the chain.
    NextEpochData(BabeNextEpoch),
    /// Disable the authority with given index.
    OnDisabled(u32),
    /// The epoch has changed, and the epoch after the current one will
    /// enact different epoch configurations.
    NextConfigData(BabeNextConfig),
}

impl<'a> From<BabeConsensusLogRef<'a>> for BabeConsensusLog {
    fn from(a: BabeConsensusLogRef<'a>) -> Self {
        match a {
            BabeConsensusLogRef::NextEpochData(v) => BabeConsensusLog::NextEpochData(v.into()),
            BabeConsensusLogRef::OnDisabled(v) => BabeConsensusLog::OnDisabled(v),
            BabeConsensusLogRef::NextConfigData(v) => BabeConsensusLog::NextConfigData(v),
        }
    }
}

/// Information about the next epoch. This is broadcast in the first block
/// of the epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabeNextEpochRef<'a> {
    /// The authorities.
    pub authorities: BabeAuthoritiesIter<'a>,

    /// The value of randomness to use for the slot-assignment.
    pub randomness: &'a [u8; 32],
}

impl<'a> BabeNextEpochRef<'a> {
    /// Decodes a [`BabePreDigestRef`] from a slice of bytes.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, Error> {
        let (slice, authorities_len) =
            match crate::util::nom_scale_compact_usize::<nom::error::Error<&[u8]>>(slice) {
                Ok(s) => s,
                Err(_) => return Err(Error::TooShort),
            };

        if slice.len() != authorities_len * 40 + 32 {
            return Err(Error::TooShort);
        }

        Ok(BabeNextEpochRef {
            authorities: BabeAuthoritiesIter(BabeAuthoritiesIterInner::Raw(
                slice[0..authorities_len * 40].chunks(40),
            )),
            randomness: <&[u8; 32]>::try_from(&slice[authorities_len * 40..]).unwrap(),
        })
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
        let header = util::encode_scale_compact_usize(self.authorities.len());
        iter::once(either::Left(header))
            .chain(
                self.authorities
                    .clone()
                    .flat_map(|a| a.scale_encoding())
                    .map(|buf| either::Right(either::Left(buf))),
            )
            .chain(iter::once(either::Right(either::Right(
                &self.randomness[..],
            ))))
    }
}

impl<'a> From<&'a BabeNextEpoch> for BabeNextEpochRef<'a> {
    fn from(a: &'a BabeNextEpoch) -> Self {
        BabeNextEpochRef {
            authorities: BabeAuthoritiesIter(BabeAuthoritiesIterInner::List(a.authorities.iter())),
            randomness: &a.randomness,
        }
    }
}

/// Information about the next epoch. This is broadcast in the first block
/// of the epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BabeNextEpoch {
    /// The authorities.
    pub authorities: Vec<BabeAuthority>,

    /// The value of randomness to use for the slot-assignment.
    pub randomness: [u8; 32],
}

impl<'a> From<BabeNextEpochRef<'a>> for BabeNextEpoch {
    fn from(a: BabeNextEpochRef<'a>) -> Self {
        BabeNextEpoch {
            authorities: a.authorities.map(Into::into).collect(),
            randomness: *a.randomness,
        }
    }
}

/// List of authorities in a BABE context.
#[derive(Clone)]
pub struct BabeAuthoritiesIter<'a>(BabeAuthoritiesIterInner<'a>);

#[derive(Clone)]
enum BabeAuthoritiesIterInner<'a> {
    List(slice::Iter<'a, BabeAuthority>),
    Raw(slice::Chunks<'a, u8>),
}

impl<'a> BabeAuthoritiesIter<'a> {
    /// Builds a new [`BabeAuthoritiesIter`] iterating over the given slice.
    pub fn from_slice(slice: &'a [BabeAuthority]) -> Self {
        Self(BabeAuthoritiesIterInner::List(slice.iter()))
    }
}

impl<'a> Iterator for BabeAuthoritiesIter<'a> {
    type Item = BabeAuthorityRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            BabeAuthoritiesIterInner::List(l) => l.next().map(Into::into),
            BabeAuthoritiesIterInner::Raw(l) => {
                let item = l.next()?;
                assert_eq!(item.len(), 40);
                Some(BabeAuthorityRef {
                    public_key: <&[u8; 32]>::try_from(&item[0..32]).unwrap(),
                    weight: u64::from_le_bytes(<[u8; 8]>::try_from(&item[32..40]).unwrap()),
                })
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            BabeAuthoritiesIterInner::List(l) => l.size_hint(),
            BabeAuthoritiesIterInner::Raw(l) => l.size_hint(),
        }
    }
}

impl<'a> ExactSizeIterator for BabeAuthoritiesIter<'a> {}

impl<'a> cmp::PartialEq<BabeAuthoritiesIter<'a>> for BabeAuthoritiesIter<'a> {
    fn eq(&self, other: &BabeAuthoritiesIter<'a>) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        loop {
            match (a.next(), b.next()) {
                (Some(a), Some(b)) if a == b => {}
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl<'a> cmp::Eq for BabeAuthoritiesIter<'a> {}

impl<'a> fmt::Debug for BabeAuthoritiesIter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabeAuthorityRef<'a> {
    /// Sr25519 public key.
    pub public_key: &'a [u8; 32],
    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    // TODO: should be NonZeroU64; requires deep changes in decoding code though
    pub weight: u64,
}

impl<'a> BabeAuthorityRef<'a> {
    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
        iter::once(either::Right(self.public_key))
            .chain(iter::once(either::Left(self.weight.to_le_bytes())))
    }
}

impl<'a> From<&'a BabeAuthority> for BabeAuthorityRef<'a> {
    fn from(a: &'a BabeAuthority) -> Self {
        BabeAuthorityRef {
            public_key: &a.public_key,
            weight: a.weight,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BabeAuthority {
    /// Sr25519 public key.
    pub public_key: [u8; 32],
    /// Arbitrary number indicating the weight of the authority.
    ///
    /// This value can only be compared to other weight values.
    // TODO: should be NonZeroU64; requires deep changes in decoding code though
    pub weight: u64,
}

impl<'a> From<BabeAuthorityRef<'a>> for BabeAuthority {
    fn from(a: BabeAuthorityRef<'a>) -> Self {
        BabeAuthority {
            public_key: *a.public_key,
            weight: a.weight,
        }
    }
}

/// Information about the next epoch config, if changed. This is broadcast in the first
/// block of the epoch, and applies using the same rules as `NextEpochDescriptor`.
// TODO: remove the Encode & Decode trait derivation ; unfortunately used elsewhere
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub struct BabeNextConfig {
    /// Value of `c` in `BabeEpochConfiguration`.
    pub c: (u64, u64),
    /// Value of `allowed_slots` in `BabeEpochConfiguration`.
    pub allowed_slots: BabeAllowedSlots,
}

impl BabeNextConfig {
    /// Decodes a [`BabeNextConfig`] from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() < 16 {
            return Err(Error::TooShort);
        }

        let c0 = u64::from_le_bytes(<[u8; 8]>::try_from(&slice[..8]).unwrap());
        let c1 = u64::from_le_bytes(<[u8; 8]>::try_from(&slice[8..16]).unwrap());
        let allowed_slots = BabeAllowedSlots::from_slice(&slice[16..])?;

        Ok(BabeNextConfig {
            c: (c0, c1),
            allowed_slots,
        })
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(&self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        iter::once(either::Left(self.c.0.to_le_bytes()))
            .chain(iter::once(either::Left(self.c.1.to_le_bytes())))
            .chain(self.allowed_slots.scale_encoding().map(either::Right))
    }
}

/// Types of allowed slots.
// TODO: remove the Encode & Decode trait derivation ; unfortunately used elsewhere
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, parity_scale_codec::Encode, parity_scale_codec::Decode,
)]
pub enum BabeAllowedSlots {
    /// Only allow primary slot claims.
    PrimarySlots,
    /// Allow primary and secondary plain slot claims.
    PrimaryAndSecondaryPlainSlots,
    /// Allow primary and secondary VRF slot claims.
    PrimaryAndSecondaryVrfSlots,
}

impl BabeAllowedSlots {
    /// Decodes a [`BabeAllowedSlots`] from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Ok(match slice.get(0) {
            Some(0) => BabeAllowedSlots::PrimarySlots,
            Some(1) => BabeAllowedSlots::PrimaryAndSecondaryPlainSlots,
            Some(2) => BabeAllowedSlots::PrimaryAndSecondaryVrfSlots,
            _ => return Err(Error::BadBabePreDigestRefType),
        })
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(&self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        iter::once(match self {
            BabeAllowedSlots::PrimarySlots => [0],
            BabeAllowedSlots::PrimaryAndSecondaryPlainSlots => [1],
            BabeAllowedSlots::PrimaryAndSecondaryVrfSlots => [2],
        })
    }
}

/// A BABE pre-runtime digest. This contains all data required to validate a
/// block and for the BABE runtime module. Slots can be assigned to a primary
/// (VRF based) and to a secondary (slot number based).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BabePreDigestRef<'a> {
    /// A primary VRF-based slot assignment.
    Primary(BabePrimaryPreDigestRef<'a>),
    /// A secondary deterministic slot assignment.
    SecondaryPlain(BabeSecondaryPlainPreDigest),
    /// A secondary deterministic slot assignment with VRF outputs.
    SecondaryVRF(BabeSecondaryVRFPreDigestRef<'a>),
}

impl<'a> BabePreDigestRef<'a> {
    /// Decodes a [`BabePreDigestRef`] from a slice of bytes.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, Error> {
        Ok(match slice.get(0) {
            Some(1) => BabePreDigestRef::Primary(BabePrimaryPreDigestRef::from_slice(&slice[1..])?),
            Some(2) => BabePreDigestRef::SecondaryPlain(BabeSecondaryPlainPreDigest::from_slice(
                &slice[1..],
            )?),
            Some(3) => BabePreDigestRef::SecondaryVRF(BabeSecondaryVRFPreDigestRef::from_slice(
                &slice[1..],
            )?),
            Some(_) => return Err(Error::BadBabePreDigestRefType),
            None => return Err(Error::TooShort),
        })
    }

    /// Returns `true` for [`BabePreDigestRef::Primary`].
    pub fn is_primary(&self) -> bool {
        matches!(self, BabePreDigestRef::Primary(_))
    }

    /// Returns the slot number stored in the header.
    pub fn slot_number(&self) -> u64 {
        match self {
            BabePreDigestRef::Primary(digest) => digest.slot_number,
            BabePreDigestRef::SecondaryPlain(digest) => digest.slot_number,
            BabePreDigestRef::SecondaryVRF(digest) => digest.slot_number,
        }
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
        let index = iter::once(match self {
            BabePreDigestRef::Primary(_) => [1],
            BabePreDigestRef::SecondaryPlain(_) => [2],
            BabePreDigestRef::SecondaryVRF(_) => [3],
        });

        let body = match self {
            BabePreDigestRef::Primary(digest) => either::Left(either::Left(
                digest
                    .scale_encoding()
                    .map(|buf| either::Left(either::Left(buf))),
            )),
            BabePreDigestRef::SecondaryPlain(digest) => either::Left(either::Right(
                digest
                    .scale_encoding()
                    .map(|buf| either::Left(either::Right(buf))),
            )),
            BabePreDigestRef::SecondaryVRF(digest) => {
                either::Right(digest.scale_encoding().map(either::Right))
            }
        };

        index.map(either::Left).chain(body.map(either::Right))
    }
}

impl<'a> From<BabePreDigestRef<'a>> for BabePreDigest {
    fn from(a: BabePreDigestRef<'a>) -> Self {
        match a {
            BabePreDigestRef::Primary(a) => BabePreDigest::Primary(a.into()),
            BabePreDigestRef::SecondaryPlain(a) => BabePreDigest::SecondaryPlain(a),
            BabePreDigestRef::SecondaryVRF(a) => BabePreDigest::SecondaryVRF(a.into()),
        }
    }
}

/// A BABE pre-runtime digest. This contains all data required to validate a
/// block and for the BABE runtime module. Slots can be assigned to a primary
/// (VRF based) and to a secondary (slot number based).
#[derive(Debug, Clone)]
pub enum BabePreDigest {
    /// A primary VRF-based slot assignment.
    Primary(BabePrimaryPreDigest),
    /// A secondary deterministic slot assignment.
    SecondaryPlain(BabeSecondaryPlainPreDigest),
    /// A secondary deterministic slot assignment with VRF outputs.
    SecondaryVRF(BabeSecondaryVRFPreDigest),
}

impl<'a> From<&'a BabePreDigest> for BabePreDigestRef<'a> {
    fn from(a: &'a BabePreDigest) -> Self {
        match a {
            BabePreDigest::Primary(a) => BabePreDigestRef::Primary(a.into()),
            BabePreDigest::SecondaryPlain(a) => BabePreDigestRef::SecondaryPlain(a.clone()),
            BabePreDigest::SecondaryVRF(a) => BabePreDigestRef::SecondaryVRF(a.into()),
        }
    }
}

/// Raw BABE primary slot assignment pre-digest.
#[derive(Debug, Clone)]
pub struct BabePrimaryPreDigestRef<'a> {
    /// Authority index
    pub authority_index: u32,
    /// Slot number
    pub slot_number: u64,
    /// VRF output
    pub vrf_output: &'a [u8; 32],
    /// VRF proof
    pub vrf_proof: &'a [u8; 64],
}

impl<'a> BabePrimaryPreDigestRef<'a> {
    /// Decodes a [`BabePrimaryPreDigestRef`] from a slice of bytes.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, Error> {
        if slice.len() != 4 + 8 + 32 + 64 {
            return Err(Error::TooShort);
        }

        Ok(BabePrimaryPreDigestRef {
            authority_index: u32::from_le_bytes(<[u8; 4]>::try_from(&slice[0..4]).unwrap()),
            slot_number: u64::from_le_bytes(<[u8; 8]>::try_from(&slice[4..12]).unwrap()),
            vrf_output: TryFrom::try_from(&slice[12..44]).unwrap(),
            vrf_proof: TryFrom::try_from(&slice[44..108]).unwrap(),
        })
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
        let header = iter::once(either::Left(self.authority_index.to_le_bytes()))
            .chain(iter::once(either::Right(self.slot_number.to_le_bytes())))
            .map(either::Left);

        header
            .chain(iter::once(either::Right(&self.vrf_output[..])))
            .chain(iter::once(either::Right(&self.vrf_proof[..])))
    }
}

impl<'a> cmp::PartialEq<BabePrimaryPreDigestRef<'a>> for BabePrimaryPreDigestRef<'a> {
    fn eq(&self, other: &BabePrimaryPreDigestRef<'a>) -> bool {
        self.authority_index == other.authority_index
            && self.slot_number == other.slot_number
            && self.vrf_output[..] == other.vrf_output[..]
            && self.vrf_proof[..] == other.vrf_proof[..]
    }
}

impl<'a> cmp::Eq for BabePrimaryPreDigestRef<'a> {}

impl<'a> From<&'a BabePrimaryPreDigest> for BabePrimaryPreDigestRef<'a> {
    fn from(a: &'a BabePrimaryPreDigest) -> Self {
        BabePrimaryPreDigestRef {
            authority_index: a.authority_index,
            slot_number: a.slot_number,
            vrf_output: &a.vrf_output,
            vrf_proof: &a.vrf_proof,
        }
    }
}

/// Raw BABE primary slot assignment pre-digest.
#[derive(Debug, Clone)]
pub struct BabePrimaryPreDigest {
    /// Authority index
    pub authority_index: u32,
    /// Slot number
    pub slot_number: u64,
    /// VRF output
    pub vrf_output: [u8; 32],
    /// VRF proof
    pub vrf_proof: [u8; 64],
}

impl<'a> From<BabePrimaryPreDigestRef<'a>> for BabePrimaryPreDigest {
    fn from(a: BabePrimaryPreDigestRef<'a>) -> Self {
        BabePrimaryPreDigest {
            authority_index: a.authority_index,
            slot_number: a.slot_number,
            vrf_output: *a.vrf_output,
            vrf_proof: *a.vrf_proof,
        }
    }
}

/// BABE secondary slot assignment pre-digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BabeSecondaryPlainPreDigest {
    /// Authority index
    ///
    /// This is not strictly-speaking necessary, since the secondary slots
    /// are assigned based on slot number and epoch randomness. But including
    /// it makes things easier for higher-level users of the chain data to
    /// be aware of the author of a secondary-slot block.
    pub authority_index: u32,

    /// Slot number
    pub slot_number: u64,
}

impl BabeSecondaryPlainPreDigest {
    /// Decodes a [`BabeSecondaryPlainPreDigest`] from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != 12 {
            return Err(Error::DigestItemDecodeError);
        }

        let authority_index = u32::from_le_bytes(<[u8; 4]>::try_from(&slice[..4]).unwrap());
        let slot_number = u64::from_le_bytes(<[u8; 8]>::try_from(&slice[4..]).unwrap());

        Ok(BabeSecondaryPlainPreDigest {
            authority_index,
            slot_number,
        })
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(&self) -> impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone {
        iter::once(either::Left(self.authority_index.to_le_bytes()))
            .chain(iter::once(either::Right(self.slot_number.to_le_bytes())))
    }
}

/// BABE secondary deterministic slot assignment with VRF outputs.
#[derive(Debug, Clone)]
pub struct BabeSecondaryVRFPreDigestRef<'a> {
    /// Authority index
    pub authority_index: u32,
    /// Slot number
    pub slot_number: u64,
    /// VRF output
    pub vrf_output: &'a [u8; 32],
    /// VRF proof
    pub vrf_proof: &'a [u8; 64],
}

impl<'a> BabeSecondaryVRFPreDigestRef<'a> {
    /// Decodes a [`BabeSecondaryVRFPreDigestRef`] from a slice of bytes.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, Error> {
        if slice.len() != 4 + 8 + 32 + 64 {
            return Err(Error::TooShort);
        }

        Ok(BabeSecondaryVRFPreDigestRef {
            authority_index: u32::from_le_bytes(<[u8; 4]>::try_from(&slice[0..4]).unwrap()),
            slot_number: u64::from_le_bytes(<[u8; 8]>::try_from(&slice[4..12]).unwrap()),
            vrf_output: TryFrom::try_from(&slice[12..44]).unwrap(),
            vrf_proof: TryFrom::try_from(&slice[44..108]).unwrap(),
        })
    }

    /// Returns an iterator to list of buffers which, when concatenated, produces the SCALE
    /// encoding of that object.
    pub fn scale_encoding(
        &self,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + Clone + 'a> + Clone + 'a {
        let header = iter::once(either::Left(self.authority_index.to_le_bytes()))
            .chain(iter::once(either::Right(self.slot_number.to_le_bytes())))
            .map(either::Left);

        header
            .chain(iter::once(either::Right(&self.vrf_output[..])))
            .chain(iter::once(either::Right(&self.vrf_proof[..])))
    }
}

impl<'a> cmp::PartialEq<BabeSecondaryVRFPreDigestRef<'a>> for BabeSecondaryVRFPreDigestRef<'a> {
    fn eq(&self, other: &BabeSecondaryVRFPreDigestRef<'a>) -> bool {
        self.authority_index == other.authority_index
            && self.slot_number == other.slot_number
            && self.vrf_output[..] == other.vrf_output[..]
            && self.vrf_proof[..] == other.vrf_proof[..]
    }
}

impl<'a> cmp::Eq for BabeSecondaryVRFPreDigestRef<'a> {}

impl<'a> From<&'a BabeSecondaryVRFPreDigest> for BabeSecondaryVRFPreDigestRef<'a> {
    fn from(a: &'a BabeSecondaryVRFPreDigest) -> Self {
        BabeSecondaryVRFPreDigestRef {
            authority_index: a.authority_index,
            slot_number: a.slot_number,
            vrf_output: &a.vrf_output,
            vrf_proof: &a.vrf_proof,
        }
    }
}

/// BABE secondary deterministic slot assignment with VRF outputs.
#[derive(Debug, Clone)]
pub struct BabeSecondaryVRFPreDigest {
    /// Authority index
    pub authority_index: u32,
    /// Slot number
    pub slot_number: u64,
    /// VRF output
    pub vrf_output: [u8; 32],
    /// VRF proof
    pub vrf_proof: [u8; 64],
}

impl<'a> From<BabeSecondaryVRFPreDigestRef<'a>> for BabeSecondaryVRFPreDigest {
    fn from(a: BabeSecondaryVRFPreDigestRef<'a>) -> Self {
        BabeSecondaryVRFPreDigest {
            authority_index: a.authority_index,
            slot_number: a.slot_number,
            vrf_output: *a.vrf_output,
            vrf_proof: *a.vrf_proof,
        }
    }
}

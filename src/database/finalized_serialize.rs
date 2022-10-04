// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Serializing/deserializing a [`chain_information::ChainInformation`].
//!
//! This module contains the [`encode_chain_storage`] and [`decode_chain`] functions that can turn
//! a [`chain_information::ChainInformation`] into a string and back, with optionally the state of
//! the finalized block.
//! With no finalized block storage, the string is expected to be in the order of magnitude of a
//! few dozens kilobytes.
//!
//! The string format designed to be stable even if the structure of
//! [`chain_information::ChainInformation`] is later modified.
//!
//! This feature is expected to be used for example by light clients in order to easily (but
//! inefficiently) store the state of the finalized chain somewhere and later reload it.

use crate::chain::chain_information;

use alloc::{string::String, vec::Vec};
use core::iter;
use hashbrown::HashMap;

mod defs;

/// Serializes the given chain information as a JSON string.
///
/// This is a shortcut for [`encode_chain_storage`] with no `finalized_storage`.
pub fn encode_chain<'a>(
    information: impl Into<chain_information::ValidChainInformationRef<'a>>,
    block_number_bytes: usize,
) -> String {
    encode_chain_storage(
        information,
        block_number_bytes,
        None::<iter::Empty<(Vec<u8>, Vec<u8>)>>,
    )
}

/// Serializes the given chain information and finalized block storage as a string.
pub fn encode_chain_storage<'a>(
    information: impl Into<chain_information::ValidChainInformationRef<'a>>,
    block_number_bytes: usize,
    finalized_storage: Option<impl Iterator<Item = (impl AsRef<[u8]>, impl AsRef<[u8]>)>>,
) -> String {
    let information = information.into();

    let decoded = defs::SerializedChainInformation::V1(defs::SerializedChainInformationV1::new(
        information.as_ref(),
        block_number_bytes,
        finalized_storage,
    ));

    serde_json::to_string(&decoded).unwrap()
}

/// Deserializes the information about the chain.
///
/// This is the invert operation of [`encode_chain_storage`].
pub fn decode_chain(
    encoded: &str,
    block_number_bytes: usize,
) -> Result<
    (
        chain_information::ValidChainInformation,
        Option<HashMap<Vec<u8>, Vec<u8>, fnv::FnvBuildHasher>>,
    ),
    CorruptedError,
> {
    let encoded: defs::SerializedChainInformation =
        serde_json::from_str(encoded).map_err(|e| CorruptedError(CorruptedErrorInner::Serde(e)))?;

    let (chain_info, storage) = encoded
        .decode(block_number_bytes)
        .map_err(|err| CorruptedError(CorruptedErrorInner::Deserialize(err)))?;

    let chain_info = chain_information::ValidChainInformation::try_from(chain_info)
        .map_err(CorruptedErrorInner::InvalidChain)
        .map_err(CorruptedError)?;

    Ok((chain_info, storage))
}

/// Opaque error indicating a corruption in the data stored in the local storage.
#[derive(Debug, derive_more::Display)]
#[display(fmt = "{}", _0)]
pub struct CorruptedError(CorruptedErrorInner);

#[derive(Debug, derive_more::Display)]
enum CorruptedErrorInner {
    #[display(fmt = "{}", _0)]
    Serde(serde_json::Error),
    #[display(fmt = "{}", _0)]
    Deserialize(defs::DeserializeError),
    #[display(fmt = "Invalid chain information: {}", _0)]
    InvalidChain(chain_information::ValidityError),
}

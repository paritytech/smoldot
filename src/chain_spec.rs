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

//! Substrate chain configuration.
//!
//! A **chain spec** (short for *chain specification*) is the description of everything that is
//! required for the client to successfully interact with a certain blockchain.
//! For example, the Polkadot chain spec contains all the constants that are needed in order to
//! successfully interact with Polkadot.
//!
//! Chain specs contain, notably:
//!
//! - The state of the genesis block. In other words, the initial content of the database. This
//! includes the Wasm runtime code of the genesis block.
//! - The list of bootstrap nodes. These are the IP addresses of the machines we need to connect
//! to.
//! - The default telemetry endpoints, to which we should send telemetry information to.
//! - The name of the network protocol, in order to avoid accidentally connecting to a different
//! network.
//! - Multiple other miscellaneous information.
//!

use crate::chain::chain_information::{
    aura_config, babe_genesis_config, grandpa_genesis_config, BabeEpochInformation,
    ChainInformation, ChainInformationConsensus, ChainInformationFinality,
};

use alloc::{borrow::ToOwned as _, string::String, vec::Vec};
use core::num::NonZeroU64;

mod light_sync_state;
mod structs;

/// A configuration of a chain. Can be used to build a genesis block.
#[derive(Clone)]
pub struct ChainSpec {
    client_spec: structs::ClientSpec,
}

impl ChainSpec {
    /// Parse JSON content into a [`ChainSpec`].
    pub fn from_json_bytes(json: impl AsRef<[u8]>) -> Result<Self, ParseError> {
        let client_spec: structs::ClientSpec = serde_json::from_slice(json.as_ref())
            .map_err(ParseErrorInner::Serde)
            .map_err(ParseError)?;

        // TODO: we don't support child tries in the genesis block
        assert!(match &client_spec.genesis {
            structs::Genesis::Raw(genesis) => genesis.children_default.is_empty(),
            structs::Genesis::StateRootHash(_) => true,
        });

        // Make sure that the light sync state can be successfully decoded.
        if let Some(light_sync_state) = &client_spec.light_sync_state {
            light_sync_state.decode()?;
        }

        Ok(ChainSpec { client_spec })
    }

    /// Builds the [`ChainInformation`] corresponding to the genesis block contained in this chain
    /// spec.
    pub fn as_chain_information(&self) -> Result<ChainInformation, FromGenesisStorageError> {
        let genesis_storage = match self.genesis_storage() {
            GenesisStorage::Items(items) => items,
            GenesisStorage::TrieRootHash(_) => {
                return Err(FromGenesisStorageError::UnknownStorageItems)
            }
        };

        let consensus = {
            let aura_genesis_config =
                aura_config::AuraConfiguration::from_storage(|k| {
                    genesis_storage.value(k).map(|v| v.to_owned())
                });

            let babe_genesis_config =
                babe_genesis_config::BabeGenesisConfiguration::from_genesis_storage(|k| {
                    genesis_storage.value(k).map(|v| v.to_owned())
                });

            match (aura_genesis_config, babe_genesis_config) {
                (Ok(aura_genesis_config), Err(err)) if err.is_function_not_found() => {
                    ChainInformationConsensus::Aura {
                        finalized_authorities_list: aura_genesis_config.authorities_list,
                        slot_duration: aura_genesis_config.slot_duration,
                    }
                }
                (Err(err), Ok(babe_genesis_config)) if err.is_function_not_found() => {
                    ChainInformationConsensus::Babe {
                        slots_per_epoch: babe_genesis_config.slots_per_epoch,
                        finalized_block_epoch_information: None,
                        finalized_next_epoch_transition: BabeEpochInformation {
                            epoch_index: 0,
                            start_slot_number: None,
                            authorities: babe_genesis_config.epoch0_information.authorities,
                            randomness: babe_genesis_config.epoch0_information.randomness,
                            c: babe_genesis_config.epoch0_configuration.c,
                            allowed_slots: babe_genesis_config.epoch0_configuration.allowed_slots,
                        },
                    }
                }
                (Err(err1), Err(err2))
                    if err1.is_function_not_found() && err2.is_function_not_found() =>
                {
                    // TODO: seems a bit risky to automatically fall back to this?
                    ChainInformationConsensus::AllAuthorized
                }
                (Err(error), _) => {
                    // Note that Babe might have produced an error as well, which is intentionally
                    // ignored here in order to not make the API too complicated.
                    return Err(FromGenesisStorageError::AuraConfigLoad(error));
                }
                (_, Err(error)) => {
                    return Err(FromGenesisStorageError::BabeConfigLoad(error));
                }
                (Ok(_), Ok(_)) => {
                    return Err(FromGenesisStorageError::MultipleConsensusAlgorithms);
                }
            }
        };

        let finality = {
            let grandpa_genesis_config =
                grandpa_genesis_config::GrandpaGenesisConfiguration::from_genesis_storage(|k| {
                    genesis_storage.value(k).map(|v| v.to_owned())
                });

            match grandpa_genesis_config {
                Ok(grandpa_genesis_config) => ChainInformationFinality::Grandpa {
                    after_finalized_block_authorities_set_id: 0,
                    finalized_scheduled_change: None,
                    finalized_triggered_authorities: grandpa_genesis_config.initial_authorities,
                },
                Err(error) if error.is_function_not_found() => ChainInformationFinality::Outsourced,
                Err(error) => return Err(FromGenesisStorageError::GrandpaConfigLoad(error)),
            }
        };

        Ok(ChainInformation {
            finalized_block_header: crate::calculate_genesis_block_header(self),
            consensus,
            finality,
        })
    }

    /// Returns the name of the chain. Meant to be displayed to the user.
    pub fn name(&self) -> &str {
        &self.client_spec.name
    }

    /// Returns the identifier of the chain. Similar to the name, but a bit more "system-looking".
    /// For example, if the name is "Flaming Fir 7", then the id could be "flamingfir7". To be
    /// used for example in file system paths.
    pub fn id(&self) -> &str {
        &self.client_spec.id
    }

    /// Returns a string indicating the type of chain.
    ///
    /// This value doesn't have any meaning in the absolute and is only meant to be shown to
    /// the user.
    pub fn chain_type(&self) -> &str {
        match &self.client_spec.chain_type {
            structs::ChainType::Development => "Development",
            structs::ChainType::Local => "Local",
            structs::ChainType::Live => "Live",
            structs::ChainType::Custom(ty) => ty,
        }
    }

    /// Returns true if the chain is of a type for which a live network is expected.
    pub fn has_live_network(&self) -> bool {
        match &self.client_spec.chain_type {
            structs::ChainType::Development | structs::ChainType::Custom(_) => false,
            structs::ChainType::Local | structs::ChainType::Live => true,
        }
    }

    /// Returns the list of bootnode addresses in the chain specs.
    // TODO: more strongly typed?
    pub fn boot_nodes(&self) -> &[String] {
        &self.client_spec.boot_nodes
    }

    /// Returns the list of libp2p multiaddresses of the default telemetry servers of the chain.
    // TODO: more strongly typed?
    pub fn telemetry_endpoints(&'_ self) -> impl Iterator<Item = impl AsRef<str> + '_> + '_ {
        self.client_spec
            .telemetry_endpoints
            .as_ref()
            .into_iter()
            .flat_map(|ep| ep.iter().map(|e| &e.0))
    }

    /// Returns the network protocol id that uniquely identifies a chain. Used to prevent nodes
    /// from different blockchain networks from accidentally connecting to each other.
    ///
    /// It is possible for the JSON chain specs to not specify any protocol id, in which case a
    /// default value is returned.
    pub fn protocol_id(&self) -> &str {
        self.client_spec.protocol_id.as_deref().unwrap_or("sup")
    }

    // TODO: this API is probably unstable, as the meaning of the string is unclear
    pub fn relay_chain(&self) -> Option<(&str, u32)> {
        self.client_spec
            .parachain
            .as_ref()
            .map(|p| (p.relay_chain.as_str(), p.para_id))
    }

    /// Gives access to what is known about the storage of the genesis block of the chain.
    pub fn genesis_storage(&self) -> GenesisStorage {
        match &self.client_spec.genesis {
            structs::Genesis::Raw(raw) => GenesisStorage::Items(GenesisStorageItems { raw }),
            structs::Genesis::StateRootHash(hash) => GenesisStorage::TrieRootHash(&hash.0),
        }
    }

    /// Returns a list of arbitrary properties contained in the chain specs, such as the name of
    /// the token or the number of decimals.
    ///
    /// The value of these properties is never interpreted by the local node, but can be served
    /// to a UI.
    ///
    /// The returned value is a JSON-formatted map, for example `{"foo":"bar"}`.
    pub fn properties(&self) -> &str {
        self.client_spec
            .properties
            .as_ref()
            .map(|p| p.get())
            .unwrap_or("{}")
    }

    pub fn light_sync_state(&self) -> Option<LightSyncState> {
        self.client_spec
            .light_sync_state
            .as_ref()
            .map(|state| LightSyncState {
                // We made sure at initialization that the decoding succeeds.
                inner: state.decode().unwrap(),
            })
    }
}

/// See [`ChainSpec::genesis_storage`].
pub enum GenesisStorage<'a> {
    /// The items of the genesis storage are known.
    Items(GenesisStorageItems<'a>),
    /// The items of the genesis storage are unknown, but we know the hash of the root node
    /// of the trie.
    TrieRootHash(&'a [u8; 32]),
}

impl<'a> GenesisStorage<'a> {
    /// Returns `Some` for [`GenesisStorage::Items`], and `None` otherwise.
    pub fn into_genesis_items(self) -> Option<GenesisStorageItems<'a>> {
        match self {
            GenesisStorage::Items(items) => Some(items),
            GenesisStorage::TrieRootHash(_) => None,
        }
    }
}

/// See [`GenesisStorage`].
pub struct GenesisStorageItems<'a> {
    raw: &'a structs::RawGenesis,
}

impl<'a> GenesisStorageItems<'a> {
    /// Returns the list of storage keys and values of the genesis block.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + Clone {
        self.raw.top.iter().map(|(k, v)| (&k.0[..], &v.0[..]))
    }

    /// Returns the genesis storage value for a specific key.
    ///
    /// Returns `None` if there is no value corresponding to that key.
    pub fn value(&self, key: &[u8]) -> Option<&[u8]> {
        self.raw.top.get(key).map(|value| &value.0[..])
    }
}

pub struct LightSyncState {
    inner: light_sync_state::DecodedLightSyncState,
}

fn convert_epoch(epoch: &light_sync_state::BabeEpoch) -> BabeEpochInformation {
    let epoch_authorities: Vec<_> = epoch
        .authorities
        .iter()
        .map(|authority| crate::header::BabeAuthority {
            public_key: authority.public_key,
            weight: authority.weight,
        })
        .collect();

    BabeEpochInformation {
        epoch_index: epoch.epoch_index,
        start_slot_number: Some(epoch.slot_number),
        authorities: epoch_authorities,
        randomness: epoch.randomness,
        c: epoch.config.c,
        allowed_slots: epoch.config.allowed_slots,
    }
}

impl LightSyncState {
    pub fn as_chain_information(&self) -> ChainInformation {
        // Create a sorted list of all regular epochs that haven't been pruned from the sync state.
        let mut epochs: Vec<_> = self
            .inner
            .babe_epoch_changes
            .epochs
            .iter()
            .filter(|((_, block_num), _)| {
                *block_num as u64 <= self.inner.finalized_block_header.number
            })
            .filter_map(|((_, block_num), epoch)| match epoch {
                light_sync_state::PersistedEpoch::Regular(epoch) => Some((block_num, epoch)),
                _ => None,
            })
            .collect();

        epochs.sort_unstable_by_key(|(&block_num, _)| block_num);

        // TODO: it seems that multiple identical epochs can be found in the list ; figure out why Substrate does that and fix it
        epochs.dedup_by_key(|(_, epoch)| epoch.epoch_index);

        // Get the latest two epochs.
        let current_epoch = &epochs[epochs.len() - 2].1;
        let next_epoch = &epochs[epochs.len() - 1].1;

        ChainInformation {
            finalized_block_header: self.inner.finalized_block_header.clone(),
            consensus: ChainInformationConsensus::Babe {
                slots_per_epoch: NonZeroU64::new(current_epoch.duration).unwrap(),
                finalized_block_epoch_information: Some(convert_epoch(current_epoch)),
                finalized_next_epoch_transition: convert_epoch(next_epoch),
            },
            finality: ChainInformationFinality::Grandpa {
                after_finalized_block_authorities_set_id: self.inner.grandpa_authority_set.set_id,
                finalized_triggered_authorities: {
                    self.inner
                        .grandpa_authority_set
                        .current_authorities
                        .iter()
                        .map(|authority| crate::header::GrandpaAuthority {
                            public_key: authority.public_key,
                            weight: NonZeroU64::new(authority.weight).unwrap(),
                        })
                        .collect()
                },
                finalized_scheduled_change: None, // TODO: unimplemented
            },
        }
    }
}

/// Error that can happen when parsing a chain spec JSON.
#[derive(Debug, derive_more::Display)]
pub struct ParseError(ParseErrorInner);

#[derive(Debug, derive_more::Display)]
enum ParseErrorInner {
    Serde(serde_json::Error),
    Other,
}

/// Error when building the chain information from the genesis storage.
#[derive(Debug, derive_more::Display)]
pub enum FromGenesisStorageError {
    /// Error when retrieving the GrandPa configuration.
    GrandpaConfigLoad(grandpa_genesis_config::FromGenesisStorageError),
    /// Error when retrieving the Aura algorithm configuration.
    AuraConfigLoad(aura_config::FromStorageError),
    /// Error when retrieving the Babe algorithm configuration.
    BabeConfigLoad(babe_genesis_config::FromGenesisStorageError),
    /// Multiple consensus algorithms have been detected.
    MultipleConsensusAlgorithms,
    /// Chain specification doesn't contain the list of storage items.
    UnknownStorageItems,
}

#[cfg(test)]
mod tests {
    use super::ChainSpec;

    #[test]
    fn can_decode_polkadot_genesis() {
        let spec = &include_bytes!("chain_spec/example.json")[..];
        let specs = ChainSpec::from_json_bytes(&spec).unwrap();
        assert_eq!(specs.id(), "polkadot");
    }
}

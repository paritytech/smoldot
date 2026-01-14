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

//! Background syncing service.
//!
//! The role of the [`SyncService`] is to do whatever necessary to obtain and stay up-to-date
//! with the best and the finalized blocks of a chain.
//!
//! The configuration of the chain to synchronize must be passed when creating a [`SyncService`],
//! after which it will spawn background tasks and use the networking service to stay
//! synchronized.
//!
//! Use [`SyncService::subscribe_all`] to get notified about updates to the state of the chain.

use crate::{log, network_service, platform::PlatformRef, runtime_service};

use alloc::{
    borrow::ToOwned as _, boxed::Box, collections::VecDeque, format, string::String, sync::Arc,
    vec::Vec,
};
use core::{cmp, fmt, mem, num::NonZero, pin::Pin, time::Duration};
use futures_channel::oneshot;
use rand::seq::IteratorRandom as _;
use rand_chacha::rand_core::SeedableRng as _;
use smoldot::{
    chain,
    executor::host,
    libp2p::PeerId,
    network::{codec, service},
    trie::{self, Nibble, minimize_proof, prefix_proof, proof_decode},
};

mod parachain;
mod paraheads;
mod substrate_compat;

pub use network_service::Role;

/// Configuration for a [`SyncService`].
pub struct Config<TPlat: PlatformRef> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// Access to the platform's capabilities.
    pub platform: TPlat,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// Extra fields depending on whether the chain is a parachain.
    pub chain_type: ConfigChainType<TPlat>,
}

/// See [`Config::chain_type`].
pub enum ConfigChainType<TPlat: PlatformRef> {
    /// Chain is a Substrate-compatible non-parachain.
    SubstrateCompatible(ConfigSubstrateCompatible<TPlat>),
    /// Chain is a parachain.
    Parachain(ConfigParachain<TPlat>),
}

/// See [`ConfigChainType::SubstrateCompatible`].
pub struct ConfigSubstrateCompatible<TPlat: PlatformRef> {
    /// State of the finalized chain.
    pub chain_information: chain::chain_information::ValidChainInformation,

    /// Known valid Merkle value and storage value combination for the `:code` key.
    ///
    /// If provided, the warp syncing algorithm will first fetch the Merkle value of `:code`, and
    /// if it matches the Merkle value provided in the hint, use the storage value in the hint
    /// instead of downloading it. If the hint doesn't match, an extra round-trip will be needed,
    /// but if the hint matches it saves a big download.
    pub runtime_code_hint: Option<ConfigSubstrateCompatibleRuntimeCodeHint>,

    /// If this chain is a parachain, contains the information of the relay chain.
    /// `None` if this chain isn't a parachain.
    pub relay_chain: Option<ConfigRelayChain<TPlat>>,
}

/// See [`ConfigSubstrateCompatible::runtime_code_hint`].
pub struct ConfigSubstrateCompatibleRuntimeCodeHint {
    /// Storage value of the `:code` trie node corresponding to
    /// [`ConfigSubstrateCompatibleRuntimeCodeHint::merkle_value`].
    pub storage_value: Vec<u8>,
    /// Merkle value of the `:code` trie node in the storage main trie.
    pub merkle_value: Vec<u8>,
    /// Closest ancestor of the `:code` key except for `:code` itself.
    pub closest_ancestor_excluding: Vec<Nibble>,
}

/// See [`ConfigChainType::Parachain`].
pub struct ConfigParachain<TPlat: PlatformRef> {
    /// Parameters of the relay chain.
    pub relay_chain: ConfigRelayChain<TPlat>,

    /// SCALE-encoded header of a known finalized block of the parachain. Used in the situation
    /// where the API user subscribes using [`SyncService::subscribe_all`] before any parachain
    /// block can be gathered.
    pub finalized_block_header: Vec<u8>,
}

/// See [`ConfigSubstrateCompatible::relay_chain`] and [`ConfigParachain::relay_chain`].
pub struct ConfigRelayChain<TPlat: PlatformRef> {
    /// Runtime service that synchronizes the relay chain of this parachain.
    pub relay_chain_sync: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Id of the parachain within the relay chain.
    ///
    /// This is an arbitrary number used to identify the parachain within the storage of the
    /// relay chain.
    ///
    /// > **Note**: This information is normally found in the chain specification of the
    /// >           parachain.
    pub para_id: u32,
}

pub struct SyncService<TPlat: PlatformRef> {
    /// Sender of messages towards the background task.
    to_background: async_channel::Sender<ToBackground>,

    /// See [`Config::platform`].
    platform: TPlat,

    /// See [`Config::network_service`].
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    /// See [`Config::block_number_bytes`].
    block_number_bytes: usize,
}

impl<TPlat: PlatformRef> SyncService<TPlat> {
    pub fn new(config: Config<TPlat>) -> Self {
        let (to_background, from_foreground) = async_channel::bounded(16);
        let from_foreground = Box::pin(from_foreground);

        let log_target = format!("sync-service-{}", config.log_name);

        let task: Pin<Box<dyn Future<Output = ()> + Send>> = match config.chain_type {
            ConfigChainType::Parachain(config_parachain) => Box::pin(parachain::start_parachain(
                log_target.clone(),
                config.platform.clone(),
                config_parachain.finalized_block_header,
                config.block_number_bytes,
                config_parachain.relay_chain.relay_chain_sync.clone(),
                config_parachain.relay_chain.para_id,
                from_foreground,
                config.network_service.clone(),
            )),
            ConfigChainType::SubstrateCompatible(config_substrate_compat) => {
                Box::pin(substrate_compat::start_substrate_compatible_chain(
                    log_target.clone(),
                    config.platform.clone(),
                    config_substrate_compat.chain_information,
                    config.block_number_bytes,
                    config_substrate_compat
                        .relay_chain
                        .map(|rc| (rc.relay_chain_sync, rc.para_id)),
                    config_substrate_compat.runtime_code_hint,
                    from_foreground,
                    config.network_service.clone(),
                ))
            }
        };

        config.platform.spawn_task(log_target.clone().into(), {
            let platform = config.platform.clone();
            async move {
                task.await;
                log!(&platform, Debug, &log_target, "shutdown");
            }
        });

        SyncService {
            to_background,
            platform: config.platform,
            network_service: config.network_service,
            block_number_bytes: config.block_number_bytes,
        }
    }

    /// Returns the value initially passed as [`Config::block_number_bytes`̀].
    pub fn block_number_bytes(&self) -> usize {
        self.block_number_bytes
    }

    /// Returns the state of the finalized block of the chain, after passing it through
    /// [`smoldot::database::finalized_serialize::encode_chain`].
    ///
    /// Returns `None` if this information couldn't be obtained because not enough is known about
    /// the chain.
    pub async fn serialize_chain_information(
        &self,
    ) -> Option<chain::chain_information::ValidChainInformation> {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .send(ToBackground::SerializeChainInformation { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Subscribes to the state of the chain: the current state and the new blocks.
    ///
    /// All new blocks are reported. Only up to `buffer_size` block notifications are buffered
    /// in the channel. If the channel is full when a new notification is attempted to be pushed,
    /// the channel gets closed.
    ///
    /// The channel also gets closed if a gap in the finality happens, such as after a Grandpa
    /// warp syncing.
    ///
    /// See [`SubscribeAll`] for information about the return value.
    ///
    /// If `runtime_interest` is `false`, then [`SubscribeAll::finalized_block_runtime`] will
    /// always be `None`. Since the runtime can only be provided to one call to this function,
    /// only one subscriber should use `runtime_interest` equal to `true`.
    ///
    /// While this function is asynchronous, it is guaranteed to finish relatively quickly. Only
    /// CPU operations are performed.
    pub async fn subscribe_all(&self, buffer_size: usize, runtime_interest: bool) -> SubscribeAll {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .send(ToBackground::SubscribeAll {
                send_back,
                buffer_size,
                runtime_interest,
            })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns true if it is believed that we are near the head of the chain.
    ///
    /// The way this method is implemented is opaque and cannot be relied on. The return value
    /// should only ever be shown to the user and not used for any meaningful logic.
    pub async fn is_near_head_of_chain_heuristic(&self) -> bool {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .send(ToBackground::IsNearHeadOfChainHeuristic { send_back })
            .await
            .unwrap();

        rx.await.unwrap()
    }

    /// Returns the list of peers from the [`network_service::NetworkService`] that are used to
    /// synchronize blocks.
    ///
    /// Returns, for each peer, their identity and best block number and hash.
    ///
    /// This function is subject to race condition. The list returned by this function can change
    /// at any moment. The return value should only ever be shown to the user and not used for any
    /// meaningful logic
    pub async fn syncing_peers(
        &self,
    ) -> impl ExactSizeIterator<Item = (PeerId, codec::Role, u64, [u8; 32])> {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .send(ToBackground::SyncingPeers { send_back })
            .await
            .unwrap();

        rx.await.unwrap().into_iter()
    }

    /// Returns the list of peers from the [`network_service::NetworkService`] that are expected to
    /// be aware of the given block.
    ///
    /// A peer is returned by this method either if it has directly sent a block announce in the
    /// past, or if the requested block height is below the finalized block height and the best
    /// block of the peer is above the requested block. In other words, it is assumed that all
    /// peers are always on the same finalized chain as the local node.
    ///
    /// This function is subject to race condition. The list returned by this function is not
    /// necessarily exact, as a peer might have known about a block in the past but no longer
    /// does.
    pub async fn peers_assumed_know_blocks(
        &self,
        block_number: u64,
        block_hash: &[u8; 32],
    ) -> impl Iterator<Item = PeerId> {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .send(ToBackground::PeersAssumedKnowBlock {
                send_back,
                block_number,
                block_hash: *block_hash,
            })
            .await
            .unwrap();

        rx.await.unwrap().into_iter()
    }

    // TODO: doc; explain the guarantees
    pub async fn block_query(
        self: Arc<Self>,
        block_number: u64,
        hash: [u8; 32],
        fields: codec::BlocksRequestFields,
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZero<u32>,
    ) -> Result<codec::BlockData, ()> {
        // TODO: better error?
        let request_config = codec::BlocksRequestConfig {
            start: codec::BlocksRequestConfigStart::Hash(hash),
            desired_count: NonZero::<u32>::new(1).unwrap(),
            direction: codec::BlocksRequestDirection::Ascending,
            fields: fields.clone(),
        };

        // TODO: handle max_parallel
        // TODO: better peers selection ; don't just take the first 3
        for target in self
            .peers_assumed_know_blocks(block_number, &hash)
            .await
            .take(usize::try_from(total_attempts).unwrap_or(usize::MAX))
        {
            let mut result = match self
                .network_service
                .clone()
                .blocks_request(target.clone(), request_config.clone(), timeout_per_request)
                .await
            {
                Ok(b) if !b.is_empty() => b,
                Ok(_) | Err(_) => {
                    self.network_service
                        .ban_and_disconnect(
                            target,
                            network_service::BanSeverity::Low,
                            "blocks-request-failed",
                        )
                        .await;
                    continue;
                }
            };

            return Ok(result.remove(0));
        }

        Err(())
    }

    // TODO: doc; explain the guarantees
    pub async fn block_query_unknown_number(
        self: Arc<Self>,
        hash: [u8; 32],
        fields: codec::BlocksRequestFields,
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZero<u32>,
    ) -> Result<codec::BlockData, ()> {
        // TODO: better error?
        let request_config = codec::BlocksRequestConfig {
            start: codec::BlocksRequestConfigStart::Hash(hash),
            desired_count: NonZero::<u32>::new(1).unwrap(),
            direction: codec::BlocksRequestDirection::Ascending,
            fields: fields.clone(),
        };

        // TODO: handle max_parallel
        // TODO: better peers selection ; don't just take the first
        for target in self
            .network_service
            .peers_list()
            .await
            .take(usize::try_from(total_attempts).unwrap_or(usize::MAX))
        {
            let mut result = match self
                .network_service
                .clone()
                .blocks_request(target, request_config.clone(), timeout_per_request)
                .await
            {
                Ok(b) if !b.is_empty() => b,
                Ok(_) | Err(_) => {
                    // Because we have no idea whether the block is canonical, it might be
                    // totally legitimate for the peer to refuse the request. For this reason,
                    // we don't ban it.
                    continue;
                }
            };

            return Ok(result.remove(0));
        }

        Err(())
    }

    /// Performs one or more storage proof requests in order to fulfill the `requests` passed as
    /// parameter.
    ///
    /// Must be passed a block hash, a block number, and the Merkle value of the root node of the
    /// storage trie of this same block. The value of `block_number` corresponds to the value
    /// in the [`smoldot::header::HeaderRef::number`] field, and the value of `main_trie_root_hash`
    /// corresponds to the value in the [`smoldot::header::HeaderRef::state_root`] field.
    ///
    /// The result will contain items corresponding to the requests, but in no particular order.
    ///
    /// See the documentation of [`StorageRequestItem`] and [`StorageResultItem`] for more
    /// information.
    pub fn storage_query(
        self: Arc<Self>,
        block_number: u64,
        block_hash: [u8; 32],
        main_trie_root_hash: [u8; 32],
        requests: impl Iterator<Item = StorageRequestItem>,
        total_attempts: u32,
        timeout_per_request: Duration,
        max_parallel: NonZero<u32>,
    ) -> StorageQuery<TPlat> {
        let total_attempts = usize::try_from(total_attempts).unwrap_or(usize::MAX);

        let requests = requests
            .map(|request| match request.ty {
                StorageRequestItemTy::DescendantsHashes
                | StorageRequestItemTy::DescendantsValues => RequestImpl::PrefixScan {
                    scan: prefix_proof::prefix_scan(prefix_proof::Config {
                        prefix: &request.key,
                        trie_root_hash: main_trie_root_hash,
                        full_storage_values_required: matches!(
                            request.ty,
                            StorageRequestItemTy::DescendantsValues
                        ),
                    }),
                    requested_key: request.key,
                },
                StorageRequestItemTy::Value => RequestImpl::ValueOrHash {
                    key: request.key,
                    hash: false,
                },
                StorageRequestItemTy::Hash => RequestImpl::ValueOrHash {
                    key: request.key,
                    hash: true,
                },
                StorageRequestItemTy::MerkleProof => RequestImpl::MerkleProof { key: request.key },
                StorageRequestItemTy::ClosestDescendantMerkleValue => {
                    RequestImpl::ClosestDescendantMerkleValue { key: request.key }
                }
            })
            .enumerate()
            .collect::<Vec<_>>();

        StorageQuery {
            block_number,
            block_hash,
            main_trie_root_hash,
            total_attempts,
            timeout_per_request,
            _max_parallel: max_parallel,
            outcome_errors: Vec::with_capacity(total_attempts),
            available_results: VecDeque::with_capacity(requests.len() * 4),
            requests_remaining: requests,
            response_nodes_cap: (16 * 1024 * 1024) / 164,
            randomness: rand_chacha::ChaCha20Rng::from_seed({
                let mut seed = [0; 32];
                self.platform.fill_random_bytes(&mut seed);
                seed
            }),
            sync_service: self,
        }
    }
}

/// An item requested with [`SyncService::storage_query`].
#[derive(Debug, Clone)]
pub struct StorageRequestItem {
    /// Key to request. Exactly what is requested depends on [`StorageRequestItem::ty`].
    pub key: Vec<u8>,
    /// Detail about what is being requested.
    pub ty: StorageRequestItemTy,
}

/// See [`StorageRequestItem::ty`].
#[derive(Debug, Clone)]
pub enum StorageRequestItemTy {
    /// The storage value associated to the [`StorageRequestItem::key`] is requested.
    /// A [`StorageResultItem::Value`] will be returned containing the potential value.
    Value,

    /// The hash of the storage value associated to the [`StorageRequestItem::key`] is requested.
    /// A [`StorageResultItem::Hash`] will be returned containing the potential hash.
    Hash,

    /// The merkle proof of the storage value associated to the [`StorageRequestItem::key`] is requested.
    /// A [`StorageResultItem::MerkleProof`] will be returned containing the proof.
    MerkleProof,

    /// The list of the descendants of the [`StorageRequestItem::key`] (including the `key`
    /// itself) that have a storage value is requested.
    ///
    /// Zero or more [`StorageResultItem::DescendantValue`] will be returned.
    DescendantsValues,

    /// The list of the descendants of the [`StorageRequestItem::key`] (including the `key`
    /// itself) that have a storage value is requested.
    ///
    /// Zero or more [`StorageResultItem::DescendantHash`] will be returned.
    DescendantsHashes,

    /// The Merkle value of the trie node that is the closest ancestor to
    /// [`StorageRequestItem::key`] is requested.
    /// A [`StorageResultItem::ClosestDescendantMerkleValue`] will be returned.
    ClosestDescendantMerkleValue,
}

/// An item returned by [`SyncService::storage_query`].
#[derive(Debug, Clone)]
pub enum StorageResultItem {
    /// Corresponds to a [`StorageRequestItemTy::Value`].
    Value {
        /// Key that was requested. Equal to the value of [`StorageRequestItem::key`].
        key: Vec<u8>,
        /// Storage value of the key, or `None` if there is no storage value associated with that
        /// key.
        value: Option<Vec<u8>>,
    },
    /// Corresponds to a [`StorageRequestItemTy::Hash`].
    Hash {
        /// Key that was requested. Equal to the value of [`StorageRequestItem::key`].
        key: Vec<u8>,
        /// Hash of the storage value of the key, or `None` if there is no storage value
        /// associated with that key.
        hash: Option<[u8; 32]>,
    },
    /// Corresponds to a [`StorageRequestItemTy::MerkleProof`].
    MerkleProof {
        /// Merkle proof of the storage value of the key.
        proof: Vec<u8>,
    },
    /// Corresponds to a [`StorageRequestItemTy::DescendantsValues`].
    DescendantValue {
        /// Equal or a descendant of the requested key.
        key: Vec<u8>,
        /// Storage value associated with [`StorageResultItem::DescendantValue::key`].
        value: Vec<u8>,
    },
    /// Corresponds to a [`StorageRequestItemTy::DescendantsHashes`].
    DescendantHash {
        /// Equal or a descendant of the requested key.
        key: Vec<u8>,
        /// Hash of the storage value associated with [`StorageResultItem::DescendantHash::key`].
        hash: [u8; 32],
    },
    /// Corresponds to a [`StorageRequestItemTy::ClosestDescendantMerkleValue`].
    ClosestDescendantMerkleValue {
        /// Key that was requested. Equal to the value of [`StorageRequestItem::key`].
        requested_key: Vec<u8>,
        /// Closest ancestor to the requested key that was found in the proof. If
        /// [`StorageResultItem::ClosestDescendantMerkleValue::closest_descendant_merkle_value`]
        /// is `Some`, then this is always the parent of the requested key.
        found_closest_ancestor_excluding: Option<Vec<Nibble>>,
        /// Merkle value of the closest descendant of the requested key. The key that corresponds
        /// to this Merkle value is not included. `None` if the key has no descendant.
        closest_descendant_merkle_value: Option<Vec<u8>>,
    },
}

/// Returned by [`SyncService::storage_query`]. Represents a storage query in progress.
pub struct StorageQuery<TPlat: PlatformRef> {
    sync_service: Arc<SyncService<TPlat>>,
    block_number: u64,
    block_hash: [u8; 32],
    main_trie_root_hash: [u8; 32],
    /// Requests that haven't been fulfilled yet.
    /// The `usize` is the index of the request in the original list of requests that the API user
    /// provided.
    requests_remaining: Vec<(usize, RequestImpl)>,
    /// Total number of network requests to try before giving up.
    total_attempts: usize,
    /// How long to wait for a response to the request.
    timeout_per_request: Duration,
    // TODO: value presently ignored
    _max_parallel: NonZero<u32>,
    /// Non-fatal errors that have happened in the network requests.
    outcome_errors: Vec<StorageQueryErrorDetail>,
    /// List of responses that are available to yield.
    /// The `usize` is the index of the request in the original list of requests that the API user
    /// provided.
    available_results: VecDeque<(usize, StorageResultItem)>,
    /// Number of nodes that are possible in a response before exceeding the response size
    /// limit. Because the size of a trie node is unknown, this can only ever be a gross
    /// estimate.
    /// If a request fails due to the limit being exceeded, this cap is dynamically reduced.
    response_nodes_cap: usize,
    /// Source of randomness.
    randomness: rand_chacha::ChaCha20Rng,
}

enum RequestImpl {
    PrefixScan {
        requested_key: Vec<u8>,
        scan: prefix_proof::PrefixScan,
    },
    ValueOrHash {
        key: Vec<u8>,
        hash: bool,
    },
    MerkleProof {
        key: Vec<u8>,
    },
    ClosestDescendantMerkleValue {
        key: Vec<u8>,
    },
}

impl<TPlat: PlatformRef> StorageQuery<TPlat> {
    /// Drain any other item that might be immediately available.
    ///
    /// The `usize` corresponds to [`StorageQueryProgress::Progress::request_index`].
    pub fn try_advance(&mut self) -> Option<(usize, StorageResultItem)> {
        self.available_results.pop_front()
    }

    /// Wait until some progress is made.
    pub async fn advance(mut self) -> StorageQueryProgress<TPlat> {
        loop {
            // TODO: instead of buffering everything here, progressively decode the proof
            if let Some((request_index, item)) = self.available_results.pop_front() {
                return StorageQueryProgress::Progress {
                    request_index,
                    item,
                    query: self,
                };
            }

            // Check if we're done.
            if self.requests_remaining.is_empty() {
                return StorageQueryProgress::Finished;
            }

            if self.outcome_errors.len() >= self.total_attempts {
                return StorageQueryProgress::Error(StorageQueryError {
                    errors: self.outcome_errors,
                });
            }

            // Choose peer to query.
            // TODO: better peers selection
            let Some(target) = self
                .sync_service
                .peers_assumed_know_blocks(self.block_number, &self.block_hash)
                .await
                .choose(&mut self.randomness)
            else {
                // No peer knows this block. Returning with a failure.
                return StorageQueryProgress::Error(StorageQueryError {
                    errors: self.outcome_errors,
                });
            };

            // Build the list of keys to request.
            let keys_to_request = {
                // Keep track of the number of nodes that might be found in the response.
                // This is a generous overestimation of the actual number.
                let mut max_reponse_nodes = 0;

                let mut keys = hashbrown::HashSet::with_capacity_and_hasher(
                    self.requests_remaining.len() * 4,
                    fnv::FnvBuildHasher::default(),
                );

                for (_, request) in &self.requests_remaining {
                    if max_reponse_nodes >= self.response_nodes_cap {
                        break;
                    }

                    match request {
                        RequestImpl::PrefixScan { scan, .. } => {
                            for scan_key in scan.requested_keys() {
                                if max_reponse_nodes >= self.response_nodes_cap {
                                    break;
                                }

                                let scan_key = trie::nibbles_to_bytes_suffix_extend(scan_key)
                                    .collect::<Vec<_>>();
                                let scan_key_len = scan_key.len();
                                if keys.insert(scan_key) {
                                    max_reponse_nodes += scan_key_len * 2;
                                }
                            }
                        }
                        RequestImpl::ValueOrHash { key, .. } | RequestImpl::MerkleProof { key } => {
                            if keys.insert(key.clone()) {
                                max_reponse_nodes += key.len() * 2;
                            }
                        }
                        RequestImpl::ClosestDescendantMerkleValue { key } => {
                            // We query the parent of `key`.
                            if key.is_empty() {
                                if keys.insert(Vec::new()) {
                                    max_reponse_nodes += 1;
                                }
                            } else if keys.insert(key[..key.len() - 1].to_owned()) {
                                max_reponse_nodes += key.len() * 2 - 1;
                            }
                        }
                    }
                }

                keys
            };

            let result = self
                .sync_service
                .network_service
                .clone()
                .storage_proof_request(
                    target.clone(),
                    codec::StorageProofRequestConfig {
                        block_hash: self.block_hash,
                        keys: keys_to_request.into_iter(),
                    },
                    self.timeout_per_request,
                )
                .await;

            let proof = match result {
                Ok(r) => r,
                Err(err) => {
                    // In case of error that isn't a protocol error, we reduce the number of
                    // trie node items to request.
                    let reduce_max = match &err {
                        network_service::StorageProofRequestError::RequestTooLarge => true,
                        network_service::StorageProofRequestError::Request(
                            service::StorageProofRequestError::Request(err),
                        ) => !err.is_protocol_error(),
                        _ => false,
                    };

                    if !matches!(
                        err,
                        network_service::StorageProofRequestError::RequestTooLarge
                    ) || self.response_nodes_cap == 1
                    {
                        self.sync_service
                            .network_service
                            .ban_and_disconnect(
                                target,
                                network_service::BanSeverity::Low,
                                "storage-request-failed",
                            )
                            .await;
                        self.outcome_errors
                            .push(StorageQueryErrorDetail::Network(err));
                    }

                    if reduce_max {
                        self.response_nodes_cap = cmp::max(1, self.response_nodes_cap / 2);
                    }

                    continue;
                }
            };

            let proof_bytes = proof.decode();
            let decoded_proof = match proof_decode::decode_and_verify_proof(proof_decode::Config {
                proof: proof_bytes.as_ref(),
            }) {
                Ok(d) => d,
                Err(err) => {
                    self.sync_service
                        .network_service
                        .ban_and_disconnect(
                            target,
                            network_service::BanSeverity::High,
                            "bad-merkle-proof",
                        )
                        .await;
                    self.outcome_errors
                        .push(StorageQueryErrorDetail::ProofVerification(err));
                    continue;
                }
            };

            let mut proof_has_advanced_verification = false;

            for (request_index, request) in mem::take(&mut self.requests_remaining) {
                match request {
                    RequestImpl::PrefixScan {
                        scan,
                        requested_key,
                    } => {
                        // TODO: how "partial" do we accept that the proof is? it should be considered malicious if the full node might return the minimum amount of information
                        match scan.resume_partial(proof_bytes) {
                            Ok(prefix_proof::ResumeOutcome::InProgress(scan)) => {
                                proof_has_advanced_verification = true;
                                self.requests_remaining.push((
                                    request_index,
                                    RequestImpl::PrefixScan {
                                        scan,
                                        requested_key,
                                    },
                                ));
                            }
                            Ok(prefix_proof::ResumeOutcome::Success {
                                entries,
                                full_storage_values_required,
                            }) => {
                                proof_has_advanced_verification = true;
                                // The value of `full_storage_values_required` determines whether
                                // we wanted full values (`true`) or hashes (`false`).
                                for (key, value) in entries {
                                    match value {
                                        prefix_proof::StorageValue::Hash(hash) => {
                                            debug_assert!(!full_storage_values_required);
                                            self.available_results.push_back((
                                                request_index,
                                                StorageResultItem::DescendantHash { key, hash },
                                            ));
                                        }
                                        prefix_proof::StorageValue::Value(value)
                                            if full_storage_values_required =>
                                        {
                                            self.available_results.push_back((
                                                request_index,
                                                StorageResultItem::DescendantValue { key, value },
                                            ));
                                        }
                                        prefix_proof::StorageValue::Value(value) => {
                                            let hashed_value =
                                                blake2_rfc::blake2b::blake2b(32, &[], &value);
                                            self.available_results.push_back((
                                                request_index,
                                                StorageResultItem::DescendantHash {
                                                    key,
                                                    hash: *<&[u8; 32]>::try_from(
                                                        hashed_value.as_bytes(),
                                                    )
                                                    .unwrap(),
                                                },
                                            ));
                                        }
                                    }
                                }
                            }
                            Err((_, prefix_proof::Error::InvalidProof(_))) => {
                                // Since we decode the proof above, this is never supposed to
                                // be reachable.
                                unreachable!()
                            }
                            Err((scan, prefix_proof::Error::MissingProofEntry)) => {
                                self.requests_remaining.push((
                                    request_index,
                                    RequestImpl::PrefixScan {
                                        requested_key,
                                        scan,
                                    },
                                ));
                            }
                        }
                    }
                    RequestImpl::ValueOrHash { key, hash } => {
                        match decoded_proof.trie_node_info(
                            &self.main_trie_root_hash,
                            trie::bytes_to_nibbles(key.iter().copied()),
                        ) {
                            Ok(node_info) => match node_info.storage_value {
                                proof_decode::StorageValue::HashKnownValueMissing(h) if hash => {
                                    proof_has_advanced_verification = true;
                                    self.available_results.push_back((
                                        request_index,
                                        StorageResultItem::Hash {
                                            key,
                                            hash: Some(*h),
                                        },
                                    ));
                                }
                                proof_decode::StorageValue::HashKnownValueMissing(_) => {
                                    self.requests_remaining.push((
                                        request_index,
                                        RequestImpl::ValueOrHash { key, hash },
                                    ));
                                }
                                proof_decode::StorageValue::Known { value, .. } => {
                                    proof_has_advanced_verification = true;
                                    if hash {
                                        let hashed_value =
                                            blake2_rfc::blake2b::blake2b(32, &[], value);
                                        self.available_results.push_back((
                                            request_index,
                                            StorageResultItem::Hash {
                                                key,
                                                hash: Some(
                                                    *<&[u8; 32]>::try_from(hashed_value.as_bytes())
                                                        .unwrap(),
                                                ),
                                            },
                                        ));
                                    } else {
                                        self.available_results.push_back((
                                            request_index,
                                            StorageResultItem::Value {
                                                key,
                                                value: Some(value.to_vec()),
                                            },
                                        ));
                                    }
                                }
                                proof_decode::StorageValue::None => {
                                    proof_has_advanced_verification = true;
                                    if hash {
                                        self.available_results.push_back((
                                            request_index,
                                            StorageResultItem::Hash { key, hash: None },
                                        ));
                                    } else {
                                        self.available_results.push_back((
                                            request_index,
                                            StorageResultItem::Value { key, value: None },
                                        ));
                                    }
                                }
                            },
                            Err(proof_decode::IncompleteProofError { .. }) => {
                                self.requests_remaining
                                    .push((request_index, RequestImpl::ValueOrHash { key, hash }));
                            }
                        }
                    }
                    RequestImpl::MerkleProof { key } => {
                        match decoded_proof.trie_node_info(
                            &self.main_trie_root_hash,
                            trie::bytes_to_nibbles(key.iter().copied()),
                        ) {
                            Ok(_) => self.available_results.push_back((
                                request_index,
                                StorageResultItem::MerkleProof {
                                    proof: minimize_proof::minimize_proof(
                                        &decoded_proof,
                                        &self.main_trie_root_hash,
                                        &key,
                                    )
                                    .unwrap(),
                                },
                            )),
                            Err(proof_decode::IncompleteProofError { .. }) => {
                                self.requests_remaining
                                    .push((request_index, RequestImpl::MerkleProof { key }));
                            }
                        }
                    }
                    RequestImpl::ClosestDescendantMerkleValue { key } => {
                        let key_nibbles = trie::bytes_to_nibbles(key.iter().copied());

                        let closest_descendant_merkle_value = match decoded_proof
                            .closest_descendant_merkle_value(
                                &self.main_trie_root_hash,
                                key_nibbles.clone(),
                            ) {
                            Ok(Some(merkle_value)) => Some(merkle_value.to_vec()),
                            Ok(None) => None,
                            Err(proof_decode::IncompleteProofError { .. }) => {
                                self.requests_remaining.push((
                                    request_index,
                                    RequestImpl::ClosestDescendantMerkleValue { key },
                                ));
                                continue;
                            }
                        };

                        let found_closest_ancestor_excluding = match decoded_proof
                            .closest_ancestor_in_proof(&self.main_trie_root_hash, key_nibbles)
                        {
                            Ok(Some(ancestor)) => Some(ancestor.collect::<Vec<_>>()),
                            Ok(None) => None,
                            Err(proof_decode::IncompleteProofError { .. }) => {
                                self.requests_remaining.push((
                                    request_index,
                                    RequestImpl::ClosestDescendantMerkleValue { key },
                                ));
                                continue;
                            }
                        };

                        proof_has_advanced_verification = true;

                        self.available_results.push_back((
                            request_index,
                            StorageResultItem::ClosestDescendantMerkleValue {
                                requested_key: key,
                                closest_descendant_merkle_value,
                                found_closest_ancestor_excluding,
                            },
                        ))
                    }
                }
            }

            // If the proof doesn't contain any item that reduces the number of things to request,
            // then we push an error.
            if !proof_has_advanced_verification {
                self.outcome_errors
                    .push(StorageQueryErrorDetail::MissingProofEntry);
            }
        }
    }
}

/// Progress in a storage query. Returned by [`StorageQuery::advance`].
pub enum StorageQueryProgress<TPlat: PlatformRef> {
    /// The query has successfully finished. All the items have been yielded through
    /// [`StorageQueryProgress::Progress`].
    Finished,
    /// The query has yielded an item.
    Progress {
        /// Index within the original list of requests passed to [`SyncService::storage_query`]
        /// the item corresponds to.
        request_index: usize,
        /// The item in question.
        item: StorageResultItem,
        /// Query to use to continue advancing.
        query: StorageQuery<TPlat>,
    },
    /// The query has failed due to having reached the maximum number of errors.
    Error(StorageQueryError),
}

/// Error that can happen when calling [`SyncService::storage_query`].
// TODO: remove?
#[derive(Debug, Clone, derive_more::Error)]
pub struct StorageQueryError {
    /// Contains one error per peer that has been contacted. If this list is empty, then we
    /// aren't connected to any node.
    pub errors: Vec<StorageQueryErrorDetail>,
}

impl StorageQueryError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        self.errors.iter().all(|err| match err {
            StorageQueryErrorDetail::Network(
                network_service::StorageProofRequestError::Request(
                    service::StorageProofRequestError::Request(_)
                    | service::StorageProofRequestError::RemoteCouldntAnswer,
                ),
            )
            | StorageQueryErrorDetail::Network(
                network_service::StorageProofRequestError::NoConnection,
            ) => true,
            StorageQueryErrorDetail::Network(
                network_service::StorageProofRequestError::Request(
                    service::StorageProofRequestError::Decode(_),
                )
                | network_service::StorageProofRequestError::RequestTooLarge,
            ) => false,
            StorageQueryErrorDetail::ProofVerification(_)
            | StorageQueryErrorDetail::MissingProofEntry => false,
        })
    }
}

impl fmt::Display for StorageQueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.errors.is_empty() {
            write!(f, "No node available for storage query")
        } else {
            write!(f, "Storage query errors:")?;
            for err in &self.errors {
                write!(f, "\n- {err}")?;
            }
            Ok(())
        }
    }
}

/// See [`StorageQueryError`].
#[derive(Debug, derive_more::Display, derive_more::Error, Clone)]
pub enum StorageQueryErrorDetail {
    /// Error during the network request.
    #[display("{_0}")]
    Network(network_service::StorageProofRequestError),
    /// Error verifying the proof.
    #[display("{_0}")]
    ProofVerification(proof_decode::Error),
    /// Proof is missing one or more desired storage items.
    MissingProofEntry,
}

/// Return value of [`SyncService::subscribe_all`].
pub struct SubscribeAll {
    /// SCALE-encoded header of the finalized block at the time of the subscription.
    pub finalized_block_scale_encoded_header: Vec<u8>,

    /// Runtime of the finalized block, if known.
    ///
    /// > **Note**: In order to do the initial synchronization, the sync service might have to
    /// >           download and use the runtime near the head of the chain. Throwing away this
    /// >           runtime at the end of the synchronization is possible, but would be wasteful.
    /// >           Instead, this runtime is provided here if possible, but no guarantee is
    /// >           offered that it can be found.
    pub finalized_block_runtime: Option<FinalizedBlockRuntime>,

    /// List of all known non-finalized blocks at the time of subscription.
    ///
    /// Only one element in this list has [`BlockNotification::is_new_best`] equal to true.
    ///
    /// The blocks are guaranteed to be ordered so that parents are always found before their
    /// children.
    pub non_finalized_blocks_ancestry_order: Vec<BlockNotification>,

    /// Channel onto which new blocks are sent. The channel gets closed if it is full when a new
    /// block needs to be reported.
    pub new_blocks: async_channel::Receiver<Notification>,
}

/// See [`SubscribeAll::finalized_block_runtime`].
pub struct FinalizedBlockRuntime {
    /// Compiled virtual machine.
    pub virtual_machine: host::HostVmPrototype,

    /// Storage value at the `:code` key.
    pub storage_code: Option<Vec<u8>>,

    /// Storage value at the `:heappages` key.
    pub storage_heap_pages: Option<Vec<u8>>,

    /// Merkle value of the `:code` key.
    pub code_merkle_value: Option<Vec<u8>>,

    /// Closest ancestor of the `:code` key except for `:code` itself.
    pub closest_ancestor_excluding: Option<Vec<Nibble>>,
}

/// Notification about a new block or a new finalized block.
///
/// See [`SyncService::subscribe_all`].
#[derive(Debug, Clone)]
pub enum Notification {
    /// A non-finalized block has been finalized.
    Finalized {
        /// BLAKE2 hash of the block that has been finalized.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        ///
        /// It is, however, not guaranteed that this block is a child of the previously-finalized
        /// block. In other words, if multiple blocks are finalized at the same time, only one
        /// [`Notification::Finalized`] is generated and contains the highest finalized block.
        hash: [u8; 32],

        /// If the current best block is pruned by the finalization, contains the updated hash
        /// of the best block after the finalization.
        ///
        /// If the newly-finalized block is an ancestor of the current best block, then this field
        /// contains the hash of this current best block. Otherwise, the best block is now
        /// the non-finalized block with the given hash.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        best_block_hash_if_changed: Option<[u8; 32]>,

        /// List of BLAKE2 hashes of the headers of the blocks that have been discarded because
        /// they're not descendants of the newly-finalized block.
        ///
        /// This list contains all the siblings of the newly-finalized block and all their
        /// descendants.
        pruned_blocks: Vec<[u8; 32]>,
    },

    /// A new block has been added to the list of unfinalized blocks.
    Block(BlockNotification),

    /// The best block has changed to a different one.
    BestBlockChanged {
        /// Hash of the new best block.
        ///
        /// This can be either the hash of the latest finalized block or the hash of a
        /// non-finalized block.
        hash: [u8; 32],
    },
}

/// Notification about a new block.
///
/// See [`SyncService::subscribe_all`].
#[derive(Debug, Clone)]
pub struct BlockNotification {
    /// True if this block is considered as the best block of the chain.
    pub is_new_best: bool,

    /// SCALE-encoded header of the block.
    pub scale_encoded_header: Vec<u8>,

    /// BLAKE2 hash of the header of the parent of this block.
    ///
    ///
    /// A block with this hash is guaranteed to have earlier been reported in a
    /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`] or
    /// in a [`Notification::Block`].
    ///
    /// > **Note**: The header of a block contains the hash of its parent. When it comes to
    /// >           consensus algorithms such as Babe or Aura, the syncing code verifies that this
    /// >           hash, stored in the header, actually corresponds to a valid block. However,
    /// >           when it comes to parachain consensus, no such verification is performed.
    /// >           Contrary to the hash stored in the header, the value of this field is
    /// >           guaranteed to refer to a block that is known by the syncing service. This
    /// >           allows a subscriber of the state of the chain to precisely track the hierarchy
    /// >           of blocks, without risking to run into a problem in case of a block with an
    /// >           invalid header.
    pub parent_hash: [u8; 32],
}

enum ToBackground {
    /// See [`SyncService::is_near_head_of_chain_heuristic`].
    IsNearHeadOfChainHeuristic { send_back: oneshot::Sender<bool> },
    /// See [`SyncService::subscribe_all`].
    SubscribeAll {
        send_back: oneshot::Sender<SubscribeAll>,
        buffer_size: usize,
        runtime_interest: bool,
    },
    /// See [`SyncService::peers_assumed_know_blocks`].
    PeersAssumedKnowBlock {
        send_back: oneshot::Sender<Vec<PeerId>>,
        block_number: u64,
        block_hash: [u8; 32],
    },
    /// See [`SyncService::syncing_peers`].
    SyncingPeers {
        send_back: oneshot::Sender<Vec<(PeerId, codec::Role, u64, [u8; 32])>>,
    },
    /// See [`SyncService::serialize_chain_information`].
    SerializeChainInformation {
        send_back: oneshot::Sender<Option<chain::chain_information::ValidChainInformation>>,
    },
}

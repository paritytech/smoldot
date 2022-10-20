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

use crate::{network_service, platform::Platform, runtime_service};

use alloc::{borrow::ToOwned as _, boxed::Box, format, string::String, sync::Arc, vec::Vec};
use core::{fmt, num::NonZeroU32, time::Duration};
use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use smoldot::{
    chain,
    executor::host,
    libp2p::PeerId,
    network::{protocol, service},
    trie::{self, prefix_proof, proof_verify},
};

mod parachain;
mod standalone;

/// Configuration for a [`SyncService`].
pub struct Config<TPlat: Platform> {
    /// Name of the chain, for logging purposes.
    ///
    /// > **Note**: This name will be directly printed out. Any special character should already
    /// >           have been filtered out from this name.
    pub log_name: String,

    /// State of the finalized chain.
    pub chain_information: chain::chain_information::ValidChainInformation,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(String, future::BoxFuture<'static, ()>) + Send>,

    /// Access to the network, and index of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (Arc<network_service::NetworkService<TPlat>>, usize),

    /// Receiver for events coming from the network, as returned by
    /// [`network_service::NetworkService::new`].
    pub network_events_receiver: stream::BoxStream<'static, network_service::Event>,

    /// Extra fields used when the chain is a parachain.
    /// If `None`, this chain is a standalone chain or a relay chain.
    pub parachain: Option<ConfigParachain<TPlat>>,
}

/// See [`Config::parachain`].
pub struct ConfigParachain<TPlat: Platform> {
    /// Runtime service that synchronizes the relay chain of this parachain.
    pub relay_chain_sync: Arc<runtime_service::RuntimeService<TPlat>>,

    /// Number of bytes used by the block number in the relay chain.
    pub relay_chain_block_number_bytes: usize,

    /// Id of the parachain within the relay chain.
    ///
    /// This is an arbitrary number used to identify the parachain within the storage of the
    /// relay chain.
    ///
    /// > **Note**: This information is normally found in the chain specification of the
    /// >           parachain.
    pub parachain_id: u32,
}

/// Identifier for a blocks request to be performed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BlocksRequestId(usize);

pub struct SyncService<TPlat: Platform> {
    /// Sender of messages towards the background task.
    to_background: Mutex<mpsc::Sender<ToBackground>>,

    /// See [`Config::network_service`].
    network_service: Arc<network_service::NetworkService<TPlat>>,
    /// See [`Config::network_service`].
    network_chain_index: usize,
    /// See [`Config::block_number_bytes`].
    block_number_bytes: usize,
}

impl<TPlat: Platform> SyncService<TPlat> {
    pub async fn new(mut config: Config<TPlat>) -> Self {
        let (to_background, from_foreground) = mpsc::channel(16);

        let log_target = format!("sync-service-{}", config.log_name);

        if let Some(config_parachain) = config.parachain {
            (config.tasks_executor)(
                log_target.clone(),
                Box::pin(parachain::start_parachain(
                    log_target,
                    config.chain_information,
                    config.block_number_bytes,
                    config_parachain.relay_chain_sync.clone(),
                    config_parachain.relay_chain_block_number_bytes,
                    config_parachain.parachain_id,
                    from_foreground,
                    config.network_service.1,
                    config.network_events_receiver,
                )),
            );
        } else {
            (config.tasks_executor)(
                log_target.clone(),
                Box::pin(standalone::start_standalone_chain(
                    log_target,
                    config.chain_information,
                    config.block_number_bytes,
                    from_foreground,
                    config.network_service.0.clone(),
                    config.network_service.1,
                    config.network_events_receiver,
                )),
            );
        }

        SyncService {
            to_background: Mutex::new(to_background),
            network_service: config.network_service.0,
            network_chain_index: config.network_service.1,
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
            .lock()
            .await
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
            .lock()
            .await
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
            .lock()
            .await
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
    ) -> impl ExactSizeIterator<Item = (PeerId, protocol::Role, u64, [u8; 32])> {
        let (send_back, rx) = oneshot::channel();

        self.to_background
            .lock()
            .await
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
            .lock()
            .await
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
        fields: protocol::BlocksRequestFields,
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZeroU32,
    ) -> Result<protocol::BlockData, ()> {
        // TODO: better error?
        let request_config = protocol::BlocksRequestConfig {
            start: protocol::BlocksRequestConfigStart::Hash(hash),
            desired_count: NonZeroU32::new(1).unwrap(),
            direction: protocol::BlocksRequestDirection::Ascending,
            fields: fields.clone(),
        };

        // TODO: handle max_parallel
        // TODO: better peers selection ; don't just take the first 3
        for target in self
            .peers_assumed_know_blocks(block_number, &hash)
            .await
            .take(usize::try_from(total_attempts).unwrap_or(usize::max_value()))
        {
            let mut result = match self
                .network_service
                .clone()
                .blocks_request(
                    target,
                    self.network_chain_index,
                    request_config.clone(),
                    timeout_per_request,
                )
                .await
            {
                Ok(b) => b,
                Err(_) => continue,
            };

            return Ok(result.remove(0));
        }

        Err(())
    }

    // TODO: doc; explain the guarantees
    pub async fn block_query_unknown_number(
        self: Arc<Self>,
        hash: [u8; 32],
        fields: protocol::BlocksRequestFields,
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZeroU32,
    ) -> Result<protocol::BlockData, ()> {
        // TODO: better error?
        let request_config = protocol::BlocksRequestConfig {
            start: protocol::BlocksRequestConfigStart::Hash(hash),
            desired_count: NonZeroU32::new(1).unwrap(),
            direction: protocol::BlocksRequestDirection::Ascending,
            fields: fields.clone(),
        };

        // TODO: handle max_parallel
        // TODO: better peers selection ; don't just take the first
        for target in self
            .network_service
            .peers_list()
            .await
            .take(usize::try_from(total_attempts).unwrap_or(usize::max_value()))
        {
            let mut result = match self
                .network_service
                .clone()
                .blocks_request(
                    target,
                    self.network_chain_index,
                    request_config.clone(),
                    timeout_per_request,
                )
                .await
            {
                Ok(b) => b,
                Err(_) => continue,
            };

            return Ok(result.remove(0));
        }

        Err(())
    }

    /// Performs one or more storage proof requests in order to find the value of the given
    /// `requested_keys`.
    ///
    /// Must be passed a block hash, a block number, and the Merkle value of the root node of the
    /// storage trie of this same block. The value of `block_number` corresponds to the value
    /// in the [`smoldot::header::HeaderRef::number`] field, and the value of `storage_trie_root`
    /// corresponds to the value in the [`smoldot::header::HeaderRef::state_root`] field.
    ///
    /// Returns the storage values of `requested_keys` in the storage of the block, or an error if
    /// it couldn't be determined. If `Ok`, the `Vec` is guaranteed to have the same number of
    /// elements as `requested_keys`.
    ///
    /// This function is equivalent to calling
    /// [`network_service::NetworkService::storage_proof_request`] and verifying the proof,
    /// potentially multiple times until it succeeds. The number of attempts and the selection of
    /// peers is done through reasonable heuristics.
    pub async fn storage_query(
        self: Arc<Self>,
        block_number: u64,
        block_hash: &[u8; 32],
        storage_trie_root: &[u8; 32],
        requested_keys: impl Iterator<Item = impl AsRef<[u8]> + Clone> + Clone,
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZeroU32,
    ) -> Result<Vec<Option<Vec<u8>>>, StorageQueryError> {
        let mut outcome_errors =
            Vec::with_capacity(usize::try_from(total_attempts).unwrap_or(usize::max_value()));

        // TODO: better peers selection ; don't just take the first
        // TODO: handle max_parallel
        for target in self
            .peers_assumed_know_blocks(block_number, block_hash)
            .await
            .take(usize::try_from(total_attempts).unwrap_or(usize::max_value()))
        {
            let result = self
                .network_service
                .clone()
                .storage_proof_request(
                    self.network_chain_index,
                    target,
                    protocol::StorageProofRequestConfig {
                        block_hash: *block_hash,
                        keys: requested_keys.clone(),
                    },
                    timeout_per_request,
                )
                .await
                .map_err(StorageQueryErrorDetail::Network)
                .and_then(|outcome| {
                    let decoded = outcome.decode();
                    let mut result = Vec::with_capacity(requested_keys.clone().count());
                    for key in requested_keys.clone() {
                        result.push(
                            proof_verify::verify_proof(proof_verify::VerifyProofConfig {
                                proof: decoded.iter().map(|nv| &nv[..]),
                                requested_key: key.as_ref(),
                                trie_root_hash: &storage_trie_root,
                            })
                            .map_err(StorageQueryErrorDetail::ProofVerification)?
                            .map(|v| v.to_owned()),
                        );
                    }
                    debug_assert_eq!(result.len(), result.capacity());
                    Ok(result)
                });

            match result {
                Ok(values) => return Ok(values),
                Err(err) => {
                    outcome_errors.push(err);
                }
            }
        }

        Err(StorageQueryError {
            errors: outcome_errors,
        })
    }

    pub async fn storage_prefix_keys_query(
        self: Arc<Self>,
        block_number: u64,
        block_hash: &[u8; 32],
        prefix: &[u8],
        storage_trie_root: &[u8; 32],
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZeroU32,
    ) -> Result<Vec<Vec<u8>>, StorageQueryError> {
        let mut prefix_scan = prefix_proof::prefix_scan(prefix_proof::Config {
            prefix,
            trie_root_hash: *storage_trie_root,
        });

        'main_scan: loop {
            let mut outcome_errors =
                Vec::with_capacity(usize::try_from(total_attempts).unwrap_or(usize::max_value()));

            // TODO: better peers selection ; don't just take the first
            // TODO: handle max_parallel
            for target in self
                .peers_assumed_know_blocks(block_number, block_hash)
                .await
                .take(usize::try_from(total_attempts).unwrap_or(usize::max_value()))
            {
                let result = self
                    .network_service
                    .clone()
                    .storage_proof_request(
                        self.network_chain_index,
                        target,
                        protocol::StorageProofRequestConfig {
                            block_hash: *block_hash,
                            keys: prefix_scan.requested_keys().map(|nibbles| {
                                trie::nibbles_to_bytes_suffix_extend(nibbles).collect::<Vec<_>>()
                            }),
                        },
                        timeout_per_request,
                    )
                    .await
                    .map_err(StorageQueryErrorDetail::Network);

                match result {
                    Ok(proof) => {
                        let decoded_proof = proof.decode();
                        match prefix_scan.resume(decoded_proof.iter().map(|v| &v[..])) {
                            Ok(prefix_proof::ResumeOutcome::InProgress(scan)) => {
                                // Continue next step of the proof.
                                prefix_scan = scan;
                                continue 'main_scan;
                            }
                            Ok(prefix_proof::ResumeOutcome::Success { keys }) => {
                                return Ok(keys);
                            }
                            Err((scan, err)) => {
                                prefix_scan = scan;
                                outcome_errors
                                    .push(StorageQueryErrorDetail::ProofVerification(err));
                            }
                        }
                    }
                    Err(err) => {
                        outcome_errors.push(err);
                    }
                }
            }

            return Err(StorageQueryError {
                errors: outcome_errors,
            });
        }
    }

    // TODO: documentation
    // TODO: there's no proof that the call proof is actually correct
    pub async fn call_proof_query<'a>(
        self: Arc<Self>,
        block_number: u64,
        config: protocol::CallProofRequestConfig<
            'a,
            impl Iterator<Item = impl AsRef<[u8]>> + Clone,
        >,
        total_attempts: u32,
        timeout_per_request: Duration,
        _max_parallel: NonZeroU32,
    ) -> Result<network_service::EncodedMerkleProof, CallProofQueryError> {
        let mut outcome_errors =
            Vec::with_capacity(usize::try_from(total_attempts).unwrap_or(usize::max_value()));

        // TODO: better peers selection ; don't just take the first
        // TODO: handle max_parallel
        for target in self
            .peers_assumed_know_blocks(block_number, &config.block_hash)
            .await
            .take(usize::try_from(total_attempts).unwrap_or(usize::max_value()))
        {
            let result = self
                .network_service
                .clone()
                .call_proof_request(
                    self.network_chain_index,
                    target,
                    config.clone(),
                    timeout_per_request,
                )
                .await;

            match result {
                Ok(value) if !value.decode().is_empty() => return Ok(value),
                // TODO: this check of emptiness is a bit of a hack; it is necessary because Substrate responds to requests about blocks it doesn't know with an empty proof
                Ok(_) => outcome_errors.push(network_service::CallProofRequestError::Request(
                    service::CallProofRequestError::Request(
                        smoldot::libp2p::peers::RequestError::Substream(
                            smoldot::libp2p::connection::established::RequestError::SubstreamClosed,
                        ),
                    ),
                )),
                Err(err) => {
                    outcome_errors.push(err);
                }
            }
        }

        Err(CallProofQueryError {
            errors: outcome_errors,
        })
    }
}

/// Error that can happen when calling [`SyncService::storage_query`].
#[derive(Debug, Clone)]
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
                    service::StorageProofRequestError::Request(_),
                ),
            )
            | StorageQueryErrorDetail::Network(
                network_service::StorageProofRequestError::NoConnection,
            ) => true,
            StorageQueryErrorDetail::Network(
                network_service::StorageProofRequestError::Request(
                    service::StorageProofRequestError::Decode(_),
                ),
            ) => false,
            // TODO: as a temporary hack, we consider `TrieRootNotFound` as the remote not knowing about the requested block; see https://github.com/paritytech/substrate/pull/8046
            StorageQueryErrorDetail::ProofVerification(proof_verify::Error::TrieRootNotFound) => {
                true
            }
            StorageQueryErrorDetail::ProofVerification(_) => false,
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
                write!(f, "\n- {}", err)?;
            }
            Ok(())
        }
    }
}

/// See [`StorageQueryError`].
#[derive(Debug, derive_more::Display, Clone)]
pub enum StorageQueryErrorDetail {
    /// Error during the network request.
    #[display(fmt = "{}", _0)]
    Network(network_service::StorageProofRequestError),
    /// Error verifying the proof.
    #[display(fmt = "{}", _0)]
    ProofVerification(proof_verify::Error),
}

/// Error that can happen when calling [`SyncService::call_proof_query`].
#[derive(Debug, Clone)]
pub struct CallProofQueryError {
    /// Contains one error per peer that has been contacted. If this list is empty, then we
    /// aren't connected to any node.
    pub errors: Vec<network_service::CallProofRequestError>,
}

impl CallProofQueryError {
    /// Returns `true` if this is caused by networking issues, as opposed to a consensus-related
    /// issue.
    pub fn is_network_problem(&self) -> bool {
        self.errors.iter().all(|err| err.is_network_problem())
    }
}

impl fmt::Display for CallProofQueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.errors.is_empty() {
            write!(f, "No node available for call proof query")
        } else {
            write!(f, "Call proof query errors:")?;
            for err in &self.errors {
                write!(f, "\n- {}", err)?;
            }
            Ok(())
        }
    }
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
    pub new_blocks: mpsc::Receiver<Notification>,
}

/// See [`SubscribeAll::finalized_block_runtime`].
pub struct FinalizedBlockRuntime {
    /// Compiled virtual machine.
    pub virtual_machine: host::HostVmPrototype,

    /// Storage value at the `:code` key.
    pub storage_code: Option<Vec<u8>>,

    /// Storage value at the `:heappages` key.
    pub storage_heap_pages: Option<Vec<u8>>,
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

        /// Hash of the best block after the finalization.
        ///
        /// If the newly-finalized block is an ancestor of the current best block, then this field
        /// contains the hash of this current best block. Otherwise, the best block is now
        /// the non-finalized block with the given hash.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        best_block_hash: [u8; 32],
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
        send_back: oneshot::Sender<Vec<(PeerId, protocol::Role, u64, [u8; 32])>>,
    },
    /// See [`SyncService::serialize_chain_information`].
    SerializeChainInformation {
        send_back: oneshot::Sender<Option<chain::chain_information::ValidChainInformation>>,
    },
}

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

//! Background synchronization service.
//!
//! The [`ConsensusService`] manages a background task dedicated to synchronizing the chain with
//! the network and authoring blocks.
//! Importantly, its design is oriented towards the particular use case of the full node.

// TODO: doc
// TODO: re-review this once finished

use crate::{LogCallback, LogLevel, database_thread, jaeger_service, network_service};

use futures_channel::{mpsc, oneshot};
use futures_lite::FutureExt as _;
use futures_util::{
    SinkExt as _, StreamExt as _, future,
    stream::{self, FuturesUnordered},
};
use hashbrown::HashSet;
use rand::seq::IteratorRandom;
use smol::lock::Mutex;
use smoldot::{
    author,
    database::full_sqlite,
    executor::{self, host, runtime_call},
    header,
    identity::keystore,
    informant::HashDisplay,
    libp2p,
    network::{self, codec::BlockData},
    sync::all,
    trie,
    verify::body_only,
};
use std::{
    array,
    borrow::Cow,
    cmp, iter,
    num::NonZero,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

/// Configuration for a [`ConsensusService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(future::BoxFuture<'static, ()>) + Send>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Database to use to read and write information about the chain.
    pub database: Arc<database_thread::DatabaseThread>,

    /// Number of bytes of the block number in the networking protocol.
    pub block_number_bytes: usize,

    /// Hash of the genesis block.
    ///
    /// > **Note**: At the time of writing of this comment, the value in this field is used only
    /// >           to compare against a known genesis hash and print a warning.
    pub genesis_block_hash: [u8; 32],

    /// Stores of key to use for all block-production-related purposes.
    pub keystore: Arc<keystore::Keystore>,

    /// Access to the network, and identifier of the chain to sync from the point of view of the
    /// network service.
    pub network_service: (
        Arc<network_service::NetworkService>,
        network_service::ChainId,
    ),

    /// Receiver for events coming from the network, as returned by
    /// [`network_service::NetworkService::new`].
    pub network_events_receiver: stream::BoxStream<'static, network_service::Event>,

    /// Service to use to report traces.
    pub jaeger_service: Arc<jaeger_service::JaegerService>,

    /// A node has the authorization to author a block during a slot.
    ///
    /// In order for the network to perform well, a block should be authored and propagated
    /// throughout the peer-to-peer network before the end of the slot. In order for this to
    /// happen, the block creation process itself should end a few seconds before the end of the
    /// slot. This threshold after which the block creation should end is determined by this value.
    ///
    /// The moment in the slot when the authoring ends is determined by
    /// `slot_duration * slot_duration_author_ratio / u16::MAX`.
    /// For example, passing `u16::MAX` means that the entire slot is used. Passing
    /// `u16::MAX / 2` means that half of the slot is used.
    ///
    /// A typical value is `43691_u16`, representing 2/3 of a slot.
    ///
    /// Note that this value doesn't determine the moment when creating the block has ended, but
    /// the moment when creating the block should start its final phase.
    pub slot_duration_author_ratio: u16,
}

/// Summary of the state of the [`ConsensusService`].
#[derive(Debug, Clone)]
pub struct SyncState {
    pub best_block_number: u64,
    pub best_block_hash: [u8; 32],
    pub finalized_block_number: u64,
    pub finalized_block_hash: [u8; 32],
}

/// Background task that verifies blocks and emits requests.
pub struct ConsensusService {
    /// Used to communicate with the background task. Also used for the background task to detect
    /// a shutdown.
    to_background_tx: Mutex<mpsc::Sender<ToBackground>>,

    /// See [`Config::block_number_bytes`].
    block_number_bytes: usize,
}

enum ToBackground {
    SubscribeAll {
        buffer_size: usize,
        // TODO: unused field
        _max_finalized_pinned_blocks: NonZero<usize>,
        result_tx: oneshot::Sender<SubscribeAll>,
    },
    GetSyncState {
        result_tx: oneshot::Sender<SyncState>,
    },
    Unpin {
        // TODO: unused field
        _subscription_id: SubscriptionId,
        // TODO: unused field
        _block_hash: [u8; 32],
        /// Sends back `()` if the unpinning was successful or the subscription no longer exists.
        /// The sender is silently destroyed if the block hash was invalid.
        result_tx: oneshot::Sender<()>,
    },
    IsMajorSyncingHint {
        result_tx: oneshot::Sender<bool>,
    },
}

/// Potential error when calling [`ConsensusService::new`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum InitError {
    /// Database is corrupted.
    DatabaseCorruption(full_sqlite::CorruptedError),
    /// Error parsing the header of a block in the database.
    InvalidHeader(header::Error),
    /// `:code` key is missing from the finalized block storage.
    FinalizedCodeMissing,
    /// Error parsing the `:heappages` of the finalized block.
    FinalizedHeapPagesInvalid(executor::InvalidHeapPagesError),
    /// Error initializing the runtime of the finalized block.
    FinalizedRuntimeInit(executor::host::NewErr),
}

impl ConsensusService {
    /// Initializes the [`ConsensusService`] with the given configuration.
    pub async fn new(mut config: Config) -> Result<Arc<Self>, InitError> {
        // Perform the initial access to the database to load a bunch of information.
        let (
            finalized_block_number,
            finalized_heap_pages,
            finalized_code,
            best_block_hash,
            best_block_number,
            finalized_chain_information,
        ) = config
            .database
            .with_database({
                let block_number_bytes = config.block_number_bytes;
                move |database| {
                    // If the previous run of the full node crashed, the database will contain
                    // blocks that are no longer useful in any way. We purge them all here.
                    database
                        .purge_finality_orphans()
                        .map_err(InitError::DatabaseCorruption)?;

                    let finalized_block_hash = database
                        .finalized_block_hash()
                        .map_err(InitError::DatabaseCorruption)?;
                    let finalized_block_number = header::decode(
                        &database
                            .block_scale_encoded_header(&finalized_block_hash)
                            .map_err(InitError::DatabaseCorruption)?
                            .unwrap(), // A panic here would indicate a bug in the database code.
                        block_number_bytes,
                    )
                    .map_err(InitError::InvalidHeader)?
                    .number;
                    let best_block_hash = database.best_block_hash().unwrap();
                    let best_block_number = header::decode(
                        &database
                            .block_scale_encoded_header(&best_block_hash)
                            .map_err(InitError::DatabaseCorruption)?
                            .unwrap(), // A panic here would indicate a bug in the database code.
                        block_number_bytes,
                    )
                    .map_err(InitError::InvalidHeader)?
                    .number;
                    let finalized_chain_information =
                        match database.to_chain_information(&finalized_block_hash) {
                            Ok(info) => info,
                            Err(full_sqlite::StorageAccessError::Corrupted(err)) => {
                                return Err(InitError::DatabaseCorruption(err));
                            }
                            Err(full_sqlite::StorageAccessError::IncompleteStorage)
                            | Err(full_sqlite::StorageAccessError::UnknownBlock) => unreachable!(),
                        };
                    let finalized_code = match database.block_storage_get(
                        &finalized_block_hash,
                        iter::empty::<iter::Empty<_>>(),
                        trie::bytes_to_nibbles(b":code".iter().copied()).map(u8::from),
                    ) {
                        Ok(Some((code, _))) => code,
                        Ok(None) => return Err(InitError::FinalizedCodeMissing),
                        Err(full_sqlite::StorageAccessError::Corrupted(err)) => {
                            return Err(InitError::DatabaseCorruption(err));
                        }
                        Err(full_sqlite::StorageAccessError::IncompleteStorage)
                        | Err(full_sqlite::StorageAccessError::UnknownBlock) => unreachable!(),
                    };
                    let finalized_heap_pages = match database.block_storage_get(
                        &finalized_block_hash,
                        iter::empty::<iter::Empty<_>>(),
                        trie::bytes_to_nibbles(b":heappages".iter().copied()).map(u8::from),
                    ) {
                        Ok(Some((hp, _))) => Some(hp),
                        Ok(None) => None,
                        Err(full_sqlite::StorageAccessError::Corrupted(err)) => {
                            return Err(InitError::DatabaseCorruption(err));
                        }
                        Err(full_sqlite::StorageAccessError::IncompleteStorage)
                        | Err(full_sqlite::StorageAccessError::UnknownBlock) => unreachable!(),
                    };
                    Ok((
                        finalized_block_number,
                        finalized_heap_pages,
                        finalized_code,
                        best_block_hash,
                        best_block_number,
                        finalized_chain_information,
                    ))
                }
            })
            .await?;

        // The Kusama chain contains a fork hardcoded in the official Polkadot client.
        // See <https://github.com/paritytech/polkadot/blob/93f45f996a3d5592a57eba02f91f2fc2bc5a07cf/node/service/src/grandpa_support.rs#L111-L216>
        // Because we don't want to support this in smoldot, a warning is printed instead if we
        // recognize Kusama.
        // See also <https://github.com/paritytech/smoldot/issues/1866>.
        if config.genesis_block_hash
            == [
                176, 168, 212, 147, 40, 92, 45, 247, 50, 144, 223, 183, 230, 31, 135, 15, 23, 180,
                24, 1, 25, 122, 20, 156, 169, 54, 84, 73, 158, 163, 218, 254,
            ]
            && finalized_block_number <= 1500988
        {
            config.log_callback.log(
                LogLevel::Warn,
                "The Kusama chain is known to be borked at block #1491596. The official Polkadot \
                client works around this issue by hardcoding a fork in its source code. Smoldot \
                does not support this hardcoded fork and will thus fail to sync past this block."
                    .to_string(),
            );
        }

        let mut sync = all::AllSync::new(all::Config {
            chain_information: finalized_chain_information,
            block_number_bytes: config.block_number_bytes,
            allow_unknown_consensus_engines: false,
            sources_capacity: 32,
            blocks_capacity: {
                // This is the maximum number of blocks between two consecutive justifications.
                1024
            },
            max_disjoint_headers: 1024,
            max_requests_per_block: NonZero::<u32>::new(3).unwrap(),
            download_ahead_blocks: {
                // Assuming a verification speed of 1k blocks/sec and a 99th download time
                // percentile of two second, the number of blocks to download ahead of time
                // in order to not block is 2000.
                // In practice, however, the verification speed and download speed depend on
                // the chain and the machine of the user.
                NonZero::<u32>::new(2000).unwrap()
            },
            download_bodies: true,
            // We ask for all the chain-information-related storage proofs and call proofs to be
            // downloaded during the warp syncing in order to guarantee that the necessary
            // information will be found in the database at the next reload.
            download_all_chain_information_storage_proofs: true,
            code_trie_node_hint: None,
        });

        let finalized_runtime = {
            // Builds the runtime of the finalized block.
            // Assumed to always be valid, otherwise the block wouldn't have been
            // saved in the database, hence the large number of unwraps here.
            let heap_pages = executor::storage_heap_pages_to_value(finalized_heap_pages.as_deref())
                .map_err(InitError::FinalizedHeapPagesInvalid)?;
            executor::host::HostVmPrototype::new(executor::host::Config {
                module: finalized_code,
                heap_pages,
                exec_hint: executor::vm::ExecHint::ValidateAndCompile, // TODO: probably should be decided by the optimisticsync
                allow_unresolved_imports: false,
            })
            .map_err(InitError::FinalizedRuntimeInit)?
        };

        let block_author_sync_source = sync
            .prepare_add_source(best_block_number, best_block_hash)
            .add_source(None, NonFinalizedBlock::NotVerified);

        let (to_background_tx, to_background_rx) = mpsc::channel(4);

        let background_sync = SyncBackground {
            sync,
            block_author_sync_source,
            block_authoring: None,
            authored_block: None,
            slot_duration_author_ratio: config.slot_duration_author_ratio,
            keystore: config.keystore,
            finalized_runtime: Arc::new(finalized_runtime),
            network_service: config.network_service.0,
            network_chain_id: config.network_service.1,
            network_local_chain_update_needed: true,
            pending_block_announce: None,
            to_background_rx,
            blocks_notifications: Vec::with_capacity(8),
            pending_notification: None,
            from_network_service: config.network_events_receiver,
            database: config.database,
            database_catch_up_download: DatabaseCatchUpDownload::NoDownloadInProgress,
            database_catch_up_download_block_verification:
                DatabaseCatchUpDownloadBlockVerification::None,
            peers_source_id_map: Default::default(),
            sub_tasks: FuturesUnordered::new(),
            log_callback: config.log_callback,
            jaeger_service: config.jaeger_service,
        };

        (config.tasks_executor)(Box::pin(background_sync.run()));

        Ok(Arc::new(ConsensusService {
            block_number_bytes: config.block_number_bytes,
            to_background_tx: Mutex::new(to_background_tx),
        }))
    }

    /// Returns the value that was provided through [`Config::block_number_bytes`].
    pub fn block_number_bytes(&self) -> usize {
        self.block_number_bytes
    }

    /// Returns a summary of the state of the service.
    ///
    /// > **Important**: This doesn't represent the content of the database.
    // TODO: maybe remove this in favour of the database; seems like a better idea
    pub async fn sync_state(&self) -> SyncState {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background_tx
            .lock()
            .await
            .send(ToBackground::GetSyncState { result_tx })
            .await;
        result_rx.await.unwrap()
    }

    /// Subscribes to the state of the chain: the current state and the new blocks.
    ///
    /// Only up to `buffer_size` notifications are buffered in the channel. If the channel is full
    /// when a new notification is attempted to be pushed, the channel gets closed.
    ///
    /// A maximum number of finalized or non-canonical (i.e. not part of the finalized chain)
    /// pinned blocks must be passed, indicating the maximum number of blocks that are finalized
    /// or non-canonical that the consensus service will pin at the same time for this
    /// subscription. If this maximum is reached, the channel will get closed. In situations
    /// where the subscriber is guaranteed to always properly unpin blocks, a value of
    /// `usize::MAX` can be passed in order to ignore this maximum.
    ///
    /// All the blocks being reported are guaranteed to be present in the database associated to
    /// this [`ConsensusService`].
    ///
    /// See [`SubscribeAll`] for information about the return value.
    ///
    /// While this function is asynchronous, it is guaranteed to finish relatively quickly. Only
    /// CPU operations are performed.
    pub async fn subscribe_all(
        &self,
        buffer_size: usize,
        max_finalized_pinned_blocks: NonZero<usize>,
    ) -> SubscribeAll {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background_tx
            .lock()
            .await
            .send(ToBackground::SubscribeAll {
                buffer_size,
                _max_finalized_pinned_blocks: max_finalized_pinned_blocks,
                result_tx,
            })
            .await;
        result_rx.await.unwrap()
    }

    /// Unpins a block that was reported as part of a subscription.
    ///
    /// Has no effect if the [`SubscriptionId`] is not or no longer valid (as the consensus service
    /// can kill any subscription at any moment).
    ///
    /// # Panic
    ///
    /// Panics if the block hash has not been reported or has already been unpinned.
    ///
    pub async fn unpin_block(&self, subscription_id: SubscriptionId, block_hash: [u8; 32]) {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background_tx
            .lock()
            .await
            .send(ToBackground::Unpin {
                _subscription_id: subscription_id,
                _block_hash: block_hash,
                result_tx,
            })
            .await;
        result_rx.await.unwrap()
    }

    /// Returns `true` if the syncing is currently downloading blocks at a high rate in order to
    /// catch up with the head of the chain.
    ///
    /// > **Note**: This function is used to implement the `system_health` JSON-RPC function and
    /// >           is basically a hack that shouldn't be relied upon.
    pub async fn is_major_syncing_hint(&self) -> bool {
        let (result_tx, result_rx) = oneshot::channel();
        let _ = self
            .to_background_tx
            .lock()
            .await
            .send(ToBackground::IsMajorSyncingHint { result_tx })
            .await;
        result_rx.await.unwrap()
    }
}

/// Return value of [`ConsensusService::subscribe_all`].
pub struct SubscribeAll {
    /// Identifier of this subscription.
    pub id: SubscriptionId,

    /// SCALE-encoded header of the finalized block at the time of the subscription.
    pub finalized_block_scale_encoded_header: Vec<u8>,

    /// Hash of the finalized block, to provide to [`ConsensusService::unpin_block`].
    pub finalized_block_hash: [u8; 32],

    /// Runtime of the finalized block.
    pub finalized_block_runtime: Arc<executor::host::HostVmPrototype>,

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

/// Identifier of a subscription returned by [`ConsensusService::subscribe_all`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(u64);

/// Notification about a new block or a new finalized block.
///
/// See [`ConsensusService::subscribe_all`].
#[derive(Debug, Clone)]
pub enum Notification {
    /// A non-finalized block has been finalized.
    Finalized {
        /// BLAKE2 hash of the blocks that have been finalized, in deceasing block number. In
        /// other words, each block in this list is the parent of the previous one. The first block
        /// in this list is the new finalized block.
        ///
        /// A block with this hash is guaranteed to have earlier been reported in a
        /// [`BlockNotification`], either in [`SubscribeAll::non_finalized_blocks_ancestry_order`]
        /// or in a [`Notification::Block`].
        finalized_blocks_newest_to_oldest: Vec<[u8; 32]>,

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

        /// List of BLAKE2 hashes of blocks that are no longer part of the canonical chain. In
        /// unspecified order.
        pruned_blocks_hashes: Vec<[u8; 32]>,
    },

    /// A new block has been added to the list of unfinalized blocks.
    Block {
        /// Information about the block.
        block: BlockNotification,

        /// Changes to the storage that the block has performed.
        ///
        /// Note that this field is only available when a new block is available.
        storage_changes: Arc<runtime_call::StorageChanges>,
    },
}

/// Notification about a new block.
///
/// See [`ConsensusService::subscribe_all`].
#[derive(Debug, Clone)]
pub struct BlockNotification {
    /// True if this block is considered as the best block of the chain.
    pub is_new_best: bool,

    /// SCALE-encoded header of the block.
    pub scale_encoded_header: Vec<u8>,

    /// Hash of the block, to provide to [`ConsensusService::unpin_block`].
    pub block_hash: [u8; 32],

    /// If the block has a different runtime compared to its parent, contains the new runtime.
    /// Contains `None` if the runtime of the block is the same as its parent's.
    pub runtime_update: Option<Arc<executor::host::HostVmPrototype>>,

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

struct SyncBackground {
    /// State machine containing the list of all the peers, all the non-finalized blocks, and all
    /// the network requests in progress.
    ///
    /// Each peer holds a struct containing either information about a networking peer, or `None`
    /// if this is the "special source" representing the local block authoring. Only one source
    /// must contain `None` and its id must be [`SyncBackground::block_author_sync_source`].
    ///
    /// Each block holds its runtime if it has been verified.
    ///
    /// Some of the sources can represent networking peers that have already been disconnected. If
    /// that is the case, no new request is started against these sources but existing requests
    /// are allowed to finish.
    /// This "trick" is necessary in order to not cancel requests that have already been started
    /// against a peer when it disconnects and that might already have a response.
    ///
    /// Each on-going request has a corresponding background task in [`SyncBackground::sub_tasks`].
    sync: all::AllSync<(), Option<NetworkSourceInfo>, NonFinalizedBlock>,

    /// Source within the [`SyncBackground::sync`] to use to import locally-authored blocks.
    block_author_sync_source: all::SourceId,

    /// State of the authoring. If `None`, the builder should be (re)created. If `Some`, also
    /// contains the list of public keys that were loaded from the keystore when creating the
    /// builder.
    ///
    /// The difference between a value of `None` and a value of `Some(Builder::Idle)` is that
    /// `None` indicates that we should try to author a block as soon as possible, while `Idle`
    /// means that we shouldn't try again until some event occurs (at which point this field is
    /// set to `None`). For instance, if the operation of building a block fails, the state is set
    /// to `Idle` so as to avoid trying to create a block over and over again.
    // TODO: this list of public keys is a bit hacky
    block_authoring: Option<(author::build::Builder, Vec<[u8; 32]>)>,

    /// See [`Config::slot_duration_author_ratio`].
    slot_duration_author_ratio: u16,

    /// After a block has been authored, it is inserted here while waiting for the `sync` to
    /// import it. Contains the block height, the block hash, the SCALE-encoded block header, and
    /// the list of SCALE-encoded extrinsics of the block.
    authored_block: Option<(u64, [u8; 32], Vec<u8>, Vec<Vec<u8>>)>,

    /// See [`Config::keystore`].
    keystore: Arc<keystore::Keystore>,

    /// Runtime of the latest finalized block.
    ///
    /// The runtime is extracted when necessary then put back it place.
    ///
    /// The `Arc` is shared with [`NonFinalizedBlock::Verified::runtime`].
    finalized_runtime: Arc<executor::host::HostVmPrototype>,

    /// Used to receive messages from the frontend service, and to detect when it shuts down.
    to_background_rx: mpsc::Receiver<ToBackground>,

    /// List of senders to report events to when they happen.
    blocks_notifications: Vec<async_channel::Sender<Notification>>,

    /// Notification ready to be sent to [`SyncBackground::blocks_notifications`].
    pending_notification: Option<Notification>,

    /// Service managing the connections to the networking peers.
    network_service: Arc<network_service::NetworkService>,

    /// Index, within the [`SyncBackground::network_service`], of the chain that this sync service
    /// is syncing from. This value must be passed as parameter when starting requests on the
    /// network service.
    network_chain_id: network_service::ChainId,

    /// If `true`, [`network_service::NetworkService::set_local_best_block`] should be called in
    /// the near future.
    network_local_chain_update_needed: bool,

    /// SCALE-encoded header, hash, and height of a block waiting to be announced to other peers.
    pending_block_announce: Option<(Vec<u8>, [u8; 32], u64)>,

    /// Stream of events coming from the [`SyncBackground::network_service`]. Used to know what
    /// happens on the peer-to-peer network.
    from_network_service: stream::BoxStream<'static, network_service::Event>,

    /// For each networking peer, the identifier of the source in [`SyncBackground::sync`].
    /// This map is kept up-to-date with the "chain connections" of the network service. Whenever
    /// a connection is established with a peer, an entry is inserted in this map and a source is
    /// added to [`SyncBackground::sync`], and whenever a connection is closed, the map entry and
    /// source are removed.
    peers_source_id_map: hashbrown::HashMap<libp2p::PeerId, all::SourceId, fnv::FnvBuildHasher>,

    /// Futures that get executed by the background task.
    sub_tasks: FuturesUnordered<Pin<Box<dyn Future<Output = SubtaskFinished> + Send>>>,

    /// See [`Config::log_callback`].
    log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// See [`Config::database`].
    database: Arc<database_thread::DatabaseThread>,

    /// Whether an old block or storage item from an old block is currently being downloaded or
    /// must be downloaded.
    database_catch_up_download: DatabaseCatchUpDownload,

    /// Whether an old block or storage item from an old block is currently being downloaded or
    /// must be downloaded.
    database_catch_up_download_block_verification: DatabaseCatchUpDownloadBlockVerification,

    /// How to report events about blocks.
    jaeger_service: Arc<jaeger_service::JaegerService>,
}

#[derive(Clone)]
enum NonFinalizedBlock {
    NotVerified,
    Verified {
        /// Runtime of the block. Generally either identical to its parent's runtime, or a
        /// different one.
        ///
        /// The `Arc` is shared with [`SyncBackground::finalized_runtime`].
        runtime: Arc<executor::host::HostVmPrototype>,
    },
}

/// Information about a source in the sync state machine.
#[derive(Debug, Clone)]
struct NetworkSourceInfo {
    /// Identity of the peer according to the networking.
    peer_id: libp2p::PeerId,
    /// If `true`, this peer is considered disconnected by the network, and no new request should
    /// be started against it.
    is_disconnected: bool,
}

enum SubtaskFinished {
    BlocksRequestFinished {
        request_id: all::RequestId,
        source_id: all::SourceId,
        result: Result<Vec<BlockData>, network_service::BlocksRequestError>,
    },
    WarpSyncRequestFinished {
        request_id: all::RequestId,
        source_id: all::SourceId,
        result: Result<
            network::service::EncodedGrandpaWarpSyncResponse,
            network_service::WarpSyncRequestError,
        >,
    },
    StorageRequestFinished {
        request_id: all::RequestId,
        source_id: all::SourceId,
        result: Result<network::service::EncodedMerkleProof, ()>,
    },
    CallProofRequestFinished {
        request_id: all::RequestId,
        source_id: all::SourceId,
        result: Result<network::service::EncodedMerkleProof, ()>,
    },
}

#[derive(Debug, Clone)]
enum DatabaseCatchUpDownload {
    /// No download currently in progress.
    NoDownloadInProgress,
    /// No download currently in progress, and we know that nothing is missing from the database.
    NothingToDownloadCache,
    /// Currently downloading.
    InProgress(all::RequestId),
}

#[derive(Debug, Clone)]
enum DatabaseCatchUpDownloadBlockVerification {
    /// No download is required.
    None,
    /// A call proof download should be started next.
    CallProofDesired {
        block_hash: [u8; 32],
        block_number: u64,
        function_name: String,
        parameter: Vec<u8>,
    },
    /// A storage proof download should be started next.
    CodeStorageProofDesired {
        block_hash: [u8; 32],
        block_number: u64,
    },
    /// Currently downloading.
    InProgress(all::RequestId),
}

impl SyncBackground {
    async fn run(mut self) {
        let mut process_sync = true;

        loop {
            enum WakeUpReason {
                ReadyToAuthor,
                FrontendEvent(ToBackground),
                FrontendClosed,
                SendPendingNotification(Notification),
                StartNetworkRequest {
                    source_id: all::SourceId,
                    request: all::DesiredRequest,
                    database_catch_up_type: DbCatchUpType,
                },
                NetworkEvent(network_service::Event),
                NetworkLocalChainUpdate,
                AnnounceBlock(Vec<u8>, [u8; 32], u64),
                SubtaskFinished(SubtaskFinished),
                SyncProcess,
            }

            enum DbCatchUpType {
                No,
                BlockVerification,
                Database,
            }

            let wake_up_reason: WakeUpReason = {
                // Creating the block authoring state and prepare a future that is ready when something
                // related to the block authoring is ready.
                // TODO: refactor as a separate task?
                // TODO: restore block authoring after https://github.com/smol-dot/smoldot/issues/1109
                let authoring_ready_future = {
                    future::pending::<WakeUpReason>()
                    /*// TODO: overhead to call best_block_consensus() multiple times
                    let local_authorities = {
                        let namespace_filter = match self.sync.best_block_consensus() {
                            chain_information::ChainInformationConsensusRef::Aura { .. } => {
                                Some(keystore::KeyNamespace::Aura)
                            }
                            chain_information::ChainInformationConsensusRef::Babe { .. } => {
                                Some(keystore::KeyNamespace::Babe)
                            }
                            chain_information::ChainInformationConsensusRef::Unknown => {
                                // In `Unknown` mode, all keys are accepted and there is no
                                // filter on the namespace, as we can't author blocks anyway.
                                // TODO: is that correct?
                                None
                            }
                        };

                        // Calling `keys()` on the keystore is racy, but that's considered
                        // acceptable and part of the design of the node.
                        self.keystore
                            .keys()
                            .await
                            .filter(|(namespace, _)| {
                                namespace_filter.map_or(true, |n| *namespace == n)
                            })
                            .map(|(_, key)| key)
                            .collect::<Vec<_>>() // TODO: collect overhead :-/
                    };

                    let block_authoring =
                        match (&mut self.block_authoring, self.sync.best_block_consensus()) {
                            (Some(ba), _) => Some(ba),
                            (
                                block_authoring @ None,
                                chain_information::ChainInformationConsensusRef::Aura {
                                    finalized_authorities_list, // TODO: field name not appropriate; should probably change the chain_information module
                                    slot_duration,
                                },
                            ) => Some(
                                block_authoring.insert((
                                    author::build::Builder::new(author::build::Config {
                                        consensus: author::build::ConfigConsensus::Aura {
                                            current_authorities: finalized_authorities_list,
                                            local_authorities: local_authorities.iter(),
                                            now_from_unix_epoch: SystemTime::now()
                                                .duration_since(SystemTime::UNIX_EPOCH)
                                                .unwrap(),
                                            slot_duration,
                                        },
                                    }),
                                    local_authorities,
                                )),
                            ),
                            (
                                None,
                                chain_information::ChainInformationConsensusRef::Babe { .. },
                            ) => {
                                None // TODO: the block authoring doesn't support Babe at the moment
                            }
                            (None, _) => todo!(),
                        };

                    match &block_authoring {
                        Some((author::build::Builder::Ready(_), _)) => future::Either::Left(
                            future::Either::Left(future::ready(Instant::now())),
                        ),
                        Some((author::build::Builder::WaitSlot(when), _)) => {
                            let delay = (UNIX_EPOCH + when.when())
                                .duration_since(SystemTime::now())
                                .unwrap_or_else(|_| Duration::new(0, 0));
                            future::Either::Right(future::FutureExt::fuse(smol::Timer::after(
                                delay,
                            )))
                        }
                        None => future::Either::Left(future::Either::Right(future::pending())),
                        Some((author::build::Builder::Idle, _)) => {
                            // If the block authoring is idle, which happens in case of error,
                            // sleep for an arbitrary duration before resetting it.
                            // This prevents the authoring from trying over and over again to generate
                            // a bad block.
                            let delay = Duration::from_secs(2);
                            future::Either::Right(future::FutureExt::fuse(smol::Timer::after(
                                delay,
                            )))
                        }
                    }*/
                };

                async {
                    if let Some(notification) = self.pending_notification.take() {
                        WakeUpReason::SendPendingNotification(notification)
                    } else {
                        future::pending().await
                    }
                }
                .or(async move {
                    authoring_ready_future.await;
                    WakeUpReason::ReadyToAuthor
                })
                .or(async {
                    self.to_background_rx
                        .next()
                        .await
                        .map_or(WakeUpReason::FrontendClosed, WakeUpReason::FrontendEvent)
                })
                .or(async {
                    WakeUpReason::NetworkEvent(self.from_network_service.next().await.unwrap())
                })
                .or(async {
                    if self.network_local_chain_update_needed {
                        self.network_local_chain_update_needed = false;
                        WakeUpReason::NetworkLocalChainUpdate
                    } else {
                        future::pending().await
                    }
                })
                .or(async {
                    if let Some((header, hash, height)) = self.pending_block_announce.take() {
                        WakeUpReason::AnnounceBlock(header, hash, height)
                    } else {
                        future::pending().await
                    }
                })
                .or(async {
                    let Some(subtask_finished) = self.sub_tasks.next().await else {
                        future::pending().await
                    };
                    WakeUpReason::SubtaskFinished(subtask_finished)
                })
                .or({
                    async {
                        // TODO: handle obsolete requests
                        // Ask the sync state machine whether any new network request should
                        // be started.
                        // `desired_requests()` returns, in decreasing order of priority, the
                        // requests that should be started in order for the syncing to proceed. We
                        // simply pick the first request, but enforce one ongoing request per
                        // source.
                        // TODO: desired_requests() is expensive and done at every iteration
                        let request_to_start = self.sync.desired_requests().find(
                            |(source_id, source_info, request_details)| {
                                if source_info
                                    .as_ref()
                                    .map_or(false, |info| info.is_disconnected)
                                {
                                    // Source is a networking source that has already been disconnected.
                                    false
                                } else if *source_id != self.block_author_sync_source {
                                    // Remote source.
                                    self.sync.source_num_ongoing_requests(*source_id) == 0
                                } else {
                                    // Locally-authored blocks source.
                                    match (request_details, &self.authored_block) {
                                        (
                                            all::DesiredRequest::BlocksRequest {
                                                first_block_hash,
                                                first_block_height,
                                                ..
                                            },
                                            Some((authored_height, authored_hash, _, _)),
                                        ) if first_block_hash == authored_hash
                                            && first_block_height == authored_height =>
                                        {
                                            true
                                        }
                                        _ => false,
                                    }
                                }
                            },
                        );
                        if let Some((source_id, _, request)) = request_to_start {
                            return WakeUpReason::StartNetworkRequest {
                                source_id,
                                request,
                                database_catch_up_type: DbCatchUpType::No,
                            };
                        }

                        match self.database_catch_up_download_block_verification.clone() {
                            _ if !matches!(
                                self.database_catch_up_download,
                                DatabaseCatchUpDownload::NoDownloadInProgress
                                    | DatabaseCatchUpDownload::NothingToDownloadCache
                            ) => {}
                            DatabaseCatchUpDownloadBlockVerification::None => {}
                            DatabaseCatchUpDownloadBlockVerification::InProgress(_) => {}
                            DatabaseCatchUpDownloadBlockVerification::CallProofDesired {
                                block_hash,
                                block_number,
                                function_name,
                                parameter,
                            } => {
                                // Choose which source to query. We have to use an `if` because
                                // `knows_non_finalized_block` panics if the parameter is inferior
                                // or equal to the finalized block number.
                                let source_id = if block_number
                                    <= self.sync.finalized_block_number()
                                {
                                    self.sync
                                        .sources()
                                        .filter(|s| *s != self.block_author_sync_source)
                                        .choose(&mut rand::thread_rng())
                                } else {
                                    self.sync
                                        .knows_non_finalized_block(block_number, &block_hash)
                                        .filter(|source_id| {
                                            *source_id != self.block_author_sync_source
                                                && self.sync.source_num_ongoing_requests(*source_id)
                                                    == 0
                                        })
                                        .choose(&mut rand::thread_rng())
                                };

                                if let Some(source_id) = source_id {
                                    return WakeUpReason::StartNetworkRequest {
                                        source_id,
                                        request: all::DesiredRequest::RuntimeCallMerkleProof {
                                            block_hash,
                                            function_name: function_name.into(),
                                            parameter_vectored: parameter.into(),
                                        },
                                        database_catch_up_type: DbCatchUpType::BlockVerification,
                                    };
                                }
                            }
                            DatabaseCatchUpDownloadBlockVerification::CodeStorageProofDesired {
                                block_hash,
                                block_number,
                            } => {
                                // Choose which source to query. We have to use an `if` because
                                // `knows_non_finalized_block` panics if the parameter is inferior
                                // or equal to the finalized block number.
                                let source_id = if block_number
                                    <= self.sync.finalized_block_number()
                                {
                                    self.sync
                                        .sources()
                                        .filter(|s| *s != self.block_author_sync_source)
                                        .choose(&mut rand::thread_rng())
                                } else {
                                    self.sync
                                        .knows_non_finalized_block(block_number, &block_hash)
                                        .filter(|source_id| {
                                            *source_id != self.block_author_sync_source
                                                && self.sync.source_num_ongoing_requests(*source_id)
                                                    == 0
                                        })
                                        .choose(&mut rand::thread_rng())
                                };

                                if let Some(source_id) = source_id {
                                    return WakeUpReason::StartNetworkRequest {
                                        source_id,
                                        request: all::DesiredRequest::StorageGetMerkleProof {
                                            block_hash,
                                            state_trie_root: [0; 32], // TODO: wrong, but field value unused so it's fine temporarily
                                            keys: vec![":code".into(), ":heappages".into()],
                                        },
                                        database_catch_up_type: DbCatchUpType::BlockVerification,
                                    };
                                }
                            }
                        }

                        // If the sync state machine doesn't require any additional request, ask
                        // the database whether any storage item is missing.
                        if matches!(
                            self.database_catch_up_download,
                            DatabaseCatchUpDownload::NoDownloadInProgress
                        ) {
                            // TODO: this has a O(n^2) complexity; in case all sources are busy, we iterate a lot
                            let missing_items = self
                                .database
                                .with_database(|db| {
                                    db.finalized_and_above_missing_trie_nodes_unordered()
                                })
                                .await
                                .unwrap();
                            if missing_items.is_empty() {
                                self.database_catch_up_download =
                                    DatabaseCatchUpDownload::NothingToDownloadCache;
                            }

                            for missing_item in missing_items
                                .into_iter()
                                .flat_map(|item| item.blocks.into_iter())
                            {
                                // Since the database and sync state machine are supposed to have the
                                // same finalized block, it is guaranteed that the missing item are
                                // in the finalized block or above.
                                debug_assert!(
                                    missing_item.number >= self.sync.finalized_block_number()
                                );

                                // Choose which source to query. We have to use an `if` because
                                // `knows_non_finalized_block` panics if the parameter is inferior
                                // or equal to the finalized block number.
                                let source_id = if missing_item.number
                                    <= self.sync.finalized_block_number()
                                {
                                    let Some(source_id) = self
                                        .sync
                                        .sources()
                                        .filter(|s| *s != self.block_author_sync_source)
                                        .choose(&mut rand::thread_rng())
                                    else {
                                        break;
                                    };
                                    source_id
                                } else {
                                    let Some(source_id) = self
                                        .sync
                                        .knows_non_finalized_block(
                                            missing_item.number,
                                            &missing_item.hash,
                                        )
                                        .filter(|source_id| {
                                            *source_id != self.block_author_sync_source
                                                && self.sync.source_num_ongoing_requests(*source_id)
                                                    == 0
                                        })
                                        .choose(&mut rand::thread_rng())
                                    else {
                                        continue;
                                    };
                                    source_id
                                };

                                return WakeUpReason::StartNetworkRequest {
                                    source_id,
                                    request: all::DesiredRequest::StorageGetMerkleProof {
                                        block_hash: missing_item.hash,
                                        state_trie_root: [0; 32], // TODO: wrong, but field value unused so it's fine temporarily
                                        keys: vec![
                                            trie::nibbles_to_bytes_suffix_extend(
                                                missing_item
                                                    .trie_node_key_nibbles
                                                    .into_iter()
                                                    // In order to download more than one item at a time,
                                                    // we add some randomly-generated nibbles to the
                                                    // requested key. The request will target the missing
                                                    // key plus a few other random keys.
                                                    .chain((0..32).map(|_| {
                                                        rand::Rng::gen_range(
                                                            &mut rand::thread_rng(),
                                                            0..16,
                                                        )
                                                    }))
                                                    .map(|n| trie::Nibble::try_from(n).unwrap()),
                                            )
                                            .collect::<Vec<_>>(),
                                        ],
                                    },
                                    database_catch_up_type: DbCatchUpType::Database,
                                };
                            }
                        }

                        // No network request to start.
                        future::pending().await
                    }
                })
                .or({
                    let is_downloading = matches!(
                        self.database_catch_up_download_block_verification,
                        DatabaseCatchUpDownloadBlockVerification::None
                    );
                    async move {
                        if !process_sync || !is_downloading {
                            future::pending().await
                        }
                        WakeUpReason::SyncProcess
                    }
                })
                .await
            };

            match wake_up_reason {
                WakeUpReason::ReadyToAuthor => {
                    // Ready to author a block. Call `author_block()`.
                    // While a block is being authored, the whole syncing state machine is
                    // deliberately frozen.
                    match self.block_authoring {
                        Some((author::build::Builder::Ready(_), _)) => {
                            self.author_block().await;
                        }
                        Some((author::build::Builder::WaitSlot(when), local_authorities)) => {
                            self.block_authoring = Some((
                                author::build::Builder::Ready(when.start()),
                                local_authorities,
                            ));
                            self.author_block().await;
                        }
                        Some((author::build::Builder::Idle, _)) => {
                            self.block_authoring = None;
                        }
                        None => {
                            unreachable!()
                        }
                    }

                    process_sync = true;
                }

                WakeUpReason::FrontendClosed => {
                    // Shutdown.
                    return;
                }

                WakeUpReason::FrontendEvent(ToBackground::SubscribeAll {
                    buffer_size,
                    _max_finalized_pinned_blocks: _,
                    result_tx,
                }) => {
                    let (tx, new_blocks) = async_channel::bounded(buffer_size.saturating_sub(1));

                    let non_finalized_blocks_ancestry_order = {
                        let blocks_in = self
                            .sync
                            .non_finalized_blocks_ancestry_order()
                            .map(|h| {
                                (
                                    h.number,
                                    h.scale_encoding_vec(self.sync.block_number_bytes()),
                                    *h.parent_hash,
                                )
                            })
                            .collect::<Vec<_>>();
                        let mut blocks_out = Vec::new();
                        for (number, scale_encoding, parent_hash) in blocks_in {
                            let hash = header::hash_from_scale_encoded_header(&scale_encoding);
                            let runtime = match &self.sync[(number, &hash)] {
                                NonFinalizedBlock::Verified { runtime } => runtime.clone(),
                                _ => unreachable!(),
                            };
                            let runtime_update = if Arc::ptr_eq(&self.finalized_runtime, &runtime) {
                                None
                            } else {
                                Some(runtime.clone())
                            };
                            blocks_out.push(BlockNotification {
                                is_new_best: header::hash_from_scale_encoded_header(
                                    &scale_encoding,
                                ) == *self.sync.best_block_hash(),
                                block_hash: header::hash_from_scale_encoded_header(&scale_encoding),
                                scale_encoded_header: scale_encoding,
                                runtime_update,
                                parent_hash,
                            });
                        }
                        blocks_out
                    };

                    self.blocks_notifications.push(tx);
                    let _ = result_tx.send(SubscribeAll {
                        id: SubscriptionId(0), // TODO:
                        finalized_block_hash: *self.sync.finalized_block_hash(),
                        finalized_block_scale_encoded_header: self
                            .sync
                            .finalized_block_header()
                            .to_owned(),
                        finalized_block_runtime: self.finalized_runtime.clone(),
                        non_finalized_blocks_ancestry_order,
                        new_blocks,
                    });
                }
                WakeUpReason::SendPendingNotification(notification) => {
                    // Elements in `blocks_notifications` are removed one by one and inserted
                    // back if the channel is still open.
                    for index in (0..self.blocks_notifications.len()).rev() {
                        let subscription = self.blocks_notifications.swap_remove(index);
                        if subscription.try_send(notification.clone()).is_err() {
                            continue;
                        }
                        self.blocks_notifications.push(subscription);
                    }
                }

                WakeUpReason::FrontendEvent(ToBackground::GetSyncState { result_tx }) => {
                    let _ = result_tx.send(SyncState {
                        best_block_hash: *self.sync.best_block_hash(),
                        best_block_number: self.sync.best_block_number(),
                        finalized_block_hash: *self.sync.finalized_block_hash(),
                        finalized_block_number: self.sync.finalized_block_number(),
                    });
                }
                WakeUpReason::FrontendEvent(ToBackground::Unpin { result_tx, .. }) => {
                    // TODO: check whether block was indeed pinned, and prune blocks that aren't pinned anymore from the database
                    let _ = result_tx.send(());
                }
                WakeUpReason::FrontendEvent(ToBackground::IsMajorSyncingHint { result_tx }) => {
                    // As documented, the value returned doesn't need to be precise.
                    let result = match self.sync.status() {
                        all::Status::Sync => false,
                        all::Status::WarpSyncFragments { .. }
                        | all::Status::WarpSyncChainInformation { .. } => true,
                    };

                    let _ = result_tx.send(result);
                }

                WakeUpReason::NetworkLocalChainUpdate => {
                    self.network_service
                        .set_local_best_block(
                            self.network_chain_id,
                            *self.sync.best_block_hash(),
                            self.sync.best_block_number(),
                        )
                        .await;
                }

                WakeUpReason::AnnounceBlock(header, hash, height) => {
                    // We can never be guaranteed that a certain source does *not* know about a
                    // block, however it is not a big problem to send a block announce to a source
                    // that already knows about that block. For this reason, the list of sources
                    // we send the block announce to is `all_sources - sources_that_know_it`.
                    //
                    // Note that not sending block announces to sources that already
                    // know that block means that these sources might also miss the
                    // fact that our local best block has been updated. This is in
                    // practice not a problem either.
                    let sources_to_announce_to = {
                        let mut all_sources = self
                            .sync
                            .sources()
                            .collect::<HashSet<_, fnv::FnvBuildHasher>>();
                        for knows in self.sync.knows_non_finalized_block(height, &hash) {
                            all_sources.remove(&knows);
                        }
                        all_sources
                    };

                    let is_best = *self.sync.best_block_hash() == hash;

                    for source_id in sources_to_announce_to {
                        let peer_id = match &self.sync[source_id] {
                            Some(info) if !info.is_disconnected => &info.peer_id,
                            _ => continue,
                        };

                        if self
                            .network_service
                            .clone()
                            .send_block_announce(
                                peer_id.clone(),
                                self.network_chain_id,
                                header.clone(),
                                is_best,
                            )
                            .await
                            .is_ok()
                        {
                            // Note that `try_add_known_block_to_source` might have
                            // no effect, which is not a problem considering that this
                            // block tracking is mostly about optimizations and
                            // politeness.
                            self.sync
                                .try_add_known_block_to_source(source_id, height, hash);
                        }
                    }
                }

                WakeUpReason::NetworkEvent(network_service::Event::Connected {
                    peer_id,
                    chain_id,
                    best_block_number,
                    best_block_hash,
                }) if chain_id == self.network_chain_id => {
                    // Most of the time, we insert a new source in the state machine.
                    // However, a source of that `PeerId` might already exist but be considered as
                    // disconnected. If that is the case, we simply mark it as no
                    // longer disconnected.
                    match self.peers_source_id_map.entry(peer_id) {
                        hashbrown::hash_map::Entry::Occupied(entry) => {
                            let id = *entry.get();
                            let is_disconnected =
                                &mut self.sync[id].as_mut().unwrap().is_disconnected;
                            debug_assert!(*is_disconnected);
                            *is_disconnected = false;
                        }
                        hashbrown::hash_map::Entry::Vacant(entry) => {
                            let id = self
                                .sync
                                .prepare_add_source(best_block_number, best_block_hash)
                                .add_source(
                                    Some(NetworkSourceInfo {
                                        peer_id: entry.key().clone(),
                                        is_disconnected: false,
                                    }),
                                    NonFinalizedBlock::NotVerified,
                                );
                            entry.insert(id);
                        }
                    }
                }
                WakeUpReason::NetworkEvent(network_service::Event::Disconnected {
                    peer_id,
                    chain_id,
                }) if chain_id == self.network_chain_id => {
                    // Sources that disconnect are only immediately removed from the sync state
                    // machine if they have no request in progress. If that is not the case, they
                    // are instead only marked as disconnected.
                    let id = *self.peers_source_id_map.get(&peer_id).unwrap();
                    if self.sync.source_num_ongoing_requests(id) == 0 {
                        self.peers_source_id_map.remove(&peer_id).unwrap();
                        let (_, mut _requests) = self.sync.remove_source(id);
                        debug_assert!(_requests.next().is_none());
                    } else {
                        let is_disconnected = &mut self.sync[id].as_mut().unwrap().is_disconnected;
                        debug_assert!(!*is_disconnected);
                        *is_disconnected = true;
                    }
                }
                WakeUpReason::NetworkEvent(network_service::Event::BlockAnnounce {
                    chain_id,
                    peer_id,
                    scale_encoded_header,
                    is_best,
                }) if chain_id == self.network_chain_id => {
                    let _jaeger_span = self.jaeger_service.block_announce_process_span(
                        &header::hash_from_scale_encoded_header(&scale_encoded_header),
                    );

                    let id = *self.peers_source_id_map.get(&peer_id).unwrap();
                    // TODO: log the outcome
                    match self.sync.block_announce(id, scale_encoded_header, is_best) {
                        all::BlockAnnounceOutcome::TooOld { .. } => {}
                        all::BlockAnnounceOutcome::AlreadyVerified(known)
                        | all::BlockAnnounceOutcome::AlreadyPending(known) => {
                            known.update_source_and_block();
                        }
                        all::BlockAnnounceOutcome::Unknown(unknown) => {
                            unknown.insert_and_update_source(NonFinalizedBlock::NotVerified)
                        }
                        all::BlockAnnounceOutcome::InvalidHeader(_) => unreachable!(), // TODO: ?!?! why unreachable? also, ban the peer
                    }
                }
                WakeUpReason::NetworkEvent(network_service::Event::GrandpaNeighborPacket {
                    chain_id,
                    peer_id,
                    finalized_block_height,
                }) if chain_id == self.network_chain_id => {
                    let source_id = *self.peers_source_id_map.get(&peer_id).unwrap();
                    self.sync
                        .update_source_finality_state(source_id, finalized_block_height);
                }
                WakeUpReason::NetworkEvent(_) => {
                    // Different chain index.
                }

                WakeUpReason::StartNetworkRequest {
                    source_id,
                    request: request_info @ all::DesiredRequest::BlocksRequest { .. },
                    database_catch_up_type,
                } if source_id == self.block_author_sync_source => {
                    debug_assert!(matches!(database_catch_up_type, DbCatchUpType::No));

                    self.log_callback.log(
                        LogLevel::Debug,
                        "queue-locally-authored-block-for-import".to_string(),
                    );

                    let (_, block_hash, scale_encoded_header, scale_encoded_extrinsics) =
                        self.authored_block.take().unwrap();

                    let _jaeger_span = self.jaeger_service.block_import_queue_span(&block_hash);

                    // Create a request that is immediately answered right below.
                    let request_id = self.sync.add_request(source_id, request_info.into(), ());
                    // TODO: announce the block on the network, but only after it's been imported
                    self.sync.blocks_request_response(
                        request_id,
                        iter::once(all::BlockRequestSuccessBlock {
                            scale_encoded_header,
                            scale_encoded_extrinsics,
                            scale_encoded_justifications: Vec::new(),
                            user_data: NonFinalizedBlock::NotVerified,
                        }),
                    );
                }

                WakeUpReason::StartNetworkRequest {
                    source_id,
                    request:
                        all::DesiredRequest::BlocksRequest {
                            first_block_hash,
                            first_block_height,
                            num_blocks,
                            request_headers,
                            request_bodies,
                            request_justification,
                        },
                    database_catch_up_type,
                } => {
                    // Before notifying the syncing of the request, clamp the number of blocks to
                    // the number of blocks we expect to receive.
                    let num_blocks = NonZero::<u64>::new(cmp::min(num_blocks.get(), 64)).unwrap();

                    let peer_id = {
                        let info = self.sync[source_id].clone().unwrap();
                        // Disconnected sources are filtered out above.
                        debug_assert!(!info.is_disconnected);
                        info.peer_id
                    };

                    // TODO: add jaeger span

                    let request = self.network_service.clone().blocks_request(
                        peer_id,
                        self.network_chain_id,
                        network::codec::BlocksRequestConfig {
                            start: network::codec::BlocksRequestConfigStart::Hash(first_block_hash),
                            desired_count: NonZero::<u32>::new(
                                u32::try_from(num_blocks.get()).unwrap_or(u32::MAX),
                            )
                            .unwrap(),
                            // The direction is hardcoded based on the documentation of the syncing
                            // state machine.
                            direction: network::codec::BlocksRequestDirection::Descending,
                            fields: network::codec::BlocksRequestFields {
                                header: true, // TODO: always set to true due to unwrapping the header when the response comes
                                body: request_bodies,
                                justifications: request_justification,
                            },
                        },
                    );

                    let request_id = self.sync.add_request(
                        source_id,
                        all::DesiredRequest::BlocksRequest {
                            first_block_hash,
                            first_block_height,
                            num_blocks,
                            request_headers,
                            request_bodies,
                            request_justification,
                        }
                        .into(),
                        (),
                    );

                    match database_catch_up_type {
                        DbCatchUpType::No => {}
                        DbCatchUpType::Database => {
                            debug_assert!(matches!(
                                self.database_catch_up_download,
                                DatabaseCatchUpDownload::NoDownloadInProgress
                            ));
                            self.database_catch_up_download =
                                DatabaseCatchUpDownload::InProgress(request_id);
                        }
                        DbCatchUpType::BlockVerification => {
                            self.database_catch_up_download_block_verification =
                                DatabaseCatchUpDownloadBlockVerification::InProgress(request_id);
                        }
                    }

                    self.sub_tasks.push(Box::pin(async move {
                        let result = request.await;
                        SubtaskFinished::BlocksRequestFinished {
                            request_id,
                            source_id,
                            result,
                        }
                    }));
                }

                WakeUpReason::StartNetworkRequest {
                    source_id,
                    request:
                        all::DesiredRequest::WarpSync {
                            sync_start_block_hash,
                        },
                    database_catch_up_type,
                } => {
                    // TODO: don't unwrap? could this target the virtual sync source?
                    let peer_id = self.sync[source_id].as_ref().unwrap().peer_id.clone(); // TODO: why does this require cloning? weird borrow chk issue

                    let request = self.network_service.clone().warp_sync_request(
                        peer_id,
                        self.network_chain_id,
                        sync_start_block_hash,
                    );

                    let request_id = self.sync.add_request(
                        source_id,
                        all::RequestDetail::WarpSync {
                            sync_start_block_hash,
                        },
                        (),
                    );

                    match database_catch_up_type {
                        DbCatchUpType::No => {}
                        DbCatchUpType::Database => {
                            debug_assert!(matches!(
                                self.database_catch_up_download,
                                DatabaseCatchUpDownload::NoDownloadInProgress
                            ));
                            self.database_catch_up_download =
                                DatabaseCatchUpDownload::InProgress(request_id);
                        }
                        DbCatchUpType::BlockVerification => {
                            self.database_catch_up_download_block_verification =
                                DatabaseCatchUpDownloadBlockVerification::InProgress(request_id);
                        }
                    }

                    self.sub_tasks.push(Box::pin(async move {
                        let result = request.await;
                        SubtaskFinished::WarpSyncRequestFinished {
                            request_id,
                            source_id,
                            result,
                        }
                    }));
                }

                WakeUpReason::StartNetworkRequest {
                    source_id,
                    request:
                        all::DesiredRequest::StorageGetMerkleProof {
                            block_hash, keys, ..
                        },
                    database_catch_up_type,
                } => {
                    // TODO: don't unwrap? could this target the virtual sync source?
                    let peer_id = self.sync[source_id].as_ref().unwrap().peer_id.clone(); // TODO: why does this require cloning? weird borrow chk issue

                    let request = self.network_service.clone().storage_request(
                        peer_id,
                        self.network_chain_id,
                        network::codec::StorageProofRequestConfig {
                            block_hash,
                            keys: keys.clone().into_iter(),
                        },
                    );

                    let request_id = self.sync.add_request(
                        source_id,
                        all::RequestDetail::StorageGet { block_hash, keys },
                        (),
                    );

                    match database_catch_up_type {
                        DbCatchUpType::No => {}
                        DbCatchUpType::Database => {
                            debug_assert!(matches!(
                                self.database_catch_up_download,
                                DatabaseCatchUpDownload::NoDownloadInProgress
                            ));
                            self.database_catch_up_download =
                                DatabaseCatchUpDownload::InProgress(request_id);
                        }
                        DbCatchUpType::BlockVerification => {
                            self.database_catch_up_download_block_verification =
                                DatabaseCatchUpDownloadBlockVerification::InProgress(request_id);
                        }
                    }

                    self.sub_tasks.push(Box::pin(async move {
                        let result = request.await;
                        SubtaskFinished::StorageRequestFinished {
                            request_id,
                            source_id,
                            result,
                        }
                    }));
                }

                WakeUpReason::StartNetworkRequest {
                    source_id,
                    request:
                        all::DesiredRequest::RuntimeCallMerkleProof {
                            block_hash,
                            function_name,
                            parameter_vectored,
                        },
                    database_catch_up_type,
                } => {
                    // TODO: don't unwrap? could this target the virtual sync source?
                    let peer_id = self.sync[source_id].as_ref().unwrap().peer_id.clone(); // TODO: why does this require cloning? weird borrow chk issue

                    let request = self.network_service.clone().call_proof_request(
                        peer_id,
                        self.network_chain_id,
                        network::codec::CallProofRequestConfig {
                            block_hash,
                            method: function_name.clone(),
                            parameter_vectored: iter::once(parameter_vectored.clone()),
                        },
                    );

                    let request_id = self.sync.add_request(
                        source_id,
                        all::RequestDetail::RuntimeCallMerkleProof {
                            block_hash,
                            function_name,
                            parameter_vectored,
                        },
                        (),
                    );

                    match database_catch_up_type {
                        DbCatchUpType::No => {}
                        DbCatchUpType::Database => {
                            debug_assert!(matches!(
                                self.database_catch_up_download,
                                DatabaseCatchUpDownload::NoDownloadInProgress
                            ));
                            self.database_catch_up_download =
                                DatabaseCatchUpDownload::InProgress(request_id);
                        }
                        DbCatchUpType::BlockVerification => {
                            self.database_catch_up_download_block_verification =
                                DatabaseCatchUpDownloadBlockVerification::InProgress(request_id);
                        }
                    }

                    self.sub_tasks.push(Box::pin(async move {
                        let result = request.await;
                        SubtaskFinished::CallProofRequestFinished {
                            request_id,
                            source_id,
                            result,
                        }
                    }));
                }

                WakeUpReason::SubtaskFinished(SubtaskFinished::BlocksRequestFinished {
                    request_id,
                    source_id,
                    result: Ok(blocks),
                }) => {
                    if matches!(self.database_catch_up_download, DatabaseCatchUpDownload::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download =
                            DatabaseCatchUpDownload::NoDownloadInProgress;
                    }
                    if matches!(self.database_catch_up_download_block_verification, DatabaseCatchUpDownloadBlockVerification::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download_block_verification =
                            DatabaseCatchUpDownloadBlockVerification::None;
                    }

                    // TODO: insert blocks in database if they are referenced through a parent_hash?

                    let _ = self.sync.blocks_request_response(
                        request_id,
                        blocks
                            .into_iter()
                            .map(|block| all::BlockRequestSuccessBlock {
                                scale_encoded_header: block.header.unwrap(), // TODO: don't unwrap
                                scale_encoded_extrinsics: block.body.unwrap(), // TODO: don't unwrap
                                scale_encoded_justifications: block
                                    .justifications
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|j| all::Justification {
                                        engine_id: j.engine_id,
                                        justification: j.justification,
                                    })
                                    .collect(),
                                user_data: NonFinalizedBlock::NotVerified,
                            }),
                    );

                    // If the source was actually disconnected and has no other request in
                    // progress, we clean it up.
                    // TODO: DRY
                    if self.sync[source_id]
                        .as_ref()
                        .map_or(false, |info| info.is_disconnected)
                        && self.sync.source_num_ongoing_requests(source_id) == 0
                    {
                        let (info, mut _requests) = self.sync.remove_source(source_id);
                        debug_assert!(_requests.next().is_none());
                        self.peers_source_id_map
                            .remove(&info.unwrap().peer_id)
                            .unwrap();
                    }

                    process_sync = true;
                }

                WakeUpReason::SubtaskFinished(SubtaskFinished::BlocksRequestFinished {
                    request_id,
                    source_id,
                    result: Err(_),
                }) => {
                    if matches!(self.database_catch_up_download, DatabaseCatchUpDownload::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download =
                            DatabaseCatchUpDownload::NoDownloadInProgress;
                    }
                    if matches!(self.database_catch_up_download_block_verification, DatabaseCatchUpDownloadBlockVerification::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download_block_verification =
                            DatabaseCatchUpDownloadBlockVerification::None;
                    }

                    // Note that we perform the ban even if the source is now disconnected.
                    let peer_id = self.sync[source_id].as_ref().unwrap().peer_id.clone();
                    self.network_service
                        .ban_and_disconnect(
                            peer_id,
                            self.network_chain_id,
                            network_service::BanSeverity::Low,
                            "blocks-request-error",
                        )
                        .await;

                    let _ = self.sync.remove_request(request_id);

                    // If the source was actually disconnected and has no other request in
                    // progress, we clean it up.
                    // TODO: DRY
                    if self.sync[source_id]
                        .as_ref()
                        .map_or(false, |info| info.is_disconnected)
                        && self.sync.source_num_ongoing_requests(source_id) == 0
                    {
                        let (info, mut _requests) = self.sync.remove_source(source_id);
                        debug_assert!(_requests.next().is_none());
                        self.peers_source_id_map
                            .remove(&info.unwrap().peer_id)
                            .unwrap();
                    }

                    process_sync = true;
                }

                WakeUpReason::SubtaskFinished(SubtaskFinished::WarpSyncRequestFinished {
                    request_id,
                    source_id,
                    result: Ok(result),
                }) => {
                    if matches!(self.database_catch_up_download, DatabaseCatchUpDownload::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download =
                            DatabaseCatchUpDownload::NoDownloadInProgress;
                    }
                    if matches!(self.database_catch_up_download_block_verification, DatabaseCatchUpDownloadBlockVerification::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download_block_verification =
                            DatabaseCatchUpDownloadBlockVerification::None;
                    }

                    let decoded = result.decode();
                    let fragments = decoded
                        .fragments
                        .into_iter()
                        .map(|f| all::WarpSyncFragment {
                            scale_encoded_header: f.scale_encoded_header.to_vec(),
                            scale_encoded_justification: f.scale_encoded_justification.to_vec(),
                        })
                        .collect();
                    let _ = self.sync.grandpa_warp_sync_response(
                        request_id,
                        fragments,
                        decoded.is_finished,
                    );

                    // If the source was actually disconnected and has no other request in
                    // progress, we clean it up.
                    // TODO: DRY
                    if self.sync[source_id]
                        .as_ref()
                        .map_or(false, |info| info.is_disconnected)
                        && self.sync.source_num_ongoing_requests(source_id) == 0
                    {
                        let (info, mut _requests) = self.sync.remove_source(source_id);
                        debug_assert!(_requests.next().is_none());
                        self.peers_source_id_map
                            .remove(&info.unwrap().peer_id)
                            .unwrap();
                    }

                    process_sync = true;
                }

                WakeUpReason::SubtaskFinished(SubtaskFinished::WarpSyncRequestFinished {
                    request_id,
                    source_id,
                    result: Err(_),
                }) => {
                    if matches!(self.database_catch_up_download, DatabaseCatchUpDownload::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download =
                            DatabaseCatchUpDownload::NoDownloadInProgress;
                    }
                    if matches!(self.database_catch_up_download_block_verification, DatabaseCatchUpDownloadBlockVerification::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download_block_verification =
                            DatabaseCatchUpDownloadBlockVerification::None;
                    }

                    // Note that we perform the ban even if the source is now disconnected.
                    let peer_id = self.sync[source_id].as_ref().unwrap().peer_id.clone();
                    self.network_service
                        .ban_and_disconnect(
                            peer_id,
                            self.network_chain_id,
                            network_service::BanSeverity::Low,
                            "warp-sync-request-error",
                        )
                        .await;

                    let _ = self.sync.remove_request(request_id);

                    // If the source was actually disconnected and has no other request in
                    // progress, we clean it up.
                    // TODO: DRY
                    if self.sync[source_id]
                        .as_ref()
                        .map_or(false, |info| info.is_disconnected)
                        && self.sync.source_num_ongoing_requests(source_id) == 0
                    {
                        let (info, mut _requests) = self.sync.remove_source(source_id);
                        debug_assert!(_requests.next().is_none());
                        self.peers_source_id_map
                            .remove(&info.unwrap().peer_id)
                            .unwrap();
                    }

                    process_sync = true;
                }

                WakeUpReason::SubtaskFinished(SubtaskFinished::StorageRequestFinished {
                    request_id,
                    source_id,
                    result,
                }) => {
                    if matches!(self.database_catch_up_download, DatabaseCatchUpDownload::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download =
                            DatabaseCatchUpDownload::NoDownloadInProgress;
                    }
                    if matches!(self.database_catch_up_download_block_verification, DatabaseCatchUpDownloadBlockVerification::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download_block_verification =
                            DatabaseCatchUpDownloadBlockVerification::None;
                    }

                    if let Ok(result) = &result {
                        let result = result.clone();
                        self.database
                            .with_database(move |database| {
                                if let Ok(decoded) = trie::proof_decode::decode_and_verify_proof(
                                    trie::proof_decode::Config {
                                        proof: result.decode(),
                                    },
                                ) {
                                    for (_, entry) in decoded.iter_ordered() {
                                        // TODO: check the state root hash; while this can't lead to a vulnerability, it can bloat the database
                                        database.insert_trie_nodes(
                                            iter::once(full_sqlite::InsertTrieNode {
                                                merkle_value: Cow::Borrowed(entry.merkle_value),
                                                partial_key_nibbles: Cow::Owned(entry.partial_key_nibbles.into_iter().map(|n| u8::from(n)).collect()),
                                                children_merkle_values: std::array::from_fn(|n| entry.trie_node_info.children.child(trie::Nibble::try_from(u8::try_from(n).unwrap()).unwrap()).merkle_value().map(Cow::Borrowed)),
                                                storage_value: match entry.trie_node_info.storage_value {
                                                    trie::proof_decode::StorageValue::HashKnownValueMissing(
                                                        _,
                                                    ) => return,
                                                    trie::proof_decode::StorageValue::None => {
                                                        full_sqlite::InsertTrieNodeStorageValue::NoValue
                                                    }
                                                    trie::proof_decode::StorageValue::Known {
                                                        value, ..
                                                    } => full_sqlite::InsertTrieNodeStorageValue::Value {
                                                        value: Cow::Borrowed(value),
                                                        references_merkle_value: false, // TODO:
                                                    },
                                                },
                                            }),
                                            match entry.trie_node_info.storage_value {
                                                trie::proof_decode::StorageValue::None => 0, // TODO: ?!
                                                trie::proof_decode::StorageValue::HashKnownValueMissing(
                                                    ..
                                                ) => return,
                                                trie::proof_decode::StorageValue::Known {
                                                    inline: true,
                                                    ..
                                                } => 0,
                                                trie::proof_decode::StorageValue::Known {
                                                    inline: false,
                                                    ..
                                                } => 1,
                                            },
                                        ).unwrap();
                                    }
                                }
                            })
                            .await;
                    }

                    if result.is_err() {
                        // Note that we perform the ban even if the source is now disconnected.
                        let peer_id = self.sync[source_id].as_ref().unwrap().peer_id.clone();
                        self.network_service
                            .ban_and_disconnect(
                                peer_id,
                                self.network_chain_id,
                                network_service::BanSeverity::Low,
                                "storage-proof-request-error",
                            )
                            .await;
                    }

                    if let Ok(result) = result {
                        // TODO: to_owned overhead
                        let _ = self
                            .sync
                            .storage_get_response(request_id, result.decode().to_owned());
                    } else {
                        let _ = self.sync.remove_request(request_id);
                    }

                    // If the source was actually disconnected and has no other request in
                    // progress, we clean it up.
                    // TODO: DRY
                    if self.sync[source_id]
                        .as_ref()
                        .map_or(false, |info| info.is_disconnected)
                        && self.sync.source_num_ongoing_requests(source_id) == 0
                    {
                        let (info, mut _requests) = self.sync.remove_source(source_id);
                        debug_assert!(_requests.next().is_none());
                        self.peers_source_id_map
                            .remove(&info.unwrap().peer_id)
                            .unwrap();
                    }

                    process_sync = true;
                }

                WakeUpReason::SubtaskFinished(SubtaskFinished::CallProofRequestFinished {
                    request_id,
                    source_id,
                    result,
                }) => {
                    if matches!(self.database_catch_up_download, DatabaseCatchUpDownload::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download =
                            DatabaseCatchUpDownload::NoDownloadInProgress;
                    }
                    if matches!(self.database_catch_up_download_block_verification, DatabaseCatchUpDownloadBlockVerification::InProgress(r) if r == request_id)
                    {
                        self.database_catch_up_download_block_verification =
                            DatabaseCatchUpDownloadBlockVerification::None;
                    }

                    // TODO: DRY with above
                    if let Ok(result) = &result {
                        let result = result.clone();
                        self.database
                            .with_database(move |database| {
                                if let Ok(decoded) = trie::proof_decode::decode_and_verify_proof(
                                    trie::proof_decode::Config {
                                        proof: result.decode(),
                                    },
                                ) {
                                    for (_, entry) in decoded.iter_ordered() {
                                        // TODO: check the state root hash; while this can't lead to a vulnerability, it can bloat the database
                                        database.insert_trie_nodes(
                                            iter::once(full_sqlite::InsertTrieNode {
                                                merkle_value: Cow::Borrowed(entry.merkle_value),
                                                partial_key_nibbles: Cow::Owned(entry.partial_key_nibbles.into_iter().map(|n| u8::from(n)).collect()),
                                                children_merkle_values: std::array::from_fn(|n| entry.trie_node_info.children.child(trie::Nibble::try_from(u8::try_from(n).unwrap()).unwrap()).merkle_value().map(Cow::Borrowed)),
                                                storage_value: match entry.trie_node_info.storage_value {
                                                    trie::proof_decode::StorageValue::HashKnownValueMissing(
                                                        _,
                                                    ) => return,
                                                    trie::proof_decode::StorageValue::None => {
                                                        full_sqlite::InsertTrieNodeStorageValue::NoValue
                                                    }
                                                    trie::proof_decode::StorageValue::Known {
                                                        value, ..
                                                    } => full_sqlite::InsertTrieNodeStorageValue::Value {
                                                        value: Cow::Borrowed(value),
                                                        references_merkle_value: false, // TODO:
                                                    },
                                                },
                                            }),
                                            match entry.trie_node_info.storage_value {
                                                trie::proof_decode::StorageValue::None => 0, // TODO: ?!
                                                trie::proof_decode::StorageValue::HashKnownValueMissing(
                                                    ..
                                                ) => return,
                                                trie::proof_decode::StorageValue::Known {
                                                    inline: true,
                                                    ..
                                                } => 0,
                                                trie::proof_decode::StorageValue::Known {
                                                    inline: false,
                                                    ..
                                                } => 1,
                                            },
                                        ).unwrap();
                                    }
                                }
                            })
                            .await;
                    }

                    if result.is_err() {
                        // Note that we perform the ban even if the source is now disconnected.
                        let peer_id = self.sync[source_id].as_ref().unwrap().peer_id.clone();
                        self.network_service
                            .ban_and_disconnect(
                                peer_id,
                                self.network_chain_id,
                                network_service::BanSeverity::Low,
                                "call-proof-request-error",
                            )
                            .await;
                    }

                    if let Ok(result) = result {
                        self.sync
                            .call_proof_response(request_id, result.decode().to_owned());
                        // TODO: need help from networking service to avoid this to_owned
                    } else {
                        self.sync.remove_request(request_id);
                    }

                    // If the source was actually disconnected and has no other request in
                    // progress, we clean it up.
                    // TODO: DRY
                    if self.sync[source_id]
                        .as_ref()
                        .map_or(false, |info| info.is_disconnected)
                        && self.sync.source_num_ongoing_requests(source_id) == 0
                    {
                        let (info, mut _requests) = self.sync.remove_source(source_id);
                        debug_assert!(_requests.next().is_none());
                        self.peers_source_id_map
                            .remove(&info.unwrap().peer_id)
                            .unwrap();
                    }

                    process_sync = true;
                }

                WakeUpReason::SyncProcess => {
                    // Given that processing blocks might generate a notification, and that
                    // only one notification can be queued at a time, this path must never be
                    // reached if a notification is already waiting.
                    debug_assert!(self.pending_notification.is_none());
                    // Similarly, verifying a block might generate a block announce.
                    debug_assert!(self.pending_block_announce.is_none());

                    // Given that a block verification might require downloading some storage
                    // items due to missing storage items, and that we only want one download at
                    // a time, we don't verify blocks if a download is in progress.
                    debug_assert!(matches!(
                        self.database_catch_up_download_block_verification,
                        DatabaseCatchUpDownloadBlockVerification::None
                    ));

                    let (new_self, maybe_more_to_process) = self.process_blocks().await;
                    process_sync = maybe_more_to_process;
                    self = new_self;
                }
            }
        }
    }

    /// Authors a block, then imports it and gossips it out.
    ///
    /// # Panic
    ///
    /// The [`SyncBackground::block_authoring`] must be [`author::build::Builder::Ready`].
    ///
    async fn author_block(&mut self) {
        let (authoring_start, local_authorities) = match self.block_authoring.take() {
            Some((author::build::Builder::Ready(authoring), local_authorities)) => {
                (authoring, local_authorities)
            }
            _ => panic!(),
        };

        // TODO: it is possible that the current best block is already the same authoring slot as the slot we want to claim ; unclear how to solve this

        let parent_number = self.sync.best_block_number();
        self.log_callback.log(
            LogLevel::Debug,
            format!(
                "block-author-start; parent_hash={}; parent_number={}",
                HashDisplay(self.sync.best_block_hash()),
                parent_number,
            ),
        );

        // We would like to create a span for authoring the new block, but the trace id depends on
        // the block hash, which is only known at the end.
        let block_author_jaeger_start_time = mick_jaeger::StartTime::now();

        // Determine when the block should stop being authored.
        //
        // In order for the network to perform well, a block should be authored and propagated
        // throughout the peer-to-peer network before the end of the slot. In order for this
        // to happen, the block creation process itself should end a few seconds before the
        // end of the slot.
        //
        // Most parts of the block authorship can't be accelerated, in particular the
        // initialization and the signing at the end. This end of authoring threshold is only
        // checked when deciding whether to continue including more transactions in the block.
        // TODO: use this
        // TODO: Substrate nodes increase the time available for authoring if it detects that slots have been skipped, in order to account for the possibility that the initialization of a block or the inclusion of an extrinsic takes too long
        let authoring_end = {
            let start = authoring_start.slot_start_from_unix_epoch();
            let end = authoring_start.slot_end_from_unix_epoch();
            debug_assert!(start < end);
            debug_assert!(SystemTime::now() >= SystemTime::UNIX_EPOCH + start);
            SystemTime::UNIX_EPOCH
                + start
                + (end - start) * u32::from(self.slot_duration_author_ratio) / u32::from(u16::MAX)
        };

        // Actual block production now happening.
        let (new_block_header, new_block_body) = {
            let parent_hash = *self.sync.best_block_hash();
            let parent_runtime_arc =
                if self.sync.best_block_number() != self.sync.finalized_block_number() {
                    let NonFinalizedBlock::Verified {
                        runtime: parent_runtime_arc,
                    } = &self.sync[(self.sync.best_block_number(), self.sync.best_block_hash())]
                    else {
                        unreachable!()
                    };
                    parent_runtime_arc.clone()
                } else {
                    self.finalized_runtime.clone()
                };
            let parent_runtime = (*parent_runtime_arc).clone();

            // Start the block authoring process.
            let mut block_authoring = {
                authoring_start.start(author::build::AuthoringStartConfig {
                    block_number_bytes: self.sync.block_number_bytes(),
                    parent_hash: &self.sync.best_block_hash(),
                    parent_number: self.sync.best_block_number(),
                    now_from_unix_epoch: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap(),
                    parent_runtime,
                    block_body_capacity: 0, // TODO: could be set to the size of the tx pool
                    max_log_level: 0,
                    calculate_trie_changes: true,
                })
            };

            // The block authoring process jumps through various states, interrupted when it needs
            // access to the storage of the best block.
            loop {
                match block_authoring {
                    author::build::BuilderAuthoring::Seal(seal) => {
                        // This is the last step of the authoring. The block creation is
                        // successful, and the only thing remaining to do is sign the block
                        // header. Signing is done through `self.keystore`.

                        // TODO: correct key namespace
                        let data_to_sign = seal.to_sign();
                        let sign_future = self.keystore.sign(
                            keystore::KeyNamespace::Aura,
                            &local_authorities[seal.authority_index()],
                            &data_to_sign,
                        );

                        let success = match sign_future.await {
                            Ok(signature) => seal.inject_sr25519_signature(signature),
                            Err(error) => {
                                // Because the keystore is subject to race conditions, it is
                                // possible for this situation to happen if the key has been
                                // removed from the keystore in parallel of the block authoring
                                // process, or the key is maybe no longer accessible because of
                                // another issue.
                                self.log_callback.log(
                                    LogLevel::Warn,
                                    format!("block-author-signing-error; error={}", error),
                                );
                                self.block_authoring = None;
                                return;
                            }
                        };

                        break (success.scale_encoded_header, success.body);
                    }

                    author::build::BuilderAuthoring::Error { error, .. } => {
                        // Block authoring process stopped because of an error.

                        // In order to prevent the block authoring from restarting immediately
                        // after and failing again repeatedly, we switch the block authoring to
                        // the same state as if it had successfully generated a block.
                        self.block_authoring = Some((author::build::Builder::Idle, Vec::new()));
                        // TODO: log the runtime logs
                        self.log_callback.log(
                            LogLevel::Warn,
                            format!("block-author-error; error={}", error),
                        );
                        return;
                    }

                    // Part of the block production consists in adding transactions to the block.
                    // These transactions are extracted from the transactions pool.
                    author::build::BuilderAuthoring::ApplyExtrinsic(apply) => {
                        // TODO: actually implement including transactions in the blocks
                        block_authoring = apply.finish();
                    }
                    author::build::BuilderAuthoring::ApplyExtrinsicResult { result, resume } => {
                        if let Err(error) = result {
                            // TODO: include transaction bytes or something?
                            self.log_callback.log(
                                LogLevel::Warn,
                                format!(
                                    "block-author-transaction-inclusion-error; error={}",
                                    error
                                ),
                            );
                        }

                        // TODO: actually implement including transactions in the blocks
                        block_authoring = resume.finish();
                    }

                    // Access to the best block storage.
                    author::build::BuilderAuthoring::StorageGet(req) => {
                        let parent_paths = req.child_trie().map(|child_trie| {
                            trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                                .map(u8::from)
                                .collect::<Vec<_>>()
                        });
                        let key = trie::bytes_to_nibbles(req.key().as_ref().iter().copied())
                            .map(u8::from)
                            .collect::<Vec<_>>();
                        let value = self
                            .database
                            .with_database(move |db| {
                                db.block_storage_get(
                                    &parent_hash,
                                    parent_paths.into_iter().map(|p| p.into_iter()),
                                    key.iter().copied(),
                                )
                            })
                            .await
                            // TODO: don't panic in case of incomplete storage
                            .expect("database access error");

                        block_authoring = req.inject_value(value.as_ref().map(|(val, vers)| {
                            (
                                iter::once(&val[..]),
                                runtime_call::TrieEntryVersion::try_from(*vers)
                                    .expect("corrupted database"),
                            )
                        }));
                    }
                    author::build::BuilderAuthoring::ClosestDescendantMerkleValue(req) => {
                        let parent_paths = req.child_trie().map(|child_trie| {
                            trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                                .map(u8::from)
                                .collect::<Vec<_>>()
                        });
                        let key_nibbles = req.key().map(u8::from).collect::<Vec<_>>();

                        let merkle_value = self
                            .database
                            .with_database(move |db| {
                                db.block_storage_closest_descendant_merkle_value(
                                    &parent_hash,
                                    parent_paths.into_iter().map(|p| p.into_iter()),
                                    key_nibbles.iter().copied(),
                                )
                            })
                            .await
                            // TODO: don't panic in case of incomplete storage
                            .expect("database access error");

                        block_authoring =
                            req.inject_merkle_value(merkle_value.as_ref().map(|v| &v[..]));
                    }
                    author::build::BuilderAuthoring::NextKey(req) => {
                        let parent_paths = req.child_trie().map(|child_trie| {
                            trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                                .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                                .map(u8::from)
                                .collect::<Vec<_>>()
                        });
                        let key_nibbles = req
                            .key()
                            .map(u8::from)
                            .chain(if req.or_equal() { None } else { Some(0u8) })
                            .collect::<Vec<_>>();
                        let prefix_nibbles = req.prefix().map(u8::from).collect::<Vec<_>>();

                        let branch_nodes = req.branch_nodes();
                        let next_key = self
                            .database
                            .with_database(move |db| {
                                db.block_storage_next_key(
                                    &parent_hash,
                                    parent_paths.into_iter().map(|p| p.into_iter()),
                                    key_nibbles.iter().copied(),
                                    prefix_nibbles.iter().copied(),
                                    branch_nodes,
                                )
                            })
                            .await
                            // TODO: don't panic in case of incomplete storage
                            .expect("database access error");

                        block_authoring = req
                            .inject_key(next_key.map(|k| {
                                k.into_iter().map(|b| trie::Nibble::try_from(b).unwrap())
                            }));
                    }
                    author::build::BuilderAuthoring::OffchainStorageSet(req) => {
                        // Ignore offchain storage writes at the moment.
                        block_authoring = req.resume();
                    }
                }
            }
        };

        // Block has now finished being generated.
        // TODO: print logs
        let new_block_hash = header::hash_from_scale_encoded_header(&new_block_header);
        self.log_callback.log(
            LogLevel::Info,
            format!(
                "block-generated; hash={}; body_len={}",
                HashDisplay(&new_block_hash),
                new_block_body.len()
            ),
        );
        let _jaeger_span = self
            .jaeger_service
            .block_authorship_span(&new_block_hash, block_author_jaeger_start_time);

        // Print a warning if generating the block has taken more time than expected.
        // This can happen because the node is completely overloaded, is running on a slow machine,
        // or if the runtime code being executed contains a very heavy operation.
        // In any case, there is not much that a node operator can do except try increase the
        // performance of their machine.
        match authoring_end.elapsed() {
            Ok(now_minus_end) if now_minus_end < Duration::from_millis(500) => {}
            _ => {
                self.log_callback.log(
                    LogLevel::Warn,
                    format!(
                        "block-generation-too-long; hash={}",
                        HashDisplay(&new_block_hash)
                    ),
                );
            }
        }

        // Switch the block authoring to a state where we won't try to generate a new block again
        // until something new happens.
        // TODO: nothing prevents the node from generating two blocks at the same height at the moment
        self.block_authoring = Some((author::build::Builder::Idle, Vec::new()));

        // The next step is to import the block in `self.sync`. This is done by pretending that
        // the local node is a source of block similar to networking peers.
        let all::BlockAnnounceOutcome::Unknown(block_insert) = self.sync.block_announce(
            self.block_author_sync_source,
            new_block_header.clone(),
            true, // Since the new block is a child of the current best block, it always becomes the new best.
        ) else {
            unreachable!();
        };
        block_insert.insert_and_update_source(NonFinalizedBlock::NotVerified);

        debug_assert!(self.authored_block.is_none());
        self.authored_block = Some((
            parent_number + 1,
            new_block_hash,
            new_block_header,
            new_block_body,
        ));
    }

    async fn process_blocks(mut self) -> (Self, bool) {
        // The sync state machine can be in a few various states. At the time of writing:
        // idle, verifying header, verifying block, verifying grandpa warp sync proof,
        // verifying storage proof.
        // If the state is one of the "verifying" states, perform the actual verification and
        // loop again until the sync is in an idle state.
        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        // TODO: move this?
        let block_number_bytes = self.sync.block_number_bytes();

        match self.sync.process_one() {
            all::ProcessOne::AllSync(idle) => {
                self.sync = idle;
                (self, false)
            }
            all::ProcessOne::VerifyWarpSyncFragment(verify) => {
                let sender = verify
                    .proof_sender()
                    .map(|(_, s)| s.as_ref().unwrap().peer_id.clone());

                let (new_sync, outcome) = verify.perform(rand::random());
                self.sync = new_sync;
                match outcome {
                    Ok((fragment_hash, fragment_height)) => {
                        self.log_callback.log(
                            LogLevel::Debug,
                            format!(
                                "warp-sync-fragment-verification-success; peer_id={}, fragment-hash={}, fragment-height={fragment_height}",
                                sender.map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_owned()),
                                hex::encode(&fragment_hash)
                            ),
                        );
                    }
                    Err(err) => {
                        // BlockNumberNotIncrementing means the chain gap is too small
                        // for warp sync to make progress. This is legitimate on
                        // short/fresh chains (e.g. zombienet) and is not misbehavior.
                        if !matches!(err, all::VerifyFragmentError::BlockNumberNotIncrementing) {
                            if let Some(sender) = &sender {
                                self.network_service
                                    .ban_and_disconnect(
                                        sender.clone(),
                                        self.network_chain_id,
                                        network_service::BanSeverity::High,
                                        "bad-warp-sync-fragment",
                                    )
                                    .await;
                            }
                        }

                        self.log_callback.log(
                            LogLevel::Warn,
                            format!(
                                "failed-warp-sync-fragment-verification; peer_id={}, error={err}",
                                sender
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "unknown".to_owned()),
                            ),
                        );
                    }
                }
                (self, true)
            }
            all::ProcessOne::WarpSyncBuildRuntime(build_runtime) => {
                let (new_sync, outcome) =
                    build_runtime.build(all::ExecHint::ValidateAndCompile, true);
                self.sync = new_sync;
                if let Err(err) = outcome {
                    self.log_callback.log(
                        LogLevel::Warn,
                        format!("failed-warp-sync-runtime-compilation; error={err}"),
                    );
                }
                (self, true)
            }
            all::ProcessOne::WarpSyncBuildChainInformation(build_chain_information) => {
                let (new_sync, outcome) = build_chain_information.build();
                self.sync = new_sync;
                if let Err(err) = outcome {
                    self.log_callback.log(
                        LogLevel::Warn,
                        format!("failed-warp-sync-chain-information-build; error={err}"),
                    );
                }
                (self, true)
            }
            all::ProcessOne::WarpSyncFinished {
                sync,
                finalized_body: Some(finalized_body),
                finalized_block_runtime,
                ..
            } => {
                self.sync = sync;

                // Destory all existing subscriptions due to the gap in the chain.
                self.pending_notification = None;
                self.blocks_notifications.clear();

                self.finalized_runtime = Arc::new(finalized_block_runtime);
                let finalized_block_header = self
                    .sync
                    .as_chain_information()
                    .as_ref()
                    .finalized_block_header
                    .scale_encoding_vec(self.sync.block_number_bytes());
                self.database
                    .with_database(move |database| {
                        database
                            .reset(
                                &finalized_block_header,
                                finalized_body.iter().map(|e| &e[..]),
                                None,
                            )
                            .unwrap();
                    })
                    .await;
                // TODO: what is known about the finalized storage into the database is currently done when a proof is downloaded; however if the proof download finished code no longer inserts entries related to unknown blocks, then we should do it here instead

                if matches!(
                    self.database_catch_up_download,
                    DatabaseCatchUpDownload::NothingToDownloadCache
                ) {
                    self.database_catch_up_download = DatabaseCatchUpDownload::NoDownloadInProgress;
                }

                (self, true)
            }
            all::ProcessOne::WarpSyncFinished {
                finalized_body: None,
                ..
            } => {
                unreachable!()
            }
            all::ProcessOne::VerifyBlock(verify) => {
                // TODO: ban peer in case of verification failure
                let when_verification_started = Instant::now();
                let hash_to_verify = verify.hash();

                let _jaeger_span = self.jaeger_service.block_verify_span(&hash_to_verify);

                let (is_new_best, header_verification_success) =
                    match verify.verify_header(unix_time) {
                        all::HeaderVerifyOutcome::Success {
                            is_new_best,
                            success,
                        } => (is_new_best, success),
                        all::HeaderVerifyOutcome::Error { sync, error } => {
                            // Print a separate warning because it is important for the user
                            // to be aware of the verification failure.
                            // `error` is last because it's quite big.
                            self.log_callback.log(
                                LogLevel::Warn,
                                format!(
                                    "failed-block-verification; hash={}; error={}",
                                    HashDisplay(&hash_to_verify),
                                    error
                                ),
                            );
                            self.sync = sync;
                            return (self, true);
                        }
                    };

                let parent_info = header_verification_success.parent_user_data().map(|b| {
                    let NonFinalizedBlock::Verified { runtime } = b else {
                        unreachable!()
                    };
                    runtime.clone()
                });
                let parent_runtime_arc = parent_info
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| self.finalized_runtime.clone());

                // TODO: check this block against the chain spec's badBlocks

                let height = header_verification_success.height();
                let scale_encoded_header =
                    header_verification_success.scale_encoded_header().to_vec();

                let execute_block_success = match execute_block_and_insert(
                    &self.database,
                    (*parent_runtime_arc).clone(),
                    &header_verification_success.parent_hash(),
                    header_verification_success.scale_encoded_header(),
                    block_number_bytes,
                    header_verification_success
                        .scale_encoded_extrinsics()
                        .unwrap(),
                    unix_time,
                    is_new_best,
                )
                .await
                {
                    Ok(success) => success,
                    Err(ExecuteBlockError::VerificationFailure(
                        ExecuteBlockVerificationFailureError::DatabaseParentAccess {
                            error: full_sqlite::StorageAccessError::IncompleteStorage,
                            context,
                        },
                    )) => {
                        // The block verification failed because the storage of the parent
                        // is still being downloaded from the network.
                        self.log_callback.log(
                            LogLevel::Debug,
                            format!(
                                "block-verification-incomplete-storage; hash={}; height={}; \
                                time_before_interrupt={:?}",
                                HashDisplay(&hash_to_verify),
                                header_verification_success.height(),
                                when_verification_started.elapsed()
                            ),
                        );

                        debug_assert!(matches!(
                            self.database_catch_up_download_block_verification,
                            DatabaseCatchUpDownloadBlockVerification::None
                        ));
                        match context {
                            ExecuteBlockDatabaseAccessFailureContext::ParentRuntimeAccess => {
                                self.database_catch_up_download_block_verification = DatabaseCatchUpDownloadBlockVerification::CodeStorageProofDesired {
                                    block_hash: *header_verification_success.parent_hash(),
                                    block_number: header_verification_success.height() - 1,
                                };
                            }
                            ExecuteBlockDatabaseAccessFailureContext::FunctionCall {
                                function_name,
                                parameter,
                            } => {
                                self.database_catch_up_download_block_verification =
                                    DatabaseCatchUpDownloadBlockVerification::CallProofDesired {
                                        block_hash: *header_verification_success.parent_hash(),
                                        block_number: header_verification_success.height() - 1,
                                        function_name: function_name.to_owned(),
                                        parameter,
                                    };
                            }
                        }

                        self.sync = header_verification_success.cancel();
                        return (self, true);
                    }
                    Err(ExecuteBlockError::VerificationFailure(
                        ExecuteBlockVerificationFailureError::DatabaseParentAccess {
                            error, ..
                        },
                    )) => {
                        panic!("corrupted database: {error}")
                    }
                    Err(ExecuteBlockError::VerificationFailure(
                        ExecuteBlockVerificationFailureError::ParentCodeEmptyInDatabase
                        | ExecuteBlockVerificationFailureError::InvaliParentHeapPagesInDatabase(_)
                        | ExecuteBlockVerificationFailureError::DatabaseInvalidStateTrieVersion,
                    )) => panic!("corrupted database"),
                    Err(error) => {
                        // Print a separate warning because it is important for the user
                        // to be aware of the verification failure.
                        // `error` is last because it's quite big.
                        self.log_callback.log(
                            LogLevel::Warn,
                            format!(
                                "failed-block-verification; hash={}; height={}; \
                                total_duration={:?}; error={error}",
                                HashDisplay(&hash_to_verify),
                                header_verification_success.height(),
                                when_verification_started.elapsed()
                            ),
                        );
                        // Note that some errors are verification failures errors that shouldn't
                        // lead to the block being marked as bad. However, there's not much else
                        // we can do here as trying to verify the block again would likely lead to
                        // the same error again. Marking the block as bad is a reasonable solution.
                        self.sync = header_verification_success.reject_bad_block();
                        return (self, true);
                    }
                };

                self.log_callback.log(
                    LogLevel::Debug,
                    format!(
                        "block-verification-success; hash={}; height={}; \
                            total_duration={:?}; database_accesses_duration={:?}; \
                            runtime_build_duration={:?}; is_new_best={:?}",
                        HashDisplay(&hash_to_verify),
                        height,
                        when_verification_started.elapsed(),
                        execute_block_success.database_accesses_duration,
                        execute_block_success.runtime_build_duration,
                        is_new_best
                    ),
                );

                match execute_block_success.block_insertion {
                    Ok(()) => {}
                    Err(full_sqlite::InsertError::Duplicate) => {} // TODO: this should be an error ; right now we silence them because non-finalized blocks aren't loaded from the database at startup, resulting in them being downloaded again
                    Err(error) => panic!("failed to insert block in database: {error}"),
                }

                // Notify the subscribers.
                debug_assert!(self.pending_notification.is_none());
                self.pending_notification = Some(Notification::Block {
                    block: BlockNotification {
                        is_new_best,
                        scale_encoded_header: scale_encoded_header.clone(),
                        block_hash: header_verification_success.hash(),
                        runtime_update: execute_block_success
                            .new_runtime
                            .as_ref()
                            .map(|new_runtime| Arc::new(new_runtime.clone())),
                        parent_hash: *header_verification_success.parent_hash(),
                    },
                    storage_changes: execute_block_success.storage_changes.clone(),
                });

                // Processing has made a step forward.

                self.sync = header_verification_success.finish(NonFinalizedBlock::NotVerified);

                // Store the storage of the children.
                self.sync[(height, &hash_to_verify)] = NonFinalizedBlock::Verified {
                    runtime: if let Some(new_runtime) = execute_block_success.new_runtime {
                        Arc::new(new_runtime)
                    } else {
                        parent_runtime_arc
                    },
                };

                if is_new_best {
                    // Update the networking.
                    self.network_local_chain_update_needed = true;
                    // Reset the block authoring, in order to potentially build a
                    // block on top of this new best.
                    self.block_authoring = None;
                }

                // Announce the newly-verified block to all the sources that might
                // not be aware of it.
                debug_assert!(self.pending_block_announce.is_none());
                self.pending_block_announce = Some((scale_encoded_header, hash_to_verify, height));

                return (self, true);
            }

            all::ProcessOne::VerifyFinalityProof(verify) => {
                let sender = verify
                    .sender()
                    .1
                    .as_ref()
                    .map(|s| s.peer_id.clone())
                    .unwrap();

                match verify.perform(rand::random()) {
                    (
                        sync_out,
                        all::FinalityProofVerifyOutcome::NewFinalized {
                            finalized_blocks_newest_to_oldest,
                            pruned_blocks,
                            updates_best_block,
                        },
                    ) => {
                        self.sync = sync_out;

                        let new_finalized_hash = finalized_blocks_newest_to_oldest
                            .first()
                            .unwrap()
                            .block_hash;
                        self.log_callback.log(
                            LogLevel::Debug,
                            format!(
                                "finality-proof-verification; outcome=success, sender={sender}, new-finalized={}",
                                HashDisplay(&new_finalized_hash)
                            ),
                        );

                        if updates_best_block {
                            // Update the networking.
                            self.network_local_chain_update_needed = true;
                            // Reset the block authoring, in order to potentially build a
                            // block on top of this new best.
                            self.block_authoring = None;
                        }

                        self.finalized_runtime =
                            match &finalized_blocks_newest_to_oldest.first().unwrap().user_data {
                                NonFinalizedBlock::Verified { runtime } => runtime.clone(),
                                _ => unreachable!(),
                            };
                        // TODO: what if best block changed?
                        self.database
                            .with_database_detached(move |database| {
                                database.set_finalized(&new_finalized_hash).unwrap();
                            })
                            .await;

                        // Notify the subscribers.
                        debug_assert!(self.pending_notification.is_none());
                        self.pending_notification = Some(Notification::Finalized {
                            finalized_blocks_newest_to_oldest: finalized_blocks_newest_to_oldest
                                .iter()
                                .map(|b| b.block_hash)
                                .collect::<Vec<_>>(),
                            pruned_blocks_hashes: pruned_blocks.clone(),
                            best_block_hash: *self.sync.best_block_hash(),
                        });

                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::GrandpaCommitPending) => {
                        self.log_callback.log(
                            LogLevel::Debug,
                            "finality-proof-verification; outcome=pending, sender={sender}"
                                .to_string(),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::AlreadyFinalized) => {
                        self.log_callback.log(
                            LogLevel::Debug,
                            "finality-proof-verification; outcome=already-finalized, sender={sender}".to_string(),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::GrandpaCommitError(error)) => {
                        self.network_service
                            .ban_and_disconnect(
                                sender.clone(),
                                self.network_chain_id,
                                network_service::BanSeverity::High,
                                "bad-warp-sync-fragment",
                            )
                            .await;
                        self.log_callback.log(
                            LogLevel::Warn,
                            format!(
                                "finality-proof-verification-failure; sender={sender}, error={}",
                                error
                            ),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                    (sync_out, all::FinalityProofVerifyOutcome::JustificationError(error)) => {
                        // Errors of type `JustificationEngineMismatch` indicate that the chain
                        // uses a finality engine that smoldot doesn't recognize. This is a benign
                        // error that shouldn't lead to a ban.
                        if !matches!(
                            error,
                            all::JustificationVerifyError::JustificationEngineMismatch
                        ) {
                            self.network_service
                                .ban_and_disconnect(
                                    sender.clone(),
                                    self.network_chain_id,
                                    network_service::BanSeverity::High,
                                    "bad-warp-sync-fragment",
                                )
                                .await;
                        }
                        self.log_callback.log(
                            LogLevel::Warn,
                            format!(
                                "finality-proof-verification-failure; sender={sender}, error={}",
                                error
                            ),
                        );
                        self.sync = sync_out;
                        (self, true)
                    }
                }
            }
        }
    }
}

/// Executes the given block. On success, inserts it and its storage into the database.
// TODO: use a config struct for the parameters?
pub async fn execute_block_and_insert(
    database: &database_thread::DatabaseThread,
    mut parent_runtime: host::HostVmPrototype,
    parent_block_hash: &[u8; 32],
    block_header: &[u8],
    block_number_bytes: usize,
    block_body: impl ExactSizeIterator<Item = impl AsRef<[u8]> + Clone> + Clone,
    now_from_unix_epoch: Duration,
    is_new_best: bool,
) -> Result<ExecuteBlockSuccess, ExecuteBlockError> {
    let mut database_accesses_duration = Duration::new(0, 0);
    let mut runtime_build_duration = Duration::new(0, 0);

    let mut storage_changes = runtime_call::StorageChanges::empty();
    let mut state_trie_version = runtime_call::TrieEntryVersion::V0; // TODO: shouldn't have to be initialized
    for (call_function, call_parameter) in [
        (
            body_only::CHECK_INHERENTS_FUNCTION_NAME,
            body_only::check_inherents_parameter(
                block_header,
                block_number_bytes,
                block_body.clone(),
                now_from_unix_epoch,
            )
            .unwrap()
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            }),
        ),
        (
            body_only::EXECUTE_BLOCK_FUNCTION_NAME,
            body_only::execute_block_parameter(
                block_header,
                block_number_bytes,
                block_body.clone(),
            )
            .unwrap()
            .fold(Vec::new(), |mut a, b| {
                a.extend_from_slice(b.as_ref());
                a
            }),
        ),
    ] {
        match runtime_call(
            database,
            parent_block_hash,
            parent_runtime,
            call_function,
            &call_parameter,
            runtime_call::StorageProofSizeBehavior::Unimplemented,
            storage_changes,
        )
        .await
        {
            Ok(success) => {
                // TODO: a bit crappy to compare function names, however I got insanely weird borrowck errors if putting a fn() in the for loop above
                let error = if call_function == body_only::CHECK_INHERENTS_FUNCTION_NAME {
                    body_only::check_check_inherents_output(&success.output)
                        .map_err(ExecuteBlockInvalidBlockError::CheckInherentsOutputError)
                        .err()
                } else {
                    body_only::check_execute_block_output(&success.output)
                        .map_err(ExecuteBlockInvalidBlockError::ExecuteBlockOutputError)
                        .err()
                };
                if let Some(error) = error {
                    return Err(ExecuteBlockError::InvalidBlock(error));
                }

                parent_runtime = success.runtime;
                storage_changes = success.storage_changes;
                state_trie_version = success.state_trie_version;
                database_accesses_duration += success.database_accesses_duration;
            }
            Err(RuntimeCallError::RuntimeStartError(error)) => {
                return Err(ExecuteBlockError::VerificationFailure(
                    ExecuteBlockVerificationFailureError::RuntimeStartError(error),
                ));
            }
            Err(RuntimeCallError::RuntimeExecutionError(error)) => {
                return Err(ExecuteBlockError::InvalidBlock(
                    ExecuteBlockInvalidBlockError::RuntimeExecutionError(error),
                ));
            }
            Err(RuntimeCallError::DatabaseParentAccess(error)) => {
                return Err(ExecuteBlockError::VerificationFailure(
                    ExecuteBlockVerificationFailureError::DatabaseParentAccess {
                        error,
                        context: ExecuteBlockDatabaseAccessFailureContext::FunctionCall {
                            function_name: call_function,
                            parameter: call_parameter.to_owned(),
                        },
                    },
                ));
            }
            Err(RuntimeCallError::ForbiddenHostFunction) => {
                return Err(ExecuteBlockError::VerificationFailure(
                    ExecuteBlockVerificationFailureError::ForbiddenHostFunction,
                ));
            }
            Err(RuntimeCallError::DatabaseInvalidStateTrieVersion) => {
                return Err(ExecuteBlockError::VerificationFailure(
                    ExecuteBlockVerificationFailureError::DatabaseInvalidStateTrieVersion,
                ));
            }
        }
    }

    // If the block performs a runtime upgrade, compile the new runtime.
    // The block is rejected if the new runtime doesn't successfully compile.
    let new_runtime: Option<executor::host::HostVmPrototype> = match (
        storage_changes.main_trie_diff_get(b":code"),
        storage_changes.main_trie_diff_get(b":heappages"),
    ) {
        (None, None) => None,
        (new_code, new_heap_pages) => {
            let new_code = match new_code {
                Some(Some(c)) => Cow::Borrowed(c),
                Some(None) => {
                    return Err(ExecuteBlockError::InvalidBlock(
                        ExecuteBlockInvalidBlockError::EmptyCode,
                    ));
                }
                None => {
                    let parent_block_hash = *parent_block_hash;
                    let access = database
                        .with_database(move |db| {
                            db.block_storage_get(
                                &parent_block_hash,
                                iter::empty::<iter::Empty<_>>(),
                                trie::bytes_to_nibbles(b":code".into_iter().copied()).map(u8::from),
                            )
                        })
                        .await;
                    match access {
                        Ok(Some((v, _))) => Cow::Owned(v),
                        Ok(None) => {
                            return Err(ExecuteBlockError::VerificationFailure(
                                ExecuteBlockVerificationFailureError::ParentCodeEmptyInDatabase,
                            ));
                        }
                        Err(error) => return Err(ExecuteBlockError::VerificationFailure(
                            ExecuteBlockVerificationFailureError::DatabaseParentAccess {
                                error,
                                context:
                                    ExecuteBlockDatabaseAccessFailureContext::ParentRuntimeAccess,
                            },
                        )),
                    }
                }
            };

            let new_heap_pages = match new_heap_pages {
                Some(c) => executor::storage_heap_pages_to_value(c)
                    .map_err(ExecuteBlockInvalidBlockError::InvalidNewHeapPages)?,
                None => executor::storage_heap_pages_to_value(
                    {
                        let parent_block_hash = *parent_block_hash;
                        let access = database
                            .with_database(move |db| {
                                db.block_storage_get(
                                    &parent_block_hash,
                                    iter::empty::<iter::Empty<_>>(),
                                    trie::bytes_to_nibbles(b":heappages".into_iter().copied())
                                        .map(u8::from),
                                )
                            })
                            .await;
                        match access {
                            Ok(Some((v, _))) => Some(v),
                            Ok(None) => None,
                            Err(error) => return Err(ExecuteBlockError::VerificationFailure(
                                ExecuteBlockVerificationFailureError::DatabaseParentAccess {
                                    error,
                                    context:
                                        ExecuteBlockDatabaseAccessFailureContext::ParentRuntimeAccess,
                                },
                            )),
                        }
                    }
                    .as_deref(),
                )
                .map_err(ExecuteBlockVerificationFailureError::InvaliParentHeapPagesInDatabase)?,
            };

            let before_runtime_build = Instant::now();
            let vm = host::HostVmPrototype::new(host::Config {
                module: &new_code,
                heap_pages: new_heap_pages,
                exec_hint: executor::vm::ExecHint::ValidateAndCompile,
                allow_unresolved_imports: false,
            })
            .map_err(ExecuteBlockInvalidBlockError::InvalidNewRuntime)?;
            runtime_build_duration += before_runtime_build.elapsed();
            Some(vm)
        }
    };

    let storage_changes = Arc::new(storage_changes);

    // Insert the block in the database.
    let when_database_access_started = Instant::now();
    let block_insertion = database
        .with_database({
            let parent_block_hash = *parent_block_hash;
            let storage_changes = storage_changes.clone();
            let block_header = block_header.to_owned();
            let block_body = block_body
                .map(|tx| tx.as_ref().to_owned())
                .collect::<Vec<_>>();
            move |database| {
                database.insert(&block_header, is_new_best, block_body.into_iter())?;

                let trie_nodes = storage_changes
                    .trie_changes_iter_ordered()
                    .unwrap()
                    .filter_map(|(_child_trie, key, change)| {
                        let runtime_call::TrieChange::InsertUpdate {
                            new_merkle_value,
                            partial_key,
                            children_merkle_values,
                            new_storage_value,
                        } = &change
                        else {
                            return None;
                        };

                        // TODO: this punches through abstraction layers; maybe add some code to runtime_call to indicate this?
                        let references_merkle_value = key
                            .iter()
                            .copied()
                            .zip(trie::bytes_to_nibbles(b":child_storage:".iter().copied()))
                            .all(|(a, b)| a == b);

                        Some(full_sqlite::InsertTrieNode {
                            merkle_value: (&new_merkle_value[..]).into(),
                            children_merkle_values: array::from_fn(|n| {
                                children_merkle_values[n]
                                    .as_ref()
                                    .map(|v| From::from(&v[..]))
                            }),
                            storage_value: match new_storage_value {
                                runtime_call::TrieChangeStorageValue::Modified {
                                    new_value: Some(value),
                                } => full_sqlite::InsertTrieNodeStorageValue::Value {
                                    value: Cow::Borrowed(value),
                                    references_merkle_value,
                                },
                                runtime_call::TrieChangeStorageValue::Modified {
                                    new_value: None,
                                } => full_sqlite::InsertTrieNodeStorageValue::NoValue,
                                runtime_call::TrieChangeStorageValue::Unmodified => {
                                    // TODO: overhead, and no child trie support
                                    if let Some((value_in_parent, _)) = database
                                        .block_storage_get(
                                            &parent_block_hash,
                                            iter::empty::<iter::Empty<_>>(),
                                            key.iter().map(|n| u8::from(*n)),
                                        )
                                        .unwrap()
                                    {
                                        full_sqlite::InsertTrieNodeStorageValue::Value {
                                            value: Cow::Owned(value_in_parent),
                                            references_merkle_value,
                                        }
                                    } else {
                                        full_sqlite::InsertTrieNodeStorageValue::NoValue
                                    }
                                }
                            },
                            partial_key_nibbles: partial_key
                                .iter()
                                .map(|n| u8::from(*n))
                                .collect::<Vec<_>>()
                                .into(),
                        })
                    })
                    .collect::<Vec<_>>();

                database
                    .insert_trie_nodes(trie_nodes.into_iter(), u8::from(state_trie_version))
                    .map_err(full_sqlite::InsertError::Corrupted)
            }
        })
        .await;
    database_accesses_duration += when_database_access_started.elapsed();

    Ok(ExecuteBlockSuccess {
        block_insertion,
        new_runtime,
        storage_changes,
        database_accesses_duration,
        runtime_build_duration,
    })
}

/// Returned by [`execute_block_and_insert`] in case of success.
#[derive(Debug)]
pub struct ExecuteBlockSuccess {
    /// Whether the block was successfully inserted in the database.
    pub block_insertion: Result<(), full_sqlite::InsertError>,

    /// If the block modifies the runtime, this contains the new runtime.
    pub new_runtime: Option<host::HostVmPrototype>,

    /// Changes to the storage performed during the execution.
    pub storage_changes: Arc<runtime_call::StorageChanges>,

    /// Total time the database accesses combined took.
    pub database_accesses_duration: Duration,

    /// Total time compiling the new runtime took. Equal to 0 if no runtime upgrade happened.
    pub runtime_build_duration: Duration,
}

/// Error returned by [`execute_block_and_insert`].
#[derive(Debug, derive_more::Display, derive_more::Error, derive_more::From)]
pub enum ExecuteBlockError {
    /// Failed to verify block.
    VerificationFailure(ExecuteBlockVerificationFailureError),
    /// Block has been verified as being invalid.
    InvalidBlock(ExecuteBlockInvalidBlockError),
}

/// See [`ExecuteBlockError::VerificationFailure`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ExecuteBlockVerificationFailureError {
    /// Error starting the runtime execution.
    RuntimeStartError(executor::host::StartErr),
    /// Error while accessing the parent block in the database.
    #[display("Error while accessing the parent block in the database: {error}")]
    DatabaseParentAccess {
        /// Error that happened.
        #[error(source)]
        error: full_sqlite::StorageAccessError,
        /// In which context the error hapened.
        context: ExecuteBlockDatabaseAccessFailureContext,
    },
    /// State trie version stored in database is invalid.
    DatabaseInvalidStateTrieVersion,
    /// Runtime has tried to call a forbidden host function.
    ForbiddenHostFunction,
    /// The `:code` of the parent block in database is empty.
    ParentCodeEmptyInDatabase,
    /// The `:heappages` after the execution is invalid.
    InvaliParentHeapPagesInDatabase(executor::InvalidHeapPagesError),
}

/// See [`ExecuteBlockVerificationFailureError::DatabaseParentAccess`].
#[derive(Debug)]
pub enum ExecuteBlockDatabaseAccessFailureContext {
    /// Error while accessing the `:code` or `:heappages` key of the parent.
    ParentRuntimeAccess,
    /// Error while performing a runtime call.
    FunctionCall {
        /// Name of the function that was being called during the access error.
        function_name: &'static str,
        /// Parameter to the function that was being called during the access error.
        parameter: Vec<u8>,
    },
}

/// See [`ExecuteBlockError::InvalidBlock`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ExecuteBlockInvalidBlockError {
    /// Error while executing the runtime.
    RuntimeExecutionError(runtime_call::ErrorDetail),
    /// Error in the output of `BlockBuilder_check_inherents`.
    #[display("Error in the output of BlockBuilder_check_inherents: {_0}")]
    CheckInherentsOutputError(body_only::InherentsOutputError),
    /// Error in the output of `Core_execute_block`.
    #[display("Error in the output of Core_execute_block: {_0}")]
    ExecuteBlockOutputError(body_only::ExecuteBlockOutputError),
    /// The new `:code` after the execution is empty.
    EmptyCode,
    /// The `:heappages` after the execution is invalid.
    InvalidNewHeapPages(executor::InvalidHeapPagesError),
    /// Failed to compile the new runtime that the block upgrades to.
    InvalidNewRuntime(host::NewErr),
}

/// Perform a runtime call, using the database as the source for storage data.
pub async fn runtime_call(
    database: &database_thread::DatabaseThread,
    storage_block_hash: &[u8; 32],
    runtime: host::HostVmPrototype,
    function_to_call: &str,
    parameter: &[u8],
    storage_proof_size_behavior: runtime_call::StorageProofSizeBehavior,
    initial_storage_changes: runtime_call::StorageChanges,
) -> Result<RuntimeCallSuccess, RuntimeCallError> {
    let mut call = runtime_call::run(runtime_call::Config {
        virtual_machine: runtime,
        function_to_call,
        parameter: iter::once(&parameter),
        storage_proof_size_behavior,
        storage_main_trie_changes: initial_storage_changes.into_main_trie_diff(),
        max_log_level: 0,
        calculate_trie_changes: true,
    })
    .map_err(|(err, _)| RuntimeCallError::RuntimeStartError(err))?;

    let mut database_accesses_duration = Duration::new(0, 0);

    loop {
        match call {
            runtime_call::RuntimeCall::Finished(Err(error)) => {
                return Err(RuntimeCallError::RuntimeExecutionError(error.detail));
            }
            runtime_call::RuntimeCall::Finished(Ok(runtime_call::Success {
                virtual_machine,
                storage_changes,
                state_trie_version,
                ..
            })) => {
                let output = virtual_machine.value().as_ref().to_owned();
                return Ok(RuntimeCallSuccess {
                    output,
                    runtime: virtual_machine.into_prototype(),
                    storage_changes,
                    state_trie_version,
                    database_accesses_duration,
                });
            }

            runtime_call::RuntimeCall::StorageGet(req) => {
                let when_database_access_started = Instant::now();
                let parent_paths = req.child_trie().map(|child_trie| {
                    trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                        .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                        .map(u8::from)
                        .collect::<Vec<_>>()
                });
                let key = trie::bytes_to_nibbles(req.key().as_ref().iter().copied())
                    .map(u8::from)
                    .collect::<Vec<_>>();
                let storage_block_hash = *storage_block_hash;
                let value = database
                    .with_database(move |db| {
                        db.block_storage_get(
                            &storage_block_hash,
                            parent_paths.into_iter().map(|p| p.into_iter()),
                            key.iter().copied(),
                        )
                    })
                    .await;
                let value = match value {
                    Ok(Some((ref val, vers))) => Some((
                        iter::once(&val[..]),
                        runtime_call::TrieEntryVersion::try_from(vers)
                            .map_err(|_| RuntimeCallError::DatabaseInvalidStateTrieVersion)?,
                    )),
                    Ok(None) => None,
                    Err(error) => return Err(RuntimeCallError::DatabaseParentAccess(error)),
                };

                database_accesses_duration += when_database_access_started.elapsed();
                call = req.inject_value(value);
            }
            runtime_call::RuntimeCall::ClosestDescendantMerkleValue(req) => {
                let when_database_access_started = Instant::now();

                let parent_paths = req.child_trie().map(|child_trie| {
                    trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                        .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                        .map(u8::from)
                        .collect::<Vec<_>>()
                });
                let key_nibbles = req.key().map(u8::from).collect::<Vec<_>>();

                let storage_block_hash = *storage_block_hash;
                let merkle_value = database
                    .with_database(move |db| {
                        db.block_storage_closest_descendant_merkle_value(
                            &storage_block_hash,
                            parent_paths.into_iter().map(|p| p.into_iter()),
                            key_nibbles.iter().copied(),
                        )
                    })
                    .await;
                let merkle_value = match merkle_value {
                    Ok(mv) => mv,
                    Err(error) => return Err(RuntimeCallError::DatabaseParentAccess(error)),
                };

                database_accesses_duration += when_database_access_started.elapsed();
                call = req.inject_merkle_value(merkle_value.as_ref().map(|v| &v[..]));
            }
            runtime_call::RuntimeCall::NextKey(req) => {
                let when_database_access_started = Instant::now();

                let parent_paths = req.child_trie().map(|child_trie| {
                    trie::bytes_to_nibbles(b":child_storage:default:".iter().copied())
                        .chain(trie::bytes_to_nibbles(child_trie.as_ref().iter().copied()))
                        .map(u8::from)
                        .collect::<Vec<_>>()
                });
                let key_nibbles = req
                    .key()
                    .map(u8::from)
                    .chain(if req.or_equal() { None } else { Some(0u8) })
                    .collect::<Vec<_>>();
                let prefix_nibbles = req.prefix().map(u8::from).collect::<Vec<_>>();

                let branch_nodes = req.branch_nodes();
                let storage_block_hash = *storage_block_hash;
                let next_key = database
                    .with_database(move |db| {
                        db.block_storage_next_key(
                            &storage_block_hash,
                            parent_paths.into_iter().map(|p| p.into_iter()),
                            key_nibbles.iter().copied(),
                            prefix_nibbles.iter().copied(),
                            branch_nodes,
                        )
                    })
                    .await;
                let next_key = match next_key {
                    Ok(k) => k,
                    Err(error) => return Err(RuntimeCallError::DatabaseParentAccess(error)),
                };

                database_accesses_duration += when_database_access_started.elapsed();
                call = req.inject_key(
                    next_key.map(|k| k.into_iter().map(|b| trie::Nibble::try_from(b).unwrap())),
                );
            }
            runtime_call::RuntimeCall::OffchainStorageSet(req) => {
                // Ignore offchain storage writes at the moment.
                call = req.resume();
            }
            runtime_call::RuntimeCall::LogEmit(req) => {
                // Logs are ignored.
                call = req.resume();
            }
            runtime_call::RuntimeCall::SignatureVerification(sig) => {
                call = sig.verify_and_resume();
            }
            runtime_call::RuntimeCall::Offchain(_) => {
                // Offchain storage calls are forbidden.
                return Err(RuntimeCallError::ForbiddenHostFunction);
            }
        }
    }
}

/// Returned by [`runtime_call()`] in case of success.
#[derive(Debug)]
pub struct RuntimeCallSuccess {
    /// Output of the runtime call.
    pub output: Vec<u8>,

    /// Runtime that was provided as input to [`runtime_call()`].
    pub runtime: host::HostVmPrototype,

    /// Changes to the storage performed during the execution.
    pub storage_changes: runtime_call::StorageChanges,

    /// Version of the trie entries of the storage changes.
    pub state_trie_version: runtime_call::TrieEntryVersion,

    /// Total time the database accesses combined took.
    pub database_accesses_duration: Duration,
}

/// Error returned by [`runtime_call()`].
#[derive(Debug, derive_more::Display, derive_more::Error, derive_more::From)]
pub enum RuntimeCallError {
    /// Error starting the runtime execution.
    #[display("{_0}")]
    RuntimeStartError(executor::host::StartErr),
    /// Error while executing the runtime.
    #[display("{_0}")]
    RuntimeExecutionError(runtime_call::ErrorDetail),
    /// Error while accessing the parent block in the database.
    #[display("{_0}")]
    DatabaseParentAccess(full_sqlite::StorageAccessError),
    /// State trie version stored in database is invalid.
    DatabaseInvalidStateTrieVersion,
    /// Runtime has tried to call a forbidden host function.
    ForbiddenHostFunction,
}

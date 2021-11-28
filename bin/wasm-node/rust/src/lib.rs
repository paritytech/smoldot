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

//! Contains a light client implementation usable from a browser environment.

#![recursion_limit = "512"]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(unused_crate_dependencies)]

use futures::{channel::mpsc, prelude::*};
use itertools::Itertools as _;
use smoldot::{
    chain, chain_spec, header,
    informant::{BytesDisplay, HashDisplay},
    libp2p::{connection, multiaddr, peer_id},
};
use std::{
    collections::{hash_map::Entry, HashMap},
    num::NonZeroU32,
    ops,
    pin::Pin,
    str,
    sync::Arc,
    time::Duration,
};

mod alloc;
pub mod ffi;

mod json_rpc_service;
mod lossy_channel;
mod network_service;
mod runtime_service;
mod sync_service;
mod transactions_service;
mod util;

/// See [`Client::add_chain`].
#[derive(Debug, Clone)]
pub struct AddChainConfig<'a, TChain, TRelays> {
    /// Opaque user data that the [`Client`] will hold for this chain.
    pub user_data: TChain,

    /// JSON text containing the specification of the chain (the so-called "chain spec").
    pub specification: &'a str,

    /// If [`AddChainConfig`] defines a parachain, contains the list of relay chains to choose
    /// from. Ignored if not a parachain.
    ///
    /// This field is necessary because multiple different chain can have the same identity. If
    /// the client tried to find the corresponding relay chain in all the previously-spawned
    /// chains, it means that a call to [`Client::add_chain`] could influence the outcome of a
    /// subsequent call to [`Client::add_chain`].
    ///
    /// For example: if user A adds a chain named "kusama", then user B adds a different chain
    /// also named "kusama", then user B adds a parachain whose relay chain is "kusama", it would
    /// be wrong to connect to the "kusama" created by user A.
    pub potential_relay_chains: TRelays,

    /// Channel to use to send the JSON-RPC responses.
    ///
    /// If `None`, then no JSON-RPC service is started for this chain. This saves up a lot of
    /// resources, but will cause all JSON-RPC requests targetting this chain to fail.
    pub json_rpc_responses: Option<mpsc::Sender<String>>,
}

/// Access to a platform's capabilities.
pub trait Platform: Send + 'static {
    type Delay: Future<Output = ()> + Unpin + Send + 'static;
    type Instant: Clone
        + ops::Add<Duration, Output = Self::Instant>
        + ops::Sub<Self::Instant, Output = Duration>
        + PartialOrd
        + Ord
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static;
    type Connection: Send + Sync + 'static;
    type ConnectFuture: Future<Output = Result<Self::Connection, ConnectError>>
        + Unpin
        + Send
        + 'static;
    type ConnectionDataFuture: Future<Output = ()> + Unpin + Send + 'static;

    /// Returns the time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time)
    /// (i.e. 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    fn now_from_unix_epoch() -> Duration;

    /// Returns an object that represents "now".
    fn now() -> Self::Instant;

    /// Creates a future that becomes ready after at least the given duration has elapsed.
    fn sleep(duration: Duration) -> Self::Delay;

    /// Creates a future that becomes ready after the given instant has been reached.
    fn sleep_until(when: Self::Instant) -> Self::Delay;

    /// Starts a connection attempt to the given multiaddress.
    ///
    /// The multiaddress is passed as a string. If the string can't be parsed, an error should be
    /// returned where [`ConnectError::is_bad_addr`] is `true`.
    fn connect(url: &str) -> Self::ConnectFuture;

    /// Returns a future that becomes ready when either the read buffer of the given connection
    /// contains data, or the remote has closed their sending side.
    ///
    /// The future is immediately ready if data is already available or the remote has already
    /// closed their sending side.
    ///
    /// This function can be called multiple times with the same connection, in which case all
    /// the futures must be notified. The user of this function, however, is encouraged to
    /// maintain only one active future.
    ///
    /// If the future is polled after the connection object has been dropped, the behaviour is
    /// not specified. The polling might panic, or return `Ready`, or return `Pending`.
    fn wait_more_data(connection: &mut Self::Connection) -> Self::ConnectionDataFuture;

    /// Gives access to the content of the read buffer of the given connection.
    ///
    /// Returns `None` if the remote has closed their sending side.
    fn read_buffer(connection: &mut Self::Connection) -> Option<&[u8]>;

    /// Discards the first `bytes` bytes of the read buffer of this connection. This makes it
    /// possible for the remote to send more data.
    ///
    /// # Panic
    ///
    /// Panics if there aren't enough bytes to discard in the buffer.
    ///
    fn advance_read_cursor(connection: &mut Self::Connection, bytes: usize);

    /// Queues the given bytes to be sent out on the given connection.
    // TODO: back-pressure
    fn send(connection: &mut Self::Connection, data: &[u8]);
}

/// Error potentially returned by [`Platform::connect`].
pub struct ConnectError {
    /// Human-readable error message.
    pub message: String,

    /// `true` if the error is caused by the address to connect to being forbidden or unsupported.
    pub is_bad_addr: bool,
}

/// Chain registered in a [`Client`].
//
// Implementation detail: corresponds to indices within [`Client::public_api_chains`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId(usize);

impl From<u32> for ChainId {
    fn from(n: u32) -> ChainId {
        // Assume that we are always on a 32bits or more platform.
        ChainId(usize::try_from(n).unwrap())
    }
}

impl From<ChainId> for u32 {
    fn from(n: ChainId) -> u32 {
        // Assume that no `ChainId` above `u32::max_value()` is ever generated.
        u32::try_from(n.0).unwrap()
    }
}

pub struct Client<TChain, TPlat: Platform> {
    /// Tasks can be spawned by sending it on this channel. The first tuple element is the name
    /// of the task used for debugging purposes.
    new_task_tx: mpsc::UnboundedSender<(String, future::BoxFuture<'static, ()>)>,

    /// List of chains currently running according to the public API. Indices in this container
    /// are reported through the public API. The values are either an error if the chain has failed
    /// to initialize, or key found in [`Client::chains_by_key`].
    public_api_chains: slab::Slab<PublicApiChain<TChain, TPlat>>,

    /// De-duplicated list of chains that are *actually* running.
    ///
    /// For each key, contains the services running for this chain plus the number of public API
    /// chains that correspond to it.
    ///
    /// The [`ChainServices`] is within a `MaybeDone`. The variant will be `MaybeDone::Future` if
    /// initialization is still in progress.
    chains_by_key: HashMap<ChainKey, RunningChain<TPlat>>,
}

enum PublicApiChain<TChain, TPlat: Platform> {
    /// Chain initialization was successful.
    Ok {
        /// Opaque user data passed to [`Client::add_chain`].
        user_data: TChain,

        /// Index of the underlying chain found in [`Client::chains_by_key`].
        key: ChainKey,

        /// Identifier of the chain found in its chain spec. Equal to the return value of
        /// [`chain_spec::ChainSpec::id`]. Used in order to match parachains with relay chains.
        chain_spec_chain_id: String,

        /// JSON-RPC service that answers incoming requests. `None` iff
        /// [`AddChainConfig::json_rpc_responses`] was `None` when adding the chain.
        ///
        /// The JSON-RPC service is wrapped within a `MaybeDone` because its initialization is
        /// done asynchronously. Note that the JSON-RPC service will only finish initializing
        /// after the [`RunningChain::services`] of its chain has finished initializing.
        json_rpc_service: Option<
            future::MaybeDone<
                future::Shared<future::RemoteHandle<Arc<json_rpc_service::JsonRpcService<TPlat>>>>,
            >,
        >,
    },

    /// Chain initialization has failed.
    Erroneous {
        /// Opaque user data passed to [`Client::add_chain`].
        user_data: TChain,
        /// Human-readable error message giving the reason for the failure.
        error: String,
    },
}

/// Identifies a chain, so that multiple identical chains are de-duplicated.
///
/// This struct serves as the key in a `HashMap<ChainKey, ChainServices>`. It must contain all the
/// values that are important to the logic of the fields that are contained in [`ChainServices`].
/// Failing to include a field in this struct could lead to two different chains using the same
/// [`ChainServices`], which has security consequences.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ChainKey {
    /// Hash of the genesis block of the chain.
    genesis_block_hash: [u8; 32],

    // TODO: what about light checkpoints?
    // TODO: must also contain forkBlocks, and badBlocks fields
    /// If the chain is a parachain, contains the relay chain and the "para ID" on this relay
    /// chain.
    relay_chain: Option<(Box<ChainKey>, u32)>,

    /// Network protocol id, found in the chain specification.
    protocol_id: String,
}

struct RunningChain<TPlat: Platform> {
    /// Services that are dedicated to this chain. Wrapped within a `MaybeDone` because the
    /// initialization is performed asynchronously.
    services: future::MaybeDone<future::Shared<future::RemoteHandle<ChainServices<TPlat>>>>,

    /// Name of this chain in the logs. This is not necessarily the same as the identifier of the
    /// chain in its chain specification.
    log_name: String,

    /// Number of elements in [`Client::public_api_chains`] that reference this chain. If this
    /// number reaches `0`, the [`RunningChain`] should be destroyed.
    num_references: NonZeroU32,
}

struct ChainServices<TPlat: Platform> {
    network_service: Arc<network_service::NetworkService<TPlat>>,
    network_identity: peer_id::PeerId,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,
}

impl<TPlat: Platform> Clone for ChainServices<TPlat> {
    fn clone(&self) -> Self {
        ChainServices {
            network_service: self.network_service.clone(),
            network_identity: self.network_identity.clone(),
            sync_service: self.sync_service.clone(),
            runtime_service: self.runtime_service.clone(),
            transactions_service: self.transactions_service.clone(),
        }
    }
}

impl<TChain, TPlat: Platform> Client<TChain, TPlat> {
    /// Initializes the smoldot Wasm client.
    ///
    /// In order for the client to function, it needs to be able to spawn tasks in the background
    /// that will run indefinitely. To do so, the `tasks_spawner` channel must be provided and that
    /// the clients can send tasks to run to. The first tuple element is the name of the task used
    /// for debugging purposes.
    pub fn new(
        tasks_spawner: mpsc::UnboundedSender<(String, future::BoxFuture<'static, ()>)>,
    ) -> Self {
        // Spawn a constantly-running task that periodically prints the total memory usage of
        // the node.
        //
        // Note that, as a hack, this is done for each `Client`, meaning that it will be printed
        // multiple times of multiple `Client`s are created. In practice only one `Client` is ever
        // created.
        // TODO: ^ solve this hack?
        tasks_spawner
            .unbounded_send((
                "memory-printer".to_owned(),
                Box::pin(async move {
                    loop {
                        TPlat::sleep(Duration::from_secs(60)).await;

                        // For the unwrap below to fail, the quantity of allocated would have to
                        // not fit in a `u64`, which as of 2021 is basically impossible.
                        let mem = u64::try_from(alloc::total_alloc_bytes()).unwrap();
                        log::info!(target: "smoldot", "Node memory usage: {}", BytesDisplay(mem));
                    }
                }),
            ))
            .unwrap();

        let expected_chains = 8;
        Client {
            new_task_tx: tasks_spawner,
            public_api_chains: slab::Slab::with_capacity(expected_chains),
            chains_by_key: HashMap::with_capacity(expected_chains),
        }
    }

    /// Adds a new chain to the list of chains smoldot tries to synchronize.
    pub fn add_chain(
        &mut self,
        config: AddChainConfig<'_, TChain, impl Iterator<Item = ChainId>>,
    ) -> ChainId {
        // Fail any new chain initialization if we're running low on memory space, which can
        // realistically happen as Wasm is a 32 bits platform. This avoids potentially running into
        // OOM errors. The threshold is completely empirical and should probably be updated
        // regularly to account for changes in the implementation.
        if alloc::total_alloc_bytes() >= usize::max_value() - 400 * 1024 * 1024 {
            return ChainId(
                self.public_api_chains
                    .insert(PublicApiChain::Erroneous {
                        user_data: config.user_data,
                        error: format!(
                        "Wasm node is running low on memory and will prevent any new chain from being added"
                    )}),
            );
        }

        // Decode the chain specification.
        let chain_spec = match chain_spec::ChainSpec::from_json_bytes(&config.specification) {
            Ok(cs) => cs,
            Err(err) => {
                return ChainId(self.public_api_chains.insert(PublicApiChain::Erroneous {
                    user_data: config.user_data,
                    error: format!("Failed to decode chain specification: {}", err),
                }));
            }
        };

        // Load the information about the chain from the chain spec. If a light sync state (also
        // known as a checkpoint) is present in the chain spec, it is possible to start syncing at
        // the finalized block it describes.
        let chain_information = {
            match (
                chain_spec
                    .as_chain_information() // TODO: very expensive, don't always call?
                    .map(chain::chain_information::ValidChainInformation::try_from),
                chain_spec.light_sync_state().map(|s| {
                    chain::chain_information::ValidChainInformation::try_from(
                        s.as_chain_information(),
                    )
                }),
            ) {
                (Err(chain_spec::FromGenesisStorageError::UnknownStorageItems), None) => {
                    // TODO: we can in theory support chain specs that have neither a checkpoint nor the genesis storage, but it's complicated
                    return ChainId(self.public_api_chains.insert(PublicApiChain::Erroneous {
                        user_data: config.user_data,
                        error: format!(
                            "Either a checkpoint or the genesis storage must be provided"
                        ),
                    }));
                }

                (Err(err), _) => {
                    return ChainId(self.public_api_chains.insert(PublicApiChain::Erroneous {
                        user_data: config.user_data,
                        error: format!("Failed to build genesis chain information: {}", err),
                    }));
                }

                (Ok(Err(err)), _) => {
                    return ChainId(self.public_api_chains.insert(PublicApiChain::Erroneous {
                        user_data: config.user_data,
                        error: format!("Invalid genesis chain information: {}", err),
                    }));
                }

                (_, Some(Err(err))) => {
                    return ChainId(self.public_api_chains.insert(PublicApiChain::Erroneous {
                        user_data: config.user_data,
                        error: format!("Invalid checkpoint in chain specification: {}", err),
                    }));
                }

                (_, Some(Ok(ci))) => ci,

                (Ok(Ok(ci)), None) => ci,
            }
        };

        // Even with a checkpoint, knowing the genesis block header is necessary for various
        // reasons.
        let genesis_block_header = smoldot::calculate_genesis_block_header(&chain_spec);

        // If the chain specification specifies a parachain, find the corresponding relay chain
        // in the list of potential relay chains passed by the user.
        // If no relay chain can be found, the chain creation fails. Exactly one matching relay
        // chain must be found. If there are multiple ones, the creation fails as well.
        let relay_chain_id = if let Some((relay_chain_id, _para_id)) = chain_spec.relay_chain() {
            let chain = config
                .potential_relay_chains
                .filter(|c| {
                    self.public_api_chains
                        .get(c.0)
                        .map_or(false, |chain| match chain {
                            PublicApiChain::Ok {
                                chain_spec_chain_id,
                                ..
                            } => chain_spec_chain_id == relay_chain_id,
                            _ => false,
                        })
                })
                .exactly_one();

            match chain {
                Ok(c) => Some(c),
                Err(mut iter) => {
                    // `iter` here is identical to the iterator above before `exactly_one` is
                    // called. This lets us know what failed.
                    let error = if iter.next().is_none() {
                        "Couldn't find any valid relay chain".to_string()
                    } else {
                        debug_assert!(iter.next().is_some());
                        "Multiple valid relay chains found".to_string()
                    };

                    return ChainId(self.public_api_chains.insert(PublicApiChain::Erroneous {
                        user_data: config.user_data,
                        error,
                    }));
                }
            }
        } else {
            None
        };

        // All the checks are performed above. Adding the chain can't fail anymore at this point.

        // Grab a couple of fields from the chain specification for later, as the chain
        // specification is consumed below.
        let chain_spec_chain_id = chain_spec.id().to_owned();
        let genesis_block_hash = genesis_block_header.hash();
        let genesis_block_state_root = genesis_block_header.state_root;

        // The key generated here uniquely identifies this chain within smoldot. Mutiple chains
        // having the same key will use the same services.
        //
        // This struct is extremely important from a security perspective. We want multiple
        // identical chains to be de-duplicated, but security issues would arise if two chains
        // were considered identical while they're in reality not identical.
        let new_chain_key = ChainKey {
            genesis_block_hash,
            relay_chain: relay_chain_id.map(|ck| {
                (
                    Box::new(match self.public_api_chains.get(ck.0).unwrap() {
                        PublicApiChain::Ok { key, .. } => key.clone(),
                        _ => unreachable!(),
                    }),
                    chain_spec.relay_chain().unwrap().1,
                )
            }),
            protocol_id: chain_spec.protocol_id().to_owned(),
        };

        // If the chain we are adding is a parachain, grab the services of the relay chain.
        //
        // Since the initialization process of a chain is done asynchronously, it is possible that
        // the relay chain is still initializing. For this reason, we don't don't simply grab
        // the relay chain services, but instead a `future::MaybeDone` of a future that yelds the
        // relay chain services.
        //
        // This could in principle be done later on, but doing so raises borrow checker errors.
        let relay_chain_ready_future: Option<(future::MaybeDone<future::Shared<_>>, String)> =
            relay_chain_id.map(|relay_chain| {
                let relay_chain = &self
                    .chains_by_key
                    .get(match self.public_api_chains.get(relay_chain.0).unwrap() {
                        PublicApiChain::Ok { key, .. } => key,
                        _ => unreachable!(),
                    })
                    .unwrap();

                let future = match &relay_chain.services {
                    future::MaybeDone::Done(d) => future::MaybeDone::Done(d.clone()),
                    future::MaybeDone::Future(d) => future::MaybeDone::Future(d.clone()),
                    future::MaybeDone::Gone => unreachable!(),
                };

                (future, relay_chain.log_name.clone())
            });

        // Determinate the name under which the chain will be identified in the logs.
        // Because the chain spec is untrusted input, we must transform the `id` to remove all
        // weird characters.
        //
        // By default, this log name will be equal to chain's `id`. Since it is possible for
        // multiple different chains to have the same `id`, we need to look into the list of
        // existing chains and make sure that there's no conflict, in which case the log name
        // will have the suffix `-1`, or `-2`, or `-3`, and so on.
        //
        // This value is ignored if we enter the `Entry::Occupied` block below. Because the
        // calculation requires accessing the list of existing chains, this block can't be put in
        // the `Entry::Vacant` block below, even though it would make sense for it to be there.
        let log_name = {
            let base = chain_spec
                .id()
                .chars()
                .filter(|c| c.is_ascii_graphic())
                .collect::<String>();
            let mut suffix = None;

            loop {
                let attempt = if let Some(suffix) = suffix {
                    format!("{}-{}", base, suffix)
                } else {
                    base.clone()
                };

                if !self.chains_by_key.values().any(|c| *c.log_name == attempt) {
                    break attempt;
                }

                match &mut suffix {
                    Some(v) => *v += 1,
                    v @ None => *v = Some(1),
                }
            }
        };

        // Start the services of the chain to add, or grab the services if they already exist.
        let (services_init, log_name) = match self.chains_by_key.entry(new_chain_key.clone()) {
            Entry::Occupied(mut entry) => {
                // The chain to add always has a corresponding chain running. Simply grab the
                // existing services and existing log name.
                // The `log_name` created above is discarded in favour of the existing log name.
                // TODO: must add bootnodes to the existing network service, otherwise the existing chain with the same key might only be using malicious bootnodes
                entry.get_mut().num_references =
                    NonZeroU32::new(entry.get_mut().num_references.get() + 1).unwrap();
                let entry = entry.into_mut();
                (&mut entry.services, &entry.log_name)
            }
            Entry::Vacant(entry) => {
                // Key used by the networking. Represents the identity of the node on the
                // peer-to-peer network.
                let network_noise_key = connection::NoiseKey::new(&rand::random());

                // Spawn a background task that initializes the services of the new chain and
                // yields a `ChainServices`.
                let running_chain_init_future: future::RemoteHandle<ChainServices<TPlat>> = {
                    let new_tasks_tx = self.new_task_tx.clone();
                    let chain_spec = chain_spec.clone(); // TODO: quite expensive
                    let log_name = log_name.clone();

                    let future = async move {
                        // Wait until the relay chain has finished initializing, if necessary.
                        let relay_chain =
                            if let Some((mut relay_chain_ready_future, relay_chain_log_name)) =
                                relay_chain_ready_future
                            {
                                (&mut relay_chain_ready_future).await;
                                let running_relay_chain = Pin::new(&mut relay_chain_ready_future)
                                    .take_output()
                                    .unwrap();
                                Some((running_relay_chain, relay_chain_log_name))
                            } else {
                                None
                            };

                        // TODO: avoid cloning here
                        let chain_name = chain_spec.name().to_owned();
                        let relay_chain_para_id = chain_spec.relay_chain().map(|(_, id)| id);
                        let starting_block_number =
                            chain_information.as_ref().finalized_block_header.number;
                        let starting_block_hash =
                            chain_information.as_ref().finalized_block_header.hash();

                        let running_chain = start_services(
                            log_name.clone(),
                            new_tasks_tx,
                            chain_information,
                            genesis_block_header.scale_encoding_vec(),
                            chain_spec,
                            relay_chain.as_ref().map(|(r, _)| r),
                            network_noise_key,
                        )
                        .await;

                        // Note that the chain name is printed through the `Debug` trait (rather
                        // than `Display`) because it is an untrusted user input.
                        //
                        // The state root hash is printed in order to make it easy to put it
                        // in the chain specification.
                        if let Some((_, relay_chain_log_name)) = relay_chain.as_ref() {
                            log::info!(
                                target: "smoldot",
                                "Parachain initialization complete for {}. Name: {:?}. Genesis \
                                hash: {}. State root hash: 0x{}. Network identity: {}. Relay \
                                chain: {} (id: {})",
                                log_name,
                                chain_name,
                                HashDisplay(&genesis_block_hash),
                                hex::encode(&genesis_block_state_root),
                                running_chain.network_identity,
                                relay_chain_log_name,
                                relay_chain_para_id.unwrap(),
                            );
                        } else {
                            log::info!(
                                target: "smoldot",
                                "Chain initialization complete for {}. Name: {:?}. Genesis \
                                hash: {}. State root hash: 0x{}. Network identity: {}. Starting \
                                at block #{} ({})",
                                log_name,
                                chain_name,
                                HashDisplay(&genesis_block_hash),
                                hex::encode(&genesis_block_state_root),
                                running_chain.network_identity,
                                starting_block_number,
                                HashDisplay(&starting_block_hash)
                            );
                        }

                        running_chain
                    };

                    let (background_future, output_future) = future.remote_handle();
                    self.new_task_tx
                        .unbounded_send((
                            "services-initialization".to_owned(),
                            background_future.boxed(),
                        ))
                        .unwrap();
                    output_future
                };

                let entry = entry.insert(RunningChain {
                    services: future::maybe_done(running_chain_init_future.shared()),
                    log_name,
                    num_references: NonZeroU32::new(1).unwrap(),
                });

                (&mut entry.services, &entry.log_name)
            }
        };

        // Apart from its services, each chain also has an entry in `public_api_chains`.
        let public_api_chains_entry = self.public_api_chains.vacant_entry();
        let new_chain_id = ChainId(public_api_chains_entry.key());

        // JSON-RPC service initialization. This is done every time `add_chain` is called, even
        // if a similar chain already existed.
        let json_rpc_service = if let Some(json_rpc_responses) = config.json_rpc_responses {
            // Clone `running_chain_init`.
            let mut running_chain_init = match services_init {
                future::MaybeDone::Done(d) => future::MaybeDone::Done(d.clone()),
                future::MaybeDone::Future(d) => future::MaybeDone::Future(d.clone()),
                future::MaybeDone::Gone => unreachable!(),
            };

            // Spawn a background task that initializes the JSON-RPC service.
            let json_rpc_service_init: future::Shared<
                future::RemoteHandle<Arc<json_rpc_service::JsonRpcService<TPlat>>>,
            > = {
                let new_task_tx = self.new_task_tx.clone();
                let log_name = log_name.clone();
                let init_future = async move {
                    // Wait for the chain to finish initializing before starting the JSON-RPC service.
                    (&mut running_chain_init).await;
                    let running_chain = Pin::new(&mut running_chain_init).take_output().unwrap();

                    Arc::new(json_rpc_service::JsonRpcService::new(
                        json_rpc_service::Config {
                            log_name, // TODO: add a way to differentiate multiple different json-rpc services under the same chain
                            tasks_executor: Box::new({
                                move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
                            }),
                            sync_service: running_chain.sync_service,
                            transactions_service: running_chain.transactions_service,
                            runtime_service: running_chain.runtime_service,
                            chain_spec: &chain_spec,
                            peer_id: &running_chain.network_identity.clone(),
                            genesis_block_hash,
                            genesis_block_state_root,
                            responses_sender: json_rpc_responses,
                            max_parallel_requests: NonZeroU32::new(24).unwrap(),
                            max_pending_requests: NonZeroU32::new(32).unwrap(),
                            max_subscriptions: 1024, // Note: the PolkadotJS UI is very heavy in terms of subscriptions.
                        },
                    ))
                };

                let (background_run, output_future) = init_future.remote_handle();
                self.new_task_tx
                    .unbounded_send(("json-rpc-service-init".to_owned(), background_run.boxed()))
                    .unwrap();
                output_future.shared()
            };

            Some(future::maybe_done(json_rpc_service_init))
        } else {
            None
        };

        // Success!
        public_api_chains_entry.insert(PublicApiChain::Ok {
            user_data: config.user_data,
            key: new_chain_key,
            chain_spec_chain_id,
            json_rpc_service,
        });
        new_chain_id
    }

    /// If [`Client::add_chain`] encountered an error when creating this chain, returns the error
    /// message corresponding to it.
    pub fn chain_is_erroneous(&self, id: ChainId) -> Option<&str> {
        if let Some(public_chain) = self.public_api_chains.get(id.0) {
            if let PublicApiChain::Erroneous { error, .. } = &public_chain {
                Some(error)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Removes the chain from smoldot. This instantaneously and silently cancels all on-going
    /// JSON-RPC requests and subscriptions.
    ///
    /// Be aware that the [`ChainId`] might be reused if [`Client::add_chain`] is called again
    /// later.
    ///
    /// While from the API perspective it will look like the chain no longer exists, calling this
    /// function will not actually immediately disconnect from the given chain if it is still used
    /// as the relay chain of a parachain.
    #[must_use]
    pub fn remove_chain(&mut self, id: ChainId) -> TChain {
        let removed_chain = self.public_api_chains.remove(id.0);

        let user_data = match removed_chain {
            PublicApiChain::Erroneous { user_data, .. } => user_data,
            PublicApiChain::Ok { key, user_data, .. } => {
                let running_chain = self.chains_by_key.get_mut(&key).unwrap();
                if running_chain.num_references.get() == 1 {
                    log::info!(target: "smoldot", "Shutting down chain {}", running_chain.log_name);
                    self.chains_by_key.remove(&key);
                } else {
                    running_chain.num_references =
                        NonZeroU32::new(running_chain.num_references.get() - 1).unwrap();
                }

                user_data
            }
        };

        self.public_api_chains.shrink_to_fit();

        user_data
    }

    /// Enqueues a JSON-RPC request towards the given chain.
    ///
    /// Since most JSON-RPC requests can only be answered asynchronously, the request is only
    /// queued and will be decoded and processed later.
    /// Requests that are not valid JSON-RPC will be silently ignored.
    ///
    /// # Panic
    ///
    /// Panics if the [`ChainId`] is invalid, or if [`AddChainConfig::json_rpc_responses`] was
    /// `None` when adding the chain.
    ///
    pub fn json_rpc_request(&mut self, json_rpc_request: impl Into<String>, chain_id: ChainId) {
        self.json_rpc_request_inner(json_rpc_request.into(), chain_id)
    }

    fn json_rpc_request_inner(&mut self, json_rpc_request: String, chain_id: ChainId) {
        let (json_rpc_service, log_target) = match self.public_api_chains.get(chain_id.0) {
            Some(PublicApiChain::Ok {
                json_rpc_service: Some(json_rpc_service),
                key,
                ..
            }) => {
                let log_name = &self.chains_by_key.get(key).unwrap().log_name;
                (json_rpc_service, format!("json-rpc-{}", log_name))
            }
            _ => panic!(),
        };

        log::log!(
            target: &log_target,
            log::Level::Debug,
            "JSON-RPC => {:?}{}",
            if json_rpc_request.len() > 100 {
                &json_rpc_request[..100]
            } else {
                &json_rpc_request[..]
            },
            if json_rpc_request.len() > 100 {
                "…"
            } else {
                ""
            }
        );

        let mut json_rpc_service = match json_rpc_service {
            future::MaybeDone::Done(d) => future::MaybeDone::Done(d.clone()),
            future::MaybeDone::Future(d) => future::MaybeDone::Future(d.clone()),
            future::MaybeDone::Gone => unreachable!(),
        };

        let future = async move {
            (&mut json_rpc_service).await;
            let json_rpc_service = Pin::new(&mut json_rpc_service).take_output().unwrap();
            if let Err(err) = json_rpc_service.queue_rpc_request(json_rpc_request).await {
                if let Some(err) = err.into_json_rpc_error() {
                    send_back(&err, &log_target, chain_id);
                }
            }
        };

        // TODO: properly spread resources usage instead of spawning new tasks all the time
        self.new_task_tx
            .unbounded_send(("json-rpc-request".to_owned(), future.boxed()))
            .unwrap();
    }
}

/// Starts all the services of the client.
///
/// Returns some of the services that have been started. If these service get shut down, all the
/// other services will later shut down as well.
async fn start_services<TPlat: Platform>(
    log_name: String,
    new_task_tx: mpsc::UnboundedSender<(
        String,
        Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    )>,
    chain_information: chain::chain_information::ValidChainInformation,
    genesis_block_scale_encoded_header: Vec<u8>,
    chain_spec: chain_spec::ChainSpec,
    relay_chain: Option<&ChainServices<TPlat>>,
    network_noise_key: connection::NoiseKey,
) -> ChainServices<TPlat> {
    // Since `network_noise_key` is moved out below, use it to build the network identity ahead
    // of the network service starting.
    let network_identity =
        peer_id::PublicKey::Ed25519(*network_noise_key.libp2p_public_ed25519_key()).into_peer_id();

    // The network service is responsible for connecting to the peer-to-peer network.
    let (network_service, mut network_event_receivers) =
        network_service::NetworkService::new(network_service::Config {
            tasks_executor: Box::new({
                let new_task_tx = new_task_tx.clone();
                move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
            }),
            num_events_receivers: 1, // Configures the length of `network_event_receivers`
            noise_key: network_noise_key,
            chains: vec![network_service::ConfigChain {
                log_name: log_name.clone(),
                bootstrap_nodes: {
                    let mut list = Vec::with_capacity(chain_spec.boot_nodes().len());
                    for node in chain_spec.boot_nodes() {
                        let mut address: multiaddr::Multiaddr = node.parse().unwrap(); // TODO: don't unwrap?
                        if let Some(multiaddr::Protocol::P2p(peer_id)) = address.pop() {
                            let peer_id = peer_id::PeerId::from_multihash(peer_id).unwrap(); // TODO: don't unwrap
                            list.push((peer_id, address));
                        } else {
                            panic!() // TODO:
                        }
                    }
                    list
                },
                has_grandpa_protocol: matches!(
                    chain_information.as_ref().finality,
                    chain::chain_information::ChainInformationFinalityRef::Grandpa { .. }
                ),
                genesis_block_hash: header::hash_from_scale_encoded_header(
                    &genesis_block_scale_encoded_header,
                ),
                finalized_block_height: chain_information.as_ref().finalized_block_header.number,
                best_block: (
                    chain_information.as_ref().finalized_block_header.number,
                    chain_information.as_ref().finalized_block_header.hash(),
                ),
                protocol_id: chain_spec.protocol_id().to_string(),
            }],
        })
        .await;

    let (sync_service, runtime_service) = if let Some(relay_chain) = relay_chain {
        // Chain is a parachain.

        // The sync service is leveraging the network service, downloads block headers,
        // and verifies them, to determine what are the best and finalized blocks of the
        // chain.
        let sync_service = Arc::new(
            sync_service::SyncService::new(sync_service::Config {
                log_name: log_name.clone(),
                chain_information: chain_information.clone(),
                tasks_executor: Box::new({
                    let new_task_tx = new_task_tx.clone();
                    move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
                }),
                network_service: (network_service.clone(), 0),
                network_events_receiver: network_event_receivers.pop().unwrap(),
                parachain: Some(sync_service::ConfigParachain {
                    parachain_id: chain_spec.relay_chain().unwrap().1,
                    relay_chain_sync: relay_chain.runtime_service.clone(),
                }),
            })
            .await,
        );

        // The runtime service follows the runtime of the best block of the chain,
        // and allows performing runtime calls.
        let runtime_service = runtime_service::RuntimeService::new(runtime_service::Config {
            log_name: log_name.clone(),
            tasks_executor: Box::new({
                let new_task_tx = new_task_tx.clone();
                move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
            }),
            sync_service: sync_service.clone(),
            chain_spec: &chain_spec,
            genesis_block_scale_encoded_header,
        })
        .await;

        (sync_service, runtime_service)
    } else {
        // Chain is a relay chain.

        // The sync service is leveraging the network service, downloads block headers,
        // and verifies them, to determine what are the best and finalized blocks of the
        // chain.
        let sync_service = Arc::new(
            sync_service::SyncService::new(sync_service::Config {
                log_name: log_name.clone(),
                chain_information: chain_information.clone(),
                tasks_executor: Box::new({
                    let new_task_tx = new_task_tx.clone();
                    move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
                }),
                network_service: (network_service.clone(), 0),
                network_events_receiver: network_event_receivers.pop().unwrap(),
                parachain: None,
            })
            .await,
        );

        // The runtime service follows the runtime of the best block of the chain,
        // and allows performing runtime calls.
        let runtime_service = runtime_service::RuntimeService::new(runtime_service::Config {
            log_name: log_name.clone(),
            tasks_executor: Box::new({
                let new_task_tx = new_task_tx.clone();
                move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
            }),
            sync_service: sync_service.clone(),
            chain_spec: &chain_spec,
            genesis_block_scale_encoded_header,
        })
        .await;

        (sync_service, runtime_service)
    };

    // The transactions service lets one send transactions to the peer-to-peer network and watch
    // them being included in the chain.
    // While this service is in principle not needed if it is known ahead of time that no
    // transaction will be submitted, the service itself is pretty low cost.
    let transactions_service = Arc::new(
        transactions_service::TransactionsService::new(transactions_service::Config {
            log_name,
            tasks_executor: Box::new(move |name, fut| {
                new_task_tx.unbounded_send((name, fut)).unwrap()
            }),
            sync_service: sync_service.clone(),
            runtime_service: runtime_service.clone(),
            network_service: (network_service.clone(), 0),
            max_pending_transactions: NonZeroU32::new(64).unwrap(),
            max_concurrent_downloads: NonZeroU32::new(3).unwrap(),
            max_concurrent_validations: NonZeroU32::new(2).unwrap(),
        })
        .await,
    );

    ChainServices {
        network_service,
        network_identity,
        runtime_service,
        sync_service,
        transactions_service,
    }
}

/// Sends back a response or a notification to the JSON-RPC client.
///
/// > **Note**: This method wraps around [`ffi::emit_json_rpc_response`] and exists primarily
/// >           in order to print a log message.
fn send_back(message: &str, log_target: &str, chain_id: ChainId) {
    log::debug!(
        target: &log_target,
        "JSON-RPC <= {}{}",
        if message.len() > 100 {
            &message[..100]
        } else {
            &message[..]
        },
        if message.len() > 100 { "…" } else { "" }
    );

    ffi::emit_json_rpc_response(message, chain_id);
}

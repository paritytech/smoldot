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

//! Smoldot light client library.
//!
//! This library provides an easy way to create a light client.
//!
//! This light client is opinionated towards certain aspects: what it downloads, how much memory
//! and CPU it is willing to consume, etc.
//!
//! # Usage
//!
//! ## Initialization
//!
//! In order to use the light client, call [`Client::new`], passing a [`ClientConfig`]. See the
//! documentation of [`ClientConfig`] for information about what to provide.
//!
//! The [`Client`] contains two generic parameters:
//!
//! - An implementation of the [`platform::Platform`] trait. This is how the client will
//! communicate with the outside, such as getting the current time.
//! - An opaque user data. If you do not use this, you can simply use `()`.
//!
//! ## Adding a chain
//!
//! After the client has been initialized, use [`Client::add_chain`] to ask the client to connect
//! to said chain. See the documentation of [`AddChainConfig`] for information about what to
//! provide.
//!
//! [`Client::add_chain`] returns a [`ChainId`], which identifies the chain within the [`Client`].
//! A [`Client`] can be thought of as a collection of chain connections, each identified by their
//! [`ChainId`], akin to a `HashMap<ChainId, ...>`.
//!
//! A chain can be removed at any time using [`Client::remove_chain`]. This will cause the client
//! to stop all connections and clean up its internal services. The [`ChainId`] is instantly
//! considered as invalid as soon as the method is called.
//!
//! ## JSON-RPC requests and responses
//!
//! Once a chain has been added, one can send JSON-RPC requests using [`Client::json_rpc_request`].
//!
//! The request parameter of this function must be a JSON-RPC request in its text form. For
//! example: `{"id":53,"jsonrpc":"2.0","method":"system_name","params":[]}`.
//!
//! Calling [`Client::json_rpc_request`] queues the request in the internals of the client. Later,
//! the client will process it.
//!
//! Responses are sent back by the client using the [`AddChainConfig::json_rpc_responses`] that
//! was provided when creating the chain.
//!
// TODO: talk about the fact that a randomness environment is assumed?

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![recursion_limit = "512"]
#![deny(rustdoc::broken_intra_doc_links)]
// TODO: the `unused_crate_dependencies` lint is disabled because of dev-dependencies, see <https://github.com/rust-lang/rust/issues/95513>
// #![deny(unused_crate_dependencies)]

extern crate alloc;

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    format,
    string::{String, ToString as _},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{cmp, num::NonZeroU32, pin::Pin};
use futures::{channel::mpsc, prelude::*};
use hashbrown::{hash_map::Entry, HashMap};
use itertools::Itertools as _;
use smoldot::{
    chain, chain_spec,
    database::finalized_serialize,
    header,
    informant::HashDisplay,
    libp2p::{connection, multiaddr, peer_id},
};

mod json_rpc_service;
mod network_service;
mod runtime_service;
mod sync_service;
mod transactions_service;
mod util;

pub mod platform;

pub use json_rpc_service::HandleRpcError;
pub use peer_id::PeerId;

/// Configuration for a client.
///
/// See [`Client::new`].
pub struct ClientConfig {
    /// In order for the client to function, it needs to be able to spawn tasks in the background
    /// that will run indefinitely. To do so, it will call this function with the task to spawn.
    /// The first parameter is the name of the task, which can be useful for debugging purposes.
    pub tasks_spawner: Box<dyn Fn(String, future::BoxFuture<'static, ()>) + Send + Sync>,

    /// Value returned when a JSON-RPC client requests the name of the client. Reasonable value
    /// is `env!("CARGO_PKG_NAME")`.
    pub system_name: String,

    /// Value returned when a JSON-RPC client requests the version of the client. Reasonable value
    /// is `env!("CARGO_PKG_VERSION")`.
    pub system_version: String,
}

/// See [`Client::add_chain`].
#[derive(Debug, Clone)]
pub struct AddChainConfig<'a, TChain, TRelays> {
    /// Opaque user data that the [`Client`] will hold for this chain.
    pub user_data: TChain,

    /// JSON text containing the specification of the chain (the so-called "chain spec").
    pub specification: &'a str,

    /// Opaque data containing the database content that was retrieved by calling
    /// the `chainHead_unstable_finalizedDatabase` JSON-RPC function in the past.
    ///
    /// Pass an empty string if no database content exists or is known.
    ///
    /// No error is generated if this data is invalid and/or can't be decoded. The implementation
    /// reserves the right to break the format of this data at any point.
    pub database_content: &'a str,

    /// If [`AddChainConfig`] defines a parachain, contains the list of relay chains to choose
    /// from. Ignored if not a parachain.
    ///
    /// This field is necessary because multiple different chain can have the same identity. If
    /// the client tried to find the corresponding relay chain in all the previously-spawned
    /// chains, it means that a call to [`Client::add_chain`] could influence the outcome of a
    /// subsequent call to [`Client::add_chain`].
    ///
    /// For example: if user A adds a chain named "Kusama", then user B adds a different chain
    /// also named "Kusama", then user B adds a parachain whose relay chain is "Kusama", it would
    /// be wrong to connect to the "Kusama" created by user A.
    pub potential_relay_chains: TRelays,

    /// Channel to use to send the JSON-RPC responses.
    ///
    /// If `None`, then no JSON-RPC service is started for this chain. This saves up a lot of
    /// resources, but will cause all JSON-RPC requests targeting this chain to fail.
    // TODO: don't expose channels from the `futures` library in the public API
    pub json_rpc_responses: Option<mpsc::Sender<String>>,
}

/// Chain registered in a [`Client`].
//
// Implementation detail: corresponds to indices within [`Client::public_api_chains`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId(usize);

/// Holds a list of chains, connections, and JSON-RPC services.
pub struct Client<TPlat: platform::Platform, TChain = ()> {
    /// Tasks can be spawned by calling this function. The first parameter is the name of the task
    /// used for debugging purposes.
    spawn_new_task: Arc<dyn Fn(String, future::BoxFuture<'static, ()>) + Send + Sync>,

    /// List of chains currently running according to the public API. Indices in this container
    /// are reported through the public API. The values are either an error if the chain has failed
    /// to initialize, or key found in [`Client::chains_by_key`].
    public_api_chains: slab::Slab<PublicApiChain<TChain>>,

    /// De-duplicated list of chains that are *actually* running.
    ///
    /// For each key, contains the services running for this chain plus the number of public API
    /// chains that correspond to it.
    ///
    /// The [`ChainServices`] is within a `MaybeDone`. The variant will be `MaybeDone::Future` if
    /// initialization is still in progress.
    // TODO: use SipHasher
    chains_by_key: HashMap<ChainKey, RunningChain<TPlat>, fnv::FnvBuildHasher>,

    /// Value to return when the `system_name` RPC is called. Should be set to the name of the
    /// final executable.
    system_name: String,

    /// Value to return when the `system_version` RPC is called. Should be set to the version of
    /// the final executable.
    system_version: String,
}

struct PublicApiChain<TChain> {
    /// Opaque user data passed to [`Client::add_chain`].
    user_data: TChain,

    /// Index of the underlying chain found in [`Client::chains_by_key`].
    key: ChainKey,

    /// Identifier of the chain found in its chain spec. Equal to the return value of
    /// [`chain_spec::ChainSpec::id`]. Used in order to match parachains with relay chains.
    chain_spec_chain_id: String,

    /// Handle that sends requests to the JSON-RPC service that runs in the background.
    /// Destroying this handle also shuts down the service. `None` iff
    /// [`AddChainConfig::json_rpc_responses`] was `None` when adding the chain.
    json_rpc_sender: Option<json_rpc_service::Sender>,
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

struct RunningChain<TPlat: platform::Platform> {
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

struct ChainServices<TPlat: platform::Platform> {
    network_service: Arc<network_service::NetworkService<TPlat>>,
    network_identity: peer_id::PeerId,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,
    // TODO: can be grabbed from the sync service instead
    block_number_bytes: usize,
}

impl<TPlat: platform::Platform> Clone for ChainServices<TPlat> {
    fn clone(&self) -> Self {
        ChainServices {
            network_service: self.network_service.clone(),
            network_identity: self.network_identity.clone(),
            sync_service: self.sync_service.clone(),
            runtime_service: self.runtime_service.clone(),
            transactions_service: self.transactions_service.clone(),
            block_number_bytes: self.block_number_bytes,
        }
    }
}

impl<TPlat: platform::Platform, TChain> Client<TPlat, TChain> {
    /// Initializes the smoldot client.
    pub fn new(config: ClientConfig) -> Self {
        let expected_chains = 8;
        Client {
            spawn_new_task: config.tasks_spawner.into(),
            public_api_chains: slab::Slab::with_capacity(expected_chains),
            chains_by_key: HashMap::with_capacity_and_hasher(expected_chains, Default::default()),
            system_name: config.system_name,
            system_version: config.system_version,
        }
    }

    /// Adds a new chain to the list of chains smoldot tries to synchronize.
    // TODO: don't return strings as errors, but something higher level
    pub fn add_chain(
        &mut self,
        config: AddChainConfig<'_, TChain, impl Iterator<Item = ChainId>>,
    ) -> Result<ChainId, String> {
        // Decode the chain specification.
        let chain_spec = match chain_spec::ChainSpec::from_json_bytes(&config.specification) {
            Ok(cs) => cs,
            Err(err) => {
                return Err(format!("Failed to decode chain specification: {}", err));
            }
        };

        // Load the information about the chain from the chain spec. If a light sync state (also
        // known as a checkpoint) is present in the chain spec, it is possible to start syncing at
        // the finalized block it describes.
        // TODO: clean up that block
        let (chain_information, genesis_block_header, checkpoint_nodes) = {
            match (
                chain_spec
                    .as_chain_information()
                    .map(|(ci, _)| chain::chain_information::ValidChainInformation::try_from(ci)), // TODO: don't just throw away the runtime
                chain_spec.light_sync_state().map(|s| {
                    chain::chain_information::ValidChainInformation::try_from(
                        s.as_chain_information(),
                    )
                }),
                decode_database(
                    config.database_content,
                    chain_spec.block_number_bytes().into(),
                ),
            ) {
                // Use the database if it contains a more recent block than the chain spec checkpoint.
                (Ok(Ok(genesis_ci)), checkpoint, Ok((database, checkpoint_nodes)))
                    if checkpoint
                        .as_ref()
                        .and_then(|r| r.as_ref().ok())
                        .map_or(true, |cp| {
                            cp.as_ref().finalized_block_header.number
                                < database.as_ref().finalized_block_header.number
                        }) =>
                {
                    let genesis_header = genesis_ci.as_ref().finalized_block_header.clone();
                    (database, genesis_header.into(), checkpoint_nodes)
                }

                // Use the database if it contains a more recent block than the chain spec checkpoint.
                (
                    Err(chain_spec::FromGenesisStorageError::UnknownStorageItems),
                    checkpoint,
                    Ok((database, checkpoint_nodes)),
                ) if checkpoint
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .map_or(true, |cp| {
                        cp.as_ref().finalized_block_header.number
                            < database.as_ref().finalized_block_header.number
                    }) =>
                {
                    let genesis_header = header::Header {
                        parent_hash: [0; 32],
                        number: 0,
                        state_root: *chain_spec.genesis_storage().into_trie_root_hash().unwrap(),
                        extrinsics_root: smoldot::trie::empty_trie_merkle_value(),
                        digest: header::DigestRef::empty().into(),
                    };

                    (database, genesis_header, checkpoint_nodes)
                }

                (Err(chain_spec::FromGenesisStorageError::UnknownStorageItems), None, _) => {
                    // TODO: we can in theory support chain specs that have neither a checkpoint nor the genesis storage, but it's complicated
                    return Err(
                        "Either a checkpoint or the genesis storage must be provided".to_string(),
                    );
                }

                (
                    Err(chain_spec::FromGenesisStorageError::UnknownStorageItems),
                    Some(Ok(checkpoint)),
                    _,
                ) => {
                    let genesis_header = header::Header {
                        parent_hash: [0; 32],
                        number: 0,
                        state_root: *chain_spec.genesis_storage().into_trie_root_hash().unwrap(),
                        extrinsics_root: smoldot::trie::empty_trie_merkle_value(),
                        digest: header::DigestRef::empty().into(),
                    };

                    (checkpoint, genesis_header, Default::default())
                }

                (Err(err), _, _) => {
                    return Err(format!(
                        "Failed to build genesis chain information: {}",
                        err
                    ));
                }

                (Ok(Err(err)), _, _) => {
                    return Err(format!("Invalid genesis chain information: {}", err));
                }

                (_, Some(Err(err)), _) => {
                    return Err(format!(
                        "Invalid checkpoint in chain specification: {}",
                        err
                    ));
                }

                (Ok(Ok(genesis_ci)), Some(Ok(checkpoint)), _) => {
                    let genesis_header = genesis_ci.as_ref().finalized_block_header.clone();
                    (checkpoint, genesis_header.into(), Default::default())
                }

                (Ok(Ok(genesis_ci)), None, _) => {
                    let genesis_header =
                        header::Header::from(genesis_ci.as_ref().finalized_block_header.clone());
                    (genesis_ci, genesis_header, Default::default())
                }
            }
        };

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
                        .map_or(false, |chain| chain.chain_spec_chain_id == relay_chain_id)
                })
                .exactly_one();

            match chain {
                Ok(c) => Some(c),
                Err(mut iter) => {
                    // `iter` here is identical to the iterator above before `exactly_one` is
                    // called. This lets us know what failed.
                    return Err(if iter.next().is_none() {
                        "Couldn't find any valid relay chain".to_string()
                    } else {
                        debug_assert!(iter.next().is_some());
                        "Multiple valid relay chains found".to_string()
                    });
                }
            }
        } else {
            None
        };

        // Build the list of bootstrap nodes ahead of time.
        // Because the specification of the format of a multiaddress is a bit flexible, it is
        // not possible to firmly affirm that a multiaddress is invalid. For this reason, we
        // simply ignore unparsable bootnode addresses rather than returning an error.
        // A list of invalid bootstrap node addresses is kept in order to print a warning later
        // in case it is non-empty. This list is sanitized in order to be safely printable as part
        // of the logs.
        let (bootstrap_nodes, invalid_bootstrap_nodes_sanitized) = {
            let mut valid_list = Vec::with_capacity(chain_spec.boot_nodes().len());
            let mut invalid_list = Vec::with_capacity(0);
            for node in chain_spec.boot_nodes() {
                match node {
                    chain_spec::Bootnode::Parsed { multiaddr, peer_id } => {
                        if let Ok(multiaddr) = multiaddr.parse::<multiaddr::Multiaddr>() {
                            let peer_id = peer_id::PeerId::from_bytes(peer_id).unwrap();
                            valid_list.push((peer_id, vec![multiaddr]));
                        } else {
                            invalid_list.push(multiaddr)
                        }
                    }
                    chain_spec::Bootnode::UnrecognizedFormat(unparsed) => invalid_list.push(
                        unparsed
                            .chars()
                            .filter(|c| c.is_ascii())
                            .collect::<String>(),
                    ),
                }
            }
            (valid_list, invalid_list)
        };

        // All the checks are performed above. Adding the chain can't fail anymore at this point.

        // Grab a couple of fields from the chain specification for later, as the chain
        // specification is consumed below.
        let chain_spec_chain_id = chain_spec.id().to_owned();
        let genesis_block_hash = genesis_block_header.hash(chain_spec.block_number_bytes().into());
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
                    Box::new(self.public_api_chains.get(ck.0).unwrap().key.clone()),
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
                    .get(&self.public_api_chains.get(relay_chain.0).unwrap().key)
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
                    let spawn_new_task = self.spawn_new_task.clone();
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
                        let starting_block_hash = chain_information
                            .as_ref()
                            .finalized_block_header
                            .hash(chain_spec.block_number_bytes().into());
                        let has_bad_blocks = chain_spec.bad_blocks_hashes().count() != 0;

                        let running_chain = start_services(
                            log_name.clone(),
                            spawn_new_task,
                            chain_information,
                            genesis_block_header
                                .scale_encoding_vec(chain_spec.block_number_bytes().into()),
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
                                hash: {}. State root hash: 0x{}. Network identity: {}. Chain \
                                specification or database starting at: {} (#{})",
                                log_name,
                                chain_name,
                                HashDisplay(&genesis_block_hash),
                                hex::encode(&genesis_block_state_root),
                                running_chain.network_identity,
                                HashDisplay(&starting_block_hash),
                                starting_block_number
                            );
                        }

                        // TODO: remove after https://github.com/paritytech/smoldot/issues/2584
                        if has_bad_blocks {
                            log::warn!(
                                target: "smoldot",
                                "Chain specification of {} contains a list of bad blocks. Bad \
                                blocks are not implemented in the light client. An appropriate \
                                way to silence this warning is to remove the bad blocks from the
                                chain specification, which can safely be done if the chain \
                                specification contains a checkpoint and that the bad blocks have \
                                a block number inferior to this checkpoint.", log_name
                            );
                        }

                        running_chain
                    };

                    let (background_future, output_future) = future.remote_handle();
                    (self.spawn_new_task)(
                        "services-initialization".to_owned(),
                        background_future.boxed(),
                    );
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

        if !invalid_bootstrap_nodes_sanitized.is_empty() {
            log::warn!(
                target: "smoldot",
                "Failed to parse some of the bootnodes of {}. \
                These bootnodes have been ignored. List: {}",
                log_name, invalid_bootstrap_nodes_sanitized.join(", ")
            );
        }

        // Print a warning if the list of bootnodes is empty, as this is a common mistake.
        if bootstrap_nodes.is_empty() {
            // Note the usage of the word "likely", because another chain with the same key might
            // have been added earlier and contains bootnodes, or we might receive an incoming
            // substream on a connection normally used for a different chain.
            log::warn!(
                target: "smoldot",
                "Newly-added chain {} has an empty list of bootnodes. Smoldot will likely fail \
                to connect to its peer-to-peer network.",
                log_name
            );
        }

        // Apart from its services, each chain also has an entry in `public_api_chains`.
        let public_api_chains_entry = self.public_api_chains.vacant_entry();
        let new_chain_id = ChainId(public_api_chains_entry.key());

        // Multiple chains can share the same network service, but each specify different
        // bootstrap nodes and database nodes. In order to resolve this, each chain adds their own
        // bootnodes and database nodes to the network service after it has been initialized. This
        // is done by adding a short-lived task that waits for the chain initialization to finish
        // then adds the nodes.
        (self.spawn_new_task)("network-service-add-initial-topology".to_owned(), {
            // Clone `running_chain_init`.
            let mut running_chain_init = match services_init {
                future::MaybeDone::Done(d) => future::MaybeDone::Done(d.clone()),
                future::MaybeDone::Future(d) => future::MaybeDone::Future(d.clone()),
                future::MaybeDone::Gone => unreachable!(),
            };

            async move {
                // Wait for the chain to finish initializing to proceed.
                (&mut running_chain_init).await;
                let running_chain = Pin::new(&mut running_chain_init).take_output().unwrap();
                running_chain
                    .network_service
                    .discover(&TPlat::now(), 0, checkpoint_nodes, false)
                    .await;
                running_chain
                    .network_service
                    .discover(&TPlat::now(), 0, bootstrap_nodes, true)
                    .await;
            }
            .boxed()
        });

        // JSON-RPC service initialization. This is done every time `add_chain` is called, even
        // if a similar chain already existed.
        let json_rpc_sender = if let Some(json_rpc_responses) = config.json_rpc_responses {
            // Clone `running_chain_init`.
            let mut running_chain_init = match services_init {
                future::MaybeDone::Done(d) => future::MaybeDone::Done(d.clone()),
                future::MaybeDone::Future(d) => future::MaybeDone::Future(d.clone()),
                future::MaybeDone::Gone => unreachable!(),
            };

            let (sender, service_starter) = json_rpc_service::service(json_rpc_service::Config {
                log_name: log_name.clone(), // TODO: add a way to differentiate multiple different json-rpc services under the same chain
                max_pending_requests: NonZeroU32::new(128).unwrap(),
                max_subscriptions: 1024, // Note: the PolkadotJS UI is very heavy in terms of subscriptions.
            });

            let spawn_new_task = self.spawn_new_task.clone();
            let system_name = self.system_name.clone();
            let system_version = self.system_version.clone();

            let init_future = async move {
                // Wait for the chain to finish initializing before starting the JSON-RPC service.
                (&mut running_chain_init).await;
                let running_chain = Pin::new(&mut running_chain_init).take_output().unwrap();

                service_starter.start(json_rpc_service::StartConfig {
                    tasks_executor: Box::new(move |name, task| spawn_new_task(name, task)),
                    sync_service: running_chain.sync_service,
                    network_service: (running_chain.network_service, 0), // TODO: 0?
                    transactions_service: running_chain.transactions_service,
                    runtime_service: running_chain.runtime_service,
                    chain_spec: &chain_spec,
                    peer_id: &running_chain.network_identity,
                    system_name,
                    system_version,
                    genesis_block_hash,
                    genesis_block_state_root,
                    responses_sender: json_rpc_responses,
                    max_parallel_requests: NonZeroU32::new(24).unwrap(),
                })
            };

            (self.spawn_new_task)("json-rpc-service-init".to_owned(), init_future.boxed());

            Some(sender)
        } else {
            None
        };

        // Success!
        public_api_chains_entry.insert(PublicApiChain {
            user_data: config.user_data,
            key: new_chain_key,
            chain_spec_chain_id,
            json_rpc_sender,
        });
        Ok(new_chain_id)
    }

    /// Removes the chain from smoldot. This instantaneously and silently cancels all on-going
    /// JSON-RPC requests and subscriptions.
    ///
    /// The provided [`ChainId`] is now considered dead. Be aware that this same [`ChainId`] might
    /// later be reused if [`Client::add_chain`] is called again.
    ///
    /// While from the API perspective it will look like the chain no longer exists, calling this
    /// function will not actually immediately disconnect from the given chain if it is still used
    /// as the relay chain of a parachain.
    #[must_use]
    pub fn remove_chain(&mut self, id: ChainId) -> TChain {
        let removed_chain = self.public_api_chains.remove(id.0);

        let running_chain = self.chains_by_key.get_mut(&removed_chain.key).unwrap();
        if running_chain.num_references.get() == 1 {
            log::info!(target: "smoldot", "Shutting down chain {}", running_chain.log_name);
            self.chains_by_key.remove(&removed_chain.key);
        } else {
            running_chain.num_references =
                NonZeroU32::new(running_chain.num_references.get() - 1).unwrap();
        }

        self.public_api_chains.shrink_to_fit();

        removed_chain.user_data
    }

    /// Returns the user data associated to the given chain.
    ///
    /// # Panic
    ///
    /// Panics if the [`ChainId`] is invalid.
    ///
    pub fn chain_user_data_mut(&mut self, chain_id: ChainId) -> &mut TChain {
        &mut self
            .public_api_chains
            .get_mut(chain_id.0)
            .unwrap()
            .user_data
    }

    /// Enqueues a JSON-RPC request towards the given chain.
    ///
    /// Since most JSON-RPC requests can only be answered asynchronously, the request is only
    /// queued and will be decoded and processed later.
    ///
    /// Returns an error if the node is overloaded and is capable of processing more JSON-RPC
    /// requests before some time has passed or the [`AddChainConfig::json_rpc_responses`] channel
    /// emptied.
    ///
    /// Also returns an error if the request could not be parsed as a valid JSON-RPC request, as
    /// in that situation smoldot is unable to send back a corresponding JSON-RPC error message.
    ///
    /// # Panic
    ///
    /// Panics if the [`ChainId`] is invalid, or if [`AddChainConfig::json_rpc_responses`] was
    /// `None` when adding the chain.
    ///
    pub fn json_rpc_request(
        &mut self,
        json_rpc_request: impl Into<String>,
        chain_id: ChainId,
    ) -> Result<(), HandleRpcError> {
        self.json_rpc_request_inner(json_rpc_request.into(), chain_id)
    }

    fn json_rpc_request_inner(
        &mut self,
        json_rpc_request: String,
        chain_id: ChainId,
    ) -> Result<(), HandleRpcError> {
        let json_rpc_sender = match self
            .public_api_chains
            .get_mut(chain_id.0)
            .unwrap()
            .json_rpc_sender
        {
            Some(ref mut json_rpc_sender) => json_rpc_sender,
            _ => panic!(),
        };

        json_rpc_sender.queue_rpc_request(json_rpc_request)
    }
}

/// Starts all the services of the client.
///
/// Returns some of the services that have been started. If these service get shut down, all the
/// other services will later shut down as well.
async fn start_services<TPlat: platform::Platform>(
    log_name: String,
    spawn_new_task: Arc<
        dyn Fn(String, Pin<Box<dyn Future<Output = ()> + Send + 'static>>) + Send + Sync,
    >,
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
                let spawn_new_task = spawn_new_task.clone();
                move |name, fut| spawn_new_task(name, fut)
            }),
            num_events_receivers: 1, // Configures the length of `network_event_receivers`
            noise_key: network_noise_key,
            chains: vec![network_service::ConfigChain {
                log_name: log_name.clone(),
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
                    chain_information
                        .as_ref()
                        .finalized_block_header
                        .hash(chain_spec.block_number_bytes().into()),
                ),
                protocol_id: chain_spec.protocol_id().to_string(),
                block_number_bytes: usize::from(chain_spec.block_number_bytes()),
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
                block_number_bytes: usize::from(chain_spec.block_number_bytes()),
                tasks_executor: Box::new({
                    let spawn_new_task = spawn_new_task.clone();
                    move |name, fut| spawn_new_task(name, fut)
                }),
                network_service: (network_service.clone(), 0),
                network_events_receiver: network_event_receivers.pop().unwrap(),
                parachain: Some(sync_service::ConfigParachain {
                    parachain_id: chain_spec.relay_chain().unwrap().1,
                    relay_chain_sync: relay_chain.runtime_service.clone(),
                    relay_chain_block_number_bytes: relay_chain.block_number_bytes,
                }),
            })
            .await,
        );

        // The runtime service follows the runtime of the best block of the chain,
        // and allows performing runtime calls.
        let runtime_service = Arc::new(
            runtime_service::RuntimeService::new(runtime_service::Config {
                log_name: log_name.clone(),
                tasks_executor: Box::new({
                    let spawn_new_task = spawn_new_task.clone();
                    move |name, fut| spawn_new_task(name, fut)
                }),
                sync_service: sync_service.clone(),
                genesis_block_scale_encoded_header,
            })
            .await,
        );

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
                block_number_bytes: usize::from(chain_spec.block_number_bytes()),
                tasks_executor: Box::new({
                    let spawn_new_task = spawn_new_task.clone();
                    move |name, fut| spawn_new_task(name, fut)
                }),
                network_service: (network_service.clone(), 0),
                network_events_receiver: network_event_receivers.pop().unwrap(),
                parachain: None,
            })
            .await,
        );

        // The runtime service follows the runtime of the best block of the chain,
        // and allows performing runtime calls.
        let runtime_service = Arc::new(
            runtime_service::RuntimeService::new(runtime_service::Config {
                log_name: log_name.clone(),
                tasks_executor: Box::new({
                    let spawn_new_task = spawn_new_task.clone();
                    move |name, fut| spawn_new_task(name, fut)
                }),
                sync_service: sync_service.clone(),
                genesis_block_scale_encoded_header,
            })
            .await,
        );

        (sync_service, runtime_service)
    };

    // The transactions service lets one send transactions to the peer-to-peer network and watch
    // them being included in the chain.
    // While this service is in principle not needed if it is known ahead of time that no
    // transaction will be submitted, the service itself is pretty low cost.
    let transactions_service = Arc::new(
        transactions_service::TransactionsService::new(transactions_service::Config {
            log_name,
            tasks_executor: Box::new(move |name, fut| spawn_new_task(name, fut)),
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
        block_number_bytes: usize::from(chain_spec.block_number_bytes()),
    }
}

async fn encode_database<TPlat: platform::Platform>(
    network_service: &network_service::NetworkService<TPlat>,
    sync_service: &sync_service::SyncService<TPlat>,
    block_number_bytes: usize,
    max_size: usize,
) -> String {
    // Craft the structure containing all the data that we would like to include.
    let mut database_draft = SerdeDatabase {
        chain: match sync_service.serialize_chain_information().await {
            Some(ci) => {
                let encoded = finalized_serialize::encode_chain(&ci, block_number_bytes);
                serde_json::from_str(&encoded).unwrap()
            }
            None => {
                // If the chain information can't be obtained, we just return a dummy value that
                // will intentionally fail to decode if passed back.
                let dummy_message = "<unknown>";
                return if dummy_message.len() > max_size {
                    String::new()
                } else {
                    dummy_message.to_owned()
                };
            }
        },
        nodes: network_service
            .discovered_nodes(0) // TODO: hacky chain_index
            .await
            .map(|(peer_id, addrs)| {
                (
                    peer_id.to_base58(),
                    addrs.map(|a| a.to_string()).collect::<Vec<_>>(),
                )
            })
            .collect(),
    };

    // Cap the database length to the maximum size.
    loop {
        let serialized = serde_json::to_string(&database_draft).unwrap();
        if serialized.len() <= max_size {
            // Success!
            return serialized;
        }

        if database_draft.nodes.is_empty() {
            // Can't shrink the database anymore. Return the string `"<too-large>"` which will
            // fail to decode but will indicate what is wrong.
            let dummy_message = "<too-large>";
            return if dummy_message.len() >= max_size {
                String::new()
            } else {
                dummy_message.to_owned()
            };
        }

        // Try to reduce the size of the database.

        // Remove half of the nodes.
        // Which nodes are removed doesn't really matter.
        let mut nodes_to_remove = cmp::max(1, database_draft.nodes.len() / 2);
        database_draft.nodes.retain(|_, _| {
            if nodes_to_remove >= 1 {
                nodes_to_remove -= 1;
                false
            } else {
                true
            }
        });
    }
}

fn decode_database(
    encoded: &str,
    block_number_bytes: usize,
) -> Result<
    (
        chain::chain_information::ValidChainInformation,
        Vec<(PeerId, Vec<multiaddr::Multiaddr>)>,
    ),
    (),
> {
    let decoded: SerdeDatabase = serde_json::from_str(encoded).map_err(|_| ())?;

    let (chain, _) = finalized_serialize::decode_chain(
        &serde_json::to_string(&decoded.chain).unwrap(),
        block_number_bytes,
    )
    .map_err(|_| ())?;

    // Nodes that fail to decode are simply ignored. This is especially important for
    // multiaddresses, as the definition of a valid or invalid multiaddress might change across
    // versions.
    let nodes = decoded
        .nodes
        .iter()
        .filter_map(|(peer_id, addrs)| {
            let addrs = addrs
                .iter()
                .filter_map(|a| Some(a.parse::<multiaddr::Multiaddr>().ok()?))
                .collect();
            Some((peer_id.parse::<PeerId>().ok()?, addrs))
        })
        .collect::<Vec<_>>();

    Ok((chain, nodes))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerdeDatabase {
    chain: Box<serde_json::value::RawValue>,
    nodes: hashbrown::HashMap<String, Vec<String>, fnv::FnvBuildHasher>,
}

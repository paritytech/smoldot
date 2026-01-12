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
//! In order to use the light client, call [`Client::new`], passing an implementation of the
//! [`platform::PlatformRef`] trait. See the documentation of the [`platform::PlatformRef`] trait
//! for more information.
//!
//! The [`Client`] contains two generic parameters:
//!
//! - An implementation of the [`platform::PlatformRef`] trait.
//! - An opaque user data. If you do not use this, you can simply use `()`.
//!
//! When the `std` feature of this library is enabled, the [`platform::DefaultPlatform`] struct
//! can be used as an implementation of [`platform::PlatformRef`].
//!
//! For example:
//!
//! ```rust
//! use smoldot_light::{Client, platform::DefaultPlatform};
//! let client = Client::new(DefaultPlatform::new(env!("CARGO_PKG_NAME").into(), env!("CARGO_PKG_VERSION").into()));
//! # let _: Client<_, ()> = client;  // Used in this example to infer the generic parameters of the Client
//! ```
//!
//! If the `std` feature of this library is disabled, then you need to implement the
//! [`platform::PlatformRef`] trait manually.
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
//! Responses can be pulled by calling the [`AddChainSuccess::json_rpc_responses`] that is returned
//! after a chain has been added.
//!

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
// TODO: the `unused_crate_dependencies` lint is disabled because of dev-dependencies, see <https://github.com/rust-lang/rust/issues/95513>
// #![deny(unused_crate_dependencies)]

extern crate alloc;

use alloc::{borrow::ToOwned as _, boxed::Box, format, string::String, sync::Arc, vec, vec::Vec};
use core::{num::NonZero, ops, time::Duration};
use hashbrown::{HashMap, hash_map::Entry};
use itertools::Itertools as _;
use platform::PlatformRef;
use smoldot::{
    chain, chain_spec, header,
    informant::HashDisplay,
    libp2p::{multiaddr, peer_id},
};

mod database;
mod json_rpc_service;
mod runtime_service;
mod sync_service;
mod transactions_service;
mod util;

pub mod network_service;
pub mod platform;

pub use json_rpc_service::HandleRpcError;

/// See [`Client::add_chain`].
#[derive(Debug, Clone)]
pub struct AddChainConfig<'a, TChain, TRelays> {
    /// Opaque user data that the [`Client`] will hold for this chain. Can later be accessed using
    /// the `Index` and `IndexMut` trait implementations on the [`Client`].
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

    /// Configuration for the JSON-RPC endpoint.
    pub json_rpc: AddChainConfigJsonRpc,
}

/// See [`AddChainConfig::json_rpc`].
#[derive(Debug, Clone)]
pub enum AddChainConfigJsonRpc {
    /// No JSON-RPC endpoint is available for this chain.  This saves up a lot of resources, but
    /// will cause all JSON-RPC requests targeting this chain to fail.
    Disabled,

    /// The JSON-RPC endpoint is enabled. Normal operations.
    Enabled {
        /// Maximum number of JSON-RPC requests that can be added to a queue if it is not ready to
        /// be processed immediately. Any additional request will be immediately rejected.
        ///
        /// This parameter is necessary in order to prevent JSON-RPC clients from using up too
        /// much memory within the client.
        /// If the JSON-RPC client is entirely trusted, then passing `u32::MAX` is
        /// completely reasonable.
        ///
        /// A typical value is 128.
        max_pending_requests: NonZero<u32>,

        /// Maximum number of active subscriptions that can be started through JSON-RPC functions.
        /// Any request that causes the JSON-RPC server to generate notifications counts as a
        /// subscription.
        /// Any additional subscription over this limit will be immediately rejected.
        ///
        /// This parameter is necessary in order to prevent JSON-RPC clients from using up too
        /// much memory within the client.
        /// If the JSON-RPC client is entirely trusted, then passing `u32::MAX` is
        /// completely reasonable.
        ///
        /// While a typical reasonable value would be for example 64, existing UIs tend to start
        /// a lot of subscriptions, and a value such as 1024 is recommended.
        max_subscriptions: u32,
    },
}

/// Chain registered in a [`Client`].
///
/// This type is a simple wrapper around a `usize`. Use the `From<usize> for ChainId` and
/// `From<ChainId> for usize` trait implementations to convert back and forth if necessary.
//
// Implementation detail: corresponds to indices within [`Client::public_api_chains`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainId(usize);

impl From<usize> for ChainId {
    fn from(id: usize) -> ChainId {
        ChainId(id)
    }
}

impl From<ChainId> for usize {
    fn from(chain_id: ChainId) -> usize {
        chain_id.0
    }
}

/// Holds a list of chains, connections, and JSON-RPC services.
pub struct Client<TPlat: platform::PlatformRef, TChain = ()> {
    /// Access to the platform capabilities.
    platform: TPlat,

    /// List of chains currently running according to the public API. Indices in this container
    /// are reported through the public API. The values are either an error if the chain has failed
    /// to initialize, or key found in [`Client::chains_by_key`].
    public_api_chains: slab::Slab<PublicApiChain<TPlat, TChain>>,

    /// De-duplicated list of chains that are *actually* running.
    ///
    /// For each key, contains the services running for this chain plus the number of public API
    /// chains that correspond to it.
    ///
    /// Because we use a `SipHasher`, this hashmap isn't created in the `new` function (as this
    /// function is `const`) but lazily the first time it is needed.
    chains_by_key: Option<HashMap<ChainKey, RunningChain<TPlat>, util::SipHasherBuild>>,

    /// All chains share a single networking service created lazily the first time that it
    /// is used.
    network_service: Option<Arc<network_service::NetworkService<TPlat>>>,
}

struct PublicApiChain<TPlat: PlatformRef, TChain> {
    /// Opaque user data passed to [`Client::add_chain`].
    user_data: TChain,

    /// Index of the underlying chain found in [`Client::chains_by_key`].
    key: ChainKey,

    /// Identifier of the chain found in its chain spec. Equal to the return value of
    /// [`chain_spec::ChainSpec::id`]. Used in order to match parachains with relay chains.
    chain_spec_chain_id: String,

    /// Handle that sends requests to the JSON-RPC service that runs in the background.
    /// Destroying this handle also shuts down the service. `None` iff
    /// [`AddChainConfig::json_rpc`] was [`AddChainConfigJsonRpc::Disabled`] when adding the chain.
    json_rpc_frontend: Option<json_rpc_service::Frontend<TPlat>>,

    /// Notified when the [`PublicApiChain`] is destroyed, in order for the [`JsonRpcResponses`]
    /// to detect when the chain has been removed.
    public_api_chain_destroyed_event: event_listener::Event,
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

    /// Networking fork id, found in the chain specification.
    fork_id: Option<String>,
}

struct RunningChain<TPlat: platform::PlatformRef> {
    /// Services that are dedicated to this chain. Wrapped within a `MaybeDone` because the
    /// initialization is performed asynchronously.
    services: ChainServices<TPlat>,

    /// Name of this chain in the logs. This is not necessarily the same as the identifier of the
    /// chain in its chain specification.
    log_name: String,

    /// Number of elements in [`Client::public_api_chains`] that reference this chain. If this
    /// number reaches `0`, the [`RunningChain`] should be destroyed.
    num_references: NonZero<u32>,
}

struct ChainServices<TPlat: platform::PlatformRef> {
    network_service: Arc<network_service::NetworkServiceChain<TPlat>>,
    sync_service: Arc<sync_service::SyncService<TPlat>>,
    runtime_service: Arc<runtime_service::RuntimeService<TPlat>>,
    transactions_service: Arc<transactions_service::TransactionsService<TPlat>>,
}

impl<TPlat: platform::PlatformRef> Clone for ChainServices<TPlat> {
    fn clone(&self) -> Self {
        ChainServices {
            network_service: self.network_service.clone(),
            sync_service: self.sync_service.clone(),
            runtime_service: self.runtime_service.clone(),
            transactions_service: self.transactions_service.clone(),
        }
    }
}

/// Returns by [`Client::add_chain`] on success.
pub struct AddChainSuccess<TPlat: PlatformRef> {
    /// Newly-allocated identifier for the chain.
    pub chain_id: ChainId,

    /// Stream of JSON-RPC responses or notifications.
    ///
    /// Is always `Some` if [`AddChainConfig::json_rpc`] was [`AddChainConfigJsonRpc::Enabled`],
    /// and `None` if it was [`AddChainConfigJsonRpc::Disabled`]. In other words, you can unwrap
    /// this `Option` if you passed `Enabled`.
    pub json_rpc_responses: Option<JsonRpcResponses<TPlat>>,
}

/// Stream of JSON-RPC responses or notifications.
///
/// See [`AddChainSuccess::json_rpc_responses`].
pub struct JsonRpcResponses<TPlat: PlatformRef> {
    /// Receiving side for responses.
    ///
    /// As long as this object is alive, the JSON-RPC service will continue running. In order
    /// to prevent that from happening, we destroy it as soon as the
    /// [`JsonRpcResponses::public_api_chain_destroyed`] is notified of the destruction of
    /// the sender.
    inner: Option<json_rpc_service::Frontend<TPlat>>,

    /// Notified when the [`PublicApiChain`] is destroyed.
    public_api_chain_destroyed: event_listener::EventListener,
}

impl<TPlat: PlatformRef> JsonRpcResponses<TPlat> {
    /// Returns the next response or notification, or `None` if the chain has been removed.
    pub async fn next(&mut self) -> Option<String> {
        if let Some(frontend) = self.inner.as_mut() {
            if let Some(response) = futures_lite::future::or(
                async { Some(frontend.next_json_rpc_response().await) },
                async {
                    (&mut self.public_api_chain_destroyed).await;
                    None
                },
            )
            .await
            {
                return Some(response);
            }
        }

        self.inner = None;
        None
    }
}

impl<TPlat: platform::PlatformRef, TChain> Client<TPlat, TChain> {
    /// Initializes the smoldot client.
    pub const fn new(platform: TPlat) -> Self {
        Client {
            platform,
            public_api_chains: slab::Slab::new(),
            chains_by_key: None,
            network_service: None,
        }
    }

    /// Adds a new chain to the list of chains smoldot tries to synchronize.
    ///
    /// Returns an error in case something is wrong with the configuration.
    pub fn add_chain(
        &mut self,
        config: AddChainConfig<'_, TChain, impl Iterator<Item = ChainId>>,
    ) -> Result<AddChainSuccess<TPlat>, AddChainError> {
        // `chains_by_key` is created lazily whenever needed.
        let chains_by_key = self.chains_by_key.get_or_insert_with(|| {
            HashMap::with_hasher(util::SipHasherBuild::new({
                let mut seed = [0; 16];
                self.platform.fill_random_bytes(&mut seed);
                seed
            }))
        });

        // Decode the chain specification.
        let chain_spec = match chain_spec::ChainSpec::from_json_bytes(config.specification) {
            Ok(cs) => cs,
            Err(err) => {
                return Err(AddChainError::ChainSpecParseError(err));
            }
        };

        // Build the genesis block, its hash, and information about the chain.
        let (
            genesis_chain_information,
            genesis_block_header,
            print_warning_genesis_root_chainspec,
            genesis_block_state_root,
        ) = {
            // TODO: don't build the chain information if only the genesis hash is needed: https://github.com/smol-dot/smoldot/issues/1017
            let genesis_chain_information = chain_spec.to_chain_information().map(|(ci, _)| ci); // TODO: don't just throw away the runtime;

            match genesis_chain_information {
                Ok(genesis_chain_information) => {
                    let header = genesis_chain_information.as_ref().finalized_block_header;
                    let state_root = *header.state_root;
                    let scale_encoded =
                        header.scale_encoding_vec(usize::from(chain_spec.block_number_bytes()));
                    (
                        Some(genesis_chain_information),
                        scale_encoded,
                        chain_spec.light_sync_state().is_some()
                            || chain_spec.relay_chain().is_some(),
                        state_root,
                    )
                }
                Err(chain_spec::FromGenesisStorageError::UnknownStorageItems) => {
                    let state_root = *chain_spec.genesis_storage().into_trie_root_hash().unwrap();
                    let header = header::Header {
                        parent_hash: [0; 32],
                        number: 0,
                        state_root,
                        extrinsics_root: smoldot::trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE,
                        digest: header::DigestRef::empty().into(),
                    }
                    .scale_encoding_vec(usize::from(chain_spec.block_number_bytes()));
                    (None, header, false, state_root)
                }
                Err(err) => return Err(AddChainError::InvalidGenesisStorage(err)),
            }
        };
        let genesis_block_hash = header::hash_from_scale_encoded_header(&genesis_block_header);

        // Decode the database and make sure that it matches the chain by comparing the finalized
        // block header in it with the actual one.
        let (database, database_was_wrong_chain) = {
            let mut maybe_database = database::decode_database(
                config.database_content,
                chain_spec.block_number_bytes().into(),
            )
            .ok();
            let mut database_was_wrong = false;
            if maybe_database
                .as_ref()
                .map_or(false, |db| db.genesis_block_hash != genesis_block_hash)
            {
                maybe_database = None;
                database_was_wrong = true;
            }
            (maybe_database, database_was_wrong)
        };

        // Load the information about the chain. If a light sync state (also known as a checkpoint)
        // is present in the chain spec, it is possible to start syncing at the finalized block
        // it describes.
        // At the same time, we deconstruct the database into `known_nodes`
        // and `runtime_code_hint`.
        let (chain_information, used_database_chain_information, known_nodes, runtime_code_hint) = {
            let checkpoint = chain_spec
                .light_sync_state()
                .map(|s| s.to_chain_information());

            match (genesis_chain_information, checkpoint, database) {
                // Use the database if it contains a more recent block than the
                // chain spec checkpoint.
                (
                    _,
                    Some(Ok(checkpoint)),
                    Some(database::DatabaseContent {
                        chain_information: Some(db_ci),
                        known_nodes,
                        runtime_code_hint,
                        ..
                    }),
                ) if db_ci.as_ref().finalized_block_header.number
                    >= checkpoint.as_ref().finalized_block_header.number =>
                {
                    (Some(db_ci), true, known_nodes, runtime_code_hint)
                }

                // Otherwise, use the chain spec checkpoint.
                (
                    _,
                    Some(Ok(checkpoint)),
                    Some(database::DatabaseContent {
                        known_nodes,
                        runtime_code_hint,
                        ..
                    }),
                ) => (Some(checkpoint), false, known_nodes, runtime_code_hint),
                (_, Some(Ok(checkpoint)), None) => (Some(checkpoint), false, Vec::new(), None),

                // If neither the genesis chain information nor the checkpoint chain information
                // is available, we could in principle use the database, but for API reasons we
                // don't want users to be able to rely on just a database (as we reserve the right
                // to break the database at any point) and thus return an error.
                (
                    None,
                    None,
                    Some(database::DatabaseContent {
                        known_nodes,
                        runtime_code_hint,
                        ..
                    }),
                ) => (None, false, known_nodes, runtime_code_hint),
                (None, None, None) => (None, false, Vec::new(), None),

                // Use the genesis block if no checkpoint is available.
                (
                    Some(genesis_ci),
                    None
                    | Some(Err(
                        chain_spec::CheckpointToChainInformationError::GenesisBlockCheckpoint,
                    )),
                    Some(database::DatabaseContent {
                        known_nodes,
                        runtime_code_hint,
                        ..
                    }),
                ) => (Some(genesis_ci), false, known_nodes, runtime_code_hint),
                (
                    Some(genesis_ci),
                    None
                    | Some(Err(
                        chain_spec::CheckpointToChainInformationError::GenesisBlockCheckpoint,
                    )),
                    None,
                ) => (Some(genesis_ci), false, Vec::new(), None),

                // If the checkpoint format is invalid, we return an error no matter whether the
                // genesis chain information could be used.
                (_, Some(Err(err)), _) => {
                    return Err(AddChainError::InvalidCheckpoint(err));
                }
            }
        };

        // If the chain specification specifies a parachain, find the corresponding relay chain
        // in the list of potential relay chains passed by the user.
        // If no relay chain can be found, the chain creation fails. Exactly one matching relay
        // chain must be found. If there are multiple ones, the creation fails as well.
        let relay_chain_id = if let Some((relay_chain_id, para_id)) = chain_spec.relay_chain() {
            let chain = config
                .potential_relay_chains
                .filter(|c| {
                    self.public_api_chains
                        .get(c.0)
                        .map_or(false, |chain| chain.chain_spec_chain_id == relay_chain_id)
                })
                .exactly_one();

            match chain {
                Ok(c) => Some((c, para_id)),
                Err(mut iter) => {
                    // `iter` here is identical to the iterator above before `exactly_one` is
                    // called. This lets us know what failed.
                    return Err(if iter.next().is_none() {
                        AddChainError::NoRelayChainFound
                    } else {
                        debug_assert!(iter.next().is_some());
                        AddChainError::MultipleRelayChains
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

        // Grab this field from the chain specification for later, as the chain specification is
        // consumed below.
        let chain_spec_chain_id = chain_spec.id().to_owned();

        // The key generated here uniquely identifies this chain within smoldot. Multiple chains
        // having the same key will use the same services.
        //
        // This struct is extremely important from a security perspective. We want multiple
        // identical chains to be de-duplicated, but security issues would arise if two chains
        // were considered identical while they're in reality not identical.
        let new_chain_key = ChainKey {
            genesis_block_hash,
            relay_chain: relay_chain_id.map(|(ck, _)| {
                (
                    Box::new(self.public_api_chains.get(ck.0).unwrap().key.clone()),
                    chain_spec.relay_chain().unwrap().1,
                )
            }),
            fork_id: chain_spec.fork_id().map(|f| f.to_owned()),
        };

        // If the chain we are adding is a parachain, grab the services of the relay chain.
        //
        // This could in principle be done later on, but doing so raises borrow checker errors.
        let relay_chain: Option<(ChainServices<_>, u32, String)> =
            relay_chain_id.map(|(relay_chain, para_id)| {
                let relay_chain = &chains_by_key
                    .get(&self.public_api_chains.get(relay_chain.0).unwrap().key)
                    .unwrap();
                (
                    relay_chain.services.clone(),
                    para_id,
                    relay_chain.log_name.clone(),
                )
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
        // the `Entry::Vacant` block below, even though it would make more sense for it to be
        // there.
        let log_name = {
            let base = chain_spec
                .id()
                .chars()
                .filter(|c| c.is_ascii_graphic())
                .collect::<String>();
            let mut suffix = None;

            loop {
                let attempt = if let Some(suffix) = suffix {
                    format!("{base}-{suffix}")
                } else {
                    base.clone()
                };

                if !chains_by_key.values().any(|c| *c.log_name == attempt) {
                    break attempt;
                }

                match &mut suffix {
                    Some(v) => *v += 1,
                    v @ None => *v = Some(1),
                }
            }
        };

        // Start the services of the chain to add, or grab the services if they already exist.
        let (services, log_name) = match chains_by_key.entry(new_chain_key.clone()) {
            Entry::Occupied(mut entry) => {
                // The chain to add always has a corresponding chain running. Simply grab the
                // existing services and existing log name.
                // The `log_name` created above is discarded in favour of the existing log name.
                entry.get_mut().num_references = entry.get().num_references.checked_add(1).unwrap();
                let entry = entry.into_mut();
                (&mut entry.services, &entry.log_name)
            }
            Entry::Vacant(entry) => {
                if let (None, None) = (&relay_chain, &chain_information) {
                    return Err(AddChainError::ChainSpecNeitherGenesisStorageNorCheckpoint);
                }

                // Start the services of the new chain.
                let services = {
                    // Version of the client when requested through the networking.
                    let network_identify_agent_version = format!(
                        "{} {}",
                        self.platform.client_name(),
                        self.platform.client_version()
                    );

                    let config = match (&relay_chain, &chain_information) {
                        (Some((relay_chain, para_id, _)), Some(chain_information)) => {
                            StartServicesChainTy::Parachain {
                                relay_chain,
                                finalized_block_header: chain_information
                                    .as_ref()
                                    .finalized_block_header
                                    .scale_encoding_vec(usize::from(
                                        chain_spec.block_number_bytes(),
                                    )),
                                para_id: *para_id,
                            }
                        }
                        (Some((relay_chain, para_id, _)), None) => {
                            StartServicesChainTy::Parachain {
                                relay_chain,
                                finalized_block_header: genesis_block_header.clone(),
                                para_id: *para_id,
                            }
                        }
                        (None, Some(chain_information)) => {
                            StartServicesChainTy::SubstrateCompatible { chain_information }
                        }
                        (None, None) => {
                            // Checked above.
                            unreachable!()
                        }
                    };

                    start_services(
                        log_name.clone(),
                        &self.platform,
                        &mut self.network_service,
                        runtime_code_hint,
                        genesis_block_header,
                        usize::from(chain_spec.block_number_bytes()),
                        chain_spec.fork_id().map(|f| f.to_owned()),
                        config,
                        network_identify_agent_version,
                    )
                };

                // Note that the chain name is printed through the `Debug` trait (rather
                // than `Display`) because it is an untrusted user input.
                if let Some((_, para_id, relay_chain_log_name)) = relay_chain.as_ref() {
                    log!(
                        &self.platform,
                        Info,
                        "smoldot",
                        format!(
                            "Parachain initialization complete for {}. Name: {:?}. Genesis \
                            hash: {}. Relay chain: {} (id: {})",
                            log_name,
                            chain_spec.name(),
                            HashDisplay(&genesis_block_hash),
                            relay_chain_log_name,
                            para_id
                        )
                    );
                } else {
                    log!(
                        &self.platform,
                        Info,
                        "smoldot",
                        format!(
                            "Chain initialization complete for {}. Name: {:?}. Genesis \
                            hash: {}. {} starting at: {} (#{})",
                            log_name,
                            chain_spec.name(),
                            HashDisplay(&genesis_block_hash),
                            if used_database_chain_information {
                                "Database"
                            } else {
                                "Chain specification"
                            },
                            HashDisplay(
                                &chain_information
                                    .as_ref()
                                    .map(|ci| ci
                                        .as_ref()
                                        .finalized_block_header
                                        .hash(usize::from(chain_spec.block_number_bytes())))
                                    .unwrap_or(genesis_block_hash)
                            ),
                            chain_information
                                .as_ref()
                                .map(|ci| ci.as_ref().finalized_block_header.number)
                                .unwrap_or(0)
                        )
                    );
                }

                if print_warning_genesis_root_chainspec {
                    log!(
                        &self.platform,
                        Info,
                        "smoldot",
                        format!(
                            "Chain specification of {} contains a `genesis.raw` item. It is \
                            possible to significantly improve the initialization time by \
                            replacing the `\"raw\": ...` field with \
                            `\"stateRootHash\": \"0x{}\"`",
                            log_name,
                            hex::encode(genesis_block_state_root)
                        )
                    );
                }

                if chain_spec.protocol_id().is_some() {
                    log!(
                        &self.platform,
                        Warn,
                        "smoldot",
                        format!(
                            "Chain specification of {} contains a `protocolId` field. This \
                            field is deprecated and its value is no longer used. It can be \
                            safely removed from the JSON document.",
                            log_name
                        )
                    );
                }

                if chain_spec.telemetry_endpoints().count() != 0 {
                    log!(
                        &self.platform,
                        Warn,
                        "smoldot",
                        format!(
                            "Chain specification of {} contains a non-empty \
                            `telemetryEndpoints` field. Smoldot doesn't support telemetry \
                            endpoints and as such this field is unused.",
                            log_name
                        )
                    );
                }

                // TODO: remove after https://github.com/paritytech/smoldot/issues/2584
                if chain_spec.bad_blocks_hashes().count() != 0 {
                    log!(
                        &self.platform,
                        Warn,
                        "smoldot",
                        format!(
                            "Chain specification of {} contains a list of bad blocks. Bad \
                            blocks are not implemented in the light client. An appropriate \
                            way to silence this warning is to remove the bad blocks from the \
                            chain specification, which can safely be done:\n\
                            - For relay chains: if the chain specification contains a \
                            checkpoint and that the bad blocks have a block number inferior \
                            to this checkpoint.\n\
                            - For parachains: if the bad blocks have a block number inferior \
                            to the current parachain finalized block.",
                            log_name
                        )
                    );
                }

                if database_was_wrong_chain {
                    log!(
                        &self.platform,
                        Warn,
                        "smoldot",
                        format!(
                            "Ignore database of {} because its genesis hash didn't match the \
                            genesis hash of the chain.",
                            log_name
                        )
                    )
                }

                let entry = entry.insert(RunningChain {
                    services,
                    log_name,
                    num_references: NonZero::<u32>::new(1).unwrap(),
                });

                (&mut entry.services, &entry.log_name)
            }
        };

        if !invalid_bootstrap_nodes_sanitized.is_empty() {
            log!(
                &self.platform,
                Warn,
                "smoldot",
                format!(
                    "Failed to parse some of the bootnodes of {}. \
                    These bootnodes have been ignored. List: {}",
                    log_name,
                    invalid_bootstrap_nodes_sanitized.join(", ")
                )
            );
        }

        // Print a warning if the list of bootnodes is empty, as this is a common mistake.
        if bootstrap_nodes.is_empty() {
            // Note the usage of the word "likely", because another chain with the same key might
            // have been added earlier and contains bootnodes, or we might receive an incoming
            // substream on a connection normally used for a different chain.
            log!(
                &self.platform,
                Warn,
                "smoldot",
                format!(
                    "Newly-added chain {} has an empty list of bootnodes. Smoldot will \
                    likely fail to connect to its peer-to-peer network.",
                    log_name
                )
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
        self.platform
            .spawn_task("network-service-add-initial-topology".into(), {
                let network_service = services.network_service.clone();
                async move {
                    network_service.discover(known_nodes, false).await;
                    network_service.discover(bootstrap_nodes, true).await;
                }
            });

        // JSON-RPC service initialization. This is done every time `add_chain` is called, even
        // if a similar chain already existed.
        let json_rpc_frontend = if let AddChainConfigJsonRpc::Enabled {
            max_pending_requests,
            max_subscriptions,
        } = config.json_rpc
        {
            let frontend = json_rpc_service::service(json_rpc_service::Config {
                platform: self.platform.clone(),
                log_name: log_name.clone(), // TODO: add a way to differentiate multiple different json-rpc services under the same chain
                max_pending_requests,
                max_subscriptions,
                sync_service: services.sync_service.clone(),
                network_service: services.network_service.clone(),
                transactions_service: services.transactions_service.clone(),
                runtime_service: services.runtime_service.clone(),
                chain_name: chain_spec.name().to_owned(),
                chain_ty: chain_spec.chain_type().to_owned(),
                chain_is_live: chain_spec.has_live_network(),
                chain_properties_json: chain_spec.properties().to_owned(),
                system_name: self.platform.client_name().into_owned(),
                system_version: self.platform.client_version().into_owned(),
                genesis_block_hash,
            });

            Some(frontend)
        } else {
            None
        };

        // Success!
        let public_api_chain_destroyed_event = event_listener::Event::new();
        let public_api_chain_destroyed = public_api_chain_destroyed_event.listen();
        public_api_chains_entry.insert(PublicApiChain {
            user_data: config.user_data,
            key: new_chain_key,
            chain_spec_chain_id,
            json_rpc_frontend: json_rpc_frontend.clone(),
            public_api_chain_destroyed_event,
        });
        Ok(AddChainSuccess {
            chain_id: new_chain_id,
            json_rpc_responses: json_rpc_frontend.map(|f| JsonRpcResponses {
                inner: Some(f),
                public_api_chain_destroyed,
            }),
        })
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
    ///
    /// If the [`JsonRpcResponses`] object that was returned when adding the chain is still alive,
    /// [`JsonRpcResponses::next`] will now return `None`.
    #[must_use]
    pub fn remove_chain(&mut self, id: ChainId) -> TChain {
        let removed_chain = self.public_api_chains.remove(id.0);

        removed_chain
            .public_api_chain_destroyed_event
            .notify(usize::MAX);

        // `chains_by_key` is created lazily when `add_chain` is called.
        // Since we're removing a chain that has been added with `add_chain`, it is guaranteed
        // that `chains_by_key` is set.
        let chains_by_key = self
            .chains_by_key
            .as_mut()
            .unwrap_or_else(|| unreachable!());

        let running_chain = chains_by_key.get_mut(&removed_chain.key).unwrap();
        if running_chain.num_references.get() == 1 {
            log!(
                &self.platform,
                Info,
                "smoldot",
                format!("Shutting down chain {}", running_chain.log_name)
            );
            chains_by_key.remove(&removed_chain.key);
        } else {
            running_chain.num_references =
                NonZero::<u32>::new(running_chain.num_references.get() - 1).unwrap();
        }

        self.public_api_chains.shrink_to_fit();

        removed_chain.user_data
    }

    /// Enqueues a JSON-RPC request towards the given chain.
    ///
    /// Since most JSON-RPC requests can only be answered asynchronously, the request is only
    /// queued and will be decoded and processed later.
    ///
    /// Returns an error if the number of requests that have been sent but whose answer hasn't been
    /// pulled with [`JsonRpcResponses::next`] is superior or equal to the value that was passed
    /// through [`AddChainConfigJsonRpc::Enabled::max_pending_requests`]. In that situation, the
    /// API user is encouraged to stop sending requests and start pulling answers with
    /// [`JsonRpcResponses::next`].
    ///
    /// Passing `u32::MAX` to [`AddChainConfigJsonRpc::Enabled::max_pending_requests`] is
    /// a good way to avoid errors here, but this should only be done if the JSON-RPC client is
    /// trusted.
    ///
    /// If the JSON-RPC request is not a valid JSON-RPC request, a JSON-RPC error response with
    /// an `id` equal to `null` is later generated, in accordance with the JSON-RPC specification.
    ///
    /// # Panic
    ///
    /// Panics if the [`ChainId`] is invalid, or if [`AddChainConfig::json_rpc`] was
    /// [`AddChainConfigJsonRpc::Disabled`] when adding the chain.
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
            .json_rpc_frontend
        {
            Some(ref mut json_rpc_sender) => json_rpc_sender,
            _ => panic!(),
        };

        json_rpc_sender.queue_rpc_request(json_rpc_request)
    }
}

impl<TPlat: platform::PlatformRef, TChain> ops::Index<ChainId> for Client<TPlat, TChain> {
    type Output = TChain;

    fn index(&self, index: ChainId) -> &Self::Output {
        &self.public_api_chains.get(index.0).unwrap().user_data
    }
}

impl<TPlat: platform::PlatformRef, TChain> ops::IndexMut<ChainId> for Client<TPlat, TChain> {
    fn index_mut(&mut self, index: ChainId) -> &mut Self::Output {
        &mut self.public_api_chains.get_mut(index.0).unwrap().user_data
    }
}

/// Error potentially returned by [`Client::add_chain`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum AddChainError {
    /// Failed to decode the specification of the chain.
    #[display("Failed to decode chain specification: {_0}")]
    ChainSpecParseError(chain_spec::ParseError),
    /// The chain specification must contain either the storage of the genesis block, or a
    /// checkpoint. Neither was provided.
    #[display("Either a checkpoint or the genesis storage must be provided")]
    ChainSpecNeitherGenesisStorageNorCheckpoint,
    /// Checkpoint provided in the chain specification is invalid.
    #[display("Invalid checkpoint in chain specification: {_0}")]
    InvalidCheckpoint(chain_spec::CheckpointToChainInformationError),
    /// Failed to build the information about the chain from the genesis storage. This indicates
    /// invalid data in the genesis storage.
    #[display("Failed to build genesis chain information: {_0}")]
    InvalidGenesisStorage(chain_spec::FromGenesisStorageError),
    /// The list of potential relay chains doesn't contain any relay chain with the name indicated
    /// in the chain specification of the parachain.
    #[display("Couldn't find relevant relay chain")]
    NoRelayChainFound,
    /// The list of potential relay chains contains more than one relay chain with the name
    /// indicated in the chain specification of the parachain.
    #[display("Multiple relevant relay chains found")]
    MultipleRelayChains,
}

enum StartServicesChainTy<'a, TPlat: platform::PlatformRef> {
    SubstrateCompatible {
        chain_information: &'a chain::chain_information::ValidChainInformation,
    },
    Parachain {
        relay_chain: &'a ChainServices<TPlat>,
        finalized_block_header: Vec<u8>,
        para_id: u32,
    },
}

/// Starts all the services of the client.
///
/// Returns some of the services that have been started. If these service get shut down, all the
/// other services will later shut down as well.
fn start_services<TPlat: platform::PlatformRef>(
    log_name: String,
    platform: &TPlat,
    network_service: &mut Option<Arc<network_service::NetworkService<TPlat>>>,
    runtime_code_hint: Option<database::DatabaseContentRuntimeCodeHint>,
    genesis_block_scale_encoded_header: Vec<u8>,
    block_number_bytes: usize,
    fork_id: Option<String>,
    config: StartServicesChainTy<'_, TPlat>,
    network_identify_agent_version: String,
) -> ChainServices<TPlat> {
    let network_service = network_service.get_or_insert_with(|| {
        network_service::NetworkService::new(network_service::Config {
            platform: platform.clone(),
            identify_agent_version: network_identify_agent_version,
            connections_open_pool_size: 8,
            connections_open_pool_restore_delay: Duration::from_millis(100),
            chains_capacity: 1,
        })
    });

    let network_service_chain = network_service.add_chain(network_service::ConfigChain {
        log_name: log_name.clone(),
        num_out_slots: 4,
        grandpa_protocol_finalized_block_height:
            if let StartServicesChainTy::SubstrateCompatible { chain_information } = &config {
                if matches!(
                    chain_information.as_ref().finality,
                    chain::chain_information::ChainInformationFinalityRef::Grandpa { .. }
                ) {
                    Some(chain_information.as_ref().finalized_block_header.number)
                } else {
                    None
                }
            } else {
                // Parachains never use GrandPa.
                None
            },
        genesis_block_hash: header::hash_from_scale_encoded_header(
            &genesis_block_scale_encoded_header,
        ),
        best_block: match &config {
            StartServicesChainTy::SubstrateCompatible { chain_information } => (
                chain_information.as_ref().finalized_block_header.number,
                chain_information
                    .as_ref()
                    .finalized_block_header
                    .hash(block_number_bytes),
            ),
            StartServicesChainTy::Parachain {
                finalized_block_header,
                ..
            } => {
                if let Ok(decoded) = header::decode(finalized_block_header, block_number_bytes) {
                    (
                        decoded.number,
                        header::hash_from_scale_encoded_header(finalized_block_header),
                    )
                } else {
                    (
                        0,
                        header::hash_from_scale_encoded_header(&genesis_block_scale_encoded_header),
                    )
                }
            }
        },
        fork_id,
        block_number_bytes,
    });

    let (sync_service, runtime_service) = match config {
        StartServicesChainTy::Parachain {
            relay_chain,
            finalized_block_header,
            para_id,
            ..
        } => {
            // Chain is a parachain.

            // The sync service is leveraging the network service, downloads block headers,
            // and verifies them, to determine what are the best and finalized blocks of the
            // chain.
            let sync_service = Arc::new(sync_service::SyncService::new(sync_service::Config {
                platform: platform.clone(),
                log_name: log_name.clone(),
                block_number_bytes,
                network_service: network_service_chain.clone(),
                chain_type: sync_service::ConfigChainType::Parachain(
                    sync_service::ConfigParachain {
                        finalized_block_header,
                        relay_chain: sync_service::ConfigRelayChain {
                            para_id,
                            relay_chain_sync: relay_chain.runtime_service.clone(),
                        },
                    },
                ),
            }));

            // The runtime service follows the runtime of the best block of the chain,
            // and allows performing runtime calls.
            let runtime_service = Arc::new(runtime_service::RuntimeService::new(
                runtime_service::Config {
                    log_name: log_name.clone(),
                    platform: platform.clone(),
                    sync_service: sync_service.clone(),
                    network_service: network_service_chain.clone(),
                    genesis_block_scale_encoded_header,
                },
            ));

            (sync_service, runtime_service)
        }
        StartServicesChainTy::SubstrateCompatible { chain_information } => {
            // Chain is a Substrate-compatible non-parachain chain.

            // The sync service is leveraging the network service, downloads block headers,
            // and verifies them, to determine what are the best and finalized blocks of the
            // chain.
            let sync_service = Arc::new(sync_service::SyncService::new(sync_service::Config {
                log_name: log_name.clone(),
                block_number_bytes,
                platform: platform.clone(),
                network_service: network_service_chain.clone(),
                chain_type: sync_service::ConfigChainType::SubstrateCompatible(
                    sync_service::ConfigSubstrateCompatible {
                        chain_information: chain_information.clone(),
                        runtime_code_hint: runtime_code_hint.map(|hint| {
                            sync_service::ConfigSubstrateCompatibleRuntimeCodeHint {
                                storage_value: hint.code,
                                merkle_value: hint.code_merkle_value,
                                closest_ancestor_excluding: hint.closest_ancestor_excluding,
                            }
                        }),
                        relay_chain: None,
                    },
                ),
            }));

            // The runtime service follows the runtime of the best block of the chain,
            // and allows performing runtime calls.
            let runtime_service = Arc::new(runtime_service::RuntimeService::new(
                runtime_service::Config {
                    log_name: log_name.clone(),
                    platform: platform.clone(),
                    sync_service: sync_service.clone(),
                    network_service: network_service_chain.clone(),
                    genesis_block_scale_encoded_header,
                },
            ));

            (sync_service, runtime_service)
        }
    };

    // The transactions service lets one send transactions to the peer-to-peer network and watch
    // them being included in the chain.
    // While this service is in principle not needed if it is known ahead of time that no
    // transaction will be submitted, the service itself is pretty low cost.
    let transactions_service = Arc::new(transactions_service::TransactionsService::new(
        transactions_service::Config {
            log_name,
            platform: platform.clone(),
            sync_service: sync_service.clone(),
            runtime_service: runtime_service.clone(),
            network_service: network_service_chain.clone(),
            max_pending_transactions: NonZero::<u32>::new(64).unwrap(),
            max_concurrent_downloads: NonZero::<u32>::new(3).unwrap(),
            max_concurrent_validations: NonZero::<u32>::new(2).unwrap(),
        },
    ));

    ChainServices {
        network_service: network_service_chain,
        runtime_service,
        sync_service,
        transactions_service,
    }
}

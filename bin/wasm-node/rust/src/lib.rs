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

//! Contains a light client implementation usable from a browser environment, using the
//! `wasm-bindgen` library.

#![recursion_limit = "512"]
#![deny(broken_intra_doc_links)]
#![deny(unused_crate_dependencies)]

use futures::{channel::mpsc, lock::Mutex, prelude::*};
use smoldot::{
    chain, chain_spec,
    informant::HashDisplay,
    json_rpc::{self, methods},
    libp2p::{connection, multiaddr, peer_id},
};
use std::{
    collections::{hash_map::Entry, HashMap},
    convert::TryFrom as _,
    num::NonZeroU32,
    pin::Pin,
    str,
    sync::Arc,
    task,
};

pub mod ffi;

mod json_rpc_service;
mod lossy_channel;
mod network_service;
mod runtime_service;
mod sync_service;
mod transactions_service;

// Use the default "system" allocator. In the context of Wasm, this uses the `dlmalloc` library.
// See <https://github.com/rust-lang/rust/tree/1.47.0/library/std/src/sys/wasm>.
//
// While the `wee_alloc` crate is usually the recommended choice in WebAssembly, testing has shown
// that using it makes memory usage explode from ~100MiB to ~2GiB and more (the environment then
// refuses to allocate 4GiB).
#[global_allocator]
static ALLOC: std::alloc::System = std::alloc::System;

/// See [`Client::add_chain`].
#[derive(Debug, Clone)]
pub struct AddChainConfig<'a> {
    /// JSON text containing the specification of the chain (the so-called "chain spec").
    pub specification: &'a str,

    /// If [`AddChainConfig`] defines a parachain, contains the list of relay chains to choose
    /// from.
    ///
    /// This field is necessary because multiple different chain can have the same identity. If
    /// the client tried to find the corresponding relay chain in all the previously-spawned
    /// chains, it means that a call to [`Client::add_chain`] could influence the outcome of a
    /// subsequent call to [`Client::add_chain`].
    ///
    /// For example: if user A adds a chain named "kusama", then user B adds a different chain
    /// also named "kusama", then user B adds a parachain whose relay chain is "kusama", it would
    /// be wrong to connect to the "kusama" created by user A.
    // TODO: pass as iterator
    pub potential_relay_chains: Vec<ChainId>,

    /// If `false`, then no JSON-RPC service is started for this chain. This saves up a lot of
    /// resources, but will cause all JSON-RPC requests targetting this chain to fail.
    pub json_rpc_running: bool,
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

pub struct Client {
    /// Tasks can be spawned by sending it on this channel. The first tuple element is the name
    /// of the task used for debugging purposes.
    new_task_tx: mpsc::UnboundedSender<(String, future::BoxFuture<'static, ()>)>,

    /// List of chains currently running according to the public API. Indices in this container
    /// are reported through the public API. The values are keys found in
    /// [`Client::chains_by_key`].
    public_api_chains: slab::Slab<PublicApiChain>,

    /// De-duplicated list of chains that are *actually* running.
    ///
    /// For each key, contains the services running for this chain plus the number of public API
    /// chains that correspond to it.
    chains_by_key: HashMap<ChainKey, (RunningChain, NonZeroU32)>,
}

impl Client {
    /// Initializes the smoldot Wasm client.
    pub fn new(max_log_level: log::LevelFilter) -> Self {
        // Try initialize the logging and the panic hook.
        // Note that `start_client` can theoretically be called multiple times, meaning that these
        // calls shouldn't panic if reached multiple times.
        let _ = log::set_boxed_logger(Box::new(ffi::Logger))
            .map(|()| log::set_max_level(max_log_level));
        std::panic::set_hook(Box::new(|info| {
            ffi::throw(info.to_string());
        }));

        // Fool-proof check to make sure that randomness is properly implemented.
        assert_ne!(rand::random::<u64>(), 0);
        assert_ne!(rand::random::<u64>(), rand::random::<u64>());

        // Starting here, the code below initializes the various "services" that make up the node.
        // Services need to be able to spawn asynchronous tasks on their own. Since "spawning a
        // task" isn't really something that a browser or Node environment can do efficiently, we
        // instead combine all the asynchronous tasks into one `FuturesUnordered` below.
        //
        // The `new_task_tx` and `new_task_rx` variables are used when spawning a new task is
        // required. Send a task on `new_task_tx` to start running it.
        // TODO: update comment ^
        let (new_task_tx, mut new_task_rx) = mpsc::unbounded();

        // This is the main future that executes the entire client.
        ffi::spawn_background_task(async move {
            let mut all_tasks = stream::FuturesUnordered::new();

            // The code below processes tasks that have names.
            #[pin_project::pin_project]
            struct FutureAdapter<F> {
                name: String,
                #[pin]
                future: F,
            }

            impl<F: Future> Future for FutureAdapter<F> {
                type Output = F::Output;
                fn poll(self: Pin<&mut Self>, cx: &mut task::Context) -> task::Poll<Self::Output> {
                    let this = self.project();
                    log::trace!("enter: {}", &this.name);
                    let out = this.future.poll(cx);
                    log::trace!("leave");
                    out
                }
            }

            // Since `all_tasks` is initially empty, polling it would produce `None` and
            // immediately interrupt the processing.
            // As such, we start by filling it with the initial content of the `new_task` channel.
            while let Some(Some((task_name, task))) = new_task_rx.next().now_or_never() {
                all_tasks.push(FutureAdapter {
                    name: task_name,
                    future: task,
                });
            }

            loop {
                match future::select(new_task_rx.select_next_some(), all_tasks.next()).await {
                    future::Either::Left(((new_task_name, new_task), _)) => {
                        all_tasks.push(FutureAdapter {
                            name: new_task_name,
                            future: new_task,
                        });
                    }
                    future::Either::Right((Some(()), _)) => {}
                    future::Either::Right((None, _)) => {
                        log::info!("All tasks complete. Stopping client.");
                        break;
                    }
                }
            }
        });

        Client {
            new_task_tx,
            public_api_chains: slab::Slab::with_capacity(2),
            chains_by_key: HashMap::with_capacity(2),
        }
    }

    /// Adds a new chain to the list of chains smoldot tries to synchronize.
    #[must_use]
    pub fn add_chain(
        &mut self,
        config: AddChainConfig<'_>,
    ) -> Result<ChainId, AddChainError> {
        // Decode the chain specification.
        let chain_spec = chain_spec::ChainSpec::from_json_bytes(&config.specification)
            .map_err(AddChainError::InvalidChainSpec)?;

        // Load the information about the chains from the chain specs. If a light sync state is
        // present in the chain specs, it is possible to start sync at the finalized block it
        // describes.
        let genesis_chain_information =
            chain::chain_information::ValidChainInformation::from_chain_spec(&chain_spec)
                .map_err(AddChainError::GenesisChainInformationError)?;
        let chain_information = if let Some(light_sync_state) = chain_spec.light_sync_state() {
            light_sync_state.as_chain_information()
        } else {
            genesis_chain_information.clone()
        };

        // If the chain specification specifies a parachain, find the corresponding relay chain.
        let relay_chain = if let Some((relay_chain_id, para_id)) = chain_spec.relay_chain() {
            let mut valid_relay_chains_iter = config
                .potential_relay_chains
                .iter()
                .filter_map(|c| self.public_api_chains.get(c.0))
                .filter(|c| self.chains_by_key.get(&c.key).unwrap().0.chain_id == relay_chain_id);

            let found_relay_chain = valid_relay_chains_iter
                .next()
                .ok_or(AddChainError::RelayChainNotFound)?;
            if valid_relay_chains_iter.next().is_some() {
                return Err(AddChainError::MultipleValidRelayChains);
            }
            Some(found_relay_chain)
        } else {
            None
        };

        let new_chain_key = ChainKey {
            genesis_block_hash: genesis_chain_information
                .as_ref()
                .finalized_block_header
                .hash(),
            relay_chain: relay_chain.clone().map(|ck| {
                (
                    Box::new(ck.key.clone()),
                    chain_spec.relay_chain().unwrap().1,
                )
            }),
        };

        match self.chains_by_key.entry(new_chain_key.clone()) {
            Entry::Occupied(mut entry) => {
                // TODO: /!\ must start a fresh json-rpc service anyway
                // TODO: must add bootnodes to the existing network service
                entry.get_mut().1 = NonZeroU32::new(entry.get_mut().1.get() + 1).unwrap();
            }
            Entry::Vacant(entry) => {
                // Key used by the networking. Represents the identity of the node on the
                // peer-to-peer network.
                let network_noise_key = connection::NoiseKey::new(&rand::random());
                log::info!(
                    "Network public key: {}",
                    peer_id::PublicKey::Ed25519(*network_noise_key.libp2p_public_ed25519_key())
                        .into_peer_id()
                );

                // The code below consists in spawning various services one by one. Services must be
                // created in a specific order, because some services must be passed an `Arc` to others.
                // One thing to be aware of, is that in order to start, a service might perform a request
                // on the other service(s) passed as parameter. These requests in turn depend on background
                // task being spawned.
                let running_chain = start_services(
                    self.new_task_tx.clone(),
                    chain_information,
                    genesis_chain_information,
                    chain_spec,
                    relay_chain.map(|relay_chain| &self.chains_by_key.get(relay_chain).unwrap().0),
                    network_noise_key,
                    config.json_rpc_running,
                )
                .await;
            }
        }

        let json_rpc_service = if config.json_rpc_running {
            let finalized_header = genesis_chain_information.as_ref().finalized_block_header;
            Some(
                json_rpc_service::start(json_rpc_service::Config {
                    tasks_executor: Box::new({
                        let new_task_tx = new_task_tx.clone();
                        move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
                    }),
                    network_service: (network_service.clone(), 0),
                    sync_service,
                    transactions_service,
                    runtime_service,
                    chain_spec,
                    genesis_block_hash: finalized_header.hash(),
                    genesis_block_state_root: *finalized_header.state_root,
                    chain_index,
                })
                .await,
            )
        } else {
            None
        };

        // Everything went ok. Generate a `ChainId` for that chain.
        let chain_id = self.public_api_chains.insert(PublicApiChain {
            key: new_chain_key,
            json_rpc_service,
        });

        Ok(ChainId(chain_id))
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
    pub fn remove_chain(&mut self, id: ChainId) {
        self.public_api_chains.remove(id.0);
        self.public_api_chains.shrink_to_fit();

        /*for service in json_rpc_services.values().cloned() {
            service.handle_unsubscribe_all(user_data).await;
        }*/
    }

    pub fn json_rpc_request(&mut self, json_rpc_request: Box<[u8]>, chain_id: ChainId) {
        let request_str = match str::from_utf8(&*json_rpc_request) {
            Ok(s) => s,
            Err(error) => {
                log::warn!(
                    target: "json-rpc",
                    "Failed to parse JSON-RPC query as UTF-8 (chain_index: {}): {}",
                    chain_index, error
                );
                return;
            }
        };

        log::debug!(
            target: "json-rpc",
            "JSON-RPC => {:?}{}",
            if request_str.len() > 100 { &request_str[..100] } else { &request_str[..] },
            if request_str.len() > 100 { "…" } else { "" }
        );

        let (request_id, call) = match methods::parse_json_call(request_str) {
            Ok(rq) => rq,
            Err(methods::ParseError::Method { request_id, error }) => {
                log::warn!(
                    target: "json-rpc",
                    "Error in JSON-RPC method call: {}", error
                );
                send_back(&error.to_json_error(request_id), chain_index, user_data);
                return;
            }
            Err(error) => {
                log::warn!(
                    target: "json-rpc",
                    "Ignoring malformed JSON-RPC call: {}", error
                );
                return;
            }
        };

        match self.public_api_chains.get(&chain_id.0) {
            Some(public_chain) => {
                public_chain
                    .json_rpc_service
                    .handle_rpc(user_data, request_id, call)
                    .await
            }
            None => {
                send_back(
                    &json_rpc::parse::build_error_response(
                        request_id,
                        json_rpc::parse::ErrorResponse::ApplicationDefined(
                            -33000,
                            &format!(
                                "A JSON-RPC service has not been started for chain index {}",
                                chain_index
                            ),
                        ),
                        None,
                    ),
                    chain_index,
                    user_data,
                );
            }
        }
    }
}

/// Identifies a chain, so that multiple identical chains are de-duplicated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ChainKey {
    /// Hash of the genesis block of the chain.
    genesis_block_hash: [u8; 32],
    /// If the chain is a parachain, contains the relay chain and the "para ID" on this relay
    /// chain.
    relay_chain: Option<(Box<ChainKey>, u32)>,
}

struct PublicApiChain {
    key: ChainKey,
    json_rpc_service: Option<Arc<json_rpc_service::JsonRpcService>>,
}

struct RunningChain {
    chain_id: String,
    sync_service: Arc<sync_service::SyncService>,
    runtime_service: Arc<runtime_service::RuntimeService>,
    transactions_service: Arc<transactions_service::TransactionsService>,
}

/// See [`Client::add_chain`].
#[derive(Debug, derive_more::Display)]
pub enum AddChainError {
    // TODO: doc
    InvalidChainSpec(chain_spec::ParseError),
    GenesisChainInformationError(chain::chain_information::FromGenesisStorageError),
    RelayChainNotFound,
    MultipleValidRelayChains,
}

/// Starts all the services of the client.
///
/// Returns some of the services that have been started. If these service get shut down, all the
/// other services will later shut down as well.
async fn start_services(
    new_task_tx: mpsc::UnboundedSender<(
        String,
        Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    )>,
    chain_information: chain::chain_information::ValidChainInformation,
    genesis_chain_information: chain::chain_information::ValidChainInformation,
    chain_spec: chain_spec::ChainSpec,
    relay_chain: Option<&RunningChain>,
    network_noise_key: connection::NoiseKey,
    json_rpc_running: bool,
) -> RunningChain {
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
                    genesis_chain_information.as_ref().finality,
                    chain::chain_information::ChainInformationFinalityRef::Grandpa { .. }
                ),
                genesis_block_hash: genesis_chain_information
                    .as_ref()
                    .finalized_block_header
                    .hash(),
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
            tasks_executor: Box::new({
                let new_task_tx = new_task_tx.clone();
                move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
            }),
            sync_service: sync_service.clone(),
            chain_spec: &chain_spec,
            genesis_block_scale_encoded_header: genesis_chain_information
                .as_ref()
                .finalized_block_header
                .scale_encoding_vec(),
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
            tasks_executor: Box::new({
                let new_task_tx = new_task_tx.clone();
                move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
            }),
            sync_service: sync_service.clone(),
            chain_spec: &chain_spec,
            genesis_block_scale_encoded_header: genesis_chain_information
                .as_ref()
                .finalized_block_header
                .scale_encoding_vec(),
        })
        .await;

        (sync_service, runtime_service)
    };

    // The transactions service lets one send transactions to the peer-to-peer network and watch
    // them being included in the chain.
    let transactions_service = Arc::new(
        transactions_service::TransactionsService::new(transactions_service::Config {
            tasks_executor: Box::new({
                let new_task_tx = new_task_tx.clone();
                move |name, fut| new_task_tx.unbounded_send((name, fut)).unwrap()
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

    let chain_id = chain_spec.id().to_owned();

    RunningChain {
        chain_id,
        runtime_service,
        sync_service,
        transactions_service,
    }
}

/// Use in an asynchronous context to interrupt the current task execution and schedule it back.
///
/// This function is useful in order to guarantee a fine granularity of tasks execution time in
/// situations where a CPU-heavy task is being performed.
async fn yield_once() {
    let mut pending = true;
    futures::future::poll_fn(move |cx| {
        if pending {
            pending = false;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        } else {
            core::task::Poll::Ready(())
        }
    })
    .await
}

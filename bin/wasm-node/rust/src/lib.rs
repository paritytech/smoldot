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

use futures::prelude::*;
use smoldot::{
    chain, chain_spec, executor,
    json_rpc::{self, methods},
    libp2p::{multiaddr, peer_id::PeerId},
    network::protocol,
    trie::proof_verify,
};
use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom as _,
    fmt, iter,
    sync::Arc,
    time::Duration,
};

pub mod ffi;

mod json_rpc_service;
mod network_service;
mod sync_service;

// Use the default "system" allocator. In the context of Wasm, this uses the `dlmalloc` library.
// See <https://github.com/rust-lang/rust/tree/1.47.0/library/std/src/sys/wasm>.
//
// While the `wee_alloc` crate is usually the recommended choice in WebAssembly, testing has shown
// that using it makes memory usage explode from ~100MiB to ~2GiB and more (the environment then
// refuses to allocate 4GiB).
#[global_allocator]
static ALLOC: std::alloc::System = std::alloc::System;

// TODO: several places in this module where we unwrap when we shouldn't

/*
# Implementation notes

TODO: remove this block after this code is production-ready

The objective of the wasm-node is to do two things:

- Synchronizing the chain(s).
- Answer JSON-RPC queries made by the user.

---

Synchronizing the chain(s) consists in:

  - At initialization, loading the chain specs (that potentially contain a checkpoint) and
optionally loading an existing database.
- Connecting and staying connected to a set of full nodes.
- Still at initialization, sending GrandPa warp sync queries to "jump" to the latest finalized
  block (https://github.com/paritytech/smoldot/issues/270). We would end up with a
  `ChainInformation` object containing an almost up-to-chain chain.
- Listening to incoming block announces (block announces contain block headers) and verifying them
  (https://github.com/paritytech/smoldot/issues/271).
- Listening to incoming GrandPa gossiping messages in order to be up-to-date with blocks being
  finalized.
- Every time the current best block is updated, downloading the values of a certain list of
  storage items (see JSON-RPC section below).

In other words, we should constantly be up-to-date with the best and finalized blocks of the
chain(s) we're connected to.

Depending on the chain specs being loaded, the node should either connect only to one chain, or,
if the chain is a parachain, to that one chain and Polkadot. In that second situation, all the
steps above should be done for both the chain and Polkadot.

The node, notably, doesn't store any block body, and doesn't hold the entire storage.

---

Answering JSON-RPC queries consists, well, in answering the requests made by the user.

An important thing to keep in mind is that the code here should be optimized for usage with a UI
whose objective is to look at the head of the chain and send transactions. For example, the code
below keeps a cache of the recent blocks, because we expect the UI to mostly query recent blocks.
It is for example not part of the objective right now to properly serve a UI that repeatedly
queries blocks that are months old.

Here is an overview of what the JSON-RPC queries consist of (without going in details):

- Submitting a transaction. It is unclear to me what this involves. In the case of
`author_submitAndWatchExtrinsic`, this theoretically means keeping track of this transaction in
order to check, in new blocks, whether this transaction has been included, and notifying the user
when that is the case.
- Getting notified when the best block or the finalized block changes.
- Requesting the headers of recent blocks, in particular the current best block and finalized
block. Because everything is asynchronous, it is possible that the user requests what they believe
is the latest finalized block while the latest finalized block has in reality in the meanwhile
been updated.
- Requesting storage items of blocks. This should be implemented by asking that information from
a full node (a so-called "storage proof").
- Requesting the metadata. The metadata is a piece of information that can be obtained from the
runtime code (see the `metadata` module), which is itself the storage item whose key is `:code`.
- Watching for changes in a storage item, where the user wants to be notified when the value of a
storage item is modified. This should also be implemented by sending, for each block we receive,
a storage proof requesting the value of every single storage item being watched, and comparing the
result with the one of the previous block. Note that "has changed" means "has changed compared to
the previous best block", and the "previous best block" can have the same height as the current
best block, notably in case of a reorg.
- Watching for changes in the runtime version. The runtime version is also a piece of information
that can be obtained from the runtime code. In order to watch for changes in the runtime version,
one has to watch for changes in the `:code` storage item, similar to the previous bullet point.

In order to be able to implement watching for storage items and runtime versions, the node should
therefore download, for each new best block, the value of each of these storage items being
watched and of the `:code` key.

*/

/// Starts a client running the given chain specifications.
///
/// > **Note**: This function returns a `Result`. The return value according to the JavaScript
/// >           function is what is in the `Ok`. If an `Err` is returned, a JavaScript exception
/// >           is thrown.
pub async fn start_client(chain_spec: String, database_content: Option<String>) {
    // Try initialize the logging and the panic hook.
    // Note that `start_client` can theoretically be called multiple times, meaning that these
    // calls shouldn't panic if reached multiple times.
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Debug) // TODO: make log level configurable from JS?
        .init();
    std::panic::set_hook(Box::new(|info| {
        ffi::throw(info.to_string());
    }));

    // Fool-proof check to make sure that randomness is properly implemented.
    assert_ne!(rand::random::<u64>(), 0);
    assert_ne!(rand::random::<u64>(), rand::random::<u64>());

    let chain_spec = match chain_spec::ChainSpec::from_json_bytes(&chain_spec) {
        Ok(cs) => {
            log::info!("Loaded chain specs for {}", cs.name());
            cs
        }
        Err(err) => ffi::throw(format!("Error while opening chain specs: {}", err)),
    };

    // The database passed from the user is decoded. Any error while decoding is treated as if
    // there was no database.
    let database_content = if let Some(database_content) = database_content {
        match smoldot::database::finalized_serialize::decode_chain_information(&database_content) {
            Ok(parsed) => Some(parsed),
            Err(error) => {
                log::warn!("Failed to decode chain information: {}", error);
                None
            }
        }
    } else {
        None
    };

    // Load the information about the chain from the chain specs. If a light sync state is
    // present in the chain specs, it is possible to start sync at the finalized block it
    // describes.
    let genesis_chain_information =
        chain::chain_information::ChainInformation::from_genesis_storage(
            chain_spec.genesis_storage(),
        )
        .unwrap();
    let chain_information = {
        let base = if let Some(light_sync_state) = chain_spec.light_sync_state() {
            log::info!(
                "Using light checkpoint starting at #{}",
                light_sync_state
                    .as_chain_information()
                    .finalized_block_header
                    .number
            );
            light_sync_state.as_chain_information()
        } else {
            genesis_chain_information.clone()
        };

        // Only use the existing database if it is ahead of `base`.
        if let Some(database_content) = database_content {
            if database_content.finalized_block_header.number > base.finalized_block_header.number {
                database_content
            } else {
                log::info!("Skipping database as it is older than checkpoint");
                base
            }
        } else {
            base
        }
    };

    let (network_service, mut network_event_receivers) =
        network_service::NetworkService::new(network_service::Config {
            tasks_executor: Box::new(|fut| ffi::spawn_task(fut)),
            num_events_receivers: 1, // Configures the length of `network_event_receivers`
            bootstrap_nodes: {
                let mut list = Vec::with_capacity(chain_spec.boot_nodes().len());
                for node in chain_spec.boot_nodes() {
                    let mut address: multiaddr::Multiaddr = node.parse().unwrap(); // TODO: don't unwrap?
                    if let Some(multiaddr::Protocol::P2p(peer_id)) = address.pop() {
                        let peer_id = PeerId::from_multihash(peer_id).unwrap(); // TODO: don't unwrap
                        list.push((peer_id, address));
                    } else {
                        panic!() // TODO:
                    }
                }
                list
            },
            genesis_block_hash: genesis_chain_information.finalized_block_header.hash(),
            best_block: (
                chain_information.finalized_block_header.number,
                chain_information.finalized_block_header.hash(),
            ),
            protocol_id: chain_spec.protocol_id().to_string(),
        })
        .await;

    let sync_service = Arc::new(
        sync_service::SyncService::new(sync_service::Config {
            chain_information: chain_information.clone(),
            tasks_executor: Box::new(|fut| ffi::spawn_task(fut)),
            network_service: network_service.clone(),
            network_events_receiver: network_event_receivers.pop().unwrap(),
        })
        .await,
    );

    json_rpc_service::start(json_rpc_service::Config {
        tasks_executor: Box::new(|fut| ffi::spawn_task(fut)),
        network_service,
        sync_service: sync_service.clone(),
        chain_spec,
        genesis_chain_information: (&genesis_chain_information).into(),
    }).await;

    ffi::spawn_task(async move {
        loop {
            ffi::Delay::new(Duration::from_secs(15)).await;
            log::debug!("Database save start");
            let database_content = sync_service.serialize_chain().await;
            ffi::database_save(&database_content);
        }
    });

    log::info!("Initialization complete");
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

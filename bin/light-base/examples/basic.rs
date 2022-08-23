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

use core::iter;
use futures::{channel::mpsc, prelude::*};

fn main() {
    // The `smoldot_light` library uses the `log` crate to emit logs.
    // We need to register some kind of logs listener, in this example `env_logger`.
    // See also <https://docs.rs/log>.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // The smoldot client will need to spawn tasks that run in the background. In order to do so,
    // we will need to provide a "tasks spawner" to the client. This block of code initializes
    // this "tasks spawner".
    // The tasks sent (by the client) to `tasks_spawner` will be received by `tasks_receiver`.
    // The `tasks_receiver`.
    let (tasks_spawner, mut tasks_receiver) = mpsc::unbounded();
    async_std::task::spawn(async move {
        let mut all_tasks = stream::FuturesUnordered::new();
        loop {
            futures::select! {
                (_, new_task) = tasks_receiver.select_next_some() => {
                    all_tasks.push(new_task);
                },
                () = all_tasks.select_next_some() => {},
            }
        }
    });

    // Now properly initialize the client. This does nothing except allocate resources.
    // We pass the "tasks spawner" created above.
    // The `Client` struct requires a generic parameter that provides platform bindings. In this
    // example, we provide `AsyncStdTcpWebSocket`, which are the "plug and play" default platform.
    // Any advance usage, such as embedding a client in WebAssembly, will likely require a custom
    // implementation of these bindings.
    let mut client = smoldot_light::Client::<
        smoldot_light::platform::async_std::AsyncStdTcpWebSocket,
    >::new(smoldot_light::ClientConfig {
        tasks_spawner,
        system_name: env!("CARGO_PKG_NAME").into(),
        system_version: env!("CARGO_PKG_VERSION").into(),
    });

    // Once a chain has been added, we will be able to send JSON-RPC requests to it. And in
    // return, the client will send back JSON-RPC responses. The JSON-RPC responses will be sent
    // by the client on the `json_rpc_responses_tx` channel (that we inject inside the client).
    let (json_rpc_responses_tx, mut json_rpc_responses_rx) = mpsc::channel(32);

    // Ask the client to connect to a chain.
    let chain_id = client.add_chain(smoldot_light::AddChainConfig {
        // The most important field of the configuration is the chain specification. This is a
        // JSON document containing all the information necessary for the client to connect to said
        // chain.
        specification: include_str!("../../polkadot.json"),

        // See above.
        // Note that it is possible to pass `None`, in which case the chain will not be able to
        // handle JSON-RPC requests. This can be used to save up some resources.
        json_rpc_responses: Some(json_rpc_responses_tx),

        // This field is necessary only if adding a parachain.
        potential_relay_chains: iter::empty(),

        // After a chain has been added, it is possible to extract a "database" (in the form of a
        // simple string). This database can later be passed back the next time the same chain is
        // added again.
        // A database with an invalid format is simply ignored by the client.
        // In this example, we don't use this feature, and as such we simply pass an empty string,
        // which is intentionally an invalid database content.
        database_content: "",

        // The client gives the possibility to insert an opaque "user data" alongside each chain.
        // This avoids having to create a separate `HashMap<ChainId, ...>` in parallel of the
        // client.
        // In this example, this feature isn't used. The chain simply has `()`.
        user_data: (),
    });

    // The `add_chain` function doesn't return a `Result`. Instead, a chain that has failed
    // initialization still exists but in an "erroneous" state. Before continuing, we need to
    // check whether the chain is in this erroneous state.
    if let Some(error_msg) = client.chain_is_erroneous(chain_id) {
        // Chains in an erroneous state must be removed using `remove_chain`.
        // Note that this doesn't matter so much here because we end up panicking, but if we
        // didn't panic it would important to call `remove_chain`.
        let error_msg = error_msg.to_owned();
        let _ = client.remove_chain(chain_id);
        panic!("Error while creating chain: {}", error_msg);
    }

    // The chain is now properly initialized.

    // Send a JSON-RPC request to the chain.
    // The example here asks the client to send us notifications whenever the new best block has
    // changed.
    // Calling this function only queues the request. It is not processed immediately.
    // An `Err` is returned immediately if and only if the request isn't a proper JSON-RPC request
    // or if the channel of JSON-RPC responses is clogged.
    client
        .json_rpc_request(
            r#"{"id":1,"jsonrpc":"2.0","method":"chain_subscribeNewHeads","params":[]}"#,
            chain_id,
        )
        .unwrap();

    // Now block the execution forever and print the responses received on the channel of
    // JSON-RPC responses.
    async_std::task::block_on(async move {
        loop {
            let response = json_rpc_responses_rx.next().await.unwrap();
            println!("JSON-RPC response: {}", response);
        }
    })
}

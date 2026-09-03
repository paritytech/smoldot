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

//! Runs a light client for a single chain and exposes it as a JSON-RPC WebSocket server.
//!
//! This makes it possible to point an existing JSON-RPC client, that only knows how to talk to a
//! node over a `ws://` URI, at a light client instead. This is in particular how the Polkadot
//! bridge relayer (`substrate-relay`) can be run without any trusted RPC node.
//!
//! ```notrust
//! json-rpc-server <listen-address> <chain-spec> [<relay-chain-spec>]
//! ```
//!
//! - `<listen-address>`: for example `127.0.0.1:9944`.
//! - `<chain-spec>`: path to the JSON chain specification of the chain to connect to. It must
//!   contain the `bootNodes` of the chain, as the light client has no other way of finding peers.
//! - `<relay-chain-spec>`: path to the chain specification of the relay chain. Mandatory if, and
//!   only if, `<chain-spec>` is the specification of a parachain.
//!
//! Every WebSocket connection gets its own JSON-RPC endpoint. The underlying networking and
//! syncing is shared between all of them, as the light client de-duplicates chains that have the
//! same specification.

use core::{iter, num::NonZero};
use futures_lite::{FutureExt as _, StreamExt as _};
use smol::{
    lock::Mutex,
    net::{TcpListener, TcpStream},
};
use std::{net::SocketAddr, sync::Arc};

/// Maximum number of JSON-RPC requests that a single connection can have in flight.
const MAX_PENDING_REQUESTS: u32 = 128;
/// Maximum number of active subscriptions per connection.
const MAX_SUBSCRIPTIONS: u32 = 1024;

type Client = smoldot_light::Client<Arc<smoldot_light::platform::default::DefaultPlatform>, ()>;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut args = std::env::args().skip(1);
    let (listen_address, chain_spec_path, relay_chain_spec_path) =
        match (args.next(), args.next(), args.next()) {
            (Some(listen_address), Some(chain_spec), relay_chain_spec) => {
                (listen_address, chain_spec, relay_chain_spec)
            }
            _ => {
                eprintln!(
                    "Usage: json-rpc-server <listen-address> <chain-spec> [<relay-chain-spec>]"
                );
                std::process::exit(1);
            }
        };

    let listen_address = match listen_address.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("Invalid listen address `{listen_address}`: {err}");
            std::process::exit(1);
        }
    };

    let chain_spec = read_to_string_or_exit(&chain_spec_path);
    let relay_chain_spec = relay_chain_spec_path.as_deref().map(read_to_string_or_exit);

    let client = Arc::new(Mutex::new(smoldot_light::Client::new(
        smoldot_light::platform::default::DefaultPlatform::new(
            env!("CARGO_PKG_NAME").into(),
            env!("CARGO_PKG_VERSION").into(),
        ),
    )));

    // Add the chains once, for as long as this process lives, and never remove them.
    //
    // The light client de-duplicates chains that have the same specification, so the per-connection
    // `add_chain` calls below latch onto these rather than starting a second syncing process. What
    // matters is that *these* handles are never released: without them, the chain would be torn
    // down as soon as the last client disconnects, and the next client to connect would start
    // syncing again from the state in the chain specification - throwing away not only the sync
    // progress but everything derived from having followed the chain, such as the finality proofs
    // and authority sets that a bridge relayer asks for. Clients here are short-lived, separate
    // processes, so that would happen constantly.

    smol::block_on(async move {
        {
            let mut client_lock = client.lock().await;
            let relay_chain_id = match relay_chain_spec.as_deref() {
                Some(spec) => match add_chain_no_json_rpc(&mut client_lock, spec, None) {
                    Ok(id) => Some(id),
                    Err(err) => {
                        eprintln!("Failed to add the relay chain: {err}");
                        std::process::exit(1);
                    }
                },
                None => None,
            };
            // A parachain has to be given its relay chain, which must therefore be added first.
            if let Err(err) = add_chain_no_json_rpc(&mut client_lock, &chain_spec, relay_chain_id) {
                eprintln!("Failed to add the chain: {err}");
                std::process::exit(1);
            }
        }

        let tcp_listener = match TcpListener::bind(listen_address).await {
            Ok(l) => l,
            Err(err) => {
                eprintln!("Failed to listen on {listen_address}: {err}");
                std::process::exit(1);
            }
        };

        log::info!(
            "JSON-RPC server listening on ws://{}",
            tcp_listener.local_addr().unwrap_or(listen_address)
        );

        let mut incoming = tcp_listener.incoming();
        while let Some(tcp_socket) = incoming.next().await {
            let tcp_socket = match tcp_socket {
                Ok(s) => s,
                Err(err) => {
                    log::debug!("Failed to accept connection: {err}");
                    continue;
                }
            };

            let client = client.clone();
            let chain_spec = chain_spec.clone();
            let relay_chain_spec = relay_chain_spec.clone();
            smol::spawn(async move {
                if let Err(err) =
                    serve_connection(client, tcp_socket, &chain_spec, relay_chain_spec.as_deref())
                        .await
                {
                    log::debug!("Connection error: {err}");
                }
            })
            .detach();
        }
    });
}

/// Adds a chain to the light client without a JSON-RPC endpoint, and leaks its identifier so that
/// the chain is never removed.
///
/// See the comment where this is called from for why the chains have to outlive the connections.
fn add_chain_no_json_rpc(
    client: &mut Client,
    specification: &str,
    relay_chain: Option<smoldot_light::ChainId>,
) -> Result<smoldot_light::ChainId, String> {
    Ok(client
        .add_chain(smoldot_light::AddChainConfig {
            specification,
            json_rpc: smoldot_light::AddChainConfigJsonRpc::Disabled,
            potential_relay_chains: relay_chain.into_iter(),
            database_content: "",
            user_data: (),
            statement_protocol_config: None,
        })
        .map_err(|err| err.to_string())?
        .chain_id)
}

/// Adds the chain (and its relay chain, if any) to the light client, then relays JSON-RPC requests
/// and responses between the light client and the WebSocket connection.
async fn serve_connection(
    client: Arc<Mutex<Client>>,
    tcp_socket: TcpStream,
    chain_spec: &str,
    relay_chain_spec: Option<&str>,
) -> Result<(), String> {
    let remote_address = tcp_socket
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_owned());

    // Add the chain to the light client. Because the light client de-duplicates chains that have
    // the same specification, doing this once per connection doesn't start a second syncing
    // process; it only creates a second JSON-RPC endpoint towards the same chain.
    let (chain_id, relay_chain_id, mut json_rpc_responses) = {
        let mut client = client.lock().await;

        let relay_chain_id = match relay_chain_spec {
            Some(relay_chain_spec) => Some(
                client
                    .add_chain(smoldot_light::AddChainConfig {
                        specification: relay_chain_spec,
                        // The relay chain is only used to verify the parachain. No JSON-RPC
                        // endpoint is exposed for it, which saves resources.
                        json_rpc: smoldot_light::AddChainConfigJsonRpc::Disabled,
                        potential_relay_chains: iter::empty(),
                        database_content: "",
                        user_data: (),
                        statement_protocol_config: None,
                    })
                    .map_err(|err| format!("Failed to add the relay chain: {err}"))?
                    .chain_id,
            ),
            None => None,
        };

        let smoldot_light::AddChainSuccess {
            chain_id,
            json_rpc_responses,
        } = client
            .add_chain(smoldot_light::AddChainConfig {
                specification: chain_spec,
                json_rpc: smoldot_light::AddChainConfigJsonRpc::Enabled {
                    max_pending_requests: NonZero::<u32>::new(MAX_PENDING_REQUESTS)
                        .unwrap_or_else(|| unreachable!()),
                    max_subscriptions: MAX_SUBSCRIPTIONS,
                },
                potential_relay_chains: relay_chain_id.into_iter(),
                database_content: "",
                user_data: (),
                statement_protocol_config: None,
            })
            .map_err(|err| format!("Failed to add the chain: {err}"))?;

        (
            chain_id,
            relay_chain_id,
            // Always `Some`, as `json_rpc` above is `Enabled`.
            json_rpc_responses.unwrap_or_else(|| unreachable!()),
        )
    };

    // Make sure that the chains are removed from the light client when this function returns,
    // whatever the reason.
    let _chains_guard = ChainsGuard {
        client: client.clone(),
        chain_ids: relay_chain_id
            .into_iter()
            .chain(iter::once(chain_id))
            .collect(),
    };

    // Perform the WebSocket handshake.
    let (mut ws_sender, mut ws_receiver) = {
        let mut ws_server = soketto::handshake::Server::new(tcp_socket);
        let key = ws_server
            .receive_request()
            .await
            .map_err(|err| format!("WebSocket handshake failed: {err}"))?
            .key();
        ws_server
            .send_response(&soketto::handshake::server::Response::Accept {
                key,
                protocol: None,
            })
            .await
            .map_err(|err| format!("WebSocket handshake failed: {err}"))?;
        ws_server.into_builder().finish()
    };

    log::info!("New JSON-RPC connection from {remote_address}");

    // Sends the JSON-RPC responses and notifications of the light client to the WebSocket client.
    let sending_future = async {
        loop {
            let Some(response) = json_rpc_responses.next().await else {
                // Only happens if the chain has been removed, which can't happen before
                // `_chains_guard` is destroyed.
                unreachable!()
            };

            ws_sender
                .send_text(&response)
                .await
                .map_err(|err| format!("Failed to send response: {err}"))?;
            ws_sender
                .flush()
                .await
                .map_err(|err| format!("Failed to send response: {err}"))?;
        }
    };

    // Sends the requests of the WebSocket client to the light client.
    let receiving_future = async {
        let mut message = Vec::new();
        loop {
            message.clear();
            match ws_receiver.receive_data(&mut message).await {
                Ok(soketto::Data::Text(_)) => {}
                Ok(soketto::Data::Binary(_)) => {
                    return Err("Unexpected binary frame".to_owned());
                }
                Err(soketto::connection::Error::Closed) => return Ok(()),
                Err(err) => return Err(format!("WebSocket error: {err}")),
            }

            let request = String::from_utf8(core::mem::take(&mut message))
                .map_err(|_| "Non-UTF8 request".to_owned())?;

            match client.lock().await.json_rpc_request(request, chain_id) {
                Ok(()) => {}
                Err(smoldot_light::HandleRpcError::TooManyPendingRequests { .. }) => {
                    // The queue of the light client is full. Rather than silently dropping the
                    // request, the connection is closed, as a JSON-RPC client has no way of
                    // knowing that one of its requests will never be answered.
                    return Err("Too many pending JSON-RPC requests".to_owned());
                }
            }
        }
    };

    let outcome = sending_future.or(receiving_future).await;
    log::info!("JSON-RPC connection from {remote_address} closed");
    outcome
}

/// Removes chains from the light client when destroyed.
struct ChainsGuard {
    client: Arc<Mutex<Client>>,
    chain_ids: Vec<smoldot_light::ChainId>,
}

impl Drop for ChainsGuard {
    fn drop(&mut self) {
        let client = self.client.clone();
        let chain_ids = core::mem::take(&mut self.chain_ids);
        // `remove_chain` requires locking the client, which can only be done asynchronously.
        smol::spawn(async move {
            let mut client = client.lock().await;
            for chain_id in chain_ids {
                // `remove_chain` returns the chain's user data, which is `()` here.
                #[allow(clippy::let_unit_value)]
                let _user_data = client.remove_chain(chain_id);
            }
        })
        .detach();
    }
}

fn read_to_string_or_exit(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("Failed to read `{path}`: {err}");
            std::process::exit(1);
        }
    }
}

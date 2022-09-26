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

use futures::{channel::oneshot, prelude::*};
use smoldot::json_rpc::{self, methods, websocket_server};
use std::{io, net::SocketAddr};
use tracing::Instrument as _;

/// Configuration for a [`JsonRpcService`].
pub struct Config<'a> {
    /// Closure that spawns background tasks.
    pub tasks_executor: &'a mut dyn FnMut(future::BoxFuture<'static, ()>),

    /// Where to bind the WebSocket server.
    pub bind_address: SocketAddr,
}

/// Running JSON-RPC service. Holds a server open for as long as it is alive.
pub struct JsonRpcService {
    /// As long as this value is alive, the background server continues running.
    _server_keep_alive: oneshot::Sender<()>,
}

impl JsonRpcService {
    /// Initializes a new [`JsonRpcService`].
    pub async fn new(config: Config<'_>) -> Result<Self, InitError> {
        let server = {
            let result = websocket_server::WsServer::new(websocket_server::Config {
                bind_address: config.bind_address,
                capacity: 1,
                max_frame_size: 4096,
                send_buffer_len: 16384,
            })
            .await;

            match result {
                Ok(server) => server,
                Err(error) => {
                    return Err(InitError::ListenError {
                        bind_address: config.bind_address,
                        error,
                    })
                }
            }
        };

        let (_server_keep_alive, client_still_alive) = oneshot::channel();

        let background = JsonRpcBackground {
            server,
            client_still_alive: client_still_alive.fuse(),
        };

        (config.tasks_executor)(
            async move { background.run().await }
                .instrument(tracing::trace_span!(parent: None, "json-rpc-server"))
                .boxed(),
        );

        Ok(JsonRpcService { _server_keep_alive })
    }
}

/// Error potentially returned by [`JsonRpcService::new`].
#[derive(Debug, derive_more::Display)]
pub enum InitError {
    /// Failed to listen on the server address.
    #[display(fmt = "Failed to listen on TCP address {}: {}", bind_address, error)]
    ListenError {
        /// Address that was attempted.
        bind_address: SocketAddr,
        /// Error returned by the operating system.
        error: io::Error,
    },
}

struct JsonRpcBackground {
    /// State machine of the WebSocket server. Holds the TCP socket.
    server: websocket_server::WsServer<SocketAddr>,

    /// As long as this channel is pending, the frontend of the JSON-RPC server is still alive.
    client_still_alive: future::Fuse<oneshot::Receiver<()>>,
}

impl JsonRpcBackground {
    async fn run(mut self) {
        loop {
            let event = futures::select! {
                _ = &mut self.client_still_alive => return,
                event = self.server.next_event().fuse() => event,
            };

            let (connection_id, message) = match event {
                websocket_server::Event::ConnectionOpen { address, .. } => {
                    tracing::debug!(%address, "incoming-connection");
                    self.server.accept(address);
                    continue;
                }
                websocket_server::Event::ConnectionError {
                    user_data: address, ..
                } => {
                    tracing::debug!(%address, "connection-closed");
                    continue;
                }
                websocket_server::Event::TextFrame {
                    connection_id,
                    message,
                    ..
                } => (connection_id, message),
            };

            let (request_id, _method) = match methods::parse_json_call(&message) {
                Ok(v) => v,
                Err(error) => {
                    tracing::debug!(%error, %message, "bad-request");
                    self.server.close(connection_id);
                    continue;
                }
            };

            tracing::debug!(%request_id, method = ?_method, "request");

            self.server.queue_send(
                connection_id,
                json_rpc::parse::build_error_response(
                    request_id,
                    json_rpc::parse::ErrorResponse::ServerError(
                        -32000,
                        "Not implemented in smoldot yet",
                    ),
                    None,
                ),
            );
        }
    }
}

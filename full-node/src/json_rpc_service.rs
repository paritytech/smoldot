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

use crate::{LogCallback, LogLevel, consensus_service, database_thread, network_service};
use futures_channel::oneshot;
use futures_util::FutureExt;
use smol::{
    future,
    net::{TcpListener, TcpStream},
};
use smoldot::json_rpc::{methods, service};
use std::{
    io, mem,
    net::SocketAddr,
    num::NonZero,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

mod chain_head_subscriptions;
mod legacy_api_subscriptions;
mod requests_handler;
mod runtime_caches_service;

/// Configuration for a [`JsonRpcService`].
pub struct Config {
    /// Function that can be used to spawn background tasks.
    ///
    /// The tasks passed as parameter must be executed until they shut down.
    pub tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// Function called in order to notify of something.
    pub log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Database to access blocks.
    pub database: Arc<database_thread::DatabaseThread>,

    /// Access to the network, and identifier of the chain from the point of view of the network
    /// service.
    pub network_service: (
        Arc<network_service::NetworkService>,
        network_service::ChainId,
    ),

    /// Where to bind the WebSocket server. If `None`, no TCP server is started.
    pub bind_address: Option<SocketAddr>,

    /// Maximum number of requests to process in parallel.
    pub max_parallel_requests: u32,

    /// Maximum number of JSON-RPC clients until new ones are rejected.
    pub max_json_rpc_clients: u32,

    /// Name of the chain, as found in the chain specification.
    pub chain_name: String,

    /// Type of the chain, as found in the chain specification.
    pub chain_type: String,

    /// JSON-encoded properties of the chain, as found in the chain specification.
    pub chain_properties_json: String,

    /// Whether the chain is a live network. Found in the chain specification.
    pub chain_is_live: bool,

    /// Hash of the genesis block.
    // TODO: load from database maybe?
    pub genesis_block_hash: [u8; 32],

    /// Consensus service of the chain.
    pub consensus_service: Arc<consensus_service::ConsensusService>,
}

/// Running JSON-RPC service.
///
/// If [`Config::bind_address`] is `Some`, holds a TCP server open for as long as it is alive.
///
/// In addition to a TCP/IP server, this service also provides a virtual JSON-RPC endpoint that
/// can be used through [`JsonRpcService::send_request`] and [`JsonRpcService::next_response`].
pub struct JsonRpcService {
    /// This events listener is notified when the service is dropped.
    service_dropped: event_listener::Event,

    /// Address the server is listening on. Not necessarily equal to [`Config::bind_address`].
    listen_addr: Option<SocketAddr>,

    /// I/O for the virtual endpoint.
    virtual_client_io: service::SerializedRequestsIo,
}

impl Drop for JsonRpcService {
    fn drop(&mut self) {
        self.service_dropped.notify(usize::MAX);
    }
}

impl JsonRpcService {
    /// Initializes a new [`JsonRpcService`].
    pub async fn new(config: Config) -> Result<Self, InitError> {
        let (tcp_listener, listen_addr) = match &config.bind_address {
            Some(addr) => match TcpListener::bind(addr).await {
                Ok(listener) => {
                    let listen_addr = match listener.local_addr() {
                        Ok(addr) => addr,
                        Err(error) => {
                            return Err(InitError::ListenError {
                                bind_address: *addr,
                                error,
                            });
                        }
                    };

                    (Some(listener), Some(listen_addr))
                }
                Err(error) => {
                    return Err(InitError::ListenError {
                        bind_address: *addr,
                        error,
                    });
                }
            },
            None => (None, None),
        };

        let service_dropped = event_listener::Event::new();
        let on_service_dropped = service_dropped.listen();

        let (to_requests_handlers, from_background) = async_channel::bounded(8);

        let (virtual_client_main_task, virtual_client_io) =
            service::client_main_task(service::Config {
                max_active_subscriptions: u32::MAX,
                max_pending_requests: NonZero::<u32>::new(u32::MAX).unwrap(),
            });

        spawn_client_main_task(
            config.tasks_executor.clone(),
            config.consensus_service.clone(),
            config.database.clone(),
            to_requests_handlers.clone(),
            virtual_client_main_task,
        );

        let runtime_caches_service = Arc::new(runtime_caches_service::RuntimeCachesService::new(
            runtime_caches_service::Config {
                tasks_executor: config.tasks_executor.clone(),
                database: config.database.clone(),
                num_cache_entries: NonZero::<usize>::new(16).unwrap(), // TODO: configurable?
            },
        ));

        for _ in 0..config.max_parallel_requests {
            requests_handler::spawn_requests_handler(requests_handler::Config {
                tasks_executor: config.tasks_executor.clone(),
                log_callback: config.log_callback.clone(),
                database: config.database.clone(),
                network_service: config.network_service.clone(),
                receiver: from_background.clone(),
                chain_name: config.chain_name.clone(),
                chain_type: config.chain_type.clone(),
                chain_properties_json: config.chain_properties_json.clone(),
                chain_is_live: config.chain_is_live,
                genesis_block_hash: config.genesis_block_hash,
                consensus_service: config.consensus_service.clone(),
                runtime_caches_service: runtime_caches_service.clone(),
            });
        }

        if let Some(tcp_listener) = tcp_listener {
            let background = JsonRpcBackground {
                tcp_listener,
                on_service_dropped,
                tasks_executor: config.tasks_executor.clone(),
                log_callback: config.log_callback,
                consensus_service: config.consensus_service.clone(),
                database: config.database.clone(),
                to_requests_handlers,
                num_json_rpc_clients: Arc::new(AtomicU32::new(0)),
                max_json_rpc_clients: config.max_json_rpc_clients,
            };

            (config.tasks_executor)(Box::pin(async move { background.run().await }));
        }

        Ok(JsonRpcService {
            service_dropped,
            listen_addr,
            virtual_client_io,
        })
    }

    /// Returns the address the server is listening on.
    ///
    /// Returns `None` if and only if [`Config::bind_address`] was `None`. However, if `Some`,
    /// the address is not necessarily equal to the one in [`Config::bind_address`].
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }

    /// Adds a JSON-RPC request to the queue of requests of the virtual endpoint.
    ///
    /// The virtual endpoint doesn't have any limit.
    pub fn send_request(&self, request: String) {
        match self.virtual_client_io.try_send_request(request) {
            Ok(()) => (),
            Err(err) => match err.cause {
                service::TrySendRequestErrorCause::TooManyPendingRequests
                | service::TrySendRequestErrorCause::ClientMainTaskDestroyed => unreachable!(),
            },
        }
    }

    /// Returns the new JSON-RPC response or notification for requests sent using
    /// [`JsonRpcService::send_request`].
    ///
    /// If this function is called multiple times simultaneously, only one invocation will receive
    /// each response. Which one is unspecified.
    pub async fn next_response(&self) -> String {
        match self.virtual_client_io.wait_next_response().await {
            Ok(r) => r,
            Err(service::WaitNextResponseError::ClientMainTaskDestroyed) => unreachable!(),
        }
    }
}

/// Error potentially returned by [`JsonRpcService::new`].
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum InitError {
    /// Failed to listen on the server address.
    #[display("Failed to listen on TCP address {bind_address}: {error}")]
    ListenError {
        /// Address that was attempted.
        bind_address: SocketAddr,
        /// Error returned by the operating system.
        #[error(source)]
        error: io::Error,
    },
}

struct JsonRpcBackground {
    /// TCP listener for new incoming connections.
    tcp_listener: TcpListener,

    /// Event notified when the frontend is dropped.
    on_service_dropped: event_listener::EventListener,

    /// See [`Config::tasks_executor`].
    tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,

    /// See [`Config::log_callback`].
    log_callback: Arc<dyn LogCallback + Send + Sync>,

    /// Database to access blocks.
    database: Arc<database_thread::DatabaseThread>,

    /// Consensus service of the chain.
    consensus_service: Arc<consensus_service::ConsensusService>,

    /// Channel used to send requests to the tasks that process said requests.
    to_requests_handlers: async_channel::Sender<requests_handler::Message>,

    /// Number of clients currently alive.
    num_json_rpc_clients: Arc<AtomicU32>,

    /// See [`Config::max_json_rpc_clients`].
    max_json_rpc_clients: u32,
}

impl JsonRpcBackground {
    async fn run(mut self) {
        loop {
            let Some(accept_result) = future::or(
                async {
                    (&mut self.on_service_dropped).await;
                    None
                },
                async { Some(self.tcp_listener.accept().await) },
            )
            .await
            else {
                return;
            };

            let (tcp_socket, address) = match accept_result {
                Ok(v) => v,
                Err(error) => {
                    // Failing to accept an incoming TCP connection generally happens due to
                    // the limit of file descriptors being reached.
                    // Sleep a little bit and try again.
                    self.log_callback.log(
                        LogLevel::Warn,
                        format!("json-rpc-tcp-listener-error; error={error}"),
                    );
                    smol::Timer::after(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // New incoming TCP connection.

            // Try to increase `num_json_rpc_clients`. Fails if the maximum is reached.
            if self
                .num_json_rpc_clients
                .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |old_value| {
                    if old_value < self.max_json_rpc_clients {
                        // Considering that `old_value < max`, and `max` fits in a `u32` by
                        // definition, then `old_value + 1` also always fits in a `u32`. QED.
                        // There's no risk of overflow.
                        Some(old_value + 1)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                // Reject the socket without sending back anything. Sending back a status
                // code would require allocating resources for that socket, which we
                // specifically don't want to do.
                self.log_callback.log(
                    LogLevel::Debug,
                    format!("json-rpc-incoming-connection-rejected; address={}", address),
                );
                smol::Timer::after(Duration::from_millis(50)).await;
                continue;
            }

            // Spawn two tasks: one for the socket I/O, and one to process requests.
            self.log_callback.log(
                LogLevel::Debug,
                format!("json-rpc-incoming-connection; address={}", address),
            );
            let (client_main_task, io) = service::client_main_task(service::Config {
                max_active_subscriptions: 128,
                max_pending_requests: NonZero::<u32>::new(64).unwrap(),
            });
            spawn_client_io_task(
                &self.tasks_executor,
                self.log_callback.clone(),
                tcp_socket,
                address,
                io,
                self.num_json_rpc_clients.clone(),
            );
            spawn_client_main_task(
                self.tasks_executor.clone(),
                self.consensus_service.clone(),
                self.database.clone(),
                self.to_requests_handlers.clone(),
                client_main_task,
            );
        }
    }
}

fn spawn_client_io_task(
    tasks_executor: &Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,
    log_callback: Arc<dyn LogCallback + Send + Sync>,
    tcp_socket: TcpStream,
    socket_address: SocketAddr,
    io: service::SerializedRequestsIo,
    num_json_rpc_clients: Arc<AtomicU32>,
) {
    let run_future = async move {
        // Perform the WebSocket handshake.
        let (mut ws_sender, mut ws_receiver) = {
            let mut ws_server = soketto::handshake::Server::new(tcp_socket);

            // TODO: enabling the `deflate` extension leads to "flate stream corrupted" errors
            //let deflate = soketto::extension::deflate::Deflate::new(soketto::Mode::Server);
            //ws_server.add_extension(Box::new(deflate));

            let key = match ws_server.receive_request().await {
                Ok(req) => req.key(),
                Err(error) => {
                    log_callback.log(
                        LogLevel::Debug,
                        format!(
                            "json-rpc-connection-error; address={socket_address}, error={error}"
                        ),
                    );
                    return;
                }
            };

            let accept = soketto::handshake::server::Response::Accept {
                key,
                protocol: None,
            };

            match ws_server.send_response(&accept).await {
                Ok(()) => {}
                Err(error) => {
                    log_callback.log(
                        LogLevel::Debug,
                        format!(
                            "json-rpc-connection-error; address={socket_address}, error={error}"
                        ),
                    );
                    return;
                }
            }

            ws_server.into_builder().finish()
        };

        // Create a future responsible for pulling responses and sending them back.
        let sending_future = async {
            let mut must_flush_asap = false;

            loop {
                // If `must_flush_asap`, we simply peek for the next response but without awaiting.
                // If `!must_flush_asap`, we wait for as long as necessary.
                let maybe_response = if must_flush_asap {
                    io.wait_next_response().now_or_never()
                } else {
                    Some(io.wait_next_response().await)
                };

                match maybe_response {
                    None => {
                        if let Err(err) = ws_sender.flush().await {
                            break Err(err.to_string());
                        }
                        must_flush_asap = false;
                    }
                    Some(Ok(response)) => {
                        log_callback.log(
                            LogLevel::Debug,
                            format!(
                                "json-rpc-response; address={}; response={}",
                                socket_address,
                                crate::util::truncated_str(
                                    response.chars().filter(|c| !c.is_control()),
                                    128
                                )
                            ),
                        );

                        if let Err(err) = ws_sender.send_text_owned(response).await {
                            break Err(err.to_string());
                        }
                        must_flush_asap = true;
                    }
                    Some(Err(service::WaitNextResponseError::ClientMainTaskDestroyed)) => {
                        // The client main task never closes by itself but only as a consequence
                        // to the I/O task closing.
                        unreachable!()
                    }
                };
            }
        };

        // Create a future responsible for pulling messages from the socket and sending them to
        // the main task.
        let receiving_future = async {
            let mut message = Vec::new();
            loop {
                message.clear();

                match ws_receiver.receive_data(&mut message).await {
                    Ok(soketto::Data::Binary(_)) => {
                        break Err("Unexpected binary frame".to_string());
                    }
                    Ok(soketto::Data::Text(_)) => {} // Handled below.
                    Err(soketto::connection::Error::Closed) => break Ok(()),
                    Err(err) => {
                        break Err(err.to_string());
                    }
                }

                let request = match String::from_utf8(mem::take(&mut message)) {
                    Ok(r) => r,
                    Err(error) => {
                        break Err(format!("Non-UTF8 text frame: {error}"));
                    }
                };

                log_callback.log(
                    LogLevel::Debug,
                    format!(
                        "json-rpc-request; address={}; request={}",
                        socket_address,
                        crate::util::truncated_str(
                            request.chars().filter(|c| !c.is_control()),
                            128
                        )
                    ),
                );

                match io.send_request(request).await {
                    Ok(()) => {}
                    Err(service::SendRequestError {
                        cause: service::SendRequestErrorCause::ClientMainTaskDestroyed,
                        ..
                    }) => {
                        // The client main task never closes by itself but only as a
                        // consequence to the I/O task closing.
                        unreachable!()
                    }
                }
            }
        };

        // Run these two futures until completion.
        match future::or(sending_future, receiving_future).await {
            Ok(()) => {
                log_callback.log(
                    LogLevel::Debug,
                    format!("json-rpc-connection-closed; address={socket_address}"),
                );
            }
            Err(error) => {
                log_callback.log(
                    LogLevel::Debug,
                    format!("json-rpc-connection-error; address={socket_address}, error={error}"),
                );
            }
        }
    };

    tasks_executor(Box::pin(async move {
        run_future.await;
        num_json_rpc_clients.fetch_sub(1, Ordering::Release);
    }))
}

fn spawn_client_main_task(
    tasks_executor: Arc<dyn Fn(Pin<Box<dyn Future<Output = ()> + Send>>) + Send + Sync>,
    consensus_service: Arc<consensus_service::ConsensusService>,
    database: Arc<database_thread::DatabaseThread>,
    to_requests_handlers: async_channel::Sender<requests_handler::Message>,
    mut client_main_task: service::ClientMainTask,
) {
    let tasks_executor2 = tasks_executor.clone();
    tasks_executor2(Box::pin(async move {
        let mut chain_head_follow_subscriptions: hashbrown::HashMap<
            String,
            async_channel::Sender<chain_head_subscriptions::Message>,
            _,
        > = hashbrown::HashMap::with_capacity_and_hasher(2, fnv::FnvBuildHasher::default());

        loop {
            match client_main_task.run_until_event().await {
                service::Event::HandleRequest {
                    task,
                    request_process,
                } => {
                    client_main_task = task;

                    match request_process.request() {
                        methods::MethodCall::chainHead_v1_header {
                            follow_subscription,
                            ..
                        } => {
                            if let Some(follow_subscription) =
                                chain_head_follow_subscriptions.get_mut(&*follow_subscription)
                            {
                                let _ = follow_subscription
                                    .send(chain_head_subscriptions::Message::Header {
                                        request: request_process,
                                    })
                                    .await;
                                // TODO racy; doesn't handle situation where follow subscription stops
                            } else {
                                request_process
                                    .respond(methods::Response::chainHead_v1_header(None));
                            }
                        }
                        methods::MethodCall::chainHead_v1_unpin {
                            follow_subscription,
                            hash_or_hashes,
                        } => {
                            if let Some(follow_subscription) =
                                chain_head_follow_subscriptions.get_mut(&*follow_subscription)
                            {
                                let block_hashes = match hash_or_hashes {
                                    methods::HashHexStringSingleOrArray::Array(list) => {
                                        list.into_iter().map(|h| h.0).collect::<Vec<_>>()
                                    }
                                    methods::HashHexStringSingleOrArray::Single(hash) => {
                                        vec![hash.0]
                                    }
                                };

                                let (outcome, outcome_rx) = oneshot::channel();
                                let _ = follow_subscription
                                    .send(chain_head_subscriptions::Message::Unpin {
                                        block_hashes,
                                        outcome,
                                    })
                                    .await;

                                match outcome_rx.await {
                                    Err(_) => {
                                        request_process
                                            .respond(methods::Response::chainHead_v1_unpin(()));
                                    }
                                    Ok(Ok(())) => {
                                        request_process
                                            .respond(methods::Response::chainHead_v1_unpin(()));
                                    }
                                    Ok(Err(())) => {
                                        request_process
                                            .fail(service::ErrorResponse::InvalidParams(None));
                                    }
                                }
                            }
                        }
                        _ => {
                            to_requests_handlers
                                .send(requests_handler::Message::Request(request_process))
                                .await
                                .unwrap();
                        }
                    }
                }
                service::Event::HandleSubscriptionStart {
                    task,
                    subscription_start,
                } => {
                    client_main_task = task;

                    match subscription_start.request() {
                        // TODO: enforce limit to number of subscriptions
                        methods::MethodCall::chainHead_v1_follow { with_runtime } => {
                            let (tx, rx) = async_channel::bounded(16);
                            let subscription_id =
                                chain_head_subscriptions::spawn_chain_head_subscription_task(
                                    chain_head_subscriptions::Config {
                                        tasks_executor: tasks_executor.clone(),
                                        receiver: rx,
                                        chain_head_follow_subscription: subscription_start,
                                        with_runtime,
                                        consensus_service: consensus_service.clone(),
                                        database: database.clone(),
                                    },
                                )
                                .await;
                            chain_head_follow_subscriptions.insert(subscription_id, tx);
                        }
                        _ => {
                            to_requests_handlers
                                .send(requests_handler::Message::SubscriptionStart(
                                    subscription_start,
                                ))
                                .await
                                .unwrap();
                        }
                    }
                }
                service::Event::SubscriptionDestroyed {
                    task,
                    subscription_id,
                    ..
                } => {
                    let _ = chain_head_follow_subscriptions.remove(&subscription_id);
                    client_main_task = task;
                }
                service::Event::SerializedRequestsIoClosed => {
                    // JSON-RPC client has disconnected.
                    return;
                }
            }
        }
    }));
}

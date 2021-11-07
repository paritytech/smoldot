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

//! Background network service.
//!
//! The [`NetworkService`] manages background tasks dedicated to connecting to other nodes.
//! Importantly, its design is oriented towards the particular use case of the full node.
//!
//! The [`NetworkService`] spawns one background task (using the [`Config::tasks_executor`]) for
//! each active TCP socket, plus one for each TCP listening socket. Messages are exchanged between
//! the service and these background tasks.

// TODO: doc
// TODO: re-review this once finished

use crate::run::jaeger_service;

use core::{cmp, pin::Pin, task::Poll, time::Duration};
use futures::{channel::mpsc, prelude::*};
use futures_timer::Delay;
use smoldot::{
    informant::HashDisplay,
    libp2p::{
        async_rw_with_buffers, connection,
        multiaddr::{Multiaddr, Protocol},
        peer_id::{self, PeerId},
        read_write::ReadWrite,
    },
    network::{protocol, service},
};
use std::{io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Instant};
use tracing::Instrument as _;

/// Configuration for a [`NetworkService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

    /// Number of event receivers returned by [`NetworkService::new`].
    pub num_events_receivers: usize,

    /// Addresses to listen for incoming connections.
    pub listen_addresses: Vec<Multiaddr>,

    /// List of block chains to be connected to.
    pub chains: Vec<ChainConfig>,

    /// Key used for the encryption layer.
    /// This is a Noise static key, according to the Noise specification.
    /// Signed using the actual libp2p key.
    pub noise_key: connection::NoiseKey,

    /// Service to use to report traces.
    pub jaeger_service: Arc<jaeger_service::JaegerService>,
}

/// Configuration for one chain.
pub struct ChainConfig {
    /// List of node identities and addresses that are known to belong to the chain's peer-to-pee
    /// network.
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,

    /// Hash of the genesis block of the chain. Sent to other nodes in order to determine whether
    /// the chains match.
    pub genesis_block_hash: [u8; 32],

    /// Number and hash of the current best block. Can later be updated with // TODO: which function?
    pub best_block: (u64, [u8; 32]),

    /// Identifier of the chain to connect to.
    ///
    /// Each blockchain has (or should have) a different "protocol id". This value identifies the
    /// chain, so as to not introduce conflicts in the networking messages.
    pub protocol_id: String,

    /// If true, the chain uses the GrandPa networking protocol.
    pub has_grandpa_protocol: bool,
}

/// Event generated by the events reporters returned by [`NetworkService::new`].
#[derive(Debug, Clone)]
pub enum Event {
    Connected {
        chain_index: usize,
        peer_id: PeerId,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    },
    Disconnected {
        chain_index: usize,
        peer_id: PeerId,
    },
    BlockAnnounce {
        chain_index: usize,
        peer_id: PeerId,
        announce: service::EncodedBlockAnnounce,
    },
}

pub struct NetworkService {
    /// Actual network service.
    inner: Arc<Inner>,

    /// Handles connected to all the background tasks of the network service. Makes it possible to
    /// abort everything.
    abort_handles: Vec<future::AbortHandle>,
}

struct Inner {
    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<Instant>,

    /// Identity of the local node.
    local_peer_id: PeerId,

    /// Service to use to report traces.
    jaeger_service: Arc<jaeger_service::JaegerService>,
}

impl NetworkService {
    /// Initializes the network service with the given configuration.
    pub async fn new(
        mut config: Config,
    ) -> Result<(Arc<Self>, Vec<stream::BoxStream<'static, Event>>), InitError> {
        let (mut senders, receivers): (Vec<_>, Vec<_>) = (0..config.num_events_receivers)
            .map(|_| mpsc::channel(16))
            .unzip();

        // TODO: code is messy
        let mut known_nodes =
            Vec::with_capacity(config.chains.iter().map(|c| c.bootstrap_nodes.len()).sum());
        let mut chains = Vec::with_capacity(config.chains.len());
        for chain in config.chains {
            let mut bootstrap_nodes = Vec::with_capacity(chain.bootstrap_nodes.len());
            for (peer_id, addr) in chain.bootstrap_nodes {
                bootstrap_nodes.push(known_nodes.len());
                known_nodes.push((peer_id, addr));
            }

            chains.push(service::ChainConfig {
                bootstrap_nodes,
                in_slots: 25,
                out_slots: 25,
                protocol_id: chain.protocol_id,
                best_hash: chain.best_block.1,
                best_number: chain.best_block.0,
                genesis_hash: chain.genesis_block_hash,
                role: protocol::Role::Full,
                grandpa_protocol_config: if chain.has_grandpa_protocol {
                    // TODO: dummy values
                    Some(service::GrandpaState {
                        commit_finalized_height: 0,
                        round_number: 1,
                        set_id: 0,
                    })
                } else {
                    None
                },
            });
        }

        // Initialize the inner network service.
        let inner = Arc::new(Inner {
            local_peer_id: peer_id::PublicKey::Ed25519(
                *config.noise_key.libp2p_public_ed25519_key(),
            )
            .into_peer_id(),
            network: service::ChainNetwork::new(service::Config {
                now: Instant::now(),
                chains,
                known_nodes,
                connections_capacity: 100, // TODO: ?
                peers_capacity: 100,       // TODO: ?
                noise_key: config.noise_key,
                handshake_timeout: Duration::from_secs(8),
                max_addresses_per_peer: NonZeroUsize::new(5).unwrap(),
                pending_api_events_buffer_size: NonZeroUsize::new(64).unwrap(),
                randomness_seed: rand::random(),
            }),
            jaeger_service: config.jaeger_service,
        });

        let mut abort_handles = Vec::new();

        // Spawn a task pulling events from the network and transmitting them to the event senders.
        (config.tasks_executor)(Box::pin({
            let inner = inner.clone();
            let future = async move {
                loop {
                    let event = loop {
                        match inner.network.next_event(Instant::now()).await {
                            service::Event::Connected(peer_id) => {
                                tracing::debug!(%peer_id, "connected");
                            }
                            service::Event::Disconnected {
                                peer_id,
                                chain_indices,
                            } => {
                                tracing::debug!(%peer_id, "disconnected");
                                if !chain_indices.is_empty() {
                                    debug_assert_eq!(chain_indices.len(), 1); // TODO: not implemented
                                    break Event::Disconnected {
                                        chain_index: chain_indices[0],
                                        peer_id,
                                    };
                                }
                            }
                            service::Event::BlockAnnounce {
                                chain_index,
                                peer_id,
                                announce,
                            } => {
                                let decoded = announce.decode();

                                let mut _jaeger_span = inner.jaeger_service.net_connection_span(
                                    &inner.local_peer_id,
                                    &peer_id,
                                    "block-announce-received",
                                );
                                _jaeger_span.add_int_tag(
                                    "number",
                                    i64::try_from(decoded.header.number).unwrap(),
                                );
                                _jaeger_span
                                    .add_string_tag("hash", &hex::encode(&decoded.header.hash()));

                                tracing::debug!(
                                    %chain_index, %peer_id,
                                    hash = %HashDisplay(&decoded.header.hash()),
                                    number = decoded.header.number,
                                    is_best = ?decoded.is_best,
                                    "block-announce"
                                );

                                break Event::BlockAnnounce {
                                    chain_index,
                                    peer_id,
                                    announce,
                                };
                            }
                            service::Event::ChainConnected {
                                peer_id,
                                chain_index,
                                best_number,
                                best_hash,
                                ..
                            } => {
                                break Event::Connected {
                                    peer_id,
                                    chain_index,
                                    best_block_number: best_number,
                                    best_block_hash: best_hash,
                                };
                            }
                            service::Event::ChainDisconnected {
                                peer_id,
                                chain_index,
                            } => {
                                break Event::Disconnected {
                                    chain_index,
                                    peer_id,
                                };
                            }
                            service::Event::ChainConnectAttemptFailed {
                                peer_id, error, ..
                            } => {
                                tracing::debug!(
                                    %peer_id, %error,
                                    "chain-connect-attempt-failed"
                                );
                            }
                            service::Event::IdentifyRequestIn { peer_id, request } => {
                                tracing::debug!(%peer_id, "identify-request");
                                request.respond("smoldot").await;
                            }
                            service::Event::GrandpaCommitMessage {
                                chain_index,
                                message,
                            } => {
                                tracing::debug!(
                                    %chain_index,
                                    target_hash = %HashDisplay(message.decode().message.target_hash),
                                    "grandpa-commit-message"
                                );
                            }
                            service::Event::ProtocolError { peer_id, error } => {
                                // TODO: handle properly?
                                tracing::warn!(
                                    %peer_id,
                                    %error,
                                    "protocol-error"
                                );
                            }
                        }
                    };

                    // Dispatch the event to the various senders.
                    // This little `if` avoids having to do `event.clone()` if we don't have to.
                    if senders.len() == 1 {
                        let _ = senders[0].send(event).await;
                    } else {
                        for sender in &mut senders {
                            let _ = sender.send(event.clone()).await;
                        }
                    }
                }
            };

            let (abortable, abort_handle) = future::abortable(
                future.instrument(tracing::debug_span!(parent: None, "network-events-poll")),
            );
            abort_handles.push(abort_handle);
            abortable.map(|_| ())
        }));

        // Spawn tasks dedicated to the Kademlia discovery.
        for chain_index in 0..inner.network.num_chains() {
            (config.tasks_executor)(Box::pin({
                let inner = inner.clone();
                let future = async move {
                    let mut next_discovery = Duration::from_secs(1);

                    loop {
                        futures_timer::Delay::new(next_discovery).await;
                        next_discovery = cmp::min(next_discovery * 2, Duration::from_secs(120));

                        match inner
                            .network
                            .kademlia_discovery_round(Instant::now(), chain_index)
                            .await
                        {
                            Ok(insert) => {
                                insert
                                    .insert(&Instant::now())
                                    .instrument(tracing::debug_span!("insert"))
                                    .await
                            }
                            Err(error) => {
                                tracing::debug!(%error, "discovery-error")
                            }
                        }
                    }
                };

                let (abortable, abort_handle) = future::abortable(
                    future.instrument(tracing::debug_span!(parent: None, "kademlia-discovery")),
                );
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }));

            (config.tasks_executor)(Box::pin({
                let inner = inner.clone();
                let future = async move {
                    let mut next_round = Duration::from_millis(500);

                    loop {
                        inner.network.assign_slots(chain_index).await;

                        futures_timer::Delay::new(next_round).await;
                        next_round = cmp::min(next_round * 2, Duration::from_secs(5));
                    }
                };

                let (abortable, abort_handle) = future::abortable(
                    future.instrument(tracing::debug_span!(parent: None, "slots-assign")),
                );
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }));
        }

        // A channel is used to communicate new tasks dedicated to handling connections.
        let (connec_tx, mut connec_rx) = mpsc::channel(num_cpus::get());

        // For each listening address in the configuration, create a background task dedicated to
        // listening on that address.
        for listen_address in config.listen_addresses {
            // Try to parse the requested address and create the corresponding listening socket.
            let tcp_listener: async_std::net::TcpListener = {
                let mut iter = listen_address.iter();
                let proto1 = match iter.next() {
                    Some(p) => p,
                    None => return Err(InitError::BadListenMultiaddr(listen_address)),
                };
                let proto2 = match iter.next() {
                    Some(p) => p,
                    None => return Err(InitError::BadListenMultiaddr(listen_address)),
                };

                if iter.next().is_some() {
                    return Err(InitError::BadListenMultiaddr(listen_address));
                }

                let addr = match (proto1, proto2) {
                    (Protocol::Ip4(ip), Protocol::Tcp(port)) => SocketAddr::from((ip, port)),
                    (Protocol::Ip6(ip), Protocol::Tcp(port)) => SocketAddr::from((ip, port)),
                    _ => return Err(InitError::BadListenMultiaddr(listen_address)),
                };

                match async_std::net::TcpListener::bind(addr).await {
                    Ok(l) => l,
                    Err(err) => {
                        return Err(InitError::ListenerIo(listen_address, err));
                    }
                }
            };

            // Spawn a background task dedicated to this listener.
            (config.tasks_executor)(Box::pin({
                let mut connec_tx = connec_tx.clone();
                let inner = inner.clone();
                let future = async move {
                    loop {
                        let (socket, addr) = match tcp_listener.accept().await {
                            Ok(v) => v,
                            Err(_) => {
                                // Errors here can happen if the accept failed, for example if no file
                                // descriptor is available.
                                // A wait is added in order to avoid having a busy-loop failing to
                                // accept connections.
                                futures_timer::Delay::new(Duration::from_secs(2)).await;
                                continue;
                            }
                        };

                        let multiaddr = Multiaddr::from(addr.ip()).with(Protocol::Tcp(addr.port()));

                        tracing::debug!(%multiaddr, "incoming-connection");

                        let connection_id = inner
                            .network
                            .add_incoming_connection(Instant::now(), multiaddr.clone())
                            .await;

                        // Ignore errors, as it is possible for the destination task to have been
                        // aborted already.
                        let inner = inner.clone();
                        let _ = connec_tx.send(
                            connection_task(socket, inner, connection_id).instrument(
                                tracing::debug_span!(parent: None, "connection", address = %multiaddr),
                            ).boxed()
                        ).await;
                    }
                };

                let (abortable, abort_handle) = future::abortable(future.instrument(
                    tracing::trace_span!(parent: None, "listener", address = %listen_address),
                ));
                abort_handles.push(abort_handle);
                abortable.map(|_| ())
            }))
        }

        // Spawn task dedicated to opening connections.
        // TODO: spawn multiple of these tasks and block them on the connection attempt; not possible now because `next_start_connect` has a bug
        (config.tasks_executor)(Box::pin({
            let inner = inner.clone();
            let mut connec_tx = connec_tx.clone();
            let future = async move {
                loop {
                    let start_connect = inner.network.next_start_connect(Instant::now()).await;

                    let span = tracing::debug_span!("start-connect", ?start_connect.id, %start_connect.multiaddr);
                    let _enter = span.enter();

                    // Convert the `multiaddr` (typically of the form `/ip4/a.b.c.d/tcp/d`) into
                    // a `Future<dyn Output = Result<TcpStream, ...>>`.
                    let socket = match multiaddr_to_socket(&start_connect.multiaddr) {
                        Ok(socket) => socket,
                        Err(_) => {
                            tracing::debug!(%start_connect.multiaddr, "not-tcp");
                            inner
                                .network
                                .pending_outcome_err(start_connect.id, true)
                                .await;
                            continue;
                        }
                    };

                    // TODO: handle dialing timeout here

                    // Ignore errors, as it is possible for the destination task to have been
                    // aborted already.
                    let inner = inner.clone();
                    let _ = connec_tx.send(pending_connection_task(socket, start_connect.timeout, inner, start_connect.id).instrument(
                        tracing::trace_span!(parent: None, "connection", address = %start_connect.multiaddr),
                    ).boxed()).await;
                }
            };

            let (abortable, abort_handle) = future::abortable(
                future.instrument(tracing::trace_span!(parent: None, "tcp-dial")),
            );
            abort_handles.push(abort_handle);
            abortable.map(|_| ())
        }));

        // Spawn task dedicated to processing connections.
        // A single task is responsible for all connections, thereby ensuring that the networking
        // won't use more than a single CPU core.
        (config.tasks_executor)(Box::pin({
            let future = async move {
                let mut connections = stream::FuturesUnordered::new();
                loop {
                    futures::select! {
                        new_connec = connec_rx.select_next_some() => {
                            connections.push(new_connec);
                        },
                        () = connections.select_next_some() => {},
                    }
                }
            };

            let (abortable, abort_handle) = future::abortable(
                future.instrument(tracing::trace_span!(parent: None, "connections-executor")),
            );
            abort_handles.push(abort_handle);
            abortable.map(|_| ())
        }));

        // Build the final network service.
        let network_service = Arc::new(NetworkService {
            inner,
            abort_handles: {
                abort_handles.shrink_to_fit();
                abort_handles
            },
        });

        // Adjust the receivers to keep the `network_service` alive.
        let receivers = receivers
            .into_iter()
            .map(|rx| {
                let mut network_service = Some(network_service.clone());
                rx.chain(stream::poll_fn(move |_| {
                    drop(network_service.take());
                    Poll::Ready(None)
                }))
                .boxed()
            })
            .collect();

        Ok((network_service, receivers))
    }

    /// Returns the number of established TCP connections, both incoming and outgoing.
    pub async fn num_established_connections(&self) -> usize {
        self.inner.network.num_established_connections().await
    }

    /// Returns the number of peers we have a substream with.
    pub async fn num_peers(&self, chain_index: usize) -> usize {
        self.inner.network.num_peers(chain_index).await
    }

    pub async fn set_local_best_block(
        &self,
        chain_index: usize,
        best_hash: [u8; 32],
        best_number: u64,
    ) {
        self.inner
            .network
            .set_local_best_block(chain_index, best_hash, best_number)
            .await
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    // TODO: proper error type
    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn blocks_request(
        self: Arc<Self>,
        target: PeerId, // TODO: by value?
        chain_index: usize,
        config: protocol::BlocksRequestConfig,
    ) -> Result<Vec<protocol::BlockData>, service::BlocksRequestError> {
        self.inner
            .network
            .blocks_request(Instant::now(), &target, chain_index, config)
            .await
    }
}

impl Drop for NetworkService {
    fn drop(&mut self) {
        for handle in &mut self.abort_handles {
            handle.abort();
        }
    }
}

/// Error when initializing the network service.
#[derive(Debug, derive_more::Display)]
pub enum InitError {
    /// I/O error when initializing a listener.
    #[display(fmt = "I/O error when creating listener for {}: {}", _0, _1)]
    ListenerIo(Multiaddr, io::Error),
    /// A listening address passed through the configuration isn't valid.
    BadListenMultiaddr(Multiaddr),
}

/// Asynchronous task managing a specific TCP connection.
#[tracing::instrument(level = "trace", skip(tcp_socket, network_service))]
async fn pending_connection_task(
    tcp_socket: impl Future<Output = Result<async_std::net::TcpStream, io::Error>>,
    timeout: Instant,
    network_service: Arc<Inner>,
    id: service::PendingId,
) {
    // Finishing ongoing connection process.
    let tcp_socket = {
        let now = Instant::now();
        let mut timeout = Delay::new(if timeout >= now {
            timeout - now
        } else {
            // `timeout - now` would panic
            Duration::new(0, 0)
        })
        .fuse();
        let tcp_socket = tcp_socket.fuse();
        futures::pin_mut!(tcp_socket);
        futures::select! {
            _ = timeout => {
                network_service.network.pending_outcome_err(id, false).await;
                return;
            }
            result = tcp_socket => {
                match result {
                    Ok(s) => s,
                    Err(_) => {
                        network_service.network.pending_outcome_err(id, true).await;
                        return;
                    }
                }
            }
        }
    };

    let id = network_service.network.pending_outcome_ok(id).await;
    connection_task(tcp_socket, network_service, id).await;
}

/// Asynchronous task managing a specific TCP connection.
#[tracing::instrument(level = "trace", skip(tcp_socket, network_service))]
async fn connection_task(
    tcp_socket: async_std::net::TcpStream,
    network_service: Arc<Inner>,
    id: service::ConnectionId,
) {
    // The Nagle algorithm, implemented in the kernel, consists in buffering the data to be sent
    // out and waiting a bit before actually sending it out, in order to potentially merge
    // multiple writes in a row into one packet. In the implementation below, it is guaranteed
    // that the buffer in `WithBuffers` is filled with as much data as possible before the
    // operating system gets involved. As such, we disable the Nagle algorithm, in order to avoid
    // adding an artificial delay to all sends.
    let _ = tcp_socket.set_nodelay(true);

    // The socket is wrapped around a `WithBuffers` object containing a read buffer and a write
    // buffer. These are the buffers whose pointer is passed to `read(2)` and `write(2)` when
    // reading/writing the socket.
    let tcp_socket = async_rw_with_buffers::WithBuffers::new(tcp_socket);
    futures::pin_mut!(tcp_socket);

    loop {
        let (read_buffer, write_buffer) = match tcp_socket.buffers() {
            Ok(b) => b,
            Err(error) => {
                tracing::debug!(%error, "task-finished");
                // TODO: report disconnect to service
                return;
            }
        };

        let now = Instant::now();

        let mut read_write = ReadWrite {
            now,
            incoming_buffer: read_buffer.map(|b| b.0),
            outgoing_buffer: write_buffer,
            read_bytes: 0,
            written_bytes: 0,
            wake_up_after: None,
            wake_up_future: None,
        };

        match network_service
            .network
            .read_write(id, &mut read_write)
            .await
        {
            Ok(rw) => rw,
            Err(error) => {
                // Make sure to finish closing the TCP socket.
                tcp_socket
                    .flush_close()
                    .instrument(tracing::debug_span!("flush-close"))
                    .await;
                tracing::debug!(%error, "task-finished");
                return;
            }
        };

        if read_write.read_bytes != 0
            || read_write.written_bytes != 0
            || read_write.outgoing_buffer.is_none()
        {
            tracing::event!(
                tracing::Level::TRACE,
                read = read_write.read_bytes,
                written = read_write.written_bytes,
                "wake-up" = ?read_write.wake_up_after,  // TODO: ugly display
                "write-close" = read_write.outgoing_buffer.is_none(),
            );
        }

        let read_bytes = read_write.read_bytes;
        let written_bytes = read_write.written_bytes;
        let write_closed = read_write.outgoing_buffer.is_none();
        let wake_up_after = read_write.wake_up_after;
        let wake_up_future = if let Some(wake_up_future) = read_write.wake_up_future {
            future::Either::Left(wake_up_future)
        } else {
            future::Either::Right(future::pending())
        };

        if write_closed && !tcp_socket.is_closed() {
            tcp_socket.close();
            tracing::debug!("write-closed");
        }

        tcp_socket.advance(read_bytes, written_bytes);

        let mut poll_after = if let Some(wake_up) = wake_up_after {
            if wake_up > now {
                let dur = wake_up - now;
                future::Either::Left(futures_timer::Delay::new(dur))
            } else {
                continue;
            }
        } else {
            future::Either::Right(future::pending())
        }
        .fuse();

        futures::select! {
            _ = tcp_socket.as_mut().process().fuse() => {
                tracing::event!(
                    tracing::Level::TRACE,
                    "socket-ready"
                );
            },
            _ = wake_up_future.fuse() => {},
            () = poll_after => {
                // Nothing to do, but guarantees that we loop again.
                tracing::event!(
                    tracing::Level::TRACE,
                    "timer-ready"
                );
            }
        }
    }
}

/// Builds a future that connects to the given multiaddress. Returns an error if the multiaddress
/// protocols aren't supported.
fn multiaddr_to_socket(
    addr: &Multiaddr,
) -> Result<impl Future<Output = Result<async_std::net::TcpStream, io::Error>>, ()> {
    let mut iter = addr.iter();
    let proto1 = iter.next().ok_or(())?;
    let proto2 = iter.next().ok_or(())?;

    if iter.next().is_some() {
        return Err(());
    }

    // Ensure ahead of time that the multiaddress is supported.
    match (&proto1, &proto2) {
        (Protocol::Ip4(_), Protocol::Tcp(_))
        | (Protocol::Ip6(_), Protocol::Tcp(_))
        | (Protocol::Dns(_), Protocol::Tcp(_))
        | (Protocol::Dns4(_), Protocol::Tcp(_))
        | (Protocol::Dns6(_), Protocol::Tcp(_)) => {}
        _ => return Err(()),
    }

    let proto1 = proto1.acquire();
    let proto2 = proto2.acquire();

    Ok(async move {
        match (proto1, proto2) {
            (Protocol::Ip4(ip), Protocol::Tcp(port)) => {
                async_std::net::TcpStream::connect(SocketAddr::new(ip.into(), port)).await
            }
            (Protocol::Ip6(ip), Protocol::Tcp(port)) => {
                async_std::net::TcpStream::connect(SocketAddr::new(ip.into(), port)).await
            }
            // TODO: for DNS, do things a bit more explicitly? with for example a library that does the resolution?
            // TODO: differences between DNS, DNS4, DNS6 not respected
            (Protocol::Dns(addr), Protocol::Tcp(port))
            | (Protocol::Dns4(addr), Protocol::Tcp(port))
            | (Protocol::Dns6(addr), Protocol::Tcp(port)) => {
                async_std::net::TcpStream::connect((&*addr, port)).await
            }
            _ => unreachable!(),
        }
    })
}

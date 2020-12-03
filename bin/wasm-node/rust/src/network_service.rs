// Substrate-lite
// Copyright (C) 2019-2020  Parity Technologies (UK) Ltd.
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

use crate::ffi;

use core::{num::NonZeroUsize, pin::Pin, time::Duration};
use futures::{lock::Mutex, prelude::*};
use std::sync::Arc;
use substrate_lite::network::{
    connection,
    multiaddr::{Multiaddr, Protocol},
    peer_id::PeerId,
    protocol, service,
};

/// Configuration for a [`NetworkService`].
pub struct Config {
    /// Closure that spawns background tasks.
    pub tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,

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
}

pub struct NetworkService {
    /// Fields behind a mutex.
    guarded: Mutex<Guarded>,

    /// Data structure holding the entire state of the networking.
    network: service::ChainNetwork<ffi::Instant, (), ()>,
}

/// Fields of [`NetworkService`] behind a mutex.
struct Guarded {
    /// See [`Config::tasks_executor`].
    tasks_executor: Box<dyn FnMut(Pin<Box<dyn Future<Output = ()> + Send>>) + Send>,
}

impl NetworkService {
    /// Initializes the network service with the given configuration.
    pub async fn new(config: Config) -> Result<Arc<Self>, InitError> {
        Ok(Arc::new(NetworkService {
            guarded: Mutex::new(Guarded {
                tasks_executor: config.tasks_executor,
            }),
            network: service::ChainNetwork::new(service::Config {
                chains: vec![service::ChainConfig {
                    bootstrap_nodes: (0..config.bootstrap_nodes.len()).collect(),
                    in_slots: 25,
                    out_slots: 25,
                    protocol_id: config.protocol_id,
                    best_hash: config.best_block.1,
                    best_number: config.best_block.0,
                    genesis_hash: config.genesis_block_hash,
                    role: protocol::Role::Full,
                }],
                known_nodes: config
                    .bootstrap_nodes
                    .into_iter()
                    .map(|(peer_id, addr)| ((), peer_id, addr))
                    .collect(),
                listen_addresses: Vec::new(), // TODO:
                noise_key: connection::NoiseKey::new(&rand::random()),
                pending_api_events_buffer_size: NonZeroUsize::new(64).unwrap(),
                randomness_seed: rand::random(),
            }),
        }))
    }

    /// Sends a blocks request to the given peer.
    // TODO: more docs
    pub async fn blocks_request(
        self: Arc<Self>,
        target: PeerId,
        config: protocol::BlocksRequestConfig,
    ) -> Result<Vec<protocol::BlockData>, service::BlocksRequestError> {
        self.network
            .blocks_request(ffi::Instant::now(), target, 0, config)
            .await // TODO: chain_index
    }

    /// Sends a storage proof request to the given peer.
    // TODO: more docs
    pub async fn storage_proof_request(
        self: Arc<Self>,
        target: PeerId,
        config: protocol::StorageProofRequestConfig<impl Iterator<Item = impl AsRef<[u8]>>>,
    ) -> Result<Vec<Vec<u8>>, service::StorageProofRequestError> {
        self.network
            .storage_proof_request(ffi::Instant::now(), target, 0, config)
            .await // TODO: chain_index
    }

    /// Returns the next event that happens in the network service.
    ///
    /// If this method is called multiple times simultaneously, the events will be distributed
    /// amongst the different calls in an unpredictable way.
    pub async fn next_event(self: &Arc<Self>) -> Event {
        loop {
            match self.network.next_event().await {
                service::Event::Connected(peer_id) => return Event::Connected(peer_id),
                service::Event::Disconnected(peer_id) => return Event::Disconnected(peer_id),
                service::Event::StartConnect { id, multiaddr } => {
                    // Convert the `multiaddr` (typically of the form `/ip4/a.b.c.d/tcp/d/ws`)
                    // into a `Future<dyn Output = Result<TcpStream, ...>>`.
                    let socket = match multiaddr_to_url(&multiaddr) {
                        Ok(url) => ffi::WebSocket::connect(&url),
                        Err(_) => {
                            self.network.pending_outcome_err(id).await;
                            continue;
                        }
                    };

                    let mut guarded = self.guarded.lock().await;
                    (guarded.tasks_executor)(Box::pin(connection_task(socket, self.clone(), id)));
                }
            }
        }
    }
}

/// Event that can happen on the network service.
pub enum Event {
    Connected(PeerId),
    Disconnected(PeerId),
}

/// Error when initializing the network service.
#[derive(Debug, derive_more::Display)]
pub enum InitError {
    // TODO: add variants or remove error altogether
}

/// Asynchronous task managing a specific WebSocket connection.
async fn connection_task(
    websocket: impl Future<Output = Result<Pin<Box<ffi::WebSocket>>, ()>>,
    network_service: Arc<NetworkService>,
    id: service::PendingId,
) {
    // Finishing the ongoing connection process.
    let mut websocket = match websocket.await {
        Ok(s) => s,
        Err(_) => {
            network_service.network.pending_outcome_err(id).await;
            return;
        }
    };

    let id = network_service.network.pending_outcome_ok(id, ()).await;

    // Set to a timer after which the state machine of the connection needs an update.
    let mut poll_after: ffi::Delay;

    let mut write_buffer = vec![0; 4096];

    loop {
        let read_buffer = websocket.read_buffer().now_or_never().unwrap_or(Some(&[]));

        let now = ffi::Instant::now();

        // TODO: hacky code
        struct Waker(std::sync::Mutex<(bool, Option<std::task::Waker>)>);
        impl futures::task::ArcWake for Waker {
            fn wake_by_ref(arc_self: &Arc<Self>) {
                let mut lock = arc_self.0.lock().unwrap();
                lock.0 = true;
                if let Some(w) = lock.1.take() {
                    w.wake();
                }
            }
        }

        let waker = Arc::new(Waker(std::sync::Mutex::new((false, None))));

        let read_write = match network_service
            .network
            .read_write(
                id,
                now,
                read_buffer,
                (&mut write_buffer, &mut []),
                &mut std::task::Context::from_waker(&*futures::task::waker_ref(&waker)),
            )
            .await
        {
            Ok(rw) => rw,
            Err(_) => {
                return;
            }
        };

        if read_write.write_close && read_buffer.is_none() {
            return;
        }

        if let Some(wake_up) = read_write.wake_up_after {
            if wake_up > now {
                let dur = wake_up - now;
                poll_after = ffi::Delay::new(dur);
            } else {
                poll_after = ffi::Delay::new(Duration::from_secs(0));
            }
        } else {
            poll_after = ffi::Delay::new(Duration::from_secs(3600));
        }

        websocket.send(&write_buffer[..read_write.written_bytes]);

        websocket.advance_read_cursor(read_write.read_bytes);

        if read_write.read_bytes != 0 || read_write.written_bytes != 0 {
            continue;
        }

        // TODO: maybe optimize the code below so that multiple messages are pulled from `to_connection` at once

        futures::select! {
            _ = websocket.read_buffer().fuse() => {},
            _ = future::poll_fn(move |cx| {
                let mut lock = waker.0.lock().unwrap();
                if lock.0 {
                    return std::task::Poll::Ready(());
                }
                match lock.1 {
                    Some(ref w) if w.will_wake(cx.waker()) => {}
                    _ => lock.1 = Some(cx.waker().clone()),
                }
                std::task::Poll::Pending
            }).fuse() => {}
            _ = (&mut poll_after).fuse() => { // TODO: no, ref mut + fuse() = probably panic
                // Nothing to do, but guarantees that we loop again.
            },
        }
    }
}

/// Returns the URL that corresponds to the given multiaddress. Returns an error if the
/// multiaddress protocols aren't supported.
fn multiaddr_to_url(addr: &Multiaddr) -> Result<String, ()> {
    let mut iter = addr.iter();
    let proto1 = iter.next().ok_or(())?;
    let proto2 = iter.next().ok_or(())?;
    let proto3 = iter.next().ok_or(())?;

    if iter.next().is_some() {
        return Err(());
    }

    match (proto1, proto2, proto3) {
        (Protocol::Ip4(ip), Protocol::Tcp(port), Protocol::Ws(url)) => {
            Ok(format!("ws://{}:{}{}", ip, port, url))
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), Protocol::Ws(url)) => {
            Ok(format!("ws://[{}]:{}{}", ip, port, url))
        }
        (Protocol::Ip4(ip), Protocol::Tcp(port), Protocol::Wss(url)) => {
            Ok(format!("wss://{}:{}{}", ip, port, url))
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), Protocol::Wss(url)) => {
            Ok(format!("wss://[{}]:{}{}", ip, port, url))
        }
        (Protocol::Dns(domain), Protocol::Tcp(port), Protocol::Ws(url))
        | (Protocol::Dns4(domain), Protocol::Tcp(port), Protocol::Ws(url))
        | (Protocol::Dns6(domain), Protocol::Tcp(port), Protocol::Ws(url)) => {
            Ok(format!("ws://{}:{}{}", domain, port, url))
        }
        (Protocol::Dns(domain), Protocol::Tcp(port), Protocol::Wss(url))
        | (Protocol::Dns4(domain), Protocol::Tcp(port), Protocol::Wss(url))
        | (Protocol::Dns6(domain), Protocol::Tcp(port), Protocol::Wss(url)) => {
            Ok(format!("wss://{}:{}{}", domain, port, url))
        }
        _ => Err(()),
    }
}

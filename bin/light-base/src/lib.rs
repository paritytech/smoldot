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

#![recursion_limit = "512"]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(unused_crate_dependencies)]

use futures::{channel::mpsc, prelude::*};
use std::{marker::PhantomData, ops, time::Duration};

#[derive(Debug, derive_more::Display)]
pub enum HandleRpcError {
    /// The JSON-RPC service cannot process this request, as it is already too busy.
    #[display(
        fmt = "The JSON-RPC service cannot process this request, as it is already too busy."
    )]
    Overloaded {
        /// Value that was passed as parameter to [`JsonRpcService::queue_rpc_request`].
        json_rpc_request: String,
    },
}

/// See [`Client::add_chain`].
#[derive(Debug, Clone)]
pub struct AddChainConfig<'a, TChain, TRelays> {
    /// Opaque user data that the [`Client`] will hold for this chain.
    pub user_data: TChain,

    /// JSON text containing the specification of the chain (the so-called "chain spec").
    pub specification: &'a str,

    /// Opaque data containing the database content that was retrieved by calling
    /// [`Client::database_content`] in the past.
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
    /// For example: if user A adds a chain named "kusama", then user B adds a different chain
    /// also named "kusama", then user B adds a parachain whose relay chain is "kusama", it would
    /// be wrong to connect to the "kusama" created by user A.
    pub potential_relay_chains: TRelays,

    /// Channel to use to send the JSON-RPC responses.
    ///
    /// If `None`, then no JSON-RPC service is started for this chain. This saves up a lot of
    /// resources, but will cause all JSON-RPC requests targetting this chain to fail.
    pub json_rpc_responses: Option<mpsc::Sender<String>>,
}

/// Access to a platform's capabilities.
pub trait Platform: Send + 'static {
    type Delay: Future<Output = ()> + Unpin + Send + 'static;
    type Instant: Clone
        + ops::Add<Duration, Output = Self::Instant>
        + ops::Sub<Self::Instant, Output = Duration>
        + PartialOrd
        + Ord
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static;
    type Connection: Send + Sync + 'static;
    type ConnectFuture: Future<Output = Result<Self::Connection, ConnectError>>
        + Unpin
        + Send
        + 'static;
    type ConnectionDataFuture: Future<Output = ()> + Unpin + Send + 'static;

    /// Returns the time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time)
    /// (i.e. 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    fn now_from_unix_epoch() -> Duration;

    /// Returns an object that represents "now".
    fn now() -> Self::Instant;

    /// Creates a future that becomes ready after at least the given duration has elapsed.
    fn sleep(duration: Duration) -> Self::Delay;

    /// Creates a future that becomes ready after the given instant has been reached.
    fn sleep_until(when: Self::Instant) -> Self::Delay;

    /// Starts a connection attempt to the given multiaddress.
    ///
    /// The multiaddress is passed as a string. If the string can't be parsed, an error should be
    /// returned where [`ConnectError::is_bad_addr`] is `true`.
    fn connect(url: &str) -> Self::ConnectFuture;

    /// Returns a future that becomes ready when either the read buffer of the given connection
    /// contains data, or the remote has closed their sending side.
    ///
    /// The future is immediately ready if data is already available or the remote has already
    /// closed their sending side.
    ///
    /// This function can be called multiple times with the same connection, in which case all
    /// the futures must be notified. The user of this function, however, is encouraged to
    /// maintain only one active future.
    ///
    /// If the future is polled after the connection object has been dropped, the behaviour is
    /// not specified. The polling might panic, or return `Ready`, or return `Pending`.
    fn wait_more_data(connection: &mut Self::Connection) -> Self::ConnectionDataFuture;

    /// Gives access to the content of the read buffer of the given connection.
    ///
    /// Returns `None` if the remote has closed their sending side.
    fn read_buffer(connection: &mut Self::Connection) -> Option<&[u8]>;

    /// Discards the first `bytes` bytes of the read buffer of this connection. This makes it
    /// possible for the remote to send more data.
    ///
    /// # Panic
    ///
    /// Panics if there aren't enough bytes to discard in the buffer.
    ///
    fn advance_read_cursor(connection: &mut Self::Connection, bytes: usize);

    /// Queues the given bytes to be sent out on the given connection.
    // TODO: back-pressure
    fn send(connection: &mut Self::Connection, data: &[u8]);
}

/// Error potentially returned by [`Platform::connect`].
pub struct ConnectError {
    /// Human-readable error message.
    pub message: String,

    /// `true` if the error is caused by the address to connect to being forbidden or unsupported.
    pub is_bad_addr: bool,
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

pub struct Client<TChain, TPlat: Platform> {
    marker: PhantomData<(TChain, TPlat)>,
}

impl<TChain, TPlat: Platform> Client<TChain, TPlat> {
    /// Initializes the smoldot Wasm client.
    ///
    /// In order for the client to function, it needs to be able to spawn tasks in the background
    /// that will run indefinitely. To do so, the `tasks_spawner` channel must be provided and that
    /// the clients can send tasks to run to. The first tuple element is the name of the task used
    /// for debugging purposes.
    pub fn new(
        tasks_spawner: mpsc::UnboundedSender<(String, future::BoxFuture<'static, ()>)>,
        system_name: String,
        system_version: String,
    ) -> Self {
        Client {
            marker: PhantomData,
        }
    }

    /// Adds a new chain to the list of chains smoldot tries to synchronize.
    pub fn add_chain(
        &mut self,
        config: AddChainConfig<'_, TChain, impl Iterator<Item = ChainId>>,
    ) -> ChainId {
        ChainId(0)
    }

    /// Adds a new dummy chain to the list of chains.
    ///
    /// The [`Client::chain_is_erroneous`] function for this chain returns `Some` with the given
    /// error message.
    pub fn add_erroneous_chain(&mut self, error_message: String, user_data: TChain) -> ChainId {
        ChainId(0)
    }

    /// If [`Client::add_chain`] encountered an error when creating this chain, returns the error
    /// message corresponding to it.
    pub fn chain_is_erroneous(&self, id: ChainId) -> Option<&str> {
        None
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
    #[must_use]
    pub fn remove_chain(&mut self, id: ChainId) -> TChain {
        panic!()
    }

    /// Returns the user data associated to the given chain.
    ///
    /// # Panic
    ///
    /// Panics if the [`ChainId`] is invalid.
    ///
    pub fn chain_user_data_mut(&mut self, chain_id: ChainId) -> &mut TChain {
        panic!()
    }

    /// Enqueues a JSON-RPC request towards the given chain.
    ///
    /// Since most JSON-RPC requests can only be answered asynchronously, the request is only
    /// queued and will be decoded and processed later.
    /// Requests that are not valid JSON-RPC will be silently ignored.
    ///
    /// Returns an error if the node is overloaded and is capable of processing more JSON-RPC
    /// requests before some time has passed or the [`AddChainConfig::json_rpc_responses`] channel
    /// emptied.
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
        Ok(())
    }

    /// Returns opaque data that can later by passing back through
    /// [`AddChainConfig::database_content`].
    ///
    /// Note that the `Future` being returned doesn't borrow `self`. Even if the chain is later
    /// removed, this `Future` will still return a value.
    ///
    /// If the database content can't be obtained because not enough information is known about
    /// the chain, a dummy value is intentionally returned.
    ///
    /// # Panic
    ///
    /// Panics if the [`ChainId`] is invalid.
    ///
    pub fn database_content(&self, chain_id: ChainId) -> impl Future<Output = String> {
        async move { String::new() }
    }
}

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

use core::{ops, str, time::Duration};
use futures::prelude::*;
use smoldot::libp2p::peer_id::PeerId;

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

    /// A multi-stream connection.
    ///
    /// This object is merely a handle. The underlying connection should be dropped only after
    /// the `Connection` and all its associated substream objects ([`Platform::Stream`]) have
    /// been dropped.
    type Connection: Send + Sync + 'static;
    type Stream: Send + Sync + 'static;
    type ConnectFuture: Future<Output = Result<PlatformConnection<Self::Stream, Self::Connection>, ConnectError>>
        + Unpin
        + Send
        + 'static;
    type StreamDataFuture: Future<Output = ()> + Unpin + Send + 'static;
    type NextSubstreamFuture: Future<Output = Option<(Self::Stream, PlatformSubstreamDirection)>>
        + Unpin
        + Send
        + 'static;

    /// Returns the time elapsed since [the Unix Epoch](https://en.wikipedia.org/wiki/Unix_time)
    /// (i.e. 00:00:00 UTC on 1 January 1970), ignoring leap seconds.
    ///
    /// # Panic
    ///
    /// Panics if the system time is configured to be below the UNIX epoch. This situation is a
    /// very very niche edge case that isn't worth handling.
    ///
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

    /// Queues the opening of an additional outbound substream.
    ///
    /// The substream, once opened, must be yielded by [`Platform::next_substream`].
    fn open_out_substream(connection: &mut Self::Connection);

    /// Waits until a new incoming substream arrives on the connection.
    ///
    /// This returns both inbound and outbound substreams. Outbound substreams should only be
    /// yielded once for every call to [`Platform::open_out_substream`].
    ///
    /// The future can also return `None` if the connection has been killed by the remote. If
    /// the future returns `None`, the user of the `Platform` should drop the `Connection` and
    /// all its associated `Stream`s as soon as possible.
    fn next_substream(connection: &mut Self::Connection) -> Self::NextSubstreamFuture;

    /// Returns a future that becomes ready when either the read buffer of the given stream
    /// contains data, or the remote has closed their sending side.
    ///
    /// The future is immediately ready if data is already available or the remote has already
    /// closed their sending side.
    ///
    /// This function can be called multiple times with the same stream, in which case all
    /// the futures must be notified. The user of this function, however, is encouraged to
    /// maintain only one active future.
    ///
    /// If the future is polled after the stream object has been dropped, the behavior is
    /// not specified. The polling might panic, or return `Ready`, or return `Pending`.
    fn wait_more_data(stream: &mut Self::Stream) -> Self::StreamDataFuture;

    /// Gives access to the content of the read buffer of the given stream.
    ///
    /// Returns `None` if the remote has closed their sending side or if the stream has been
    /// reset.
    fn read_buffer(stream: &mut Self::Stream) -> Option<&[u8]>;

    /// Discards the first `bytes` bytes of the read buffer of this stream. This makes it
    /// possible for the remote to send more data.
    ///
    /// # Panic
    ///
    /// Panics if there aren't enough bytes to discard in the buffer.
    ///
    fn advance_read_cursor(stream: &mut Self::Stream, bytes: usize);

    /// Queues the given bytes to be sent out on the given connection.
    // TODO: back-pressure
    // TODO: allow closing sending side
    fn send(stream: &mut Self::Stream, data: &[u8]);
}

/// Type of opened connection. See [`Platform::connect`].
#[derive(Debug)]
pub enum PlatformConnection<TStream, TConnection> {
    /// The connection is a single stream on top of which encryption and multiplexing should be
    /// negotiated. The division in multiple substreams is handled internally.
    SingleStream(TStream),
    /// The connection is made of multiple substreams. The encryption and multiplexing are handled
    /// externally.
    MultiStream(TConnection, PeerId),
}

/// Direction in which a substream has been opened. See [`Platform::next_substream`].
#[derive(Debug)]
pub enum PlatformSubstreamDirection {
    /// Substream has been opened by the remote.
    Inbound,
    /// Substream has been opened locally in response to [`Platform::open_out_substream`].
    Outbound,
}

/// Error potentially returned by [`Platform::connect`].
pub struct ConnectError {
    /// Human-readable error message.
    pub message: String,

    /// `true` if the error is caused by the address to connect to being forbidden or unsupported.
    pub is_bad_addr: bool,
}

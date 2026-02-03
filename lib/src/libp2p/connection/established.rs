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

mod multi_stream;
mod single_stream;
pub mod substream;
mod tests;

use super::yamux;
use alloc::{string::String, vec::Vec};
use core::time::Duration;

pub use multi_stream::{MultiStream, SubstreamFate};
pub use single_stream::{ConnectionPrototype, Error, SingleStream};
pub use substream::{
    BitswapInClosedErr, BitswapOutClosedErr, BitswapOutOpenErr, InboundError, InboundTy,
    NotificationsInClosedErr, NotificationsOutErr, RequestError, RespondInRequestError,
};

/// Identifier of a request or a notifications substream.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubstreamId(SubstreamIdInner);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SubstreamIdInner {
    SingleStream(yamux::SubstreamId),
    MultiStream(u32),
}

impl SubstreamId {
    /// Value that compares inferior or equal to all possible values.
    pub const MIN: Self = Self(SubstreamIdInner::SingleStream(yamux::SubstreamId::MIN));
    /// Value that compares superior or equal to all possible values.
    pub const MAX: Self = Self(SubstreamIdInner::MultiStream(u32::MAX));
}

/// Event that happened on the connection. See [`SingleStream::read_write`] and
/// [`MultiStream::pull_event`].
#[must_use]
#[derive(Debug)]
pub enum Event<TSubUd> {
    /// The connection is now in a mode where opening new substreams (i.e. starting requests
    /// and opening notifications substreams) is forbidden, but the remote is still able to open
    /// substreams and messages on existing substreams are still allowed to be sent and received.
    NewOutboundSubstreamsForbidden,

    /// Received an incoming substream, but this substream has produced an error.
    ///
    /// > **Note**: This event exists only for diagnostic purposes. No action is expected in
    /// >           return.
    InboundError(InboundError),

    /// An inbound substream has requested to use a protocol. Call
    /// [`SingleStream::accept_inbound`], [`SingleStream::reject_inbound`],
    /// [`MultiStream::accept_inbound`], or [`MultiStream::reject_inbound`] in order to accept or
    /// reject this substream.
    InboundNegotiated {
        /// Identifier of the request. Needs to be provided back when accepting or rejecting
        /// the protocol.
        id: SubstreamId,
        /// Name of the protocol requested by the remote.
        protocol_name: String,
    },

    /// An inbound substream that is waiting for a call to [`SingleStream::accept_inbound`],
    /// [`SingleStream::reject_inbound`], [`MultiStream::accept_inbound`], or
    /// [`MultiStream::reject_inbound`] has been abruptly closed.
    InboundNegotiatedCancel {
        /// Identifier of the substream.
        id: SubstreamId,
    },

    /// An inbound substream that was previously accepted using [`SingleStream::accept_inbound`]
    /// or [`MultiStream::accept_inbound`] was closed by the remote or has generated an error.
    InboundAcceptedCancel {
        /// Identifier of the substream.
        id: SubstreamId,
        /// Value that was passed to [`SingleStream::accept_inbound`] or
        /// [`MultiStream::accept_inbound`].
        user_data: TSubUd,
    },

    /// Received a request in the context of a request-response protocol.
    RequestIn {
        /// Identifier of the request. Needs to be provided back when answering the request.
        id: SubstreamId,
        /// Bytes of the request. Its interpretation is out of scope of this module.
        request: Vec<u8>,
    },

    /// Received a response to a previously emitted request on a request-response protocol.
    Response {
        /// Bytes of the response. Its interpretation is out of scope of this module.
        response: Result<Vec<u8>, RequestError>,
        /// Identifier of the request. Value that was returned by [`SingleStream::add_request`]
        /// or [`MultiStream::add_request`].
        id: SubstreamId,
        /// Value that was passed to [`SingleStream::add_request`] or [`MultiStream::add_request`].
        user_data: TSubUd,
    },

    /// Remote has opened an inbound notifications substream.
    ///
    /// Either [`SingleStream::accept_in_notifications_substream`] or
    /// [`SingleStream::reject_in_notifications_substream`], or
    /// [`MultiStream::accept_in_notifications_substream`] or
    /// [`MultiStream::reject_in_notifications_substream`] must be called in the near future in
    /// order to accept or reject this substream.
    NotificationsInOpen {
        /// Identifier of the substream. Needs to be provided back when accept or rejecting the
        /// substream.
        id: SubstreamId,
        /// Handshake sent by the remote. Its interpretation is out of scope of this module.
        handshake: Vec<u8>,
    },
    /// Remote has canceled an inbound notifications substream opening.
    ///
    /// This can only happen after [`Event::NotificationsInOpen`].
    /// [`SingleStream::accept_in_notifications_substream`] or
    /// [`SingleStream::reject_in_notifications_substream`], or
    /// [`MultiStream::accept_in_notifications_substream`] or
    /// [`MultiStream::reject_in_notifications_substream`] should not be called on this substream.
    NotificationsInOpenCancel {
        /// Identifier of the substream.
        id: SubstreamId,
    },
    /// Remote has sent a notification on an inbound notifications substream. Can only happen
    /// after the substream has been accepted.
    // TODO: give a way to back-pressure notifications
    NotificationIn {
        /// Identifier of the substream.
        id: SubstreamId,
        /// Notification sent by the remote.
        notification: Vec<u8>,
    },
    /// Remote has closed an inbound notifications substream.Can only happen
    /// after the substream has been accepted.
    NotificationsInClose {
        /// Identifier of the substream.
        id: SubstreamId,
        /// If `Ok`, the substream has been closed gracefully. If `Err`, a problem happened.
        outcome: Result<(), NotificationsInClosedErr>,
        /// Value that was passed to [`SingleStream::accept_inbound`] or
        /// [`MultiStream::accept_inbound`].
        user_data: TSubUd,
    },

    /// Outcome of trying to open a substream with [`SingleStream::open_notifications_substream`]
    /// or [`MultiStream::open_notifications_substream`].
    ///
    /// If `Ok`, it is now possible to send notifications on this substream.
    /// If `Err`, the substream no longer exists.
    NotificationsOutResult {
        /// Identifier of the substream. Value that was returned by
        /// [`SingleStream::open_notifications_substream`] or
        /// [`MultiStream::open_notifications_substream`].
        id: SubstreamId,
        /// If `Ok`, contains the handshake sent back by the remote. Its interpretation is out of
        /// scope of this module.
        result: Result<Vec<u8>, (NotificationsOutErr, TSubUd)>,
    },
    /// Remote has closed an outgoing notifications substream, meaning that it demands the closing
    /// of the substream.
    NotificationsOutCloseDemanded {
        /// Identifier of the substream. Value that was returned by
        /// [`SingleStream::open_notifications_substream`] or
        /// [`MultiStream::open_notifications_substream`].
        id: SubstreamId,
    },
    /// Remote has reset an outgoing notifications substream. The substream is instantly closed.
    NotificationsOutReset {
        /// Identifier of the substream. Value that was returned by
        /// [`SingleStream::open_notifications_substream`].
        id: SubstreamId,
        /// Value that was passed to [`SingleStream::open_notifications_substream`] or
        /// [`MultiStream::open_notifications_substream`].
        user_data: TSubUd,
    },

    /// An outgoing ping has succeeded. This event is generated automatically over time.
    PingOutSuccess {
        /// Duration between sending the ping and receiving the pong.
        ping_time: Duration,
    },
    /// An outgoing ping has failed. This event is generated automatically over time.
    PingOutFailed,

    /// Remote has accepted or refused a substream opened with [`Substream::bitswap_out`].
    ///
    /// If `Ok`, it is now possiblr to send Bitswap messages on this substream.
    BitswapOutOpenResult {
        /// Identifier of the substream.
        id: SubstreamId,
        /// If `Ok`, the substream was successfully opened.
        result: Result<(), BitswapOutOpenErr>,
    },
    /// Remote has closed a writing side of our outbound Bitswap substream or error occured.
    /// The substream is instantly closed.
    BitswapOutClose {
        /// Identifier of the substream.
        id: SubstreamId,
        /// If `Ok`, the substream has been closed gracefully. If `Err`, a problem happened.
        outcome: Result<(), BitswapOutClosedErr>,
    },
    /// Remote has opened an inbound Bitswap substream. This event can be used to limit the number
    /// of open inbound Bitswap substreams per peer by closing old substreams.
    BitswapInOpen {
        /// Identifier of the substream.
        id: SubstreamId,
    },
    /// Remote has sent a Bitswap message.
    BitswapIn {
        /// Identifier of the substream.
        id: SubstreamId,
        /// Message sent by the remote.
        message: Vec<u8>,
    },
    /// Remote has closed an inbound Bitswap substream.
    BitswapInClose {
        /// Identifier of the substream.
        id: SubstreamId,
        /// If `Ok`, the substream has been closed gracefully. If `Err`, a problem happened.
        outcome: Result<(), BitswapInClosedErr>,
    },
}

/// Configuration to turn a [`ConnectionPrototype`] into a [`SingleStream`] or [`MultiStream`].
// TODO: this struct isn't zero-cost, but making it zero-cost is kind of hard and annoying
#[derive(Debug, Clone)]
pub struct Config<TNow> {
    /// Maximum number of substreams that the remote can have simultaneously opened.
    pub max_inbound_substreams: usize,
    /// Number of substreams that are expected to be opened simultaneously.
    pub substreams_capacity: usize,
    /// Maximum size in bytes of the protocols supported by the local node. Any protocol larger
    /// than that requested by the remote is automatically refused. Necessary in order to avoid
    /// situations where the remote sends an infinitely-sized protocol name.
    pub max_protocol_name_len: usize,
    /// Name of the ping protocol on the network.
    // TODO: remove from config?
    pub ping_protocol: String,
    /// When to start the first outgoing ping.
    pub first_out_ping: TNow,
    /// Interval between two consecutive outgoing ping attempts.
    pub ping_interval: Duration,
    /// Time after which an outgoing ping is considered failed.
    pub ping_timeout: Duration,
    /// Entropy used for the randomness specific to this connection.
    pub randomness_seed: [u8; 32],
}

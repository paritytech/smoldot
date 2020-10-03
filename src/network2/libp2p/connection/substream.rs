// Copyright (C) 2019-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! After the handshake phase, libp2p connections are divided into multiple individual
//! substreams, each incoming and outgoing packet of data belonging to a certain substream. This
//! module provides the tools to handle a single substream.
//!
//! # Protocol
//!
//! Each substream starts in a protocol selection phase that uses the *multistream-select*
//! protocol. See [the corresponding module](multistream-select) for more details.
//!
//!

// TODO: ^ finish docs

use super::{super::super::leb128, multistream_select};

use core::{
    iter,
    ops::{Add, Sub},
    time::Duration,
};
/*
/// State of a single substream.
pub struct Substream<TNow, TProtoList, TProto> {
    /// Specialization for the substream.
    ty: SubstreamTy<TNow, TProtoList, TProto>,
}

/// Specialization for the substream.
enum SubstreamTy<TNow, TProtoList, TProto> {
    /// Protocol negotiation is still in progress on this substream.
    Negotiating {
        state: multistream_select::InProgress<TProtoList, TProto>,
        when_timeout: TNow,
    },
    NotificationsOut,
    NotificationsIn,
    // TODO: necessary?
    RequestOutWaitLocal,
    RequestOutSend,
    /// Receiving a response to an outgoing request from the remote.
    RequestOutReceive(leb128::Framed),
    /// Receiving an incoming request from the remote.
    RequestInReceive(leb128::Framed),
    /// Request has been reported on the API layer. Waiting for 
    // TODO: wait for which method to be called?
    RequestInWaitLocal,
    RequestInSend,
}

impl<TNow> Substream<TNow>
where
    TNow: Clone + Add<Duration> + Sub<TNow, Output = Duration> + Ord,
{
    pub fn new(now: TNow) {
        Substream {
            ty: SubstreamTy::Negotiating {
                state: multistream_select::InProgress::new(multistream_select::Config::Dialer {

                }),
                when_timeout: now + Duration::from_secs(20), // TODO:
            },
        }
    }

    /// Reads data coming from the socket from `incoming_data`, updates the internal state machine,
    /// and writes data destined to the socket to `outgoing_buffer`.
    ///
    /// `incoming_data` should be `None` if the remote has closed their writing side.
    ///
    /// The returned structure contains the number of bytes read and written from/to the two
    /// buffers. Call this method in a loop until these two values are both 0 and
    /// [`ReadWrite::event`] is `None`.
    ///
    /// If the remote isn't ready to accept new data, pass an empty slice as `outgoing_buffer`.
    ///
    /// The current time must be passed via the `now` parameter. This is used internally in order
    /// to keep track of ping times and timeouts. The returned structure optionally contains a
    /// `TNow` representing the moment after which this method should be called again.
    ///
    /// If an error is returned, the socket should be entirely shut down.
    pub fn read_write(
        mut self,
        now: TNow,
        mut incoming_data: Option<&[u8]>,
        mut outgoing_buffer: &mut [u8],
    ) -> Result<ReadWrite<TNow>, Error> {
        let mut total_read = 0;

        if let Some(incoming_data) = incoming_data.as_mut() {
            let num_read = self
                .encryption
                .inject_inbound_data(*incoming_data)
                .map_err(Error::Noise)?;
            total_read += incoming_data.len();
            *incoming_data = &incoming_data[num_read..];
        }

        /*loop {
            let mut buffer = encryption.prepare_buffer_encryption(destination);
            let (updated, written_interm) = negotiation.write_out(&mut *buffer);
            let written = buffer.finish(written_interm);
            destination = &mut destination[written..];
            total_written += written;

            self.state = match updated {
                multistream_select::Negotiation::InProgress(updated) => {
                    HandshakeState::NegotiatingMultiplexing {
                        encryption,
                        negotiation: updated,
                        peer_id,
                    }
                }
                multistream_select::Negotiation::Success(_) => {
                    return (
                        Handshake::Success {
                            connection: Connection { encryption },
                            remote_peer_id: peer_id,
                        },
                        total_written,
                    );
                }
                multistream_select::Negotiation::NotAvailable => todo!(), // TODO: ?!
            };

            if written == 0 {
                break;
            }
        }*/

        todo!()
    }
}
*/

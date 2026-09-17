// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::{Event, Limits, ProtocolError, framing};
use crate::jam::{
    params::Params,
    types::{Announcement, Handshake},
};

pub(super) struct Up0 {
    pub(super) writer: framing::Writer,
    reader: framing::Reader,
    handshake_received: bool,
}

impl Up0 {
    pub(super) fn new(payload: &[u8], outgoing: bool, max: usize) -> Result<Self, ProtocolError> {
        Ok(Self {
            writer: framing::Writer::new(outgoing.then_some(0), payload, max)?,
            reader: framing::Reader::default(),
            handshake_received: false,
        })
    }

    pub(super) fn read(
        &mut self,
        input: &mut &[u8],
        fin: bool,
        params: &Params,
        limits: &Limits,
    ) -> Result<Option<Event>, ProtocolError> {
        if let Some(payload) = self.reader.read(input, limits.max_message_size)? {
            return if self.handshake_received {
                Ok(Some(Event::Announcement(
                    Announcement::decode(params, &payload).map_err(ProtocolError::Decode)?,
                )))
            } else {
                let handshake = Handshake::decode(&payload, limits.max_leaves_in_handshake)
                    .map_err(ProtocolError::Decode)?;
                self.handshake_received = true;
                Ok(Some(Event::HandshakeReceived(handshake)))
            };
        }
        if fin {
            return Err(ProtocolError::UnexpectedFin);
        }
        Ok(None)
    }
}

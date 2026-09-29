// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::{Event, ProtocolError, RequestId, framing};
use alloc::vec::Vec;

/// One CE153 exchange; finality verification belongs to the caller.
pub(super) struct Ce153 {
    pub(super) id: RequestId,
    start_set_id: u32,
    pub(super) writer: framing::Writer,
    reader: framing::Reader,
    response: Option<Vec<u8>>,
    pub(super) fin_sent: bool,
}

impl Ce153 {
    pub(super) fn new(id: RequestId, start_set_id: u32, max: usize) -> Result<Self, ProtocolError> {
        Ok(Self {
            id,
            start_set_id,
            writer: framing::Writer::new(Some(153), &start_set_id.to_le_bytes(), max)?,
            reader: framing::Reader::default(),
            response: None,
            fin_sent: false,
        })
    }

    pub(super) fn read(
        &mut self,
        input: &mut &[u8],
        fin: bool,
        max: usize,
    ) -> Result<Option<Event>, ProtocolError> {
        if !self.fin_sent {
            return Ok(None);
        }
        if self.response.is_none() {
            let Some(payload) = self.reader.read(input, max)? else {
                return if fin {
                    Err(ProtocolError::UnexpectedFin)
                } else {
                    Ok(None)
                };
            };
            self.response = Some(payload);
        }
        if !input.is_empty() {
            return Err(ProtocolError::TrailingResponse);
        }
        if fin {
            return Ok(self.response.take().map(|fragments| Event::WarpResponse {
                request_id: self.id,
                start_set_id: self.start_set_id,
                fragments,
            }));
        }
        Ok(None)
    }
}

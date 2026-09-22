// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::{Event, ProtocolError, RequestId, framing};
use crate::jam::types::Hash;
use alloc::vec::Vec;

/// One CE130 exchange. The payload remains untrusted until finality verification.
pub(super) struct Ce130 {
    pub(super) id: RequestId,
    target: Hash,
    pub(super) writer: framing::Writer,
    reader: framing::Reader,
    response: Option<Vec<u8>>,
    pub(super) fin_sent: bool,
}

impl Ce130 {
    pub(super) fn new(id: RequestId, target: Hash, max: usize) -> Result<Self, ProtocolError> {
        Ok(Self {
            id,
            target,
            writer: framing::Writer::new(Some(130), &target, max)?,
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
            return Ok(self
                .response
                .take()
                .map(|justification| Event::JustificationResponse {
                    request_id: self.id,
                    target: self.target,
                    justification,
                }));
        }
        Ok(None)
    }
}

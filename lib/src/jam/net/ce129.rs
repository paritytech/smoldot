// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::{Event, ProtocolError, RequestId, framing};
use crate::jam::trie::{ResponseLimits, StateRequest, StateResponse};
use alloc::vec::Vec;

pub(super) struct Ce129 {
    pub(super) id: RequestId,
    pub(super) writer: framing::Writer,
    pub(super) fin_sent: bool,
    reader: framing::Reader,
    nodes: Option<Vec<u8>>,
    entries: Option<Vec<u8>>,
}

impl Ce129 {
    pub(super) fn new(
        id: RequestId,
        request: &StateRequest,
        max: usize,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            id,
            writer: framing::Writer::new(Some(129), &request.encode(), max)?,
            fin_sent: false,
            reader: framing::Reader::default(),
            nodes: None,
            entries: None,
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
        let max = max.min(1024 * 1024);
        if self.nodes.is_none() {
            self.nodes = self.reader.read(input, max.min(496 * 64))?;
            if self.nodes.is_none() {
                return if fin {
                    Err(ProtocolError::UnexpectedFin)
                } else {
                    Ok(None)
                };
            }
        }
        if self.entries.is_none() {
            self.entries = self.reader.read(input, max)?;
            if self.entries.is_none() {
                return if fin {
                    Err(ProtocolError::UnexpectedFin)
                } else {
                    Ok(None)
                };
            }
        }
        if !input.is_empty() {
            return Err(ProtocolError::TrailingResponse);
        }
        if !fin {
            return Ok(None);
        }
        let nodes = self.nodes.take().ok_or(ProtocolError::UnexpectedFin)?;
        let entries = self.entries.take().ok_or(ProtocolError::UnexpectedFin)?;
        let response = StateResponse::decode(
            &nodes,
            &entries,
            &ResponseLimits {
                max_nodes: 496,
                max_entries: max / 32,
                max_value_bytes: max,
                max_total_bytes: max.saturating_add(496 * 64),
            },
        )
        .map_err(ProtocolError::Decode)?;
        Ok(Some(Event::StateResponse {
            request_id: self.id,
            response,
        }))
    }
}

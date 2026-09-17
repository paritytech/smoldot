// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use alloc::vec::Vec;

use super::{Event, Limits, ProtocolError, RequestError, RequestId, framing};
use crate::jam::{
    params::Params,
    types::{Block, BlockRequest, Direction},
};

pub(super) struct Ce128 {
    pub(super) id: RequestId,
    request: BlockRequest,
    pub(super) writer: framing::Writer,
    reader: framing::Reader,
    // Frame completion is independent of whether the sequence contains a block.
    response_received: bool,
    blocks: Vec<Block>,
    pub(super) fin_sent: bool,
}

impl Ce128 {
    pub(super) fn new(
        id: RequestId,
        request: BlockRequest,
        max: usize,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            writer: framing::Writer::new(Some(128), &request.encode(), max)?,
            id,
            request,
            reader: framing::Reader::default(),
            response_received: false,
            blocks: Vec::new(),
            fin_sent: false,
        })
    }

    pub(super) fn read(
        &mut self,
        input: &mut &[u8],
        fin: bool,
        params: &Params,
        limits: &Limits,
    ) -> Result<Option<Event>, ProtocolError> {
        if !self.fin_sent {
            return Ok(None);
        }
        if !self.response_received {
            let Some(payload) = self.reader.read(input, limits.max_message_size)? else {
                return if fin {
                    Err(ProtocolError::UnexpectedFin)
                } else {
                    Ok(None)
                };
            };
            let blocks = Block::decode_sequence(
                params,
                &payload,
                limits.max_body_bytes,
                usize::try_from(self.request.max_blocks).map_err(|_| {
                    ProtocolError::Decode(crate::jam::codec::DecodeError::LengthLimit)
                })?,
            )
            .map_err(ProtocolError::Decode)?;
            let mut expected = self.request.hash;
            for block in &blocks {
                let hash = block.header.hash(params);
                let bound = match self.request.direction {
                    Direction::AscendingExclusive => block.header.parent == expected,
                    Direction::DescendingInclusive => hash == expected,
                };
                if !bound {
                    return Err(ProtocolError::ResponseMismatch);
                }
                expected = match self.request.direction {
                    Direction::AscendingExclusive => hash,
                    Direction::DescendingInclusive => block.header.parent,
                };
            }
            self.blocks = blocks;
            self.response_received = true;
        }
        if !input.is_empty() {
            return Err(ProtocolError::TrailingResponse);
        }
        if fin {
            return Ok(Some(if self.blocks.is_empty() {
                Event::RequestFailed {
                    request_id: self.id,
                    reason: RequestError::NoBlocks,
                }
            } else {
                Event::BlockResponse {
                    request_id: self.id,
                    blocks: core::mem::take(&mut self.blocks),
                }
            }));
        }
        Ok(None)
    }
}

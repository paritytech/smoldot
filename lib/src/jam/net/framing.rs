// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::ProtocolError;
use alloc::vec::Vec;

/// Checks the LE32 length before reserving payload memory.
#[derive(Default)]
pub(super) struct Reader {
    prefix: [u8; 4],
    prefix_len: usize,
    length: Option<usize>,
    payload: Vec<u8>,
}

impl Reader {
    pub(super) fn read(
        &mut self,
        input: &mut &[u8],
        max: usize,
    ) -> Result<Option<Vec<u8>>, ProtocolError> {
        while self.prefix_len < 4 {
            let Some((&byte, rest)) = input.split_first() else {
                return Ok(None);
            };
            self.prefix[self.prefix_len] = byte;
            self.prefix_len += 1;
            *input = rest;
        }
        let length = match self.length {
            Some(length) => length,
            None => {
                let length = usize::try_from(u32::from_le_bytes(self.prefix))
                    .map_err(|_| ProtocolError::MessageTooLarge)?;
                if length > max {
                    return Err(ProtocolError::MessageTooLarge);
                }
                self.payload
                    .try_reserve_exact(length)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                self.length = Some(length);
                length
            }
        };
        let count = input.len().min(length - self.payload.len());
        self.payload.extend_from_slice(&input[..count]);
        *input = &input[count..];
        if self.payload.len() != length {
            return Ok(None);
        }
        self.prefix_len = 0;
        self.length = None;
        Ok(Some(core::mem::take(&mut self.payload)))
    }
}

#[derive(Default)]
pub(super) struct Writer {
    bytes: Vec<u8>,
    position: usize,
}

impl Writer {
    pub(super) fn new(kind: Option<u8>, payload: &[u8], max: usize) -> Result<Self, ProtocolError> {
        if payload.len() > max {
            return Err(ProtocolError::MessageTooLarge);
        }
        let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::MessageTooLarge)?;
        let capacity = payload
            .len()
            .checked_add(5)
            .ok_or(ProtocolError::MessageTooLarge)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        bytes.extend(kind);
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(payload);
        Ok(Self { bytes, position: 0 })
    }

    pub(super) fn write(&mut self, output: &mut [u8]) -> usize {
        let count = output.len().min(self.bytes.len() - self.position);
        output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
        self.position += count;
        if self.position == self.bytes.len() {
            self.bytes = Vec::new();
            self.position = 0;
        }
        count
    }

    pub(super) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

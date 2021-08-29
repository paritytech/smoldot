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

//! Implementation detail of the optimistic syncing. Provides a queue of block requests and blocks
//! that are ready to be verified.

use alloc::collections::VecDeque;
use core::{
    convert::TryFrom as _,
    fmt, iter, mem,
    num::{NonZeroU32, NonZeroU64},
};
use itertools::Itertools as _;

use super::{RequestId, RequestSuccessBlock, SourceId}; // TODO: ?

/// Queue of block requests, either waiting to be started, in progress, or completed.
pub(super) struct VerificationQueue<TRq, TBl> {
    /// Actual queue.
    ///
    /// Must contain at least one entry of type [`VerificationQueueEntryTy::Missing`] at the end.
    verification_queue: VecDeque<VerificationQueueEntry<TRq, TBl>>,
}

// TODO: the implementation has lots of bugs; fix

impl<TRq, TBl> VerificationQueue<TRq, TBl> {
    /// Creates a new queue.
    pub fn new(base_block_number: u64) -> Self {
        let mut verification_queue = VecDeque::new();
        verification_queue.push_back(VerificationQueueEntry {
            block_height: NonZeroU64::new(base_block_number).unwrap(),
            ty: VerificationQueueEntryTy::Missing,
        });

        VerificationQueue { verification_queue }
    }

    /// Returns true if the queue starts with ready blocks.
    ///
    /// This is equivalent to calling `is_some` on the `Option` returned by
    /// [`VerificationQueue::first_block`].
    pub fn blocks_ready(&self) -> bool {
        matches!(
            self.verification_queue.front().unwrap().ty,
            VerificationQueueEntryTy::Queued { .. }
        )
    }

    /// If the queue starts with ready blocks, returns the first block that is ready.
    ///
    /// Returns `Some` if and only if [`VerificationQueue::blocks_ready`] returns `true`.
    pub fn first_block(&self) -> Option<&RequestSuccessBlock<TBl>> {
        match &self.verification_queue.front().unwrap().ty {
            VerificationQueueEntryTy::Queued { blocks, .. } => Some(blocks.front().unwrap()),
            _ => None,
        }
    }

    /// If the queue starts with ready blocks, returns the first block that is ready and removes
    /// it.
    ///
    /// Returns `Some` if and only if [`VerificationQueue::blocks_ready`] returns `true`.
    pub fn pop_first_block(&mut self) -> Option<(RequestSuccessBlock<TBl>, SourceId)> {
        let verif_queue_front = self.verification_queue.get_mut(0).unwrap();

        let block;
        let blocks_now_empty;
        let source_id;

        match &mut verif_queue_front.ty {
            VerificationQueueEntryTy::Queued { blocks, source } => {
                block = blocks.pop_front().unwrap();
                blocks_now_empty = blocks.is_empty();
                source_id = *source;
            }
            _ => return None,
        };

        verif_queue_front.block_height =
            NonZeroU64::new(verif_queue_front.block_height.get() + 1).unwrap();

        if blocks_now_empty {
            self.verification_queue.pop_front().unwrap();
            debug_assert!(!self.verification_queue.is_empty());
        }

        Some((block, source_id))
    }

    pub fn desired_requests(&'_ self) -> impl Iterator<Item = (NonZeroU64, NonZeroU32)> + '_ {
        let base_block_number = self.verification_queue.front().unwrap().block_height;

        let iter1 = self
            .verification_queue
            .iter()
            .tuple_windows::<(_, _)>()
            .filter(|(e, _)| matches!(e.ty, VerificationQueueEntryTy::Missing))
            .map(|(entry, next_entry)| {
                (
                    entry.block_height,
                    NonZeroU32::new(
                        u32::try_from(next_entry.block_height.get() - entry.block_height.get())
                            .unwrap(),
                    )
                    .unwrap(),
                )
            });

        let verif_queue_last = self.verification_queue.back().unwrap();
        let iter2 = if verif_queue_last.block_height.get() < base_block_number.get() + 1024
        // TODO: u64::from(self.download_ahead_blocks) instead of 1024
        {
            either::Left(iter::once((
                verif_queue_last.block_height,
                NonZeroU32::new(u32::max_value()).unwrap(),
            )))
        } else {
            either::Right(iter::empty())
        };

        iter1.chain(iter2)
    }

    /// Updates the queue with the fact that a request has been started.
    ///
    /// Returns `Ok` if the request has updated the queue, and `Err` if the request isn't relevant
    /// to anything in the queue and has been silently discarded.
    pub fn insert_request(
        &mut self,
        block_height: NonZeroU64,
        num_blocks: NonZeroU32,
        request_id: RequestId,
        source: SourceId,
        user_data: TRq,
    ) -> Result<(), TRq> {
        let missing_pos = self.verification_queue.iter().position(|entry| {
            entry.block_height == block_height
                && matches!(entry.ty, VerificationQueueEntryTy::Missing)
        });

        let missing_pos = match missing_pos {
            Some(n) => n,
            None => return Err(user_data),
        };

        self.verification_queue[missing_pos].ty = VerificationQueueEntryTy::Requested {
            id: request_id,
            source,
            user_data,
        };

        // TODO: adjust if num_blocks < the diff with the next entry

        if missing_pos == self.verification_queue.len() - 1 {
            self.verification_queue.push_back(VerificationQueueEntry {
                block_height: NonZeroU64::new(
                    block_height
                        .get()
                        .checked_add(u64::from(num_blocks.get()))
                        .unwrap(),
                )
                .unwrap(),
                ty: VerificationQueueEntryTy::Missing,
            })
        }

        Ok(())
    }

    pub fn finish_request(
        &mut self,
        request_id: RequestId,
        replacement: Result<impl Iterator<Item = RequestSuccessBlock<TBl>>, ()>,
    ) -> (TRq, SourceId) {
        let (index, source_id) = self
            .verification_queue
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| match entry.ty {
                VerificationQueueEntryTy::Requested { id, source, .. } if id == request_id => {
                    Some((index, source))
                }
                _ => None,
            })
            .next()
            .unwrap();

        let new_entry = match replacement {
            Ok(blocks) => VerificationQueueEntryTy::Queued {
                source: source_id,
                blocks: blocks.collect(),
            },
            Err(()) => VerificationQueueEntryTy::Missing,
        };

        let prev_value = mem::replace(&mut self.verification_queue[index].ty, new_entry);

        let user_data = match prev_value {
            VerificationQueueEntryTy::Requested { user_data, .. } => user_data,
            _ => unreachable!(),
        };

        // TODO: insert a `Missing` at the end if necessary

        (user_data, source_id)
    }

    /// Consumes the queue and returns an iterator to all the requests that were inside of it.
    pub fn into_requests(self) -> impl Iterator<Item = (TRq, RequestId, SourceId)> {
        self.verification_queue
            .into_iter()
            .filter_map(|queue_elem| {
                if let VerificationQueueEntryTy::Requested {
                    id,
                    user_data,
                    source,
                } = queue_elem.ty
                {
                    Some((user_data, id, source))
                } else {
                    None
                }
            })
    }

    /// Returns an iterator that removes from the queue all requests belonging to a certain source.
    pub fn drain_source(&'_ mut self, source_id: SourceId) -> SourceDrain<'_, TRq, TBl> {
        SourceDrain {
            queue: self,
            source_id,
        }
    }
}

/// See [`VerificationQueue::drain_source`].
pub(super) struct SourceDrain<'a, TRq, TBl> {
    queue: &'a mut VerificationQueue<TRq, TBl>,
    source_id: SourceId,
}

impl<'a, TRq, TBl> Iterator for SourceDrain<'a, TRq, TBl> {
    type Item = (RequestId, TRq);

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: unoptimized
        let source_id = self.source_id;
        let entry = self
            .queue
            .verification_queue
            .iter_mut()
            .find(|entry| match entry.ty {
                VerificationQueueEntryTy::Requested { source, .. } if source == source_id => true,
                _ => false,
            })?;

        match mem::replace(&mut entry.ty, VerificationQueueEntryTy::Missing) {
            VerificationQueueEntryTy::Requested { id, user_data, .. } => Some((id, user_data)),
            _ => unreachable!(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.queue.verification_queue.len()))
    }
}

impl<'a, TRq, TBl> fmt::Debug for SourceDrain<'a, TRq, TBl> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SourceDrain").finish()
    }
}

struct VerificationQueueEntry<TRq, TBl> {
    block_height: NonZeroU64,
    ty: VerificationQueueEntryTy<TRq, TBl>,
}

enum VerificationQueueEntryTy<TRq, TBl> {
    Missing,
    Requested {
        id: RequestId,
        /// User-chosen data for this request.
        user_data: TRq,
        // Index of this source within [`OptimisticSyncInner::sources`].
        source: SourceId,
    },
    Queued {
        source: SourceId,
        /// Must never be empty.
        blocks: VecDeque<RequestSuccessBlock<TBl>>, // TODO: replace entirely with ̀`TBl`?
    },
}

// TODO: tests

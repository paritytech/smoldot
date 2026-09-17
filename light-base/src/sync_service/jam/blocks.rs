// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Header sync over one connection: CE 128 requests for ascending batches and
//! for the parents of announced headers, and importing what they return.

use super::{
    InsertFailure, REPAIR_LIMIT,
    connection::{Conn, InFlight},
    log::{End, Hex, Tag, direction_str, event, request_ended},
};
use crate::{log, platform::PlatformRef};
use alloc::vec::Vec;
use smoldot::jam::{
    net, tree,
    types::{Announcement, Block, BlockRequest, Direction, Handshake},
};

impl<P: PlatformRef> Conn<'_, P> {
    /// Takes the peer's handshake: its finalized head and leaves.
    pub(super) async fn handshake(&mut self, h: Handshake) {
        self.handshaken = true;
        self.advertised = Some(h.final_.clone());
        self.peer_slot = h
            .leaves
            .iter()
            .map(|leaf| leaf.slot)
            .chain(core::iter::once(h.final_.slot))
            .max()
            .unwrap_or(0);
    }

    /// Takes an announcement: a new head and the peer's finalized head.
    pub(super) async fn announcement(&mut self, a: Announcement) -> Result<(), End> {
        event!(
            self,
            "jam-announcement",
            slot = self.peer_index,
            block_slot = a.header.slot,
            final_slot = a.final_.slot
        );
        self.peer_slot = self.peer_slot.max(a.header.slot).max(a.final_.slot);
        if self
            .waiting_for_finality
            .is_some_and(|slot| a.final_.slot > slot)
        {
            self.cursor = Some(self.state.lock().await.tree.finalized().hash());
            self.fallback = true;
            self.waiting_for_finality = None;
        }
        self.advertised = Some(a.final_);
        let s = self.state.lock().await;
        if a.header.slot > s.tree.finalized().slot()
            && a.header.encode(self.params).len() <= s.header_bytes
            && self.announcements.len() < REPAIR_LIMIT
            && !self.announcements.contains(&a.header)
        {
            self.announcements.push_back(a.header);
        }
        Ok(())
    }

    /// Handles a CE 128 response: headers to repair or import.
    pub(super) async fn block_response(
        &mut self,
        request_id: net::RequestId,
        blocks: Vec<Block>,
    ) -> Result<(), End> {
        let Some(r) = self.requested.take().filter(|r| r.id == request_id) else {
            return Err(End::UnexpectedResponse);
        };
        request_ended!(
            self,
            "jam-block-request-ended",
            r,
            "ok",
            blocks = blocks.len(),
            bytes = blocks
                .iter()
                .map(|block| block.header.encode(self.params).len() + block.body.len())
                .sum::<usize>()
        );
        let request = r.expected;
        let mut bytes = 0;
        for block in blocks {
            let header_len = block.header.encode(self.params).len();
            if header_len > self.state.lock().await.header_bytes {
                return Err(End::Limit);
            }
            bytes += header_len + block.body.len();
            drop(block.body);
            if request.direction == Direction::DescendingInclusive {
                let parent = block.header.parent;
                self.repair.push(block.header);
                self.repair_ready = self.state.lock().await.tree.get(&parent).is_some();
                if !self.repair_ready && self.repair.len() >= REPAIR_LIMIT {
                    self.repair.clear();
                }
            } else {
                self.imports.push_back(block.header);
            }
        }
        if request.direction == Direction::AscendingExclusive {
            self.fetch_size.received(bytes);
        }
        Ok(())
    }

    /// Handles a failed CE 128 request.
    pub(super) async fn block_failed(
        &mut self,
        request_id: net::RequestId,
        reason: net::RequestError,
    ) -> Result<(), End> {
        let Some(r) = self.requested.take().filter(|r| r.id == request_id) else {
            return Err(End::UnexpectedResponse);
        };
        request_ended!(self, "jam-block-request-ended", r, "failed", error = ?reason);
        let request = r.expected;
        if request.direction == Direction::DescendingInclusive {
            self.repair.clear();
            self.repair_ready = false;
        } else if !self.fallback {
            self.cursor = Some(self.state.lock().await.tree.finalized().hash());
            self.fallback = true;
        } else if request.hash == self.state.lock().await.tree.finalized().hash() {
            // This peer cannot extend our authenticated root.
            return Err(End::RootUnextendable);
        } else {
            // First-child selection can repeat a dead branch. Wait for
            // an announcement repair or for the server to prune it.
            self.waiting_for_finality = Some(self.advertised.as_ref().map_or(0, |f| f.slot));
        }
        Ok(())
    }

    /// Ends the connection on an oversized response, halving the ascending
    /// batch size first when that response was blocks.
    pub(super) fn message_too_large(&mut self) -> Result<(), End> {
        if let Some(r) = &self.requested
            && r.expected.direction == Direction::AscendingExclusive
        {
            let before = self.fetch_size.count;
            self.fetch_size.oversized();
            event!(
                self,
                "jam-block-size-halved",
                slot = self.peer_index,
                req = r.tag.req,
                max_blocks = before,
                next_max_blocks = self.fetch_size.count,
                ceiling = self.fetch_size.ceiling
            );
        }
        Err(End::MessageTooLarge)
    }

    /// Imports the next header of an ascending batch.
    pub(super) async fn import_next(&mut self, now: &P::Instant) -> Result<(), End> {
        if let Some(header) = self.imports.pop_front() {
            let hash = header.hash(self.params);
            let block_slot = header.slot;
            let mut s = self.state.lock().await;
            let known = s.tree.get(&hash).is_some();
            // Headers at or before the configured anchor need no import.
            let result = if header.slot <= s.tree.finalized().slot() {
                Ok(())
            } else {
                s.insert(header, self.platform.now_from_unix_epoch().as_secs())
            };
            match result {
                Ok(()) => {
                    self.cursor = self.fallback.then_some(hash);
                    self.last_activity = now.clone();
                    event!(
                        self,
                        "jam-header-inserted",
                        slot = self.peer_index,
                        via = "ascending",
                        block_slot = block_slot,
                        hash = Hex(&hash),
                        known = known || block_slot <= s.tree.finalized().slot()
                    );
                }
                Err(InsertFailure::Tree(tree::InsertError::Verify(_))) if !self.fallback => {
                    self.imports.clear();
                    self.cursor = Some(s.tree.finalized().hash());
                    self.fallback = true;
                }
                Err(_) => return Err(End::InsertFailed),
            }
            self.local_progress = true;
        }
        Ok(())
    }

    /// Inserts a repair header whose parent is known, else an announced one.
    pub(super) async fn import_repaired(&mut self, now: &P::Instant) -> Result<(), End> {
        let (header, via) = if self.repair_ready {
            (self.repair.pop(), "repair")
        } else if self.repair.is_empty() {
            (self.announcements.pop_front(), "announcement")
        } else {
            (None, "")
        };
        if let Some(header) = header {
            let mut s = self.state.lock().await;
            if header.slot > s.tree.finalized().slot() {
                let hash = header.hash(self.params);
                let known = s.tree.get(&hash).is_some();
                match s.insert(
                    header.clone(),
                    self.platform.now_from_unix_epoch().as_secs(),
                ) {
                    Ok(()) => {
                        self.cursor = None;
                        self.fallback = false;
                        self.waiting_for_finality = None;
                        self.last_activity = now.clone();
                        event!(
                            self,
                            "jam-header-inserted",
                            slot = self.peer_index,
                            via = via,
                            block_slot = header.slot,
                            hash = Hex(&hash),
                            known = known
                        );
                    }
                    Err(InsertFailure::Tree(tree::InsertError::UnknownParent)) => {
                        self.repair_ready = false;
                        self.repair.push(header);
                        if self.repair.len() >= REPAIR_LIMIT {
                            self.repair.clear();
                        }
                    }
                    Err(_) => return Err(End::InsertFailed),
                }
            }
            self.repair_ready = !self.repair.is_empty() && self.repair_ready;
            self.local_progress = true;
        }
        Ok(())
    }

    /// Requests the next blocks: the parent of a repair header, or an
    /// ascending batch from the cursor or the best block.
    pub(super) async fn request_blocks(&mut self) -> Result<(), End> {
        let s = self.state.lock().await;
        let request = if let Some(header) = self.repair.last() {
            Some((
                BlockRequest {
                    hash: header.parent,
                    direction: Direction::DescendingInclusive,
                    max_blocks: 1,
                },
                "repair",
            ))
        } else if self.waiting_for_finality.is_none() {
            let head = self
                .cursor
                .and_then(|hash| s.tree.get(&hash))
                .unwrap_or_else(|| s.tree.best());
            (self.peer_slot > head.slot()).then_some((
                BlockRequest {
                    hash: head.hash(),
                    direction: Direction::AscendingExclusive,
                    max_blocks: self.fetch_size.count,
                },
                "ascending",
            ))
        } else {
            None
        };
        if let Some((request, purpose)) = request {
            let Ok(id) = self.connection.request_blocks(request.clone()) else {
                return Err(End::RequestRefused);
            };
            let tag = Tag::new(purpose);
            let (hash, direction, max_blocks) = (
                request.hash,
                direction_str(&request.direction),
                request.max_blocks,
            );
            self.requested = Some(InFlight::new(id, request, self.platform.now(), tag));
            self.local_progress = true;
            event!(
                self,
                "jam-block-request-queued",
                slot = self.peer_index,
                req = tag.req,
                purpose = tag.purpose,
                hash = Hex(&hash),
                direction = direction,
                max_blocks = max_blocks
            );
        }
        Ok(())
    }
}

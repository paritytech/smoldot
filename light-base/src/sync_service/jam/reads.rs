// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Verified state reads over CE 129: one read at a time, served by one
//! connection at a time, each response proven against the root the caller
//! authenticated.

use super::{
    MAX_PEERS, State,
    connection::{Conn, InFlight},
    log::{
        End, Hex, Keys, Opt, Tag, Token, event, read_purpose, request_ended, state_response_bytes,
        trust_str,
    },
};
use crate::{log, platform::PlatformRef};
use smoldot::jam::{
    net,
    trie::{self, StateRequest, StateResponse, VerifiedRange},
    types::Hash,
};

/// Trust of the caller-authenticated header carrying this posterior state root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trust {
    Finalized,
    Authenticated,
}

#[derive(Clone, Debug)]
pub(crate) struct StateRead {
    pub at: Hash,
    pub root: Hash,
    pub trust: Trust,
    /// Header whose posterior root `root` is: the read block itself when a
    /// GRANDPA target signs it (the warp join), or its child when the root is
    /// that child's prior state root (`State::finalized_read`).
    pub root_header: Option<Hash>,
    pub request: StateRequest,
}

#[derive(Debug)]
pub(crate) struct StateReadResult {
    pub at: Hash,
    pub root: Hash,
    pub trust: Trust,
    pub root_header: Option<Hash>,
    pub range: VerifiedRange,
}

impl StateReadResult {
    /// Whether this is the result of `read`: same block, root, trust and root header.
    pub(super) fn answers(&self, read: &StateRead) -> bool {
        self.at == read.at
            && self.root == read.root
            && self.trust == read.trust
            && self.root_header == read.root_header
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateReadError {
    Unavailable,
}

pub(super) struct StateReads {
    pub(super) pending: Option<(
        StateRead,
        futures_channel::oneshot::Sender<Result<StateReadResult, StateReadError>>,
    )>,
    pub(super) owner: Option<usize>,
    pub(super) attempts: u8,
    peers: usize,
}

impl StateReads {
    pub(super) fn new(peers: usize) -> Self {
        Self {
            pending: None,
            owner: None,
            attempts: 0,
            peers: peers.min(MAX_PEERS),
        }
    }

    fn finish_exhausted(&mut self) {
        if self.owner.is_none()
            && (0..self.peers).all(|peer| self.attempts & (1u8 << peer) != 0)
            && let Some((_, tx)) = self.pending.take()
        {
            let _ = tx.send(Err(StateReadError::Unavailable));
        }
    }
    /// Bounded in-process API: caller supplies the authenticated root and trust.
    /// Dropping the receiver cancels the read at the next reservation/response.
    pub(super) fn start(
        &mut self,
        read: StateRead,
    ) -> Result<
        futures_channel::oneshot::Receiver<Result<StateReadResult, StateReadError>>,
        net::Error,
    > {
        if read.at != read.request.block
            || read.request.start > read.request.end
            || read.request.max_size == 0
        {
            return Err(net::Error::InvalidRequest);
        }
        if self.owner.is_none()
            && self
                .pending
                .as_ref()
                .is_some_and(|(_, tx)| tx.is_canceled())
        {
            self.pending = None;
        }
        if self.pending.is_some() || self.owner.is_some() {
            return Err(net::Error::Limit);
        }
        let (tx, rx) = futures_channel::oneshot::channel();
        self.pending = Some((read, tx));
        self.attempts = 0;
        self.finish_exhausted();
        Ok(rx)
    }

    pub(super) fn reserve(&mut self, peer: usize) -> Option<StateRequest> {
        if peer >= self.peers || self.owner.is_some() {
            return None;
        }
        let (read, tx) = self.pending.as_ref()?;
        if tx.is_canceled() {
            self.pending = None;
            return None;
        }
        let bit = 1u8 << peer;
        if self.attempts & bit != 0 {
            return None;
        }
        self.attempts |= bit;
        self.owner = Some(peer);
        Some(read.request.clone())
    }

    pub(super) fn release(&mut self, peer: usize, transient: bool) {
        if self.owner == Some(peer) {
            self.owner = None;
            if transient && peer < MAX_PEERS {
                self.attempts &= !(1u8 << peer);
            }
            self.finish_exhausted();
        }
    }

    pub(super) fn received(
        &mut self,
        peer: usize,
        response: &StateResponse,
    ) -> Result<(), trie::ProofError> {
        if self.owner != Some(peer) {
            return Err(trie::ProofError::InvalidRange);
        }
        self.owner = None;
        let (read, _) = self
            .pending
            .as_ref()
            .ok_or(trie::ProofError::InvalidRange)?;
        let range = match trie::verify_range(&read.root, &read.request, response) {
            Ok(range) => range,
            Err(error) => {
                self.finish_exhausted();
                return Err(error);
            }
        };
        if let Some((read, tx)) = self.pending.take() {
            let _ = tx.send(Ok(StateReadResult {
                at: read.at,
                root: read.root,
                trust: read.trust,
                root_header: read.root_header,
                range,
            }));
        }
        Ok(())
    }
}

impl State {
    /// Wait until the best chain has an authenticated child of the finalized head.
    pub(super) fn finalized_read(
        &self,
        start: trie::StateKey,
        end: trie::StateKey,
        max_size: u32,
    ) -> Option<StateRead> {
        let at = self.tree.finalized().hash();
        let child = self
            .tree
            .ancestors(&self.tree.best().hash())
            .find(|child| child.parent() == at)?;
        let root = child.encoded().get(32..64)?.try_into().ok()?;
        Some(StateRead {
            at,
            root,
            trust: Trust::Authenticated,
            root_header: Some(child.hash()),
            request: StateRequest {
                block: at,
                start,
                end,
                max_size,
            },
        })
    }
}

impl<P: PlatformRef> Conn<'_, P> {
    /// Handles a CE 129 response: the reserved read's proof.
    pub(super) async fn state_response(
        &mut self,
        request_id: net::RequestId,
        response: StateResponse,
    ) -> Result<(), End> {
        let Some(r) = self.state_requested.take().filter(|r| r.id == request_id) else {
            return Err(End::UnexpectedResponse);
        };
        let entries = response.entries.len();
        let nodes = response.nodes.len();
        let bytes = state_response_bytes(&response);
        if let Err(error) = self
            .state
            .lock()
            .await
            .reads
            .received(self.peer_index, &response)
        {
            request_ended!(
                self,
                "jam-state-request-ended",
                r,
                "rejected",
                entries = entries,
                nodes = nodes,
                bytes = bytes,
                error = Token(&error)
            );
            event!(
                self,
                "jam-state-rejected",
                slot = self.peer_index,
                req = r.tag.req,
                error = ?error
            );
            return Err(End::StateRejected);
        }
        request_ended!(
            self,
            "jam-state-request-ended",
            r,
            "ok",
            entries = entries,
            nodes = nodes,
            bytes = bytes
        );
        Ok(())
    }

    /// Handles a failed CE 129 request.
    pub(super) async fn state_failed(&mut self, reason: net::RequestError) -> Result<(), End> {
        if let Some(r) = self.state_requested.take() {
            request_ended!(self, "jam-state-request-ended", r, "failed", error = ?reason);
        }
        self.state
            .lock()
            .await
            .reads
            .release(self.peer_index, reason == net::RequestError::Transient);
        if self.warp.is_some()
            || !matches!(
                reason,
                net::RequestError::NoData | net::RequestError::ResetWithoutCode
            )
        {
            return Err(End::StateFailed);
        }
        Ok(())
    }

    /// Takes the pending read, if this connection may serve it, and requests it.
    pub(super) async fn request_state(&mut self) -> Result<(), End> {
        let mut s = self.state.lock().await;
        if !s.stopped
            && s.warp_owner.is_none_or(|owner| owner == self.peer_index)
            && let Some(request) = s.reads.reserve(self.peer_index)
        {
            let trust = s.reads.pending.as_ref().map(|(read, _)| read.trust);
            let keys = alloc::format!("{}", Keys(&request));
            let block = request.block;
            let max_size = request.max_size;
            match self.connection.request_state(request) {
                Ok(id) => {
                    let tag = Tag::new(trust.map_or("-", read_purpose));
                    self.state_requested = Some(InFlight::new(id, (), self.platform.now(), tag));
                    self.local_progress = true;
                    event!(
                        self,
                        "jam-state-request-queued",
                        slot = self.peer_index,
                        req = tag.req,
                        purpose = tag.purpose,
                        block = Hex(&block),
                        trust = Opt(trust.map(trust_str)),
                        keys = keys,
                        max_size = max_size
                    );
                }
                Err(_) => {
                    s.reads.release(self.peer_index, true);
                    return Err(End::RequestRefused);
                }
            }
        }
        Ok(())
    }
}

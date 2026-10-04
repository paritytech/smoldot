// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The warp join: CE 153 fragments up to the latest finalized epoch, the
//! finalized head and its justification, the head's state read against its
//! signed root, and re-anchoring the tree there. Until the join is applied it
//! never touches the live tree.

use super::{
    MAX_PEERS, STATE_READ_BYTES, State,
    connection::{Conn, InFlight},
    log::{End, Hex, Opt, Tag, Token, direction_str, event, request_ended},
    reads::{StateRead, StateReadError, StateReadResult, Trust},
};
use crate::{log, platform::PlatformRef};
use alloc::vec::Vec;
use smoldot::jam::{
    finality::{self, AuthoritySet, Justification},
    net,
    params::Params,
    state::LightState,
    tree::{self, HeaderTree},
    trie::{self, StateRequest},
    types::{BlockRequest, Direction, Final, GenesisLightState, Hash, Header},
    verify::verified_genesis,
};

#[derive(Debug)]
pub(super) enum WarpError {
    Finality(finality::Error),
    State(smoldot::jam::state::StateError),
    Tree(tree::InsertError),
    InvalidJoin,
    StaleAnchor,
    ResourceLimit,
}

/// Terminal availability failure, scoped to the exact authenticated anchor.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AnchorUnserved {
    pub(super) hash: Hash,
    pub(super) slot: u32,
}

impl core::fmt::Display for AnchorUnserved {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "anchor {:?} at slot {} is unserved",
            self.hash, self.slot
        )
    }
}

impl core::error::Error for AnchorUnserved {}

impl core::fmt::Display for WarpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Finality(e) => write!(f, "{e}"),
            Self::State(e) => write!(f, "{e}"),
            Self::Tree(e) => write!(f, "{e:?}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// [`Token`] of a warp error, unwrapped like its `Display`.
pub(super) fn warp_token(error: &WarpError) -> Token<'_> {
    match error {
        WarpError::Finality(error) => Token(error),
        WarpError::State(error) => Token(error),
        WarpError::Tree(error) => Token(error),
        other => Token(other),
    }
}

/// Staged authorities and state never affect the live tree until the finalized
/// head's justification and the state proofs against its signed root succeed.
pub(super) struct Warp {
    anchor: Hash,
    pub(super) authorities: AuthoritySet,
    last_slot: u32,
    /// Exact target already finalized and rotated by the last verified fragment.
    pub(super) last_final: Option<finality::Target>,
    pub(super) fragments: usize,
    pub(super) chain_done: bool,
    pub(super) final_head: Option<Final>,
    /// The frozen finalized head F, fetched as one descending block.
    pub(super) head: Option<Header>,
    /// F's verified GRANDPA target: its `state_root` is the signed posterior root
    /// the join reads against. `None` until F is authenticated.
    pub(super) finalized: Option<finality::Target>,
    state_responses: usize,
    pub(super) items: Vec<(trie::StateKey, Vec<u8>)>,
    read: Option<futures_channel::oneshot::Receiver<Result<StateReadResult, StateReadError>>>,
}

impl Warp {
    pub(super) fn new(state: &State) -> Self {
        Self {
            anchor: state.tree.finalized().hash(),
            authorities: state.authorities.clone(),
            last_slot: state.tree.finalized().slot(),
            last_final: None,
            fragments: 0,
            chain_done: false,
            final_head: None,
            head: None,
            finalized: None,
            state_responses: 0,
            items: Vec::new(),
            read: None,
        }
    }

    pub(super) fn advance(
        &mut self,
        params: &Params,
        bytes: &[u8],
        limits: &finality::WarpLimits,
    ) -> Result<(), WarpError> {
        let fragments =
            finality::decode_warp_response(params, bytes, limits).map_err(WarpError::Finality)?;
        self.chain_done = fragments.len() < 32;
        for fragment in fragments {
            if params.epoch_len == 0
                || fragment.header.slot / params.epoch_len <= self.last_slot / params.epoch_len
            {
                return Err(WarpError::InvalidJoin);
            }
            let (authorities, target) = self
                .authorities
                .advance_warp(params, &fragment, limits.proof)
                .map_err(WarpError::Finality)?;
            self.authorities = authorities;
            self.last_slot = fragment.header.slot;
            self.last_final = Some(target);
            self.fragments = self
                .fragments
                .checked_add(1)
                .ok_or(WarpError::ResourceLimit)?;
        }
        Ok(())
    }

    pub(super) fn receive_headers(
        &mut self,
        params: &Params,
        blocks: Vec<smoldot::jam::types::Block>,
        header_bytes: usize,
    ) -> Result<(), WarpError> {
        let advertised = self.final_head.as_ref().ok_or(WarpError::InvalidJoin)?;
        if blocks.len() != 1 || self.head.is_some() {
            return Err(WarpError::InvalidJoin);
        }
        let f = blocks
            .into_iter()
            .next()
            .ok_or(WarpError::InvalidJoin)?
            .header;
        if f.hash(params) != advertised.hash
            || f.slot != advertised.slot
            || f.slot < self.last_slot
            || f.encode(params).len() > header_bytes
        {
            return Err(WarpError::InvalidJoin);
        }
        // The fragment's proof used the outgoing set. Its successful advancement
        // already authenticated this exact header, signed its posterior root and
        // consumed its rotation.
        self.finalized = self
            .last_final
            .filter(|last| last.hash == advertised.hash && last.slot == f.slot);
        self.head = Some(f);
        Ok(())
    }

    pub(super) fn authenticate(
        &mut self,
        params: &Params,
        bytes: &[u8],
        limits: finality::Limits,
    ) -> Result<(), WarpError> {
        if self.finalized.is_some() {
            return Err(WarpError::InvalidJoin);
        }
        let f = self.head.as_ref().ok_or(WarpError::InvalidJoin)?;
        let hash = f.hash(params);
        let proof = Justification::decode(params, bytes, limits).map_err(WarpError::Finality)?;
        let verified = proof
            .verify(
                params,
                self.authorities.set_id(),
                self.authorities.current(),
                &hash,
                limits,
                |h| (*h == hash).then_some((hash, f.parent, f.prior_state_root, f.slot)),
            )
            .map_err(WarpError::Finality)?;
        if let Some(authorities) = self
            .authorities
            .after_finalizing(
                params,
                &verified,
                hash,
                f.slot,
                f.epoch_mark.as_ref().map(|mark| mark.validators.as_slice()),
            )
            .map_err(WarpError::Finality)?
        {
            self.authorities = authorities;
        }
        self.finalized = Some(*verified.target());
        Ok(())
    }

    /// Reads at F itself against the posterior root its justification signs.
    pub(super) fn next_read(&self) -> Result<StateRead, WarpError> {
        let target = self.finalized.as_ref().ok_or(WarpError::InvalidJoin)?;
        let index = *[4, 6, 8, 11]
            .get(self.items.len())
            .ok_or(WarpError::InvalidJoin)?;
        let key = trie::state_key(index);
        Ok(StateRead {
            at: target.hash,
            root: target.state_root,
            trust: Trust::Finalized,
            root_header: Some(target.hash),
            // The full range costs more bytes but saves three round trips. An
            // honest early stop falls back to the remaining keys one by one.
            request: StateRequest {
                block: target.hash,
                start: key,
                end: if self.items.is_empty() {
                    trie::state_key(11)
                } else {
                    key
                },
                max_size: STATE_READ_BYTES,
            },
        })
    }
}

/// Where a warp join stands, for `jam-warp-abandoned`.
pub(super) fn warp_step(warp: &Warp) -> &'static str {
    if !warp.chain_done {
        "fragments"
    } else if warp.head.is_none() {
        "head"
    } else if warp.finalized.is_none() {
        "justification"
    } else {
        "state"
    }
}

impl State {
    pub(super) fn reserve_warp(&mut self, peer: usize) -> Option<Warp> {
        // Discovery yields to a warp join: a refresh that no peer is serving
        // right now is cancelled, and retried at the next finality advance.
        if self.reads.owner.is_none() && self.discovery.read.take().is_some() {
            self.discovery.due = false;
        }
        if self.reads.owner.is_none()
            && self
                .reads
                .pending
                .as_ref()
                .is_some_and(|(_, tx)| tx.is_canceled())
        {
            self.reads.pending = None;
        }
        if self.stopped
            || self.warp_owner.is_some()
            || self.proof_owner.is_some()
            || self.reads.owner.is_some()
            || self.reads.pending.is_some()
        {
            return None;
        }
        self.warp_owner = Some(peer);
        Some(Warp::new(self))
    }

    pub(super) fn apply_warp(&mut self, peer: usize, warp: Warp) -> Result<(), WarpError> {
        if self.stopped
            || self.warp_owner != Some(peer)
            || self.tree.finalized().hash() != warp.anchor
        {
            return Err(WarpError::StaleAnchor);
        }
        let (Some(target), Some(head)) = (warp.finalized, warp.head) else {
            return Err(WarpError::InvalidJoin);
        };
        if warp.items.len() != 4 || head.hash(&self.params) != target.hash {
            return Err(WarpError::InvalidJoin);
        }
        // The items were proven against F's signed posterior root, so they are
        // the state after F: anchor at F directly, as a checkpoint would.
        let raw = GenesisLightState::from_state_items(
            &self.params,
            warp.items.iter().map(|(k, v)| (k, v.as_slice())),
        )
        .map_err(|_| WarpError::InvalidJoin)?;
        if raw.slot != head.slot {
            return Err(WarpError::InvalidJoin);
        }
        let state = LightState::from_anchor(&self.params, &raw).map_err(WarpError::State)?;
        let root = verified_genesis(&self.params, head, state);
        let tree = HeaderTree::new(self.params.clone(), root, self.tree_config)
            .map_err(WarpError::Tree)?;
        let revision = self
            .warp_revision
            .checked_add(1)
            .ok_or(WarpError::ResourceLimit)?;
        self.tree = tree;
        self.authorities = warp.authorities;
        self.warp_revision = revision;
        self.warp_owner = None;
        self.proof_attempts.clear();
        self.root_refusals = None;
        self.subscribers.clear();
        // A new anchor may sit in a later epoch; read again after its first
        // finality advance.
        self.discovery.stale = true;
        self.discovery.due = false;
        Ok(())
    }

    pub(super) fn refuse_root(&mut self, peer: usize, hash: Hash) -> Result<(), AnchorUnserved> {
        if hash != self.tree.finalized().hash() || peer >= MAX_PEERS {
            return Ok(());
        }
        let old = self
            .root_refusals
            .filter(|(root, _)| *root == hash)
            .map_or(0, |(_, mask)| mask);
        let mask = old | (1u8 << peer);
        self.root_refusals = Some((hash, mask));
        self.stop_if_unserved()
    }

    pub(super) fn stop_if_unserved(&mut self) -> Result<(), AnchorUnserved> {
        let mask = self
            .root_refusals
            .filter(|(hash, _)| *hash == self.tree.finalized().hash())
            .map_or(0, |(_, mask)| mask);
        // A concurrently staged warp may still replace the refused anchor.
        if self.warp_owner.is_none()
            && self.peer_count == MAX_PEERS
            && mask.count_ones() >= u32::try_from(self.peer_count).unwrap_or(u32::MAX)
        {
            self.stopped = true;
            self.subscribers.clear();
            return Err(AnchorUnserved {
                hash: self.tree.finalized().hash(),
                slot: self.tree.finalized().slot(),
            });
        }
        Ok(())
    }
}

impl<P: PlatformRef> Conn<'_, P> {
    /// Handles a CE 153 response: verifies the fragments against the staged set.
    pub(super) async fn warp_response(
        &mut self,
        request_id: net::RequestId,
        start_set_id: u32,
        fragments: Vec<u8>,
    ) -> Result<(), End> {
        let (Some(r), Some(warp)) = (self.warp_requested.take(), &mut self.warp) else {
            return Err(End::UnexpectedResponse);
        };
        if r.id != request_id
            || start_set_id != r.expected
            || r.expected != warp.authorities.set_id()
        {
            return Err(End::UnexpectedResponse);
        }
        let limits = {
            let s = self.state.lock().await;
            finality::WarpLimits {
                max_fragments: 32,
                max_header_bytes: s.header_bytes,
                proof: s.proof_limits(),
            }
        };
        let before = warp.fragments;
        if let Err(error) = warp.advance(self.params, &fragments, &limits) {
            request_ended!(
                self,
                "jam-warp-request-ended",
                r,
                "rejected",
                start_set_id = start_set_id,
                bytes = fragments.len(),
                error = warp_token(&error)
            );
            event!(
                self,
                "jam-warp-rejected",
                slot = self.peer_index,
                step = "fragments",
                req = r.tag.req,
                error = warp_token(&error)
            );
            return Err(End::WarpRejected);
        }
        request_ended!(
            self,
            "jam-warp-request-ended",
            r,
            "ok",
            start_set_id = start_set_id,
            bytes = fragments.len(),
            fragments = warp.fragments.saturating_sub(before),
            set_id = warp.authorities.set_id(),
            chain_done = warp.chain_done
        );
        Ok(())
    }

    /// Handles a failed CE 153 request: `NoData` ends the fragment chain.
    pub(super) fn warp_failed(&mut self, reason: net::RequestError) -> Result<(), End> {
        let req = self.warp_requested.take().map(|r| {
            request_ended!(self, "jam-warp-request-ended", r, "failed", error = ?reason);
            r.tag.req
        });
        // A reset without a code ends the chain too, as Firefox reports every
        // reset that way. This is safe: each received fragment was verified, and
        // a chain that ends early leaves an older authority set, against which
        // the finalized head's justification then fails to verify.
        if !matches!(
            reason,
            net::RequestError::NoData | net::RequestError::ResetWithoutCode
        ) {
            event!(
                self,
                "jam-warp-rejected",
                reason = ?reason,
                slot = self.peer_index,
                step = "fragments",
                req = Opt(req)
            );
            return Err(End::WarpFailed);
        }
        let Some(warp) = &mut self.warp else {
            return Err(End::UnexpectedResponse);
        };
        warp.chain_done = true;
        if warp.fragments == 0 {
            event!(
                self,
                "jam-warp-fragmentless",
                reason = ?reason,
                slot = self.peer_index,
                req = Opt(req)
            );
        }
        Ok(())
    }

    /// One step of the warp join on this connection, until it is applied or
    /// found unnecessary: reserve it, then request fragments, the finalized
    /// head, its justification and its state items in turn, then apply it.
    pub(super) async fn warp_turn(&mut self, now: &P::Instant) -> Result<(), End> {
        if self.warp.is_none() {
            self.warp = self.state.lock().await.reserve_warp(self.peer_index);
        }
        if let Some(w) = &mut self.warp {
            if !w.chain_done && self.warp_requested.is_none() {
                let start = w.authorities.set_id();
                let Ok(id) = self.connection.request_warp(start) else {
                    return Err(End::RequestRefused);
                };
                let tag = Tag::new("warp-join");
                self.warp_requested = Some(InFlight::new(id, start, now.clone(), tag));
                event!(
                    self,
                    "jam-warp-request-queued",
                    set_id = start,
                    slot = self.peer_index,
                    req = tag.req,
                    purpose = tag.purpose
                );
                self.local_progress = true;
            } else if w.chain_done {
                if w.fragments == 0 {
                    let mut s = self.state.lock().await;
                    s.warp_owner = None;
                    if let Err(error) = s.stop_if_unserved() {
                        log!(
                            self.platform,
                            Warn,
                            self.log_name,
                            "jam-anchor-unserved",
                            reason = "NoData",
                            error = error,
                            slot = s.tree.finalized().slot()
                        );
                        return Err(End::AnchorUnserved);
                    }
                    self.warp = None;
                    self.warped = true;
                    self.local_progress = true;
                } else {
                    if w.final_head.is_none() {
                        // Freeze the latest advertisement processed when CE153
                        // pagination completes, not subsequent announcements.
                        w.final_head = self.advertised.clone();
                        if let Some(f) = &w.final_head {
                            event!(
                                self,
                                "jam-warp-join-selected",
                                advertisement = self.advertisement_revision,
                                slot = f.slot,
                                conn = self.peer_index,
                                hash = Hex(&f.hash),
                                fragments = w.fragments,
                                set_id = w.authorities.set_id()
                            );
                        }
                    }
                    if w.head.is_none() && self.requested.is_none() {
                        let Some(f) = &w.final_head else {
                            return Err(End::WarpInvalid);
                        };
                        // F alone: the read is at F against its signed root.
                        let request = BlockRequest {
                            hash: f.hash,
                            direction: Direction::DescendingInclusive,
                            max_blocks: 1,
                        };
                        let Ok(id) = self.connection.request_blocks(request.clone()) else {
                            return Err(End::RequestRefused);
                        };
                        let tag = Tag::new("warp-join-head");
                        event!(
                            self,
                            "jam-block-request-queued",
                            slot = self.peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            hash = Hex(&request.hash),
                            direction = direction_str(&request.direction),
                            max_blocks = request.max_blocks
                        );
                        self.requested = Some(InFlight::new(id, request, now.clone(), tag));
                        self.local_progress = true;
                    } else if w.head.is_some()
                        && w.finalized.is_none()
                        && self.proof_requested.is_none()
                    {
                        let Some(f) = &w.final_head else {
                            return Err(End::WarpInvalid);
                        };
                        let Ok(id) = self.connection.request_justification(f.hash) else {
                            return Err(End::RequestRefused);
                        };
                        let tag = Tag::new("warp-join");
                        event!(
                            self,
                            "jam-justification-request-queued",
                            slot = self.peer_index,
                            req = tag.req,
                            purpose = tag.purpose,
                            target = Hex(&f.hash),
                            target_slot = f.slot
                        );
                        self.proof_requested = Some(InFlight::new(id, f.hash, now.clone(), tag));
                        self.local_progress = true;
                    } else if w.finalized.is_some() {
                        if let Some(rx) = &mut w.read {
                            match rx.try_recv() {
                                Ok(Some(Ok(result))) => {
                                    if !w.next_read().is_ok_and(|read| result.answers(&read)) {
                                        return Err(End::WarpInvalid);
                                    }
                                    let before = w.items.len();
                                    for index in [4, 6, 8, 11].into_iter().skip(before) {
                                        let key = trie::state_key(index);
                                        if key > result.range.complete_to {
                                            break;
                                        }
                                        let Some((_, value)) =
                                            result.range.entries.iter().find(|(k, _)| *k == key)
                                        else {
                                            return Err(End::WarpInvalid);
                                        };
                                        w.items.push((key, value.clone()));
                                        event!(
                                            self,
                                            "jam-warp-item-read",
                                            slot = self.peer_index,
                                            item = index,
                                            bytes = value.len()
                                        );
                                    }
                                    if w.items.len() == before {
                                        return Err(End::WarpInvalid);
                                    }
                                    w.state_responses += 1;
                                    w.read = None;
                                    self.local_progress = true;
                                }
                                Ok(None) => {}
                                Ok(Some(Err(StateReadError::Unavailable))) => {
                                    event!(
                                        self,
                                        "jam-state-unavailable",
                                        slot = self.peer_index,
                                        purpose = "warp-join"
                                    );
                                    return Err(End::StateUnavailable);
                                }
                                Err(_) => return Err(End::StateCancelled),
                            }
                        }
                        if w.items.len() == 4 {
                            self.apply_join().await?;
                        } else if w.read.is_none() {
                            let Ok(read) = w.next_read() else {
                                return Err(End::WarpInvalid);
                            };
                            let mut s = self.state.lock().await;
                            match s.reads.start(read) {
                                Ok(rx) => {
                                    w.read = Some(rx);
                                    self.local_progress = true;
                                }
                                Err(net::Error::Limit) => {}
                                Err(_) => return Err(End::WarpInvalid),
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Applies the completed join to the shared state and restarts this
    /// connection's header sync at the new anchor.
    async fn apply_join(&mut self) -> Result<(), End> {
        let Some(w) = self.warp.take() else {
            return Err(End::WarpInvalid);
        };
        let count = w.fragments;
        let fragment_finality = w.last_final.is_some_and(|last| {
            w.final_head
                .as_ref()
                .is_some_and(|f| f.hash == last.hash && f.slot == last.slot)
        });
        let state_responses = w.state_responses;
        let state_bytes: usize = w.items.iter().map(|(_, value)| value.len()).sum();
        let mut s = self.state.lock().await;
        if let Err(error) = s.apply_warp(self.peer_index, w) {
            event!(
                self,
                "jam-warp-rejected",
                slot = self.peer_index,
                step = "apply",
                error = warp_token(&error)
            );
            return Err(End::WarpRejected);
        }
        self.warp_revision = s.warp_revision;
        self.fetch_size.count = self
            .params
            .epoch_len
            .clamp(1, 64)
            .min(self.fetch_size.ceiling);
        self.cursor = Some(s.tree.finalized().hash());
        *self.root_probe = None;
        self.fallback = true;
        self.waiting_for_finality = None;
        self.repair.clear();
        self.imports.clear();
        self.announcements.clear();
        self.warped = true;
        self.local_progress = true;
        event!(
            self,
            "jam-warp-applied",
            set_id = s.authorities.set_id(),
            slot = s.tree.finalized().slot(),
            fragments = count,
            state_bytes = state_bytes,
            state_responses = state_responses,
            fragment_finality = fragment_finality,
            conn = self.peer_index,
            hash = Hex(&s.tree.finalized().hash())
        );
        Ok(())
    }
}

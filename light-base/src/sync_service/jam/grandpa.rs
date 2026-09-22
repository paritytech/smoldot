// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! GRANDPA finality: one shared proof reservation across connections, the
//! CE 130 justification requests, and verifying a justification against the
//! header tree to advance the finalized root.

use super::{
    FRAME_BYTES, Notification, State,
    connection::{Conn, InFlight},
    log::{End, Hex, Opt, Tag, Token, event, request_ended},
};
use crate::{log, platform::PlatformRef};
use alloc::vec::Vec;
use smoldot::jam::{
    finality::{self, Justification},
    net,
    types::{Final, Hash},
};

impl State {
    pub(super) fn proof_limits(&self) -> finality::Limits {
        let witnesses = (FRAME_BYTES / self.header_bytes).max(1);
        finality::Limits {
            max_bytes: FRAME_BYTES,
            max_ancestry_headers: witnesses,
            max_ancestry_steps: self
                .tree
                .len()
                .saturating_add(witnesses)
                .saturating_mul(usize::from(self.params.max_validators))
                .saturating_mul(2),
        }
    }

    /// Select an authenticated target, stopping at the first unfinalized epoch
    /// mark. Advertisements trigger fetching but never supply authority state.
    pub(super) fn reserve_proof(&mut self, peer: usize, advertised: &Final) -> Option<Hash> {
        if self.stopped
            || self.proof_owner.is_some()
            || advertised.slot <= self.tree.finalized().slot()
        {
            return None;
        }
        let tip = self
            .tree
            .get(&advertised.hash)
            .unwrap_or_else(|| self.tree.best());
        let path: Vec<_> = self
            .tree
            .ancestors(&tip.hash())
            .take_while(|b| b.hash() != self.tree.finalized().hash())
            .collect();
        let candidate = path
            .iter()
            .rev()
            .find(|b| b.epoch_changed())
            .copied()
            .or_else(|| path.first().copied())?;
        if candidate.slot() > advertised.slot {
            return None;
        }
        let target = candidate.hash();
        self.proof_attempts.retain(|(hash, _)| {
            self.tree.get(hash).is_some() && *hash != self.tree.finalized().hash()
        });
        let bit = 1u8 << peer;
        if let Some((_, attempts)) = self
            .proof_attempts
            .iter_mut()
            .find(|(hash, _)| *hash == target)
        {
            if *attempts & bit != 0 {
                return None;
            }
            *attempts |= bit;
        } else {
            self.proof_attempts.push((target, bit));
        }
        self.proof_owner = Some((peer, target));
        Some(target)
    }

    pub(super) fn finalize(&mut self, target: Hash, bytes: &[u8]) -> Result<(), finality::Error> {
        let limits = self.proof_limits();
        let proof = Justification::decode(&self.params, bytes, limits)?;
        let verified = proof.verify(
            &self.params,
            self.authorities.set_id(),
            self.authorities.current(),
            &target,
            limits,
            |hash| self.tree.get(hash).and_then(finality::ancestry_link),
        )?;
        let result = self.tree.finalize(&verified, &mut self.authorities)?;
        if result.finalized.is_empty() {
            return Ok(());
        }
        let notification = Notification::Finalized {
            finalized_blocks_hashes: result.finalized,
            pruned_blocks: result.pruned,
            best_block_hash_if_changed: result.best_changed.then(|| self.tree.best().hash()),
        };
        self.subscribers
            .retain(|tx| tx.try_send(notification.clone()).is_ok());
        self.proof_attempts.retain(|(hash, _)| {
            self.tree.get(hash).is_some() && *hash != self.tree.finalized().hash()
        });
        Ok(())
    }
}

impl<P: PlatformRef> Conn<'_, P> {
    /// Handles a CE 130 response.
    pub(super) async fn justification_response(
        &mut self,
        request_id: net::RequestId,
        target: Hash,
        justification: Vec<u8>,
    ) -> Result<(), End> {
        let Some(r) = self
            .proof_requested
            .take()
            .filter(|r| r.id == request_id && r.expected == target)
        else {
            return Err(End::UnexpectedResponse);
        };
        request_ended!(
            self,
            "jam-justification-request-ended",
            r,
            "ok",
            bytes = justification.len()
        );
        let mut s = self.state.lock().await;
        s.proof_owner = None;
        if let Err(error) = s.finalize(target, &justification) {
            event!(
                self,
                "jam-finality-rejected",
                slot = self.peer_index,
                req = r.tag.req,
                target = Hex(&target),
                set_id = s.authorities.set_id(),
                error = Token(&error)
            );
            return Err(End::FinalityRejected);
        }
        event!(
            self,
            "jam-finalized",
            slot = s.tree.finalized().slot(),
            set_id = s.authorities.set_id(),
            retained = s.tree.len(),
            conn = self.peer_index,
            req = r.tag.req,
            hash = Hex(&s.tree.finalized().hash())
        );
        Ok(())
    }

    /// Handles a failed CE 130 request.
    pub(super) async fn justification_failed(
        &mut self,
        reason: net::RequestError,
    ) -> Result<(), End> {
        if let Some(r) = self.proof_requested.take() {
            request_ended!(
                self,
                "jam-justification-request-ended",
                r,
                "failed",
                error = ?reason
            );
        }
        self.state.lock().await.proof_owner = None;
        Ok(())
    }

    /// Requests a justification for the target [`State::reserve_proof`] picks
    /// against the peer's advertised finalized head.
    pub(super) async fn request_justification(&mut self) -> Result<(), End> {
        let Some(advertised) = &self.advertised else {
            return Ok(());
        };
        let mut s = self.state.lock().await;
        if let Some(target) = s.reserve_proof(self.peer_index, advertised) {
            let Ok(id) = self.connection.request_justification(target) else {
                return Err(End::RequestRefused);
            };
            let tag = Tag::new("finality");
            self.proof_requested = Some(InFlight::new(id, target, self.platform.now(), tag));
            self.local_progress = true;
            event!(
                self,
                "jam-justification-request-queued",
                slot = self.peer_index,
                req = tag.req,
                purpose = tag.purpose,
                target = Hex(&target),
                target_slot = Opt(s.tree.get(&target).map(|block| block.slot())),
                set_id = s.authorities.set_id()
            );
        }
        Ok(())
    }
}

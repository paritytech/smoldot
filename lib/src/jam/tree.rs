// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Bounded, fork-aware storage of authenticated JAM headers.
//!
//! The trusted starting point is fixed; there is no finalization in the MVP.
//!
//! Callers map query snapshots and insert results to their own subscription
//! types. An insertion with nonempty `evicted` requires subscribers to
//! resnapshot or stop: subscription notifications cannot express pruning
//! without finalization. `Full` likewise signals stop. No notification history
//! is retained here.

use super::{
    params::Params,
    types::{Final, Hash, Header},
    verify::{VerifiedHeader, VerifyError, verify_header},
};
use crate::chain::fork_tree::{ForkTree, NodeIndex};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{iter, num::NonZeroUsize};

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Maximum stored blocks, including the starting point. Must be nonzero.
    pub max_blocks: NonZeroUsize,
    /// Retained allocation budget, including shared records and index metadata.
    pub max_bytes: usize,
    /// Maximum distinct shared epoch records (including the root's).
    pub max_epoch_records: NonZeroUsize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Insert {
    Inserted {
        hash: Hash,
        is_new_best: bool,
        /// Removed hashes, child before parent; bounded by `max_blocks`.
        evicted: Vec<Hash>,
    },
    AlreadyKnown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertError {
    UnknownParent,
    ParentMismatch,
    Verify(VerifyError),
    /// The verified slot does not exceed the parent's slot.
    InvalidVerifiedSlot,
    /// A trusted anchor from [`verified_genesis`](super::verify::verified_genesis):
    /// only [`HeaderTree::new`] accepts one.
    TrustedAnchor,
    Full,
}

/// Outcome of [`HeaderTree::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifySuccess {
    /// The header is already retained, the root included. It was not verified again.
    AlreadyKnown,
    /// An authenticated child of a retained block, for [`HeaderTree::insert_verified`].
    Verified(VerifiedHeader),
}

/// A fixed root plus verified descendants. Queries never expose mutable state.
/// Best is the highest verified slot; equal slots retain the earlier insertion.
/// Hash-indexed lookups; eviction rebuilds the bounded tree.
pub struct HeaderTree {
    params: Params,
    config: Config,
    root: VerifiedHeader,
    blocks: ForkTree<VerifiedHeader>,
    best: Option<NodeIndex>,
    index: BTreeMap<Hash, NodeIndex>,
}

impl HeaderTree {
    /// Starts at a caller-trusted authenticated checkpoint/genesis.
    pub fn new(params: Params, root: VerifiedHeader, config: Config) -> Result<Self, InsertError> {
        let slot = core::mem::size_of::<VerifiedHeader>() + 10 * core::mem::size_of::<usize>();
        config
            .max_blocks
            .get()
            .checked_mul(slot)
            .ok_or(InsertError::Full)?;
        let mut tree = Self {
            params,
            config,
            root,
            blocks: ForkTree::new(),
            best: None,
            index: BTreeMap::new(),
        };
        if tree.retained_bytes() > config.max_bytes {
            return Err(InsertError::Full);
        }
        tree.blocks = ForkTree::with_capacity(config.max_blocks.get() - 1);
        Ok(tree)
    }

    /// Verifies `header` as a child of the retained block `parent_hash`. Time is
    /// Unix seconds. A mismatched explicit parent is always rejected first. An
    /// exact duplicate, the root included, is reported without verifying it again.
    pub fn verify(
        &self,
        parent_hash: Hash,
        header: Header,
        now_unix_secs: u64,
    ) -> Result<VerifySuccess, InsertError> {
        if header.parent != parent_hash {
            return Err(InsertError::ParentMismatch);
        }
        if self.get(&header.hash(&self.params)).is_some() {
            return Ok(VerifySuccess::AlreadyKnown);
        }
        let parent = self.get(&parent_hash).ok_or(InsertError::UnknownParent)?;
        verify_header(&self.params, parent, header, now_unix_secs)
            .map(VerifySuccess::Verified)
            .map_err(InsertError::Verify)
    }

    /// Inserts a header that [`HeaderTree::verify`] returned, atomically. Exact
    /// duplicates (including the root) succeed even at capacity. The parent must
    /// still be retained.
    pub fn insert_verified(&mut self, verified: VerifiedHeader) -> Result<Insert, InsertError> {
        if self.get(&verified.hash()).is_some() {
            return Ok(Insert::AlreadyKnown);
        }
        if verified.is_anchor() {
            return Err(InsertError::TrustedAnchor);
        }
        let parent_hash = verified.parent();
        let parent = self.get(&parent_hash).ok_or(InsertError::UnknownParent)?;
        if verified.slot() <= parent.slot() {
            return Err(InsertError::InvalidVerifiedSlot);
        }
        let is_new_best = verified.slot() > self.best().slot();
        let prospective = self.accounting(Some(&verified), &[]);
        let evicted = if self.len() >= self.config.max_blocks.get()
            || prospective.0 > self.config.max_bytes
            || prospective.1 > self.config.max_epoch_records.get()
        {
            if !is_new_best {
                return Err(InsertError::Full);
            }
            self.eviction_chain(&parent_hash).ok_or(InsertError::Full)?
        } else {
            Vec::new()
        };
        let prospective = self.accounting(Some(&verified), &evicted);
        if prospective.0 > self.config.max_bytes
            || prospective.1 > self.config.max_epoch_records.get()
        {
            return Err(InsertError::Full);
        }

        // ForkTree only offers finalization-style pruning. Rebuild survivors
        // rather than using those operations, which could discard other forks.
        // Build before committing so any structural failure remains atomic.
        let mut rebuilt_index = BTreeMap::new();
        let mut rebuilt = if evicted.is_empty() {
            None
        } else {
            let mut blocks: ForkTree<VerifiedHeader> =
                ForkTree::with_capacity(self.config.max_blocks.get() - 1);
            for block in self.ancestry_order().skip(1) {
                if evicted.contains(&block.hash()) {
                    continue;
                }
                let parent = if block.parent() == self.root.hash() {
                    None
                } else {
                    Some(
                        rebuilt_index
                            .get(&block.parent())
                            .copied()
                            .ok_or(InsertError::UnknownParent)?,
                    )
                };
                let index = blocks.insert(parent, block.clone());
                rebuilt_index.insert(block.hash(), index);
            }
            Some(blocks)
        };
        let index = if rebuilt.is_some() {
            &mut rebuilt_index
        } else {
            &mut self.index
        };
        let blocks = rebuilt.as_mut().unwrap_or(&mut self.blocks);
        let parent = if parent_hash == self.root.hash() {
            None
        } else {
            Some(
                index
                    .get(&parent_hash)
                    .copied()
                    .ok_or(InsertError::UnknownParent)?,
            )
        };
        let hash = verified.hash();
        let node_index = blocks.insert(parent, verified);
        index.insert(hash, node_index);
        if let Some(rebuilt) = rebuilt {
            self.blocks = rebuilt;
            self.index = rebuilt_index;
        }
        // Every rebuild accompanies a new best, so no old index survives it.
        if is_new_best {
            self.best = Some(node_index);
        }
        Ok(Insert::Inserted {
            hash,
            is_new_best,
            evicted,
        })
    }

    fn eviction_chain(&self, incoming_parent: &Hash) -> Option<Vec<Hash>> {
        let best = self.best().hash();
        let (mut index, _) = self
            .blocks
            .iter_unordered()
            .filter(|(index, block)| {
                self.blocks.children(Some(*index)).next().is_none()
                    && !self.is_ancestor(&block.hash(), &best)
                    && !self.is_ancestor(&block.hash(), incoming_parent)
            })
            .min_by_key(|(_, block)| (block.slot(), block.hash()))?;
        let mut removed = Vec::new();
        loop {
            removed.push(self.blocks.get(index)?.hash());
            let Some(parent) = self.blocks.parent(index) else {
                break;
            };
            let block = self.blocks.get(parent)?;
            if self.blocks.children(Some(parent)).count() != 1
                || self.is_ancestor(&block.hash(), &best)
                || self.is_ancestor(&block.hash(), incoming_parent)
            {
                break;
            }
            index = parent;
        }
        Some(removed)
    }

    /// Looks up any retained block, including the root.
    pub fn get(&self, hash: &Hash) -> Option<&VerifiedHeader> {
        if *hash == self.root.hash() {
            Some(&self.root)
        } else {
            self.index
                .get(hash)
                .and_then(|index| self.blocks.get(*index))
        }
    }

    /// The starting point, which never changes.
    pub fn finalized(&self) -> &VerifiedHeader {
        &self.root
    }

    /// Highest-slot leaf; the root is best only when there are no descendants.
    pub fn best(&self) -> &VerifiedHeader {
        self.best
            .and_then(|index| self.blocks.get(index))
            .unwrap_or(&self.root)
    }

    /// Number of retained blocks, including the root.
    pub fn len(&self) -> usize {
        self.blocks.len() + 1
    }

    /// Accounted retained bytes, including distinct shared allocations once.
    pub fn retained_bytes(&self) -> usize {
        self.accounting(None, &[]).0
    }

    /// Number of distinct epoch records referenced by retained headers.
    pub fn epoch_records(&self) -> usize {
        self.accounting(None, &[]).1
    }

    /// Inline node, fork links and conservative B-tree index allocation overhead.
    pub const fn node_overhead() -> usize {
        core::mem::size_of::<VerifiedHeader>() + 16 * core::mem::size_of::<usize>() + 64
    }

    fn accounting(&self, incoming: Option<&VerifiedHeader>, removed: &[Hash]) -> (usize, usize) {
        let mut epochs = BTreeMap::new();
        let mut tickets = BTreeMap::new();
        // Preallocate the policy capacity so holes left by pruning cannot hide
        // retained slab storage. Eight words cover ForkTree's four Option<usize>
        // links; two more cover its flag, slab discriminant and alignment.
        let slot = core::mem::size_of::<VerifiedHeader>() + 10 * core::mem::size_of::<usize>();
        // Cover the partial B-tree root page and the containing structs too.
        let mut bytes = self
            .config
            .max_blocks
            .get()
            .saturating_mul(slot)
            .saturating_add(512 + core::mem::size_of::<Self>());
        for block in self
            .ancestry_order()
            .filter(|b| !removed.contains(&b.hash()))
            .chain(incoming)
        {
            let node = (Self::node_overhead() - slot).saturating_add(block.encoded_capacity());
            bytes = bytes.saturating_add(node);
            let (id, cost) = block.post_state().epoch_allocation();
            if epochs.insert(id, ()).is_none() {
                bytes = bytes.saturating_add(cost);
            }
            if let Some((id, cost)) = block.post_state().tickets_allocation()
                && tickets.insert(id, ()).is_none()
            {
                bytes = bytes.saturating_add(cost);
            }
        }
        (bytes, epochs.len())
    }

    /// Always false: the root cannot be removed.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Root first, then every retained descendant exactly once, parent before
    /// child. Sibling ordering is unspecified (not insertion order).
    pub fn ancestry_order(&self) -> impl Iterator<Item = &VerifiedHeader> {
        iter::once(&self.root).chain(self.blocks.iter_ancestry_order().map(|(_, block)| block))
    }

    /// Self-inclusive path from `hash` back to and including the root.
    /// Unknown hashes yield an empty iterator. The root's external parent is
    /// deliberately not followed.
    pub fn ancestors(&self, hash: &Hash) -> impl Iterator<Item = &VerifiedHeader> {
        iter::successors(self.get(hash), |block| {
            if block.hash() == self.root.hash() {
                None
            } else {
                self.get(&block.parent())
            }
        })
    }

    /// Self-inclusive ancestry. False if either hash is unknown.
    pub fn is_ancestor(&self, ancestor: &Hash, descendant: &Hash) -> bool {
        self.ancestors(descendant)
            .any(|block| block.hash() == *ancestor)
    }

    /// UP 0 leaves, in unspecified order. Includes the root only when it is
    /// the sole stored block; otherwise includes only non-finalized leaves.
    pub fn leaves(&self) -> Vec<Final> {
        if self.blocks.is_empty() {
            return alloc::vec![Final {
                hash: self.root.hash(),
                slot: self.root.slot()
            }];
        }
        self.blocks
            .iter_unordered()
            .filter(|(index, _)| self.blocks.children(Some(*index)).next().is_none())
            .map(|(_, block)| Final {
                hash: block.hash(),
                slot: block.slot(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;

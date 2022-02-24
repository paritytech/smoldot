// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Data structure containing trees of nodes.
//!
//! The [`AsyncTree`] data structure can be used in situations where there exists a finalized
//! block, plus a tree of non-finalized blocks that all descend from that finalized block.
//!
//! The [`AsyncTree`] only contains the non-finalized blocks. The finalized block, virtual root
//! of the tree, is only implicitly there.
//!
//! When a block is inserted in the [`AsyncTree`], it is marked as "pending".
//! TODO: finish doc
//!
//! # Example
//!
//! ```
//! use smoldot::chain::async_tree;
//! use std::time::{Instant, Duration};
//!
//! let mut tree = async_tree::AsyncTree::new(async_tree::Config {
//!     finalized_async_user_data: "hello",
//!     retry_after_failed: Duration::from_secs(5),
//! });
//!
//! // Insert a new best block, parent of the finalized block.
//! // When doing so, we insert a "user data", a value opaque to the tree and that can be
//! // retreived later. Here we pass "my block".
//! let _my_block_index = tree.input_insert_block("my block", None, false, true);
//!
//! // When calling `next_necessary_async_op`, the tree now generates a new asynchronous
//! // operation id.
//! let async_op_id = match tree.next_necessary_async_op(&Instant::now()) {
//!     async_tree::NextNecessaryAsyncOp::Ready(params) => {
//!         assert_eq!(params.block_index, _my_block_index);
//!         assert_eq!(*params.block_user_data, "my block");
//!         params.id
//!     }
//!     async_tree::NextNecessaryAsyncOp::NotReady { when: _ } => {
//!         // In this example, this variant can't be returned. In practice, however, you need
//!         // to call `next_necessary_async_op` again after `when`.
//!         panic!();
//!     }
//! };
//!
//! // The user is now responsible for performing this asynchronous operation.
//! // When it is finished, call `async_op_finished`.
//! // Just like when inserting a new block, we insert another "user data" in all the blocks that
//! // have this asynchronous operation associated to them.
//! tree.async_op_finished(async_op_id, "world");
//!
//! // You can now advance the best and finalized block of the tree. Calling this function tries
//! // to update the tree to match the best and finalized block of the input, except that only
//! // blocks whose asynchronous operation is finished are considered.
//! match tree.try_advance_output() {
//!     Some(async_tree::OutputUpdate::Block(block)) => {
//!         assert_eq!(block.index, _my_block_index);
//!         assert_eq!(*block.user_data, "my block");
//!         assert_eq!(*block.async_op_user_data, "world");
//!         assert!(block.is_new_best);
//!     }
//!     _ => unreachable!() // Unreachable in this example.
//! }
//! ```

use crate::chain::fork_tree;
use alloc::vec::Vec;
use core::{cmp, mem, ops, time::Duration};

pub use fork_tree::NodeIndex;

/// Identifier for an asynchronous operation in the [`AsyncTree`].
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct AsyncOpId(u64);

#[derive(Debug)]
pub enum NextNecessaryAsyncOp<'a, TNow, TBl> {
    Ready(AsyncOpParams<'a, TBl>),
    NotReady { when: Option<TNow> },
}

/// Information about an operation that must be started.
#[derive(Debug)]
pub struct AsyncOpParams<'a, TBl> {
    /// Identifier to later provide when calling [`AsyncTree::async_op_finished`] or
    /// [`AsyncTree::async_op_failure`].
    pub id: AsyncOpId,

    /// Index of the block to perform the operation against.
    pub block_index: NodeIndex,

    /// User data of the block to perform the operation against.
    pub block_user_data: &'a TBl,
}

/// Configuration for [`AsyncTree::new`].
pub struct Config<TAsync> {
    /// Outcome of the asynchronous operation of the finalized block.
    pub finalized_async_user_data: TAsync,

    /// After an asynchronous operation fails, retry after this given duration.
    pub retry_after_failed: Duration,
}

pub struct AsyncTree<TNow, TBl, TAsync> {
    /// State of all the non-finalized blocks.
    non_finalized_blocks: fork_tree::ForkTree<Block<TNow, TBl, TAsync>>,

    /// Outcome of the asynchronous operation for the finalized block.
    finalized_async_user_data: TAsync,

    /// Index within [`AsyncTree::non_finalized_blocks`] of the current "output" best block.
    /// `None` if the best block is the finalized block.
    ///
    /// The value of [`Block::async_op`] for this block is guaranteed to be
    /// [`AsyncOpState::Finished`].
    best_block_index: Option<fork_tree::NodeIndex>,

    /// Index within [`AsyncTree::non_finalized_blocks`] of the finalized block according to
    /// the input. `None` if the input finalized block is the same as the output finalized block.
    ///
    /// The value of [`Block::async_op`] for this block is guaranteed to **not** be
    /// [`AsyncOpState::Finished`].
    input_finalized_index: Option<fork_tree::NodeIndex>,

    /// Incremented by one and stored within [`Block::input_best_block_weight`].
    input_best_block_next_weight: u32,

    /// Weight that would be stored in [`Block::input_best_block_weight`] of the finalized block.
    finalized_block_weight: u32,

    /// Identifier to assign to the next asynchronous operation.
    next_async_op_id: AsyncOpId,

    /// See [`Config::retry_after_failed`].
    retry_after_failed: Duration,
}

impl<TNow, TBl, TAsync> AsyncTree<TNow, TBl, TAsync>
where
    TNow: Clone + ops::Add<Duration, Output = TNow> + Ord,
    TAsync: Clone,
{
    /// Returns a new empty [`AsyncTree`].
    pub fn new(config: Config<TAsync>) -> Self {
        AsyncTree {
            best_block_index: None,
            finalized_async_user_data: config.finalized_async_user_data,
            non_finalized_blocks: fork_tree::ForkTree::with_capacity(32),
            input_finalized_index: None,
            input_best_block_next_weight: 2,
            finalized_block_weight: 1, // `0` is reserved for blocks who are never best.
            next_async_op_id: AsyncOpId(0),
            retry_after_failed: config.retry_after_failed,
        }
    }

    /// Replaces all asynchronous operation user data with new values.
    ///
    /// The returned tree keeps the same [`NodeIndex`]es as `self`.
    pub fn map_async_op_user_data<TAsync2>(
        self,
        mut map: impl FnMut(TAsync) -> TAsync2,
    ) -> AsyncTree<TNow, TBl, TAsync2> {
        AsyncTree {
            best_block_index: self.best_block_index,
            finalized_async_user_data: map(self.finalized_async_user_data),
            non_finalized_blocks: self.non_finalized_blocks.map(move |block| Block {
                async_op: match block.async_op {
                    AsyncOpState::Finished {
                        user_data,
                        reported,
                    } => AsyncOpState::Finished {
                        user_data: map(user_data),
                        reported,
                    },
                    AsyncOpState::InProgress {
                        async_op_id,
                        timeout,
                    } => AsyncOpState::InProgress {
                        async_op_id,
                        timeout,
                    },
                    AsyncOpState::Pending {
                        same_as_parent,
                        timeout,
                    } => AsyncOpState::Pending {
                        same_as_parent,
                        timeout,
                    },
                },
                input_best_block_weight: block.input_best_block_weight,
                user_data: block.user_data,
            }),
            input_finalized_index: self.input_finalized_index,
            input_best_block_next_weight: self.input_best_block_next_weight,
            finalized_block_weight: self.finalized_block_weight,
            next_async_op_id: self.next_async_op_id,
            retry_after_failed: self.retry_after_failed,
        }
    }

    /// Returns the [`NodeIndex`] of the current "output" best block.
    ///
    /// Returns `None` if there is no best block. In terms of logic, this means that the best block
    /// is the finalized block, which is out of scope of this data structure.
    pub fn best_block_index(&self) -> Option<(NodeIndex, &'_ TAsync)> {
        self.best_block_index.map(|best_block_index| {
            (
                best_block_index,
                match &self
                    .non_finalized_blocks
                    .get(best_block_index)
                    .unwrap()
                    .async_op
                {
                    AsyncOpState::Finished {
                        reported: true,
                        user_data,
                    } => user_data,
                    _ => unreachable!(),
                },
            )
        })
    }

    /// Returns the user data associated to the given block.
    ///
    /// # Panic
    ///
    /// Panics if the [`NodeIndex`] is invalid.
    ///
    pub fn block_user_data(&self, node_index: NodeIndex) -> &TBl {
        &self.non_finalized_blocks.get(node_index).unwrap().user_data
    }

    /// Returns the user data associated to the given block.
    ///
    /// # Panic
    ///
    /// Panics if the [`NodeIndex`] is invalid.
    ///
    pub fn block_user_data_mut(&mut self, node_index: NodeIndex) -> &mut TBl {
        &mut self
            .non_finalized_blocks
            .get_mut(node_index)
            .unwrap()
            .user_data
    }

    /// Returns the outcome of the asynchronous operation for the finalized block.
    ///
    /// This is the value that was passed at initialization, or is updated after
    /// [`AsyncTree::try_advance_output`] has returned [`OutputUpdate::Finalized`].
    pub fn finalized_async_user_data(&self) -> &TAsync {
        &self.finalized_async_user_data
    }

    /// Returns the asynchronous operation user data associated to the given block.
    ///
    /// Returns `None` if the asynchronous operation isn't complete for this block yet.
    ///
    /// # Panic
    ///
    /// Panics if the [`NodeIndex`] is invalid.
    ///
    pub fn block_async_user_data(&self, node_index: NodeIndex) -> Option<&TAsync> {
        match &self.non_finalized_blocks.get(node_index).unwrap().async_op {
            AsyncOpState::Finished { user_data, .. } => Some(user_data),
            _ => None,
        }
    }

    /// Returns the asynchronous operation user data associated to the given block.
    ///
    /// Returns `None` if the asynchronous operation isn't complete for this block yet.
    ///
    /// # Panic
    ///
    /// Panics if the [`NodeIndex`] is invalid.
    ///
    pub fn block_async_user_data_mut(&mut self, node_index: NodeIndex) -> Option<&mut TAsync> {
        match &mut self
            .non_finalized_blocks
            .get_mut(node_index)
            .unwrap()
            .async_op
        {
            AsyncOpState::Finished { user_data, .. } => Some(user_data),
            _ => None,
        }
    }

    /// Returns the parent of the given node. Returns `None` if the node doesn't have any parent,
    /// meaning that its parent is the finalized node.
    ///
    /// # Panic
    ///
    /// Panics if the [`NodeIndex`] is invalid.
    ///
    pub fn parent(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.non_finalized_blocks.parent(node)
    }

    /// Returns the list of children that have the given node as parent.
    ///
    /// # Panic
    ///
    /// Panics if the [`NodeIndex`] is invalid.
    ///
    pub fn children(&'_ self, node: Option<NodeIndex>) -> impl Iterator<Item = NodeIndex> + '_ {
        self.non_finalized_blocks.children(node)
    }

    /// Returns the list of all non-finalized blocks that have been inserted.
    ///
    /// Similar to [`AsyncTree::input_iter_unordered`], except that the returned items are
    /// guaranteed to be in an order in which the parents are found before their children.
    pub fn input_iter_ancestry_order(
        &'_ self,
    ) -> impl Iterator<Item = InputIterItem<'_, TBl, TAsync>> + '_ {
        self.non_finalized_blocks
            .iter_ancestry_order()
            .map(move |(id, b)| {
                let async_op_user_data = match &b.async_op {
                    AsyncOpState::Finished {
                        reported: true,
                        user_data,
                    } => Some(user_data),
                    _ => None,
                };

                InputIterItem {
                    id,
                    user_data: &b.user_data,
                    async_op_user_data,
                    is_output_best: self.best_block_index == Some(id),
                }
            })
    }

    /// Returns the list of all non-finalized blocks that have been inserted, in no particular
    /// order.
    pub fn input_iter_unordered(
        &'_ self,
    ) -> impl Iterator<Item = InputIterItem<'_, TBl, TAsync>> + '_ {
        self.non_finalized_blocks
            .iter_unordered()
            .map(move |(id, b)| {
                let async_op_user_data = match &b.async_op {
                    AsyncOpState::Finished {
                        reported: true,
                        user_data,
                    } => Some(user_data),
                    _ => None,
                };

                InputIterItem {
                    id,
                    user_data: &b.user_data,
                    async_op_user_data,
                    is_output_best: self.best_block_index == Some(id),
                }
            })
    }

    /// Returns the blocks targeted by this asynchronous operation.
    pub fn async_op_blocks(&self, async_op_id: AsyncOpId) -> impl Iterator<Item = &TBl> {
        self.non_finalized_blocks
            .iter_unordered()
            .map(|(_, b)| b)
            .filter(move |b| {
                matches!(b.async_op, AsyncOpState::InProgress { async_op_id: id, .. } if id == async_op_id)
            })
            .map(|b| &b.user_data)
    }

    /// Injects into the state of the data structure a completed operation.
    ///
    /// This "destroys" the [`AsyncOpId`].
    ///
    /// Returns the list of blocks whose state was affected by this asynchronous operation. This
    /// can be zero blocks, or be more than one block if blocks were inserted with
    /// `same_async_op_as_parent` as `true`.
    ///
    /// # Panic
    ///
    /// Panics if the [`AsyncOpId`] is invalid.
    ///
    pub fn async_op_finished(&mut self, async_op_id: AsyncOpId, user_data: TAsync) -> Vec<NodeIndex>
    where
        TAsync: Clone,
    {
        // TODO: O(n) and allocation

        // Find the list of blocks that are bound to this operation.
        let list = self
            .non_finalized_blocks
            .iter_unordered()
            .filter(|(_, b)| {
                matches!(b.async_op,
                AsyncOpState::InProgress {
                    async_op_id: id, ..
                } if id == async_op_id)
            })
            .map(|(b, _)| b)
            .collect::<Vec<_>>();

        // Update the blocks that were performing this operation to become `Finished`.
        for index in &list {
            let block = self.non_finalized_blocks.get_mut(*index).unwrap();
            match block.async_op {
                AsyncOpState::InProgress {
                    async_op_id: id, ..
                } if id == async_op_id => {
                    block.async_op = AsyncOpState::Finished {
                        user_data: user_data.clone(),
                        reported: false,
                    };
                }
                _ => {}
            }
        }

        list
    }

    /// Injects into the state of the state machine a failed operation.
    ///
    /// This same operation will not be repeated for the next few seconds. Thanks to this, it is
    /// possible to immediately call this function in response to a new necessary operation
    /// without worrying about loops.
    ///
    /// This "destroys" the [`AsyncOpId`].
    ///
    /// # Panic
    ///
    /// Panics if the [`AsyncOpId`] is invalid.
    ///
    pub fn async_op_failure(&mut self, async_op_id: AsyncOpId, now: &TNow) {
        let new_timeout = now.clone() + self.retry_after_failed;

        // Update the blocks that were performing this operation.
        // The blocks are iterated from child to parent, so that we can check, for each node,
        // whether its parent has the same asynchronous operation id.
        // TODO: O(n) and allocation
        for index in self
            .non_finalized_blocks
            .iter_ancestry_order()
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            let new_timeout = match self.non_finalized_blocks.get_mut(index).unwrap().async_op {
                AsyncOpState::InProgress {
                    async_op_id: id,
                    timeout: Some(ref timeout),
                } if id == async_op_id => Some(cmp::min(timeout.clone(), new_timeout.clone())),
                AsyncOpState::InProgress {
                    async_op_id: id,
                    timeout: None,
                } if id == async_op_id => Some(new_timeout.clone()),
                _ => continue,
            };

            let same_as_parent = self
                .non_finalized_blocks
                .parent(index)
                .map(
                    |idx| match self.non_finalized_blocks.get(idx).unwrap().async_op {
                        AsyncOpState::InProgress {
                            async_op_id: id, ..
                        } => id == async_op_id,
                        _ => false,
                    },
                )
                .unwrap_or(false);

            self.non_finalized_blocks.get_mut(index).unwrap().async_op = AsyncOpState::Pending {
                same_as_parent,
                timeout: new_timeout,
            };
        }
    }

    /// Examines the state of `self` and, if a block's asynchronous operation should be started,
    /// changes the state of the block to "in progress" and returns the parameters of the
    /// operation.
    ///
    /// The order in which operations are started is:
    ///
    /// - The input finalized block.
    /// - The input best block.
    /// - Any other block.
    ///
    pub fn next_necessary_async_op(&mut self, now: &TNow) -> NextNecessaryAsyncOp<TNow, TBl> {
        let mut when_not_ready = None;

        // Finalized block according to the blocks input.
        if let Some(idx) = self.input_finalized_index {
            match self.start_necessary_async_op(idx, now) {
                NextNecessaryAsyncOpInternal::Ready(async_op_id, block_index) => {
                    return NextNecessaryAsyncOp::Ready(AsyncOpParams {
                        id: async_op_id,
                        block_index,
                        block_user_data: &self
                            .non_finalized_blocks
                            .get(block_index)
                            .unwrap()
                            .user_data,
                    })
                }
                NextNecessaryAsyncOpInternal::NotReady { when } => {
                    when_not_ready = match (when, when_not_ready.take()) {
                        (None, None) => None,
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (Some(a), Some(b)) => Some(cmp::min(a, b)),
                    };
                }
            }
        }

        // Best block according to the blocks input.
        if let Some((idx, _)) = self
            .non_finalized_blocks
            .iter_unordered()
            .max_by_key(|(_, b)| b.input_best_block_weight)
        {
            match self.start_necessary_async_op(idx, now) {
                NextNecessaryAsyncOpInternal::Ready(async_op_id, block_index) => {
                    return NextNecessaryAsyncOp::Ready(AsyncOpParams {
                        id: async_op_id,
                        block_index,
                        block_user_data: &self
                            .non_finalized_blocks
                            .get(block_index)
                            .unwrap()
                            .user_data,
                    })
                }
                NextNecessaryAsyncOpInternal::NotReady { when } => {
                    when_not_ready = match (when, when_not_ready.take()) {
                        (None, None) => None,
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (Some(a), Some(b)) => Some(cmp::min(a, b)),
                    };
                }
            }
        }

        // Other blocks.
        for idx in self
            .non_finalized_blocks
            .iter_unordered()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>()
        {
            match self.start_necessary_async_op(idx, now) {
                NextNecessaryAsyncOpInternal::Ready(async_op_id, block_index) => {
                    return NextNecessaryAsyncOp::Ready(AsyncOpParams {
                        id: async_op_id,
                        block_index,
                        block_user_data: &self
                            .non_finalized_blocks
                            .get(block_index)
                            .unwrap()
                            .user_data,
                    })
                }
                NextNecessaryAsyncOpInternal::NotReady { when } => {
                    when_not_ready = match (when, when_not_ready.take()) {
                        (None, None) => None,
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (Some(a), Some(b)) => Some(cmp::min(a, b)),
                    };
                }
            }
        }

        NextNecessaryAsyncOp::NotReady {
            when: when_not_ready,
        }
    }

    /// Starts the operation of the block with the given index, if necessary.
    fn start_necessary_async_op(
        &mut self,
        block_index: NodeIndex,
        now: &TNow,
    ) -> NextNecessaryAsyncOpInternal<TNow> {
        match self
            .non_finalized_blocks
            .get_mut(block_index)
            .unwrap()
            .async_op
        {
            AsyncOpState::Pending {
                same_as_parent: false,
                ref timeout,
                ..
            } if timeout.as_ref().map_or(true, |t| t <= now) => {}
            AsyncOpState::Pending {
                same_as_parent: false,
                ref timeout,
                ..
            } => {
                return NextNecessaryAsyncOpInternal::NotReady {
                    when: timeout.clone(),
                }
            }
            _ => return NextNecessaryAsyncOpInternal::NotReady { when: None },
        };

        // A new asynchronous operation can be started.
        let async_op_id = self.next_async_op_id;
        self.next_async_op_id.0 += 1;

        // Gather `block_index` and all its descendants in `to_update`, provided the chain between
        // `block_index` and the node only contains `Pending { same_as_parent: true }`.
        // TODO: allocation and O(n) :-/
        let mut to_update = Vec::new();
        for (child_index, _) in self.non_finalized_blocks.iter_unordered() {
            if !self
                .non_finalized_blocks
                .is_ancestor(block_index, child_index)
            {
                continue;
            }

            if !self
                .non_finalized_blocks
                .node_to_root_path(child_index)
                .take_while(|idx| *idx != block_index)
                .all(|idx| {
                    matches!(
                        self.non_finalized_blocks.get(idx).unwrap().async_op,
                        AsyncOpState::Pending {
                            same_as_parent: true,
                            ..
                        }
                    )
                })
            {
                continue;
            }

            to_update.push(child_index);
        }

        debug_assert!(to_update.iter().any(|idx| *idx == block_index));
        for to_update in to_update {
            self.non_finalized_blocks
                .get_mut(to_update)
                .unwrap()
                .async_op = AsyncOpState::InProgress {
                async_op_id,
                timeout: None,
            };
        }

        NextNecessaryAsyncOpInternal::Ready(async_op_id, block_index)
    }

    /// Inserts a new block in the state machine.
    ///
    /// If `same_async_op_as_parent` is `true`, then the asynchronous operation user data is
    /// shared with the parent of the block. This "sharing" is done by emitting only one
    /// asynchronous operation for both blocks, and/or by cloning the `TAsyncOp`.
    ///
    /// # Panic
    ///
    /// Panics if `parent_index` is an invalid node.
    ///
    pub fn input_insert_block(
        &mut self,
        block: TBl,
        parent_index: Option<NodeIndex>,
        same_async_op_as_parent: bool,
        is_new_best: bool,
    ) -> NodeIndex {
        // When this block is inserted, value to use for `input_best_block_weight`.
        let input_best_block_weight = if is_new_best {
            let id = self.input_best_block_next_weight;
            debug_assert!(self
                .non_finalized_blocks
                .iter_unordered()
                .all(|(_, b)| b.input_best_block_weight < id));
            self.input_best_block_next_weight += 1;
            id
        } else {
            0
        };

        let async_op = match (same_async_op_as_parent, parent_index) {
            (true, Some(parent_index)) => {
                match &self
                    .non_finalized_blocks
                    .get(parent_index)
                    .unwrap()
                    .async_op
                {
                    AsyncOpState::InProgress { async_op_id, .. } => AsyncOpState::InProgress {
                        async_op_id: *async_op_id,
                        timeout: None,
                    },
                    AsyncOpState::Finished { user_data, .. } => AsyncOpState::Finished {
                        user_data: user_data.clone(),
                        reported: false,
                    },
                    AsyncOpState::Pending { .. } => AsyncOpState::Pending {
                        same_as_parent: true,
                        timeout: None,
                    },
                }
            }
            (true, None) => AsyncOpState::Finished {
                user_data: self.finalized_async_user_data.clone(),
                reported: false,
            },
            (false, _) => AsyncOpState::Pending {
                same_as_parent: false,
                timeout: None,
            },
        };

        // Insert the new block.
        self.non_finalized_blocks.insert(
            parent_index,
            Block {
                user_data: block,
                async_op,
                input_best_block_weight,
            },
        )
    }

    /// Updates the state machine to take into account that the input of blocks has finalized the
    /// given block.
    ///
    /// `new_best_block` is the best block after the finalization.
    ///
    /// > **Note**: Finalizing a block might have to modify the current best block if the block
    /// >           being finalized isn't an ancestor of the current best block.
    ///
    /// # Panic
    ///
    /// Panics if `node_to_finalize` or `new_best_block` aren't valid nodes.
    /// Panics if `new_best_block` is not a descendant of `node_to_finalize`.
    ///
    pub fn input_finalize(&mut self, node_to_finalize: NodeIndex, new_best_block: NodeIndex) {
        // Make sure that `new_best_block` is a descendant of `node_to_finalize`,
        // otherwise the state of the tree will be corrupted.
        // This is checked with an `assert!` rather than a `debug_assert!`, as this constraint
        // is part of the public API of this method.
        assert!(self
            .non_finalized_blocks
            .is_ancestor(node_to_finalize, new_best_block));

        self.input_finalized_index = Some(node_to_finalize);

        // If necessary, update the weight of the block.
        match &mut self
            .non_finalized_blocks
            .get_mut(new_best_block)
            .unwrap()
            .input_best_block_weight
        {
            w if *w == self.input_best_block_next_weight - 1 => {}
            w => {
                *w = self.input_best_block_next_weight;
                self.input_best_block_next_weight += 1;
            }
        }

        // Minor sanity checks.
        debug_assert!(self
            .non_finalized_blocks
            .iter_unordered()
            .all(|(_, b)| b.input_best_block_weight < self.input_best_block_next_weight));
    }

    /// Tries to update the output blocks to follow the input.
    ///
    /// Should be called after inserting a new block, finalizing a block, or when an operation is
    /// finished.
    ///
    /// Returns `None` if the state machine doesn't have any update. This method should be called
    /// repeatedly until it returns `None`. Each call can perform an additional update.
    pub fn try_advance_output(&mut self) -> Option<OutputUpdate<TBl, TAsync>> {
        // Try to advance the output finalized block.
        // `input_finalized_index` is `Some` if the input finalized is not already equal to the
        // output finalized.
        if let Some(input_finalized_index) = self.input_finalized_index {
            // Finding a new finalized block.
            // We always take the first node on the path towards `input_finalized_index`, in
            // order to finalized blocks one by one.
            let new_finalized = {
                self.non_finalized_blocks
                    .root_to_node_path(input_finalized_index)
                    .take(1)
                    .find(|node_index| {
                        matches!(
                            self.non_finalized_blocks.get(*node_index).unwrap().async_op,
                            AsyncOpState::Finished { reported: true, .. }
                        )
                    })
            };

            if let Some(new_finalized) = new_finalized {
                // Update `input_finalized_index`.
                if self.input_finalized_index == Some(new_finalized) {
                    self.input_finalized_index = None;
                }

                let mut pruned_blocks = Vec::new();
                let mut pruned_finalized = None;

                for pruned in self.non_finalized_blocks.prune_ancestors(new_finalized) {
                    debug_assert_ne!(Some(pruned.index), self.input_finalized_index);

                    // If the best block would be pruned, reset it to the finalized block. The
                    // best block is updated later down this function.
                    if self.best_block_index.map_or(false, |b| b == pruned.index) {
                        self.best_block_index = None;
                    }

                    // Update `self.finalized_block_weight`.
                    if pruned.index == new_finalized {
                        self.finalized_block_weight = pruned.user_data.input_best_block_weight;
                        pruned_finalized = Some(pruned);
                        continue;
                    }

                    let async_op = match pruned.user_data.async_op {
                        AsyncOpState::Finished {
                            user_data,
                            reported,
                            ..
                        } => {
                            // Here's a small corner case: the async operation was finished, but
                            // this block wasn't reported yet.
                            // This is actually problematic because the `TAsync` is thrown away
                            // silently while the public API gives the impression that all
                            // `TAsync`s are always returned.
                            // TODO: solve that
                            if reported {
                                Some(user_data)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    pruned_blocks.push((pruned.index, pruned.user_data.user_data, async_op));
                }

                // Try to advance the output best block to the `Finished` block with the highest
                // weight.
                // Weight of the current output best block.
                let mut current_runtime_service_best_block_weight = match self.best_block_index {
                    None => self.finalized_block_weight,
                    Some(idx) => {
                        self.non_finalized_blocks
                            .get(idx)
                            .unwrap()
                            .input_best_block_weight
                    }
                };

                for (node_index, block) in self.non_finalized_blocks.iter_unordered() {
                    // Check uniqueness of weights.
                    debug_assert!(
                        block.input_best_block_weight != current_runtime_service_best_block_weight
                            || block.input_best_block_weight == 0
                            || self.best_block_index == Some(node_index)
                    );

                    if block.input_best_block_weight <= current_runtime_service_best_block_weight {
                        continue;
                    }

                    if !matches!(
                        block.async_op,
                        AsyncOpState::Finished { reported: true, .. }
                    ) {
                        continue;
                    }

                    // Input best can be updated to the block being iterated.
                    current_runtime_service_best_block_weight = block.input_best_block_weight;
                    self.best_block_index = Some(node_index);

                    // Continue looping, as there might be another block with an even
                    // higher weight.
                }

                let pruned_finalized = pruned_finalized.unwrap();
                let former_finalized_async_op_user_data = match pruned_finalized.user_data.async_op
                {
                    AsyncOpState::Finished { user_data, .. } => {
                        mem::replace(&mut self.finalized_async_user_data, user_data)
                    }
                    _ => unreachable!(),
                };

                return Some(OutputUpdate::Finalized {
                    former_index: new_finalized,
                    user_data: pruned_finalized.user_data.user_data,
                    async_op_user_data: &self.finalized_async_user_data,
                    former_finalized_async_op_user_data,
                    pruned_blocks,
                    best_block_index: self.best_block_index,
                });
            }
        }

        // Now try to report blocks that haven't been reported yet.
        // TODO: O(n) complexity and allocations
        for node_index in self
            .non_finalized_blocks
            .iter_unordered()
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>()
        {
            // Skip this block if its parent isn't reported yet.
            if let Some(parent) = self.non_finalized_blocks.parent(node_index) {
                if !matches!(
                    self.non_finalized_blocks.get(parent).unwrap().async_op,
                    AsyncOpState::Finished { reported: true, .. }
                ) {
                    continue;
                }
            }

            // Skip this block if it's already been reported. Otherwise, mark it as reported.
            match &mut self
                .non_finalized_blocks
                .get_mut(node_index)
                .unwrap()
                .async_op
            {
                AsyncOpState::Finished { reported, .. } if !*reported => {
                    *reported = true;
                }
                _ => continue,
            }

            // Try to mark the best we're about to report as best block, if possible.
            let is_new_best = self
                .non_finalized_blocks
                .get(node_index)
                .unwrap()
                .input_best_block_weight
                > self
                    .best_block_index
                    .map_or(self.finalized_block_weight, |idx| {
                        self.non_finalized_blocks
                            .get(idx)
                            .unwrap()
                            .input_best_block_weight
                    });
            if is_new_best {
                debug_assert_ne!(self.best_block_index, Some(node_index));
                self.best_block_index = Some(node_index);
            }

            // Report the new block.
            return Some(OutputUpdate::Block(OutputUpdateBlock {
                index: node_index,
                user_data: &self.non_finalized_blocks.get(node_index).unwrap().user_data,
                async_op_user_data: match &self
                    .non_finalized_blocks
                    .get(node_index)
                    .unwrap()
                    .async_op
                {
                    AsyncOpState::Finished { user_data, .. } => user_data,
                    _ => unreachable!(),
                },
                is_new_best,
            }));
        }

        // Nothing to do.
        None
    }
}

/// See [`AsyncTree::input_iter_unordered`] and [`AsyncTree::input_iter_ancestry_order`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputIterItem<'a, TBl, TAsync> {
    /// Index of the block.
    pub id: NodeIndex,

    /// User data associated to this block that was passed to [`AsyncTree::input_insert_block`].
    pub user_data: &'a TBl,

    /// User data of the asynchronous operation of this block.
    ///
    /// `Some` if and only if the block has been reported in a [`OutputUpdate`] before.
    pub async_op_user_data: Option<&'a TAsync>,

    /// Whether this block is considered as the best block of the output.
    ///
    /// Either 0 or 1 blocks will have the "is output best" boolean set to true. If no blocks have
    /// this boolean set, then the best block is the finalized block.
    pub is_output_best: bool,
}

/// See [`AsyncTree::try_advance_output`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputUpdate<'a, TBl, TAsync> {
    /// A non-finalized block has been finalized in the output.
    ///
    /// This block is no longer part of the data structure.
    ///
    /// Blocks are guaranteed to be finalized one after the other, without any gap.
    Finalized {
        /// Index of the node within the data structure. This index is no longer valid and is
        /// here for reference.
        former_index: NodeIndex,

        /// User data associated to this block.
        user_data: TBl,

        /// User data associated to the async operation of this block.
        ///
        /// This is the same value as is now returned by
        /// [`AsyncTree::finalized_async_user_data`], and is provided here for convenience.
        async_op_user_data: &'a TAsync,

        /// User data associated to the async operation of the previous finalized block.
        former_finalized_async_op_user_data: TAsync,

        /// Index of the best block after the finalization. `None` if the best block is the block
        /// that has just been finalized.
        best_block_index: Option<NodeIndex>,

        /// Blocks that were a descendant of the former finalized block but not of the new
        /// finalized block. These blocks are no longer part of the data structure.
        ///
        /// If the `Option<TAsync>` is `Some`, then that block was part of the output. Otherwise
        /// it wasn't.
        pruned_blocks: Vec<(NodeIndex, TBl, Option<TAsync>)>,
    },

    /// A new block has been added to the list of output unfinalized blocks.
    Block(OutputUpdateBlock<'a, TBl, TAsync>),
}

/// See [`OutputUpdate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputUpdateBlock<'a, TBl, TAsync> {
    /// Index of the node within the data structure.
    pub index: NodeIndex,

    /// User data associated to this block.
    pub user_data: &'a TBl,

    /// User data associated to the async operation of this block.
    pub async_op_user_data: &'a TAsync,

    /// True if this block is considered as the best block of the chain.
    pub is_new_best: bool,
}

struct Block<TNow, TBl, TAsync> {
    /// User data associated with that block.
    user_data: TBl,

    /// Operation information of that block. Shared amongst multiple different blocks.
    async_op: AsyncOpState<TNow, TAsync>,

    /// A block with a higher value here has been reported by the input as the best block
    /// more recently than a block with a lower value. `0` means never reported as best block.
    input_best_block_weight: u32,
}

enum AsyncOpState<TNow, TAsync> {
    /// Operation has finished and was successful.
    Finished {
        /// User data chose by the user.
        user_data: TAsync,

        /// `true` if this block has already been reported in the output.
        reported: bool,
    },

    /// Operation is currently in progress.
    InProgress {
        /// Identifier for this operation in the public API.
        /// Attributed from [`AsyncTree::next_async_op_id`]. Multiple different blocks can
        /// point to the same `async_op_id` when it is known that they point to the same operation.
        async_op_id: AsyncOpId,

        /// Do not start any operation before `TNow`. Used to avoid repeatedly trying to perform
        /// the operation on the same block over and over again when it's constantly failing.
        timeout: Option<TNow>,
    },

    /// Operation hasn't started.
    Pending {
        /// `true` if this operation should be the same as its parent's.
        /// If `true`, it is illegal for the parent to be in the state
        /// [`AsyncOpState::Finished`] or [`AsyncOpState::InProgress`].
        ///
        /// When in doubt, `false`.
        same_as_parent: bool,

        /// Do not start any operation before `TNow`. Used to avoid repeatedly trying to perform
        /// the same operation over and over again when it's constantly failing.
        timeout: Option<TNow>,
    },
}

/// Equivalent to [`NextNecessaryAsyncOp`] but private and doesn't use lifetimes. Necessary in
/// order to bypass borrow checker issues.
#[derive(Debug)]
enum NextNecessaryAsyncOpInternal<TNow> {
    Ready(AsyncOpId, NodeIndex),
    NotReady { when: Option<TNow> },
}

// TODO: needs tests

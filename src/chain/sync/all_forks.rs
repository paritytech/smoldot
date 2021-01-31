// Substrate-lite
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

//! *All-forks* header and body syncing.
//!
//! # Overview
//!
//! This state machine holds:
//!
//! - A list of sources of blocks, maintained by the API user.
//!  - For each source, a list of blocks hashes known by the source.
//! - The latest known finalized block.
//! - A tree of valid non-finalized blocks that all descend from the latest known finalized block.
//! - (if full mode) A list of block headers whose body is currently being downloaded.
//! - A list of block header waiting to be verified and whose ancestry with the latest finalized
//!   block is currently unknown.
//!
//! The state machine has the objective to synchronize the tree of non-finalized blocks with its
//! equivalent on the sources added by the API user.
//!
//! Because it is not possible to predict which block in this tree is going to be finalized in
//! the future, the entire tree needs to be synchronized.
//!
//! > **Example**: If the latest finalized block is block number 4, and the tree contains blocks
//! >              5, 6, and 7, and a source announces a block 5 that is different from the
//! >              locally-known block 5, a block request will be emitted for this block 5, even
//! >              if it is certain that this "other" block 5 will not become the local best
//! >              block. This is necessary in case it is this other block 5 that will end up
//! >              being finalized.
//!
//! # Full vs non-full
//!
//! The [`Config::full`] option configures whether the state machine only holds headers of the
//! non-finalized blocks (`full` equal to `false`), or the headers, and bodies, and storage
//! (`full` equal to `true`).
//!
//! In full mode, .
//!
//! # Bounded and unbounded containers
//!
//! It is important to limit the memory usage of this state machine no matter how the
//! potentially-malicious sources behave.
//!
//! The state in this state machine can be put into three categories:
//!
//! - Each source of blocks has a certain fixed-size state associated to it (containing for
//!   instance its best block number and height). Each source also has up to one in-flight
//!   request, which might incur more memory usage. Managing this additional request is out of
//!   scope of this module. The user of this module is expected to limit the number of
//!   simultaneous sources.
//!
//! - A set of verified blocks that descend from the latest finalized block. This set is
//!   unbounded. The consensus and finalization algorithms of the chain are supposed to limit
//!   the number of possible blocks in this set.
//!
//! - A set of blocks that can't be verified yet. Receiving a block announce inserts an element
//!   in this set. In order to handle situations where a malicious source announces lots of
//!   invalid blocks, this set must be bounded. Once it has reached a certain size, the blocks
//!   with the highest block number are discarded if their parent is also in this set or being
//!   downloaded from a source.
//!
//! Consequently, and assuming that the number of simultaneous sources is bounded, and that
//! the consensus and finalization algorithms of the chain are properly configured, malicious
//! sources can't indefinitely grow the state in this state machine.
//! Malicious sources, however, can potentially increase the number of block requests required to
//! download a long fork. This is, at most, an annoyance, and not a vulnerability.
//!

// TODO: finish ^

use crate::{
    chain::{blocks_tree, chain_information},
    header, verify,
};

use alloc::collections::{btree_map, BTreeMap, BTreeSet};
use core::{mem, num::NonZeroU64, time::Duration};

/// Configuration for the [`AllForksSync`].
#[derive(Debug)]
pub struct Config {
    /// Information about the latest finalized block and its ancestors.
    pub chain_information: chain_information::ChainInformation,

    /// Pre-allocated capacity for the number of block sources.
    pub sources_capacity: usize,

    /// Pre-allocated capacity for the number of blocks between the finalized block and the head
    /// of the chain.
    ///
    /// Should be set to the maximum number of block between two consecutive justifications.
    pub blocks_capacity: usize,

    /// Maximum number of blocks of unknown ancestry to keep in memory. A good default is 1024.
    ///
    /// When a potential long fork is detected, its blocks are downloaded progressively in
    /// descending order until a common ancestor is found.
    /// Unfortunately, an attack could generate fake very long forks in order to make the node
    /// consume a lot of memory keeping track of the blocks in that fork.
    /// In order to avoid this, a limit is added to the number of blocks of unknown ancestry that
    /// are kept in memory.
    ///
    /// Note that the download of long forks will always work no matter this limit. In the worst
    /// case scenario, the same blocks will be downloaded multiple times. There is an implicit
    /// minimum size equal to the number of sources that have been added to the state machine.
    ///
    /// Increasing this value has no drawback, except for increasing the maximum possible memory
    /// consumption of this state machine.
    //
    // Implementation note: the size of `disjoint_blocks` can temporarily grow above this limit
    // due to the internal processing of the state machine.
    pub max_disjoint_blocks: usize,

    /// If true, the block bodies and storage are also synchronized.
    pub full: bool,
}

pub struct AllForksSync<TSrc, TBl> {
    /// Data structure containing the non-finalized blocks.
    ///
    /// If [`Inner::full`], this only contains blocks whose header *and* body have been verified.
    chain: blocks_tree::NonFinalizedTree<Block<TBl>>,

    /// Extra fields. In a separate structure in order to be moved around.
    inner: Inner<TSrc>,
}

/// Extra fields. In a separate structure in order to be moved around.
struct Inner<TSrc> {
    /// See [`Config::full`].
    full: bool,

    /// List of sources. Controlled by the API user.
    sources: hashbrown::HashMap<SourceId, Source<TSrc>, fnv::FnvBuildHasher>,

    /// Identifier to allocate to the next source. Identifiers are never reused, which allows
    /// keeping obsolete identifiers in the internal state.
    next_source_id: SourceId,

    /// List of blocks whose header has been verified, but whose body is currently being
    /// downloaded from a source or should be downloaded from a source.
    ///
    /// Contains as value the SCALE-encoded header and source the block is currently being
    /// downloaded from.
    ///
    /// Always empty if `full` is `false`.
    pending_body_downloads:
        hashbrown::HashMap<[u8; 32], (Vec<u8>, Option<SourceId>), fnv::FnvBuildHasher>,

    /// Stores `(source, block hash)` tuples. Each tuple is an information about the fact that
    /// this source knows about the given block. Only contains blocks whose height is strictly
    /// superior to the height of the local finalized block.
    known_blocks1: BTreeSet<(SourceId, [u8; 32])>, // TODO: move to standalone container?

    /// Contains the same entries as [`Inner::known_blocks1`], but in reverse.
    known_blocks2: BTreeSet<([u8; 32], SourceId)>, // TODO: move to standalone container?

    /// Map of blocks whose parent is either unknown or present in `disjoint_blocks` as well.
    ///
    /// Only contains blocks whose height is strictly superior to the height of the local
    /// finalized block.
    ///
    /// The keys are `(block_height, block_hash)`. Using a b-tree and putting the block number in
    /// the key makes it possible to remove obsolete entries once blocks are finalized. For
    /// example, when block `N` is finalized, all entries whose key starts with `N` can be
    /// removed.
    disjoint_blocks: BTreeMap<(u64, [u8; 32]), DisjointBlock>, // TODO: move to standalone container?

    /// See [`Config::max_disjoint_blocks`].
    max_disjoint_blocks: usize,
}

struct Block<TBl> {
    user_data: TBl,
}

struct DisjointBlock {
    /// Header of the block, if known. Guaranteed to be a valid header.
    scale_encoded_header: Option<Vec<u8>>,

    /// If `true`, this block is known to be bad. It is potentially kept in the list in order
    /// to avoid redownloading this block if a child of this block later gets received.
    known_bad: bool,

    /// If `Some`, the given source is currently performing an ancestry search whose first
    /// block is the parent of this one.
    /// [`Source::occupation`] must be [`SourceOccupation::AncestrySearch`] with the parent hash
    /// indicated by [`DisjointBlock::scale_encoded_header`].
    ancestry_search: Option<SourceId>,
}

/// Extra fields specific to each blocks source.
struct Source<TSrc> {
    best_block_number: u64,
    best_block_hash: [u8; 32],
    occupation: SourceOccupation,
    user_data: TSrc,
}

#[derive(Debug)]
enum SourceOccupation {
    /// Source isn't doing anything.
    Idle,
    /// Source is performing an ancestry search. Contains the hash of the first block expected in
    /// the response.
    AncestrySearch([u8; 32]),
    /// Source is performing a header request. Contains the hash of the expected block.
    HeaderRequest([u8; 32]),
}

impl<TSrc, TBl> AllForksSync<TSrc, TBl> {
    /// Initializes a new [`AllForksSync`].
    pub fn new(config: Config) -> Self {
        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree::Config {
            chain_information: config.chain_information,
            blocks_capacity: config.blocks_capacity,
        });

        Self {
            chain,
            inner: Inner {
                full: config.full,
                max_disjoint_blocks: config.max_disjoint_blocks,
                sources: Default::default(),
                next_source_id: SourceId(0),
                pending_body_downloads: Default::default(),
                known_blocks1: Default::default(),
                known_blocks2: Default::default(),
                disjoint_blocks: Default::default(),
            },
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        self.chain.as_chain_information()
    }

    /// Inform the [`AllForksSync`] of a new potential source of blocks.
    ///
    /// The `user_data` parameter is opaque and decided entirely by the user. It can later be
    /// retrieved using [`SourceMutAccess::user_data`].
    ///
    /// Returns the newly-created source entry, plus optionally a request that should be started
    /// towards this source.
    pub fn add_source(
        &mut self,
        user_data: TSrc,
        best_block_number: u64,
        best_block_hash: [u8; 32],
    ) -> (SourceMutAccess<TSrc, TBl>, Option<Request>) {
        let new_id = {
            let id = self.inner.next_source_id;
            self.inner.next_source_id.0 += 1;
            id
        };

        self.inner.sources.insert(
            new_id,
            Source {
                best_block_number,
                best_block_hash,
                occupation: SourceOccupation::Idle,
                user_data,
            },
        );

        let mut request = None;

        // If the source's best block is below the finalized block height, don't do anything.
        if best_block_number > self.chain.finalized_block_header().number {
            self.inner.known_blocks1.insert((new_id, best_block_hash));
            self.inner.known_blocks2.insert((best_block_hash, new_id));

            // Add the source's best block to `disjoint_blocks`.
            if let btree_map::Entry::Vacant(entry) = self
                .inner
                .disjoint_blocks
                .entry((best_block_number, best_block_hash))
            {
                // If this entry was unknown, ask the source about this block.
                self.inner.sources.get_mut(&new_id).unwrap().occupation =
                    SourceOccupation::HeaderRequest(best_block_hash);

                entry.insert(DisjointBlock {
                    scale_encoded_header: None,
                    known_bad: false,
                    ancestry_search: Some(new_id), // TODO: we use `ancestry_search` field for a header request; clarify
                });

                request = Some(Request::HeaderRequest {
                    hash: best_block_hash,
                    number: best_block_number,
                });
            }
        }

        // `request` might have been already filled above.
        // If not, try use this new source to make progress elsewhere.
        if request.is_none() {
            // At this point, the state of `self` is consistency. It's ok to call a separate
            // method.
            request = self.source_next_request(new_id);
        }

        (
            SourceMutAccess {
                parent: self,
                source_id: new_id,
            },
            request,
        )
    }

    /// Grants access to a source, using its identifier.
    pub fn source_mut(&mut self, id: SourceId) -> Option<SourceMutAccess<TSrc, TBl>> {
        if self.inner.sources.contains_key(&id) {
            Some(SourceMutAccess {
                parent: self,
                source_id: id,
            })
        } else {
            None
        }
    }

    /// Call in response to a [`BlockAnnounceOutcome::AncestrySearchStart`].
    ///
    /// The headers are expected to be sorted in decreasing order. The first element of the
    /// iterator should be the block with the hash passed through
    /// [`BlockAnnounceOutcome::AncestrySearchStart::first_block_hash`]. Each subsequent element
    /// is then expected to be the parent of the previous one.
    ///
    /// It is legal for the iterator to be shorter than the number of blocks that were requested
    /// through [`BlockAnnounceOutcome::AncestrySearchStart::num_blocks`].
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't known locally as downloading something.
    ///
    pub fn ancestry_search_response(
        mut self,
        source_id: SourceId,
        scale_encoded_headers: Result<impl Iterator<Item = impl AsRef<[u8]>>, ()>,
    ) -> (AncestrySearchResponseOutcome<TSrc, TBl>, Option<Request>) {
        let outcome = self.ancestry_search_response_inner(source_id, scale_encoded_headers);
        // TODO: (outcome, )
        todo!()
    }

    fn ancestry_search_response_inner(
        mut self,
        source_id: SourceId,
        scale_encoded_headers: Result<impl Iterator<Item = impl AsRef<[u8]>>, ()>,
    ) -> AncestrySearchResponseOutcome<TSrc, TBl> {
        // Height of the finalized chain. Saved for later.
        let local_finalized_block_number = self.chain.finalized_block_header().number;

        // The next block in the list of headers should have a hash equal to this one.
        // Sets the `occupation` of `source_id` back to `Idle`.
        let expected_next_hash = match mem::replace(
            &mut self.inner.sources.get_mut(&source_id).unwrap().occupation,
            SourceOccupation::Idle,
        ) {
            SourceOccupation::AncestrySearch(hash) => hash,
            _ => panic!(),
        };

        // Iterate through the headers. If the request has failed, treat it the same way as if
        // no blocks were returned.
        for (index_in_response, scale_encoded_header) in scale_encoded_headers
            .into_iter()
            .flat_map(|l| l)
            .enumerate()
        {
            let scale_encoded_header = scale_encoded_header.as_ref();

            // Compare expected with actual hash.
            // This ensure that each header being processed is the parent of the previous one.
            if expected_next_hash != header::hash_from_scale_encoded_header(scale_encoded_header) {
                break;
            }

            // Invalid headers are skipped. The next iteration will likely fail when comparing
            // actual with expected hash, but we give it a chance.
            let decoded_header = match header::decode(scale_encoded_header) {
                Ok(h) => h,
                Err(_) => continue,
            };

            let decoded_header_number = decoded_header.number;

            match self.header_from_source(source_id, &expected_next_hash, decoded_header, false) {
                BlockAnnounceOutcome::HeaderVerify(this) => {
                    return AncestrySearchResponseOutcome::Verify(this);
                }
                BlockAnnounceOutcome::TooOld(this) => {
                    // Block is below the finalized block number.
                    // Ancestry searches never request any block earlier than the finalized block
                    // number. `TooOld` can happen if the source is misbehaving, but also if the
                    // finalized block has been updated between the moment the request was emitted
                    // and the moment the response is received.
                    debug_assert_eq!(index_in_response, 0);
                    self = this;
                    break;
                }
                BlockAnnounceOutcome::NotFinalizedChain(this) => {
                    // Block isn't part of the finalized chain.
                    // This doesn't necessarily mean that the source and the local node disagree
                    // on the finalized chain. It is possible that the finalized block has been
                    // updated between the moment the request was emitted and the moment the
                    // response is received.
                    self = this;

                    // Discard from the local state all blocks that descend from this one.
                    // TODO: blocks aren't marked as bad
                    // TODO: keep known bad blocks and document
                    self.discard_disjoint_chain(decoded_header_number, expected_next_hash);

                    return AncestrySearchResponseOutcome::NotFinalizedChain {
                        discarded_unverified_block_headers: todo!(),
                    };
                }
                BlockAnnounceOutcome::AlreadyInChain(this) => {
                    // Block is already in chain. Can happen if a different response or
                    // announcement has arrived and been processed between the moment the request
                    // was emitted and the moment the response is received.
                    debug_assert_eq!(index_in_response, 0);
                    return AncestrySearchResponseOutcome::AllAlreadyInChain(this);
                }
                BlockAnnounceOutcome::Disjoint(this) => {
                    // Block of unknown ancestry. Continue looping.
                    self = this;
                }
            }
        }

        // If this is reached, then the ancestry search was inconclusive. Only disjoint blocks
        // have been received.
        AncestrySearchResponseOutcome::Inconclusive(self)
    }

    /// Finds a request that the given source could start performing.
    ///
    /// If `Some` is returned, updates the [`SourceOccupation`] in `self` and returns the request
    /// that must be started.
    fn source_next_request(&mut self, source_id: SourceId) -> Option<Request> {
        let source_access = self.inner.sources.get_mut(&source_id).unwrap();
        debug_assert!(matches!(source_access.occupation, SourceOccupation::Idle));

        // Iterator through `pending_body_downloads` to find a block that needs attention.
        for (block_hash, _) in self
            .inner
            .pending_body_downloads
            .iter()
            .filter(|(_, (_, s))| s.is_none())
        {
            // Only download the block if the source knows about it.
            // `continue` if this `pending_body_download` isn't known by this source.
            if !self.inner.known_blocks1.contains(&(source_id, *block_hash)) {
                debug_assert!(!self.inner.known_blocks2.contains(&(*block_hash, source_id)));
                continue;
            } else {
                debug_assert!(self.inner.known_blocks2.contains(&(*block_hash, source_id)));
            }

            // TODO: finish
            todo!()
        }

        // Iterator through `disjoint_blocks` to find a block that needs attention.
        for (&(ref disjoint_block_height, ref disjoint_block_hash), &mut ref mut disjoint_block) in
            self.inner.disjoint_blocks.iter_mut()
        {
            // Bad blocks are kept only for informative purposes and don't require any further
            // action.
            if disjoint_block.known_bad {
                continue;
            }

            // The source can only operate on blocks that it knows about.
            // `continue` if this `disjoint_block` isn't known by this source.
            if !self
                .inner
                .known_blocks1
                .contains(&(source_id, *disjoint_block_hash))
            {
                debug_assert!(!self
                    .inner
                    .known_blocks2
                    .contains(&(*disjoint_block_hash, source_id)));
                continue;
            } else {
                debug_assert!(self
                    .inner
                    .known_blocks2
                    .contains(&(*disjoint_block_hash, source_id)));
            }

            // Header of the block might not necessarily be known.
            if let Some(disjoint_block_encoded_header) =
                disjoint_block.scale_encoded_header.as_ref()
            {
                if disjoint_block.ancestry_search.is_none() {
                    // Start an ancestry search in order to find an ancestor of this block in our
                    // local chain. When answered, this will ultimately add new blocks to
                    // `disjoint_block`.
                    disjoint_block.ancestry_search = Some(source_id);

                    let local_finalized_height = self.chain.finalized_block_header().number;
                    debug_assert!(*disjoint_block_height > local_finalized_height);
                    return Some(Request::AncestrySearch {
                        first_block_hash: *header::decode(&disjoint_block_encoded_header)
                            .unwrap()
                            .parent_hash,
                        num_blocks: NonZeroU64::new(
                            *disjoint_block_height - local_finalized_height,
                        )
                        .unwrap(),
                    });
                }
            } else if disjoint_block.ancestry_search.is_none() {
                // Block header isn't known.
                // Start a header request to obtain the header of this block.
                disjoint_block.ancestry_search = Some(source_id);
                return Some(Request::HeaderRequest {
                    number: *disjoint_block_height,
                    hash: *disjoint_block_hash,
                });
            }
        }

        None
    }

    /// Update the source with a newly-announced block.
    ///
    /// > **Note**: This information is normally reported by the source itself. In the case of a
    /// >           a networking peer, call this when the source sent a block announce.
    ///
    /// Must be passed the current UNIX time in order to verify that the block doesn't pretend to
    /// come from the future.
    ///
    /// # Panic
    ///
    /// Panics if [`source_id`] is invalid.
    ///
    pub fn block_announce(
        self,
        source_id: SourceId,
        announced_scale_encoded_header: Vec<u8>,
        is_best: bool,
    ) -> BlockAnnounceOutcome<TSrc, TBl> {
        // TODO: also return Option<Request>?
        let announced_header = match header::decode(&announced_scale_encoded_header) {
            Ok(h) => h,
            Err(err) => todo!(), // TODO: return (BlockAnnounceOutcome::InvalidHeader(err), None),
        };

        let announced_header_hash = announced_header.hash();

        self.header_from_source(source_id, &announced_header_hash, announced_header, is_best)
    }

    /// Called when a source reports a header, either through a block announce, an ancestry
    /// search result, or a block header query.
    ///
    /// `known_to_be_source_best` being `true` means that we are sure that this is the best block
    /// of the source. `false` means "it is not", but also "maybe", "unknown", and similar.
    ///
    /// # Panic
    ///
    /// Panics if [`source_id`] is invalid.
    ///
    fn header_from_source(
        mut self,
        source_id: SourceId,
        header_hash: &[u8; 32],
        header: header::HeaderRef,
        known_to_be_source_best: bool,
    ) -> BlockAnnounceOutcome<TSrc, TBl> {
        debug_assert_eq!(header.hash(), *header_hash);

        // No matter what is done below, start by updating the view the local state machine
        // maintains for this source.
        if known_to_be_source_best {
            let source = self.inner.sources.get_mut(&source_id).unwrap();
            source.best_block_number = header.number;
            source.best_block_hash = header.hash();
        }

        // It is assumed that all sources will eventually agree on the same finalized chain. If
        // the block number is lower or equal than the locally-finalized block number, it is
        // assumed that this source is simply late compared to the local node, and that the block
        // that has been received is either part of the finalized chain or belongs to a fork that
        // will get discarded by this source in the future.
        if header.number <= self.chain.finalized_block_header().number {
            return BlockAnnounceOutcome::TooOld(self);
        }

        // Now that we know that the block height is (supposedly) a descendant of the finalized
        // chain, add it to `known_blocks`.
        debug_assert_eq!(
            self.inner.known_blocks1.len(),
            self.inner.known_blocks2.len()
        );
        self.inner.known_blocks1.insert((source_id, *header_hash));
        self.inner.known_blocks2.insert((*header_hash, source_id));

        // TODO: somehow optimize? the encoded block is normally known from it being decoded
        let scale_encoded_header = header.scale_encoding_vec();

        // Calculate the height of the parent of the block.
        let parent_header_number = match header.number.checked_sub(1) {
            Some(n) => n,
            // The code right above verifies that `header.number <= finalized_number`,
            // which is always true if `header.number` is 0.
            None => unreachable!(),
        };

        // If the block is already part of the local tree of blocks, nothing more to do.
        if self
            .chain
            .non_finalized_block_by_hash(&header_hash)
            .is_some()
        {
            return BlockAnnounceOutcome::AlreadyInChain(self);
        }

        // `pending_body_downloads` contains blocks whose header has already been verified.
        if self.inner.pending_body_downloads.contains_key(header_hash) {
            debug_assert!(self.inner.full);
            return BlockAnnounceOutcome::AlreadyInChain(self);
        }

        if *header.parent_hash == self.chain.finalized_block_hash()
            || self
                .chain
                .non_finalized_block_by_hash(header.parent_hash)
                .is_some()
        {
            // Parent is in the `NonFinalizedTree`, meaning it is possible to verify it.
            debug_assert!(!self
                .inner
                .disjoint_blocks
                .contains_key(&(header.number, *header_hash)));

            let block_height = header.number;
            let parent_hash = *header.parent_hash;
            BlockAnnounceOutcome::HeaderVerify(HeaderVerify {
                parent: self,
                block_hash: *header_hash,
                block_height,
                parent_hash,
                scale_encoded_header,
            })
        } else if header.number == self.chain.finalized_block_header().number + 1 {
            // Checked above.
            debug_assert_ne!(*header.parent_hash, self.chain.finalized_block_hash());

            // Announced block is not part of the finalized chain.
            debug_assert!(!self
                .inner
                .disjoint_blocks
                .contains_key(&(header.number, *header_hash)));
            BlockAnnounceOutcome::NotFinalizedChain(self)
        } else {
            // Parent is not in the `NonFinalizedTree`. It is unknown whether this block belongs
            // to the same finalized chain as the one known locally, but we expect that it is the
            // case.

            // Update `disjoint_blocks`.
            match self
                .inner
                .disjoint_blocks
                .entry((header.number, *header_hash))
            {
                btree_map::Entry::Occupied(mut entry) => {
                    match &mut entry.get_mut().scale_encoded_header {
                        Some(h) => debug_assert_eq!(*h, scale_encoded_header),
                        h @ None => *h = Some(scale_encoded_header.to_vec()),
                    }
                }
                btree_map::Entry::Vacant(entry) => {
                    entry.insert(DisjointBlock {
                        scale_encoded_header: Some(scale_encoded_header.to_vec()),
                        known_bad: false,
                        ancestry_search: None,
                    });
                }
            }

            BlockAnnounceOutcome::Disjoint(self)
        }
    }

    /// Call in response to a [`BlockAnnounceOutcome::BlockBodyDownloadStart`].
    ///
    /// # Panic
    ///
    /// Panics if the source wasn't known locally as downloading something.
    ///
    pub fn block_body_response(
        mut self,
        now_from_unix_epoch: Duration,
        source_id: SourceId,
        block_body: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> (BlockBodyVerify<TSrc, TBl>, Option<Request>) {
        // TODO: unfinished

        todo!()

        /*// TODO: update occupation

        // Removes traces of the request from the state machine.
        let block_header_hash = if let Some((h, _)) = self
            .inner
            .pending_body_downloads
            .iter_mut()
            .find(|(_, (_, s))| *s == Some(source_id))
        {
            let hash = *h;
            let header = self.inner.pending_body_downloads.remove(&hash).unwrap().0;
            (header, hash)
        } else {
            panic!()
        };

        // Sanity check.
        debug_assert_eq!(block_header_hash.1, block_header_hash.0.hash());

        // If not full, there shouldn't be any block body download happening in the first place.
        debug_assert!(self.inner.full);

        match self
            .chain
            .verify_body(
                block_header_hash.0.scale_encoding()
                    .fold(Vec::new(), |mut a, b| { a.extend_from_slice(b.as_ref()); a }), now_from_unix_epoch) // TODO: stupid extra allocation
        {
            blocks_tree::BodyVerifyStep1::BadParent { .. }
            | blocks_tree::BodyVerifyStep1::InvalidHeader(..)
            | blocks_tree::BodyVerifyStep1::Duplicate(_) => unreachable!(),
            blocks_tree::BodyVerifyStep1::ParentRuntimeRequired(_runtime_req) => {
                todo!()
            }
        }*/
    }

    /// Passed a known entry in `disjoint_blocks`. Removes this entry and any known children of
    /// this block.
    ///
    /// # Panic
    ///
    /// Panics if `(number, hash)` isn't an entry in [`Inner::disjoint_chain]`.
    ///
    fn discard_disjoint_chain(&mut self, number: u64, hash: [u8; 32]) {
        // TODO: keep a list of banned blocks for later? this is required by chain specs anyway

        // The implementation consists in iterating over the increasing block number, and removing
        // all blocks whose parent was removed at the previous iteration.

        // List of blocks to discard at the next iteration.
        let mut blocks_to_discard = Vec::with_capacity(16);
        blocks_to_discard.push(hash);

        for number in number.. {
            // Find in `disjoint_blocks` any block whose parent is in `blocks_to_discard`.
            let blocks_to_discard_next = {
                let mut blocks_to_discard_next = Vec::with_capacity(16);
                for ((_, hash), block) in self
                    .inner
                    .disjoint_blocks
                    .range((number + 1, [0; 32])..(number + 2, [0; 32]))
                {
                    if let Some(encoded) = block.scale_encoded_header.as_ref() {
                        let decoded = header::decode(encoded).unwrap();
                        if blocks_to_discard.iter().any(|b| b == decoded.parent_hash) {
                            blocks_to_discard_next.push(*hash);
                        }
                    }
                }
                blocks_to_discard_next
            };

            // Now discard `blocks_to_discard`.
            for to_discard in mem::replace(&mut blocks_to_discard, blocks_to_discard_next) {
                let discarded_block = self
                    .inner
                    .disjoint_blocks
                    .remove(&(number, to_discard))
                    .unwrap();

                // Any ongoing search needs to be cancelled.
                if let Some(_source_id) = discarded_block.ancestry_search {
                    todo!() // TODO:
                }
            }

            // The `for` loop would be infinite unless we put an explicit `break`.
            // Note that `blocks_to_discard` was replaced with `blocks_to_discard_next` above,
            // we're therefore testing `blocks_to_discard_next.is_empty()`.
            if blocks_to_discard.is_empty() {
                break;
            }
        }
    }
}

/// Request that should be performed towards a source.
#[must_use]
pub enum Request {
    /// An ancestry search is necessary in situations where there are links missing between some
    /// block headers and the local chain of valid blocks. It consists in asking the source for
    /// its block headers in descending order starting from `first_block_height`. The answer will
    /// make it possible for the local state machine to determine how the chain is connected.
    ///
    /// > **Note**: This situation can happen for instance after a network split (also called
    /// >           *netsplit*) ends. During the split, some nodes have produced one chain, while
    /// >           some other nodes have produced a different chain.
    AncestrySearch {
        /// Hash of the first block to request.
        first_block_hash: [u8; 32],

        /// Number of blocks the request should return.
        ///
        /// Note that this is only an indication, and the source is free to give fewer blocks
        /// than requested. If that happens, the state machine might later send out further
        /// ancestry search requests to complete the chain.
        num_blocks: NonZeroU64,
    },

    /// The header of the block with the given hash is requested.
    HeaderRequest {
        /// Height of the block.
        ///
        /// > **Note**: This value is passed because it is always known, but the hash alone is
        /// >           expected to be enough to fetch the block header.
        number: u64,

        /// Hash of the block whose header to obtain.
        hash: [u8; 32],
    },

    /// The body of the block with the given hash is requested.
    ///
    /// Can only happen if [`Config::full`].
    BodyRequest {
        /// Height of the block.
        ///
        /// > **Note**: This value is passed because it is always known, but the hash alone is
        /// >           expected to be enough to fetch the block body.
        number: u64,

        /// Hash of the block whose body to obtain.
        hash: [u8; 32],
    },
}

/// Access to a source in a [`AllForksSync`]. Obtained through [`AllForksSync::source_mut`].
pub struct SourceMutAccess<'a, TSrc, TBl> {
    parent: &'a mut AllForksSync<TSrc, TBl>,

    /// Guaranteed to be a valid entry in [`AllForksSync::sources`].
    source_id: SourceId,
}

impl<'a, TSrc, TBl> SourceMutAccess<'a, TSrc, TBl> {
    /// Returns the identifier of this source.
    pub fn id(&self) -> SourceId {
        self.source_id
    }

    /// Returns true if the source has earlier announced the block passed as parameter or one of
    /// its descendants.
    // TODO: document precisely what it means
    pub fn knows_block(&self, hash: &[u8; 32]) -> bool {
        if self
            .parent
            .inner
            .known_blocks1
            .contains(&(self.source_id, *hash))
        {
            return true;
        }

        let source = self.parent.inner.sources.get(&self.source_id).unwrap();

        // TODO: finish
        false
    }

    /// Removes the source from the [`AllForksSync`].
    ///
    /// Removing the source implicitly cancels the request that is associated to it (if any).
    ///
    /// Returns the user data that was originally passed to [`AllForksSync::add_source`], plus
    /// an `Option`.
    /// If this `Option` is `Some`, it contains a request that must be started towards the source
    /// indicated by the [`SourceId`].
    ///
    /// > **Note**: For example, if the source that has just been removed was performing an
    /// >           ancestry search, the `Option` might contain that same ancestry search.
    pub fn remove(self) -> (TSrc, Option<(SourceId, Request)>) {
        let source_id = self.source_id;
        let source = self.parent.inner.sources.remove(&source_id).unwrap();

        if let Some((_, (_, src))) = self
            .parent
            .inner
            .pending_body_downloads
            .iter_mut()
            .find(|(_, (_, s))| *s == Some(source_id))
        {
            // TODO: redirect download to other source
            *src = None;
        }

        // Purge `known_blocks1` and `known_blocks2`.
        let known_blocks = self
            .parent
            .inner
            .known_blocks1
            .range((source_id, [0; 32])..=(source_id, [0xff; 32]))
            .map(|(_, h)| *h)
            .collect::<Vec<_>>();
        for known_block in known_blocks {
            let _was_in1 = self
                .parent
                .inner
                .known_blocks1
                .remove(&(source_id, known_block));
            let _was_in2 = self
                .parent
                .inner
                .known_blocks2
                .remove(&(known_block, source_id));
            debug_assert!(_was_in1);
            debug_assert!(_was_in2);
        }

        match source.occupation {
            SourceOccupation::Idle => {}
            SourceOccupation::AncestrySearch(hash) => {
                todo!()
            }
            SourceOccupation::HeaderRequest(_) => todo!(),
        }

        // TODO: None hardcoded
        (source.user_data, None)
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`AllForksSync::add_source`].
    pub fn user_data(&mut self) -> &mut TSrc {
        let source = self.parent.inner.sources.get_mut(&self.source_id).unwrap();
        &mut source.user_data
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`AllForksSync::add_source`].
    pub fn into_user_data(self) -> &'a mut TSrc {
        let source = self.parent.inner.sources.get_mut(&self.source_id).unwrap();
        &mut source.user_data
    }
}

/// Outcome of calling [`AllForksSync::header_from_source`].
pub enum BlockAnnounceOutcome<TSrc, TBl> {
    /// Header is ready to be verified.
    HeaderVerify(HeaderVerify<TSrc, TBl>),

    /// Announced block is too old to be part of the finalized chain.
    ///
    /// It is assumed that all sources will eventually agree on the same finalized chain. Blocks
    /// whose height is inferior to the height of the latest known finalized block should simply
    /// be ignored. Whether or not this old block is indeed part of the finalized block isn't
    /// verified, and it is assumed that the source is simply late.
    TooOld(AllForksSync<TSrc, TBl>),
    /// Announced block has already been successfully verified and is part of the non-finalized
    /// chain.
    AlreadyInChain(AllForksSync<TSrc, TBl>),
    /// Announced block is known to not be a descendant of the finalized block.
    NotFinalizedChain(AllForksSync<TSrc, TBl>),
    /// Header cannot be verified now, and has been stored for later.
    Disjoint(AllForksSync<TSrc, TBl>),
}

/// Outcome of calling [`SourceMutAccess::ancestry_search_response`].
pub enum AncestrySearchResponseOutcome<TSrc, TBl> {
    /// Ready to start verifying one or more headers return in the ancestry search.
    Verify(HeaderVerify<TSrc, TBl>),

    /// Source has given blocks that aren't part of the finalized chain.
    ///
    /// This doesn't necessarily mean that the source is malicious or uses a different chain. It
    /// is possible for this to legitimately happen, for example if the finalized chain has been
    /// updated while the ancestry search was in progress.
    NotFinalizedChain {
        /// List of block headers that were pending verification and that have now been discarded
        /// since it has been found out that they don't belong to the finalized chain.
        discarded_unverified_block_headers: Vec<Vec<u8>>,
    },

    /// Couldn't verify any of the blocks of the ancestry search. Some or all of these blocks
    /// have been stored in the local machine for later.
    Inconclusive(AllForksSync<TSrc, TBl>),

    /// All blocks in the ancestry search response were already in the list of verified blocks.
    ///
    /// This can happen if a block announce or different ancestry search response has been
    /// processed in between the request and response.
    AllAlreadyInChain(AllForksSync<TSrc, TBl>),
}

/// Identifier for a source in the [`AllForksSync`].
//
// Implementation note: the `u64` values are never re-used, making it possible to avoid clearing
// obsolete SourceIds in the `AllForksSync` state machine.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourceId(u64);

/// Header verification to be performed.
///
/// Internally holds the [`AllForksSync`].
pub struct HeaderVerify<TSrc, TBl> {
    parent: AllForksSync<TSrc, TBl>,
    block_height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    scale_encoded_header: Vec<u8>,
}

impl<TSrc, TBl> HeaderVerify<TSrc, TBl> {
    /// Perform the verification.
    pub fn perform(
        mut self,
        now_from_unix_epoch: Duration,
        user_data: TBl,
    ) -> HeaderVerifyOutcome<TSrc, TBl> {
        // Before verifying, find in `disjoint_blocks` the next header to verify.
        // The order of verification is: any other block with the same height and the same
        // parent, then any child.
        // TODO: move after verification
        // TODO: make cleaner
        let next_verification: Option<(u64, [u8; 32], [u8; 32], Vec<u8>)> = {
            let sibling = self
                .parent
                .inner
                .disjoint_blocks
                .range((self.block_height, [0x0; 32])..=(self.block_height, [0xff; 32]))
                .filter(|(_, b)| !b.known_bad)
                .find(|(_, block)| {
                    if let Some(header) = block.scale_encoded_header.as_ref() {
                        let decoded = header::decode(&header).unwrap();
                        *decoded.parent_hash == self.parent_hash
                    } else {
                        false
                    }
                })
                .map(|((n, h), _)| (*n, *h, self.parent_hash));

            let parameters = if let Some(sibling) = sibling {
                Some(sibling)
            } else {
                self.parent
                    .inner
                    .disjoint_blocks
                    .range((self.block_height + 1, [0x0; 32])..=(self.block_height + 1, [0xff; 32]))
                    .filter(|(_, b)| !b.known_bad)
                    .find(|(_, block)| {
                        if let Some(header) = block.scale_encoded_header.as_ref() {
                            let decoded = header::decode(&header).unwrap();
                            *decoded.parent_hash == self.block_hash
                        } else {
                            false
                        }
                    })
                    .map(|((n, h), _)| (*n, *h, self.block_hash))
            };

            if let Some((height, hash, parent_hash)) = parameters {
                let disjoint_block = self
                    .parent
                    .inner
                    .disjoint_blocks
                    .remove(&(height, hash))
                    .unwrap();
                Some((
                    height,
                    hash,
                    parent_hash,
                    disjoint_block.scale_encoded_header.unwrap(),
                ))
            } else {
                None
            }
        };

        // Perform the actual verification.
        let result = match self
            .parent
            .chain
            .verify_header(self.scale_encoded_header, now_from_unix_epoch)
        {
            Ok(blocks_tree::HeaderVerifySuccess::Insert {
                insert,
                is_new_best,
                ..
            }) => {
                insert.insert(Block { user_data });
                Ok(is_new_best)
            }
            Err(blocks_tree::HeaderVerifyError::VerificationFailed(error)) => {
                // TODO: mark the block as bad and insert it back in `disjoint_blocks`?
                Err((error, user_data))
            }
            Ok(blocks_tree::HeaderVerifySuccess::Duplicate)
            | Err(blocks_tree::HeaderVerifyError::BadParent { .. })
            | Err(blocks_tree::HeaderVerifyError::InvalidHeader(_)) => unreachable!(),
        };

        match (result, next_verification) {
            (
                Ok(is_new_best), // TODO: use is_new_best
                Some((block_height, block_hash, parent_hash, scale_encoded_header)),
            ) => HeaderVerifyOutcome::SuccessContinue {
                next_block: HeaderVerify {
                    parent: self.parent,
                    block_height,
                    block_hash,
                    parent_hash,
                    scale_encoded_header,
                },
            },
            // TODO: use is_new_best
            (Ok(is_new_best), None) => HeaderVerifyOutcome::Success(self.parent),
            (
                Err((error, user_data)),
                Some((block_height, block_hash, parent_hash, scale_encoded_header)),
            ) => HeaderVerifyOutcome::ErrorContinue {
                next_block: HeaderVerify {
                    parent: self.parent,
                    block_height,
                    block_hash,
                    parent_hash,
                    scale_encoded_header,
                },
                error,
                user_data,
            },
            (Err((error, user_data)), None) => HeaderVerifyOutcome::Error {
                sync: self.parent,
                error,
                user_data,
            },
        }
    }

    // Note: no `cancel` method is provided, as it would leave the `AllForksSync` in a weird
    // state.
}

/// Outcome of calling [`HeaderVerify::perform`].
pub enum HeaderVerifyOutcome<TSrc, TBl> {
    /// Header has been successfully verified.
    Success(AllForksSync<TSrc, TBl>),

    /// Header has been successfully verified. A follow-up header is ready to be verified.
    SuccessContinue {
        /// Next verification.
        next_block: HeaderVerify<TSrc, TBl>,
    },

    /// Header verification failed.
    Error {
        sync: AllForksSync<TSrc, TBl>,
        /// Error that happened.
        error: verify::header_only::Error,
        /// User data that was passed to [`HeaderVerify::perform`] and is unused.
        user_data: TBl,
    },

    /// Header verification failed. A follow-up header is ready to be verified.
    ErrorContinue {
        /// Next verification.
        next_block: HeaderVerify<TSrc, TBl>,
        /// Error that happened.
        error: verify::header_only::Error,
        /// User data that was passed to [`HeaderVerify::perform`] and is unused.
        user_data: TBl,
    },
}

/// State of the processing of blocks.
pub enum BlockBodyVerify<TSrc, TBl> {
    #[doc(hidden)]
    Foo(core::marker::PhantomData<(TSrc, TBl)>),
    // TODO: finish
    /*/// Processing of the block is over.
    ///
    /// There might be more blocks remaining. Call [`AllForksSync::process_one`] again.
    NewBest {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the
        /// [`AllForksSync`]. This field yields it back.
        sync: AllForksSync<TSrc, TBl>,

        new_best_number: u64,
        new_best_hash: [u8; 32],
    },

    /// Processing of the block is over. The block has been finalized.
    ///
    /// There might be more blocks remaining. Call [`AllForksSync::process_one`] again.
    Finalized {
        /// The state machine.
        /// The [`AllForksSync::process_one`] method takes ownership of the
        /// [`AllForksSync`]. This field yields it back.
        sync: AllForksSync<TSrc, TBl>,

        /// Blocks that have been finalized. Includes the block that has just been verified.
        finalized_blocks: Vec<Block<TBl>>,
    },

    /// Loading a storage value of the finalized block is required in order to continue.
    FinalizedStorageGet(StorageGet<TSrc, TBl>),

    /// Fetching the list of keys of the finalized block with a given prefix is required in order
    /// to continue.
    FinalizedStoragePrefixKeys(StoragePrefixKeys<TSrc, TBl>),

    /// Fetching the key of the finalized block storage that follows a given one is required in
    /// order to continue.
    FinalizedStorageNextKey(StorageNextKey<TSrc, TBl>),*/
}

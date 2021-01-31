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

use alloc::collections::{btree_map, BTreeMap, BTreeSet, VecDeque};
use core::{mem, num::NonZeroU64, time::Duration};

mod sources;

pub use sources::SourceId;

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
    // Implementation note: the size of `disjoint_headers` can temporarily grow above this limit
    // due to the internal processing of the state machine.
    pub max_disjoint_headers: usize,

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
    sources: sources::AllForksSources<Source<TSrc>>,

    /// List of blocks whose header has been verified, but whose body is currently being
    /// downloaded from a source or should be downloaded from a source.
    ///
    /// Contains as value the SCALE-encoded header and source the block is currently being
    /// downloaded from.
    ///
    /// Always empty if `full` is `false`.
    pending_body_downloads:
        hashbrown::HashMap<[u8; 32], (Vec<u8>, Option<SourceId>), fnv::FnvBuildHasher>,

    /// Map of blocks whose parent is either in `unknown_headers` or in `disjoint_headers`.
    ///
    /// Only contains blocks whose height is strictly superior to the height of the local
    /// finalized block.
    ///
    /// The keys are `(block_height, block_hash)`. Using a b-tree and putting the block number in
    /// the key makes it possible to remove obsolete entries once blocks are finalized. For
    /// example, when block `N` is finalized, all entries whose key starts with `N` can be
    /// removed.
    disjoint_headers: BTreeMap<(u64, [u8; 32]), DisjointBlock>, // TODO: move to standalone container?

    /// List of block height and hash whose header is not known.
    ///
    /// Only contains blocks whose height is strictly superior to the height of the local
    /// finalized block.
    ///
    /// The keys are `(block_height, block_hash)`. Using a b-tree and putting the block number in
    /// the key makes it possible to remove obsolete entries once blocks are finalized. For
    /// example, when block `N` is finalized, all entries whose key starts with `N` can be
    /// removed.
    unknown_headers: BTreeMap<(u64, [u8; 32]), Option<SourceId>>,

    /// See [`Config::max_disjoint_headers`].
    max_disjoint_headers: usize,
}

struct Block<TBl> {
    user_data: TBl,
}

struct DisjointBlock {
    /// Header of the block. Guaranteed to be a valid header.
    scale_encoded_header: Vec<u8>,
}

/// Extra fields specific to each blocks source.
struct Source<TSrc> {
    /// What the source is busy doing.
    occupation: SourceOccupation,
    user_data: TSrc,
}

#[derive(Debug)]
enum SourceOccupation {
    /// Source isn't doing anything.
    Idle,
    /// Source is performing an ancestry search. Contains the height and hash of the first block
    /// expected in the response.
    AncestrySearch(u64, [u8; 32]),
    /// Source is performing a header request. Contains the height and hash of the expected block.
    HeaderRequest(u64, [u8; 32]),
}

impl<TSrc, TBl> AllForksSync<TSrc, TBl> {
    /// Initializes a new [`AllForksSync`].
    pub fn new(config: Config) -> Self {
        let finalized_block_height = config.chain_information.finalized_block_header.number;

        let chain = blocks_tree::NonFinalizedTree::new(blocks_tree::Config {
            chain_information: config.chain_information,
            blocks_capacity: config.blocks_capacity,
        });

        Self {
            chain,
            inner: Inner {
                full: config.full,
                max_disjoint_headers: config.max_disjoint_headers,
                sources: sources::AllForksSources::new(
                    config.sources_capacity,
                    finalized_block_height,
                ),
                pending_body_downloads: Default::default(),
                disjoint_headers: Default::default(),
                unknown_headers: Default::default(),
            },
        }
    }

    /// Builds a [`chain_information::ChainInformationRef`] struct corresponding to the current
    /// latest finalized block. Can later be used to reconstruct a chain.
    pub fn as_chain_information(&self) -> chain_information::ChainInformationRef {
        self.chain.as_chain_information()
    }

    /// Returns the header of the finalized block.
    pub fn finalized_block_header(&self) -> header::HeaderRef {
        self.chain.as_chain_information().finalized_block_header
    }

    /// Returns the header of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_header(&self) -> header::HeaderRef {
        self.chain.best_block_header()
    }

    /// Returns the number of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_number(&self) -> u64 {
        self.chain.best_block_header().number
    }

    /// Returns the hash of the best block.
    ///
    /// > **Note**: This value is provided only for informative purposes. Keep in mind that this
    /// >           best block might be reverted in the future.
    pub fn best_block_hash(&self) -> [u8; 32] {
        self.chain.best_block_hash()
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
        let mut new_source = self.inner.sources.add_source(
            Source {
                occupation: SourceOccupation::Idle,
                user_data,
            },
            best_block_number,
            best_block_hash,
        );

        let mut request = None;

        // If the source's best block is below the finalized block height, don't do anything.
        if best_block_number > self.chain.finalized_block_header().number {
            // Add the source's best block to `unknown_headers`.
            let entry = self
                .inner
                .unknown_headers
                .entry((best_block_number, best_block_hash))
                .or_insert(None);

            if entry.is_none() {
                // If this entry was unknown, ask the source about this block.
                new_source.user_data().occupation =
                    SourceOccupation::HeaderRequest(best_block_number, best_block_hash);
                *entry = Some(new_source.id());
                request = Some(Request::HeaderRequest {
                    hash: best_block_hash,
                    number: best_block_number,
                });
            }
        }

        let source_id = new_source.id();

        // `request` might have been already filled above.
        // If not, try use this new source to make progress elsewhere.
        if request.is_none() {
            // At this point, the state of `self` is consistent. It's ok to call a separate
            // method.
            request = self.source_next_request(source_id);
        }

        (
            SourceMutAccess {
                parent: self,
                source_id,
            },
            request,
        )
    }

    /// Grants access to a source, using its identifier.
    pub fn source_mut(&mut self, id: SourceId) -> Option<SourceMutAccess<TSrc, TBl>> {
        if self.inner.sources.source_mut(id).is_some() {
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
    ) -> AncestrySearchResponseOutcome<TSrc, TBl> {
        // The next block in the list of headers should have a hash equal to this one.
        // Sets the `occupation` of `source_id` back to `Idle`.
        let (expected_next_height, expected_next_hash) = match mem::replace(
            &mut self
                .inner
                .sources
                .source_mut(source_id)
                .unwrap()
                .user_data()
                .occupation,
            SourceOccupation::Idle,
        ) {
            SourceOccupation::AncestrySearch(num, hash) => (num, hash),
            SourceOccupation::HeaderRequest(num, hash) => (num, hash), // TODO: correct?
            SourceOccupation::Idle => panic!(),
        };

        if let Some(entry) = self
            .inner
            .unknown_headers
            .get_mut(&(expected_next_height, expected_next_hash))
        {
            *entry = None;
        }

        // Set to true below if any block is inserted in `disjoint_headers`.
        let mut any_progress = false;

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
            println!("response block {:?}", decoded_header_number);

            match self.header_from_source(source_id, &expected_next_hash, decoded_header, false) {
                HeaderFromSourceOutcome::HeaderVerify(this) => {
                    println!("verify");
                    return AncestrySearchResponseOutcome::Verify(this);
                }
                HeaderFromSourceOutcome::TooOld(this) => {
                    // Block is below the finalized block number.
                    // Ancestry searches never request any block earlier than the finalized block
                    // number. `TooOld` can happen if the source is misbehaving, but also if the
                    // finalized block has been updated between the moment the request was emitted
                    // and the moment the response is received.
                    debug_assert_eq!(index_in_response, 0);
                    println!("too old");
                    self = this;
                    break;
                }
                HeaderFromSourceOutcome::NotFinalizedChain(this) => {
                    // Block isn't part of the finalized chain.
                    // This doesn't necessarily mean that the source and the local node disagree
                    // on the finalized chain. It is possible that the finalized block has been
                    // updated between the moment the request was emitted and the moment the
                    // response is received.
                    self = this;
                    println!("not finalized");

                    // Discard from the local state all blocks that descend from this one.
                    // TODO: keep known bad blocks and document
                    // TODO: move to header_from_source
                    let discarded =
                        self.discard_disjoint_chain(decoded_header_number, expected_next_hash);

                    let next_request = self.source_next_request(source_id);
                    return AncestrySearchResponseOutcome::NotFinalizedChain {
                        sync: self,
                        next_request,
                        discarded_unverified_block_headers: discarded
                            .into_iter()
                            .map(|(_, _, b)| b.scale_encoded_header)
                            .collect(),
                    };
                }
                HeaderFromSourceOutcome::AlreadyInChain(mut this) => {
                    // Block is already in chain. Can happen if a different response or
                    // announcement has arrived and been processed between the moment the request
                    // was emitted and the moment the response is received.
                    debug_assert_eq!(index_in_response, 0);
                    println!("already in chain");
                    let next_request = this.source_next_request(source_id);
                    return AncestrySearchResponseOutcome::AllAlreadyInChain {
                        sync: this,
                        next_request,
                    };
                }
                HeaderFromSourceOutcome::Disjoint(this) => {
                    // Block of unknown ancestry. Continue looping.
                    any_progress = true;
                    self = this;
                }
            }
        }

        // If this is reached, then the ancestry search was inconclusive. Only disjoint blocks
        // have been received.
        // TODO: use any_progress
        let next_request = self.source_next_request(source_id);
        AncestrySearchResponseOutcome::Inconclusive {
            sync: self,
            next_request,
        }
    }

    /// Finds a request that the given source could start performing.
    ///
    /// If `Some` is returned, updates the [`SourceOccupation`] in `self` and returns the request
    /// that must be started.
    fn source_next_request(&mut self, source_id: SourceId) -> Option<Request> {
        let mut source_access = self.inner.sources.source_mut(source_id).unwrap();
        debug_assert!(matches!(
            source_access.user_data().occupation,
            SourceOccupation::Idle
        ));

        // Iterator through `pending_body_downloads` to find a block that needs attention.
        for (block_hash, _) in self
            .inner
            .pending_body_downloads
            .iter()
            .filter(|(_, (_, s))| s.is_none())
        {
            // Only download the block if the source knows about it.
            // `continue` if this `pending_body_download` isn't known by this source.
            if !source_access.knows_block(todo!(), block_hash) {
                continue;
            }

            // TODO: finish
            todo!()
        }

        // Iterator through `unknown_headers` to find a block that needs attention.
        for (
            &(ref unknown_block_height, ref unknown_block_hash),
            &mut ref mut downloading_source,
        ) in self
            .inner
            .unknown_headers
            .iter_mut()
            .filter(|(_, s)| s.is_none())
        {
            // The source can only operate on blocks that it knows about.
            // `continue` if this block isn't known by this source.
            if !source_access.knows_block(*unknown_block_height, unknown_block_hash) {
                continue;
            }

            // Start an ancestry search in order to find an ancestor of this block in our
            // local chain. When answered, this will ultimately add new blocks to
            // `disjoint_block`.
            *downloading_source = Some(source_id);

            let local_finalized_height = self.chain.finalized_block_header().number;
            debug_assert!(*unknown_block_height > local_finalized_height);
            source_access.user_data().occupation =
                SourceOccupation::AncestrySearch(*unknown_block_height, *unknown_block_hash);
            return Some(Request::AncestrySearch {
                first_block_hash: *unknown_block_hash,
                num_blocks: NonZeroU64::new(*unknown_block_height - local_finalized_height)
                    .unwrap(),
            });
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
            Err(error) => return BlockAnnounceOutcome::InvalidHeader { sync: self, error },
        };

        let announced_header_hash = announced_header.hash();

        match self.header_from_source(source_id, &announced_header_hash, announced_header, is_best)
        {
            HeaderFromSourceOutcome::HeaderVerify(verify) => {
                BlockAnnounceOutcome::HeaderVerify(verify)
            }
            HeaderFromSourceOutcome::TooOld(sync) => BlockAnnounceOutcome::TooOld(sync),
            HeaderFromSourceOutcome::AlreadyInChain(sync) => {
                BlockAnnounceOutcome::AlreadyInChain(sync)
            }
            HeaderFromSourceOutcome::NotFinalizedChain(sync) => {
                BlockAnnounceOutcome::NotFinalizedChain(sync)
            }
            HeaderFromSourceOutcome::Disjoint(mut sync) => {
                let next_request = if matches!(
                    sync.inner
                        .sources
                        .source_mut(source_id)
                        .unwrap()
                        .user_data()
                        .occupation,
                    SourceOccupation::Idle
                ) {
                    sync.source_next_request(source_id)
                } else {
                    None
                };

                BlockAnnounceOutcome::Disjoint { sync, next_request }
            }
        }
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
    ) -> HeaderFromSourceOutcome<TSrc, TBl> {
        debug_assert_eq!(header.hash(), *header_hash);

        // No matter what is done below, start by updating the view the local state machine
        // maintains for this source.
        let mut source_access = self.inner.sources.source_mut(source_id).unwrap();
        if known_to_be_source_best {
            source_access.set_best_block(header.number, header.hash());
        } else {
            source_access.add_known_block(header.number, header.hash());
        }

        // It is assumed that all sources will eventually agree on the same finalized chain. If
        // the block number is lower or equal than the locally-finalized block number, it is
        // assumed that this source is simply late compared to the local node, and that the block
        // that has been received is either part of the finalized chain or belongs to a fork that
        // will get discarded by this source in the future.
        if header.number <= self.chain.finalized_block_header().number {
            debug_assert!(!self
                .inner
                .unknown_headers
                .contains_key(&(header.number, *header_hash)));
            debug_assert!(!self
                .inner
                .disjoint_headers
                .contains_key(&(header.number, *header_hash)));
            return HeaderFromSourceOutcome::TooOld(self);
        }

        // TODO: somehow optimize? the encoded block is normally known from it being decoded
        let scale_encoded_header = header.scale_encoding_vec();

        // If the block is already part of the local tree of blocks, nothing more to do.
        if self
            .chain
            .non_finalized_block_by_hash(&header_hash)
            .is_some()
        {
            debug_assert!(!self
                .inner
                .unknown_headers
                .contains_key(&(header.number, *header_hash)));
            debug_assert!(!self
                .inner
                .disjoint_headers
                .contains_key(&(header.number, *header_hash)));
            return HeaderFromSourceOutcome::AlreadyInChain(self);
        }

        // As the header is now known, remove it from `unknown_headers`.
        // TODO: cancel request if there was one!
        let _ = self
            .inner
            .unknown_headers
            .remove(&(header.number, *header_hash));

        // `pending_body_downloads` contains blocks whose header has already been verified.
        if self.inner.pending_body_downloads.contains_key(header_hash) {
            debug_assert!(self.inner.full);
            return HeaderFromSourceOutcome::AlreadyInChain(self);
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
                .disjoint_headers
                .contains_key(&(header.number, *header_hash)));

            // The block and all its descendants can all be verified.
            // Remove them all from `disjoint_headers` and move them to a new `HeaderVerify`
            // object.
            // TODO: no, that's stupid
            self.inner.disjoint_headers.insert(
                (header.number, *header_hash),
                DisjointBlock {
                    scale_encoded_header: scale_encoded_header.to_vec(),
                },
            );
            let verifiable_blocks = self.discard_disjoint_chain(header.number, *header_hash);

            HeaderFromSourceOutcome::HeaderVerify(HeaderVerify {
                parent: self,
                source_id,
                verifiable_blocks: verifiable_blocks
                    .into_iter()
                    .map(|(_, _, bl)| bl.scale_encoded_header)
                    .collect(),
            })
        } else if header.number == self.chain.finalized_block_header().number + 1 {
            // Checked above.
            debug_assert_ne!(*header.parent_hash, self.chain.finalized_block_hash());

            // Announced block is not part of the finalized chain.
            debug_assert!(!self
                .inner
                .disjoint_headers
                .contains_key(&(header.number, *header_hash)));
            HeaderFromSourceOutcome::NotFinalizedChain(self)
        } else {
            // Parent is not in the `NonFinalizedTree`. It is unknown whether this block belongs
            // to the same finalized chain as the one known locally, but we expect that it is the
            // case.

            // Insert the parent in the unknown headers.
            if let btree_map::Entry::Vacant(entry) = self
                .inner
                .unknown_headers
                .entry((header.number - 1, *header.parent_hash))
            {
                entry.insert(None);
            }

            // Update `disjoint_headers`.
            match self
                .inner
                .disjoint_headers
                .entry((header.number, *header_hash))
            {
                btree_map::Entry::Occupied(mut entry) => {
                    debug_assert_eq!(entry.get_mut().scale_encoded_header, scale_encoded_header);
                }
                btree_map::Entry::Vacant(entry) => {
                    entry.insert(DisjointBlock {
                        scale_encoded_header: scale_encoded_header.to_vec(),
                    });
                }
            }

            HeaderFromSourceOutcome::Disjoint(self)
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

    /// Passed a known entry in `disjoint_headers`. Removes this entry and any known children of
    /// this block.
    ///
    /// # Panic
    ///
    /// Panics if `(number, hash)` isn't an entry in [`Inner::disjoint_chain]`.
    ///
    fn discard_disjoint_chain(
        &mut self,
        number: u64,
        hash: [u8; 32],
    ) -> Vec<(u64, [u8; 32], DisjointBlock)> {
        // TODO: keep a list of banned blocks for later? this is required by chain specs anyway

        // The implementation consists in iterating over the increasing block number, and removing
        // all blocks whose parent was removed at the previous iteration.

        // Return value of the function.
        let mut result = Vec::with_capacity(64);

        // List of blocks to discard at the next iteration.
        let mut blocks_to_discard = Vec::with_capacity(16);
        blocks_to_discard.push(hash);

        for number in number.. {
            // Find in `disjoint_headers` any block whose parent is in `blocks_to_discard`.
            let blocks_to_discard_next = {
                let mut blocks_to_discard_next = Vec::with_capacity(16);
                for ((_, hash), block) in self
                    .inner
                    .disjoint_headers
                    .range((number + 1, [0; 32])..(number + 2, [0; 32]))
                {
                    let decoded = header::decode(&block.scale_encoded_header).unwrap();
                    if blocks_to_discard.iter().any(|b| b == decoded.parent_hash) {
                        blocks_to_discard_next.push(*hash);
                    }
                }
                blocks_to_discard_next
            };

            // Now discard `blocks_to_discard`.
            for to_discard in mem::replace(&mut blocks_to_discard, blocks_to_discard_next) {
                let mut discarded_block = self
                    .inner
                    .disjoint_headers
                    .remove(&(number, to_discard))
                    .unwrap();

                // Any ongoing search needs to be cancelled.
                // TODO:
                /*if let Some(_source_id) = discarded_block.ancestry_search {
                    todo!() // TODO:
                }*/

                result.push((number, to_discard, discarded_block));
            }

            // The `for` loop would be infinite unless we put an explicit `break`.
            // Note that `blocks_to_discard` was replaced with `blocks_to_discard_next` above,
            // we're therefore testing `blocks_to_discard_next.is_empty()`.
            if blocks_to_discard.is_empty() {
                break;
            }
        }

        result
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
    // TODO: shouldn't take &mut self but just &self
    pub fn knows_block(&mut self, height: u64, hash: &[u8; 32]) -> bool {
        self.parent
            .inner
            .sources
            .source_mut(self.source_id)
            .unwrap()
            .knows_block(height, hash)
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
        let source = self
            .parent
            .inner
            .sources
            .source_mut(self.source_id)
            .unwrap()
            .remove();

        let source_id = self.source_id;
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

        match source.occupation {
            SourceOccupation::Idle => {}
            SourceOccupation::AncestrySearch(_, hash) => {
                todo!()
            }
            SourceOccupation::HeaderRequest(_, _) => todo!(),
        }

        // TODO: None hardcoded
        (source.user_data, None)
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`AllForksSync::add_source`].
    pub fn user_data(&mut self) -> &mut TSrc {
        let source = self
            .parent
            .inner
            .sources
            .source_mut(self.source_id)
            .unwrap();
        &mut source.into_user_data().user_data
    }

    /// Returns the user data associated to the source. This is the value originally passed
    /// through [`AllForksSync::add_source`].
    pub fn into_user_data(self) -> &'a mut TSrc {
        let source = self
            .parent
            .inner
            .sources
            .source_mut(self.source_id)
            .unwrap();
        &mut source.into_user_data().user_data
    }
}

/// Outcome of calling [`AllForksSync::header_from_source`].
///
/// Not public.
enum HeaderFromSourceOutcome<TSrc, TBl> {
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

/// Outcome of calling [`AllForksSync::block_announce`].
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
    Disjoint {
        sync: AllForksSync<TSrc, TBl>,
        /// Next request that the same source should now perform.
        next_request: Option<Request>,
    },
    /// Failed to decode announce header.
    InvalidHeader {
        sync: AllForksSync<TSrc, TBl>,
        error: header::Error,
    },
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
        sync: AllForksSync<TSrc, TBl>,

        /// Next request that the same source should now perform.
        next_request: Option<Request>,

        /// List of block headers that were pending verification and that have now been discarded
        /// since it has been found out that they don't belong to the finalized chain.
        discarded_unverified_block_headers: Vec<Vec<u8>>,
    },

    /// Couldn't verify any of the blocks of the ancestry search. Some or all of these blocks
    /// have been stored in the local machine for later.
    Inconclusive {
        sync: AllForksSync<TSrc, TBl>,

        /// Next request that the same source should now perform.
        next_request: Option<Request>,
    },

    /// All blocks in the ancestry search response were already in the list of verified blocks.
    ///
    /// This can happen if a block announce or different ancestry search response has been
    /// processed in between the request and response.
    AllAlreadyInChain {
        sync: AllForksSync<TSrc, TBl>,

        /// Next request that the same source should now perform.
        next_request: Option<Request>,
    },
}

/// Header verification to be performed.
///
/// Internally holds the [`AllForksSync`].
pub struct HeaderVerify<TSrc, TBl> {
    parent: AllForksSync<TSrc, TBl>,
    /// Source that gave the first block that allows verification.
    source_id: SourceId,
    /// List of blocks to verify. Must never be empty.
    verifiable_blocks: VecDeque<Vec<u8>>,
}

impl<TSrc, TBl> HeaderVerify<TSrc, TBl> {
    /// Perform the verification.
    pub fn perform(
        mut self,
        now_from_unix_epoch: Duration,
        user_data: TBl,
    ) -> HeaderVerifyOutcome<TSrc, TBl> {
        // `verifiable_blocks` must never be empty.
        let scale_encoded_header = self.verifiable_blocks.pop_front().unwrap();

        let result = match self
            .parent
            .chain
            .verify_header(scale_encoded_header, now_from_unix_epoch)
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
                // TODO: mark the block as bad and insert it back in `disjoint_headers`?
                Err((error, user_data))
            }
            Ok(blocks_tree::HeaderVerifySuccess::Duplicate)
            | Err(blocks_tree::HeaderVerifyError::BadParent { .. })
            | Err(blocks_tree::HeaderVerifyError::InvalidHeader(_)) => unreachable!(),
        };

        match (result, self.verifiable_blocks.is_empty()) {
            (
                Ok(is_new_best), // TODO: use is_new_best
                false,
            ) => HeaderVerifyOutcome::SuccessContinue {
                next_block: HeaderVerify {
                    parent: self.parent,
                    source_id: self.source_id,
                    verifiable_blocks: self.verifiable_blocks,
                },
            },
            // TODO: use is_new_best
            (Ok(is_new_best), true) => {
                let next_request = if matches!(
                    self.parent
                        .inner
                        .sources
                        .source_mut(self.source_id)
                        .unwrap()
                        .user_data()
                        .occupation,
                    SourceOccupation::Idle
                ) {
                    self.parent.source_next_request(self.source_id)
                } else {
                    None
                };

                HeaderVerifyOutcome::Success {
                    sync: self.parent,
                    next_request,
                }
            }
            (Err((error, user_data)), false) => HeaderVerifyOutcome::ErrorContinue {
                next_block: HeaderVerify {
                    parent: self.parent,
                    source_id: self.source_id,
                    verifiable_blocks: self.verifiable_blocks,
                },
                error,
                user_data,
            },
            (Err((error, user_data)), true) => {
                let next_request = if matches!(
                    self.parent
                        .inner
                        .sources
                        .source_mut(self.source_id)
                        .unwrap()
                        .user_data()
                        .occupation,
                    SourceOccupation::Idle
                ) {
                    self.parent.source_next_request(self.source_id)
                } else {
                    None
                };

                HeaderVerifyOutcome::Error {
                    sync: self.parent,
                    error,
                    user_data,
                    next_request,
                }
            }
        }
    }

    // Note: no `cancel` method is provided, as it would leave the `AllForksSync` in a weird
    // state.
}

/// Outcome of calling [`HeaderVerify::perform`].
pub enum HeaderVerifyOutcome<TSrc, TBl> {
    /// Header has been successfully verified.
    Success {
        sync: AllForksSync<TSrc, TBl>,
        /// Next request that must be performed on the source.
        next_request: Option<Request>,
    },

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
        /// Next request that must be performed on the source.
        next_request: Option<Request>,
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

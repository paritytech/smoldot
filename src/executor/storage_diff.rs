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

//! "Diff" between a storage and the next.
//!
//! Imagine two `HashMap<Vec<u8>, Vec<u8>>`s representing the storage of the chain. This data
//! structure contains the difference from one to the other.
//!
//! This data structure can be used in a variety of circumstances, such as storing the storage
//! differences between a block and its child or storing on-going changes while a runtime call is
//! being performed. It can also be used to store an entire storage, by representing a diff where
//! the base is an empty storage.
//!
//! # About keys hashing
//!
//! This data structure internally uses a hash map. This hash map assumes that storage keys are
//! already uniformly distributed and doesn't perform any additional hashing.
//!
//! You should be aware that a malicious runtime could perform hash collision attacks that
//! considerably slow down this data structure.
//!

// TODO: is this module properly located?

// TODO: more docs

use alloc::{collections::BTreeMap, vec::Vec};
use core::{cmp, fmt, iter, ops};
use hashbrown::HashMap;

#[derive(Clone)]
pub struct StorageDiff {
    /// Contains the same entries as [`StorageDiff::hashmap`], except that values are booleans
    /// indicating whether the value updates (`true`) or deletes (`false`) the underlying
    /// storage item.
    btree: BTreeMap<Vec<u8>, bool>,

    /// Actual diff. For each key, `Some` if the underlying storage item is updated by this diff,
    /// and `None` if it is deleted.
    ///
    /// A FNV hasher is used because the runtime is supposed to guarantee a uniform distribution
    /// of storage keys.
    hashmap: HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>,
}

impl StorageDiff {
    /// Builds a new empty diff.
    pub fn empty() -> Self {
        Self {
            btree: BTreeMap::default(),
            // TODO: with_capacity?
            hashmap: HashMap::with_capacity_and_hasher(0, Default::default()),
        }
    }

    /// Removes all the entries within this diff.
    pub fn clear(&mut self) {
        self.hashmap.clear();
        self.btree.clear();
    }

    /// Inserts the given key-value combination in the diff.
    ///
    /// Returns the value associated to this `key` that was previously in the diff, if any.
    pub fn diff_insert(
        &mut self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Option<Option<Vec<u8>>> {
        let key = key.into();
        // Note that we clone the key here. This is considered as a tolerable overhead.
        let previous = self.hashmap.insert(key.clone(), Some(value.into()));
        match &previous {
            Some(Some(_)) => {
                // No need to update `btree`.
                debug_assert_eq!(self.btree.get(&key), Some(&true));
            }
            None | Some(None) => {
                self.btree.insert(key, true);
            }
        }
        previous
    }

    /// Inserts in the diff an entry at the given key that delete the value that is located in
    /// the base storage.
    ///
    /// Returns the value associated to this `key` that was previously in the diff, if any.
    pub fn diff_insert_erase(&mut self, key: impl Into<Vec<u8>>) -> Option<Option<Vec<u8>>> {
        let key = key.into();
        // Note that we clone the key here. This is considered as a tolerable overhead.
        let previous = self.hashmap.insert(key.clone(), None);
        match &previous {
            Some(None) => {
                // No need to update `btree`.
                debug_assert_eq!(self.btree.get(&key), Some(&false));
            }
            None | Some(Some(_)) => {
                self.btree.insert(key, false);
            }
        }
        previous
    }

    /// Removes from the diff the entry corresponding to the given `key`.
    ///
    /// Returns the value associated to this `key` that was previously in the diff, if any.
    pub fn diff_remove(&mut self, key: impl AsRef<[u8]>) -> Option<Option<Vec<u8>>> {
        let previous = self.hashmap.remove(key.as_ref());
        if let Some(_previous) = &previous {
            let _in_btree = self.btree.remove(key.as_ref());
            debug_assert_eq!(_in_btree, Some(_previous.is_some()));
        }
        previous
    }

    /// Returns the diff entry at the given key.
    ///
    /// Returns `None` if the diff doesn't have any entry for this key, and `Some(None)` if the
    /// diff has an entry that deletes the storage item.
    pub fn diff_get(&self, key: &[u8]) -> Option<Option<&[u8]>> {
        self.hashmap.get(key).map(|v| v.as_ref().map(|v| &v[..]))
    }

    /// Returns an iterator to all the entries in the diff.
    ///
    /// Each value is either `Some` if the diff overwrites this diff, or `None` if it erases the
    /// underlying value.
    pub fn diff_iter_unordered(
        &self,
    ) -> impl ExactSizeIterator<Item = (&[u8], Option<&[u8]>)> + Clone {
        self.hashmap
            .iter()
            .map(|(k, v)| (&k[..], v.as_ref().map(|v| &v[..])))
    }

    /// Returns an iterator to all the entries in the diff.
    ///
    /// Each value is either `Some` if the diff overwrites this diff, or `None` if it erases the
    /// underlying value.
    pub fn diff_into_iter_unordered(
        self,
    ) -> impl ExactSizeIterator<Item = (Vec<u8>, Option<Vec<u8>>)> {
        self.hashmap.into_iter()
    }

    /// Returns the storage value at the given key. `None` if this key doesn't have any value.
    pub fn storage_get<'a, 'b>(
        &'a self,
        key: &'b [u8],
        or_parent: impl FnOnce() -> Option<&'a [u8]>,
    ) -> Option<&'a [u8]> {
        self.hashmap
            .get(key)
            .map_or_else(or_parent, |opt| opt.as_ref().map(|v| &v[..]))
    }

    /// Returns the storage key that immediately follows the provided `key`. Must be passed the
    /// storage key that immediately follows the provided `key` according to the base storage this
    /// diff is based upon.
    ///
    /// If [`StorageNextKey::Found`] is returned, it contains the desired key. If
    /// [`StorageNextKey::NextOf`] is returned, then this function should be called again but by
    /// passing the `key` found in the [`StorageNextKey::NextOf`] (and of course the corresponding
    /// `in_parent_next_key`).
    ///
    /// # Panic
    ///
    /// Panics if `in_parent_next_key` is provided and is inferior or equal to `key`.
    ///
    pub fn storage_next_key<'a, 'b>(
        &'a self,
        key: &'b [u8],
        in_parent_next_key: Option<&'a [u8]>,
    ) -> StorageNextKey<'a> {
        if let Some(in_parent_next_key) = in_parent_next_key {
            assert!(in_parent_next_key > key);
        }

        // Find the diff entry that immediately follows `key`.
        let in_diff = self
            .btree
            .range::<[u8], _>((ops::Bound::Excluded(key), ops::Bound::Unbounded))
            .next();

        match (in_parent_next_key, in_diff) {
            (Some(a), Some((b, true))) if a <= &b[..] => StorageNextKey::Found(Some(a)),
            (Some(a), Some((b, false))) if a < &b[..] => StorageNextKey::Found(Some(a)),
            (Some(a), Some((b, false))) => {
                debug_assert!(a >= &b[..]);
                debug_assert_ne!(&b[..], key);

                // The next key according to the parent storage has been erased in this diff. It
                // is necessary to ask the user again, this time for the key after the one that
                // has been erased.

                // Note that there is probably something wrong here if `a != b`, but we ignore
                // that here.

                StorageNextKey::NextOf(b)
            }
            (Some(a), Some((b, true))) => {
                debug_assert!(a >= &b[..]);
                StorageNextKey::Found(Some(&b[..]))
            }

            (Some(a), None) => StorageNextKey::Found(Some(a)),
            (None, Some((b, true))) => StorageNextKey::Found(Some(&b[..])),
            (None, Some((b, false))) => {
                debug_assert!(&b[..] > key);
                let found = self
                    .btree
                    .range::<[u8], _>((ops::Bound::Excluded(&b[..]), ops::Bound::Unbounded))
                    .find(|(_, value)| **value)
                    .map(|(key, _)| &key[..]);
                StorageNextKey::Found(found)
            }
            (None, None) => StorageNextKey::Found(None),
        }
    }

    /// Takes as parameter a list (`in_parent_ordered`) of all the keys that are present in the
    /// storage this diff is based upon and that start with the given `prefix`.
    ///
    /// Returns another iterator that provides the list of all keys that start with the given
    /// `prefix` after this diff has been applied.
    ///
    /// The list must be lexicographically ordered. The returned list is ordered
    /// lexicographically as well.
    pub fn storage_prefix_keys_ordered<'a>(
        &'a self, // TODO: unclear lifetime
        prefix: &'a [u8],
        in_parent_ordered: impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a,
    ) -> impl Iterator<Item = impl AsRef<[u8]> + 'a> + 'a {
        let mut in_finalized_filtered = in_parent_ordered
            .filter(|k| !self.btree.contains_key(k.as_ref()))
            .peekable();

        let mut diff_inserted = self
            .btree
            .range::<[u8], _>((ops::Bound::Included(prefix), ops::Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(prefix))
            .filter(|(_, v)| **v)
            .map(|(k, _)| &k[..])
            .peekable();

        iter::from_fn(
            move || match (in_finalized_filtered.peek(), diff_inserted.peek()) {
                (Some(_), None) => in_finalized_filtered.next().map(either::Left),
                (Some(a), Some(b)) if a.as_ref() < *b => {
                    in_finalized_filtered.next().map(either::Left)
                }
                (Some(a), Some(b)) => {
                    debug_assert_ne!(a.as_ref(), *b);
                    diff_inserted.next().map(either::Right)
                }
                (None, Some(_)) => diff_inserted.next().map(either::Right),
                (None, None) => None,
            },
        )
    }

    /// Applies the given diff on top of the current one.
    pub fn merge(&mut self, other: &StorageDiff) {
        // TODO: provide an alternative method that consumes `other` as well?
        for (key, value) in &other.hashmap {
            self.hashmap.insert(key.clone(), value.clone());
            self.btree.insert(key.clone(), value.is_some());
        }
    }
}

impl fmt::Debug for StorageDiff {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Delegate to `self.inner`
        fmt::Debug::fmt(&self.hashmap, f)
    }
}

// We implement `PartialEq` manually, because deriving it would mean that both the hash map and
// the tree are compared.
impl cmp::PartialEq for StorageDiff {
    fn eq(&self, other: &Self) -> bool {
        self.hashmap == other.hashmap
    }
}

impl cmp::Eq for StorageDiff {}

impl Default for StorageDiff {
    fn default() -> Self {
        StorageDiff::empty()
    }
}

impl FromIterator<(Vec<u8>, Option<Vec<u8>>)> for StorageDiff {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
    {
        let hashmap = iter
            .into_iter()
            .collect::<HashMap<Vec<u8>, Option<Vec<u8>>, fnv::FnvBuildHasher>>();
        let btree = hashmap
            .iter()
            .map(|(k, v)| (k.clone(), v.is_some()))
            .collect();

        Self { btree, hashmap }
    }
}

pub enum StorageNextKey<'a> {
    Found(Option<&'a [u8]>),
    NextOf(&'a [u8]),
}

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
//! being performed.

// TODO: is this module properly located?

// TODO: more docs

use crate::{
    executor::{self, host, vm},
    trie::calculate_root,
    util,
};

use alloc::{
    borrow::ToOwned as _,
    collections::BTreeMap,
    string::{String, ToString as _},
    vec::Vec,
};
use core::{fmt, iter};
use hashbrown::{hash_map::Entry, HashMap, HashSet};

pub struct StorageChanges {
    inner: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl StorageChanges {
    pub fn empty() -> Self {
        Self {
            inner: BTreeMap::default(),
        }
    }

    pub fn diff_insert(
        &mut self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Option<Option<Vec<u8>>> {
        self.inner.insert(key.into(), Some(value.into()))
    }

    pub fn diff_insert_erase(&mut self, key: impl Into<Vec<u8>>) -> Option<Option<Vec<u8>>> {
        self.inner.insert(key.into(), None)
    }

    pub fn diff_get(&self, key: &[u8]) -> Option<Option<&[u8]>> {
        self.inner.get(key).map(|v| v.as_ref().map(|v| &v[..]))
    }

    /// Returns the storage value at the given key. `None` if this key doesn't have any value.
    pub fn storage_get<'a>(
        &'a self, // TODO: unclear lifetime
        key: &[u8],
        or_parent: impl FnOnce() -> Option<&'a [u8]>,
    ) -> Option<&'a [u8]> {
        self.inner
            .get(key)
            .map(|opt| opt.as_ref().map(|v| &v[..]))
            .unwrap_or_else(or_parent)
    }

    pub fn storage_prefix_keys_ordered<'a>(
        &'a self, // TODO: unclear lifetime
        prefix: &'a [u8],
        in_parent_ordered: impl Iterator<Item = &'a [u8]> + 'a,
    ) -> impl Iterator<Item = &'a [u8]> + 'a {
        let mut in_finalized_filtered = in_parent_ordered
            .filter(|k| !self.inner.contains_key(*k))
            .peekable();

        let mut diff_inserted = self
            .inner
            .range(prefix.to_owned()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .filter(|(_, v)| v.is_some())
            .map(|(k, _)| &k[..])
            .peekable();

        iter::from_fn(
            move || match (in_finalized_filtered.peek(), diff_inserted.peek()) {
                (Some(_), None) => in_finalized_filtered.next(),
                (Some(a), Some(b)) if a < b => in_finalized_filtered.next(),
                (Some(a), Some(b)) => {
                    debug_assert_ne!(a, b);
                    diff_inserted.next()
                }
                (None, Some(_)) => diff_inserted.next(),
                (None, None) => None,
            },
        )
    }
}

impl fmt::Debug for StorageChanges {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Delegate to `self.inner`
        fmt::Debug::fmt(&self.inner, f)
    }
}

impl FromIterator<(Vec<u8>, Option<Vec<u8>>)> for StorageChanges {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
    {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

// TODO: consider removing this trait impl; this is required only for API reasons at the moment
impl From<BTreeMap<Vec<u8>, Option<Vec<u8>>>> for StorageChanges {
    fn from(inner: BTreeMap<Vec<u8>, Option<Vec<u8>>>) -> Self {
        Self { inner }
    }
}

// TODO: consider removing this trait impl; this is required only for API reasons at the moment
impl From<StorageChanges> for BTreeMap<Vec<u8>, Option<Vec<u8>>> {
    fn from(c: StorageChanges) -> Self {
        c.inner
    }
}

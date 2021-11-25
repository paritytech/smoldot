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

use alloc::vec::Vec;
use core::{fmt, ops::Add, time::Duration};
use sha2::{Digest as _, Sha256};

/// K-buckets, as popularized by the Kademlia algorithm, and defined by the libp2p specification.
pub struct KBuckets<K, V, TNow, const ENTRIES_PER_BUCKET: usize> {
    /// Key of the "local" node, that holds the buckets.
    local_key: (K, Key),
    /// List of buckets, ordered by increasing distance. In other words, the first elements of
    /// this field are the ones that are the closests to [`KBuckets::local_key`].
    buckets: Vec<Bucket<K, V, TNow, ENTRIES_PER_BUCKET>>,
    /// Duration after which . // TODO:
    pending_timeout: Duration,
}

impl<K, V, TNow, const ENTRIES_PER_BUCKET: usize> KBuckets<K, V, TNow, ENTRIES_PER_BUCKET>
where
    K: Clone + PartialEq + AsRef<[u8]>,
    TNow: Clone + Add<Duration, Output = TNow> + Ord,
{
    pub fn new(local_key: K, pending_timeout: Duration) -> Self {
        let local_key_hashed = Key::new(local_key.as_ref());

        KBuckets {
            local_key: (local_key, local_key_hashed),
            buckets: (0..256)
                .map(|_| Bucket {
                    entries: arrayvec::ArrayVec::new(),
                    num_connected_entries: 0,
                    pending_entry: None,
                })
                .collect(),
            pending_timeout,
        }
    }

    /// Returns the local key that was passed to [`KBuckets::new`].
    pub fn local_key(&self) -> &K {
        &self.local_key.0
    }

    /// Returns the value corresponding to the given key. Returns `None` if the key can't be found.
    pub fn get(&self, key: &K) -> Option<&V> {
        let key_hashed = Key::new(key.as_ref());
        let distance = match distance_log2(&self.local_key.1, &key_hashed) {
            Some(d) => d,
            None => return None,
        };

        self.buckets[usize::from(distance)].get(key)
    }

    /// Returns the value corresponding to the given key. Returns `None` if the key can't be found.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let key_hashed = Key::new(key.as_ref());
        let distance = match distance_log2(&self.local_key.1, &key_hashed) {
            Some(d) => d,
            None => return None,
        };

        self.buckets[usize::from(distance)].get_mut(key)
    }

    /// Inserts or updates an entry in the buckets.
    pub fn entry<'a>(&'a mut self, key: &'a K) -> Entry<'a, K, V, TNow, ENTRIES_PER_BUCKET>
    where
        K: Clone,
    {
        let key_hashed = Key::new(key.as_ref());
        let distance = match distance_log2(&self.local_key.1, &key_hashed) {
            Some(d) => d,
            None => return Entry::LocalKey,
        };

        if self.buckets[usize::from(distance)].get_mut(key).is_some() {
            return Entry::Occupied(OccupiedEntry {
                inner: self,
                key,
                distance,
            });
        }

        Entry::Vacant(VacantEntry {
            inner: self,
            key,
            distance,
        })
    }

    /// Returns the list of entries in the k-buckets, ordered by increasing distance with the
    /// target.
    pub fn closest_entries(&self, target: &K) -> impl Iterator<Item = (&K, &V)> {
        // TODO: this is extremely unoptimized
        let target_hashed = Key::new(target.as_ref());
        let mut list = self.iter().collect::<Vec<_>>();
        list.sort_by_key(|(key, _)| {
            let key_hashed = Key::new(key.as_ref());
            distance_log2(&key_hashed, &target_hashed)
                .map(|d| u16::from(d) + 1)
                .unwrap_or(0)
        });
        list.into_iter()
    }
}

impl<K, V, TNow, const ENTRIES_PER_BUCKET: usize> KBuckets<K, V, TNow, ENTRIES_PER_BUCKET> {
    /// Iterates over all the peers in the k-buckets.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter().map(|(k, v)| (k, v)))
    }

    /// Iterates over all the peers in the k-buckets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.buckets
            .iter_mut()
            .flat_map(|b| b.entries.iter_mut().map(|(k, v)| (&*k, v)))
    }
}

impl<K, V, TNow, const ENTRIES_PER_BUCKET: usize> fmt::Debug
    for KBuckets<K, V, TNow, ENTRIES_PER_BUCKET>
where
    K: fmt::Debug,
    V: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

pub enum Entry<'a, K, V, TNow, const ENTRIES_PER_BUCKET: usize> {
    /// Requested key is the same as local key. The local key is never present in the k-buckets.
    LocalKey,
    Vacant(VacantEntry<'a, K, V, TNow, ENTRIES_PER_BUCKET>),
    Occupied(OccupiedEntry<'a, K, V, TNow, ENTRIES_PER_BUCKET>),
}

impl<'a, K, V, TNow, const ENTRIES_PER_BUCKET: usize> Entry<'a, K, V, TNow, ENTRIES_PER_BUCKET>
where
    K: Clone + PartialEq + AsRef<[u8]>,
    TNow: Clone + Add<Duration, Output = TNow> + Ord,
{
    /// If `self` is [`Entry::Occupied`], returns the inner [`OccupiedEntry ]. Otherwise returns
    /// `None`.
    pub fn into_occupied(self) -> Option<OccupiedEntry<'a, K, V, TNow, ENTRIES_PER_BUCKET>> {
        match self {
            Entry::LocalKey | Entry::Vacant(_) => None,
            Entry::Occupied(e) => Some(e),
        }
    }

    pub fn or_insert(
        self,
        value: V,
        now: &TNow,
        state: PeerState,
    ) -> Result<OccupiedEntry<'a, K, V, TNow, ENTRIES_PER_BUCKET>, ()> {
        match self {
            Entry::LocalKey => Err(()),
            Entry::Vacant(v) => v.insert(value, now, state),
            Entry::Occupied(e) => Ok(e),
        }
    }
}

pub struct VacantEntry<'a, K, V, TNow, const ENTRIES_PER_BUCKET: usize> {
    inner: &'a mut KBuckets<K, V, TNow, ENTRIES_PER_BUCKET>,
    key: &'a K,
    distance: u8,
}

impl<'a, K, V, TNow, const ENTRIES_PER_BUCKET: usize>
    VacantEntry<'a, K, V, TNow, ENTRIES_PER_BUCKET>
where
    K: Clone + PartialEq + AsRef<[u8]>,
    TNow: Clone + Add<Duration, Output = TNow> + Ord,
{
    /// Inserts the entry in the vacant slot. Returns an error if the k-buckets are full.
    pub fn insert(
        self,
        value: V,
        now: &TNow,
        state: PeerState,
    ) -> Result<OccupiedEntry<'a, K, V, TNow, ENTRIES_PER_BUCKET>, ()> {
        let bucket = &mut self.inner.buckets[usize::from(self.distance)];

        match state {
            PeerState::Connected if bucket.num_connected_entries < ENTRIES_PER_BUCKET => {
                let index = bucket.num_connected_entries;
                bucket.entries.insert(index, (self.key.clone(), value));
                bucket.num_connected_entries += 1;
            }
            PeerState::Connected => {
                debug_assert_eq!(bucket.num_connected_entries, ENTRIES_PER_BUCKET);
                if bucket.pending_entry.is_none() {
                    bucket.pending_entry = Some((
                        self.key.clone(),
                        value,
                        now.clone() + self.inner.pending_timeout,
                    ));
                } else {
                    return Err(());
                }
            }
            PeerState::Disconnected if bucket.entries.is_full() => {
                if matches!(bucket.pending_entry, Some((_, _, ref exp)) if *exp > *now) {
                    return Err(());
                }

                bucket.pending_entry = Some((
                    self.key.clone(),
                    value,
                    now.clone() + self.inner.pending_timeout,
                ));
            }
            PeerState::Disconnected => {
                debug_assert!(!bucket.entries.is_full());
                debug_assert!(bucket.pending_entry.is_none());
                bucket.entries.push((self.key.clone(), value));
            }
        };

        Ok(OccupiedEntry {
            inner: self.inner,
            key: self.key,
            distance: self.distance,
        })
    }
}

pub struct OccupiedEntry<'a, K, V, TNow, const ENTRIES_PER_BUCKET: usize> {
    inner: &'a mut KBuckets<K, V, TNow, ENTRIES_PER_BUCKET>,
    key: &'a K,
    distance: u8,
}

impl<'a, K, V, TNow, const ENTRIES_PER_BUCKET: usize>
    OccupiedEntry<'a, K, V, TNow, ENTRIES_PER_BUCKET>
where
    K: Clone + PartialEq + AsRef<[u8]>,
    TNow: Clone + Add<Duration, Output = TNow> + Ord,
{
    /// Updates the state of this entry.
    pub fn set_state(&mut self, state: PeerState) {
        let bucket = &mut self.inner.buckets[usize::from(self.distance)];
        match (bucket.pending_entry.as_ref(), state) {
            (Some(pending_entry), PeerState::Disconnected) if pending_entry.0 == *self.key => {}
            (Some(pending_entry), PeerState::Connected) if pending_entry.0 == *self.key => {}
            (_, PeerState::Connected) => {
                let position = bucket
                    .entries
                    .iter()
                    .position(|(k, _)| *k == *self.key)
                    .unwrap();
                if position >= bucket.num_connected_entries {
                    debug_assert!(bucket.num_connected_entries < ENTRIES_PER_BUCKET);
                    let entry = bucket.entries.remove(position);
                    bucket.entries.insert(bucket.num_connected_entries, entry);
                    bucket.num_connected_entries += 1;
                }
            }
            (_, PeerState::Disconnected) => {
                let position = bucket
                    .entries
                    .iter()
                    .position(|(k, _)| *k == *self.key)
                    .unwrap();
                if position < bucket.num_connected_entries {
                    let entry = bucket.entries.remove(position);
                    bucket.num_connected_entries -= 1;
                    bucket.entries.insert(bucket.num_connected_entries, entry);
                }
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut V {
        self.inner.buckets[usize::from(self.distance)]
            .get_mut(self.key)
            .unwrap()
    }
}

pub enum PeerState {
    Connected,
    Disconnected,
}

struct Bucket<K, V, TNow, const ENTRIES_PER_BUCKET: usize> {
    /// List of entries in the bucket. Ordered by decreasing importance. The first entries in
    /// the list are the ones we've been connected to for the longest time, while the last entries
    /// are the ones we've disconnected from for a long time.
    entries: arrayvec::ArrayVec<(K, V), ENTRIES_PER_BUCKET>,
    /// Number of entries in the [`Bucket::entries`] that are in the [`PeerState::Connected`]
    /// state.
    num_connected_entries: usize,
    /// Entry that has been "kicked out" from [`Bucket::pending_entry`]. After the given `TNow`,
    /// this entry will be switched to `None`.
    pending_entry: Option<(K, V, TNow)>,
}

impl<K, V, TNow, const ENTRIES_PER_BUCKET: usize> Bucket<K, V, TNow, ENTRIES_PER_BUCKET>
where
    K: PartialEq,
{
    fn get(&self, key: &K) -> Option<&V> {
        if let Some((_, value)) = self.entries.iter().find(|e| e.0 == *key) {
            return Some(value);
        }

        if let Some(pending_entry) = &self.pending_entry {
            if pending_entry.0 == *key {
                // TODO: check expiration?
                return Some(&pending_entry.1);
            }
        }

        None
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if let Some((_, value)) = self.entries.iter_mut().find(|e| e.0 == *key) {
            return Some(value);
        }

        if let Some(pending_entry) = &mut self.pending_entry {
            if pending_entry.0 == *key {
                // TODO: check expiration?
                return Some(&mut pending_entry.1);
            }
        }

        None
    }
}

/// Key entry in a bucket.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key {
    digest: [u8; 32],
}

impl Key {
    fn new(value: &[u8]) -> Self {
        Self {
            digest: Sha256::digest(value).into(),
        }
    }

    #[cfg(test)] // TODO: #[cfg(test)] is a bit crappy; figure out
    fn from_sha256_hash(hash: [u8; 32]) -> Self {
        Self { digest: hash }
    }
}

/// Returns the log2 distance between two keys. Returns `None` if the distance is zero.
fn distance_log2(a: &Key, b: &Key) -> Option<u8> {
    for n in 0..32 {
        let a = a.digest[n];
        let b = b.digest[n];
        let xor_leading_zeroes = (a ^ b).leading_zeros();
        if xor_leading_zeroes == 8 {
            continue;
        }

        let xor_distance = u32::try_from((31 - n) * 8).unwrap() + (8 - xor_leading_zeroes);
        debug_assert!(xor_distance > 0);
        debug_assert!(xor_distance <= 256);
        return Some(u8::try_from(xor_distance - 1).unwrap());
    }

    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn basic_distance_1() {
        let a = super::Key::from_sha256_hash([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let b = super::Key::from_sha256_hash([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);

        assert_eq!(super::distance_log2(&a, &b), Some(0));
    }

    #[test]
    fn basic_distance_2() {
        let a = super::Key::from_sha256_hash([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let b = super::Key::from_sha256_hash([
            0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);

        assert_eq!(super::distance_log2(&a, &b), Some(255));
    }

    #[test]
    fn distance_of_zero() {
        let a = super::Key::new(&[1, 2, 3, 4]);
        let b = super::Key::new(&[1, 2, 3, 4]);
        assert_eq!(super::distance_log2(&a, &b), None);
    }

    // TODO: a lot of tests
}

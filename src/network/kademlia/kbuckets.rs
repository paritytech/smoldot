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

//! K-buckets are a collection used to store a partial view of the list of nodes in a
//! peer-to-peer network.
//!
//! # How it works
//!
//! The k-buckets consist in 256 so-called "buckets", each containing up to `ENTRIES_PER_BUCKET`
//! elements. The value for `ENTRIES_PER_BUCKET` is configurable as a parameter of the [`KBuckets`]
//! struct, but is typically equal to 20. Therefore, the k-buckets cannot contain more than `256 *
//! ENTRIES_PER_BUCKET` elements in total.
//!
//! The API of the [`KBuckets`] struct is similar to the one of a `key => value` map. In addition
//! to its value, each element also contains a [`PeerState`] indicating whether this node is
//! connected to the local node.
//!
//! In order to insert an element, its key is first hashed using the SHA-256 algorithm, then this
//! hash is compared with the hash of a `local_key` that was passed at initialization. The
//! position of the highest non-matching bit in this comparison determines in which of the 256
//! buckets the element will be inserted. It is forbidden to insert the `local_key` itself.
//!
//! Within a bucket, each new element is inserted one after the other, except that the elements
//! whose [`PeerState`] is [`PeerState::Connected`] are always earlier in the list compared to the
//! ones whose state is [`PeerState::Disconnected`]. If the state of an element is updated using
//! [`OccupiedEntry::set_state`], the elements are re-ordered accordingly.
//!
//! Each bucket can only contain `ENTRIES_PER_BUCKET` elements. If a bucket is full and contains
//! only elements in the [`PeerState::Connected`] state, then no new element can be added. If a
//! bucket is full and contains at least one [`PeerState::Disconnected`] elements, then the last
//! element in the bucket will expire after a certain time after which it can be replaced with a
//! new one.
//!
//! # Properties
//!
//! While this data structure is generic, the `local_key` passed at initialization is typically
//! the network identity of the local node, and the keys being inserted are typically the network
//! identities of the other nodes of the peer-to-peer network.
//!
//! Assuming that all the network identities that exist are distributed uniformly, the k-buckets
//! will hold more network identities that are close to the the local node's network identity, and
//! fewer network identities that are far away. In other words, the k-buckets store the neighbors
//! of the local node, and a few far-away nodes.
//!
//! Since all the nodes of the network do the same, one can find all the node whose identity is
//! closest to a certain key `K` by doing the following:
//!
//! - Find in our local k-buckets the node `N` closest to `K`.
//! - Ask `N` to look into its own k-buckets what is the node closest to `K`.
//! - If `N` has a node `N2` where `distance(K, N2) < distance(K, N)`, then repeat the previous
//! step but with `N2`.
//! - If no closer node is found, we know that `N` is the node closest to `K` in the network.
//!

use alloc::vec::Vec;
use core::{fmt, ops::Add, time::Duration};
use sha2::{Digest as _, Sha256};

/// K-buckets, as popularized by the Kademlia algorithm, and defined by the libp2p specification.
pub struct KBuckets<K, V, TNow, const ENTRIES_PER_BUCKET: usize> {
    /// Key of the "local" node, that holds the buckets.
    local_key: (K, Key),
    /// List of buckets, ordered by increasing distance. In other words, the first elements of
    /// this field are the ones that are the closest to [`KBuckets::local_key`].
    buckets: Vec<Bucket<K, V, TNow, ENTRIES_PER_BUCKET>>,
    /// Duration after which the last entry of each bucket will expired if it is disconnected.
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
        let mut list = self.iter_ordered().collect::<Vec<_>>();
        list.sort_by_key(|(key, _)| {
            let key_hashed = Key::new(key.as_ref());
            distance_log2(&key_hashed, &target_hashed).map_or(0, |d| u16::from(d) + 1)
        });
        list.into_iter()
    }
}

impl<K, V, TNow, const ENTRIES_PER_BUCKET: usize> KBuckets<K, V, TNow, ENTRIES_PER_BUCKET> {
    /// Iterates over all the peers in the k-buckets.
    ///
    /// The buckets are iterated one by one from closest to furthest away, and within each bucket
    /// elements are ordered by descending time since connectivity.
    pub fn iter_ordered(&self) -> impl Iterator<Item = (&K, &V)> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter().map(|(k, v)| (k, v)))
    }

    /// Iterates over all the peers in the k-buckets.
    ///
    /// The buckets are iterated one by one from closest to furthest away, and within each bucket
    /// elements are ordered by descending time since connectivity.
    pub fn iter_mut_ordered(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
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
        f.debug_list().entries(self.iter_ordered()).finish()
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
    /// If `self` is [`Entry::Occupied`], returns the inner [`OccupiedEntry`]. Otherwise returns
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
                if bucket.entries.is_full() {
                    let _ = bucket.entries.pop(); // TODO: return element?
                    bucket.pending_entry = Some(now.clone() + self.inner.pending_timeout);
                }

                bucket
                    .entries
                    .insert(bucket.num_connected_entries, (self.key.clone(), value));
                bucket.num_connected_entries += 1;

                if bucket.num_connected_entries == ENTRIES_PER_BUCKET {
                    bucket.pending_entry = None;
                }
            }
            PeerState::Connected => {
                debug_assert!(bucket.entries.is_full());
                debug_assert_eq!(bucket.num_connected_entries, ENTRIES_PER_BUCKET);
                debug_assert!(bucket.pending_entry.is_none());
                return Err(());
            }
            PeerState::Disconnected if bucket.entries.is_full() => {
                if bucket.num_connected_entries == ENTRIES_PER_BUCKET {
                    return Err(());
                }

                if *bucket.pending_entry.as_ref().unwrap() > *now {
                    return Err(());
                }

                let _ = bucket.entries.pop(); // TODO: return element?
                bucket.entries.push((self.key.clone(), value));
                bucket.pending_entry = Some(now.clone() + self.inner.pending_timeout);
            }
            PeerState::Disconnected => {
                debug_assert!(!bucket.entries.is_full());
                debug_assert!(bucket.pending_entry.is_none());
                bucket.entries.push((self.key.clone(), value));

                if bucket.entries.is_full() {
                    bucket.pending_entry = Some(now.clone() + self.inner.pending_timeout);
                }
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
    pub fn set_state(&mut self, now: &TNow, state: PeerState) {
        let bucket = &mut self.inner.buckets[usize::from(self.distance)];
        let position = bucket
            .entries
            .iter()
            .position(|(k, _)| *k == *self.key)
            .unwrap();

        match state {
            PeerState::Connected if position >= bucket.num_connected_entries => {
                debug_assert!(bucket.num_connected_entries < ENTRIES_PER_BUCKET);
                let entry = bucket.entries.remove(position);
                bucket.entries.insert(bucket.num_connected_entries, entry);
                bucket.num_connected_entries += 1;

                // If the peer we switch from disconnected to connected was the last one, reset
                // the expiration.
                if position == bucket.entries.capacity() - 1 {
                    debug_assert!(bucket.pending_entry.is_some());
                    bucket.pending_entry = Some(now.clone() + self.inner.pending_timeout);
                }
            }

            PeerState::Disconnected if position < bucket.num_connected_entries => {
                let entry = bucket.entries.remove(position);
                bucket.num_connected_entries -= 1;
                bucket.entries.insert(bucket.num_connected_entries, entry);

                // If the peer we switch from connected to disconnected is now the last one, start
                // the expiration.
                if bucket.num_connected_entries == bucket.entries.capacity() - 1 {
                    debug_assert!(bucket.pending_entry.is_none());
                    bucket.pending_entry = Some(now.clone() + self.inner.pending_timeout);
                }
            }

            _ => {}
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
    /// If `Some`, the last entry in [`Bucket::entries`] is going to get kicked out after `TNow`.
    /// Always `None` if [`Bucket::entries`] isn't full or contains only connected entries.
    pending_entry: Option<TNow>,
}

impl<K, V, TNow, const ENTRIES_PER_BUCKET: usize> Bucket<K, V, TNow, ENTRIES_PER_BUCKET>
where
    K: PartialEq,
{
    fn get(&self, key: &K) -> Option<&V> {
        if let Some((_, value)) = self.entries.iter().find(|e| e.0 == *key) {
            return Some(value);
        }

        // TODO: check expiration?

        None
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if let Some((_, value)) = self.entries.iter_mut().find(|e| e.0 == *key) {
            return Some(value);
        }

        // TODO: check expiration?

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

/// Returns the `log2` distance between two keys. Returns `None` if the distance is zero.
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
    use core::time::Duration;
    use sha2::{Digest as _, Sha256};

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
    fn basic_distance_3() {
        let a = super::Key::from_sha256_hash([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        let b = super::Key::from_sha256_hash([
            0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 5, 7, 94, 103, 94, 26, 20, 0, 0,
            1, 37, 198, 200, 57, 33, 32,
        ]);

        assert_eq!(super::distance_log2(&a, &b), Some(255));
    }

    #[test]
    fn distance_of_zero() {
        let a = super::Key::new(&[1, 2, 3, 4]);
        let b = super::Key::new(&[1, 2, 3, 4]);
        assert_eq!(super::distance_log2(&a, &b), None);
    }

    #[test]
    fn nodes_kicked_out() {
        let local_key = vec![0u8; 4];

        // Iterator that generates random keys that are in the maximum size bucket.
        let mut max_bucket_keys = {
            let local_key_hash = Sha256::digest(&local_key);
            (0..).map(move |_| loop {
                let other_key: [u8; 32] = rand::random();
                let other_key_hashed = Sha256::digest(&other_key);
                if ((local_key_hash[0] ^ other_key_hashed[0]) & 0x80) != 0 {
                    break other_key.to_vec();
                }
            })
        };

        let mut buckets = super::KBuckets::<_, _, _, 4>::new(local_key, Duration::from_secs(1));

        // Insert 4 nodes in the bucket of maximum distance. Since there's only capacity for 4,
        // the last one is in pending mode.
        for _ in 0..4 {
            match buckets.entry(&max_bucket_keys.next().unwrap()) {
                super::Entry::Vacant(e) => {
                    e.insert((), &Duration::new(0, 0), super::PeerState::Disconnected)
                        .unwrap();
                }
                _ => panic!(),
            }
        }

        // Inserting another node in that bucket. Since it's full, the insertion must fail.
        match buckets.entry(&max_bucket_keys.next().unwrap()) {
            super::Entry::Vacant(e) => {
                match e.insert((), &Duration::new(0, 0), super::PeerState::Disconnected) {
                    Ok(_) => panic!(),
                    Err(_) => {}
                }
            }
            _ => panic!(),
        }

        // Try again, but this time after the pending node's expiration has passed. This time,
        // the insertion must succeed.
        match buckets.entry(&max_bucket_keys.next().unwrap()) {
            super::Entry::Vacant(e) => {
                match e.insert((), &Duration::new(2, 0), super::PeerState::Disconnected) {
                    Ok(_) => {}
                    Err(_) => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    // TODO: a lot of tests
}

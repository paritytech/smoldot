// Smoldot
// Copyright (C) 2023  Pierre Krieger
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

#![cfg(test)]

use super::{Config, InProgress, TrieEntryVersion, trie_root_calculator};
use crate::{executor::storage_diff::TrieDiff, trie};
use core::{iter, ops};

use rand::distributions::{Distribution as _, Uniform};

#[test]
fn empty_trie_works() {
    let mut calculation = trie_root_calculator(Config {
        diff: TrieDiff::empty(),
        diff_trie_entries_version: TrieEntryVersion::V0,
        max_trie_recalculation_depth_hint: 8,
    });

    loop {
        match calculation {
            InProgress::Finished { trie_root_hash } => {
                assert_eq!(trie_root_hash, trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE);
                return;
            }
            InProgress::ClosestDescendant(req) => {
                calculation = req.inject(None::<iter::Empty<_>>);
            }
            InProgress::ClosestDescendantMerkleValue(req) => {
                calculation = req.resume_unknown();
            }
            InProgress::StorageValue(req) => {
                calculation = req.inject_value(None);
            }
            InProgress::TrieNodeInsertUpdateEvent(ev) => calculation = ev.resume(),
            InProgress::TrieNodeRemoveEvent(ev) => calculation = ev.resume(),
        }
    }
}

#[test]
fn one_inserted_node_in_diff() {
    let mut diff = TrieDiff::empty();
    diff.diff_insert(vec![0xaa, 0xaa], b"foo".to_vec(), ());

    let mut calculation = trie_root_calculator(Config {
        diff,
        diff_trie_entries_version: TrieEntryVersion::V0,
        max_trie_recalculation_depth_hint: 8,
    });

    loop {
        match calculation {
            InProgress::Finished { trie_root_hash } => {
                let expected = trie::trie_node::calculate_merkle_value(
                    trie::trie_node::Decoded {
                        children: [None::<&'static [u8]>; 16],
                        partial_key: trie::bytes_to_nibbles(vec![0xaa, 0xaa].into_iter()),
                        storage_value: trie::trie_node::StorageValue::Unhashed(b"foo"),
                    },
                    trie::HashFunction::Blake2,
                    true,
                )
                .unwrap();

                assert_eq!(trie_root_hash, expected.as_ref());
                return;
            }
            InProgress::ClosestDescendant(req) => {
                calculation = req.inject(None::<iter::Empty<_>>);
            }
            InProgress::ClosestDescendantMerkleValue(req) => {
                calculation = req.resume_unknown();
            }
            InProgress::StorageValue(req) => {
                calculation = req.inject_value(None);
            }
            InProgress::TrieNodeInsertUpdateEvent(ev) => calculation = ev.resume(),
            InProgress::TrieNodeRemoveEvent(ev) => calculation = ev.resume(),
        }
    }
}

/// Trie whose nodes hold `(storage value + version if any, Merkle value once calculated)`.
type TestTrieStructure = trie::trie_structure::TrieStructure<(
    Option<(Vec<u8>, TrieEntryVersion)>,
    Option<trie::trie_node::MerkleValueOutput>,
)>;

fn build_trie(entries: &[Vec<u8>]) -> TestTrieStructure {
    let mut t = trie::trie_structure::TrieStructure::new();
    for (i, key) in entries.iter().enumerate() {
        let value = vec![u8::try_from(i).unwrap(); 4];
        match t.node(trie::bytes_to_nibbles(key.iter().copied())) {
            trie::trie_structure::Entry::Vacant(e) => {
                e.insert_storage_value()
                    .insert((Some((value, TrieEntryVersion::V0)), None), (None, None));
            }
            trie::trie_structure::Entry::Occupied(trie::trie_structure::NodeAccess::Branch(
                mut e,
            )) => {
                *e.user_data() = (Some((value, TrieEntryVersion::V0)), None);
                e.insert_storage_value();
            }
            trie::trie_structure::Entry::Occupied(trie::trie_structure::NodeAccess::Storage(_)) => {
            }
        }
    }
    t
}

/// A diff that erases keys absent from the base trie must not produce remove events for them.
#[test]
fn erase_of_nonexistent_key_emits_no_spurious_events() {
    // Pairs of (keys of the base trie, keys the diff erases).
    let cases = vec![
        (vec![vec![]], vec![vec![0x02]]),
        (vec![vec![], vec![0x01]], vec![vec![0x01, 0xff]]),
        (vec![vec![0xaa, 0x01], vec![0xaa, 0x02]], vec![vec![0xaa]]),
        (
            vec![vec![0xaa, 0x01], vec![0xaa, 0x02]],
            vec![vec![0xbb], vec![0xaa, 0x01, 0x01]],
        ),
        (vec![], vec![vec![0x42]]),
        (
            vec![vec![0xaa, 0x01], vec![0xaa, 0x02]],
            vec![vec![0xaa, 0x01, 0x01], vec![0xaa, 0x01, 0x02]],
        ),
    ];
    for (base_keys, erased) in cases {
        let before = build_trie(&base_keys);
        let after = before.clone();
        let mut diff = TrieDiff::empty();
        for key in &erased {
            diff.diff_insert_erase(key.clone(), ());
        }
        for provide_merkle_value in [false, true] {
            let mut before = before.clone();
            let mut after = after.clone();
            check_against_diff(
                &mut before,
                &mut after,
                &diff,
                TrieEntryVersion::V0,
                &mut || provide_merkle_value,
                &format!("base = {base_keys:?}, erased = {erased:?}, pmv = {provide_merkle_value}"),
            );
        }
    }
}

/// The base trie contains a node that the diff removes through the "replaced with its single
/// remaining child" mechanism. Recalculating the Merkle value of the child (whose partial key
/// has changed) walks the subtree again, and must not report again the removals that were
/// already reported during the first walk.
#[test]
fn no_duplicate_remove_event_during_single_child_recalculation() {
    let before = build_trie(&[vec![], vec![0x00]]);
    let after = build_trie(&[vec![0x00, 0x00]]);
    let mut diff = TrieDiff::empty();
    diff.diff_insert_erase(vec![], ());
    diff.diff_insert_erase(vec![0x00], ());
    diff.diff_insert(vec![0x00, 0x00], vec![0x00; 4], ());

    for provide_merkle_value in [false, true] {
        let mut before = before.clone();
        let mut after = after.clone();
        check_against_diff(
            &mut before,
            &mut after,
            &diff,
            TrieEntryVersion::V0,
            &mut || provide_merkle_value,
            &format!("pmv = {provide_merkle_value}"),
        );
    }
}

/// The root of the base trie is a branch node without any storage value, and the diff empties
/// the trie. A remove event must be generated for the destroyed branch root, like for every
/// other destroyed node.
#[test]
fn remove_event_generated_when_branch_root_destroyed() {
    let before = build_trie(&[vec![0x00], vec![0x01]]);
    let after = build_trie(&[]);
    let mut diff = TrieDiff::empty();
    diff.diff_insert_erase(vec![0x00], ());
    diff.diff_insert_erase(vec![0x01], ());

    for provide_merkle_value in [false, true] {
        let mut before = before.clone();
        let mut after = after.clone();
        check_against_diff(
            &mut before,
            &mut after,
            &diff,
            TrieEntryVersion::V0,
            &mut || provide_merkle_value,
            &format!("pmv = {provide_merkle_value}"),
        );
    }
}

/// Unlike `fuzzing`, this test tries every case instead of random ones.
///
/// The world is seven short keys: the empty key, two one-byte keys and four two-byte keys.
/// Every subset of these keys is used as a base trie (2^7 = 128 tries), and every assignment
/// of nothing/insert/erase to these keys is used as a diff (3^7 = 2187 diffs). Each pair is run
/// through the calculator and its root hash and insert/remove events are checked. About 560k
/// cases in total. If a remove-event bug fits in a trie this small, this test finds it.
///
/// Ignored because it takes about 20 s in debug mode on 24 cores. Run by hand when changing
/// the re-walk logic:
/// `cargo test -p smoldot --lib --release -- exhaustive_small_scope --ignored`.
#[test]
#[ignore]
fn exhaustive_small_scope() {
    // Two alphabets: one where the bytes differ in the low nibble, one in the high nibble, so
    // that forks happen at both nibble positions.
    for alphabet in [[0x00u8, 0x01], [0x00, 0x10]] {
        // keys = ["", [a], [a,a], [a,b], [b], [b,a], [b,b]], as a full binary trie of depth 2.
        let mut keys: Vec<Vec<u8>> = vec![vec![]];
        for &a in &alphabet {
            keys.push(vec![a]);
            for &b in &alphabet {
                keys.push(vec![a, b]);
            }
        }
        let n = keys.len();
        assert_eq!(n, 7);

        // Spread the 128 base tries over 16 threads.
        std::thread::scope(|scope| {
            for chunk in (0u32..1 << n).collect::<Vec<_>>().chunks(16) {
                let keys = &keys;
                let chunk = chunk.to_vec();
                scope.spawn(move || {
                    // `base_mask` is a 7-bit number: bit `i` set means key `i` is in the base
                    // trie. Counting 0..128 covers every subset once.
                    for base_mask in chunk {
                        let base_keys: Vec<Vec<u8>> = (0..n)
                            .filter(|i| base_mask & (1 << i) != 0)
                            .map(|i| keys[i].clone())
                            .collect();
                        let before_proto = build_trie(&base_keys);

                        // `diff_code` is a 7-digit number in base 3: digit `i` says what the
                        // diff does to key `i` (0 = nothing, 1 = insert, 2 = erase). Counting
                        // 0..3^7 covers every diff once.
                        for diff_code in 0..3u32.pow(u32::try_from(n).unwrap()) {
                            let mut diff = TrieDiff::empty();
                            // `after_proto` is the expected trie after the diff, built by hand.
                            let mut after_proto = before_proto.clone();
                            let mut c = diff_code;
                            for key in keys.iter().take(n) {
                                match c % 3 {
                                    0 => {}
                                    1 => {
                                        let value = vec![0x99, (c % 256) as u8, key.len() as u8];
                                        diff.diff_insert(key.clone(), value.clone(), ());
                                        match after_proto
                                            .node(trie::bytes_to_nibbles(key.iter().copied()))
                                        {
                                            trie::trie_structure::Entry::Vacant(e) => {
                                                e.insert_storage_value().insert(
                                                    (Some((value, TrieEntryVersion::V0)), None),
                                                    (None, None),
                                                );
                                            }
                                            trie::trie_structure::Entry::Occupied(
                                                trie::trie_structure::NodeAccess::Branch(mut e),
                                            ) => {
                                                *e.user_data() =
                                                    (Some((value, TrieEntryVersion::V0)), None);
                                                e.insert_storage_value();
                                            }
                                            trie::trie_structure::Entry::Occupied(
                                                trie::trie_structure::NodeAccess::Storage(mut e),
                                            ) => {
                                                *e.user_data() =
                                                    (Some((value, TrieEntryVersion::V0)), None);
                                            }
                                        }
                                    }
                                    2 => {
                                        diff.diff_insert_erase(key.clone(), ());
                                        if let trie::trie_structure::Entry::Occupied(
                                            trie::trie_structure::NodeAccess::Storage(mut e),
                                        ) = after_proto
                                            .node(trie::bytes_to_nibbles(key.iter().copied()))
                                        {
                                            e.user_data().0 = None;
                                            e.remove();
                                        }
                                    }
                                    _ => unreachable!(),
                                }
                                c /= 3;
                            }

                            // Run once answering Merkle value requests and once refusing them,
                            // since the calculator takes different paths in each case.
                            for pmv in [false, true] {
                                let mut before = before_proto.clone();
                                let mut after = after_proto.clone();
                                check_against_diff(
                                    &mut before,
                                    &mut after,
                                    &diff,
                                    TrieEntryVersion::V0,
                                    &mut || pmv,
                                    &format!(
                                        "base_mask = {base_mask:#b}, \
                                         diff_code = {diff_code}, \
                                         alphabet = {alphabet:?}, pmv = {pmv}"
                                    ),
                                );
                            }
                        }
                    }
                });
            }
        });
    }
}

#[test]
fn fuzzing() {
    // We run the test multiple times because of randomness. Each iteration uses its own seed,
    // and the seed is included in panic messages, so that a failure can be reproduced
    // deterministically.
    for _ in 0..32768 {
        fuzzing_iteration(rand::random::<u64>());
    }
}

fn fuzzing_iteration(seed: u64) {
    use rand::{Rng as _, SeedableRng as _};

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);

    fn uniform_sample(rng: &mut rand_chacha::ChaCha20Rng, min: u8, max: u8) -> u8 {
        Uniform::new_inclusive(min, max).sample(rng)
    }

    {
        // Create a random trie.
        // Each node contains a `Some` with the storage value or `None` for branch nodes, plus its
        // Merkle value as `Some` if already calculated.
        let mut trie_before_diff = trie::trie_structure::TrieStructure::<(
            Option<(Vec<u8>, TrieEntryVersion)>,
            Option<trie::trie_node::MerkleValueOutput>,
        )>::new();

        let mut list = vec![Vec::new()];
        for elem in list.clone().into_iter() {
            for _ in 0..uniform_sample(&mut rng, 0, 4) {
                let mut elem = elem.clone();
                for _ in 0..uniform_sample(&mut rng, 0, 3) {
                    elem.push(uniform_sample(&mut rng, 0, 255));
                }
                list.push(elem);
            }
        }
        for elem in list {
            let mut storage_value = Vec::new();
            for _ in 0..uniform_sample(&mut rng, 0, 24) {
                storage_value.push(uniform_sample(&mut rng, 0, 255));
            }

            let trie_entry_version = if rng.gen_bool(0.5) {
                TrieEntryVersion::V1
            } else {
                TrieEntryVersion::V0
            };

            match trie_before_diff.node(trie::bytes_to_nibbles(elem.iter().copied())) {
                trie::trie_structure::Entry::Vacant(e) => {
                    e.insert_storage_value().insert(
                        (Some((storage_value, trie_entry_version)), None),
                        (None, None),
                    );
                }
                trie::trie_structure::Entry::Occupied(
                    trie::trie_structure::NodeAccess::Branch(mut e),
                ) => {
                    *e.user_data() = (Some((storage_value, trie_entry_version)), None);
                    e.insert_storage_value();
                }
                trie::trie_structure::Entry::Occupied(
                    trie::trie_structure::NodeAccess::Storage(_),
                ) => {}
            }
        }

        // Clone the trie and apply modifications to it. These modifications are also registered
        // in a diff.
        let mut trie_after_diff = trie_before_diff.clone();
        let mut diff = TrieDiff::empty();
        let diff_trie_entries_version = if rng.gen_bool(0.5) {
            TrieEntryVersion::V1
        } else {
            TrieEntryVersion::V0
        };

        for _ in 0..5 {
            let mut list = vec![Vec::new()];
            for elem in list.clone().into_iter() {
                for _ in 0..uniform_sample(&mut rng, 0, 4) {
                    let mut elem = elem.clone();
                    for _ in 0..uniform_sample(&mut rng, 0, 3) {
                        elem.push(uniform_sample(&mut rng, 0, 255));
                    }
                    list.push(elem);
                }
            }
            for elem in list {
                let mut storage_value = Vec::new();
                for _ in 0..uniform_sample(&mut rng, 0, 24) {
                    storage_value.push(uniform_sample(&mut rng, 0, 255));
                }

                match trie_after_diff.node(trie::bytes_to_nibbles(elem.iter().copied())) {
                    trie::trie_structure::Entry::Occupied(
                        trie::trie_structure::NodeAccess::Storage(mut e),
                    ) => {
                        if rng.gen_bool(0.5) {
                            // Update storage value.
                            *e.user_data() = (
                                Some((storage_value.clone(), diff_trie_entries_version)),
                                None,
                            );
                            diff.diff_insert(elem, storage_value, ());
                        } else {
                            // Erase node.
                            e.user_data().0 = None;
                            e.remove();
                            diff.diff_insert_erase(elem, ());
                        }
                    }
                    trie::trie_structure::Entry::Occupied(
                        trie::trie_structure::NodeAccess::Branch(mut e),
                    ) => {
                        *e.user_data() = (
                            Some((storage_value.clone(), diff_trie_entries_version)),
                            None,
                        );
                        e.insert_storage_value();
                        diff.diff_insert(elem, storage_value, ());
                    }
                    trie::trie_structure::Entry::Vacant(e) => {
                        e.insert_storage_value().insert(
                            (
                                Some((storage_value.clone(), diff_trie_entries_version)),
                                None,
                            ),
                            (None, None),
                        );
                        diff.diff_insert(elem, storage_value, ());
                    }
                }
            }
        }

        check_against_diff(
            &mut trie_before_diff,
            &mut trie_after_diff,
            &diff,
            diff_trie_entries_version,
            &mut || rng.gen_bool(0.5),
            &format!("seed = {seed}"),
        );
    }
}

/// Verifies that `trie_root_calculator` on `trie_before_diff` + `diff` produces the root hash of
/// `trie_after_diff` and a consistent stream of insert/update/remove events.
///
/// `trie_after_diff` must be exactly `trie_before_diff` with `diff` applied. The `(storage value,
/// version)` user data of every node must be set; Merkle value user data is filled in by this
/// function. `ctx` is included in panic messages.
fn check_against_diff(
    trie_before_diff: &mut TestTrieStructure,
    trie_after_diff: &mut TestTrieStructure,
    diff: &TrieDiff,
    diff_trie_entries_version: TrieEntryVersion,
    // Decides, for each `ClosestDescendantMerkleValue` request, whether to answer it from the
    // base trie (`true`) or to answer `resume_unknown` (`false`).
    provide_merkle_value: &mut dyn FnMut() -> bool,
    ctx: &str,
) {
    {
        // Calculate the Merkle values of the nodes of `trie_before_diff` and `trie_after_diff`.
        for trie in [&mut *trie_before_diff, &mut *trie_after_diff] {
            for node_index in trie.iter_ordered().collect::<Vec<_>>().into_iter().rev() {
                let mut node_access = trie.node_by_index(node_index).unwrap();

                let children = core::array::from_fn::<_, 16, _>(|n| {
                    node_access
                        .child(trie::Nibble::try_from(u8::try_from(n).unwrap()).unwrap())
                        .map(|mut child| child.user_data().1.as_ref().unwrap().clone())
                });

                let is_root_node = node_access.is_root_node();
                let partial_key = node_access.partial_key().collect::<Vec<_>>().into_iter();

                // We have to hash the storage value ahead of time if necessary due to borrow
                // checking difficulties.
                let storage_value_hashed = match node_access.user_data().0.as_ref() {
                    Some((v, TrieEntryVersion::V1)) => {
                        if v.len() >= 33 {
                            Some(blake2_rfc::blake2b::blake2b(32, &[], v))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                let storage_value = match (
                    node_access.user_data().0.as_ref(),
                    storage_value_hashed.as_ref(),
                ) {
                    (_, Some(storage_value_hashed)) => trie::trie_node::StorageValue::Hashed(
                        <&[u8; 32]>::try_from(storage_value_hashed.as_bytes()).unwrap(),
                    ),
                    (Some((v, _)), None) => trie::trie_node::StorageValue::Unhashed(&v[..]),
                    (None, _) => trie::trie_node::StorageValue::None,
                };

                let merkle_value = trie::trie_node::calculate_merkle_value(
                    trie::trie_node::Decoded {
                        children,
                        partial_key,
                        storage_value,
                    },
                    trie::HashFunction::Blake2,
                    is_root_node,
                )
                .unwrap();

                node_access.into_user_data().1 = Some(merkle_value);
            }
        }

        // Build alternative linear versions of the two tries.
        let mut trie_map = trie_before_diff
            .iter_ordered()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|n| {
                (
                    trie_before_diff
                        .node_full_key_by_index(n)
                        .unwrap()
                        .collect::<Vec<_>>(),
                    trie_before_diff[n].1.clone().unwrap().as_ref().to_vec(),
                )
            })
            .collect::<hashbrown::HashMap<_, _, fnv::FnvBuildHasher>>();
        let trie_after_diff_map = trie_after_diff
            .iter_ordered()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|n| {
                (
                    trie_after_diff
                        .node_full_key_by_index(n)
                        .unwrap()
                        .collect::<Vec<_>>(),
                    trie_after_diff[n].1.clone().unwrap().as_ref().to_vec(),
                )
            })
            .collect::<hashbrown::HashMap<_, _, fnv::FnvBuildHasher>>();

        // Use the trie_root_calculator to calculate the root of `trie_after_diff`.
        let obtained_hash = {
            let mut calculator = trie_root_calculator(Config {
                diff: diff.clone(),
                diff_trie_entries_version,
                max_trie_recalculation_depth_hint: 8,
            });

            loop {
                match calculator {
                    InProgress::Finished { trie_root_hash } => break trie_root_hash,
                    InProgress::ClosestDescendant(req) => {
                        let mut next_node = trie_before_diff
                            .range_iter(
                                ops::Bound::Included(req.key_as_vec().into_iter()),
                                ops::Bound::Unbounded::<iter::Empty<trie::Nibble>>,
                            )
                            .next();
                        // Set `next_node` to `None` if it isn't a descendant of the demanded key.
                        if next_node.is_some_and(|n| {
                            !trie_before_diff
                                .node_full_key_by_index(n)
                                .unwrap()
                                .collect::<Vec<_>>()
                                .starts_with(&req.key_as_vec())
                        }) {
                            next_node = None;
                        }
                        calculator = req.inject(
                            next_node.map(|n| trie_before_diff.node_full_key_by_index(n).unwrap()),
                        );
                    }
                    InProgress::ClosestDescendantMerkleValue(req) => {
                        if provide_merkle_value() {
                            let mut next_node = trie_before_diff
                                .range_iter(
                                    ops::Bound::Included(req.key_as_vec().into_iter()),
                                    ops::Bound::Unbounded::<iter::Empty<trie::Nibble>>,
                                )
                                .next();
                            // Set `next_node` to `None` if it isn't a descendant of the demanded key.
                            if next_node.is_some_and(|n| {
                                !trie_before_diff
                                    .node_full_key_by_index(n)
                                    .unwrap()
                                    .collect::<Vec<_>>()
                                    .starts_with(&req.key_as_vec())
                            }) {
                                next_node = None;
                            }

                            if let Some(next_node) = next_node {
                                calculator = req.inject_merkle_value(
                                    trie_before_diff
                                        .node_by_index(next_node)
                                        .unwrap()
                                        .into_user_data()
                                        .1
                                        .as_ref()
                                        .unwrap()
                                        .clone()
                                        .as_ref(),
                                );
                            } else {
                                calculator = req.resume_unknown();
                            }
                        } else {
                            calculator = req.resume_unknown()
                        }
                    }
                    InProgress::StorageValue(req) => {
                        let value = if let trie::trie_structure::Entry::Occupied(
                            trie::trie_structure::NodeAccess::Storage(e),
                        ) = trie_before_diff.node(req.key_as_vec().into_iter())
                        {
                            Some(e.into_user_data().0.as_ref().unwrap().clone())
                        } else {
                            None
                        };

                        calculator =
                            req.inject_value(value.as_ref().map(|(val, vers)| (&val[..], *vers)));
                    }
                    InProgress::TrieNodeInsertUpdateEvent(ev) => {
                        trie_map.insert(
                            ev.key()
                                .flat_map(crate::util::as_ref_iter)
                                .collect::<Vec<_>>(),
                            ev.merkle_value().to_vec(),
                        );
                        calculator = ev.resume();
                    }
                    InProgress::TrieNodeRemoveEvent(ev) => {
                        let key = ev
                            .key()
                            .flat_map(crate::util::as_ref_iter)
                            .collect::<Vec<_>>();
                        let was_in = trie_map.remove(&key);
                        if was_in.is_none() {
                            panic!(
                                "\n{}\nremove event for absent or already-removed node\nkey = {:?}\ntrie_before = {:?}\ndiff = {:?}",
                                ctx, key, trie_before_diff, diff
                            );
                        }
                        calculator = ev.resume();
                    }
                }
            }
        };

        // Actual test is here.
        let expected_hash = trie_after_diff
            .root_user_data()
            .map(|n| *<&[u8; 32]>::try_from(n.1.as_ref().unwrap().as_ref()).unwrap())
            .unwrap_or(trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE);
        if obtained_hash != expected_hash {
            panic!(
                "\n{}\nexpected = {:?}\ncalculated = {:?}\ntrie_before = {:?}\ndiff = {:?}",
                ctx, expected_hash, obtained_hash, trie_before_diff, diff
            );
        }
        if trie_map != trie_after_diff_map {
            panic!(
                "\n{}\nexpected = {:?}\ncalculated = {:?}\ntrie_before = {:?}\ndiff = {:?}",
                ctx, trie_after_diff_map, trie_map, trie_before_diff, diff
            );
        }
    }
}

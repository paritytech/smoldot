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

use super::{Config, ResumeOutcome, prefix_scan};

// TODO: more tests

#[test]
fn regression_test_174() {
    let test_data = serde_json::from_str::<TestData>(include_str!("./test.json")).unwrap();

    let mut prefix_scan = prefix_scan(Config {
        prefix: &test_data.prefix.0,
        trie_root_hash: <[u8; 32]>::try_from(&test_data.trie_root_hash.0[..]).unwrap(),
        full_storage_values_required: true,
    });

    for proof in test_data.proofs {
        match prefix_scan.resume_all_keys(&proof.0) {
            Ok(ResumeOutcome::InProgress(scan)) => {
                prefix_scan = scan;
                continue;
            }
            Ok(ResumeOutcome::Success { mut entries, .. }) => {
                let mut expected = test_data
                    .expected_entries
                    .into_iter()
                    .map(|e| e.0)
                    .collect::<Vec<_>>();
                expected.sort();
                entries.sort_by(|(key1, _), (key2, _)| key1.cmp(key2));
                assert_eq!(
                    entries.into_iter().map(|(key, _)| key).collect::<Vec<_>>(),
                    expected
                );
                return;
            }
            Err((_, err)) => panic!("{err:?}"),
        }
    }
}

#[test]
fn entries_ordered_by_key() {
    // `state_getKeysPaged` relies on the entries being ordered by key in order to paginate.
    let test_data = serde_json::from_str::<TestData>(include_str!("./test.json")).unwrap();

    let mut prefix_scan = prefix_scan(Config {
        prefix: &test_data.prefix.0,
        trie_root_hash: <[u8; 32]>::try_from(&test_data.trie_root_hash.0[..]).unwrap(),
        full_storage_values_required: true,
    });

    for proof in test_data.proofs {
        match prefix_scan.resume_all_keys(&proof.0) {
            Ok(ResumeOutcome::InProgress(scan)) => {
                prefix_scan = scan;
                continue;
            }
            Ok(ResumeOutcome::Success { entries, .. }) => {
                let keys = entries.into_iter().map(|(key, _)| key).collect::<Vec<_>>();
                let mut sorted = keys.clone();
                sorted.sort();
                assert_eq!(keys, sorted);
                return;
            }
            Err((_, err)) => panic!("{err:?}"),
        }
    }

    panic!("scan didn't finish")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TestData {
    prefix: HexString,
    trie_root_hash: HexString,
    proofs: Vec<HexString>,
    expected_entries: Vec<HexString>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct HexString(Vec<u8>);

impl serde::Serialize for HexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&("0x".to_string() + &hex::encode(&self.0)), serializer)
    }
}

impl<'a> serde::Deserialize<'a> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<HexString, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let string = String::deserialize(deserializer)?;

        if string.is_empty() {
            return Ok(HexString(Vec::new()));
        }

        if !string.starts_with("0x") {
            return Err(serde::de::Error::custom(
                "hexadecimal string doesn't start with 0x",
            ));
        }

        let bytes = hex::decode(&string[2..]).map_err(serde::de::Error::custom)?;
        Ok(HexString(bytes))
    }
}

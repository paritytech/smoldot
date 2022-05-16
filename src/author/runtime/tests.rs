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

#![cfg(test)]

use crate::verify::inherents;
use core::iter;

#[test]
fn block_building_works() {
    let chain_specs = crate::chain_spec::ChainSpec::from_json_bytes(
        &include_bytes!("example-chain-specs.json")[..],
    )
    .unwrap();
    let genesis_storage = chain_specs.genesis_storage().into_genesis_items().unwrap();

    let (chain_info, genesis_runtime) = chain_specs.as_chain_information().unwrap();
    let genesis_hash = chain_info.finalized_block_header.hash();

    let mut builder = super::build_block(super::Config {
        parent_runtime: genesis_runtime,
        parent_hash: &genesis_hash,
        parent_number: 0,
        block_body_capacity: 0,
        consensus_digest_log_item: super::ConfigPreRuntime::Aura(crate::header::AuraPreDigest {
            slot_number: 1234u64,
        }),
        top_trie_root_calculation_cache: None,
    });

    loop {
        match builder {
            super::BlockBuild::Finished(Ok(success)) => {
                let decoded = crate::header::decode(&success.scale_encoded_header).unwrap();
                assert_eq!(decoded.number, 1);
                assert_eq!(*decoded.parent_hash, genesis_hash);
                break;
            }
            super::BlockBuild::Finished(Err(err)) => panic!("{}", err),
            super::BlockBuild::ApplyExtrinsic(ext) => builder = ext.finish(),
            super::BlockBuild::ApplyExtrinsicResult { .. } => unreachable!(),
            super::BlockBuild::InherentExtrinsics(ext) => {
                builder = ext.inject_inherents(inherents::InherentData { timestamp: 1234 });
            }
            super::BlockBuild::StorageGet(get) => {
                let key = get.key_as_vec();
                let value = genesis_storage
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| iter::once(v));
                builder = get.inject_value(value);
            }
            super::BlockBuild::NextKey(_) => unimplemented!(), // Not needed for this test.
            super::BlockBuild::PrefixKeys(prefix) => {
                let p = prefix.prefix().as_ref().to_owned();
                let list = genesis_storage
                    .iter()
                    .filter(move |(k, _)| k.starts_with(&p))
                    .map(|(k, _)| k);
                builder = prefix.inject_keys_ordered(list);
            }
        }
    }
}

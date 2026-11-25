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

//! Downloads the GrandPa warp sync proof of Polkadot from genesis through the Rust API
//! (`Client::grandpa_warp_sync_proof`), and prints the number and hash of each fragment.
//! See <https://github.com/paritytech/smoldot/issues/3288>.
//!
//! The fragments are printed as received and are **not verified**.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smoldot-light --features std --example warp_proof
//! ```

use core::{iter, num::NonZero, time::Duration};
use smoldot::{chain_spec, header};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let specification = include_str!("../../demo-chain-specs/polkadot.json");

    // Compute the genesis block hash, which is where the warp sync proof starts.
    let chain_spec = chain_spec::ChainSpec::from_json_bytes(specification).unwrap();
    let block_number_bytes = usize::from(chain_spec.block_number_bytes());
    let genesis_hash = match chain_spec.genesis_storage() {
        // The chain specification only contains the root of the genesis storage. The genesis
        // header is then built the same way as `Client::add_chain` does.
        chain_spec::GenesisStorage::TrieRootHash(state_root) => header::Header {
            parent_hash: [0; 32],
            number: 0,
            state_root: *state_root,
            extrinsics_root: smoldot::trie::EMPTY_BLAKE2_TRIE_MERKLE_VALUE,
            digest: header::DigestRef::empty().into(),
        }
        .hash(block_number_bytes),
        chain_spec::GenesisStorage::Items(_) => {
            let (chain_information, _) = chain_spec.to_chain_information().unwrap();
            chain_information
                .as_ref()
                .finalized_block_header
                .hash(block_number_bytes)
        }
    };

    let mut client =
        smoldot_light::Client::new(smoldot_light::platform::default::DefaultPlatform::new(
            env!("CARGO_PKG_NAME").into(),
            env!("CARGO_PKG_VERSION").into(),
        ));

    let chain_id = client
        .add_chain(smoldot_light::AddChainConfig {
            specification,
            json_rpc: smoldot_light::AddChainConfigJsonRpc::Disabled,
            max_pending_transactions: NonZero::<u32>::new(64).unwrap(),
            potential_relay_chains: iter::empty(),
            database_content: "",
            user_data: (),
            statement_protocol_config: None,
        })
        .unwrap()
        .chain_id;

    let mut lifecycle = client.lifecycle_state(chain_id);

    smol::block_on(async move {
        // Wait until the chain has at least one peer.
        loop {
            let state = lifecycle.next().await.unwrap();
            if state.num_peers >= 1 {
                println!("connected to {} peer(s)", state.num_peers);
                break;
            }
        }

        let mut begin = genesis_hash;
        for iteration in 1..=50 {
            println!("request #{iteration} starting at 0x{}", hex::encode(begin));

            let response = match client
                .grandpa_warp_sync_proof(chain_id, begin, 3, Duration::from_secs(24))
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    println!("  error: {error}");
                    smol::Timer::after(Duration::from_secs(2)).await;
                    continue;
                }
            };

            let response = response.decode();
            for fragment in &response.fragments {
                let decoded =
                    header::decode(fragment.scale_encoded_header, block_number_bytes).unwrap();
                println!(
                    "  fragment #{} 0x{}",
                    decoded.number,
                    hex::encode(decoded.hash(block_number_bytes))
                );
            }
            println!("  is_finished = {}", response.is_finished);

            if response.is_finished {
                return;
            }
            match response.fragments.last() {
                Some(fragment) => {
                    begin = header::hash_from_scale_encoded_header(fragment.scale_encoded_header)
                }
                None => {
                    println!("  empty response that isn't finished, stopping");
                    return;
                }
            }
        }

        println!("stopped after 50 requests without is_finished");
    });
}

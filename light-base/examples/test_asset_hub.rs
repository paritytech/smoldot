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

//! Test example that connects to Asset Hub Kusama and verifies:
//! - Blocks arrive approximately every ~2 seconds
//! - Block numbers are sequential (no gaps)
//! - Blocks get finalized via the relay chain

use core::{iter, num::NonZero};
use std::time::Instant;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut client =
        smoldot_light::Client::new(smoldot_light::platform::default::DefaultPlatform::new(
            env!("CARGO_PKG_NAME").into(),
            env!("CARGO_PKG_VERSION").into(),
        ));

    // Add Kusama relay chain.
    let smoldot_light::AddChainSuccess {
        chain_id: kusama_chain_id,
        json_rpc_responses: _,
    } = client
        .add_chain(smoldot_light::AddChainConfig {
            specification: include_str!("../../demo-chain-specs/ksmcc3.json"),
            json_rpc: smoldot_light::AddChainConfigJsonRpc::Disabled,
            potential_relay_chains: iter::empty(),
            database_content: "",
            user_data: (),
        })
        .unwrap();

    // Add Asset Hub Kusama parachain.
    let smoldot_light::AddChainSuccess {
        chain_id: _asset_hub_chain_id,
        json_rpc_responses: asset_hub_json_rpc_responses,
    } = client
        .add_chain(smoldot_light::AddChainConfig {
            specification: include_str!("../../demo-chain-specs/ksmcc3_asset_hub.json"),
            json_rpc: smoldot_light::AddChainConfigJsonRpc::Enabled {
                max_pending_requests: NonZero::<u32>::new(128).unwrap(),
                max_subscriptions: 1024,
            },
            potential_relay_chains: [kusama_chain_id].into_iter(),
            database_content: "",
            user_data: (),
        })
        .unwrap();

    let mut asset_hub_json_rpc_responses = asset_hub_json_rpc_responses.unwrap();

    println!("Connecting to Asset Hub Kusama...");
    println!("[ALL] = chain_subscribeAllHeads, [FIN] = chain_subscribeFinalizedHeads");
    println!("Expecting blocks every ~2s with no gaps.\n");

    // Subscribe to all heads and finalized heads.
    client
        .json_rpc_request(
            r#"{"id":1,"jsonrpc":"2.0","method":"chain_subscribeAllHeads","params":[]}"#,
            _asset_hub_chain_id,
        )
        .unwrap();
    client
        .json_rpc_request(
            r#"{"id":2,"jsonrpc":"2.0","method":"chain_subscribeFinalizedHeads","params":[]}"#,
            _asset_hub_chain_id,
        )
        .unwrap();

    smol::block_on(async move {
        let start = Instant::now();
        let mut last_all_time = start;
        let mut last_all_number: Option<u64> = None;
        let mut last_fin_number: Option<u64> = None;
        let mut all_count: u64 = 0;

        loop {
            let response = asset_hub_json_rpc_responses.next().await.unwrap();
            let now = Instant::now();
            let elapsed = now.duration_since(start).as_secs_f64();

            // Parse the response to extract block number.
            let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

            // Subscription confirmations.
            if parsed.get("id").is_some() {
                println!("[SUB] Confirmed: {response}");
                continue;
            }

            // Extract block number from params.result.number.
            let number_hex = parsed["params"]["result"]["number"]
                .as_str()
                .unwrap_or("0x0");
            let number = u64::from_str_radix(number_hex.trim_start_matches("0x"), 16).unwrap_or(0);

            let _sub_id = parsed["params"]["subscription"].as_str().unwrap_or("");

            // Determine if this is an allHeads or finalizedHeads notification by tracking
            // subscription IDs. The first subscription (id=1) is allHeads.
            // We use a simple heuristic: finalizedHeads numbers lag behind allHeads.
            if let Some(last_fin) = last_fin_number {
                if number <= last_fin || (last_all_number.is_some() && number < last_all_number.unwrap()) {
                    // Finalized head.
                    let jumped = number - last_fin;
                    println!("[FIN] #{number} +{elapsed:.1}s (jumped {jumped} blocks)");
                    last_fin_number = Some(number);
                    continue;
                }
            }

            // Check if this looks like a finalized head notification (first time or
            // same number as what we've seen in allHeads).
            if last_all_number.is_none() && last_fin_number.is_none() {
                // First notification — treat as finalized (the initial finalized block).
                println!("[FIN] #{number} +{elapsed:.1}s (jumped 0 blocks)");
                last_fin_number = Some(number);
                continue;
            }

            // allHeads notification.
            let interval = now.duration_since(last_all_time).as_secs_f64();
            last_all_time = now;
            all_count += 1;

            println!(
                "[ALL] #{number} +{elapsed:.1}s (interval: {interval:.2}s) total={all_count}"
            );

            if let Some(last) = last_all_number {
                if number != last + 1 {
                    println!(
                        "  *** GAP DETECTED: expected #{}, got #{number} ***",
                        last + 1
                    );
                }
            }

            last_all_number = Some(number);

            // Update finalized number tracking: if we haven't seen a finalized head yet
            // that's different from an allHead, initialize it.
            if last_fin_number.is_none() {
                last_fin_number = Some(number.saturating_sub(1));
            }
        }
    });
}

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

//! Reproducer for parachain finality stall bug in smoldot 3.0.0.
//!
//! Connects to Paseo (relay) + Paseo Asset Hub (parachain) and monitors finality
//! on both chains using both the legacy API (`chain_subscribeFinalizedHeads`) and
//! the new API (`chainHead_v1_follow`).
//!
//! Expected bug behavior: relay finalized head advances normally, but parachain
//! finalized head is emitted once at subscription start and never again — even
//! though parachain best head keeps advancing.
//!
//! Run:
//!   cargo run -p smoldot-light --example parachain_finality_repro
//!
//! Verbose smoldot internals:
//!   RUST_LOG=info cargo run -p smoldot-light --example parachain_finality_repro
//!
//! Exits with code 1 if the bug reproduces (parachain finality stalls while relay
//! finalizes and parachain best head advances). Exits 0 if finality is healthy.

use core::{iter, num::NonZero};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures_lite::FutureExt as _;

const TEST_DURATION: Duration = Duration::from_secs(90);
const STALL_THRESHOLD: Duration = Duration::from_secs(30);

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let mut client =
        smoldot_light::Client::new(smoldot_light::platform::default::DefaultPlatform::new(
            env!("CARGO_PKG_NAME").into(),
            env!("CARGO_PKG_VERSION").into(),
        ));

    // --- Add Paseo relay chain ---
    let smoldot_light::AddChainSuccess {
        chain_id: relay_chain_id,
        json_rpc_responses: relay_json_rpc,
    } = client
        .add_chain(smoldot_light::AddChainConfig {
            specification: include_str!("../../demo-chain-specs/paseo.json"),
            json_rpc: smoldot_light::AddChainConfigJsonRpc::Enabled {
                max_pending_requests: NonZero::<u32>::new(128).unwrap(),
                max_subscriptions: 1024,
            },
            potential_relay_chains: iter::empty(),
            database_content: "",
            user_data: (),
            statement_protocol_config: None,
        })
        .unwrap();

    let mut relay_json_rpc = relay_json_rpc.unwrap();

    // --- Add Paseo Asset Hub parachain ---
    let smoldot_light::AddChainSuccess {
        chain_id: para_chain_id,
        json_rpc_responses: para_json_rpc,
    } = client
        .add_chain(smoldot_light::AddChainConfig {
            specification: include_str!("../../demo-chain-specs/asset-hub-paseo.json"),
            json_rpc: smoldot_light::AddChainConfigJsonRpc::Enabled {
                max_pending_requests: NonZero::<u32>::new(128).unwrap(),
                max_subscriptions: 1024,
            },
            potential_relay_chains: [relay_chain_id].into_iter(),
            database_content: "",
            user_data: (),
            statement_protocol_config: None,
        })
        .unwrap();

    let mut para_json_rpc = para_json_rpc.unwrap();

    // --- Send subscriptions ---
    // Relay: legacy best + finalized
    client
        .json_rpc_request(
            r#"{"id":1,"jsonrpc":"2.0","method":"chain_subscribeNewHeads","params":[]}"#,
            relay_chain_id,
        )
        .unwrap();
    client
        .json_rpc_request(
            r#"{"id":2,"jsonrpc":"2.0","method":"chain_subscribeFinalizedHeads","params":[]}"#,
            relay_chain_id,
        )
        .unwrap();

    // Parachain: legacy best + finalized
    client
        .json_rpc_request(
            r#"{"id":1,"jsonrpc":"2.0","method":"chain_subscribeNewHeads","params":[]}"#,
            para_chain_id,
        )
        .unwrap();
    client
        .json_rpc_request(
            r#"{"id":2,"jsonrpc":"2.0","method":"chain_subscribeFinalizedHeads","params":[]}"#,
            para_chain_id,
        )
        .unwrap();
    // Parachain: new API (chainHead_v1_follow)
    client
        .json_rpc_request(
            r#"{"id":3,"jsonrpc":"2.0","method":"chainHead_v1_follow","params":[false]}"#,
            para_chain_id,
        )
        .unwrap();

    println!("=== Parachain Finality Reproducer ===");
    println!("Relay:     Paseo");
    println!("Parachain: Paseo Asset Hub");
    println!("Duration:  {}s", TEST_DURATION.as_secs());
    println!("Stall threshold: {}s", STALL_THRESHOLD.as_secs());
    println!();
    println!("Subscriptions:");
    println!("  Relay:     chain_subscribeNewHeads, chain_subscribeFinalizedHeads");
    println!("  Parachain: chain_subscribeNewHeads, chain_subscribeFinalizedHeads, chainHead_v1_follow");
    println!();
    println!("Waiting for peers and sync...");
    println!();

    smol::block_on(async move {
        let start = Instant::now();

        // Subscription ID -> label mapping, built from confirmation responses.
        // relay uses ids 1,2; para uses ids 1,2,3
        let mut relay_sub_map: HashMap<String, &str> = HashMap::new();
        let mut para_sub_map: HashMap<String, &str> = HashMap::new();

        // Tracking state.
        let mut relay_best: Option<u64> = None;
        let mut relay_fin: Option<u64> = None;
        let mut relay_fin_count: u64 = 0;
        let mut _relay_fin_last_time = start;

        let mut para_best: Option<u64> = None;
        let mut para_fin: Option<u64> = None;
        let mut para_fin_count: u64 = 0;
        let mut para_fin_last_time = start;
        let mut para_best_count: u64 = 0;

        // chainHead_v1_follow tracking.
        let mut follow_initialized = false;
        let mut follow_fin_count: u64 = 0;
        let mut follow_best_count: u64 = 0;

        loop {
            let elapsed = start.elapsed();
            if elapsed >= TEST_DURATION {
                break;
            }

            // Race relay vs para responses, with a timeout for the remaining duration.
            let remaining = TEST_DURATION - elapsed;
            let response = async { Some(("relay", relay_json_rpc.next().await.unwrap())) }
                .or(async { Some(("para", para_json_rpc.next().await.unwrap())) })
                .or(async {
                    smol::Timer::after(remaining).await;
                    None
                })
                .await;

            let (source, response) = match response {
                Some(r) => r,
                None => break, // timeout
            };

            let elapsed_secs = start.elapsed().as_secs_f64();
            let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

            // Handle subscription confirmations.
            if let Some(id) = parsed.get("id").and_then(|v| v.as_u64()) {
                let sub_id = parsed["result"].as_str().unwrap_or("").to_string();
                let label = match (source, id) {
                    ("relay", 1) => "relay_best",
                    ("relay", 2) => "relay_fin",
                    ("para", 1) => "para_best",
                    ("para", 2) => "para_fin",
                    ("para", 3) => "para_follow",
                    _ => "unknown",
                };
                println!("[{elapsed_secs:6.1}s] [SUB] {label} confirmed (sub_id={sub_id})");
                match source {
                    "relay" => { relay_sub_map.insert(sub_id, label); }
                    "para" => { para_sub_map.insert(sub_id, label); }
                    _ => {}
                }
                continue;
            }

            // Handle chainHead_v1_follow events (they come as method calls, not subscription notifications).
            if let Some(method) = parsed.get("method").and_then(|v| v.as_str()) {
                if method == "chainHead_v1_followEvent" && source == "para" {
                    let event = &parsed["params"]["result"];
                    let event_type = event["event"].as_str().unwrap_or("");
                    match event_type {
                        "initialized" => {
                            follow_initialized = true;
                            let hashes = event["finalizedBlockHashes"]
                                .as_array()
                                .map(|a| a.len())
                                .unwrap_or(0);
                            println!(
                                "[{elapsed_secs:6.1}s] [PARA FOLLOW INIT] finalized_hashes={hashes}"
                            );
                        }
                        "bestBlockChanged" => {
                            follow_best_count += 1;
                        }
                        "finalized" => {
                            follow_fin_count += 1;
                            let hashes = event["finalizedBlockHashes"]
                                .as_array()
                                .map(|a| a.len())
                                .unwrap_or(0);
                            println!(
                                "[{elapsed_secs:6.1}s] [PARA FOLLOW FIN] finalized {hashes} blocks (total follow finality events: {follow_fin_count})"
                            );
                        }
                        _ => {} // newBlock, etc — not needed for repro
                    }
                    continue;
                }
            }

            // Handle legacy subscription notifications.
            let sub_id = parsed["params"]["subscription"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let number_hex = parsed["params"]["result"]["number"]
                .as_str()
                .unwrap_or("0x0");
            let number =
                u64::from_str_radix(number_hex.trim_start_matches("0x"), 16).unwrap_or(0);

            let label = match source {
                "relay" => relay_sub_map.get(&sub_id).copied().unwrap_or("relay_?"),
                "para" => para_sub_map.get(&sub_id).copied().unwrap_or("para_?"),
                _ => "?",
            };

            match label {
                "relay_best" => {
                    relay_best = Some(number);
                    // Don't print every relay best — too noisy.
                }
                "relay_fin" => {
                    relay_fin = Some(number);
                    relay_fin_count += 1;
                    _relay_fin_last_time = Instant::now();
                    let lag = relay_best.map(|b| b.saturating_sub(number));
                    println!(
                        "[{elapsed_secs:6.1}s] [RELAY FIN]  #{number} (lag: {} blocks, finality event #{relay_fin_count})",
                        lag.map(|l| l.to_string()).unwrap_or_else(|| "?".into())
                    );
                }
                "para_best" => {
                    para_best = Some(number);
                    para_best_count += 1;
                    let since_fin = para_fin_last_time.elapsed();
                    if para_fin_count > 0 && since_fin >= STALL_THRESHOLD {
                        println!(
                            "[{elapsed_secs:6.1}s] [PARA BEST]  #{number} (best event #{para_best_count})"
                        );
                        println!(
                            "             *** PARA FINALITY STALLED for {:.1}s — last finalized: #{}, gap: {} blocks ***",
                            since_fin.as_secs_f64(),
                            para_fin.unwrap_or(0),
                            number.saturating_sub(para_fin.unwrap_or(0))
                        );
                    } else if para_best_count <= 3 || para_best_count % 10 == 0 {
                        println!(
                            "[{elapsed_secs:6.1}s] [PARA BEST]  #{number} (best event #{para_best_count})"
                        );
                    }
                }
                "para_fin" => {
                    para_fin = Some(number);
                    para_fin_count += 1;
                    para_fin_last_time = Instant::now();
                    let lag = para_best.map(|b| b.saturating_sub(number));
                    println!(
                        "[{elapsed_secs:6.1}s] [PARA FIN]   #{number} (lag: {} blocks, finality event #{para_fin_count})",
                        lag.map(|l| l.to_string()).unwrap_or_else(|| "?".into())
                    );
                    // Print the raw JSON for the first few finalized notifications.
                    if para_fin_count <= 3 {
                        println!("             raw: {response}");
                    }
                }
                _ => {}
            }
        }

        // --- Verdict ---
        println!();
        println!("=== Results after {}s ===", TEST_DURATION.as_secs());
        println!();
        println!("Relay:");
        println!("  Best block:      #{}", relay_best.unwrap_or(0));
        println!("  Finalized block: #{}", relay_fin.unwrap_or(0));
        println!("  Finality events: {relay_fin_count}");
        println!();
        println!("Parachain (legacy API):");
        println!("  Best block:      #{}", para_best.unwrap_or(0));
        println!("  Finalized block: #{}", para_fin.unwrap_or(0));
        println!("  Best events:     {para_best_count}");
        println!("  Finality events: {para_fin_count}");
        println!();
        println!("Parachain (chainHead_v1_follow):");
        println!("  Initialized:     {follow_initialized}");
        println!("  Best events:     {follow_best_count}");
        println!("  Finality events: {follow_fin_count}");
        println!();

        // Determine if the bug reproduced.
        let relay_finalizes = relay_fin_count >= 2;
        // Accept either legacy or follow as proof that the parachain is syncing.
        let para_advances = para_best_count >= 5 || follow_best_count >= 5;
        let para_legacy_stalled = para_fin_count <= 1;
        let para_legacy_dead = para_best_count == 0 && para_fin_count == 0;
        let para_follow_stalled = follow_initialized && follow_fin_count == 0;

        if relay_finalizes && para_advances && (para_legacy_stalled || para_follow_stalled) {
            println!("VERDICT: BUG REPRODUCED");
            println!("  Relay finality is healthy ({relay_fin_count} events).");
            if para_legacy_dead {
                println!(
                    "  Parachain legacy API completely dead (0 best, 0 finalized events)."
                );
                println!(
                    "  Root cause: runtime_service stuck in FinalizedBlockRuntimeUnknown state."
                );
            } else if para_legacy_stalled {
                println!(
                    "  Parachain finalized head (legacy) is FROZEN ({para_fin_count} event — initial only)."
                );
            }
            if para_follow_stalled {
                println!(
                    "  Parachain finalized head (chainHead_v1_follow) is FROZEN ({follow_fin_count} finality events after init)."
                );
            }
            if follow_fin_count >= 1 {
                println!(
                    "  Note: chainHead_v1_follow works ({follow_fin_count} finality, {follow_best_count} best events)."
                );
                println!(
                    "  This confirms the sync layer is healthy — the bug is in the legacy JSON-RPC path."
                );
            }
            std::process::exit(1);
        } else if relay_finalizes && para_advances && para_fin_count >= 2 && follow_fin_count >= 1 {
            println!("VERDICT: HEALTHY — parachain finality is working on both APIs.");
            std::process::exit(0);
        } else if relay_finalizes && follow_fin_count >= 1 && para_fin_count >= 2 {
            println!("VERDICT: HEALTHY — parachain finality is working on both APIs.");
            std::process::exit(0);
        } else {
            println!("VERDICT: INCONCLUSIVE");
            println!("  Could not gather enough data. Network connectivity issues?");
            println!("  relay_fin_count={relay_fin_count}, para_best_count={para_best_count}, para_fin_count={para_fin_count}, follow_best_count={follow_best_count}, follow_fin_count={follow_fin_count}");
            std::process::exit(2);
        }
    });
}

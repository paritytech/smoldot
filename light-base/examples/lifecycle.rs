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

//! Prints the lifecycle state of a relay chain and one of its parachains as it changes, through
//! both the Rust API (`Client::lifecycle_state`) and the `lifecycle_unstable_follow` JSON-RPC
//! subscription. See <https://github.com/paritytech/smoldot/issues/3301>.
//!
//! Run with:
//!
//! ```text
//! cargo run -p smoldot-light --features std --example lifecycle
//! ```
//!
//! Environment variables: `RELAY` and `PARA` select chain specifications from
//! `demo-chain-specs/` (default: Kusama and Kusama Asset Hub), `SECS` sets how long to watch
//! (default: 150).

use core::{iter, num::NonZero, time::Duration};
use futures_lite::FutureExt as _;
use std::time::Instant;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let relay_spec = std::env::var("RELAY").unwrap_or_else(|_| "ksmcc3.json".into());
    let para_spec = std::env::var("PARA").unwrap_or_else(|_| "ksmcc3_asset_hub.json".into());
    let secs: u64 = std::env::var("SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150);
    let specs_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../demo-chain-specs/");
    let relay_spec = std::fs::read_to_string(format!("{specs_dir}{relay_spec}")).unwrap();
    let para_spec = std::fs::read_to_string(format!("{specs_dir}{para_spec}")).unwrap();

    let mut client =
        smoldot_light::Client::new(smoldot_light::platform::default::DefaultPlatform::new(
            env!("CARGO_PKG_NAME").into(),
            env!("CARGO_PKG_VERSION").into(),
        ));
    let rpc = smoldot_light::AddChainConfigJsonRpc::Enabled {
        max_pending_requests: NonZero::<u32>::new(128).unwrap(),
        max_subscriptions: 1024,
    };

    let smoldot_light::AddChainSuccess {
        chain_id: relay,
        json_rpc_responses: relay_rx,
    } = client
        .add_chain(smoldot_light::AddChainConfig {
            specification: &relay_spec,
            json_rpc: rpc.clone(),
            potential_relay_chains: iter::empty(),
            database_content: "",
            user_data: (),
            statement_protocol_config: None,
        })
        .unwrap();
    let mut relay_rx = relay_rx.unwrap();

    let smoldot_light::AddChainSuccess {
        chain_id: para,
        json_rpc_responses: para_rx,
    } = client
        .add_chain(smoldot_light::AddChainConfig {
            specification: &para_spec,
            json_rpc: rpc,
            database_content: "",
            user_data: (),
            potential_relay_chains: [relay].into_iter(),
            statement_protocol_config: None,
        })
        .unwrap();
    let mut para_rx = para_rx.unwrap();

    // Rust API on the relay chain.
    let mut rust_sub = client.lifecycle_state(relay);

    // JSON-RPC subscription on both chains.
    for chain in [relay, para] {
        client
            .json_rpc_request(
                r#"{"id":1,"jsonrpc":"2.0","method":"lifecycle_unstable_follow","params":[]}"#,
                chain,
            )
            .unwrap();
    }

    let start = Instant::now();
    smol::block_on(async move {
        let deadline = smol::Timer::after(Duration::from_secs(secs));
        let watch = async {
            loop {
                let line = async { format!("relay rpc:  {}", relay_rx.next().await.unwrap()) }
                    .or(async { format!("para rpc:   {}", para_rx.next().await.unwrap()) })
                    .or(async {
                        match rust_sub.next().await {
                            Some(s) => format!("relay rust: {s:?}"),
                            None => "relay rust: ended".to_string(),
                        }
                    })
                    .await;
                println!("[{:>6.1}s] {line}", start.elapsed().as_secs_f32());
            }
        };
        watch
            .or(async {
                deadline.await;
            })
            .await;
    });
    println!("done");
}

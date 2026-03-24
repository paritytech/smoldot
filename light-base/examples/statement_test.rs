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

//! Example demonstrating how to use the statement store protocol with smoldot.

use core::{iter, num::NonZero};
use std::env;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Read chain specs from environment variables
    let relay_chain_spec = env::var("RELAY_CHAIN_SPEC")
        .map(|path| std::fs::read_to_string(path).expect("Failed to read relay chain spec"))
        .unwrap_or_else(|_| {
            eprintln!("Error: RELAY_CHAIN_SPEC environment variable not set");
            std::process::exit(1);
        });

    let para_chain_spec = env::var("PARA_CHAIN_SPEC")
        .map(|path| std::fs::read_to_string(path).expect("Failed to read para chain spec"))
        .ok();

    smol::block_on(async move {
        // Initialize the client
        let mut client =
            smoldot_light::Client::new(smoldot_light::platform::default::DefaultPlatform::new(
                env!("CARGO_PKG_NAME").into(),
                env!("CARGO_PKG_VERSION").into(),
            ));

        // Add relay chain with statement protocol enabled
        let smoldot_light::AddChainSuccess {
            chain_id: relay_chain_id,
            json_rpc_responses: _,
        } = client
            .add_chain(smoldot_light::AddChainConfig {
                specification: &relay_chain_spec,
                json_rpc: smoldot_light::AddChainConfigJsonRpc::Enabled {
                    max_pending_requests: NonZero::<u32>::new(128).unwrap(),
                    max_subscriptions: 1024,
                },
                potential_relay_chains: iter::empty(),
                database_content: "",
                user_data: (),
                statement_protocol_config: Some(
                    smoldot_light::network_service::StatementProtocolConfig::default(),
                ),
            })
            .unwrap();

        log::info!("Relay chain added");

        // Add parachain if chain spec provided
        if let Some(para_spec) = para_chain_spec {
            let smoldot_light::AddChainSuccess {
                chain_id: parachain_id,
                json_rpc_responses,
            } = client
                .add_chain(smoldot_light::AddChainConfig {
                    specification: &para_spec,
                    json_rpc: smoldot_light::AddChainConfigJsonRpc::Enabled {
                        max_pending_requests: NonZero::<u32>::new(128).unwrap(),
                        max_subscriptions: 1024,
                    },
                    potential_relay_chains: [relay_chain_id].into_iter(),
                    database_content: "",
                    user_data: (),
                    statement_protocol_config: Some(
                        smoldot_light::network_service::StatementProtocolConfig::default(),
                    ),
                })
                .unwrap();

            log::info!("Parachain added with statement protocol enabled");

            client
                .json_rpc_request(
                    r#"{"id":1,"jsonrpc":"2.0","method":"statement_unstable_subscribe","params":[{"type":"any"}]}"#,
                    parachain_id,
                )
                .unwrap();
            log::info!("Listening for statements via JSON-RPC subscription...");

            let mut responses = json_rpc_responses.unwrap();
            loop {
                let response: String = responses.next().await.unwrap();
                log::info!("Statement JSON-RPC response: {response}");
            }
        }
    });
}

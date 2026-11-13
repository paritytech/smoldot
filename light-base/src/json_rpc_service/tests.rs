// Smoldot
// Copyright (C) 2026  Parity Technologies (UK) Ltd.
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

//! Tests of the JSON-RPC service, through a [`Client`] without peers: its chain specification has
//! no boot node, so nothing is ever dialed, and a request that needs the network fails at once.
//! That is enough to take an operation from its start to its end.

use crate::{
    AddChainConfig, AddChainConfigJsonRpc, AddChainSuccess, ChainId, Client, JsonRpcResponses,
    platform::default::DefaultPlatform,
};

use alloc::{format, string::ToString as _, sync::Arc, vec::Vec};
use core::{iter, num::NonZero, time::Duration};
use futures_lite::FutureExt as _;

/// A client with a relay chain and no peer, and the chain's JSON-RPC responses.
fn client_without_peers() -> (
    Client<Arc<DefaultPlatform>>,
    ChainId,
    JsonRpcResponses<Arc<DefaultPlatform>>,
) {
    let mut specification: serde_json::Value =
        serde_json::from_str(include_str!("../../../demo-chain-specs/paseo.json")).unwrap();
    specification["bootNodes"] = serde_json::Value::Array(Vec::new());

    let mut client = Client::new(DefaultPlatform::new("smoldot-test".into(), "0".into()));
    let AddChainSuccess {
        chain_id,
        json_rpc_responses,
    } = client
        .add_chain(AddChainConfig {
            user_data: (),
            specification: &specification.to_string(),
            database_content: "",
            potential_relay_chains: iter::empty(),
            json_rpc: AddChainConfigJsonRpc::Enabled {
                max_pending_requests: NonZero::<u32>::new(128).unwrap(),
                max_subscriptions: 1024,
            },
            statement_protocol_config: None,
            max_pending_transactions: NonZero::<u32>::new(64).unwrap(),
        })
        .unwrap();

    (client, chain_id, json_rpc_responses.unwrap())
}

async fn next_message(responses: &mut JsonRpcResponses<Arc<DefaultPlatform>>) -> serde_json::Value {
    serde_json::from_str(&responses.next().await.unwrap()).unwrap()
}

/// A `chainHead_v1_storage` call takes one of the follow subscription's 32 operation slots for
/// each item it starts, and must give all of them back when it ends. Otherwise the next call of
/// 32 items can't start them all.
///
/// The subscription's first event takes 30 seconds: without a peer, the sync service serves its
/// subscriptions only once it has decided how to sync, at `MODE_DECISION_TIMEOUT`.
#[test]
fn chain_head_storage_gives_back_every_slot() {
    smol::block_on(
        async {
            let (mut client, chain_id, mut responses) = client_without_peers();

            client
                .json_rpc_request(
                    r#"{"jsonrpc":"2.0","id":1,"method":"chainHead_v1_follow","params":[false]}"#,
                    chain_id,
                )
                .unwrap();
            let (mut subscription, mut finalized) = (None, None);
            while subscription.is_none() || finalized.is_none() {
                let message = next_message(&mut responses).await;
                if message["id"] == 1 {
                    subscription = Some(message["result"].clone());
                } else if message["params"]["result"]["event"] == "initialized" {
                    finalized = message["params"]["result"]["finalizedBlockHashes"]
                        .as_array()
                        .and_then(|hashes| hashes.last())
                        .cloned();
                }
            }

            let items = (0..32)
                .map(|n| serde_json::json!({ "key": format!("0x{n:02x}"), "type": "value" }))
                .collect::<Vec<_>>();
            for id in 2..5 {
                client
                    .json_rpc_request(
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "method": "chainHead_v1_storage",
                            "params": [subscription, finalized, items, null],
                        })
                        .to_string(),
                        chain_id,
                    )
                    .unwrap();

                // Every item starts...
                let operation_id = loop {
                    let message = next_message(&mut responses).await;
                    if message["id"] == id {
                        assert_eq!(message["result"]["result"], "started", "{message}");
                        assert_eq!(message["result"]["discardedItems"], 0, "{message}");
                        break message["result"]["operationId"].clone();
                    }
                };

                // ...and the operation ends: without a peer to ask, it fails at once.
                loop {
                    let message = next_message(&mut responses).await;
                    let event = &message["params"]["result"];
                    if event["operationId"] == operation_id
                        && matches!(
                            event["event"].as_str(),
                            Some(
                                "operationError" | "operationInaccessible" | "operationStorageDone"
                            )
                        )
                    {
                        break;
                    }
                }
            }
        }
        .or(async {
            smol::Timer::after(Duration::from_secs(60)).await;
            panic!("timeout")
        }),
    );
}

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

use smoldot::json_rpc;
use std::sync::Arc;

async fn start_client() -> smoldot_full_node::Client {
    smoldot_full_node::start(smoldot_full_node::Config {
        chain: smoldot_full_node::ChainConfig {
            chain_spec: (&include_bytes!("./substrate-node-template.json")[..]).into(),
            additional_bootnodes: Vec::new(),
            keystore_memory: vec![],
            sqlite_database_path: None,
            sqlite_cache_size: 256 * 1024 * 1024,
            keystore_path: None,
            json_rpc_listen: None,
        },
        relay_chain: None,
        libp2p_key: Box::new([0; 32]),
        listen_addresses: Vec::new(),
        tasks_executor: Arc::new(|task| smol::spawn(task).detach()),
        log_callback: Arc::new(move |_, _| {}),
        jaeger_agent: None,
    })
    .await
    .unwrap()
}

#[test]
fn chain_spec_v1_chain_name() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_chainName","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "Local Testnet"
        );
    });
}

#[test]
fn chain_spec_v1_genesis_hash() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_genesisHash","params":[]}"#
                .to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"
        );
    });
}

#[test]
fn chain_spec_v1_properties() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chainSpec_v1_properties","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(result_json, r#"{"tokenDecimals": 15}"#);
    });
}

#[test]
fn chain_get_block_hash() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"
        );

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[10000]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(result_json, "null");

        // TODO: test for a non-zero block?
    });
}

#[test]
fn chain_get_header() {
    smol::block_on(async move {
        let client = start_client().await;

        // Test the current best block.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chain_getHeader","params":[]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded_header =
            serde_json::from_str::<json_rpc::methods::Header>(result_json).unwrap();
        assert_eq!(
            decoded_header.parent_hash.0,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );
        assert_eq!(decoded_header.number, 0);
        assert_eq!(
            decoded_header.state_root.0,
            [
                40, 162, 219, 5, 170, 164, 232, 78, 136, 198, 190, 40, 202, 73, 212, 91, 4, 51,
                248, 171, 238, 66, 27, 9, 45, 250, 15, 77, 216, 87, 135, 166
            ]
        );
        assert!(decoded_header.digest.logs.is_empty());

        // Test passing an explicit block hash.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chain_getHeader","params":["0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded_header =
            serde_json::from_str::<json_rpc::methods::Header>(result_json).unwrap();
        assert_eq!(
            decoded_header.parent_hash.0,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );
        assert_eq!(decoded_header.number, 0);
        assert_eq!(
            decoded_header.state_root.0,
            [
                40, 162, 219, 5, 170, 164, 232, 78, 136, 198, 190, 40, 202, 73, 212, 91, 4, 51,
                248, 171, 238, 66, 27, 9, 45, 250, 15, 77, 216, 87, 135, 166
            ]
        );
        assert!(decoded_header.digest.logs.is_empty());

        // Test for unknown block.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"chain_getHeader","params":["0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(result_json, "null");
    });
}

#[test]
fn state_get_metadata() {
    smol::block_on(async move {
        let client = start_client().await;

        // Query the metadata of the genesis.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getMetadata","params":["0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            include_str!("./substrate-node-template-metadata.hex").trim()
        );

        // TOOD: there are no tests for the corner cases of state_getMetadata because it's unclear how the function is supposed to behave at all
    });
}

#[test]
fn state_get_runtime_version() {
    smol::block_on(async move {
        let client = start_client().await;

        // Query the runtime of the genesis.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getRuntimeVersion","params":["0x6bf30d04495c16ef053de4ac74eac35dfd6473e4907810f450bea1b976ac518f"]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded =
            serde_json::from_str::<json_rpc::methods::RuntimeVersion>(result_json).unwrap();
        assert_eq!(decoded.impl_name, "node-template");
        assert_eq!(decoded.spec_version, 100);
        assert_eq!(decoded.apis.len(), 10);

        // TOOD: there are no tests for the corner cases of state_getRuntimeVersion because it's unclear how the function is supposed to behave at all
    });
}

#[test]
fn state_get_keys_paged_basic() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getKeysPaged","params":["0x", 10]}"#
                .to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded = serde_json::from_str::<Vec<json_rpc::methods::HexString>>(result_json)
            .unwrap()
            .into_iter()
            .map(|v| v.0)
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            &[
                &[
                    23, 126, 104, 87, 251, 29, 14, 64, 147, 118, 18, 47, 238, 58, 212, 248, 78,
                    123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41
                ][..],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 78,
                    123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 86,
                    132, 160, 34, 163, 77, 216, 191, 162, 186, 175, 68, 241, 114, 183, 16
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 138,
                    66, 243, 51, 35, 203, 92, 237, 59, 68, 221, 130, 95, 218, 159, 204
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 164,
                    71, 4, 181, 104, 210, 22, 103, 53, 106, 90, 5, 12, 17, 135, 70, 180, 222, 242,
                    92, 253, 166, 239, 58, 0, 0, 0, 0
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 167,
                    253, 108, 40, 131, 107, 154, 40, 82, 45, 201, 36, 17, 12, 244, 57
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 185,
                    157, 136, 14, 198, 129, 121, 156, 12, 243, 14, 136, 134, 55, 29, 169, 0, 124,
                    188, 18, 112, 181, 176, 145, 117, 143, 156, 66, 245, 145, 91, 62, 138, 197,
                    158, 17, 150, 58, 241, 145, 116, 208, 185, 77, 93, 120, 4, 28, 35, 63, 85, 210,
                    225, 147, 36, 102, 91, 175, 223, 182, 41, 37, 175, 45
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 185,
                    157, 136, 14, 198, 129, 121, 156, 12, 243, 14, 136, 134, 55, 29, 169, 35, 160,
                    92, 171, 246, 211, 189, 231, 202, 62, 240, 209, 21, 150, 181, 97, 28, 189, 45,
                    67, 83, 10, 68, 112, 90, 208, 136, 175, 49, 62, 24, 248, 11, 83, 239, 22, 179,
                    97, 119, 205, 75, 119, 184, 70, 242, 165, 240, 124
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 185,
                    157, 136, 14, 198, 129, 121, 156, 12, 243, 14, 136, 134, 55, 29, 169, 50, 165,
                    147, 95, 110, 220, 97, 122, 225, 120, 254, 249, 235, 30, 33, 31, 190, 93, 219,
                    21, 121, 183, 46, 132, 82, 79, 194, 158, 120, 96, 158, 60, 175, 66, 232, 90,
                    161, 24, 235, 254, 11, 10, 212, 4, 181, 189, 210, 95
                ],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 185,
                    157, 136, 14, 198, 129, 121, 156, 12, 243, 14, 136, 134, 55, 29, 169, 79, 154,
                    234, 26, 250, 121, 18, 101, 250, 227, 89, 39, 43, 173, 193, 207, 142, 175, 4,
                    21, 22, 135, 115, 99, 38, 201, 254, 161, 126, 37, 252, 82, 135, 97, 54, 147,
                    201, 18, 144, 156, 178, 38, 170, 71, 148, 242, 106, 72
                ]
            ]
        );
    });
}

#[test]
fn state_get_keys_paged_prefix_works() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getKeysPaged","params":["0x26aa394e", 2]}"#
                .to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded = serde_json::from_str::<Vec<json_rpc::methods::HexString>>(result_json)
            .unwrap()
            .into_iter()
            .map(|v| v.0)
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            &[
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 78,
                    123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41
                ][..],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 86,
                    132, 160, 34, 163, 77, 216, 191, 162, 186, 175, 68, 241, 114, 183, 16
                ]
            ]
        );
    });
}

#[test]
fn state_get_keys_paged_start_key_exact_match() {
    smol::block_on(async move {
        let client = start_client().await;

        // This test checks whether the start key is included in the results on an exact match.
        // `0x26aa394eea5630e07c48ae0c9558cef7` is equal to `[38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247]`.

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getKeysPaged","params":["0x", 2, "0x26aa394eea5630e07c48ae0c9558cef7"]}"#
                .to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded = serde_json::from_str::<Vec<json_rpc::methods::HexString>>(result_json)
            .unwrap()
            .into_iter()
            .map(|v| v.0)
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            &[
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 78,
                    123, 144, 18, 9, 107, 65, 196, 235, 58, 175, 148, 127, 110, 164, 41
                ][..],
                &[
                    38, 170, 57, 78, 234, 86, 48, 224, 124, 72, 174, 12, 149, 88, 206, 247, 86,
                    132, 160, 34, 163, 77, 216, 191, 162, 186, 175, 68, 241, 114, 183, 16
                ]
            ]
        );
    });
}

#[test]
fn state_get_keys_paged_count_overflow() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getKeysPaged","params":["0x", 1000]}"#
                .to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        assert!(matches!(
            json_rpc::parse::parse_response(&response_raw).unwrap(),
            json_rpc::parse::Response::Success { .. }
        ));

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":2,"method":"state_getKeysPaged","params":["0x", 1001]}"#
                .to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        assert!(matches!(
            json_rpc::parse::parse_response(&response_raw).unwrap(),
            json_rpc::parse::Response::Error {
                error_code: -32602, // Invalid parameter error code.
                ..
            }
        ));
    });
}

#[test]
fn state_get_keys_paged_unknown_block() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"state_getKeysPaged","params":["0x", 10, "0x", "0x0000000000000000000000000000000000000000000000000000000000000000"]}"#
                .to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        assert!(matches!(
            json_rpc::parse::parse_response(&response_raw).unwrap(),
            json_rpc::parse::Response::Error {
                error_code: -32602, // Invalid parameter error code.
                ..
            }
        ));
    });
}

#[test]
fn system_chain() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_chain","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "Local Testnet"
        );
    });
}

#[test]
fn system_chain_type() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_chainType","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "Local"
        );
    });
}

#[test]
fn system_health() {
    smol::block_on(async move {
        let client = start_client().await;

        // Query the runtime of the genesis.
        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}"#.to_owned(),
        );
        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        let decoded = serde_json::from_str::<json_rpc::methods::SystemHealth>(result_json).unwrap();
        assert_eq!(decoded.peers, 0);
        assert_eq!(decoded.should_have_peers, true);
    });
}

#[test]
fn system_local_peer_id() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_localPeerId","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        );
    });
}

#[test]
fn system_name() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<String>(result_json).unwrap(),
            "smoldot-full-node"
        );
    });
}

#[test]
fn system_properties() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_properties","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        let (_, result_json) = json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
        assert_eq!(result_json, r#"{"tokenDecimals": 15}"#);
    });
}

#[test]
fn system_version() {
    smol::block_on(async move {
        let client = start_client().await;

        client.send_json_rpc_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"system_version","params":[]}"#.to_owned(),
        );

        let response_raw = client.next_json_rpc_response().await;
        // Note: we don't check the actual result, as the version changes pretty often.
        json_rpc::parse::parse_response(&response_raw)
            .unwrap()
            .into_success()
            .unwrap();
    });
}

// TODO: add tests for `chain_subscribeAllHeads`
// TODO: add tests for `chain_subscribeFinalizedHeads`
// TODO: add tests for `chain_subscribeNewHeads`
// TODO: add tests for `state_queryStorageAt`

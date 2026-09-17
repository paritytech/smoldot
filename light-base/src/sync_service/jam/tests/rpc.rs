// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The JSON-RPC methods of a JAM chain, through the real frontend.

use super::*;

// Mock only the sync/RPC boundary so snapshot forks can be tested without
// constructing or bypassing consensus verification. The RPC frontend is real.
fn rpc_snapshot(
    blocks: Vec<BlockNotification>,
) -> (
    crate::json_rpc_service::Frontend<FakePlatform>,
    async_channel::Sender<Notification>,
    Vec<u8>,
) {
    rpc_snapshot_with(blocks, 2)
}

fn rpc_snapshot_with(
    blocks: Vec<BlockNotification>,
    max_subscriptions: u32,
) -> (
    crate::json_rpc_service::Frontend<FakePlatform>,
    async_channel::Sender<Notification>,
    Vec<u8>,
) {
    let platform = platform(Control::default());
    let root = header_bytes(0);
    let (notifications, new_blocks) = async_channel::bounded(16);
    let (to_background, requests) = async_channel::bounded(16);
    let sync_service = Arc::new(JamSyncService { to_background });
    platform.spawn_task("rpc-snapshot-test".into(), {
        let root = root.clone();
        async move {
            while let Ok(request) = requests.recv().await {
                assert!(!request.runtime_interest);
                let _ = request.send_back.send(SubscribeAll {
                    finalized_block_scale_encoded_header: root.clone(),
                    finalized_block_runtime: None,
                    non_finalized_blocks_ancestry_order: blocks.clone(),
                    new_blocks: new_blocks.clone(),
                });
            }
        }
    });
    let frontend = crate::json_rpc_service::service_jam(crate::json_rpc_service::JamConfig {
        platform,
        log_name: "snapshot-test".into(),
        sync_service,
        max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
        max_subscriptions,
        chain_name: "snapshot".into(),
        genesis_block_hash: [7; 32],
    });
    (frontend, notifications, root)
}

async fn rpc_message(frontend: &crate::json_rpc_service::Frontend<FakePlatform>) -> Value {
    let text = future::or(frontend.next_json_rpc_response(), async {
        smol::Timer::after(Duration::from_secs(3)).await;
        panic!("RPC message timed out");
    })
    .await;
    serde_json::from_str(&text).unwrap()
}

async fn rpc_call(
    frontend: &crate::json_rpc_service::Frontend<FakePlatform>,
    method: &str,
    params: Value,
) -> Value {
    frontend
        .queue_rpc_request(
            json!({"jsonrpc":"2.0", "id":7, "method":method, "params":params}).to_string(),
        )
        .unwrap();
    let reply = rpc_message(frontend).await;
    // A request after snapshot delivery also detects extra snapshot notifications.
    assert_eq!(reply["id"], 7, "unexpected notification: {reply}");
    reply
}

fn rpc_hash(bytes: &[u8]) -> String {
    prefixed(blake2b_256(bytes))
}

async fn rpc_follow_snapshot(
    frontend: &crate::json_rpc_service::Frontend<FakePlatform>,
    root: &[u8],
    blocks: &[BlockNotification],
    best: &[u8],
) -> String {
    let reply = rpc_call(frontend, "jamHead_unstable_follow", json!([])).await;
    let id = reply["result"].as_str().unwrap().to_owned();
    let initialized = rpc_message(frontend).await;
    assert_eq!(initialized["params"]["subscription"], id);
    assert_eq!(
        initialized["params"]["result"],
        json!({"event":"initialized", "finalizedBlockHashes":[rpc_hash(root)]})
    );
    for block in blocks {
        let event = rpc_message(frontend).await;
        assert_eq!(event["params"]["subscription"], id);
        assert_eq!(event["params"]["result"]["event"], "newBlock");
        assert_eq!(
            event["params"]["result"]["blockHash"],
            rpc_hash(&block.scale_encoded_header)
        );
        assert_eq!(
            event["params"]["result"]["parentBlockHash"],
            prefixed(block.parent_hash)
        );
        assert_eq!(
            event["params"]["result"]["slot"],
            smoldot::jam::codec::header_slot(&block.scale_encoded_header).unwrap()
        );
    }
    let best_event = rpc_message(frontend).await;
    assert_eq!(best_event["params"]["subscription"], id);
    assert_eq!(
        best_event["params"]["result"],
        json!({"event":"bestBlockChanged", "bestBlockHash":rpc_hash(best)})
    );
    id
}

#[test]
fn jam_rpc_root_only_snapshot_reports_best_once_and_keeps_anchor_pinned() {
    smol::block_on(async {
        let (frontend, _notifications, root) = rpc_snapshot(Vec::new());
        let id = rpc_follow_snapshot(&frontend, &root, &[], &root).await;
        let reply = rpc_call(
            &frontend,
            "jamHead_unstable_header",
            json!([id, rpc_hash(&root)]),
        )
        .await;
        assert_eq!(reply["result"], prefixed(&root));
    });
}

fn rpc_large_snapshot_blocks() -> Vec<BlockNotification> {
    let mut parent_hash = blake2b_256(&header_bytes(0));
    (1u32..=600)
        .map(|number| {
            let block = BlockNotification {
                is_new_best: number == 600,
                scale_encoded_header: header_bytes(number),
                parent_hash,
            };
            parent_hash = blake2b_256(&block.scale_encoded_header);
            block
        })
        .collect()
}

#[test]
fn jam_rpc_large_snapshot_initializes_then_excess_finality_stops_follow() {
    smol::block_on(async {
        let blocks = rpc_large_snapshot_blocks();
        let best = &blocks.last().unwrap().scale_encoded_header;
        let (frontend, notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, best).await;
        for bytes in core::iter::once(&root).chain(blocks.iter().map(|b| &b.scale_encoded_header)) {
            assert_eq!(
                rpc_call(
                    &frontend,
                    "jamHead_unstable_header",
                    json!([id, rpc_hash(bytes)])
                )
                .await["result"],
                prefixed(bytes)
            );
        }
        notifications
            .try_send(Notification::Finalized {
                finalized_blocks_hashes: blocks
                    .iter()
                    .map(|block| blake2b_256(&block.scale_encoded_header))
                    .collect(),
                best_block_hash_if_changed: Some(blake2b_256(best)),
                pruned_blocks: Vec::new(),
            })
            .unwrap();
        // Rejection must emit only stop, not bestBlockChanged or finalized first.
        let stopped = rpc_message(&frontend).await;
        assert_eq!(stopped["params"]["subscription"], id);
        assert_eq!(stopped["params"]["result"], json!({"event":"stop"}));
        for bytes in [&root, best] {
            assert_eq!(
                rpc_call(
                    &frontend,
                    "jamHead_unstable_header",
                    json!([id, rpc_hash(bytes)])
                )
                .await
                .get("result"),
                Some(&Value::Null)
            );
        }
    });
}

#[test]
fn jam_rpc_unpin_refunds_finalized_budget_for_later_finality() {
    smol::block_on(async {
        let blocks = rpc_large_snapshot_blocks();
        let best = &blocks.last().unwrap().scale_encoded_header;
        let (frontend, notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, best).await;
        for (index, batch) in blocks.chunks(300).enumerate() {
            notifications
                .try_send(Notification::Finalized {
                    finalized_blocks_hashes: batch
                        .iter()
                        .map(|block| blake2b_256(&block.scale_encoded_header))
                        .collect(),
                    best_block_hash_if_changed: None,
                    pruned_blocks: Vec::new(),
                })
                .unwrap();
            let finalized = rpc_message(&frontend).await;
            assert_eq!(finalized["params"]["subscription"], id);
            assert_eq!(
                finalized["params"]["result"],
                json!({
                    "event":"finalized",
                    "finalizedBlockHashes":batch.iter().map(|b| rpc_hash(&b.scale_encoded_header)).collect::<Vec<_>>(),
                    "prunedBlockHashes":[],
                })
            );
            if index == 0 {
                let unpinned: Vec<_> = blocks[..100]
                    .iter()
                    .map(|block| rpc_hash(&block.scale_encoded_header))
                    .collect();
                assert_eq!(
                    rpc_call(&frontend, "jamHead_unstable_unpin", json!([id, unpinned]))
                        .await
                        .get("result"),
                    Some(&Value::Null)
                );
                for hash in unpinned {
                    assert_eq!(
                        rpc_call(&frontend, "jamHead_unstable_header", json!([id, hash])).await["error"]
                            ["code"],
                        -32801
                    );
                }
            }
        }
        // Without the 100 refunds, the second charge of 300 would stop this follow.
        for bytes in core::iter::once(&root).chain(
            blocks[100..]
                .iter()
                .map(|block| &block.scale_encoded_header),
        ) {
            assert_eq!(
                rpc_call(
                    &frontend,
                    "jamHead_unstable_header",
                    json!([id, rpc_hash(bytes)])
                )
                .await["result"],
                prefixed(bytes)
            );
        }
    });
}

#[test]
fn jam_rpc_fork_snapshot_reports_all_blocks_before_best_and_preserves_live_order() {
    smol::block_on(async {
        let blocks = vec![
            notification(1, 0, true),
            notification(2, 0, false),
            notification(3, 2, false),
        ];
        let (frontend, notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, &header_bytes(1)).await;
        for block in &blocks {
            let reply = rpc_call(
                &frontend,
                "jamHead_unstable_header",
                json!([id, rpc_hash(&block.scale_encoded_header)]),
            )
            .await;
            assert_eq!(reply["result"], prefixed(&block.scale_encoded_header));
        }
        notifications
            .try_send(Notification::Block(notification(4, 3, true)))
            .unwrap();
        let live_block = rpc_message(&frontend).await;
        assert_eq!(
            live_block["params"]["result"],
            json!({"event":"newBlock", "blockHash":rpc_hash(&header_bytes(4)), "parentBlockHash":rpc_hash(&header_bytes(3)), "slot":4})
        );
        assert_eq!(
            rpc_message(&frontend).await["params"]["result"],
            json!({"event":"bestBlockChanged", "bestBlockHash":rpc_hash(&header_bytes(4))})
        );
        assert_eq!(
            rpc_call(
                &frontend,
                "jamHead_unstable_header",
                json!([id, rpc_hash(&header_bytes(4))])
            )
            .await["result"],
            prefixed(header_bytes(4))
        );
    });
}

#[test]
fn jam_rpc_unpin_unknown_and_already_unpinned_are_32801_and_batches_are_atomic() {
    smol::block_on(async {
        let blocks = vec![notification(1, 0, true)];
        let (frontend, _notifications, root) = rpc_snapshot(blocks.clone());
        let id = rpc_follow_snapshot(&frontend, &root, &blocks, &header_bytes(1)).await;
        let known = rpc_hash(&header_bytes(1));
        let unknown = rpc_hash(&[99]);
        for hashes in [json!(unknown), json!([known, unknown])] {
            assert_eq!(
                rpc_call(&frontend, "jamHead_unstable_unpin", json!([id, hashes])).await["error"]["code"],
                -32801
            );
            assert_eq!(
                rpc_call(&frontend, "jamHead_unstable_header", json!([id, known])).await["result"],
                prefixed(header_bytes(1))
            );
        }
        assert_eq!(
            rpc_call(
                &frontend,
                "jamHead_unstable_unpin",
                json!([id, [known, known]])
            )
            .await["error"]["code"],
            -32804
        );
        assert_eq!(
            rpc_call(&frontend, "jamHead_unstable_header", json!([id, known])).await["result"],
            prefixed(header_bytes(1))
        );
        assert_eq!(
            rpc_call(&frontend, "jamHead_unstable_unpin", json!([id, known]))
                .await
                .get("result"),
            Some(&Value::Null)
        );
        for hashes in [json!(known), json!([rpc_hash(&root), known])] {
            assert_eq!(
                rpc_call(&frontend, "jamHead_unstable_unpin", json!([id, hashes])).await["error"]["code"],
                -32801
            );
            assert_eq!(
                rpc_call(
                    &frontend,
                    "jamHead_unstable_header",
                    json!([id, rpc_hash(&root)])
                )
                .await["result"],
                prefixed(header_bytes(0))
            );
        }
        assert_eq!(
            rpc_call(&frontend, "jamHead_unstable_unpin", json!([id, 42])).await["error"]["code"],
            -32602
        );
        assert_eq!(
            rpc_call(
                &frontend,
                "jamHead_unstable_unpin",
                json!(["unknown-subscription", unknown])
            )
            .await
            .get("result"),
            Some(&Value::Null)
        );
        assert_eq!(
            rpc_call(&frontend, "jamHead_unstable_unfollow", json!([id]))
                .await
                .get("result"),
            Some(&Value::Null)
        );
        assert_eq!(
            rpc_call(&frontend, "jamHead_unstable_unpin", json!([id, unknown]))
                .await
                .get("result"),
            Some(&Value::Null)
        );
    });
}

#[test]
fn jam_rpc_answers_its_methods_and_nothing_else() {
    smol::block_on(async {
        let (frontend, _notifications, root) = rpc_snapshot_with(Vec::new(), 3);
        let methods = json!([
            "chainSpec_v1_chainName",
            "chainSpec_v1_genesisHash",
            "chainSpec_v1_properties",
            "jamHead_unstable_follow",
            "jamHead_unstable_header",
            "jamHead_unstable_unfollow",
            "jamHead_unstable_unpin",
            "rpc_methods",
        ]);
        assert_eq!(
            rpc_call(&frontend, "rpc_methods", json!([])).await["result"],
            json!({ "methods": methods })
        );
        for (method, result) in [
            ("chainSpec_v1_chainName", json!("snapshot")),
            ("chainSpec_v1_genesisHash", json!(prefixed([7; 32]))),
            ("chainSpec_v1_properties", json!({})),
        ] {
            assert_eq!(
                rpc_call(&frontend, method, json!([])).await["result"],
                result
            );
        }
        // Up to the configured maximum of follows, each answering the group.
        for _ in 0..3 {
            let id = rpc_follow_snapshot(&frontend, &root, &[], &root).await;
            let hash = rpc_hash(&root);
            assert_eq!(
                rpc_call(&frontend, "jamHead_unstable_header", json!([id, hash])).await["result"],
                prefixed(&root)
            );
            assert!(
                rpc_call(&frontend, "jamHead_unstable_unpin", json!([id, hash])).await["result"]
                    .is_null()
            );
        }
        assert_eq!(
            rpc_call(&frontend, "jamHead_unstable_follow", json!([])).await["error"]["code"],
            -32800
        );
        assert!(
            rpc_call(&frontend, "jamHead_unstable_unfollow", json!(["1"])).await["result"]
                .is_null()
        );
        rpc_follow_snapshot(&frontend, &root, &[], &root).await;
        // `chainHead_v1` would carry JAM bytes under SCALE names.
        for (method, params) in [
            ("chainHead_v1_follow", json!([false])),
            ("chainHead_v1_header", json!(["2", rpc_hash(&root)])),
            ("chainHead_v1_unpin", json!(["2", rpc_hash(&root)])),
            ("chainHead_v1_unfollow", json!(["2"])),
            ("chain_getBlockHash", json!([])),
        ] {
            assert_eq!(
                rpc_call(&frontend, method, params).await["error"]["code"],
                -32601,
                "{method}"
            );
        }
    });
}

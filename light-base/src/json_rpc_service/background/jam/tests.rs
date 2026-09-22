// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;

/// The smallest encoding with a readable slot: three hashes, then the slot.
fn header(slot: u32) -> Vec<u8> {
    let mut bytes = vec![0; 96];
    bytes.extend(slot.to_le_bytes());
    bytes
}

fn event(rx: &async_channel::Receiver<String>) -> serde_json::Value {
    let message: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
    assert_eq!(message["method"], "jamHead_unstable_followEvent");
    assert_eq!(message["params"]["subscription"], "1");
    message["params"]["result"].clone()
}

fn hex(hash: [u8; 32]) -> String {
    format!("0x{}", hex::encode(hash))
}

async fn large_follow() -> (
    JamFollow,
    Vec<[u8; 32]>,
    async_channel::Sender<String>,
    async_channel::Receiver<String>,
) {
    let (_, notifications) = async_channel::bounded(1);
    let (mut follow, root) = JamFollow::new(vec![0], notifications);
    let (tx, rx) = async_channel::bounded(2);
    let mut hashes = Vec::new();
    let mut parent_hash = root;
    for number in 1u32..=600 {
        let bytes = header(number);
        let hash = codec::header_hash(&bytes);
        jam_notification(
            "1",
            &mut follow,
            sync_service::Notification::Block(sync_service::BlockNotification {
                is_new_best: false,
                scale_encoded_header: bytes.clone(),
                parent_hash,
            }),
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(
            event(&rx),
            serde_json::json!({"event":"newBlock", "blockHash":hex(hash), "parentBlockHash":hex(parent_hash), "slot":number})
        );
        assert_eq!(follow.headers[&hash], bytes);
        hashes.push(hash);
        parent_hash = hash;
    }
    assert_eq!(follow.headers.len(), 601);
    assert_eq!(follow.finalized_pinned_remaining, JAM_PIN_COUNT - 1);
    assert_eq!(follow.counted_headers, BTreeSet::from([root]));
    assert!(rx.is_empty());
    (follow, hashes, tx, rx)
}

#[test]
fn jam_large_snapshot_charges_finality_and_refunds_unpins() {
    smol::block_on(async {
        let (mut follow, hashes, tx, rx) = large_follow().await;
        let headers = follow.headers.clone();
        jam_notification(
            "1",
            &mut follow,
            sync_service::Notification::Finalized {
                finalized_blocks_hashes: hashes[..300].to_vec(),
                best_block_hash_if_changed: Some(hashes[299]),
                pruned_blocks: Vec::new(),
            },
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(follow.headers, headers);
        assert_eq!(follow.finalized_pinned_remaining, 511 - 300);
        assert_eq!(follow.counted_headers.len(), 301);
        assert!(
            hashes[..300]
                .iter()
                .all(|hash| follow.counted_headers.contains(hash))
        );
        for expected in ["bestBlockChanged", "finalized"] {
            assert_eq!(event(&rx)["event"], expected);
        }
        for hash in &hashes[..100] {
            follow.unpin(hash);
            assert!(!follow.headers.contains_key(hash));
            assert!(!follow.counted_headers.contains(hash));
        }
        assert_eq!(follow.headers.len(), 501);
        assert_eq!(follow.counted_headers.len(), 201);
        assert_eq!(follow.finalized_pinned_remaining, 511 - 300 + 100);

        // An uncounted pin removed before finality neither refunds nor charges.
        follow.unpin(&hashes[300]);
        assert_eq!(follow.finalized_pinned_remaining, 311);
        jam_notification(
            "1",
            &mut follow,
            sync_service::Notification::Finalized {
                finalized_blocks_hashes: vec![hashes[300], hashes[301], hashes[301]],
                best_block_hash_if_changed: None,
                // Include an already charged hash and duplicates within/across lists.
                pruned_blocks: vec![hashes[100], hashes[301], hashes[302], hashes[302]],
            },
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(follow.finalized_pinned_remaining, 309);
        assert_eq!(follow.counted_headers.len(), 203);
        assert!(!follow.counted_headers.contains(&hashes[300]));
        assert!(follow.counted_headers.contains(&hashes[301]));
        assert!(follow.counted_headers.contains(&hashes[302]));
        assert_eq!(follow.headers[&hashes[302]], headers[&hashes[302]]);
        follow.unpin(&hashes[302]);
        assert_eq!(follow.finalized_pinned_remaining, 310);
    });
}

#[test]
fn jam_excess_finality_charge_is_atomic() {
    smol::block_on(async {
        let (mut follow, hashes, tx, rx) = large_follow().await;
        let headers = follow.headers.clone();
        let counted_headers = follow.counted_headers.clone();
        let remaining = follow.finalized_pinned_remaining;
        // Both finalized-only and combined finalized/pruned charges are transactional.
        for finalized_count in [600, 300, 0] {
            assert!(
                jam_notification(
                    "1",
                    &mut follow,
                    sync_service::Notification::Finalized {
                        finalized_blocks_hashes: hashes[..finalized_count].to_vec(),
                        best_block_hash_if_changed: Some(hashes[599]),
                        pruned_blocks: hashes[finalized_count..].to_vec(),
                    },
                    &tx,
                )
                .await
                .is_err()
            );
            assert_eq!(follow.headers, headers);
            assert_eq!(follow.counted_headers, counted_headers);
            assert_eq!(follow.finalized_pinned_remaining, remaining);
            assert!(rx.is_empty());
        }
    });
}

#[test]
fn jam_exact_finality_budget_deduplicates_and_charges_root_once() {
    smol::block_on(async {
        let (mut follow, hashes, tx, rx) = large_follow().await;
        let root = *follow.counted_headers.first().unwrap();
        let mut finalized = hashes[..511].to_vec();
        finalized.extend([root, hashes[0]]);
        jam_notification(
            "1",
            &mut follow,
            sync_service::Notification::Finalized {
                finalized_blocks_hashes: finalized,
                best_block_hash_if_changed: None,
                pruned_blocks: vec![root, hashes[0], hashes[510]],
            },
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(follow.finalized_pinned_remaining, 0);
        assert_eq!(follow.counted_headers.len(), JAM_PIN_COUNT);
        rx.try_recv().unwrap();
        // Re-reporting counted pins is valid even with no budget remaining.
        jam_notification(
            "1",
            &mut follow,
            sync_service::Notification::Finalized {
                finalized_blocks_hashes: vec![root],
                best_block_hash_if_changed: None,
                pruned_blocks: vec![hashes[0]],
            },
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(follow.finalized_pinned_remaining, 0);
        follow.unpin(&root);
        assert_eq!(follow.finalized_pinned_remaining, 1);
    });
}

#[test]
fn every_notification_becomes_its_events_in_order() {
    smol::block_on(async {
        let (_, notifications) = async_channel::bounded(1);
        let (mut follow, root) = JamFollow::new(header(0), notifications);
        let (tx, rx) = async_channel::bounded(4);
        let bytes = header(7);
        let hash = smoldot::jam::crypto::blake2b_256(&bytes);
        let block = |is_new_best| {
            sync_service::Notification::Block(sync_service::BlockNotification {
                is_new_best,
                scale_encoded_header: bytes.clone(),
                parent_hash: root,
            })
        };
        jam_notification("1", &mut follow, block(true), &tx)
            .await
            .unwrap();
        assert_eq!(follow.headers.get(&hash), Some(&bytes));
        assert_eq!(
            event(&rx),
            serde_json::json!({"event":"newBlock", "blockHash":hex(hash), "parentBlockHash":hex(root), "slot":7})
        );
        assert_eq!(
            event(&rx),
            serde_json::json!({"event":"bestBlockChanged", "bestBlockHash":hex(hash)})
        );
        jam_notification("1", &mut follow, block(false), &tx)
            .await
            .unwrap();
        assert_eq!(event(&rx)["event"], "newBlock");
        assert!(rx.is_empty());
        jam_notification(
            "1",
            &mut follow,
            sync_service::Notification::BestBlockChanged { hash: root },
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(
            event(&rx),
            serde_json::json!({"event":"bestBlockChanged", "bestBlockHash":hex(root)})
        );
        jam_notification(
            "1",
            &mut follow,
            sync_service::Notification::Finalized {
                finalized_blocks_hashes: vec![hash],
                best_block_hash_if_changed: Some(hash),
                pruned_blocks: vec![[9; 32]],
            },
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(
            event(&rx),
            serde_json::json!({"event":"bestBlockChanged", "bestBlockHash":hex(hash)})
        );
        assert_eq!(
            event(&rx),
            serde_json::json!({"event":"finalized", "finalizedBlockHashes":[hex(hash)], "prunedBlockHashes":[hex([9; 32])]})
        );
        assert_eq!(follow.headers.get(&hash), Some(&bytes));
        // A header too short to hold a slot ends the subscription, pinning nothing.
        let short = sync_service::Notification::Block(sync_service::BlockNotification {
            is_new_best: true,
            scale_encoded_header: bytes[..99].to_vec(),
            parent_hash: hash,
        });
        assert!(
            jam_notification("1", &mut follow, short, &tx)
                .await
                .is_err()
        );
        assert_eq!(follow.headers.len(), 2);
        assert!(rx.is_empty());
    });
}

#[test]
fn jam_pin_budget_and_finality_preserve_pinned_headers() {
    smol::block_on(async {
        let (_, notifications) = async_channel::bounded(1);
        let (mut follow, root) = JamFollow::new(vec![0; JAM_PIN_BYTES], notifications);
        let (tx, rx) = async_channel::bounded(4);
        let block = sync_service::Notification::Block(sync_service::BlockNotification {
            is_new_best: true,
            scale_encoded_header: vec![1],
            parent_hash: root,
        });
        assert!(
            jam_notification("1", &mut follow, block, &tx)
                .await
                .is_err()
        );
        assert_eq!(follow.headers.len(), 1);
        assert_eq!(follow.headers[&root].len(), JAM_PIN_BYTES);
        assert_eq!(follow.finalized_pinned_remaining, JAM_PIN_COUNT - 1);
        assert_eq!(follow.counted_headers, BTreeSet::from([root]));
        assert!(rx.is_empty());
        assert!(
            jam_notification(
                "1",
                &mut follow,
                sync_service::Notification::Finalized {
                    finalized_blocks_hashes: vec![root],
                    best_block_hash_if_changed: None,
                    pruned_blocks: vec![[8; 32]]
                },
                &tx
            )
            .await
            .is_ok()
        );
        assert_eq!(event(&rx)["event"], "finalized");
        assert_eq!(follow.headers[&root].len(), JAM_PIN_BYTES);
        assert_eq!(follow.finalized_pinned_remaining, JAM_PIN_COUNT - 1);
        follow.unpin(&root);
        assert!(follow.headers.is_empty());
        assert!(follow.counted_headers.is_empty());
        assert_eq!(follow.finalized_pinned_remaining, JAM_PIN_COUNT);
    });
}

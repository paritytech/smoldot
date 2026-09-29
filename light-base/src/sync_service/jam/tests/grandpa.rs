// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! GRANDPA finality: proof requests, verification and the tree budget.

use super::*;

#[test]
fn proof_work_includes_witnesses_beyond_a_small_retained_tree() {
    smol::block_on(async {
        let mut state = root_state();
        let (keys, public) = grandpa_key(43).await;
        state.authorities =
            AuthoritySet::from_checkpoint(&state.params, 0, vec![public; 6], vec![public; 6])
                .unwrap();
        let root = state.tree.finalized().clone();
        let mut header = Header::decode(&state.params, root.encoded()).unwrap();
        header.parent = root.hash();
        header.slot = 1;
        let block = assume_verified(&state.params, &header, root.post_state().clone());
        let target = final_of(&state.params, &header);
        state.tree.insert_verified(block).unwrap();
        let mut witnesses = Vec::new();
        for slot in 2u32..=26 {
            header.parent = header.hash(&state.params);
            header.slot = slot;
            witnesses.push(header.clone());
        }
        assert!(state.proof_limits().max_ancestry_headers >= witnesses.len());
        assert!(state.proof_limits().max_ancestry_steps >= witnesses.len());
        // Every witness carries the same prior state root: the walk reaches the
        // target under it, so the commit must sign it as the target's root.
        let commit = (target.clone(), header.prior_state_root);
        let key = (&keys, public);
        let proof = single_vote_justification(key, (1, 0), commit, &witnesses, &state.params).await;
        state.finalize(target.hash, &proof).unwrap();
        assert_eq!(state.tree.finalized().hash(), target.hash);
    });
}

#[test]
fn external_captured_finality_requests_are_deduplicated_and_notifications_follow_verification() {
    let fixture = fixture("polkajam-grandpa.json");
    let spec = parse(&fixture["spec"].to_string());
    let mut state = state(Config::from_spec(&spec).unwrap());
    for encoded in fixture["headers"].as_array().unwrap() {
        let header = Header::decode(&state.params, &bytes(encoded)).unwrap();
        state.insert(header, 1_900_000_000).unwrap();
    }
    let snapshot = state.subscribe(16, false);
    let advertised = Final {
        hash: state.tree.best().hash(),
        slot: state.tree.best().slot(),
    };
    let first_target = state.reserve_proof(0, &advertised).unwrap();
    assert_eq!(
        state.reserve_proof(1, &advertised),
        None,
        "deduplicate across peers"
    );
    state.proof_owner = None; // First peer failed or timed out.
    assert_eq!(
        state.reserve_proof(0, &advertised),
        None,
        "do not repeat a rejected target on the same peer"
    );
    assert_eq!(state.reserve_proof(1, &advertised), Some(first_target));
    let root = state.tree.finalized().hash();
    let set_id = state.authorities.set_id();
    assert!(state.finalize(first_target, &[0xff]).is_err());
    assert_eq!(state.tree.finalized().hash(), root);
    assert_eq!(state.authorities.set_id(), set_id);
    assert!(snapshot.new_blocks.try_recv().is_err());
    for encoded in fixture["justifications"].as_array().unwrap() {
        let bytes = hex::decode(encoded.as_str().unwrap()).unwrap();
        let proof = Justification::decode(&state.params, &bytes, state.proof_limits()).unwrap();
        state.finalize(proof.target().hash, &bytes).unwrap();
        let notification = snapshot.new_blocks.try_recv().unwrap();
        assert!(
            matches!(notification, Notification::Finalized { ref finalized_blocks_hashes, .. }
            if finalized_blocks_hashes.last() == Some(&state.tree.finalized().hash()))
        );
    }
    assert_eq!(state.authorities.set_id(), 3);
    assert!(state.tree.len() <= 2);
    assert!(!snapshot.new_blocks.is_closed());
}

#[test]
fn external_full_parameter_1200_blocks_interleave_finality() {
    smol::block_on(async {
        use smoldot::jam::types::EpochMark;
        let (platform, _, _, _) = fixture_setup();
        let (keys, public) = grandpa_key(42).await;
        let (secret, sealer) = bandersnatch_key(b"full parameters");
        let now = platform.now_from_unix_epoch().as_secs();
        let mut params = root_config().params;
        params.epoch_len = 600;
        params.epoch_tail_start = 500;
        params.max_validators = 1023;
        params.core_count = 341;
        let (header_bytes, limits) = memory_limits(&params).unwrap();
        // Every validator has the one sealing key, so it seals every slot.
        let pairs = vec![(sealer, public); 1023];
        let mut header = Header::decode(&params, root_config().tree.finalized().encoded()).unwrap();
        header.slot = 0;
        let root = verified_genesis(
            &params,
            header.clone(),
            LightState::from_parts(
                [[0; 32]; 4],
                pairs.clone(),
                pairs.clone(),
                SealingSequence::Keys(vec![sealer; 600]),
                None,
                0,
            ),
        );
        let mut headers = Vec::new();
        let mut proofs = BTreeMap::new();
        let mut parent = root.clone();
        for slot in 1u32..=1200 {
            header.parent = parent.hash();
            header.slot = slot;
            header.epoch_mark = (slot % 600 == 0).then(|| EpochMark {
                entropy: parent.post_state().entropy()[0],
                tickets_entropy: parent.post_state().entropy()[1],
                validators: pairs.clone(),
            });
            header = seal_fallback(&params, &parent, header, &secret);
            parent =
                smoldot::jam::verify::verify_header(&params, &parent, header.clone(), now).unwrap();
            let hash = parent.hash();
            let set_id = (slot - 1) / 600;
            // Every header here has the same prior state root.
            let commit = (final_of(&params, &header), header.prior_state_root);
            let key = (&keys, public);
            let proof = single_vote_justification(key, (1, set_id), commit, &[], &params).await;
            proofs.insert(hash, framed(proof));
            headers.push(header.clone());
        }
        {
            let mut control = platform.0.lock().unwrap();
            control.responses.clear();
            control.io.params = Some(params.clone());
            control.io.proofs = proofs;
            for header in &headers {
                serve(&mut control, &params, header);
            }
            control.handshake = handshake_frame(final_of(&params, &headers[1199]), vec![]);
        }
        let config = Config {
            params: params.clone(),
            tree: HeaderTree::new(params.clone(), root, limits).unwrap(),
            peers: vec![],
            header_bytes,
            authorities: AuthoritySet::from_checkpoint(
                &params,
                0,
                vec![public; 1023],
                vec![public; 1023],
            )
            .unwrap(),
            max_blocks: limits.max_blocks.get(),
            tree_config: limits,
        };
        let state = driver_state(config);
        let subscription = state.lock().await.subscribe(16, false);
        let mut imported = Vec::new();
        let mut peak_nodes = 0;
        let mut peak_bytes = 0;
        let driver = drive_scripted(&platform, &params, &state, 0, 64);
        while_driving(30, "full-parameter catch-up", driver, async {
            loop {
                if let Notification::Block(block) = subscription.new_blocks.recv().await.unwrap() {
                    imported.push(blake2b_256(&block.scale_encoded_header));
                }
                let s = state.lock().await;
                peak_nodes = peak_nodes.max(s.tree.len());
                peak_bytes = peak_bytes.max(s.tree.retained_bytes());
                assert!(s.tree.len() + 64 < s.max_blocks, "no import backpressure");
                assert!(s.tree.retained_bytes() <= limits.max_bytes);
                assert!(s.tree.epoch_records() <= 2);
                assert!(!s.stopped);
                if s.tree.finalized().slot() == 1200 {
                    break;
                }
            }
        })
        .await;
        assert_eq!(
            imported,
            headers.iter().map(|h| h.hash(&params)).collect::<Vec<_>>()
        );
        let control = platform.0.lock().unwrap();
        assert_eq!(control.attempts, 1);
        assert!(!control.io.proof_requests.is_empty());
        assert!(
            control
                .requests
                .iter()
                .all(|r| r.direction == Direction::AscendingExclusive)
        );
    });
}

#[test]
fn external_ascending_600_blocks_interleaves_finality_without_reconnect() {
    smol::block_on(async {
        let (platform, config, headers) = synthetic_driver(600, 32);
        let params = config.params.clone();
        let state = driver_state(config);
        let subscription = state.lock().await.subscribe(16, false);
        let mut imported = Vec::new();
        let driver = drive_scripted(&platform, &params, &state, 0, 64);
        while_driving(30, "600-block catch-up", driver, async {
            loop {
                if let Notification::Block(block) = subscription.new_blocks.recv().await.unwrap() {
                    imported.push(blake2b_256(&block.scale_encoded_header));
                }
                let s = state.lock().await;
                assert!(s.tree.len() <= s.max_blocks);
                if s.tree.finalized().slot() == 600 {
                    break;
                }
            }
        })
        .await;
        let expected: Vec<_> = headers.iter().map(|h| h.hash(&params)).collect();
        assert_eq!(imported, expected);
        let c = platform.0.lock().unwrap();
        assert_eq!(c.attempts, 1);
        // Batches of 1, 2, 4, 8, 16, 32, then 64 blocks.
        assert_eq!(c.requests.len(), 15);
        assert!(
            c.requests
                .iter()
                .all(|r| r.direction == Direction::AscendingExclusive
                    && (1..=64).contains(&r.max_blocks))
        );
        for header in headers.iter().filter(|h| h.epoch_mark.is_some()) {
            assert!(c.io.proof_requests.contains(&header.hash(&params)));
        }
    });
}

#[test]
fn external_dead_first_child_escapes_through_bounded_announcement_repair() {
    smol::block_on(async {
        let (platform, config, headers) = synthetic_driver(10, 32);
        let params = config.params.clone();
        let root = config.tree.finalized().hash();
        let dead = bytes(&fixture("synthetic.json")["dead_header"]);
        let dead = Header::decode(&params, &dead).unwrap();
        let dead_hash = dead.hash(&params);
        {
            let mut c = platform.0.lock().unwrap();
            c.io.proofs.clear();
            c.io.preferred_child = Some((dead.parent, dead_hash));
            serve(&mut c, &params, &dead);
            let genesis = Final {
                hash: root,
                slot: 0,
            };
            c.io.fork_announcement = Some(announcement_frame(&params, headers[9].clone(), genesis));
        }
        let state = driver_state(config);
        let driver = drive_scripted(&platform, &params, &state, 0, 64);
        let tip = headers[9].hash(&params);
        let recovered = yield_until(async || state.lock().await.tree.best().hash() == tip);
        while_driving(15, "fork recovery", driver, recovered).await;
        let s = state.lock().await;
        assert!(
            s.tree.get(&dead_hash).is_some(),
            "peer opinion must not remove authenticated best"
        );
        assert_eq!(s.tree.finalized().hash(), root);
        let c = platform.0.lock().unwrap();
        assert_eq!(c.attempts, 1);
        assert_eq!(
            c.io.no_blocks, 2,
            "best reset, then repeated dead fallback reset"
        );
        assert!(
            c.requests
                .iter()
                .filter(|r| r.direction == Direction::DescendingInclusive)
                .count()
                <= REPAIR_LIMIT
        );
        assert_eq!(c.requests.iter().filter(|r| r.hash == root).count(), 2);
    });
}

#[test]
fn external_full_unfinalizable_tree_exits_instead_of_deadlocking() {
    smol::block_on(async {
        let (platform, config, _) = synthetic_driver(10, 4);
        let params = config.params.clone();
        platform.0.lock().unwrap().io.proofs.clear();
        let state = driver_state(config);
        let driver = drive_scripted(&platform, &params, &state, 0, 64);
        within(10, "exit of the full unfinalizable tree", driver).await;
        let s = state.lock().await;
        assert_eq!(s.tree.len(), 4);
        assert_eq!(s.tree.finalized().slot(), 0);
        assert!(
            !s.stopped,
            "dropping the peer leaves shared state available"
        );
    });
}

#[test]
fn external_oversized_batch_retries_with_persistent_lower_ceiling() {
    smol::block_on(async {
        let (platform, config, headers) = synthetic_driver(10, 32);
        let params = config.params.clone();
        let state = driver_state(config);
        platform.0.lock().unwrap().io.reject_batch_above = Some(2);
        let mut size = FetchSize {
            count: 8,
            ceiling: 64,
        };
        let mut probe = None;
        for expected in [4, 2] {
            let driver = drive_peer(&platform, &params, &state, 0, (&mut size, &mut probe));
            within(10, "end of the driver on an oversized response", driver).await;
            assert_eq!(size.count, expected);
            assert_eq!(state.lock().await.tree.len(), 1);
        }
        let tip = headers[9].hash(&params);
        let caught_up = yield_until(async || state.lock().await.tree.best().hash() == tip);
        let driver = drive_peer(&platform, &params, &state, 0, (&mut size, &mut probe));
        while_driving(10, "catch-up in resized batches", driver, caught_up).await;
        assert_eq!(size.count, 2);
        let c = platform.0.lock().unwrap();
        assert_eq!(
            c.requests.iter().map(|r| r.max_blocks).collect::<Vec<_>>(),
            vec![8, 4, 2, 2, 2, 2, 2]
        );
    });
}

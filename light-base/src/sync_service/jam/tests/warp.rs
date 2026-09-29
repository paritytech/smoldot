// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The warp join, the root probe and typed stream resets.

use super::*;

#[test]
fn external_warp_paginates_32_then_short_batch_or_no_data() {
    smol::block_on(async {
        for no_data in [false, true] {
            let (platform, config, headers) = synthetic_driver(600, 32);
            let params = config.params.clone();
            {
                let mut c = platform.0.lock().unwrap();
                let fragments: Vec<_> = (headers.iter())
                    .filter(|h| h.epoch_mark.is_some())
                    .map(|h| {
                        [
                            h.encode(&params),
                            c.io.proofs[&h.hash(&params)][4..].to_vec(),
                        ]
                        .concat()
                    })
                    .collect();
                assert!(fragments.len() > 32);
                let pages = if no_data { 1 } else { usize::MAX };
                for (index, batch) in fragments.chunks(32).enumerate().take(pages) {
                    let count = codec::encode_natural(u64::try_from(batch.len()).unwrap());
                    let start = u32::try_from(index * 32).unwrap();
                    c.io.warps
                        .insert(start, framed([count, batch.concat()].concat()));
                }
                // This corpus has no state proofs, so stop at the join request
                // for F. The captured join corpus covers completion.
                c.io.block_resets.push_back((
                    Direction::DescendingInclusive,
                    Reset(Some(1), "join unavailable"),
                ));
            }
            let handshake = platform.0.lock().unwrap().handshake.clone();
            let advertised = Handshake::decode(&handshake[4..], 8).unwrap().final_;
            let state = driver_state(config);
            let original = state.lock().await.tree.finalized().clone();
            let driver = drive_scripted(&platform, &params, &state, 0, 64);
            within(10, "pagination to the finalized-state join", driver).await;
            assert_eq!(state.lock().await.tree.finalized(), &original);
            {
                let c = platform.0.lock().unwrap();
                assert_eq!(c.io.warp_requests, vec![0, 32]);
                assert_eq!(c.requests.len(), 1);
                assert_eq!(c.requests[0].hash, advertised.hash);
                assert_eq!(c.requests[0].direction, Direction::DescendingInclusive);
                assert_eq!(c.requests[0].max_blocks, 1);
            }
            if no_data {
                assert_reset_log(&platform, "no warp fragments", "NoData");
            }
        }
    });
}

/// A reset without a code ends the fragment chain like `NoData`, even when it
/// cuts the chain short. The join then fails at the finalized head's
/// justification, which a later set signed, and the tree keeps its anchor.
#[test]
fn early_end_of_the_warp_chain_fails_the_join() {
    smol::block_on(async {
        let (platform, config, headers) = synthetic_driver(600, 32);
        let params = config.params.clone();
        {
            let mut c = platform.0.lock().unwrap();
            let fragments: Vec<_> = (headers.iter())
                .filter(|h| h.epoch_mark.is_some())
                .map(|h| {
                    [
                        h.encode(&params),
                        c.io.proofs[&h.hash(&params)][4..].to_vec(),
                    ]
                    .concat()
                })
                .collect();
            assert!(fragments.len() > 32);
            let count = codec::encode_natural(32);
            c.io.warps
                .insert(0, framed([count, fragments[..32].concat()].concat()));
            // The second page is lost to a reset that reaches the client
            // without a code.
            c.io.codeless = true;
        }
        let state = driver_state(config);
        let original = state.lock().await.tree.finalized().clone();
        let driver = drive_scripted(&platform, &params, &state, 0, 64);
        within(10, "the join after an early end", driver).await;
        assert_eq!(state.lock().await.tree.finalized(), &original);
        assert_eq!(state.lock().await.warp_revision, 0);
        assert_reset_log(&platform, "no warp fragments", "ResetWithoutCode");
        let rejected = logged(&platform, "jam-warp-rejected");
        assert!(rejected.iter().any(|f| f["step"] == "justification"));
        let c = platform.0.lock().unwrap();
        assert_eq!(c.io.warp_requests, vec![0, 32]);
        assert!(c.io.state_requests.is_empty());
    });
}

/// A warp peer whose fragments are assembled from captured CE 130
/// justifications and headers, not from a CE 153 capture. With `pruned`,
/// returns [`join_setup`] instead.
fn warp_setup(pruned: bool) -> (FakePlatform, Config, Vec<Header>, Header) {
    if pruned {
        return join_setup();
    }
    let fixture = fixture("polkajam-grandpa.json");
    let config = Config::from_spec(&parse(&fixture["spec"].to_string())).unwrap();
    let params = &config.params;
    let headers: Vec<_> = (fixture["headers"].as_array().unwrap().iter())
        .map(|h| Header::decode(params, &bytes(h)).unwrap())
        .collect();
    let limits = finality::Limits {
        max_bytes: FRAME_BYTES,
        max_ancestry_headers: 64,
        max_ancestry_steps: 4096,
    };
    let mut fragments = codec::encode_natural(3);
    let mut target = None;
    let mut proofs = BTreeMap::new();
    for value in fixture["justifications"].as_array().unwrap() {
        let raw = bytes(value);
        let hash = Justification::decode(params, &raw, limits)
            .unwrap()
            .target()
            .hash;
        let header = headers.iter().find(|h| h.hash(params) == hash).unwrap();
        if header.epoch_mark.is_some() {
            fragments.extend([header.encode(params), raw.clone()].concat());
            target = Some(header.clone());
        }
        proofs.insert(hash, framed(raw));
    }
    let tip = &headers[headers.len() - 2]; // Last fixture header has no captured proof.
    let mut control = Control {
        handshake: handshake_frame(final_of(params, tip), vec![]),
        supported: true,
        io: IoState {
            params: Some(params.clone()),
            proofs,
            warps: BTreeMap::from([(0, framed(fragments))]),
            ..IoState::default()
        },
        ..Control::default()
    };
    for header in &headers {
        serve(&mut control, params, header);
    }
    (platform(control), config, headers, target.unwrap())
}

fn join_vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../lib/src/jam/trie/fixtures/polkajam-join.json"
    ))
    .unwrap()
}

fn join_exchange(vector: &Value, name: &str) -> Vec<u8> {
    let exchanges = vector["exchanges"].as_array().unwrap();
    bytes(&exchanges.iter().find(|e| e["name"] == name).unwrap()["response_frame_hex"])
}

async fn captured_join() -> (State, Warp) {
    let vector = join_vector();
    let mut s = state(Config::from_spec(&parse(&vector["spec"].to_string())).unwrap());
    let head = join_exchange(&vector, "join-head");
    let blocks =
        smoldot::jam::types::Block::decode_sequence(&s.params, &head[4..], FRAME_BYTES, 1).unwrap();
    let proof = join_exchange(&vector, "join-finality");
    let set_id = Justification::decode(&s.params, &proof[4..], s.proof_limits())
        .unwrap()
        .set_id();
    // The captured justification is signed by the fixed dev keys under its
    // own set id; start the replay at that set.
    let current = s.authorities.current().to_vec();
    s.authorities =
        AuthoritySet::from_checkpoint(&s.params, set_id, current.clone(), current).unwrap();
    let mut w = s.reserve_warp(0).unwrap();
    w.final_head = Some(final_of(&s.params, &blocks[0].header));
    assert!(w.next_read().is_err());
    w.receive_headers(&s.params, blocks, s.header_bytes)
        .unwrap();
    assert!(w.next_read().is_err());
    w.authenticate(&s.params, &proof[4..], s.proof_limits())
        .unwrap();
    // The read is at F itself against the posterior root F's justification signs.
    let read = w.next_read().unwrap();
    assert_eq!(read.at, w.head.as_ref().unwrap().hash(&s.params));
    assert_eq!(hex::encode(read.root), vector["commit"]["state_root"]);
    assert_eq!(read.root_header, Some(read.at));
    assert_eq!(read.trust, Trust::Finalized);
    for name in ["join-c4", "join-c6", "join-c8", "join-c11"] {
        let rx = s.reads.start(w.next_read().unwrap()).unwrap();
        s.reads.reserve(0).unwrap();
        let response = state_response(&join_exchange(&vector, name));
        s.reads.received(0, &response).unwrap();
        w.items.extend(rx.await.unwrap().unwrap().range.entries);
    }
    (s, w)
}

// Captured CE 129 proofs and captured sealed F and child, with GRANDPA votes and
// three warp fragments signed by a scripted authority set. The proof for F signs
// F's real posterior root, which is the child's prior root.
fn join_setup() -> (FakePlatform, Config, Vec<Header>, Header) {
    smol::block_on(async {
        let (platform, mut config, old_headers, _) = warp_setup(false);
        let params = config.params.clone();
        let vector = join_vector();
        let head = join_exchange(&vector, "join-head");
        let blocks =
            smoldot::jam::types::Block::decode_sequence(&params, &head[4..], FRAME_BYTES, 1)
                .unwrap();
        let f = blocks[0].header.clone();
        let child = Header::decode(&params, &bytes(&vector["child"]["header_hex"])).unwrap();
        let (keys, public) = grandpa_key(42).await;
        let signer = (&keys, public);
        config.authorities =
            AuthoritySet::from_checkpoint(&params, 0, vec![public; 6], vec![public; 6]).unwrap();
        let mut fragments = vec![3];
        let marked = old_headers.iter().filter(|h| h.epoch_mark.is_some());
        for (set_id, original) in (0..).zip(marked) {
            let mut h = original.clone();
            for (_, ed) in &mut h.epoch_mark.as_mut().unwrap().validators {
                *ed = public;
            }
            fragments.extend(h.encode(&params));
            let commit = (final_of(&params, &h), [0; 32]);
            let proof = single_vote_justification(signer, (1, set_id), commit, &[], &params);
            fragments.extend(proof.await);
        }
        let mut proofs = BTreeMap::new();
        // The child's own posterior root was not captured; its proof is scripted.
        for (h, root) in [(&f, child.prior_state_root), (&child, [0; 32])] {
            let commit = (final_of(&params, h), root);
            let proof = single_vote_justification(signer, (1, 3), commit, &[], &params).await;
            proofs.insert(h.hash(&params), framed(proof));
        }
        let mut c = platform.0.lock().unwrap();
        c.responses.clear();
        for block in blocks {
            c.responses
                .insert(block.header.hash(&params), framed(block.encode(&params)));
        }
        c.responses.insert(
            child.hash(&params),
            join_exchange(&vector, "finalized-child"),
        );
        c.handshake = handshake_frame(final_of(&params, &f), vec![final_of(&params, &child)]);
        c.io.proofs = proofs;
        let announcement = announcement_frame(&params, child.clone(), final_of(&params, &child));
        c.io.join_announcement = Some(announcement);
        c.io.warps = BTreeMap::from([(0, framed(fragments))]);
        c.io.state_responses = ["join-c4", "join-c6", "join-c8", "join-c11"]
            .iter()
            .map(|name| Ok(join_exchange(&vector, name)))
            .collect();
        drop(c);
        (platform, config, vec![f.clone(), child], f)
    })
}

#[test]
fn assembled_warp_reanchors_stops_followers_then_imports_and_finalizes() {
    smol::block_on(async {
        for full_range in [false, true] {
            let (platform, config, headers, target) = warp_setup(true);
            if full_range {
                let mut c = platform.0.lock().unwrap();
                c.io.state_responses =
                    [Ok(join_exchange(&join_vector(), "join-range-c4-c11"))].into();
                c.io.announce_during_join = true;
            }
            let params = config.params.clone();
            let target_hash = target.hash(&params);
            let state = driver_state(config);
            let old = state.lock().await.subscribe(16, false);
            let (mut oracle_state, oracle_join) = captured_join().await;
            oracle_state.apply_warp(0, oracle_join).unwrap();
            let oracle = oracle_state.tree.finalized().clone();
            let driver = drive_scripted(&platform, &params, &state, 0, 1);
            while_driving(10, "warp", driver, async {
                yield_until(async || old.new_blocks.is_closed()).await;
                let follow = {
                    let mut s = state.lock().await;
                    assert_eq!(s.tree.finalized().hash(), target_hash);
                    assert_eq!(s.tree.finalized().post_state(), oracle.post_state());
                    assert_eq!(s.authorities.set_id(), 3);
                    s.subscribe(16, false)
                };
                assert_eq!(
                    blake2b_256(&follow.finalized_block_scale_encoded_header),
                    target_hash
                );
                // The child imports on top of F and is finalized.
                loop {
                    let notification = follow.new_blocks.recv().await.unwrap();
                    if matches!(notification, Notification::Finalized { .. })
                        && state.lock().await.tree.finalized().slot() > target.slot
                    {
                        break;
                    }
                }
            })
            .await;
            assert!(!logged(&platform, "jam-warp-applied").is_empty());
            let slot = target.slot.to_string();
            let joins = logged(&platform, "jam-warp-join-selected");
            assert!(
                joins
                    .iter()
                    .any(|f| f["advertisement"] == "1" && f["slot"] == slot)
            );
            let c = platform.0.lock().unwrap();
            assert_eq!(c.io.warp_requests, vec![0]);
            assert_eq!(c.io.state_requests.len(), if full_range { 1 } else { 4 });
            let (descending, ascending): (Vec<_>, Vec<_>) =
                (c.requests.iter()).partition(|r| r.direction == Direction::DescendingInclusive);
            assert_eq!(descending.len(), 1);
            assert_eq!(descending[0].hash, target_hash);
            assert_eq!(descending[0].max_blocks, 1, "the join fetches F alone");
            assert_eq!(ascending[0].hash, target_hash);
            assert!(ascending.iter().all(|r| {
                (headers.iter()).any(|h| h.hash(&params) == r.hash && h.slot >= target.slot)
            }));
        }
    });
}

#[test]
fn warp_no_data_keeps_anchor_and_ordinary_sync_works() {
    // A platform that reports resets without a code, as Firefox, does the same.
    for codeless in [false, true] {
        warp_no_data_keeps_anchor(codeless);
    }
}

fn warp_no_data_keeps_anchor(codeless: bool) {
    smol::block_on(async {
        let (platform, config, _, _) = warp_setup(false);
        {
            let mut c = platform.0.lock().unwrap();
            c.io.warps.clear();
            c.io.codeless = codeless;
        }
        let params = config.params.clone();
        let root = config.tree.finalized().hash();
        let state = driver_state(config);
        let follow = state.lock().await.subscribe(16, false);
        let driver = drive_scripted(&platform, &params, &state, 0, 64);
        while_driving(10, "ordinary sync", driver, async {
            while !matches!(
                follow.new_blocks.recv().await.unwrap(),
                Notification::Block(_)
            ) {}
        })
        .await;
        assert_eq!(state.lock().await.warp_revision, 0);
        assert!(!follow.new_blocks.is_closed());
        let reason = if codeless {
            "ResetWithoutCode"
        } else {
            "NoData"
        };
        let fragmentless = logged(&platform, "jam-warp-fragmentless");
        assert!(fragmentless.iter().any(|f| f["reason"] == reason));
        assert!(logged(&platform, "jam-warp-applied").is_empty());
        assert_reset_log(&platform, "no warp fragments", reason);
        let c = platform.0.lock().unwrap();
        assert_eq!(c.requests[0].hash, root);
        assert_eq!(c.io.warp_requests, vec![0]);
        assert!(c.io.state_requests.is_empty());
    });
}

#[test]
fn ascending_no_data_at_available_root_waits_for_a_child_instead_of_stopping() {
    smol::block_on(async {
        let (platform, config, headers, _) = warp_setup(false);
        let params = config.params.clone();
        let root = config.tree.finalized().clone();
        let root_final = Final {
            hash: root.hash(),
            slot: root.slot(),
        };
        {
            let mut c = platform.0.lock().unwrap();
            c.io.warps.clear();
            c.io.proofs.clear();
            c.responses.clear();
            serve(
                &mut c,
                &params,
                &Header::decode(&params, root.encoded()).unwrap(),
            );
            let leaf = Final {
                hash: [99; 32],
                slot: headers.last().unwrap().slot,
            };
            c.handshake = handshake_frame(root_final.clone(), vec![leaf]);
        }
        let state = driver_state(config);
        state.lock().await.peer_count = 2;
        assert!(state.lock().await.refuse_root(1, root.hash()).is_ok());
        let follow = state.lock().await.subscribe(16, false);
        let driver = drive_scripted(&platform, &params, &state, 0, 64);
        while_driving(10, "root availability", driver, async {
            yield_until(async || {
                let requests = &platform.0.lock().unwrap().requests;
                requests
                    .iter()
                    .any(|r| r.direction == Direction::DescendingInclusive && r.hash == root.hash())
            })
            .await;
            smol::Timer::after(Duration::from_millis(20)).await;
            assert!(!state.lock().await.stopped);
            {
                let mut c = platform.0.lock().unwrap();
                c.io.no_blocks = 2;
                let child = headers[0].clone();
                c.io.fork_announcement = Some(announcement_frame(&params, child, root_final));
            }
            assert!(matches!(
                follow.new_blocks.recv().await.unwrap(),
                Notification::Block(_)
            ));
            let s = state.lock().await;
            assert!(!s.stopped && s.root_refusals.is_none());
        })
        .await;
    });
}

#[test]
fn all_peers_refusing_warp_and_root_stop_without_reconnecting() {
    // A platform that reports resets without a code, as Firefox, does the same.
    for codeless in [false, true] {
        all_peers_refusing_stop(codeless);
    }
}

fn all_peers_refusing_stop(codeless: bool) {
    smol::block_on(async {
        let (platform, mut config, _, _) = warp_setup(false);
        {
            let mut c = platform.0.lock().unwrap();
            c.io.warps.clear();
            c.responses.clear();
            c.io.codeless = codeless;
        }
        let peer = config.peers.remove(0);
        let params = config.params.clone();
        let root = config.tree.finalized().hash();
        let state = driver_state(config);
        state.lock().await.peer_count = 2;
        let follow = state.lock().await.subscribe(16, false);
        let peers = future::or(
            peer_loop(&platform, "unserved-0", &peer, 0, &params, state.clone()),
            peer_loop(&platform, "unserved-1", &peer, 1, &params, state.clone()),
        );
        let stopped = async {
            yield_until(async || state.lock().await.stopped).await;
            assert!(follow.new_blocks.is_closed());
            assert_eq!(state.lock().await.tree.finalized().hash(), root);
            let attempts = platform.0.lock().unwrap().attempts;
            smol::Timer::after(Duration::from_millis(1200)).await;
            assert_eq!(platform.0.lock().unwrap().attempts, attempts);
        };
        within(10, "terminal stop", future::or(peers, stopped)).await;
        assert_eq!(platform.0.lock().unwrap().attempts, 2);
        let unserved = logged(&platform, "jam-anchor-unserved");
        let reason = if codeless {
            "ResetWithoutCode"
        } else {
            "NoData"
        };
        assert!(unserved.iter().any(|f| f["reason"] == reason));
    });
}

#[test]
fn reset_classifier_requires_the_exact_transport_code() {
    for code in (0..=8).chain([60, 0x52e4a40f, u32::MAX]) {
        let expected = match code {
            6 => net::RequestError::NoData,
            2..=5 => net::RequestError::Transient,
            _ => net::RequestError::Rejected,
        };
        assert_eq!(classify_reset(Some(code)), expected, "{code}");
    }
    assert_eq!(classify_reset(None), net::RequestError::ResetWithoutCode);
}

fn assert_reset_log(platform: &FakePlatform, raw: &str, reason: &str) {
    let resets = logged(platform, "jam-stream-reset");
    assert!(
        resets
            .iter()
            .any(|f| f["reason"] == reason && f["message"] == raw)
    );
}

#[test]
fn non_no_data_root_probes_reconnect_without_counting_and_later_succeed() {
    for (raw, reason) in [
        (Reset(Some(2), "busy"), "Transient"),
        (Reset(Some(4), "rate limited"), "Transient"),
        (Reset(Some(1), "rejected reset"), "Rejected"),
    ] {
        smol::block_on(async {
            let (first, mut config, _, _) = warp_setup(false);
            let (second, _, _, _) = warp_setup(false);
            let platforms = [&first, &second];
            let peer = config.peers.remove(0);
            let params = config.params.clone();
            let root = config.tree.finalized().clone();
            let root_header = Header::decode(&params, root.encoded()).unwrap();
            for platform in platforms {
                let mut c = platform.0.lock().unwrap();
                c.io.warps.clear();
                c.responses.clear();
                c.io.block_resets
                    .push_back((Direction::DescendingInclusive, raw));
            }
            let state = driver_state(config);
            state.lock().await.peer_count = 2;
            let follow = state.lock().await.subscribe(16, false);
            let peers = future::or(
                peer_loop(&first, "probe-0", &peer, 0, &params, state.clone()),
                peer_loop(&second, "probe-1", &peer, 1, &params, state.clone()),
            );
            let retried =
                async {
                    let reconnected = |p: &FakePlatform| !logged(p, "jam-reconnect").is_empty();
                    yield_until(async || platforms.iter().all(|p| reconnected(p))).await;
                    assert!(!state.lock().await.stopped);
                    assert!(state.lock().await.root_refusals.is_none());
                    assert!(!follow.new_blocks.is_closed());
                    for platform in platforms {
                        assert_reset_log(platform, raw.1, reason);
                        let mut c = platform.0.lock().unwrap();
                        assert_eq!(c.attempts, 1);
                        assert_eq!(c.requests.len(), 2);
                        serve(&mut c, &params, &root_header);
                    }
                    let requested = |p: &FakePlatform| p.0.lock().unwrap().requests.len() >= 3;
                    yield_until(async || platforms.iter().all(|p| requested(p))).await;
                    // Let the successful root response reach the driver. A lost
                    // probe would issue another ascending request before this one.
                    smol::Timer::after(Duration::from_millis(100)).await;
                    for platform in platforms {
                        assert!(logged(platform, "jam-anchor-unserved").is_empty());
                        let c = platform.0.lock().unwrap();
                        assert_eq!(c.attempts, 2);
                        assert_eq!(c.requests.len(), 3);
                        assert_eq!(c.requests[0].direction, Direction::AscendingExclusive);
                        assert!(c.requests[1..].iter().all(|r| r.hash == root.hash()
                            && r.direction == Direction::DescendingInclusive));
                    }
                    assert!(!state.lock().await.stopped);
                    assert!(state.lock().await.root_refusals.is_none());
                    assert!(!follow.new_blocks.is_closed());
                };
            within(
                10,
                &alloc::format!("root probe retry, {raw}"),
                future::or(peers, retried),
            )
            .await;
        });
    }
}

#[test]
fn rejected_root_ascending_reset_drops_connection_without_arming_probe() {
    smol::block_on(async {
        let (platform, config, _, _) = warp_setup(false);
        let params = config.params.clone();
        let root = config.tree.finalized().hash();
        {
            let mut c = platform.0.lock().unwrap();
            c.io.warps.clear();
            c.io.block_resets.push_back((
                Direction::AscendingExclusive,
                Reset(Some(1), "rejected ascending reset"),
            ));
        }
        let state = driver_state(config);
        let mut probe = None;
        let budget = (&mut FetchSize::default(), &mut probe);
        let driver = drive_peer(&platform, &params, &state, 0, budget);
        within(10, "disconnect on the rejected reset", driver).await;
        assert_eq!(probe, None);
        assert!(state.lock().await.root_refusals.is_none());
        assert!(!state.lock().await.stopped);
        assert_reset_log(&platform, "rejected ascending reset", "Rejected");
        let c = platform.0.lock().unwrap();
        assert_eq!(c.requests.len(), 1);
        assert_eq!(c.requests[0].hash, root);
        assert_eq!(c.requests[0].direction, Direction::AscendingExclusive);
        assert_eq!(c.io.live_connections, 0);
    });
}

/// An ascending reset at the root without a code arms the root probe as
/// `NoData` does: the next request asks the peer for the root itself.
#[test]
fn codeless_root_ascending_reset_arms_the_probe_like_no_data() {
    for (reset, reason) in [
        (Reset(Some(6), "no block"), "NoData"),
        (Reset(None, "Error in input stream"), "ResetWithoutCode"),
    ] {
        smol::block_on(async {
            let (platform, config, _, _) = warp_setup(false);
            let params = config.params.clone();
            let root = config.tree.finalized().hash();
            {
                let mut c = platform.0.lock().unwrap();
                c.io.warps.clear();
                c.io.block_resets
                    .push_back((Direction::AscendingExclusive, reset));
                // Stop at the probe.
                c.io.block_resets
                    .push_back((Direction::DescendingInclusive, Reset(Some(1), "stop")));
            }
            let state = driver_state(config);
            let mut probe = None;
            let budget = (&mut FetchSize::default(), &mut probe);
            let driver = drive_peer(&platform, &params, &state, 0, budget);
            within(10, "the root probe", driver).await;
            assert_eq!(probe, Some(root));
            assert_reset_log(&platform, reset.1, reason);
            let c = platform.0.lock().unwrap();
            let requests: Vec<_> = (c.requests.iter())
                .map(|r| (r.hash, r.direction.clone()))
                .collect();
            assert_eq!(
                requests,
                [
                    (root, Direction::AscendingExclusive),
                    (root, Direction::DescendingInclusive)
                ]
            );
        });
    }
}

#[test]
fn reconnect_discards_retained_probe_after_finalized_root_changes() {
    smol::block_on(async {
        let (platform, config, headers, _) = warp_setup(false);
        let params = config.params.clone();
        let old_root = config.tree.finalized().hash();
        let state = driver_state(config);
        let mut probe = Some(old_root);
        // Another peer finalizes while this peer's root probe awaits reconnect.
        let new_root = {
            let mut s = state.lock().await;
            for header in headers {
                let hash = header.hash(&params);
                s.insert(header, 1_900_000_000).unwrap();
                let proof = platform.0.lock().unwrap().io.proofs.get(&hash).cloned();
                if let Some(proof) = proof {
                    s.finalize(hash, &proof[4..]).unwrap();
                    break;
                }
            }
            s.tree.finalized().hash()
        };
        assert_ne!(new_root, old_root);
        {
            let mut c = platform.0.lock().unwrap();
            // No warp fragments, so only the entry check in `drive` can clear
            // the probe. Stop at the first ordinary ascending request.
            c.io.warps.clear();
            c.io.block_resets.push_back((
                Direction::AscendingExclusive,
                Reset(Some(1), "scripted reconnect reset"),
            ));
        }
        let budget = (&mut FetchSize::default(), &mut probe);
        let driver = drive_peer(&platform, &params, &state, 0, budget);
        within(10, "stale-probe reconnect", driver).await;
        assert_eq!(probe, None);
        assert!(state.lock().await.root_refusals.is_none());
        let c = platform.0.lock().unwrap();
        assert_eq!(c.requests.len(), 1);
        assert_eq!(c.requests[0].hash, new_root);
        assert_eq!(c.requests[0].direction, Direction::AscendingExclusive);
    });
}

#[test]
fn typed_proof_resets_release_reservation_without_disconnecting() {
    for (raw, reason) in [
        (Reset(Some(6), "no proof"), "NoData"),
        (Reset(Some(2), "busy proof"), "Transient"),
        (Reset(None, "Error in input stream"), "ResetWithoutCode"),
    ] {
        smol::block_on(async {
            let (platform, config, headers, _) = warp_setup(false);
            let params = config.params.clone();
            let root_slot = config.tree.finalized().slot();
            let tip = &headers[headers.len() - 2];
            {
                let mut c = platform.0.lock().unwrap();
                c.io.warps.clear();
                c.io.proof_resets.push_back(raw);
            }
            let state = driver_state(config);
            let driver = drive_scripted(&platform, &params, &state, 0, 1);
            let synced = yield_until(async || state.lock().await.tree.best().slot() >= tip.slot);
            while_driving(10, &alloc::format!("proof retry, {raw}"), driver, synced).await;
            assert_reset_log(&platform, raw.1, reason);
            let mut s = state.lock().await;
            assert_eq!(s.tree.finalized().slot(), root_slot);
            assert!(s.proof_owner.is_none());
            // The first unavailable set-change proof still blocks finality,
            // but another peer remains free to serve it.
            assert!(s.reserve_proof(1, &final_of(&params, tip)).is_some());
            let c = platform.0.lock().unwrap();
            assert_eq!(c.attempts, 1);
            assert_eq!(c.io.proof_requests.len(), 1);
        });
    }
}

#[test]
fn warp_reservation_and_refusals_are_snapshot_scoped() {
    let mut s = root_state();
    let root = s.tree.finalized().hash();
    s.proof_owner = Some((0, root));
    assert!(s.reserve_warp(1).is_none());
    s.proof_owner = None;
    assert!(s.reserve_warp(0).is_some());
    assert!(s.reserve_warp(1).is_none());
    let advertised = Final {
        hash: root,
        slot: 10,
    };
    assert_eq!(s.reserve_proof(1, &advertised), None);
    s.warp_owner = None;
    assert!(s.refuse_root(0, root).is_ok());
    assert!(s.refuse_root(0, root).is_ok());
    assert!(s.refuse_root(1, [99; 32]).is_ok());
    assert_eq!(
        s.refuse_root(1, root),
        Err(AnchorUnserved {
            hash: root,
            slot: s.tree.finalized().slot()
        })
    );
}

#[test]
fn join_authenticates_exact_final_head_before_reading() {
    let (_, config, _, _) = warp_setup(false);
    let s = state(config);
    let head = join_exchange(&join_vector(), "join-head");
    let blocks =
        smoldot::jam::types::Block::decode_sequence(&s.params, &head[4..], FRAME_BYTES, 1).unwrap();
    type Block = smoldot::jam::types::Block;
    let failures: [fn(&mut Warp, &mut Vec<Block>); 4] = [
        |_, blocks| blocks[0].header.prior_state_root[0] ^= 1,
        |_, blocks| blocks.push(blocks[0].clone()),
        |_, blocks| drop(blocks.pop()),
        |w, _| w.final_head.as_mut().unwrap().slot += 1,
    ];
    for fail in failures {
        let mut w = Warp::new(&s);
        w.final_head = Some(final_of(&s.params, &blocks[0].header));
        let mut bad = blocks.clone();
        fail(&mut w, &mut bad);
        assert!(matches!(
            w.receive_headers(&s.params, bad, s.header_bytes),
            Err(WarpError::InvalidJoin)
        ));
        assert!(w.next_read().is_err());
    }
}

#[test]
fn staged_join_failure_is_atomic_for_header_state_and_tree_errors() {
    smol::block_on(async {
        type Failure = (fn(&mut State, &mut Warp), bool);
        let failures: [Failure; 4] = [
            (|_, w| w.finalized = None, false),
            // F's header must be the one its justification finalized.
            (|_, w| w.head.as_mut().unwrap().seal[0] ^= 1, false),
            (|_, w| w.items[3].1 = 0u32.to_le_bytes().to_vec(), false),
            (|s, _| s.tree_config.max_bytes = 1, true),
        ];
        for (fail, tree_error) in failures {
            let (mut s, mut w) = captured_join().await;
            let old_root = s.tree.finalized().clone();
            let old_authorities = s.authorities.clone();
            let follow = s.subscribe(16, false);
            fail(&mut s, &mut w);
            match s.apply_warp(0, w) {
                Err(WarpError::Tree(_)) => assert!(tree_error),
                Err(WarpError::InvalidJoin) => assert!(!tree_error),
                _ => panic!("the join must fail"),
            }
            assert_eq!(s.tree.finalized(), &old_root);
            assert_eq!(s.authorities, old_authorities);
            assert_eq!(s.warp_revision, 0);
            assert!(!follow.new_blocks.is_closed());
        }
    });
}

#[test]
fn join_epoch_finality_rotates_exactly_once_and_finalizes_child() {
    smol::block_on(async {
        let vector = join_vector();
        let epoch = &vector["epoch_join_regression"];
        let spec = parse(&vector["spec"].to_string());
        let params = spec.params();
        let header = |name: &str| Header::decode(params, &bytes(&epoch[name])).unwrap();
        let (f, p, child) = (
            header("finalized_header_hex"),
            header("parent_header_hex"),
            header("child_header_hex"),
        );
        let f_root: Hash = bytes(&epoch["finalized_post_state_root"])
            .try_into()
            .unwrap();
        assert_eq!(f_root, child.prior_state_root);
        let state_items = |name: &str| -> Vec<(trie::StateKey, Vec<u8>)> {
            (epoch[name].as_array().unwrap().iter())
                .map(|item| {
                    let key = bytes(&item["key_hex"]).try_into().unwrap();
                    (key, bytes(&item["value_hex"]))
                })
                .collect()
        };
        let anchor = |items: &[(trie::StateKey, Vec<u8>)]| {
            let items = items.iter().map(|(k, v)| (k, v.as_slice()));
            let state = GenesisLightState::from_state_items(params, items).unwrap();
            LightState::from_anchor(params, &state).unwrap()
        };
        // Anchoring at F on its posterior state equals verifying F on top of P.
        let parent = verified_genesis(
            params,
            p.clone(),
            anchor(&state_items("parent_state_items")),
        );
        let stepped =
            smoldot::jam::verify::verify_header(params, &parent, f.clone(), 1_900_000_000).unwrap();
        assert_eq!(
            anchor(&state_items("finalized_state_items")),
            *stepped.post_state()
        );
        let (key_a, a) = grandpa_key(77).await;
        let (key_b, b) = grandpa_key(78).await;
        assert_ne!(a, b);
        let next: Vec<_> = (f.epoch_mark.as_ref().unwrap().validators.iter())
            .map(|(_, ed)| *ed)
            .collect();
        assert_ne!(next, vec![a; 6]);
        assert_ne!(next, vec![b; 6]);
        let mut previous = f.clone();
        previous.slot -= params.epoch_len;
        for (_, ed) in &mut previous.epoch_mark.as_mut().unwrap().validators {
            *ed = a;
        }
        let proof = async |signer, header: &Header, root, set_id| {
            let commit = (final_of(params, header), root);
            single_vote_justification(signer, (1, set_id), commit, &[], params).await
        };
        let previous_proof = proof((&key_a, a), &previous, [0; 32], 7).await;
        let f_proof = proof((&key_b, b), &f, f_root, 8).await;
        let child_proof = proof((&key_a, a), &child, [0; 32], 9).await;
        // A rotated set must also roll back on a failed join; the other
        // rollback injections are in `staged_join_failure_is_atomic_...`.
        for consumed in [false, true] {
            for tree_full in [false, true] {
                let mut config = Config::from_spec(&spec).unwrap();
                config.authorities =
                    AuthoritySet::from_checkpoint(params, 7, vec![a; 6], vec![b; 6]).unwrap();
                let mut s = state(config);
                let original_root = s.tree.finalized().clone();
                let original_authorities = s.authorities.clone();
                let follower = s.subscribe(16, false);
                let limits = finality::WarpLimits {
                    max_fragments: 32,
                    max_header_bytes: s.header_bytes,
                    proof: s.proof_limits(),
                };
                let mut w = s.reserve_warp(0).unwrap();
                let mut fragments = vec![if consumed { 2 } else { 1 }];
                fragments.extend(previous.encode(params));
                fragments.extend(&previous_proof);
                if consumed {
                    fragments.extend(f.encode(params));
                    fragments.extend(&f_proof);
                }
                w.advance(params, &fragments, &limits).unwrap();
                assert!(w.chain_done);
                assert_eq!(w.authorities.set_id(), if consumed { 9 } else { 8 });
                w.final_head = Some(final_of(params, &f));
                let block = |header| smoldot::jam::types::Block {
                    header,
                    body: vec![],
                };
                w.receive_headers(params, vec![block(f.clone())], s.header_bytes)
                    .unwrap();
                assert_eq!(w.finalized.is_some(), consumed);
                if consumed {
                    // F's own justification, by the outgoing set 8, cannot be
                    // checked under set 9; the verified fragment is the evidence.
                    let f_set = Justification::decode(params, &f_proof, limits.proof)
                        .unwrap()
                        .set_id();
                    assert_eq!(f_set, 8);
                    // The fragment's signed root is the one the join reads against.
                    assert_eq!(w.next_read().unwrap().root, f_root);
                    let mut other = Warp::new(&s);
                    other.last_final = w.last_final;
                    other.authorities = w.authorities.clone();
                    let mut different = f.clone();
                    different.seal[0] ^= 1;
                    other.final_head = Some(final_of(params, &different));
                    other
                        .receive_headers(params, vec![block(different)], s.header_bytes)
                        .unwrap();
                    assert!(
                        other.finalized.is_none(),
                        "same slot is not the same finalized target"
                    );
                    assert!(other.next_read().is_err());
                } else {
                    assert!(w.next_read().is_err());
                    let before = w.authorities.clone();
                    let mut bad = f_proof.clone();
                    bad[90] ^= 1;
                    assert!(w.authenticate(params, &bad, limits.proof).is_err());
                    assert_eq!(w.authorities, before);
                    assert!(w.finalized.is_none());
                    w.authenticate(params, &f_proof, limits.proof).unwrap();
                    assert_eq!(w.next_read().unwrap().root, f_root);
                }
                assert_eq!(w.authorities.set_id(), 9);
                assert_eq!(w.authorities.current(), vec![a; 6]);
                assert_eq!(w.authorities.next(), next);
                assert!(
                    w.authenticate(params, &f_proof, limits.proof).is_err(),
                    "cannot consume F twice"
                );
                w.items = state_items("finalized_state_items");
                if tree_full {
                    s.tree_config.max_bytes = 1;
                    assert!(s.apply_warp(0, w).is_err());
                    assert_eq!(s.tree.finalized(), &original_root);
                    assert_eq!(s.authorities, original_authorities);
                    assert_eq!(s.warp_revision, 0);
                    assert!(!follower.new_blocks.is_closed());
                    continue;
                }
                s.apply_warp(0, w).unwrap();
                assert!(follower.new_blocks.is_closed());
                assert_eq!(s.tree.finalized().hash(), f.hash(params));
                assert_eq!(s.authorities.set_id(), 9);
                assert_eq!(s.authorities.current(), vec![a; 6]);
                assert_eq!(s.authorities.next(), next);
                s.insert(child.clone(), 1_900_000_000).unwrap();
                s.finalize(child.hash(params), &child_proof).unwrap();
                assert_eq!(s.tree.finalized().hash(), child.hash(params));
                assert_eq!(s.authorities.set_id(), 9);
            }
        }
    });
}

/// How the first peer fails a warp join.
#[derive(Clone, Copy, Debug, PartialEq)]
enum JoinFailure {
    BadStateProof,
    BadJustification,
    /// A valid justification for F that signs another posterior root: the
    /// served state cannot be proven against it.
    WrongRoot,
    ProofNoData,
    StateTransient,
    TamperedWarp,
    WarpRateLimited,
}

#[test]
fn failed_joins_release_the_warp_to_another_peer() {
    smol::block_on(async {
        use JoinFailure::*;
        for failure in [
            BadStateProof,
            BadJustification,
            WrongRoot,
            ProofNoData,
            StateTransient,
            TamperedWarp,
            WarpRateLimited,
        ] {
            let (bad, mut config, _, f) = join_setup();
            let (good, _, _, _) = join_setup();
            let params = config.params.clone();
            let peer = config.peers.remove(0);
            let wrong_root = if failure == WrongRoot {
                let (keys, public) = grandpa_key(42).await;
                let commit = (final_of(&params, &f), [0xee; 32]);
                let proof =
                    single_vote_justification((&keys, public), (1, 3), commit, &[], &params);
                Some(framed(proof.await))
            } else {
                None
            };
            {
                let mut c = bad.0.lock().unwrap();
                let f_hash = f.hash(&params);
                match failure {
                    BadStateProof => {
                        let Ok(frame) = c.io.state_responses.front_mut().unwrap() else {
                            unreachable!()
                        };
                        *frame.last_mut().unwrap() ^= 1;
                    }
                    BadJustification => c.io.proofs.get_mut(&f_hash).unwrap()[90] ^= 1,
                    WrongRoot => drop(c.io.proofs.insert(f_hash, wrong_root.unwrap())),
                    ProofNoData => {
                        c.io.proof_resets
                            .push_back(Reset(Some(6), "no advertised proof"))
                    }
                    StateTransient => c.io.state_responses[0] = Err(Reset(Some(4), "too soon")),
                    TamperedWarp => c.io.bad_warp_once = true,
                    WarpRateLimited => c.io.warp_resets.push_back(Reset(Some(4), "rate limited")),
                }
            }
            let state = driver_state(config);
            state.lock().await.peer_count = 2;
            let root = state.lock().await.tree.finalized().clone();
            let follow = state.lock().await.subscribe(16, false);
            // A rate limit ends the connection before the warp is released.
            let rate_limited = failure == WarpRateLimited;
            let released = async {
                yield_until(async || {
                    !bad.0.lock().unwrap().io.warp_requests.is_empty()
                        && state.lock().await.warp_owner.is_none()
                        && (!rate_limited || !logged(&bad, "jam-reconnect").is_empty())
                })
                .await;
                if rate_limited {
                    assert_eq!(bad.0.lock().unwrap().io.live_connections, 0);
                }
            };
            let bad_peer = peer_loop(&bad, "join-bad", &peer, 0, &params, state.clone());
            let what = alloc::format!("release of the bad join, {failure:?}");
            within(10, &what, future::or(bad_peer, released)).await;
            assert_eq!(state.lock().await.tree.finalized(), &root);
            assert_eq!(state.lock().await.warp_revision, 0);
            assert!(!follow.new_blocks.is_closed());
            {
                let c = bad.0.lock().unwrap();
                assert_eq!(c.attempts, 1);
                if [BadJustification, ProofNoData, TamperedWarp, WarpRateLimited].contains(&failure)
                {
                    assert!(
                        c.io.state_requests.is_empty(),
                        "root must not be trusted before CE130"
                    );
                }
                if [TamperedWarp, WarpRateLimited].contains(&failure) {
                    assert_eq!(c.io.warp_requests, [0]);
                    assert!(c.requests.is_empty(), "no warp tail or ordinary sync");
                }
            }
            match failure {
                TamperedWarp => assert!(!logged(&bad, "jam-warp-rejected").is_empty()),
                WarpRateLimited => {
                    let rejected = logged(&bad, "jam-warp-rejected");
                    assert!(rejected.iter().any(|f| f["reason"] == "Transient"));
                    assert_reset_log(&bad, "rate limited", "Transient");
                }
                _ => (),
            }
            let driver = drive_scripted(&good, &params, &state, 1, 64);
            let joined = yield_until(async || state.lock().await.warp_revision != 0);
            let what = alloc::format!("healthy join, {failure:?}");
            while_driving(10, &what, driver, joined).await;
            assert!(follow.new_blocks.is_closed());
            assert!(!state.lock().await.stopped);
            assert!(!logged(&good, "jam-warp-applied").is_empty());
            assert_eq!(good.0.lock().unwrap().io.state_requests.len(), 4);
        }
    });
}

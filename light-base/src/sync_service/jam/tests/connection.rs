// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Configuration, subscriptions, connections and header sync through the driver.

use super::*;

/// Verifies `header` against the retained parent it names and inserts it, as
/// the driver does.
fn verify_and_insert(
    tree: &mut HeaderTree,
    header: Header,
    now: u64,
) -> Result<tree::Insert, tree::InsertError> {
    match tree.verify(header.parent, header, now)? {
        tree::VerifySuccess::AlreadyKnown => Ok(tree::Insert::AlreadyKnown),
        tree::VerifySuccess::Verified(verified) => tree.insert_verified(verified),
    }
}

#[test]
fn snapshot_excludes_root_and_refuses_runtime_and_excess_subscribers() {
    let mut state = root_state();
    let snapshot = state.subscribe(0, false);
    assert!(snapshot.non_finalized_blocks_ancestry_order.is_empty());
    assert_eq!(
        blake2b_256(&snapshot.finalized_block_scale_encoded_header),
        state.tree.finalized().hash()
    );
    assert!(snapshot.finalized_block_runtime.is_none());
    assert_eq!(snapshot.new_blocks.capacity(), Some(1));
    assert!(state.subscribe(usize::MAX, true).new_blocks.is_closed());
    let mut retained = vec![snapshot];
    for _ in 1..MAX_SUBSCRIBERS {
        retained.push(state.subscribe(usize::MAX, false));
    }
    assert!(state.subscribe(1, false).new_blocks.is_closed());
    state.stopped = true;
    assert!(state.subscribe(1, false).new_blocks.is_closed());
}

#[test]
fn invalid_header_does_not_change_anchor_or_notify() {
    let mut state = root_state();
    let snapshot = state.subscribe(1, false);
    let root = state.tree.finalized().clone();
    let mut child = Header::decode(&state.params, root.encoded()).unwrap();
    child.parent = root.hash();
    child.slot = 1;
    assert!(state.insert(child, u64::MAX).is_err());
    assert_eq!(state.tree.len(), 1);
    assert_eq!(state.tree.finalized(), &root);
    assert!(snapshot.new_blocks.try_recv().is_err());
}

/// A client with one JAM chain, and that chain's JSON-RPC responses.
struct RpcClient {
    client: Client<FakePlatform>,
    chain: crate::ChainId,
    responses: crate::JsonRpcResponses<FakePlatform>,
}

impl RpcClient {
    fn new(platform: &FakePlatform, spec: &str) -> Self {
        let mut client = Client::new(platform.clone());
        let added = add_chain(&mut client, spec, true).unwrap();
        Self {
            client,
            chain: added.chain_id,
            responses: added.json_rpc_responses.unwrap(),
        }
    }

    async fn next(&mut self) -> Value {
        let responses = &mut self.responses;
        let text = within(10, "RPC", async {
            responses.next().await.expect("RPC ended")
        })
        .await;
        serde_json::from_str(&text).unwrap()
    }

    /// Sends a request and returns its reply, which must come before any
    /// notification.
    async fn call(&mut self, method: &str, params: Value) -> Value {
        let request = json!({"jsonrpc":"2.0", "id":2, "method":method, "params":params});
        self.client
            .json_rpc_request(request.to_string(), self.chain)
            .unwrap();
        let reply = self.next().await;
        assert_eq!(reply["id"], 2, "unexpected notification: {reply}");
        reply
    }

    /// Follows the chain and checks its root-only snapshot at `finalized`;
    /// returns the subscription id.
    async fn follow(&mut self, finalized: Hash) -> String {
        let id = self.call("jamHead_unstable_follow", json!([])).await["result"]
            .as_str()
            .unwrap()
            .to_owned();
        let initialized = self.next().await;
        assert_eq!(initialized["params"]["subscription"], id);
        assert_eq!(
            initialized["params"]["result"],
            json!({"event":"initialized", "finalizedBlockHashes":[prefixed(finalized)]})
        );
        assert_eq!(
            self.next().await["params"]["result"],
            json!({"event":"bestBlockChanged", "bestBlockHash":prefixed(finalized)})
        );
        id
    }

    /// Checks the `newBlock` and `bestBlockChanged` events of `header`.
    async fn new_best(&mut self, id: &str, params: &Params, header: &Header) {
        let hash = prefixed(header.hash(params));
        let block = self.next().await;
        assert_eq!(block["params"]["subscription"], id);
        assert_eq!(block["params"]["result"]["event"], "newBlock");
        assert_eq!(block["params"]["result"]["blockHash"], hash);
        assert_eq!(
            block["params"]["result"]["parentBlockHash"],
            prefixed(header.parent)
        );
        assert_eq!(block["params"]["result"]["slot"], header.slot);
        assert_eq!(
            self.next().await["params"]["result"],
            json!({"event":"bestBlockChanged", "bestBlockHash":hash})
        );
    }

    /// Removes the chain; its JSON-RPC responses must end.
    async fn remove(mut self) {
        let () = self.client.remove_chain(self.chain);
        assert!(self.responses.next().await.is_none());
    }
}

/// The hash of a block notification.
fn block_hash(notification: &Notification) -> Option<Hash> {
    match notification {
        Notification::Block(block) => Some(blake2b_256(&block.scale_encoded_header)),
        _ => None,
    }
}

/// Every task, connection and stream of `platform` has ended.
fn torn_down(platform: &FakePlatform) -> bool {
    let c = platform.0.lock().unwrap();
    c.io.live_tasks == 0 && c.io.live_connections == 0 && c.io.live_streams == 0
}

#[test]
fn external_frames_add_chain_follow_header_unpin_unfollow_and_reconnect() {
    smol::block_on(async {
        let (platform, spec, hash, header) = fixture_setup();
        platform.0.lock().unwrap().fail_first = true;
        assert_eq!(blake2b_256(&header), hash);
        let parsed = parse(&spec);
        let params = parsed.params();
        let mut rpc = RpcClient::new(&platform, &spec);
        let id = rpc.follow(parsed.genesis_header().hash(params)).await;
        let decoded = Header::decode(params, &header).unwrap();
        rpc.new_best(&id, params, &decoded).await;
        let hash = prefixed(hash);
        assert_eq!(
            rpc.call("jamHead_unstable_header", json!([id, hash])).await["result"],
            prefixed(&header)
        );
        for (method, params) in [
            ("chainHead_v1_follow", json!([false])),
            ("system_health", json!([])),
            ("lifecycle_unstable_follow", json!([])),
        ] {
            assert_eq!(rpc.call(method, params).await["error"]["code"], -32601);
        }
        // A JAM chain has no runtime to ask for.
        assert_eq!(
            rpc.call("jamHead_unstable_follow", json!([true])).await["error"]["code"],
            -32602
        );
        let unpinned = rpc
            .call("jamHead_unstable_unpin", json!([id, [hash]]))
            .await;
        assert!(unpinned["result"].is_null());
        assert_eq!(
            rpc.call("jamHead_unstable_header", json!([id, hash])).await["error"]["code"],
            -32801
        );
        assert!(rpc.call("jamHead_unstable_unfollow", json!([id])).await["result"].is_null());
        assert_eq!(platform.0.lock().unwrap().attempts, 2);
        // A known-parent announcement must not depend on CE128/body availability.
        assert_eq!(platform.0.lock().unwrap().requests.len(), 0);
        let config = Config::from_spec(&parsed).unwrap();
        let expected = jam_webtransport_cert::certificate_hashes(
            &config.peers[0].identity,
            platform.now_from_unix_epoch().as_secs(),
        );
        let pins = platform.0.lock().unwrap().pins.clone();
        assert!(pins.iter().all(|pins| pins == &expected));
        assert!(rpc.client.lifecycle_state(rpc.chain).next().await.is_none());
        rpc.remove().await;
    });
}

#[test]
fn conservative_full_network_and_oversized_parameter_budgets() {
    let mut params = root_config().params;
    params.epoch_len = 600;
    params.max_validators = 1023;
    let (header, limits) = memory_limits(&params).unwrap();
    let state = 600 * 160 + 1023 * 256 + 2048;
    assert!(limits.max_blocks.get() >= 2048);
    assert!(limits.max_bytes * 2 + header + state <= TREE_BYTES);
    let epoch = smoldot::jam::state::EpochState {
        active: vec![([0; 32], [0; 32]); 1023],
        pending: vec![([0; 32], [0; 32]); 1023],
        sealing: SealingSequence::Keys(vec![[0; 32]; 600]),
        history: [[0; 32]; 3],
    };
    let record =
        core::mem::size_of_val(&epoch) + 2 * core::mem::size_of::<usize>() + 2046 * 64 + 600 * 32;
    assert!(2048 * HeaderTree::node_overhead() + record <= limits.max_bytes);
    let anchor = Header::decode(&params, root_config().tree.finalized().encoded()).unwrap();
    let root = verified_genesis(
        &params,
        anchor.clone(),
        LightState::from_parts(
            [[0; 32]; 4],
            epoch.active,
            epoch.pending,
            epoch.sealing,
            None,
            0,
        ),
    );
    let mut tree = HeaderTree::new(params.clone(), root.clone(), limits).unwrap();
    for i in 0u32..2048 {
        let mut header = anchor.clone();
        header.parent = root.hash();
        header.slot = 1;
        header.extrinsic_hash[..4].copy_from_slice(&i.to_le_bytes());
        let block = assume_verified(&params, &header, root.post_state().clone());
        tree.insert_verified(block).unwrap();
    }
    assert_eq!(tree.len(), 2049);
    assert_eq!(tree.epoch_records(), 1);
    assert!(tree.retained_bytes() <= limits.max_bytes);
    params.epoch_len = u32::MAX;
    assert!(memory_limits(&params).is_err());
}

#[test]
fn a_subscription_with_runtime_interest_gets_a_closed_channel() {
    smol::block_on(async {
        let service =
            JamSyncService::new(platform(Control::default()), "test".into(), root_config());
        assert!(service.subscribe_all(1, true).await.new_blocks.is_closed());
        assert!(!service.subscribe_all(1, false).await.new_blocks.is_closed());
    });
}

#[test]
fn external_untrusted_finality_catches_up_oldest_first_and_stops_slow_followers() {
    smol::block_on(async {
        let (platform, spec, _, _) = fixture_setup();
        let parsed = parse(&spec);
        let params = parsed.params();
        let headers: Vec<_> = (0..36).map(|index| fixture_header(params, index)).collect();
        let hashes: Vec<_> = headers.iter().map(|h| h.hash(params)).collect();
        {
            let mut c = platform.0.lock().unwrap();
            for header in &headers[1..] {
                c.responses
                    .insert(header.hash(params), framed(header.encode(params)));
            }
            c.handshake = handshake_frame(final_of(params, &headers[35]), Vec::new());
        }
        let config = Config::from_spec(&parsed).unwrap();
        let service = JamSyncService::new(platform.clone(), "catchup".into(), config);
        let initial = service.subscribe_all(1, false).await;
        assert!(initial.non_finalized_blocks_ancestry_order.is_empty());
        until(|| initial.new_blocks.is_closed()).await;
        let block = within(10, "catchup", initial.new_blocks.recv()).await;
        assert_eq!(block_hash(&block.unwrap()), Some(hashes[0]));
        assert!(initial.new_blocks.recv().await.is_err());
        // Replay is cooperative: closing the slow subscriber does not mean the
        // remaining ancestry is already inserted.
        let snapshot = within(10, "replay of the remaining ancestry", async {
            loop {
                let snapshot = service.subscribe_all(16, false).await;
                if snapshot.non_finalized_blocks_ancestry_order.len() == 36 {
                    break snapshot;
                }
                future::yield_now().await;
            }
        })
        .await;
        assert_eq!(
            snapshot.finalized_block_scale_encoded_header,
            initial.finalized_block_scale_encoded_header
        );
        let blocks = snapshot.non_finalized_blocks_ancestry_order;
        let replayed: Vec<_> = blocks
            .iter()
            .map(|b| blake2b_256(&b.scale_encoded_header))
            .collect();
        assert_eq!(replayed, hashes);
        assert!(blocks.last().unwrap().is_new_best);
        // Batches double: 1, 2, 4, 8, 16 and 32 blocks.
        let requested: Vec<_> = platform
            .0
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|r| r.hash)
            .collect();
        let genesis = parsed.genesis_header().hash(params);
        let starts = [
            genesis, hashes[0], hashes[2], hashes[6], hashes[14], hashes[30],
        ];
        assert_eq!(requested, starts);
    });
}

#[test]
fn external_verified_tree_memory_and_full_preserve_fixed_anchor() {
    let (_, spec, _, _) = fixture_setup();
    let parsed = parse(&spec);
    let mut s = state(Config::from_spec(&parsed).unwrap());
    for index in 0..36 {
        s.insert(fixture_header(&s.params, index), 1_800_000_000)
            .unwrap();
    }
    assert!(s.tree.retained_bytes() * 2 < TREE_BYTES);
    let anchor = s.tree.finalized().clone();
    let mut full = state(Config::from_spec(&parsed).unwrap());
    let limits = tree::Config {
        max_blocks: NonZeroUsize::new(2).unwrap(),
        max_bytes: usize::MAX,
        max_epoch_records: NonZeroUsize::new(8).unwrap(),
    };
    full.tree = HeaderTree::new(full.params.clone(), anchor.clone(), limits).unwrap();
    let snapshot = full.subscribe(16, false);
    let [first, second] = [0, 1].map(|index| fixture_header(&full.params, index));
    full.insert(first, 1_800_000_000).unwrap();
    assert!(full.insert(second, 1_800_000_000).is_err());
    assert!(full.stopped && snapshot.new_blocks.is_closed());
    assert!(matches!(
        snapshot.new_blocks.try_recv(),
        Ok(Notification::Block(_))
    ));
    assert!(snapshot.new_blocks.try_recv().is_err());
    assert_eq!(full.tree.finalized(), &anchor);
    assert!(full.subscribe(16, false).new_blocks.is_closed());
}

#[test]
fn external_invalid_identity_is_propagated_before_startup_and_capability_is_guarded() {
    smol::block_on(async {
        let (platform, raw, _, _) = fixture_setup();
        let mut spec: Value = serde_json::from_str(&raw).unwrap();
        spec["bootnodes_p256"] = json!([alloc::format!("v{}b@127.0.0.1:4433", "7".repeat(51))]);
        // The text is valid, but X = 2^256 - 1 is outside the P-256 field.
        let invalid = spec.to_string();
        parse(&invalid);
        let mut client = Client::new(platform.clone());
        let error = add_chain(&mut client, &invalid, false).err().unwrap();
        assert!(
            error.to_string().contains("bootnodes_p256 entry 0"),
            "{error}"
        );
        assert_eq!(platform.0.lock().unwrap().attempts, 0);
        // The client dials only `bootnodes_p256`, never an Ed25519 `bootnodes` entry.
        spec["bootnodes_p256"] = json!([]);
        spec["bootnodes"] = json!([alloc::format!("e{}@127.0.0.1:4433", "a".repeat(52))]);
        let ed_only = spec.to_string();
        assert!(
            Config::from_spec(&parse(&ed_only))
                .unwrap()
                .peers
                .is_empty()
        );
        let added = add_chain(&mut client, &ed_only, false).unwrap();
        smol::Timer::after(Duration::from_millis(10)).await;
        assert_eq!(platform.0.lock().unwrap().attempts, 0);
        let () = client.remove_chain(added.chain_id);
        platform.0.lock().unwrap().supported = false;
        let added = add_chain(&mut client, &raw, false).unwrap();
        smol::Timer::after(Duration::from_millis(10)).await;
        assert_eq!(platform.0.lock().unwrap().attempts, 0);
        let () = client.remove_chain(added.chain_id);
    });
}

fn fixture_header(params: &Params, index: usize) -> Header {
    Header::decode(
        params,
        &bytes(&fixture(&alloc::format!("headers/{index:04}.json"))["header_hex"]),
    )
    .unwrap()
}

#[test]
fn external_missing_parent_announcement_retained_and_captured_ce128_used() {
    smol::block_on(async {
        let (platform, spec, first_hash, _) = fixture_setup();
        let parsed = parse(&spec);
        let params = parsed.params();
        let child = fixture_header(params, 1);
        let child_hash = child.hash(params);
        let mut frames = bytes(&fixture("messages/up0.json")["handshake_frame_hex"]);
        let genesis = final_of(params, parsed.genesis_header());
        frames.extend(announcement_frame(params, child, genesis));
        platform.0.lock().unwrap().handshake = frames;
        let service = sync_service(&platform, &parsed);
        let snapshot = service.subscribe_all(16, false).await;
        until(|| platform.0.lock().unwrap().requests.len() == 1).await;
        let mut initial = snapshot.non_finalized_blocks_ancestry_order.into_iter();
        for expected in [first_hash, child_hash] {
            let notification = match initial.next() {
                Some(block) => Notification::Block(block),
                None => received("ancestor notification", &snapshot.new_blocks).await,
            };
            assert_eq!(block_hash(&notification), Some(expected));
        }
        let requested: Vec<_> = platform
            .0
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|r| r.hash)
            .collect();
        assert_eq!(requested, [first_hash]);
    });
}

#[test]
fn external_established_disconnect_reconnect_catches_up_without_finalizing() {
    smol::block_on(async {
        let (platform, spec, first_hash, _) = fixture_setup();
        let parsed = parse(&spec);
        let params = parsed.params();
        let service = sync_service(&platform, &parsed);
        let snapshot = service.subscribe_all(16, false).await;
        let first = received("initial sync", &snapshot.new_blocks).await;
        assert_eq!(block_hash(&first), Some(first_hash));
        let [second, third] = [1, 2].map(|index| fixture_header(params, index));
        {
            let mut c = platform.0.lock().unwrap();
            serve(&mut c, params, &second);
            serve(&mut c, params, &third);
            c.handshake = handshake_frame(final_of(params, &third), Vec::new());
            c.disconnect = true;
        }
        for header in [&second, &third] {
            let notification = received("reconnect catch-up", &snapshot.new_blocks).await;
            assert_eq!(block_hash(&notification), Some(header.hash(params)));
        }
        {
            let c = platform.0.lock().unwrap();
            assert_eq!(c.attempts, 2);
            let requested: Vec<_> = c.requests.iter().map(|r| r.hash).collect();
            assert_eq!(requested, [first_hash, second.hash(params)]);
        }
        assert_eq!(
            service
                .subscribe_all(1, false)
                .await
                .finalized_block_scale_encoded_header,
            snapshot.finalized_block_scale_encoded_header
        );
    });
}

#[test]
fn external_queued_request_and_unidentified_streams_cannot_starve_deadlines() {
    smol::block_on(async {
        let (platform, spec, hash, _) = fixture_setup();
        let parsed = parse(&spec);
        let header = fixture_header(parsed.params(), 0);
        {
            let mut c = platform.0.lock().unwrap();
            c.handshake = handshake_frame(final_of(parsed.params(), &header), Vec::new());
            c.starve = true;
        }
        let service = sync_service(&platform, &parsed);
        let snapshot = service.subscribe_all(16, false).await;
        until(|| platform.0.lock().unwrap().queued).await;
        {
            let mut c = platform.0.lock().unwrap();
            assert_eq!(
                c.requests.len(),
                0,
                "CE must still be queued behind the unidentified streams"
            );
            c.clock_shift = Duration::from_secs(21);
            c.starve = false;
        }
        until(|| platform.0.lock().unwrap().attempts >= 2).await;
        assert_eq!(
            service
                .subscribe_all(1, false)
                .await
                .finalized_block_scale_encoded_header,
            snapshot.finalized_block_scale_encoded_header
        );
        let notification = received("sync after the timeout", &snapshot.new_blocks).await;
        assert_eq!(block_hash(&notification), Some(hash));
    });
}

#[test]
fn external_genesis_and_checkpoint_configs_use_complete_anchor_state() {
    let (_, raw, _, _) = fixture_setup();
    let genesis_spec = parse(&raw);
    let genesis_config = Config::from_spec(&genesis_spec).unwrap();
    assert_eq!(
        *genesis_config.tree.finalized().post_state(),
        LightState::from_anchor(genesis_spec.params(), genesis_spec.genesis_light_state()).unwrap(),
    );
    for (case, index) in checkpoint_cases(genesis_spec.params())
        .into_iter()
        .enumerate()
    {
        let parsed = parse(&with_checkpoint(&raw, index).to_string());
        let checkpoint = parsed.checkpoint().unwrap();
        let fixture = fixture(&alloc::format!("headers/{index:04}.json"));
        let raw_state = raw_fixture_state(parsed.params(), &fixture["post_light_state"]);
        assert_eq!(checkpoint.state, raw_state);
        let config = Config::from_spec(&parsed).unwrap();
        assert_eq!(
            *config.tree.finalized().post_state(),
            LightState::from_anchor(parsed.params(), &raw_state).unwrap(),
            "fixture {index:04}",
        );
        assert_eq!(
            Header::decode(&config.params, config.tree.finalized().encoded()).unwrap(),
            checkpoint.header
        );
        assert_eq!(config.tree.len(), 1);
        let params = parsed.params();
        let epoch_len = usize::try_from(params.epoch_len).unwrap();
        let tail = raw_state.slot % params.epoch_len >= params.epoch_tail_start;
        let accumulated = &raw_state.safrole.ticket_accumulator;
        let pending = config.tree.finalized().post_state().pending_tickets();
        match case {
            0 => assert!(tail && accumulated.len() < epoch_len && pending.is_none()),
            1 => assert!(!tail && accumulated.len() == epoch_len && pending.is_none()),
            2 => {
                assert_eq!(accumulated.len(), epoch_len);
                assert!(accumulated.windows(2).all(|pair| pair[0].id < pair[1].id));
                // The captured winners mark is already sequenced. The driver
                // passes the raw accumulator to the light state without applying
                // Z itself.
                let winners = (0..=index)
                    .rev()
                    .find_map(|i| {
                        let header = fixture_header(params, i);
                        (header.slot / params.epoch_len == raw_state.slot / params.epoch_len)
                            .then_some(header.tickets_mark)
                            .flatten()
                    })
                    .expect("captured winners mark in checkpoint epoch");
                assert_eq!(pending, Some(winners.as_slice()));
                assert_ne!(&winners, accumulated);
            }
            _ => unreachable!(),
        }
    }
}

fn raw_fixture_state(params: &Params, fixture: &Value) -> GenesisLightState {
    let items: Vec<([u8; 31], Vec<u8>)> = fixture["state_items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                bytes(&item["key_hex"]).try_into().unwrap(),
                bytes(&item["value_hex"]),
            )
        })
        .collect();
    GenesisLightState::from_state_items(
        params,
        items.iter().map(|(key, value)| (key, value.as_slice())),
    )
    .unwrap()
}

#[test]
fn external_tail_checkpoint_tree_replays_complete_ticket_epoch() {
    let (_, raw, _, _) = fixture_setup();
    let anchor_index = checkpoint_cases(parse(&raw).params())[2];
    let parsed = parse(&with_checkpoint(&raw, anchor_index).to_string());
    let epoch_len = usize::try_from(parsed.params().epoch_len).unwrap();
    let mut config = Config::from_spec(&parsed).unwrap();
    let anchor = config.tree.finalized().clone();
    let mut reference = verified_genesis(
        parsed.params(),
        parsed.genesis_header().clone(),
        LightState::from_anchor(parsed.params(), parsed.genesis_light_state()).unwrap(),
    );
    for index in 0..=anchor_index {
        reference = smoldot::jam::verify::verify_header(
            parsed.params(),
            &reference,
            fixture_header(parsed.params(), index),
            1_800_000_000,
        )
        .unwrap();
    }
    assert_eq!(anchor.hash(), reference.hash());
    assert_eq!(anchor.post_state(), reference.post_state());
    for index in anchor_index + 1..=anchor_index + epoch_len {
        let fixture = fixture(&alloc::format!("headers/{index:04}.json"));
        let header = fixture_header(parsed.params(), index);
        reference = smoldot::jam::verify::verify_header(
            parsed.params(),
            &reference,
            header.clone(),
            1_800_000_000,
        )
        .unwrap();
        verify_and_insert(&mut config.tree, header, 1_800_000_000).unwrap();
        let block = config.tree.get(&reference.hash()).unwrap();
        assert_eq!(block, &reference, "header {index:04}");
        assert!(block.sealed_with_ticket(), "header {index:04}");
        assert_eq!(block.hash().as_slice(), bytes(&fixture["header_hash"]));
        assert_eq!(
            *block.post_state(),
            LightState::from_anchor(
                parsed.params(),
                &raw_fixture_state(parsed.params(), &fixture["post_light_state"])
            )
            .unwrap()
        );
        assert_eq!(config.tree.finalized(), &anchor);
    }
    assert_eq!(config.tree.len(), epoch_len + 1);
}

#[test]
fn external_oversized_anchor_accumulator_preserves_constructor_and_parser_errors() {
    let (platform, raw, _, _) = fixture_setup();
    let mut spec = with_checkpoint(&raw, checkpoint_cases(parse(&raw).params())[2]);
    let parsed = parse(&spec.to_string());
    let mut raw_state = parsed.checkpoint().unwrap().state.clone();
    raw_state
        .safrole
        .ticket_accumulator
        .push(raw_state.safrole.ticket_accumulator[0].clone());
    assert_eq!(
        LightState::from_anchor(parsed.params(), &raw_state),
        Err(smoldot::jam::state::StateError::TicketAccumulatorTooLong)
    );
    assert!(matches!(
        Config::anchor_state(parsed.params(), &raw_state),
        Err(ConfigError::StartingState(
            smoldot::jam::state::StateError::TicketAccumulatorTooLong
        ))
    ));
    // The spec parser checks the same bound first, so `add_chain` reports the
    // parser's error.
    spec["checkpoint"]["state"]["safrole"] =
        json!(hex::encode(raw_state.safrole.encode(parsed.params())));
    let error = rejected_add_chain_without_startup(&platform, &spec.to_string());
    assert!(matches!(error, ConfigError::Spec(_)), "{error}");
    assert!(
        error.to_string().contains("checkpoint.state.safrole"),
        "{error}"
    );
}

// A capture starts wherever the wall clock is in the epoch, so the three
// checkpoint shapes are found from the post-states, not by file number.
fn checkpoint_cases(params: &Params) -> [usize; 3] {
    let headers: Vec<_> = (0..36)
        .map(|i| fixture(&alloc::format!("headers/{i:04}.json")))
        .collect();
    let epoch_len = usize::try_from(params.epoch_len).unwrap();
    let states: Vec<_> = headers
        .iter()
        .map(|h| raw_fixture_state(params, &h["post_light_state"]))
        .collect();
    let incomplete_tail = states
        .iter()
        .position(|state| {
            state.slot % params.epoch_len >= params.epoch_tail_start
                && state.safrole.ticket_accumulator.len() < epoch_len
        })
        .expect("capture needs a non-saturated tail checkpoint");
    let saturated_before_tail = states
        .iter()
        .position(|state| {
            state.slot % params.epoch_len < params.epoch_tail_start
                && state.safrole.ticket_accumulator.len() == epoch_len
        })
        .expect("capture needs a saturated pre-tail checkpoint");
    let saturated_tail = states
        .iter()
        .enumerate()
        .find_map(|(i, state)| {
            (state.slot % params.epoch_len == params.epoch_len - 1
                && state.safrole.ticket_accumulator.len() == epoch_len
                && headers.get(i + 1..i + 1 + epoch_len).is_some_and(|epoch| {
                    epoch.iter().enumerate().all(|(offset, h)| {
                        h["seal_mode"] == "ticket"
                            && h["slot"].as_u64().unwrap()
                                == u64::from(state.slot) + 1 + u64::try_from(offset).unwrap()
                    })
                }))
            .then_some(i)
        })
        .expect("capture needs a tail checkpoint followed by a complete ticket epoch");
    [incomplete_tail, saturated_before_tail, saturated_tail]
}

/// The spec `raw` with a checkpoint at captured header `index`.
fn with_checkpoint(raw: &str, index: usize) -> Value {
    let mut spec: Value = serde_json::from_str(raw).unwrap();
    spec["checkpoint"] = checkpoint_fixture(index);
    spec
}

fn checkpoint_fixture(index: usize) -> Value {
    let checkpoint = fixture(&alloc::format!("headers/{index:04}.json"));
    let items = checkpoint["post_light_state"]["state_items"]
        .as_array()
        .unwrap();
    let item =
        |index: u8| items.iter().find(|item| item["index"] == index).unwrap()["value_hex"].clone();
    json!({"header":checkpoint["header_hex"], "state":{"safrole":item(4),"entropy":item(6),"active_validators":item(8),"slot":item(11)}})
}

#[test]
fn external_malformed_genesis_and_checkpoint_state_errors_are_propagated() {
    for checkpoint in [false, true] {
        let (platform, raw, _, _) = fixture_setup();
        let mut spec: Value = serde_json::from_str(&raw).unwrap();
        let expected_field = if checkpoint {
            spec = with_checkpoint(&raw, 13);
            spec["checkpoint"]["state"]["slot"] = json!("00");
            "checkpoint.state.slot"
        } else {
            let key = hex::encode(smoldot::jam::codec::state_key(11));
            spec["genesis_state"][key] = json!("00");
            "genesis_state.slot"
        };
        let error = rejected_add_chain_without_startup(&platform, &spec.to_string());
        assert!(matches!(error, ConfigError::Spec(_)), "{error}");
        assert!(error.to_string().contains(expected_field), "{error}");
    }
}

fn event_driven_fixture(
    executor: &Arc<smol::Executor<'static>>,
    peers: usize,
) -> (FakePlatform, String, Vec<Header>) {
    let (platform, spec, _, _) = fixture_setup();
    let parsed = parse(&spec);
    let params = parsed.params();
    let headers: Vec<_> = (0..36).map(|index| fixture_header(params, index)).collect();
    {
        let mut c = platform.0.lock().unwrap();
        c.io.event_driven = true;
        c.io.executor = Some(executor.clone());
        for header in &headers[1..] {
            c.responses
                .insert(header.hash(params), framed(header.encode(params)));
        }
        c.handshake = handshake_frame(final_of(params, &headers[35]), Vec::new());
    }
    let mut spec: Value = serde_json::from_str(&spec).unwrap();
    let first = spec["bootnodes_p256"][0].as_str().unwrap();
    let identity = first.split_once('@').unwrap().0.to_owned();
    spec["bootnodes_p256"] = json!(
        (0..peers)
            .map(|index| alloc::format!("{identity}@127.0.0.1:{}", 4433 + index))
            .collect::<Vec<_>>()
    );
    (platform, spec.to_string(), headers)
}

#[test]
fn external_active_rpc_survives_large_catchup_with_one_and_two_event_driven_peers() {
    for peers in [1, 2] {
        event_driven(move |executor| async move {
            let (platform, spec, headers) = event_driven_fixture(&executor, peers);
            let parsed = parse(&spec);
            let params = parsed.params();
            let mut rpc = RpcClient::new(&platform, &spec);
            let id = rpc.follow(parsed.genesis_header().hash(params)).await;
            for header in &headers {
                rpc.new_best(&id, params, header).await;
            }
            // A reply, not a duplicate or a stop event, follows the catch-up.
            let tip = headers.last().unwrap();
            let reply = rpc
                .call(
                    "jamHead_unstable_header",
                    json!([id, prefixed(tip.hash(params))]),
                )
                .await;
            assert_eq!(reply["result"], prefixed(tip.encode(params)));
            until(|| {
                let c = platform.0.lock().unwrap();
                c.io.pending_waits != 0 && c.io.live_streams == peers
            })
            .await;
            {
                let c = platform.0.lock().unwrap();
                assert_eq!(c.attempts, peers);
                assert!(c.requests.len() >= 6);
                assert!(
                    c.requests
                        .iter()
                        .all(|request| (1..=64).contains(&request.max_blocks)
                            && request.direction == Direction::AscendingExclusive)
                );
                assert_eq!(c.io.live_connections, peers);
                assert_eq!(
                    c.io.live_streams, peers,
                    "completed CE128 streams must be retired"
                );
            }
            rpc.remove().await;
            until(|| torn_down(&platform)).await;
        });
    }
}

#[test]
fn external_coalesced_up0_frames_progress_without_fresh_readiness_edges() {
    event_driven(|executor| async move {
        let (platform, spec, headers) = event_driven_fixture(&executor, 1);
        let parsed = parse(&spec);
        let params = parsed.params();
        let root = final_of(params, parsed.genesis_header());
        let mut frames = bytes(&fixture("messages/up0.json")["handshake_frame_hex"]);
        for header in &headers {
            frames.extend(announcement_frame(params, header.clone(), root.clone()));
        }
        platform.0.lock().unwrap().handshake = frames;
        let service = sync_service(&platform, &parsed);
        let snapshot = service.subscribe_all(16, false).await;
        assert!(snapshot.non_finalized_blocks_ancestry_order.is_empty());
        for header in &headers {
            // A buffered UP 0 frame must not wait for a readiness edge.
            let notification = received("buffered UP 0 frame", &snapshot.new_blocks).await;
            assert!(
                matches!(notification, Notification::Block(ref block) if block.parent_hash == header.parent)
            );
            assert_eq!(block_hash(&notification), Some(header.hash(params)));
        }
        assert!(!snapshot.new_blocks.is_closed());
        assert!(snapshot.new_blocks.try_recv().is_err());
        assert!(platform.0.lock().unwrap().requests.is_empty());
        until(|| platform.0.lock().unwrap().io.pending_waits != 0).await;
        drop(service);
        until(|| torn_down(&platform)).await;
        assert!(snapshot.new_blocks.is_closed());
    });
}

#[test]
fn external_shutdown_cancels_pending_opening_without_timer_or_io_wakeup() {
    event_driven(|executor| async move {
        let (platform, spec, _) = event_driven_fixture(&executor, 1);
        platform.0.lock().unwrap().io.stall_outbound = true;
        let service = sync_service(&platform, &parse(&spec));
        let snapshot = service.subscribe_all(16, false).await;
        until(|| {
            let c = platform.0.lock().unwrap();
            c.io.stalled_openings == 1 && c.io.pending_waits != 0
        })
        .await;
        assert!(platform.0.lock().unwrap().requests.is_empty());
        assert!(snapshot.new_blocks.try_recv().is_err());
        drop(service);
        until(|| torn_down(&platform)).await;
        assert!(snapshot.new_blocks.is_closed());
    });
}

#[test]
fn external_checkpoint_public_follow_header_and_older_peer_finality() {
    // Captured checkpoints in a non-saturated tail, a saturated pre-tail, and a
    // saturated tail whose next epoch must use the recovered winners.
    let spec = parse(&fixture("chain-spec.polkajam.json").to_string());
    let [incomplete_tail, before_tail, tail] = checkpoint_cases(spec.params());
    let epoch_len = usize::try_from(spec.params().epoch_len).unwrap();
    for (anchor_index, tip_index) in [
        (incomplete_tail, incomplete_tail + 1),
        (before_tail, tail + 1),
        (tail, tail + epoch_len),
    ] {
        event_driven(move |executor| async move {
            let (platform, raw, headers) = event_driven_fixture(&executor, 1);
            let spec = with_checkpoint(&raw, anchor_index).to_string();
            let parsed = parse(&spec);
            let params = parsed.params();
            {
                let mut c = platform.0.lock().unwrap();
                let served = &headers[..=tip_index];
                c.responses
                    .retain(|hash, _| served.iter().any(|h| h.hash(params) == *hash));
                let genesis = final_of(params, parsed.genesis_header());
                c.handshake = handshake_frame(genesis, vec![final_of(params, &headers[tip_index])]);
            }
            let mut rpc = RpcClient::new(&platform, &spec);
            let id = rpc.follow(headers[anchor_index].hash(params)).await;
            for header in &headers[anchor_index + 1..=tip_index] {
                rpc.new_best(&id, params, header).await;
            }
            // The fixed checkpoint and every descendant remain pinned. Replies
            // also serve as barriers against any extra stop/finalized events.
            for header in &headers[anchor_index..=tip_index] {
                let hash = prefixed(header.hash(params));
                let reply = rpc.call("jamHead_unstable_header", json!([id, hash])).await;
                assert_eq!(reply["result"], prefixed(header.encode(params)));
            }
            until(|| platform.0.lock().unwrap().io.pending_waits != 0).await;
            {
                let c = platform.0.lock().unwrap();
                assert_eq!(
                    c.attempts, 1,
                    "older peer finality must not disconnect a useful peer"
                );
                assert_eq!(c.io.live_connections, 1);
                let mut index = anchor_index;
                for request in &c.requests {
                    assert_eq!(request.hash, headers[index].hash(params));
                    assert!((1..=64).contains(&request.max_blocks));
                    assert_eq!(request.direction, Direction::AscendingExclusive);
                    index += usize::try_from(request.max_blocks).unwrap();
                }
            }
            rpc.remove().await;
            until(|| torn_down(&platform)).await;
        });
    }
}

#[test]
fn adaptive_batch_limit_stays_lowered_after_oversize_reconnect() {
    let mut size = FetchSize::default();
    for expected in [2, 4, 8, 16, 32, 64, 64] {
        size.received(FRAME_BYTES / 2 - 1);
        assert_eq!(size.count, expected);
    }
    size.oversized();
    assert_eq!(size.count, 32);
    size.received(100);
    assert_eq!(size.count, 32);
    for _ in 0..10 {
        size.oversized();
    }
    assert_eq!(size.count, 1);
    size.received(100);
    assert_eq!(size.count, 1);
}

// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The peer pool, its `C(8)` refresh and slot churn.

use super::*;

/// The dev network's `C(8)` value, from the captured CE 129 exchange.
fn dev_active_set() -> Vec<u8> {
    let capture: Value = serde_json::from_str(include_str!(
        "../../../../../lib/src/jam/trie/fixtures/polkajam-ce129.json"
    ))
    .unwrap();
    bytes(&capture["expected_validators_hex"])
}

fn dev_candidates(params: &Params, value: &[u8]) -> Vec<Peer> {
    codec::decode_active_validators(params, value)
        .unwrap()
        .iter()
        .filter_map(|key| Peer::discovered(&ValidatorEndpoint::from_validator(key)))
        .collect()
}

/// A root-only state with `epoch_len`, a bootnode pool, one GRANDPA key and
/// one Bandersnatch key that seals every slot.
struct DiscoveryFixture {
    state: Arc<async_lock::Mutex<State>>,
    params: Params,
    keys: ed25519_zebra::SigningKey,
    public: [u8; 32],
    sealer: bandersnatch::Secret,
    value: Vec<u8>,
}

impl DiscoveryFixture {
    async fn new(epoch_len: u32, bootnodes: usize) -> Self {
        let mut state = root_state();
        let mut params = state.params.clone();
        params.epoch_len = epoch_len;
        let capacity = tree::Config {
            max_blocks: NonZeroUsize::new(16).unwrap(),
            max_bytes: usize::MAX,
            max_epoch_records: NonZeroUsize::new(8).unwrap(),
        };
        let (keys, public) = grandpa_key(42).await;
        let (sealer, sealer_public) = bandersnatch_key(b"discovery");
        let header = Header::decode(&state.params, state.tree.finalized().encoded()).unwrap();
        let pairs = vec![(sealer_public, public); 6];
        let sealing =
            SealingSequence::Keys(vec![sealer_public; usize::try_from(epoch_len).unwrap()]);
        let light_state =
            LightState::from_parts([[0; 32]; 4], pairs.clone(), pairs, sealing, None, 0);
        let root = verified_genesis(&params, header, light_state);
        state.tree = HeaderTree::new(params.clone(), root, capacity).unwrap();
        state.tree_config = capacity;
        state.max_blocks = 16;
        state.params = params.clone();
        state.authorities =
            AuthoritySet::from_checkpoint(&params, 0, vec![public; 6], vec![public; 6]).unwrap();
        let value = dev_active_set();
        let peers = dev_candidates(&params, &value)
            .into_iter()
            .take(bootnodes)
            .map(|peer| Peer {
                source: Source::Bootnode,
                ..peer
            })
            .collect();
        let max = usize::from(params.max_validators);
        state.discovery = Discovery::new(Pool::new(peers, Vec::new(), max));
        Self {
            state: Arc::new(async_lock::Mutex::new(state)),
            params,
            keys,
            public,
            sealer,
            value,
        }
    }

    /// Appends a header at `slot` on the best chain whose prior state root
    /// is `root`, and returns it.
    async fn extend(&self, slot: u32, root: Hash) -> Header {
        let mut s = self.state.lock().await;
        let parent = s.tree.best().clone();
        let mut header = Header::decode(&self.params, parent.encoded()).unwrap();
        header.parent = parent.hash();
        header.slot = slot;
        header.prior_state_root = root;
        header.epoch_mark = None;
        let verified = assume_verified(&self.params, &header, parent.post_state().clone());
        s.tree.insert_verified(verified).unwrap();
        header
    }

    /// Seals `header` on its retained parent, so that it passes verification.
    async fn seal(&self, header: Header) -> Header {
        let s = self.state.lock().await;
        let parent = s.tree.get(&header.parent).unwrap();
        seal_fallback(&self.params, parent, header, &self.sealer)
    }

    /// Finalizes `header` with one vote in `round`. A single vote for the
    /// commit target walks no ancestry, so any root is signed.
    async fn finalize(&self, header: &Header, round: u64) {
        let commit = (final_of(&self.params, header), [0; 32]);
        let signer = (&self.keys, self.public);
        let proof = single_vote_justification(signer, (round, 0), commit, &[], &self.params).await;
        let target = header.hash(&self.params);
        self.state.lock().await.finalize(target, &proof).unwrap();
    }

    /// Runs the driver for peer 0 of `platform` until `condition` holds.
    async fn drive_until(&self, platform: &FakePlatform, condition: impl Fn(&State) -> bool) {
        let (mut fetch, mut probe) = (FetchSize::default(), None);
        let connection = fake_connection(platform);
        let budget = (&mut fetch, &mut probe);
        let state = &self.state;
        let driver = drive(
            platform,
            "discovery",
            &self.params,
            0,
            state,
            connection,
            budget,
        );
        let done = async {
            while !condition(&*state.lock().await) {
                smol::Timer::after(Duration::from_millis(1)).await;
            }
        };
        while_driving(10, "discovery", driver, done).await;
    }
}

fn discovery_platform(final_: Final) -> FakePlatform {
    platform(Control {
        handshake: handshake_frame(final_, vec![]),
        supported: true,
        ..Control::default()
    })
}

fn pool_ports(state: &State) -> Vec<(u16, Source)> {
    let entries = state.discovery.pool.entries();
    entries
        .map(|(peer, _, _)| (peer.port, peer.source))
        .collect()
}

/// The result of a verified `C(8)` read for `expected`.
fn active_set_read(expected: &StateRead, root: Hash, value: Option<Vec<u8>>) -> StateReadResult {
    let key = trie::state_key(8);
    StateReadResult {
        at: expected.at,
        root,
        trust: Trust::Authenticated,
        root_header: expected.root_header,
        range: VerifiedRange {
            entries: value.map(|value| (key, value)).into_iter().collect(),
            complete_to: key,
        },
    }
}

#[test]
fn one_bootnode_discovers_five_validators_after_the_first_finality_advance() {
    smol::block_on(async {
        let fixture = DiscoveryFixture::new(4, 1).await;
        let (root, response) = active_set_trie(&fixture.value);
        let first = fixture.extend(1, root).await;
        fixture.extend(2, root).await;
        // No read before the first finality advance, even with a child present.
        {
            let mut s = fixture.state.lock().await;
            assert!(s.discovery.stale && !s.discovery.due);
            assert_eq!(s.discovery_turn(Duration::ZERO), None);
            assert!(s.reads.pending.is_none());
            assert_eq!(pool_ports(&s), [(40000, Source::Bootnode)]);
        }
        fixture.finalize(&first, 1).await;
        assert!(fixture.state.lock().await.discovery.due);

        let platform = discovery_platform(Final {
            hash: [0; 32],
            slot: 0,
        });
        platform.0.lock().unwrap().io.state_responses = [Ok(response)].into();
        fixture
            .drive_until(&platform, |s| s.discovery.pool.entries().count() == 6)
            .await;
        let s = fixture.state.lock().await;
        let discovered = (40001..40006).map(|port| (port, Source::Discovered));
        let expected: Vec<_> = [(40000, Source::Bootnode)]
            .into_iter()
            .chain(discovered)
            .collect();
        assert_eq!(pool_ports(&s), expected);
        assert!(!s.discovery.stale && !s.discovery.due && s.discovery.read.is_none());
        // The read went to the finalized head, against its child's prior root.
        let requests = platform.0.lock().unwrap().io.state_requests.clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0][..32], first.hash(&fixture.params));
        assert_eq!(requests[0][32..63], trie::state_key(8));
        assert_eq!(requests[0][63..94], trie::state_key(8));
        let changes = logged(&platform, "jam-pool-changed");
        assert_eq!(changes.len(), 1);
        for (key, value) in [
            ("validators", "6"),
            ("usable", "6"),
            ("discovered", "5"),
            ("added", "5"),
            ("removed", "0"),
            ("retired", "0"),
            ("value_bytes", "2017"),
        ] {
            assert_eq!(changes[0][key], value, "{key}");
        }
        assert_eq!(logged(&platform, "jam-discovery-read-started").len(), 1);
    });
}

#[test]
fn failed_active_set_read_leaves_the_pool_and_header_sync_unaffected() {
    smol::block_on(async {
        let fixture = DiscoveryFixture::new(4, 1).await;
        let params = &fixture.params;
        let (root, response) = active_set_trie(&fixture.value);
        let first = fixture.extend(1, root).await;
        let second = fixture.extend(2, root).await;
        fixture.finalize(&first, 1).await;
        // The peer has a third block to serve and no state.
        let mut third = second.clone();
        third.parent = second.hash(params);
        third.slot = 3;
        let third = fixture.seal(third).await;
        let platform = discovery_platform(final_of(params, &third));
        {
            let mut c = platform.0.lock().unwrap();
            c.io.params = Some(params.clone());
            serve(&mut c, params, &third);
            c.io.state_responses = [Err(Reset(Some(6), "no state"))].into();
        }
        // NoData does not end the connection. The finality request for the new
        // head must have been answered too, as its reservation outlives `drive`.
        fixture
            .drive_until(&platform, |s| {
                s.tree.best().slot() == 3
                    && s.discovery.read.is_none()
                    && !s.discovery.due
                    && s.proof_owner.is_none()
            })
            .await;
        {
            let s = fixture.state.lock().await;
            assert_eq!(pool_ports(&s), [(40000, Source::Bootnode)]);
            assert!(s.discovery.stale, "a failed read is retried");
            assert!(!s.discovery.due, "but only on the next finality advance");
            assert!(s.reads.pending.is_none() || s.reads.owner.is_none());
        }
        let failures = logged(&platform, "jam-discovery-failed");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["reason"], "Released");
        assert_eq!(platform.0.lock().unwrap().attempts, 0, "no reconnect");

        // The next finality advance retries, and this time the peer serves it.
        platform.0.lock().unwrap().io.state_responses = [Ok(response)].into();
        fixture.finalize(&second, 2).await;
        fixture.drive_until(&platform, |s| !s.discovery.stale).await;
        assert_eq!(
            fixture.state.lock().await.discovery.pool.entries().count(),
            6
        );
        assert_eq!(platform.0.lock().unwrap().io.state_requests.len(), 2);
    });
}

#[test]
fn only_a_finalized_epoch_change_refreshes_and_warp_joins_take_precedence() {
    smol::block_on(async {
        let fixture = DiscoveryFixture::new(4, 1).await;
        let (root, response) = active_set_trie(&fixture.value);
        let mut headers = Vec::new();
        for slot in [1, 2, 5, 6] {
            headers.push(fixture.extend(slot, root).await);
        }
        let serve = |s: &mut State| {
            let request = s.reads.reserve(0).unwrap();
            assert_eq!(request.start, trie::state_key(8));
            s.reads.received(0, &state_response(&response)).unwrap();
        };
        // First advance: stale, so due; the read succeeds.
        fixture.finalize(&headers[0], 1).await;
        {
            let mut s = fixture.state.lock().await;
            assert!(matches!(
                s.discovery_turn(Duration::ZERO),
                Some(DiscoveryEvent::Started { slot: 1 })
            ));
            serve(&mut s);
            assert!(matches!(
                s.discovery_turn(Duration::from_millis(30)),
                Some(DiscoveryEvent::Refreshed {
                    elapsed_ms: 30,
                    value_bytes: 2017,
                    ..
                })
            ));
            assert!(!s.discovery.stale);
        }
        // Slot 2 is still epoch 0: no refresh.
        fixture.finalize(&headers[1], 2).await;
        {
            let mut s = fixture.state.lock().await;
            assert!(!s.discovery.due);
            assert_eq!(s.discovery_turn(Duration::ZERO), None);
        }
        // Slot 5 opens epoch 1: due again. A warp join reserving first wins.
        fixture.finalize(&headers[2], 3).await;
        let mut s = fixture.state.lock().await;
        assert!(s.discovery.due);
        assert!(matches!(
            s.discovery_turn(Duration::ZERO),
            Some(DiscoveryEvent::Started { slot: 5 })
        ));
        let warp = s.reserve_warp(1);
        assert!(warp.is_some(), "an unserved refresh yields to a warp join");
        assert!(s.discovery.read.is_none() && !s.discovery.due);
        assert_eq!(
            s.discovery_turn(Duration::ZERO),
            None,
            "nothing during a warp"
        );
        s.warp_owner = None;
        // A refresh already being served is not cancelled by a warp attempt.
        s.discovery.due = true;
        assert!(matches!(
            s.discovery_turn(Duration::ZERO),
            Some(DiscoveryEvent::Started { .. })
        ));
        assert!(s.reads.reserve(0).is_some());
        assert!(s.reserve_warp(1).is_none());
        assert!(s.discovery.read.is_some());
    });
}

/// A pool of node0 as the bootnode and the six dev validators as discovered
/// candidates, in `fixture`.
async fn dev_pool(fixture: &DiscoveryFixture) {
    let candidates = dev_candidates(&fixture.params, &fixture.value);
    let pool = &mut fixture.state.lock().await.discovery.pool;
    pool.replace_discovered(6, candidates.into_iter().map(Some));
}

#[test]
fn a_dead_bootnode_moves_its_slot_to_a_discovered_validator_without_its_backoff() {
    smol::block_on(async {
        let fixture = DiscoveryFixture::new(4, 1).await;
        dev_pool(&fixture).await;
        let params = fixture.params.clone();
        let platform = discovery_platform(Final {
            hash: [0; 32],
            slot: 0,
        });
        platform.0.lock().unwrap().io.dead_ports = vec![40000];
        let state = fixture.state.clone();
        let origin = platform.now();
        let initial = state.lock().await.acquire_candidate(0, Duration::ZERO);
        let initial = initial.unwrap();
        assert_eq!(initial.port, 40000);
        let started = Instant::now();
        let slot = slot_loop(
            &platform,
            "dead-bootnode",
            0,
            &params,
            state.clone(),
            origin,
            Some(initial),
        );
        let dialed = until(|| platform.0.lock().unwrap().io.connected_ports.len() >= 2);
        while_driving(10, "a second dial", slot, dialed).await;
        // The dead bootnode's 1 s backoff did not delay the slot.
        assert!(started.elapsed() < Duration::from_millis(900));
        assert_eq!(
            platform.0.lock().unwrap().io.connected_ports[..2],
            [40000, 40001]
        );
        let assigned = logged(&platform, "jam-slot-assigned");
        assert_eq!(assigned[0]["source"], "bootnode");
        assert_eq!(assigned[1]["source"], "discovered");
        assert_eq!(assigned[1]["address"], "127.0.0.1:40001");
        assert_eq!(
            assigned[1]["p256"],
            "ordkiwj4rcxzhxrh3xbfj6dyt3utrhrxukgy6xfi3fpubv4ioerzb"
        );
        let s = state.lock().await;
        assert_eq!(s.discovery.pool.held(0).map(|p| p.port), Some(40001));
    });
}

#[test]
fn two_slots_never_hold_one_identity_while_churning() {
    smol::block_on(async {
        let fixture = DiscoveryFixture::new(4, 1).await;
        dev_pool(&fixture).await;
        let params = fixture.params.clone();
        let platform = discovery_platform(Final {
            hash: [0; 32],
            slot: 0,
        });
        // Every connection dies at once, so both slots churn through the pool.
        platform.0.lock().unwrap().io.dead_ports = (40000..40006).collect();
        let state = fixture.state.clone();
        let origin = platform.now();
        let slot = |index: usize| {
            let platform = platform.clone();
            let state = state.clone();
            let params = params.clone();
            async move {
                slot_loop(&platform, "churn", index, &params, state, origin, None).await;
            }
        };
        let mut samples = 0;
        future::or(future::or(slot(0), slot(1)), async {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                {
                    let s = state.lock().await;
                    let held: Vec<_> = (0..MAX_PEERS)
                        .filter_map(|slot| s.discovery.pool.held(slot).map(|p| p.identity))
                        .collect();
                    if held.len() == 2 {
                        assert_ne!(held[0], held[1], "two slots hold one identity");
                    }
                }
                samples += 1;
                smol::Timer::after(Duration::from_millis(1)).await;
            }
        })
        .await;
        assert!(samples > 100);
        let ports = platform.0.lock().unwrap().io.connected_ports.clone();
        // Both slots tried every candidate, each in its own backoff.
        for port in 40000..40006 {
            assert!(ports.contains(&port), "{port} never dialed: {ports:?}");
        }
        let assigned = logged(&platform, "jam-slot-assigned");
        assert!(assigned.iter().any(|f| f["slot"] == "0"));
        assert!(assigned.iter().any(|f| f["slot"] == "1"));
    });
}

#[test]
fn rotation_releases_a_validator_that_left_after_its_connection_ends() {
    smol::block_on(async {
        let fixture = DiscoveryFixture::new(4, 0).await;
        dev_pool(&fixture).await;
        let value = fixture.value.clone();
        let params = fixture.params.clone();
        let state = fixture.state.clone();
        let platform = discovery_platform(Final {
            hash: [0; 32],
            slot: 0,
        });
        let origin = platform.now();
        // Slot 1 holds validator 0 (port 40000) on a live connection; slot 0
        // a refusal for the current root that must not survive a change.
        let initial = state.lock().await.acquire_candidate(1, Duration::ZERO);
        let initial = initial.unwrap();
        assert_eq!(initial.port, 40000);
        let root = state.lock().await.tree.finalized().hash();
        state.lock().await.root_refusals = Some((root, 0b10));
        let run = async {
            slot_loop(
                &platform,
                "rotation",
                1,
                &params,
                state.clone(),
                origin,
                Some(initial),
            )
            .await;
            panic!("slot loop ended");
        };
        future::or(run, async {
            until(|| !logged(&platform, "jam-peer-connected").is_empty()).await;
            // A finalized epoch change brings a set without validator 0.
            let mut remaining = codec::decode_active_validators(&params, &value).unwrap();
            remaining.remove(0);
            let changed = codec::encode_active_validators(&remaining);
            {
                let mut s = state.lock().await;
                let expected = StateRead {
                    at: root,
                    root: [1; 32],
                    trust: Trust::Authenticated,
                    root_header: Some([2; 32]),
                    request: StateRequest {
                        block: root,
                        start: trie::state_key(8),
                        end: trie::state_key(8),
                        max_size: STATE_READ_BYTES,
                    },
                };
                let read = DiscoveryRead {
                    expected: expected.clone(),
                    rx: futures_channel::oneshot::channel().1,
                    started_ms: 0,
                };
                let result = active_set_read(&expected, expected.root, Some(changed));
                let DiscoveryEvent::Refreshed { merge, .. } =
                    s.apply_active_set(&read, result, Duration::ZERO)
                else {
                    panic!("merge failed")
                };
                assert_eq!((merge.discovered, merge.retired), (5, 1));
                // Not cut: the slot keeps its connection to the leaver.
                assert_eq!(s.discovery.pool.held(1).map(|p| p.port), Some(40000));
                // A provenance mismatch is rejected before touching the pool.
                for (root, reason) in [([9; 32], "Provenance"), (expected.root, "Absent")] {
                    let wrong = active_set_read(&expected, root, None);
                    assert_eq!(
                        s.apply_active_set(&read, wrong, Duration::ZERO),
                        DiscoveryEvent::Failed { reason }
                    );
                }
            }
            // The connection ends: the leaver is released and dropped, and the
            // slot takes a validator still in the set.
            platform.0.lock().unwrap().disconnect = true;
            until(|| platform.0.lock().unwrap().io.connected_ports.len() >= 2).await;
        })
        .await;
        let s = state.lock().await;
        assert!(pool_ports(&s).iter().all(|(port, _)| *port != 40000));
        assert_eq!(s.discovery.pool.held(1).map(|p| p.port), Some(40001));
        assert_eq!(
            s.root_refusals,
            Some((s.tree.finalized().hash(), 0)),
            "the slot's refusal bit belongs to the peer it left"
        );
        assert_eq!(
            platform.0.lock().unwrap().io.connected_ports,
            [40000, 40001]
        );
    });
}

/// The captured dev spec: node0 as its one `bootnodes_p256` entry, and the six dev
/// validators with P-256 ids and ports 40000 to 40005 in the genesis `C(8)`.
fn dev_spec_with_bootnode() -> Value {
    fixture("polkajam-grandpa.json")["spec"].clone()
}

fn config_of(spec: &Value) -> Result<Config, ConfigError> {
    let parsed =
        JamChainSpec::from_json_bytes(spec.to_string().as_bytes()).map_err(ConfigError::Spec)?;
    Config::from_spec(&parsed)
}

fn acquired(pool: &mut Pool, slot: usize) -> Peer {
    match pool.acquire(slot, Duration::ZERO) {
        Acquire::Peer { peer, .. } => peer,
        Acquire::Wait(wait) => panic!("slot {slot}: expected a peer, got Wait({wait:?})"),
    }
}

#[test]
fn bootnodes_and_genesis_validators_seed_one_pool() {
    // Both sources: node0 is a bootnode and a genesis validator, and stays one
    // candidate, the bootnode. The second slot gets a genesis validator at once.
    let spec = dev_spec_with_bootnode();
    let config = config_of(&spec).unwrap();
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.genesis.len(), 6);
    assert!(config.genesis.iter().all(|p| p.source == Source::Genesis));
    let node0 = config.peers[0].identity;
    let mut pool = Pool::new(config.peers, config.genesis.clone(), 6);
    let sources: Vec<_> = pool.entries().map(|(p, _, _)| (p.source, p.port)).collect();
    let genesis = (40001..40006).map(|port| (Source::Genesis, port));
    let expected: Vec<_> = [(Source::Bootnode, 40000)]
        .into_iter()
        .chain(genesis)
        .collect();
    assert_eq!(sources, expected);
    let first = acquired(&mut pool, 0);
    assert_eq!((first.source, first.identity), (Source::Bootnode, node0));
    let second = acquired(&mut pool, 1);
    assert_eq!((second.source, second.port), (Source::Genesis, 40001));

    // The first verified `C(8)` read replaces the genesis entries; held ones
    // keep their slot and become discovered entries.
    let discovered: Vec<_> = (config.genesis.iter())
        .map(|p| {
            Some(Peer {
                source: Source::Discovered,
                ..p.clone()
            })
        })
        .collect();
    let merge = pool.replace_discovered(6, discovered);
    assert_eq!((merge.discovered, merge.added, merge.removed), (5, 0, 0));
    assert!(
        pool.entries()
            .skip(1)
            .all(|(p, _, retired)| p.source == Source::Discovered && !retired)
    );
    assert_eq!(pool.held(1).unwrap().port, 40001);
}

#[test]
fn either_source_alone_is_enough_and_a_bootnode_wins_an_overlap() {
    // Genesis only: no bootnodes at all.
    let mut spec = dev_spec_with_bootnode();
    spec["bootnodes_p256"] = json!([]);
    let config = config_of(&spec).unwrap();
    assert!(config.peers.is_empty());
    let mut pool = Pool::new(config.peers, config.genesis, 6);
    let first = acquired(&mut pool, 0);
    assert_eq!((first.source, first.port), (Source::Genesis, 40000));
    assert_eq!(acquired(&mut pool, 1).port, 40001);

    // Bootnodes only: genesis validators without P-256 ids are skipped.
    let mut spec = dev_spec_with_bootnode();
    without_genesis_p256(&mut spec);
    let config = config_of(&spec).unwrap();
    assert_eq!((config.peers.len(), config.genesis.len()), (1, 0));

    // Overlap: a bootnode with validator 1's identity at another address is one
    // candidate, the bootnode, with the bootnode's address.
    let mut spec = dev_spec_with_bootnode();
    let config = config_of(&spec).unwrap();
    let (genesis, node0) = (config.genesis, config.peers[0].identity);
    let bootnode = spec["bootnodes_p256"][0].as_str().unwrap().to_owned();
    let (id, _) = bootnode.split_once('@').unwrap();
    spec["bootnodes_p256"] = json!([bootnode.clone(), alloc::format!("{id}@127.0.0.1:4433")]);
    let config = config_of(&spec).unwrap();
    assert_eq!(config.peers[0].identity, node0);
    // The same identity twice among bootnodes is one bootnode, the first.
    let pool = Pool::new(config.peers, genesis.clone(), 6);
    let entries: Vec<_> = pool.entries().map(|(p, _, _)| (p.source, p.port)).collect();
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[0], (Source::Bootnode, 40000));
    assert!(!entries.iter().any(|(_, port)| *port == 4433));
    assert_eq!(entries.iter().filter(|(_, port)| *port == 40000).count(), 1);
    let genesis_one = genesis.iter().find(|p| p.port == 40001).unwrap();
    let bootnode = Peer {
        port: 4433,
        source: Source::Bootnode,
        ..genesis_one.clone()
    };
    let pool = Pool::new(vec![bootnode], genesis, 6);
    let entries: Vec<_> = pool.entries().map(|(p, _, _)| (p.source, p.port)).collect();
    assert_eq!(entries[0], (Source::Bootnode, 4433));
    assert!(!entries.contains(&(Source::Genesis, 40001)));
    assert_eq!(entries.len(), 6);
}

#[test]
fn a_spec_without_any_dialable_peer_is_refused() {
    let ed25519_only = alloc::format!("e{}@127.0.0.1:4433", "a".repeat(52));
    let mut specs = Vec::new();
    // Neither source, or only an Ed25519 bootnode, which the client ignores.
    for bootnodes in [json!([]), json!([ed25519_only])] {
        let mut spec = dev_spec_with_bootnode();
        spec["bootnodes"] = bootnodes;
        spec["bootnodes_p256"] = json!([]);
        without_genesis_p256(&mut spec);
        specs.push(spec);
    }
    // Genesis keys that parse but are not curve points.
    let mut spec = dev_spec_with_bootnode();
    spec["bootnodes_p256"] = json!([]);
    edit_genesis_metadata(&mut spec, |metadata| {
        metadata[18] = 0;
        metadata[19..51].fill(0xff);
    });
    specs.push(spec);
    // Refused by the driver config, naming both sources, before any dial or task.
    for spec in specs {
        let (platform, _, _, _) = fixture_setup();
        let error = rejected_add_chain_without_startup(&platform, &spec.to_string());
        assert!(matches!(error, ConfigError::NoDialablePeer), "{error}");
        let error = error.to_string();
        assert!(
            error.contains("bootnode") && error.contains("C(8)"),
            "{error}"
        );
    }
}

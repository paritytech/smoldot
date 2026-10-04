// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use alloc::vec;
use core::net::Ipv4Addr;
use smoldot::jam::{metadata, params::Params};

const SECOND: Duration = Duration::from_secs(1);

/// The dev network's `C(8)` value from D2's committed CE 129 capture.
fn captured_endpoints() -> Vec<ValidatorEndpoint> {
    let capture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../lib/src/jam/trie/fixtures/polkajam-ce129.json"
    ))
    .unwrap();
    let unhex = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
    let params = Params::from_protocol_parameters(&unhex(&capture["protocol_parameters"])).unwrap();
    metadata::decode_active_set(&params, &unhex(&capture["expected_validators_hex"]))
        .unwrap()
        .iter()
        .map(ValidatorEndpoint::from_validator)
        .collect()
}

fn dev_peers() -> Vec<Peer> {
    captured_endpoints()
        .iter()
        .map(|e| Peer::discovered(e).unwrap())
        .collect()
}

fn as_bootnode(peer: &Peer) -> Peer {
    Peer {
        source: Source::Bootnode,
        ..peer.clone()
    }
}

/// node0 as the only bootnode, the six dev validators merged.
fn dev_pool() -> (Pool, Vec<Peer>) {
    let peers = dev_peers();
    let mut pool = Pool::new(vec![as_bootnode(&peers[0])], Vec::new(), 1023);
    let merge = pool.replace_discovered(6, peers.iter().cloned().map(Some));
    assert_eq!(merge.discovered, 5);
    (pool, peers)
}

fn port(acquire: &Acquire) -> u16 {
    match acquire {
        Acquire::Peer { peer, .. } => peer.port,
        Acquire::Wait(wait) => panic!("expected a peer, got Wait({wait:?})"),
    }
}

fn assert_distinct_holders(pool: &Pool) {
    let held: Vec<_> = (0..SLOTS)
        .filter_map(|slot| pool.held(slot).map(|p| p.ed25519))
        .collect();
    for (i, a) in held.iter().enumerate() {
        assert!(
            held[i + 1..].iter().all(|b| b != a),
            "two slots hold one identity"
        );
    }
    for (peer, holder, _) in pool.entries() {
        if let Some(slot) = holder {
            assert_eq!(pool.held(slot).map(|p| p.ed25519), Some(peer.ed25519));
        }
    }
}

#[test]
fn captured_metadata_yields_the_identities_the_harness_spells() {
    let peers = dev_peers();
    assert_eq!(peers.len(), 6);
    // `network.mjs` NODE0_P256_ID; node1's is the second A2 vector key.
    assert_eq!(
        peers[0].identity.to_text(),
        "oqov2a57d7etnpzb6aerv64y5j622ejkkvqjencdrwln4qhnoqvqb"
    );
    assert_eq!(
        peers[1].identity.to_text(),
        "ordkiwj4rcxzhxrh3xbfj6dyt3utrhrxukgy6xfi3fpubv4ioerzb"
    );
    for (index, peer) in peers.iter().enumerate() {
        assert_eq!(peer.ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(peer.port, 40000 + u16::try_from(index).unwrap());
        assert_eq!(peer.source, Source::Discovered);
        assert_eq!(
            alloc::format!("{}", peer.address()),
            alloc::format!("127.0.0.1:{}", peer.port)
        );
    }
    let mut v6 = captured_endpoints().remove(0);
    v6.ip = IpAddr::V6("2001:db8::1".parse().unwrap());
    assert_eq!(
        alloc::format!("{}", Peer::discovered(&v6).unwrap().address()),
        "[2001:db8::1]:40000"
    );
}

#[test]
fn unusable_records_are_dropped() {
    let endpoints = captured_endpoints();
    let mut no_key = endpoints[1].clone();
    no_key.p256 = None;
    let mut no_port = endpoints[2].clone();
    no_port.port = 0;
    let mut off_curve = endpoints[3].clone();
    off_curve.p256 = Some(([255; 32], false));
    for endpoint in [&no_key, &no_port, &off_curve] {
        assert_eq!(Peer::discovered(endpoint), None);
    }
    let mut pool = Pool::new(Vec::new(), Vec::new(), 1023);
    let merge = pool.replace_discovered(
        4,
        [&endpoints[0], &no_key, &no_port, &off_curve]
            .into_iter()
            .map(Peer::discovered),
    );
    assert_eq!(
        merge,
        Merge {
            validators: 4,
            usable: 1,
            discovered: 1,
            added: 1,
            removed: 0,
            retired: 0
        }
    );
}

#[test]
fn bootnode_first_then_oldest_failure_and_per_candidate_backoff() {
    let (mut pool, _) = dev_pool();
    // The bootnode goes to the first slot that asks, never twice.
    assert_eq!(port(&pool.acquire(0, Duration::ZERO)), 40000);
    assert_eq!(port(&pool.acquire(1, Duration::ZERO)), 40001);
    assert_distinct_holders(&pool);

    // node0 dies: slot 0 releases it and gets a discovered validator at
    // once, without waiting for node0's backoff.
    let now = 10 * SECOND;
    pool.release(0, Release::Ended { lasted: SECOND }, now);
    assert_eq!(port(&pool.acquire(0, now)), 40002);
    assert_distinct_holders(&pool);

    // Failing discovered validators rotate through the never-failed ones,
    // then the oldest failure.
    for expected in [40003, 40004, 40005] {
        pool.release(0, Release::Ended { lasted: SECOND }, now);
        assert_eq!(port(&pool.acquire(0, now)), expected);
    }
    pool.release(0, Release::Ended { lasted: SECOND }, now);
    // Everyone free has failed within the last second: node0 (1 failure)
    // and 40002..40005 (1 failure each) wait 1 s.
    assert_eq!(pool.acquire(0, now), Acquire::Wait(Some(SECOND)));
    // After the backoff the bootnode is preferred again.
    assert_eq!(port(&pool.acquire(0, now + SECOND)), 40000);
    assert_distinct_holders(&pool);
    pool.release(0, Release::Ended { lasted: SECOND }, now + SECOND);
    // node0 now has two failures (2 s); validators' 1 s backoff has passed,
    // so the oldest failure among them wins.
    assert_eq!(port(&pool.acquire(0, now + 2 * SECOND)), 40002);
}

#[test]
fn backoff_doubles_to_thirty_seconds_and_long_connections_reset_it() {
    let peer = dev_peers().remove(0);
    let mut pool = Pool::new(vec![as_bootnode(&peer)], Vec::new(), 0);
    let mut now = Duration::ZERO;
    for expected in [1, 2, 4, 8, 16, 30, 30] {
        assert_eq!(port(&pool.acquire(0, now)), 40000);
        pool.release(0, Release::Ended { lasted: SECOND }, now);
        assert_eq!(
            pool.acquire(0, now),
            Acquire::Wait(Some(Duration::from_secs(expected)))
        );
        now += Duration::from_secs(expected);
    }
    assert_eq!(port(&pool.acquire(0, now)), 40000);
    pool.release(0, Release::Ended { lasted: LONG_LIVED }, now);
    assert_eq!(pool.acquire(0, now), Acquire::Wait(Some(SECOND)));
    // Nothing selectable at all: the pool must change first.
    assert_eq!(port(&pool.acquire(1, now + SECOND)), 40000);
    assert_eq!(pool.acquire(0, now + SECOND), Acquire::Wait(None));
    // Unsupported address types are never selected again.
    pool.release(1, Release::Unsupported, now + SECOND);
    assert_eq!(pool.acquire(0, now + 100 * SECOND), Acquire::Wait(None));
}

#[test]
fn two_slots_never_hold_the_same_identity() {
    let (mut pool, _) = dev_pool();
    // A deterministic interleaving of acquire, release and preempt.
    let mut now = Duration::ZERO;
    let mut state = 0x2545_f491_u32;
    for _ in 0..2000 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let slot = usize::try_from(state % 2).unwrap();
        now += Duration::from_millis(u64::from(state % 7000));
        match state % 5 {
            0 | 1 => {
                let _ = pool.acquire(slot, now);
            }
            2 | 3 => pool.release(
                slot,
                Release::Ended {
                    lasted: Duration::from_millis(u64::from(state % 90_000)),
                },
                now,
            ),
            _ => {
                let _ = pool.preempt(slot, now);
            }
        }
        assert_distinct_holders(&pool);
        if state.is_multiple_of(97) {
            // Rotation while held: a changed set never duplicates holders either.
            let peers = dev_peers();
            let keep = usize::try_from(state % 6).unwrap();
            pool.replace_discovered(6, peers.into_iter().skip(keep).map(Some));
            assert_distinct_holders(&pool);
        }
    }
}

#[test]
fn per_slot_state_is_cleared_exactly_on_identity_change() {
    let (mut pool, _) = dev_pool();
    // First assignment: each slot changes from nothing to a peer.
    assert_eq!(
        pool.acquire(0, Duration::ZERO),
        Acquire::Peer {
            peer: pool.entries().next().unwrap().0.clone(),
            cleared: 0b01
        }
    );
    let Acquire::Peer { cleared, .. } = pool.acquire(1, Duration::ZERO) else {
        panic!()
    };
    assert_eq!(cleared, 0b10);
    // Re-acquiring the same identity after a failure keeps the slot's state.
    pool.release(0, Release::Ended { lasted: SECOND }, Duration::ZERO);
    pool.release(1, Release::Ended { lasted: SECOND }, Duration::ZERO);
    let Acquire::Peer { peer, cleared } = pool.acquire(1, Duration::ZERO) else {
        panic!()
    };
    // Slot 1 takes the third validator (both previous ones are in backoff).
    assert_eq!((peer.port, cleared), (40002, 0b10));
    let Acquire::Peer { peer, cleared } = pool.acquire(0, SECOND) else {
        panic!()
    };
    // node0 again on slot 0: unchanged identity, nothing cleared.
    assert_eq!((peer.port, cleared), (40000, 0));
    // Slot 1 moves on to a never-failed validator: its identity changes again.
    pool.release(1, Release::Ended { lasted: SECOND }, SECOND);
    let Acquire::Peer { peer, cleared } = pool.acquire(1, SECOND) else {
        panic!()
    };
    assert_eq!((peer.port, cleared), (40003, 0b10));
    // Another slot taking an identity a slot held last clears both records.
    let mut fresh = Pool::new(vec![as_bootnode(&dev_peers()[0])], Vec::new(), 0);
    assert_eq!(port(&fresh.acquire(0, Duration::ZERO)), 40000);
    fresh.release(0, Release::Ended { lasted: SECOND }, Duration::ZERO);
    let Acquire::Peer { cleared, .. } = fresh.acquire(1, SECOND) else {
        panic!()
    };
    assert_eq!(
        cleared, 0b11,
        "slot 0's refusal must not pair with slot 1's"
    );
}

#[test]
fn merge_replaces_wholesale_keeps_bootnodes_failures_and_retires_held_leavers() {
    let (mut pool, peers) = dev_pool();
    // Slot 1 holds validator 5, then validator 3 fails once.
    assert_eq!(port(&pool.acquire(0, Duration::ZERO)), 40000);
    for _ in 0..3 {
        let _ = pool.acquire(1, Duration::ZERO);
        pool.release(1, Release::Ended { lasted: SECOND }, Duration::ZERO);
    }
    // 40001..40003 failed at t=0; slot 1 now holds 40004.
    assert_eq!(port(&pool.acquire(1, Duration::ZERO)), 40004);

    // Rotation: validators 3 and 4 leave, a new validator joins, node0 stays.
    let mut joiner = peers[5].clone();
    joiner.ed25519 = [9; 32];
    joiner.port = 40100;
    let next = [&peers[0], &peers[1], &peers[2], &peers[5], &joiner];
    let merge = pool.replace_discovered(5, next.into_iter().cloned().map(Some));
    assert_eq!(
        merge,
        Merge {
            validators: 5,
            usable: 5,
            // node0 is a bootnode, not a discovered duplicate.
            discovered: 4,
            added: 1,
            removed: 1,
            retired: 1
        }
    );
    // The held leaver stays held until its connection ends, but is never
    // selected; releasing it removes it from the pool.
    assert_eq!(pool.held(1).map(|p| p.port), Some(40004));
    let ports = |pool: &Pool| pool.entries().map(|(p, _, _)| p.port).collect::<Vec<_>>();
    assert_eq!(ports(&pool), [40000, 40001, 40002, 40005, 40100, 40004]);
    pool.release(1, Release::Ended { lasted: SECOND }, Duration::ZERO);
    assert_eq!(ports(&pool), [40000, 40001, 40002, 40005, 40100]);
    // Survivors kept their failure records: never-failed entries go first.
    assert_eq!(port(&pool.acquire(1, Duration::ZERO)), 40005);
    pool.release(1, Release::Ended { lasted: SECOND }, Duration::ZERO);
    assert_eq!(port(&pool.acquire(1, Duration::ZERO)), 40100);

    // Duplicate identities in one read and the bound are both respected.
    let mut bounded = Pool::new(Vec::new(), Vec::new(), 2);
    let merge = bounded.replace_discovered(
        6,
        [&peers[1], &peers[1], &peers[2], &peers[3]]
            .into_iter()
            .cloned()
            .map(Some),
    );
    assert_eq!((merge.usable, merge.discovered), (4, 2));
    // A duplicated address under different identities is two candidates.
    let mut twin = peers[1].clone();
    twin.ed25519 = [8; 32];
    let mut pool = Pool::new(Vec::new(), Vec::new(), 1023);
    let merge = pool.replace_discovered(2, [Some(peers[1].clone()), Some(twin)]);
    assert_eq!(merge.discovered, 2);
}

#[test]
fn restarted_bootnode_preempts_a_discovered_slot_after_its_retry_interval() {
    let (mut pool, _) = dev_pool();
    assert_eq!(port(&pool.acquire(0, Duration::ZERO)), 40000);
    assert_eq!(port(&pool.acquire(1, Duration::ZERO)), 40001);
    // A slot on a bootnode is never preempted.
    assert_eq!(pool.preempt(0, Duration::ZERO), None);
    // node0 dies at t=10 s; slot 0 moves to a validator.
    let killed = 10 * SECOND;
    pool.release(0, Release::Ended { lasted: SECOND }, killed);
    assert_eq!(port(&pool.acquire(0, killed)), 40002);
    // Its ordinary 1 s backoff does not cut a working connection; 30 s does.
    assert_eq!(pool.preempt(0, killed + 29 * SECOND), None);
    let (peer, cleared) = pool.preempt(1, killed + 30 * SECOND).unwrap();
    assert_eq!((peer.port, cleared), (40000, 0b10));
    assert_eq!(pool.held(1).map(|p| p.port), Some(40000));
    // Only one slot can take the bootnode.
    assert_eq!(pool.preempt(0, killed + 30 * SECOND), None);
    assert_distinct_holders(&pool);
    // Still dead: the next retry waits 60 s, then 120 s, capped at 300 s.
    let mut failed = killed + 30 * SECOND;
    for wait in [60, 120, 240, 300, 300] {
        pool.release(1, Release::Ended { lasted: SECOND }, failed);
        let _ = pool.acquire(1, failed);
        assert_eq!(
            pool.preempt(1, failed + Duration::from_secs(wait - 1)),
            None
        );
        failed += Duration::from_secs(wait);
        assert_eq!(pool.preempt(1, failed).map(|(p, _)| p.port), Some(40000));
    }
    // The validator the preempted slot left is free again, with no failure.
    assert!(
        pool.entries()
            .any(|(p, holder, _)| p.port == 40001 && holder.is_none())
    );
}

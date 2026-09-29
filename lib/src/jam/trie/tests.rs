// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use alloc::vec;

// Independent GP M(d) prover. Stores all nodes but emits only boundary paths.
fn prove(map: &BTreeMap<StateKey, Vec<u8>>, start: StateKey, last: StateKey) -> (Hash, Vec<Node>) {
    fn build(
        map: BTreeMap<StateKey, Vec<u8>>,
        depth: usize,
        nodes: &mut BTreeMap<Hash, Node>,
    ) -> Hash {
        if map.is_empty() {
            return [0; 32];
        }
        let mut node = [0; 64];
        if map.len() == 1 {
            let (key, value) = map.first_key_value().unwrap();
            node[1..32].copy_from_slice(key);
            if value.len() <= 32 {
                node[0] = 128 + u8::try_from(value.len()).unwrap();
                node[32..32 + value.len()].copy_from_slice(value);
            } else {
                node[0] = 192;
                node[32..].copy_from_slice(&blake2b_256(value));
            }
        } else {
            let (left, right) = map
                .into_iter()
                .partition(|(key, _)| key[depth / 8] & (128 >> (depth % 8)) == 0);
            node[..32].copy_from_slice(&build(left, depth + 1, nodes));
            node[0] &= 127;
            node[32..].copy_from_slice(&build(right, depth + 1, nodes));
        }
        let hash = blake2b_256(&node);
        nodes.insert(hash, node);
        hash
    }
    let mut nodes = BTreeMap::new();
    let root = build(map.clone(), 0, &mut nodes);
    let mut proof = BTreeMap::new();
    for key in [start, last] {
        let mut hash = root;
        for depth in 0..=248 {
            if hash == [0; 32] {
                break;
            }
            let node = *nodes.get(&hash).unwrap();
            proof.insert(hash, node);
            if node[0] & 128 != 0 {
                break;
            }
            let right = key[depth / 8] & (128 >> (depth % 8)) != 0;
            hash = if right {
                node[32..].try_into().unwrap()
            } else {
                node[..32].try_into().unwrap()
            };
            if !right && hash != [0; 32] && !nodes.contains_key(&hash) {
                hash[0] |= 128;
            }
        }
    }
    (root, proof.into_values().collect())
}

fn request(start: u8, end: u8) -> StateRequest {
    StateRequest {
        block: [42; 32],
        start: state_key(start),
        end: state_key(end),
        max_size: 1000,
    }
}

#[test]
fn boundaries_completeness_and_adversaries() {
    let map: BTreeMap<_, _> = [2, 4, 6, 8, 10]
        .into_iter()
        .map(|i| (state_key(i), vec![i; usize::from(i) + 30]))
        .collect();
    let req = request(3, 9);
    let (root, nodes) = prove(&map, req.start, state_key(8));
    let response = StateResponse {
        nodes,
        entries: map
            .range(req.start..=req.end)
            .map(|(k, v)| (*k, v.clone()))
            .collect(),
    };
    assert_eq!(
        verify_range(&root, &req, &response).unwrap().entries,
        response.entries
    );
    let mut bad = response.clone();
    bad.entries.remove(1);
    assert_eq!(
        verify_range(&root, &req, &bad),
        Err(ProofError::RootMismatch)
    );
    let mut bad = response.clone();
    bad.entries[0].1[0] ^= 1;
    assert!(verify_range(&root, &req, &bad).is_err());
    let mut bad = response.clone();
    bad.entries.insert(1, (state_key(5), vec![]));
    assert!(verify_range(&root, &req, &bad).is_err());
    let mut bad = response.clone();
    bad.entries.reverse();
    assert_eq!(
        verify_range(&root, &req, &bad),
        Err(ProofError::UnsortedEntries)
    );
    let mut bad = response.clone();
    bad.nodes.clear();
    assert_eq!(
        verify_range(&root, &req, &bad),
        Err(ProofError::MissingNode)
    );
    assert!(verify_range(&[7; 32], &req, &response).is_err());
    let mut bad = response.clone();
    bad.nodes.push(bad.nodes[0]);
    assert_eq!(
        verify_range(&root, &req, &bad),
        Err(ProofError::DuplicateNode)
    );
    let (root, nodes) = prove(&map, req.start, state_key(6));
    let early = StateResponse {
        nodes,
        entries: response.entries[..2].to_vec(),
    };
    assert_eq!(
        verify_range(&root, &req, &early).unwrap().complete_to,
        state_key(6)
    );
    for i in 0..response.nodes.len() {
        for byte in 0..64 {
            let mut bad = response.clone();
            bad.nodes[i][byte] ^= 0x80;
            let _ = verify_range(&root, &req, &bad);
        }
    }
}

#[test]
fn empty_range_start_path_has_conservative_coverage() {
    let map = [0x00, 0xc0, 0xe0]
        .into_iter()
        .map(|key| (state_key(key), vec![key]))
        .collect();
    let req = request(0x40, 0x80);
    // PolkaJam prove_range emits only prove_key(start) when no entry is returned.
    let (root, nodes) = prove(&map, req.start, req.start);
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().any(|node| blake2b_256(node) == root));
    assert!(nodes.contains(&leaf(&state_key(0x00), &[0x00]).unwrap()));
    let response = StateResponse {
        nodes,
        entries: vec![],
    };
    assert_eq!(
        verify_range(&root, &req, &response),
        Ok(VerifiedRange {
            entries: vec![],
            complete_to: req.start,
        })
    );
    // The same path can prove a shorter interval completely absent.
    let narrow = request(0x40, 0x7f);
    assert_eq!(
        verify_range(&root, &narrow, &response).unwrap().complete_to,
        narrow.end
    );
    // More evidence permits extending the original interval through its end.
    let (_, nodes) = prove(&map, req.start, req.end);
    assert_eq!(
        verify_range(
            &root,
            &req,
            &StateResponse {
                nodes,
                entries: vec![]
            }
        )
        .unwrap()
        .complete_to,
        req.end
    );
    // An empty response never claims absence of later keys merely because start
    // is absent, even when the requested interval includes an existing key.
    assert_eq!(
        verify_range(&root, &request(0x40, 0xe0), &response)
            .unwrap()
            .complete_to,
        req.start
    );
}

#[test]
fn empty_range_rejects_omitted_existing_start() {
    let map = [0x00, 0xc0, 0xe0]
        .into_iter()
        .map(|key| (state_key(key), vec![key]))
        .collect();
    let req = request(0x00, 0x80);
    let (root, nodes) = prove(&map, req.start, req.start);
    assert_eq!(
        verify_range(
            &root,
            &req,
            &StateResponse {
                nodes,
                entries: vec![]
            }
        ),
        Err(ProofError::RootMismatch)
    );
}

#[test]
fn empty_range_requires_start_proof_for_nonzero_root() {
    let map = [0x00, 0xc0, 0xe0]
        .into_iter()
        .map(|key| (state_key(key), vec![key]))
        .collect();
    let req = request(0x40, 0x80);
    let (root, nodes) = prove(&map, req.start, req.start);
    for nodes in [
        vec![],
        nodes
            .into_iter()
            .filter(|node| blake2b_256(node) == root)
            .collect(),
    ] {
        assert_eq!(
            verify_range(
                &root,
                &req,
                &StateResponse {
                    nodes,
                    entries: vec![]
                }
            ),
            Err(ProofError::MissingNode)
        );
    }
}

#[test]
fn absence_empty_and_value_thresholds() {
    for len in [0, 32, 33, 336 * 1023 + 2] {
        let map = BTreeMap::from([(state_key(8), vec![7; len])]);
        let (root, nodes) = prove(&map, state_key(8), state_key(8));
        let response = StateResponse {
            nodes,
            entries: map.clone().into_iter().collect(),
        };
        assert_eq!(
            verify_value(&root, &[0; 32], &state_key(8), &response).unwrap(),
            Some(vec![7; len])
        );
        let absent = StateResponse {
            nodes: response.nodes.clone(),
            entries: vec![],
        };
        assert_eq!(
            verify_value(&root, &[0; 32], &state_key(7), &absent).unwrap(),
            None
        );
    }
    let map = BTreeMap::from([(state_key(8), vec![0]), (state_key(9), vec![1])]);
    let (root, nodes) = prove(&map, state_key(1), state_key(1));
    assert_eq!(
        verify_value(
            &root,
            &[0; 32],
            &state_key(1),
            &StateResponse {
                nodes,
                entries: vec![]
            }
        )
        .unwrap(),
        None
    );
    assert_eq!(
        verify_range(
            &[0; 32],
            &request(0, 255),
            &StateResponse {
                nodes: vec![],
                entries: vec![]
            }
        )
        .unwrap()
        .complete_to,
        state_key(255)
    );
}

#[test]
fn decoding_limits_and_mutations() {
    let limits = ResponseLimits {
        max_nodes: 496,
        max_entries: 1,
        max_value_bytes: 400000,
        max_total_bytes: MAX_BYTES,
    };
    let value = vec![0; 336 * 1023 + 2];
    let mut entries = state_key(8).to_vec();
    entries.extend(codec::encode_natural(u64::try_from(value.len()).unwrap()));
    entries.extend(&value);
    let node = leaf(&state_key(8), &value).unwrap();
    let response = StateResponse::decode(&node, &entries, &limits).unwrap();
    assert_eq!(
        verify_value(&blake2b_256(&node), &[0; 32], &state_key(8), &response).unwrap(),
        Some(value)
    );
    assert_eq!(
        StateResponse::decode(&node[..63], &[], &limits),
        Err(DecodeError::UnexpectedEnd)
    );
    for end in 0..entries.len().min(80) {
        let _ = StateResponse::decode(&node, &entries[..end], &limits);
    }
    let mut over = entries.clone();
    over.extend(&entries);
    assert_eq!(
        StateResponse::decode(&node, &over, &limits),
        Err(DecodeError::LengthLimit)
    );
}

#[test]
fn key_constructors_and_wire_request() {
    assert_eq!(
        &service_key(255, 0x04030201)[..9],
        &[255, 1, 0, 2, 0, 3, 0, 4, 0]
    );
    let hash = blake2b_256(b"hello");
    let key = storage_key(0x04030201, b"hello");
    assert_eq!(&key[..8], &[1, hash[0], 2, hash[1], 3, hash[2], 4, hash[3]]);
    assert_eq!(&key[8..], &hash[4..27]);
    let req = request(4, 8);
    assert_eq!(&req.encode()[94..], &1000u32.to_le_bytes());
}

#[test]
fn many_small_entries_use_wire_budget_and_hostile_paths_have_work_cap() {
    let entries: Vec<_> = (0..30000u32)
        .map(|i| {
            let mut key = [0; 31];
            key[..4].copy_from_slice(&i.to_be_bytes());
            (key, vec![1])
        })
        .collect();
    let root = subtree(&entries, 0, &Cell::new(usize::MAX)).unwrap();
    let req = StateRequest {
        block: [0; 32],
        start: [0; 31],
        end: [255; 31],
        max_size: u32::MAX,
    };
    let map = entries.iter().cloned().collect();
    let (_, nodes) = prove(&map, req.start, entries.last().unwrap().0);
    assert!(verify_range(&root, &req, &StateResponse { nodes, entries }).is_ok());
    let entries = (0..8192u16)
        .flat_map(|i| {
            [0u8, 1].map(move |last| {
                let mut key = [255; 31];
                let prefix = (i << 3).to_be_bytes();
                key[0] = prefix[0];
                key[1] = prefix[1] | 7;
                key[30] = 254 | last;
                (key, vec![])
            })
        })
        .collect();
    assert_eq!(
        verify_range(
            &[1; 32],
            &req,
            &StateResponse {
                nodes: vec![],
                entries
            }
        ),
        Err(ProofError::Limit)
    );
}

#[test]
fn committed_public_root_vector() {
    // w3f/jamtestvectors 1dc503af, trie/trie.json, 32-byte embedded value.
    let key =
        hex::decode("3dbc5f775f6156957139100c343bb5ae6589af7398db694ab6c60630a9ed0fcd").unwrap();
    let key: StateKey = key[..31].try_into().unwrap();
    let value =
        hex::decode("4227b4a465084852cd87d8f23bec0db6fa7766b9685ab5e095ef9cda9e15e49d").unwrap();
    let (root, _) = prove(&BTreeMap::from([(key, value)]), key, key);
    assert_eq!(
        hex::encode(root),
        "5fd68f074c914741601931d64c6c772c18ab8a4cd0cd3a4fff0611a5d97ecc94"
    );
}

#[cfg(feature = "std")]
#[test]
#[ignore = "requires JAM_TEST_VECTORS public checkout"]
fn external_all_public_roots() {
    let path = std::env::var("JAM_TEST_VECTORS")
        .unwrap_or_else(|_| "/tmp/opencode/jamtestvectors-1dc503af".into());
    let vectors: serde_json::Value =
        serde_json::from_slice(&std::fs::read(alloc::format!("{path}/trie/trie.json")).unwrap())
            .unwrap();
    check_public_roots(&vectors);
}

#[test]
fn committed_public_trie_fixtures() {
    // Unmodified subset of w3f/jamtestvectors 1dc503af/trie/trie.json.
    let vectors = serde_json::from_str(include_str!("fixtures/public-trie.json")).unwrap();
    check_public_roots(&vectors);
}

fn check_public_roots(vectors: &serde_json::Value) {
    for vector in vectors.as_array().unwrap() {
        let map = vector["input"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                (
                    hex::decode(key).unwrap()[..31].try_into().unwrap(),
                    hex::decode(value.as_str().unwrap()).unwrap(),
                )
            })
            .collect();
        let (root, _) = prove(&map, [0; 31], [255; 31]);
        assert_eq!(hex::encode(root), vector["output"].as_str().unwrap());
    }
}

fn unhex(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn captured_request(item: &serde_json::Value) -> StateRequest {
    let wire = unhex(&item["request_frame_hex"]);
    assert_eq!(&wire[..4], &98u32.to_le_bytes());
    let request = StateRequest {
        block: wire[4..36].try_into().unwrap(),
        start: wire[36..67].try_into().unwrap(),
        end: wire[67..98].try_into().unwrap(),
        max_size: u32::from_le_bytes(wire[98..102].try_into().unwrap()),
    };
    assert_eq!(wire[4..], request.encode());
    request
}

fn captured_messages(item: &serde_json::Value) -> (Vec<u8>, Vec<u8>) {
    let wire = unhex(&item["response_frame_hex"]);
    let size = usize::try_from(u32::from_le_bytes(wire[..4].try_into().unwrap())).unwrap();
    let entries = 8 + size;
    assert_eq!(
        usize::try_from(u32::from_le_bytes(
            wire[entries - 4..entries].try_into().unwrap()
        ))
        .unwrap(),
        wire.len() - entries
    );
    (wire[4..size + 4].to_vec(), wire[entries..].to_vec())
}

fn capture_limits() -> ResponseLimits {
    ResponseLimits {
        max_nodes: 496,
        max_entries: 32768,
        max_value_bytes: MAX_BYTES,
        max_total_bytes: MAX_BYTES + 496 * 64,
    }
}

fn captured_range(item: &serde_json::Value) -> VerifiedRange {
    let request = captured_request(item);
    let (nodes, entries) = captured_messages(item);
    let response = StateResponse::decode(&nodes, &entries, &capture_limits()).unwrap();
    let root = unhex(&item["root"]).try_into().unwrap();
    verify_range(&root, &request, &response).unwrap()
}

#[test]
fn captured_ce129_single_early_stop_and_absence() {
    use crate::jam::{params::Params, types::Header};
    let capture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/polkajam-ce129.json")).unwrap();
    let params = Params::from_protocol_parameters(&unhex(&capture["protocol_parameters"])).unwrap();
    let child = Header::decode(&params, &unhex(&capture["child"]["header_hex"])).unwrap();
    for item in capture["exchanges"].as_array().unwrap() {
        if item["reset"] == true {
            continue;
        }
        let request = captured_request(item);
        assert_eq!(hex::encode(child.hash(&params)), item["root_header"]);
        assert_eq!(child.parent, request.block);
        assert_eq!(hex::encode(child.prior_state_root), item["root"]);
        let range = captured_range(item);
        assert_eq!(hex::encode(range.complete_to), item["complete_to"]);
        let keys: Vec<_> = range
            .entries
            .iter()
            .map(|(key, _)| hex::encode(key))
            .collect();
        assert_eq!(serde_json::to_value(keys).unwrap(), item["expected_keys"]);
        let (nodes, entries) = captured_messages(item);
        let response = StateResponse::decode(&nodes, &entries, &capture_limits()).unwrap();
        if item["name"] == "single-c8" {
            let value = verify_value(
                &child.prior_state_root,
                &request.block,
                &request.start,
                &response,
            )
            .unwrap()
            .unwrap();
            assert_eq!(value.len(), 1 + 6 * 336);
            let validators = codec::decode_active_validators(&params, &value).unwrap();
            assert_eq!(validators.len(), 6);
            assert_eq!(value, unhex(&capture["expected_validators_hex"]));
            assert_eq!(codec::encode_active_validators(&validators), value);
        } else if item["name"] == "absent" {
            assert_eq!(
                verify_value(
                    &child.prior_state_root,
                    &request.block,
                    &request.start,
                    &response
                ),
                Ok(None)
            );
        } else {
            assert_eq!(item["name"], "early-stop");
            assert_eq!(range.entries.len(), 1);
            assert_eq!(range.complete_to, range.entries.last().unwrap().0);
            assert!(range.complete_to < request.end);
        }
    }
}

#[test]
fn captured_ce129_mutations_are_bounded_and_do_not_panic() {
    let capture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/polkajam-ce129.json")).unwrap();
    for item in capture["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["reset"] == false)
    {
        let request = captured_request(item);
        let root = unhex(&item["root"]).try_into().unwrap();
        let (nodes, entries) = captured_messages(item);
        for index in 0..nodes.len() + entries.len() {
            let (mut nodes, mut entries) = (nodes.clone(), entries.clone());
            if index < nodes.len() {
                nodes[index] ^= 0x80;
            } else {
                entries[index - nodes.len()] ^= 0x80;
            }
            if let Ok(response) = StateResponse::decode(&nodes, &entries, &capture_limits()) {
                let _ = verify_range(&root, &request, &response);
            }
        }
    }
}

#[cfg(feature = "std")]
#[test]
#[ignore = "requires the browser corpus; set JAM_D2_FIXTURES"]
fn external_ce129_corpus_and_join_state() {
    use crate::jam::{
        finality,
        params::Params,
        state::LightState,
        types::{Block, GenesisLightState},
        verify,
    };
    // Captured at PolkaJam 27d63b8d (D15, pin move): the join reads at the
    // finalized head F against the posterior root its justification signs.
    let directory = std::env::var("JAM_D2_FIXTURES").unwrap_or_else(|_| {
        "/home/sebastian/work/repos/jam-light-client-planning/fixtures/d15".into()
    });
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(alloc::format!("{directory}/ce129.capture")).unwrap(),
    )
    .unwrap();
    let params =
        Params::from_protocol_parameters(&unhex(&capture["spec"]["protocol_parameters"])).unwrap();
    let exchanges = capture["exchanges"].as_array().unwrap();
    let item = |name| exchanges.iter().find(|e| e["name"] == name).unwrap();
    let wire = unhex(&item("join-head")["response_frame_hex"]);
    let blocks = Block::decode_sequence(&params, &wire[4..], MAX_BYTES, 1).unwrap();
    assert_eq!(blocks.len(), 1);
    let f = &blocks[0].header;
    let wire = unhex(&item("finalized-child")["response_frame_hex"]);
    let children = Block::decode_sequence(&params, &wire[4..], MAX_BYTES, 1).unwrap();
    assert_eq!(children.len(), 1);
    let child = &children[0].header;
    assert_eq!(child.parent, f.hash(&params));
    // F's justification: the signed target is F with its posterior root, which
    // the child header independently states as its prior state root.
    let wire = unhex(&item("join-finality")["response_frame_hex"]);
    let limits = finality::Limits {
        max_bytes: MAX_BYTES,
        max_ancestry_headers: 128,
        max_ancestry_steps: 1024,
    };
    let proof = finality::Justification::decode(&params, &wire[4..], limits).unwrap();
    assert_eq!(proof.target().hash, f.hash(&params));
    assert_eq!(proof.target().slot, f.slot);
    assert_eq!(proof.target().state_root, child.prior_state_root);
    let root = proof.target().state_root;
    for name in [
        "single-c8",
        "range-c1-c16",
        "early-stop",
        "absent",
        "join-c4",
        "join-c6",
        "join-c8",
        "join-c11",
        "join-range-c4-c11",
    ] {
        let exchange = item(name);
        assert_eq!(exchange["kind"], 129);
        assert_eq!(exchange["reset"], false);
        let request = captured_request(exchange);
        assert_eq!(request.block, f.hash(&params));
        assert_eq!(unhex(&exchange["root"]), root);
        let carrier = if name.starts_with("join-") { f } else { child };
        assert_eq!(hex::encode(carrier.hash(&params)), exchange["root_header"]);
        let range = captured_range(exchange);
        assert_eq!(
            range.entries.len(),
            exchange["entries"].as_array().unwrap().len()
        );
        if exchange["name"] == "early-stop" {
            assert!(range.complete_to < captured_request(exchange).end);
        } else {
            assert_eq!(range.complete_to, captured_request(exchange).end);
        }
    }
    assert_eq!(captured_range(item("range-c1-c16")).entries.len(), 16);
    assert_eq!(item("unknown-block")["reset"], true);
    assert_eq!(item("unknown-block")["streamErrorCode"], 6);
    let mut entries = Vec::new();
    for name in ["join-c4", "join-c6", "join-c8", "join-c11"] {
        entries.extend(captured_range(item(name)).entries);
    }
    let state = GenesisLightState::from_state_items(
        &params,
        entries.iter().map(|(k, v)| (k, v.as_slice())),
    )
    .unwrap();
    assert_eq!(state.slot, f.slot);
    let wide = captured_range(item("join-range-c4-c11"));
    for entry in &entries {
        assert!(wide.entries.contains(entry));
    }
    // The state read at F is the posterior state at F: anchored there, the
    // captured child verifies as its successor.
    let anchor = verify::verified_genesis(
        &params,
        f.clone(),
        LightState::from_anchor(&params, &state).unwrap(),
    );
    let verified = verify::verify_header(&params, &anchor, child.clone(), u64::MAX).unwrap();
    assert_eq!(verified.hash, child.hash(&params));
    // Signature interoperability under this fixed dev set, NOT a warp authority-transition oracle.
    let authorities: Vec<_> = state.active_validators.iter().map(|v| v.ed25519).collect();
    proof
        .verify(
            &params,
            proof.set_id(),
            &authorities,
            &anchor.hash,
            limits,
            |hash| {
                (*hash == anchor.hash)
                    .then(|| finality::ancestry_link(&anchor))
                    .flatten()
            },
        )
        .unwrap();
}

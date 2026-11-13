// Smoldot
// Copyright (C) 2019-2026  Parity Technologies (UK) Ltd.
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

use std::{str::FromStr as _, time::Duration};

use log::info;
use smoldot::{libp2p::PeerId, network::codec::statement_hash};
use smoldot_e2e_tests::statement::*;
use smoldot_e2e_tests::*;

/// More collators than the four gossip slots of smoldot, so that some of them stay outside its
/// gossip peers.
const COLLATORS: [&str; 6] = ["alice", "bob", "charlie", "dave", "eve", "ferdie"];

/// With the v2 DHT path on, smoldot opens a statement link to the peer closest to a subscribed
/// topic, also when that peer is none of its gossip peers.
///
/// Flow:
///   1. Spawn six collators with the v2 DHT path on and a replication factor of one, so that
///      a statement is kept by the single collator closest to its topic.
///   2. For every collator, submit a statement on the topic that the collator is closest to,
///      and wait until the collator holds it and the other ones dropped their transient copy.
///   3. Start smoldot. It picks a collator outside its gossip peers and subscribes to that
///      collator's topic.
///   4. Smoldot must receive the statement, which only that collator can deliver.
#[tokio::test(flavor = "multi_thread")]
async fn reaches_the_peer_closest_to_a_topic() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let (seed, pubkey) = test_keypair();

    let base_dir = resolve_base_dir()?;
    let para_spec_path = create_para_chain_spec_with_allowances(&[pubkey], &base_dir)?;
    let network = spawn_network_with(
        &base_dir,
        &para_spec_path,
        &COLLATORS,
        &["--statement-v2-dht", "--statement-replication-factor=1"],
    )
    .await?;
    info!("Network spawned");

    let (relay_base, para_base) = spawned_chain_spec_paths(&network)?;
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();
    let (relay_spec_path, para_spec_path) =
        prepare_runtime_specs(&network, &relay_base, &para_base, &base_dir_str).await?;

    // The full nodes key a peer by the blake2b-256 hash of its peer id, which `statement_hash`
    // computes. A topic equal to that key has the peer at distance zero.
    let mut targets = Vec::new();
    for name in COLLATORS {
        let node = network.get_node(name)?;
        let peer_id = node
            .multiaddr()
            .rsplit("/p2p/")
            .next()
            .expect("rsplit yields at least one item");
        let topic = statement_hash(
            PeerId::from_str(peer_id)
                .map_err(|e| anyhow::anyhow!("peer id of {name}: {e}"))?
                .as_bytes(),
        );
        let statement = create_test_statement(&seed, &topic, format!("steering-{name}").as_bytes());
        targets.push((name, peer_id.to_owned(), topic, statement));
    }

    // Bind the RPC clients: dropping one closes its subscription.
    let mut subscriptions = Vec::new();
    for (name, ..) in &targets {
        let rpc = network.get_node(*name)?.rpc().await?;
        let subscription = subscribe_any(&rpc).await?;
        subscriptions.push((rpc, subscription));
    }

    // Every statement enters through one collator and travels to its replica.
    let alice = network.get_node("alice")?;
    for (name, _, _, statement) in &targets {
        submit_statement(alice, statement, name).await?;
    }
    for ((name, _, _, statement), (_, subscription)) in targets.iter().zip(&mut subscriptions) {
        loop {
            if receive_statements(1, subscription, 120)
                .await?
                .contains(statement)
            {
                break;
            }
        }
        info!("{name} holds the statement of its topic");
    }
    drop(subscriptions);

    // A collator that only passed a statement on drops it at its next retention sweep, which
    // runs every 29 seconds.
    tokio::time::sleep(Duration::from_secs(45)).await;

    info!("Ensuring smoldot JS bundle is built");
    ensure_smoldot_built();
    info!("Ensuring JS test dependencies are installed");
    ensure_js_deps_installed();

    let targets_json = serde_json::to_string(
        &targets
            .iter()
            .map(|(name, peer_id, topic, statement)| {
                serde_json::json!({
                    "name": name,
                    "peerId": peer_id,
                    "topic": format!("0x{}", hex::encode(topic)),
                    "statement": statement,
                })
            })
            .collect::<Vec<_>>(),
    )?;

    run_shared_test(
        Host::Node,
        "statement_store_peer_steering",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec_path.to_str().unwrap()),
            ("PARA_CHAIN_SPEC", para_spec_path.to_str().unwrap()),
            ("TARGETS", targets_json.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow::anyhow!("JS test failed: {e}"))?;

    Ok(())
}

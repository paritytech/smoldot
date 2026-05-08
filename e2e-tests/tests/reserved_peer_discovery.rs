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

//! End-to-end test for Kademlia peer discovery.
//!
//! Spawns a westend-local relay with two validators:
//!
//! - `validator-a`: chain-spec bootnode. Smoldot's address book starts
//!   knowing only A.
//! - `validator-b`: not a chain-spec bootnode. Zombienet still patches A's
//!   address into the chain spec before B starts, so B uses A as its own
//!   bootnode and the two validators gossip-peer with each other normally.
//!
//! Smoldot is given the same chain spec, sees only A in `bootNodes`, and
//! must learn about B through Kademlia FindNode against A (Identify
//! advertises A's Kad protocol; FindNode then surfaces B from A's routing
//! table). The test passes if `system_peers` on smoldot eventually lists
//! B's peer-id — that can only happen after smoldot dials B directly,
//! which can only happen after Kademlia surfaced B's address.

use anyhow::anyhow;
use smoldot_e2e_tests::*;
use std::path::PathBuf;
use zombienet_sdk::NetworkConfigBuilder;

/// Extracts the trailing `/p2p/<peer_id>` segment from a multiaddr string.
fn peer_id_from_multiaddr(multiaddr: &str) -> Result<String, anyhow::Error> {
    let suffix = multiaddr
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow!("multiaddr is empty: {multiaddr}"))?;
    if !suffix.starts_with("12D3KooW") {
        return Err(anyhow!(
            "multiaddr {multiaddr} does not end with a /p2p/<peer_id> segment"
        ));
    }
    Ok(suffix.to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn reserved_peer_discovery() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let base_dir = resolve_base_dir()?;
    let images = zombienet_sdk::environment::get_images_from_env();
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    // Reserved-peer args use zombienet's `{{ZOMBIE:<name>:multiAddress}}`
    // placeholder, which is resolved at spawn time once both peer-ids are
    // known. The Rust SDK passes through these placeholders unchanged.
    let config = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            r.with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str())
                // Only A is a chain-spec bootnode. Zombienet writes A's
                // multiaddr into the relay chain spec it emits, so smoldot
                // (which we point at that same chain spec) sees only A
                // initially. Discovery must surface B.
                .with_validator(|n| n.with_name("validator-a").bootnode(true))
                // B is not a chain-spec bootnode, so it stays out of the
                // emitted spec's `bootNodes` array. Zombienet still feeds
                // A's address to B through its own internal --bootnodes
                // CLI arg, so A and B gossip-peer with each other.
                .with_validator(|n| n.with_name("validator-b").bootnode(false))
        })
        .with_global_settings(|g| g.with_base_dir(base_dir_str.as_str()))
        .build()
        .map_err(|errs| {
            anyhow!(
                "config errors: {}",
                errs.into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(config).await?;
    network.detach().await;
    network.wait_until_is_up(120).await?;

    // Wait for the validators to peer with each other before we attach
    // smoldot — that way we know B is reachable and Kademlia on A has
    // something to return for FindNode queries on the chain's namespace.
    let validator_a = network.get_node("validator-a")?;
    let validator_b = network.get_node("validator-b")?;
    validator_a
        .wait_metric_with_timeout(
            "substrate_sub_libp2p_peers_count",
            |n| n >= 1.0,
            120u64,
        )
        .await
        .map_err(|e| anyhow!("validator-a never peered with validator-b: {e}"))?;

    let validator_b_peer_id = peer_id_from_multiaddr(validator_b.multiaddr())?;
    log::info!("validator-b peer_id={validator_b_peer_id}");

    // Locate the relay chain spec zombienet has emitted (with bootnodes
    // patched in — only validator-a at this point).
    let zombienet_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let relay_spec = zombienet_base.join(format!("{}.json", network.relaychain().chain()));

    ensure_smoldot_built();
    ensure_js_deps_installed();
    run_js_test(
        "js/reserved_peer_discovery.js",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec.to_str().expect("UTF-8 path")),
            ("VALIDATOR_B_PEER_ID", validator_b_peer_id.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow!("JS test failed: {e}"))?;

    Ok(())
}

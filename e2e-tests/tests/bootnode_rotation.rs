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

//! End-to-end test for the rotation of gossip slots away from the bootnodes.
//!
//! Spawns a westend-local relay with two validators and four full nodes. Only
//! `validator-a` is listed in the chain spec `bootNodes`. Smoldot first fills
//! a slot with it, discovers the other nodes, and once synced must free the
//! bootnode slot: `validator-a` leaves `system_peers` while the other nodes
//! take the slots. It then stays out, as smoldot rejects the block announces
//! link that `validator-a` reopens from its side while it is banned.
//!
//! At least four non-bootnodes are needed: three share smoldot's four slots
//! with the bootnode and one is free to take its slot. The test has five.

use anyhow::anyhow;
use smoldot_e2e_tests::*;
use std::path::PathBuf;
use zombienet_sdk::NetworkConfigBuilder;

const FULL_NODES: [&str; 4] = ["full-c", "full-d", "full-e", "full-f"];

#[tokio::test(flavor = "multi_thread")]
async fn bootnode_rotation() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let base_dir = resolve_base_dir()?;
    let images = zombienet_sdk::environment::get_images_from_env();
    let base_dir_str = base_dir.to_str().expect("UTF-8 path").to_owned();

    let config = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            let r = r
                .with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str())
                .with_validator(|n| {
                    n.with_name("validator-a")
                        .bootnode(true)
                        .with_args(webrtc_args())
                })
                .with_validator(|n| {
                    n.with_name("validator-b")
                        .bootnode(false)
                        .with_args(webrtc_args())
                });
            FULL_NODES.into_iter().fold(r, |r, name| {
                r.with_fullnode(|n| n.with_name(name).bootnode(false).with_args(webrtc_args()))
            })
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

    let bootnode_peer_id = peer_id_from_multiaddr(network.get_node("validator-a")?.multiaddr())?;
    log::info!("validator-a peer_id={bootnode_peer_id}");

    let zombienet_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let spawned_spec = zombienet_base.join(format!("{}.json", network.relaychain().chain()));

    let relay_spec = prepare_runtime_spec(
        &network,
        &spawned_spec,
        &["validator-a"],
        &base_dir_str,
        "relay-spec.json",
    )
    .await?;

    ensure_smoldot_built();
    run_test(
        "bootnode_rotation",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec.to_str().expect("UTF-8 path")),
            ("BOOTNODE_PEER_ID", bootnode_peer_id.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow!("test failed: {e}"))?;

    Ok(())
}

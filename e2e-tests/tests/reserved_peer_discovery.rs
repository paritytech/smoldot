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
//! - `validator-a`: chain-spec bootnode. Refuses inbound light-client gossip
//!   slots (`--in-peers-light 0`) so smoldot cannot establish a gossip
//!   substream with it — only Kademlia requests are accepted.
//! - `validator-b`: regular validator; smoldot can gossip-connect to it.
//!
//! Smoldot is given the chain spec, sees only A in `bootNodes`, and must
//! learn about B through a Kademlia `FindNode` request against A. The test
//! passes if `system_peers` on smoldot eventually lists B's peer-id — which
//! can only happen after smoldot dials B directly, which can only happen
//! after Kademlia surfaced B's address.

use anyhow::anyhow;
use smoldot_e2e_tests::*;
use std::path::PathBuf;
use zombienet_sdk::NetworkConfigBuilder;

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

    let config = NetworkConfigBuilder::new()
        .with_relaychain(|r| {
            r.with_chain("westend-local")
                .with_default_command("polkadot")
                .with_default_image(images.polkadot.as_str())
                // The WebRTC listener is per node: one UDP port each.
                .with_validator(|n| {
                    n.with_name("validator-a")
                        .bootnode(true)
                        .with_args([vec![("--in-peers-light", "0").into()], webrtc_args()].concat())
                })
                .with_validator(|n| {
                    n.with_name("validator-b")
                        .bootnode(false)
                        .with_args(webrtc_args())
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

    let validator_b = network.get_node("validator-b")?;
    let validator_b_peer_id = peer_id_from_multiaddr(validator_b.multiaddr())?;
    log::info!("validator-b peer_id={validator_b_peer_id}");

    let zombienet_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let spawned_spec = zombienet_base.join(format!("{}.json", network.relaychain().chain()));

    // Hand smoldot a spec whose bootNodes carry validator-a's live TCP + WebRTC
    // multiaddrs. Only A, the test's invariant is that B is reachable solely
    // through Kademlia discovery.
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
        "reserved_peer_discovery",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec.to_str().expect("UTF-8 path")),
            ("REQUIRED_PEER_ID", validator_b_peer_id.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow!("test failed: {e}"))?;

    Ok(())
}

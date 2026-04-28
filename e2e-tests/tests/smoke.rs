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

use std::path::PathBuf;

use anyhow::anyhow;
use smoldot_e2e_tests::*;
use zombienet_sdk::NetworkConfigBuilder;

const PARA_ID: u32 = 1004;
const REQUIRED_BLOCKS: u32 = 5;

/// Smoke test: spawn westend-local + people-westend-local (both built-in
/// chains of `polkadot` and `polkadot-parachain`), then run smoldot and
/// assert it sees new parachain blocks.
#[tokio::test(flavor = "multi_thread")]
async fn smoke() -> Result<(), anyhow::Error> {
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
                .with_validator(|n| n.with_name("validator-0").bootnode(true))
                .with_validator(|n| n.with_name("validator-1").bootnode(true))
        })
        .with_parachain(|p| {
            p.with_id(PARA_ID)
                .with_default_command("polkadot-parachain")
                .with_default_image(images.cumulus.as_str())
                .with_chain("people-westend-local")
                .with_default_args(vec![
                    "--force-authoring".into(),
                    "--authoring=slot-based".into(),
                ])
                .with_collator(|n| n.with_name("alice").bootnode(true))
                .with_collator(|n| n.with_name("bob").bootnode(true))
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

    network
        .get_node("alice")?
        .wait_metric_with_timeout(
            "block_height{status=\"best\"}",
            |h| h >= REQUIRED_BLOCKS as f64,
            300u64,
        )
        .await
        .map_err(|e| anyhow!("alice did not produce parachain blocks: {e}"))?;

    let zombienet_base = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let relay_spec = zombienet_base.join(format!("{}.json", network.relaychain().chain()));
    let parachain = network
        .parachain(PARA_ID)
        .ok_or_else(|| anyhow!("parachain {PARA_ID} not found"))?;
    let para_spec_name = parachain.chain_id().unwrap_or(parachain.unique_id());
    let para_spec = zombienet_base.join(format!("{para_spec_name}.json"));

    ensure_smoldot_built();
    ensure_js_deps_installed();
    let required_blocks = REQUIRED_BLOCKS.to_string();
    run_js_test(
        "js/smoke.js",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec.to_str().expect("UTF-8 path")),
            ("PARA_CHAIN_SPEC", para_spec.to_str().expect("UTF-8 path")),
            ("REQUIRED_BLOCKS", required_blocks.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow!("JS test failed: {e}"))?;

    Ok(())
}

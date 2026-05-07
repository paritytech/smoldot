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

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde::Serialize;
use smoldot_e2e_tests::{
    bulletin, ensure_js_deps_installed, ensure_smoldot_built, resolve_base_dir, run_js_test,
};
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfigBuilder};

/// GCS URLs for the snapshots produced by `bulletin_generate_snapshot`.
const DB_SNAPSHOT_RELAY: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/smoldot/bulletin_fetch/relay-2026-05-04.tgz";
const DB_SNAPSHOT_BULLETIN_FULL: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/smoldot/bulletin_fetch/bulletin-full-2026-05-04.tgz";
const DB_SNAPSHOT_BULLETIN_PARTIAL: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/smoldot/bulletin_fetch/bulletin-partial-2026-05-04.tgz";

#[derive(Serialize)]
struct PayloadJson {
    label: &'static str,
    cid: String,
    sha256: String,
    size: u64,
    on_partial: bool,
}

/// Smoldot fetches every CID in `bulletin::payloads()`, asserts NotFound
/// for an unrelated CID, and exercises mixed-availability peer selection.
#[tokio::test(flavor = "multi_thread")]
async fn bulletin_fetch() -> Result<()> {
    env_logger::try_init().ok();

    let chain_spec = bulletin_chain_spec();
    let base_dir = resolve_base_dir()?;

    let relay = get_snapshot_url(DB_SNAPSHOT_RELAY, "DB_SNAPSHOT_RELAY_OVERRIDE");
    let bulletin_full = get_snapshot_url(
        DB_SNAPSHOT_BULLETIN_FULL,
        "DB_SNAPSHOT_BULLETIN_FULL_OVERRIDE",
    );
    let bulletin_partial = get_snapshot_url(
        DB_SNAPSHOT_BULLETIN_PARTIAL,
        "DB_SNAPSHOT_BULLETIN_PARTIAL_OVERRIDE",
    );

    let network = spawn_with_snapshots(
        &base_dir,
        &chain_spec,
        &relay,
        &bulletin_full,
        &bulletin_partial,
    )
    .await?;

    let (relay_spec, bulletin_spec) = chain_spec_paths(&network)?;

    ensure_smoldot_built();
    ensure_js_deps_installed();

    let payloads_json = serde_json::to_string(
        &bulletin::payloads()
            .iter()
            .map(|p| PayloadJson {
                label: p.label,
                cid: p.predicted_cid(),
                sha256: p.sha256_hex(),
                size: p.size(),
                on_partial: p.on_partial,
            })
            .collect::<Vec<_>>(),
    )?;
    let missing_cid = bulletin::sha256_cid(b"smoldot-bitswap-not-on-chain").to_string();
    let relay_spec = relay_spec
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 relay spec path"))?;
    let bulletin_spec = bulletin_spec
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 bulletin spec path"))?;

    run_js_test(
        "js/bulletin_fetch.js",
        &[
            ("RELAY_CHAIN_SPEC", relay_spec),
            ("BULLETIN_CHAIN_SPEC", bulletin_spec),
            ("PAYLOADS_JSON", payloads_json.as_str()),
            ("MISSING_CID", missing_cid.as_str()),
        ],
    )
    .await
    .map_err(|e| anyhow!("JS test failed: {e}"))
}

/// Returns the GCS URL by default, or the contents of `env_var` if set
/// (so a developer can point at a local `.tgz` for iteration).
fn get_snapshot_url(default: &str, env_var: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.to_string())
}

fn bulletin_chain_spec() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chain-specs/bulletin-westend-local-spec.json")
}

async fn spawn_with_snapshots(
    base_dir: &Path,
    chain_spec: &Path,
    relay_snap: &str,
    bulletin_full_snap: &str,
    bulletin_partial_snap: &str,
) -> Result<Network<LocalFileSystem>> {
    let chain_spec_str = chain_spec
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 chain spec path"))?
        .to_string();
    let base_dir_str = base_dir
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 base dir"))?
        .to_string();
    let relay = relay_snap.to_string();
    let bulletin_full = bulletin_full_snap.to_string();
    let bulletin_partial = bulletin_partial_snap.to_string();

    let cfg = NetworkConfigBuilder::new()
        .with_relaychain(|rc| {
            rc.with_chain(bulletin::RELAY_CHAIN)
                .with_default_command(bulletin::RELAY_BINARY)
                .with_validator(|n| {
                    n.with_name("alice")
                        .bootnode(true)
                        .with_db_snapshot(relay.as_str())
                })
                .with_validator(|n| {
                    n.with_name("bob")
                        .bootnode(true)
                        .with_db_snapshot(relay.as_str())
                })
        })
        .with_parachain(|p| {
            p.with_id(bulletin::PARA_ID)
                .with_chain_spec_path(chain_spec_str.as_str())
                .cumulus_based(true)
                .with_collator(|c| {
                    c.with_name("collator-1")
                        .validator(true)
                        .bootnode(true)
                        .with_command(bulletin::PARA_BINARY)
                        .with_db_snapshot(bulletin_full.as_str())
                        .with_args(vec!["--ipfs-server".into()])
                })
                .with_collator(|c| {
                    c.with_name("collator-2")
                        .validator(true)
                        .bootnode(true)
                        .with_command(bulletin::PARA_BINARY)
                        .with_db_snapshot(bulletin_partial.as_str())
                        .with_args(vec!["--ipfs-server".into()])
                })
        })
        .with_global_settings(|g| g.with_base_dir(base_dir_str.as_str()))
        .build()
        .map_err(|e| anyhow!("network config errors: {e:?}"))?;

    let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
    let network = spawn_fn(cfg).await?;
    network.detach().await;
    network.wait_until_is_up(180).await?;
    Ok(network)
}

/// Returns the raw chain-spec files zombienet emits for the relay and the
/// bulletin parachain. Smoldot consumes these directly.
fn chain_spec_paths(network: &Network<LocalFileSystem>) -> Result<(PathBuf, PathBuf)> {
    let base_dir = PathBuf::from(
        network
            .base_dir()
            .ok_or_else(|| anyhow!("network has no base_dir"))?,
    );
    let relay_chain = network.relaychain().chain();
    let relay_path = base_dir.join(format!("{relay_chain}.json"));
    let para = network
        .parachain(bulletin::PARA_ID)
        .ok_or_else(|| anyhow!("parachain {} not found", bulletin::PARA_ID))?;
    let para_path = base_dir.join(format!("{}.json", para.unique_id()));
    Ok((relay_path, para_path))
}

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

use anyhow::{anyhow, Result};
use serde::Serialize;
use smoldot_e2e_tests::{
    bulletin, ensure_smoldot_built,
    harness::{
        bulletin_chain_spec, chain_spec_paths, print_dev_mode_invocation, resolve_bundle,
        spawn_with_snapshots,
    },
    prepare_runtime_spec, resolve_base_dir, run_test,
};

#[derive(Serialize)]
struct PayloadJson {
    label: &'static str,
    cid: String,
    sha256: String,
    size: u64,
    on_partial: bool,
}

/// Smoldot fetches every CID in `bulletin::payloads()`, asserts NotFound
/// for an unrelated CID, and exercises mixed-availability peer selection
/// (some CIDs only on the full-snapshot collator).
#[tokio::test(flavor = "multi_thread")]
async fn bulletin_fetch() -> Result<()> {
    env_logger::try_init().ok();

    let chain_spec = bulletin_chain_spec();
    let base_dir = resolve_base_dir()?;

    let snaps = resolve_bundle(&base_dir)?;

    let network = spawn_with_snapshots(&base_dir, &chain_spec, &snaps, &[]).await?;

    let (relay_spec, bulletin_spec) = chain_spec_paths(&network)?;

    // Overwrite the specs' bootNodes with the live TCP + WebRTC multiaddrs so
    // both hosts can connect (Node over TCP, browser over WebRTC). Both
    // collators must be dialable: payloads are split across full/partial.
    let base_dir_str = base_dir.to_str().ok_or_else(|| anyhow!("non-utf8 base dir"))?;
    let relay_spec =
        prepare_runtime_spec(&network, &relay_spec, &["alice", "bob"], base_dir_str, "relay-spec.json")
            .await?;
    let bulletin_spec = prepare_runtime_spec(
        &network,
        &bulletin_spec,
        &["collator-1", "collator-2"],
        base_dir_str,
        "bulletin-spec.json",
    )
    .await?;

    ensure_smoldot_built();

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

    let env_pairs = [
        ("RELAY_CHAIN_SPEC", relay_spec),
        ("BULLETIN_CHAIN_SPEC", bulletin_spec),
        ("PAYLOADS_JSON", payloads_json.as_str()),
        ("MISSING_CID", missing_cid.as_str()),
    ];

    // `DEV_MODE=1` skips the JS bitswap suite and keeps the network alive
    // for `KEEP_ALIVE_SECS` seconds (default 36000) so a developer can
    // run the JS client manually (the printed `node …` invocation has
    // every env var the test would have set).
    if std::env::var("DEV_MODE").is_ok() {
        let mut dev_env = env_pairs.to_vec();
        dev_env.push(("TEST_NAME", "bulletin_fetch"));
        print_dev_mode_invocation(&dev_env, "hosts/node/run.js");
        let secs: u64 = std::env::var("KEEP_ALIVE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36000);
        eprintln!(
            "DEV_MODE: keeping zombienet alive for {secs}s (set KEEP_ALIVE_SECS to override)..."
        );
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        return Ok(());
    }

    run_test("bulletin_fetch", &env_pairs)
        .await
        .map_err(|e| anyhow!("test failed: {e}"))
}

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
    bulletin, ensure_js_deps_installed, ensure_smoldot_built,
    harness::{
        bulletin_chain_spec, chain_spec_paths, get_snapshot_url, print_dev_mode_invocation,
        spawn_with_snapshots, SnapshotUrls, DB_SNAPSHOT_BULLETIN_FULL,
        DB_SNAPSHOT_BULLETIN_PARTIAL, DB_SNAPSHOT_RELAY,
    },
    resolve_base_dir, run_js_test,
};

/// Mirrors `light-base/src/bitswap_service.rs::MAX_CIDS_PER_REQUEST`.
const MAX_CIDS: u32 = 64;

#[derive(Serialize)]
struct PayloadJson {
    label: &'static str,
    cid: String,
    sha256: String,
    size: u64,
    on_partial: bool,
}

/// Drives `bitswap_unstable_stream` against a real bulletin chain. The JS run
/// exercises: happy path, dedup rejection (-32803), too-many rejection
/// (-32801), empty-input rejection (-32802), per-CID errors, mixed-availability
/// (some CIDs only on the full-snapshot collator), and the spec requirement
/// that `bitswap_unstable_unstream` mid-stream silently suppresses `streamDone`.
#[tokio::test(flavor = "multi_thread")]
async fn bulletin_batch() -> Result<()> {
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
        SnapshotUrls {
            relay: &relay,
            bulletin_full: &bulletin_full,
            bulletin_partial: &bulletin_partial,
        },
        &["-lsub-libp2p::bitswap=trace", "-lsync=debug"],
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
    let max_cids = MAX_CIDS.to_string();
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
        ("MAX_CIDS", max_cids.as_str()),
    ];

    if std::env::var("DEV_MODE").is_ok() {
        print_dev_mode_invocation(&env_pairs, "js/bulletin_batch.js");
        let secs: u64 = std::env::var("KEEP_ALIVE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36000);
        eprintln!("DEV_MODE: keeping zombienet alive for {secs}s (set KEEP_ALIVE_SECS to override)...");
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        return Ok(());
    }

    run_js_test("js/bulletin_batch.js", &env_pairs)
        .await
        .map_err(|e| anyhow!("JS test failed: {e}"))
}

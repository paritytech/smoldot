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

use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Context, Result};
use smoldot_e2e_tests::{
    jam::{dev_mode_keep_alive, spawn_jam, BodyRun, Finality, POLKAJAM_COMMIT, VALIDATORS},
    SyncFile,
};

/// Live GRANDPA acceptance (D1, GRANDPA finality): a fresh browser client
/// verifies three authority sets, keeps a pinned header across pruning, and
/// keeps finalizing while jam0 is killed for 12 s and started again. Body:
/// `shared/jam_finality.js`.
///
/// `JAM_FINALITY_FIXTURE=<path>` regenerates the committed D1 fixture
/// (`lib/src/jam/finality/fixtures/polkajam-grandpa.json`) from this run and
/// writes the raw capture to `<path>.capture.json`.
#[tokio::test(flavor = "multi_thread")]
async fn jam_finality() -> Result<()> {
    let _ = env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    let started = Instant::now();
    let live = spawn_jam(Finality::Grandpa, None, None).await?;
    let sync = SyncFile::new()?;
    let fixture = std::env::var_os("JAM_FINALITY_FIXTURE").map(std::path::PathBuf::from);
    let dump_dir = live.base_dir.join("finality-export");
    let mut env = vec![
        (
            "JAM_CHAIN_SPEC".to_string(),
            live.spec_path().to_string_lossy().into_owned(),
        ),
        ("JAM_RPC_URL".to_string(), live.rpc_url()?),
        (
            "SYNC_PATH".to_string(),
            sync.path().to_string_lossy().into_owned(),
        ),
        (
            "JAM_POLKAJAM_COMMIT".to_string(),
            POLKAJAM_COMMIT.to_string(),
        ),
    ];
    if fixture.is_some() {
        env.push(("JAM_FINALITY_FIXTURE_EXPORT".into(), "1".into()));
        env.push((
            "SMOLDOT_DB_DUMP_DIR".into(),
            dump_dir.to_string_lossy().into_owned(),
        ));
    }
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    if dev_mode_keep_alive(&live, Some(("jam_finality", &env_refs))).await? {
        return live.teardown().await;
    }

    let mut body = BodyRun::spawn("jam_finality", env);
    body.wait_for(&sync, "THREE_SETS", Duration::from_secs(300))
        .await?;

    // Node-side: the network finalized three set changes too.
    let (finalized_at_kill, ancestry) = live
        .wait_for_set_changes(3, Duration::from_secs(60))
        .await?;
    log::info!(
        "node finalized slot {} with {} set changes; killing jam0 for 12 s",
        finalized_at_kill.slot,
        ancestry.set_changes
    );
    live.kill_node(VALIDATORS[0]).await?;
    tokio::time::sleep(Duration::from_secs(12)).await;
    live.start_node(VALIDATORS[0]).await?;
    ensure!(
        live.genesis_writes(VALIDATORS[0]).await? == 1,
        "jam0 did not restart on its own database"
    );
    sync.send("RESTARTED")?;

    body.finish().await?;

    let finalized = live.finalized_block().await?;
    ensure!(
        finalized.slot > finalized_at_kill.slot,
        "node finality did not advance across the jam0 restart ({} -> {})",
        finalized_at_kill.slot,
        finalized.slot
    );

    if let Some(path) = fixture {
        std::fs::copy(dump_dir.join("fixture.json"), &path)
            .with_context(|| format!("writing the fixture to {}", path.display()))?;
        let capture = path.with_extension("capture.json");
        std::fs::copy(dump_dir.join("capture.json"), &capture)?;
        log::info!(
            "fixture written to {}, raw capture to {}",
            path.display(),
            capture.display()
        );
    }
    log::info!(
        "jam_finality passed in {:.1?}; node finalized slot {} -> {}",
        started.elapsed(),
        finalized_at_kill.slot,
        finalized.slot
    );
    live.teardown()
        .await
        .map_err(|e| anyhow!("teardown: {e:#}"))
}

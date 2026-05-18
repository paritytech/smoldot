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

//! Shared scaffolding for the bulletin-chain integration tests
//! (`bulletin_fetch.rs`, `bulletin_batch.rs`). Contains the snapshot URLs,
//! zombienet spawn helper, dev-mode invocation printer, and chain-spec
//! path resolver.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfigBuilder};

use crate::bulletin;

/// GCS URLs for the snapshots produced by `bulletin_generate_snapshot`.
pub const DB_SNAPSHOT_RELAY: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/smoldot/bulletin_fetch/relay-2026-05-04.tgz";
pub const DB_SNAPSHOT_BULLETIN_FULL: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/smoldot/bulletin_fetch/bulletin-full-2026-05-04.tgz";
pub const DB_SNAPSHOT_BULLETIN_PARTIAL: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/smoldot/bulletin_fetch/bulletin-partial-2026-05-04.tgz";

/// Bundle of snapshot URLs passed to [`spawn_with_snapshots`]. Borrowed —
/// the caller owns the strings.
pub struct SnapshotUrls<'a> {
    pub relay: &'a str,
    pub bulletin_full: &'a str,
    pub bulletin_partial: &'a str,
}

/// Path to the bulletin chain spec shipped with the `smoldot-e2e-tests` crate.
pub fn bulletin_chain_spec() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chain-specs/bulletin-westend-local-spec.json")
}

/// Returns the value of `env_var` if set, or `default` otherwise. Useful for
/// pointing snapshot URLs at a locally-staged `.tgz` while iterating.
pub fn get_snapshot_url(default: &str, env_var: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.to_string())
}

/// Emit a copy-pasteable shell command equivalent to what `run_js_test`
/// would execute. Used in `DEV_MODE` so a developer can iterate on the JS
/// client against a long-lived zombienet without restarting the cargo
/// harness. `js_script` is the path relative to `e2e-tests/`, e.g.
/// `"js/bulletin_fetch.js"`.
pub fn print_dev_mode_invocation(env_pairs: &[(&str, &str)], js_script: &str) {
    println!();
    println!("=== DEV_MODE: skipping JS test, run it manually with: ===");
    println!();
    println!("cd e2e-tests && \\");
    for (k, v) in env_pairs {
        println!("  {}={} \\", k, shell_quote(v));
    }
    println!("  node {js_script}");
    println!();
}

/// Single-quote a string for safe shell pasting. Embedded single quotes are
/// escaped via the standard `'\''` trick.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Spawns a zombienet network running a westend relay + the bulletin
/// parachain, restoring the supplied DB snapshots on the relay and on each
/// of the two collators. `extra_para_args` are appended verbatim to the
/// parachain's default arg list — used by `bulletin_batch` to crank up log
/// verbosity on the collator side.
pub async fn spawn_with_snapshots(
    base_dir: &Path,
    chain_spec: &Path,
    snaps: SnapshotUrls<'_>,
    extra_para_args: &[&str],
) -> Result<Network<LocalFileSystem>> {
    let chain_spec_str = chain_spec
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 chain spec path"))?
        .to_string();
    let base_dir_str = base_dir
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 base dir"))?
        .to_string();
    let relay = snaps.relay.to_string();
    let bulletin_full = snaps.bulletin_full.to_string();
    let bulletin_partial = snaps.bulletin_partial.to_string();
    let extra_para_args: Vec<String> = extra_para_args.iter().map(|s| s.to_string()).collect();

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
            // Skip the embedded relay client and proxy relay-chain queries
            // through alice/bob's RPC. Zombienet expands the
            // `{{ZOMBIE:<node>:ws_uri}}` templates at spawn time. This
            // sidesteps the relay-side libp2p discovery quirks we hit with
            // the embedded relay (see polkadot-sdk's
            // `full_node_warp_sync/common.rs` for the same pattern on
            // collators "four" / "five", and
            // `bulletin_generate_snapshot::spawn_network` for the original
            // investigation).
            let mut args = vec!["--ipfs-server".into()];
            for arg in &extra_para_args {
                args.push(arg.as_str().into());
            }
            args.push(("--relay-chain-rpc-urls", "{{ZOMBIE:alice:ws_uri}}").into());

            p.with_id(bulletin::PARA_ID)
                .with_chain_spec_path(chain_spec_str.as_str())
                .cumulus_based(true)
                .with_default_args(args)
                .with_collator(|c| {
                    c.with_name("collator-1")
                        .validator(true)
                        .bootnode(true)
                        .with_command(bulletin::PARA_BINARY)
                        .with_db_snapshot(bulletin_full.as_str())
                })
                .with_collator(|c| {
                    c.with_name("collator-2")
                        .validator(true)
                        .bootnode(true)
                        .with_command(bulletin::PARA_BINARY)
                        .with_db_snapshot(bulletin_partial.as_str())
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
pub fn chain_spec_paths(network: &Network<LocalFileSystem>) -> Result<(PathBuf, PathBuf)> {
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

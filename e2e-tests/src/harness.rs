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

use anyhow::{anyhow, bail, Context, Result};
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfig, NetworkConfigBuilder};

use crate::bulletin;

/// GCS URL of the snapshot bundle produced by `bulletin_generate_snapshot`
/// (a single `bundle.tar.gz` packed by the zombienet-sdk `BundleBuilder`).
pub const DB_SNAPSHOT_BUNDLE: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/smoldot/bulletin_fetch/bundle-2026-05-29.tar.gz";

/// SHA256 of the published bundle. Empty means not yet pinned — in that case
/// the resolver requires [`BUNDLE_OVERRIDE_ENV`] to point at a local bundle.
pub const DB_SNAPSHOT_BUNDLE_SHA256: &str =
    "658acad23c4e4e44e088dfb135d5691de5f079b0f48a6d5597b99007ce60ee25";

/// Point this at a locally-generated `bundle.tar.gz` (e.g. `./tmp/snapshots/
/// bundle.tar.gz` produced by `./g`) to skip the download and run against it.
pub const BUNDLE_OVERRIDE_ENV: &str = "DB_SNAPSHOT_BUNDLE_OVERRIDE";

/// Per-node DB archives unpacked from the bundle, ready to hand to
/// `with_db_snapshot`. Owned local paths under the network base dir.
pub struct BulletinSnapshots {
    pub relay: PathBuf,
    pub bulletin_full: PathBuf,
    pub bulletin_partial: PathBuf,
}

/// Path to the bulletin chain spec shipped with the `smoldot-e2e-tests` crate.
pub fn bulletin_chain_spec() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chain-specs/bulletin-westend-local-spec.json")
}

/// Resolves the snapshot bundle (local override or download + SHA256-verify),
/// unpacks it under `{base_dir}/bulletin-snapshots/`, and returns the inner
/// per-node archive paths.
///
/// Set [`BUNDLE_OVERRIDE_ENV`] to a local `bundle.tar.gz` to iterate without a
/// download. Otherwise the bundle is fetched from [`DB_SNAPSHOT_BUNDLE`] into
/// `~/.cache/smoldot-e2e/bulletin/` and verified against
/// [`DB_SNAPSHOT_BUNDLE_SHA256`].
pub fn resolve_bundle(base_dir: &Path) -> Result<BulletinSnapshots> {
    let bundle_path = if let Ok(p) = std::env::var(BUNDLE_OVERRIDE_ENV) {
        let p = PathBuf::from(p);
        if !p.is_file() {
            bail!("{BUNDLE_OVERRIDE_ENV}: {} is not a file", p.display());
        }
        log::info!("bulletin snapshot: using local override {}", p.display());
        p
    } else {
        if DB_SNAPSHOT_BUNDLE_SHA256.is_empty() {
            return Err(anyhow!(
                "DB_SNAPSHOT_BUNDLE_SHA256 not pinned (placeholder); set \
                 {BUNDLE_OVERRIDE_ENV} to a local bundle.tar.gz"
            ));
        }
        let cached = bundle_cache_path(DB_SNAPSHOT_BUNDLE_SHA256)?;
        if !cached.is_file() {
            log::info!("bulletin snapshot: downloading {DB_SNAPSHOT_BUNDLE}");
            crate::snapshot::download(DB_SNAPSHOT_BUNDLE, &cached)?;
        }
        crate::snapshot::verify_sha256(&cached, DB_SNAPSHOT_BUNDLE_SHA256)?;
        cached
    };

    // Unpack fresh each run so stale inner archives can't leak across runs.
    let extract_dir = base_dir.join("bulletin-snapshots");
    let _ = std::fs::remove_dir_all(&extract_dir);
    zombienet_sdk::snapshot::untar_bundle(&bundle_path, &extract_dir)
        .with_context(|| format!("untar bundle {}", bundle_path.display()))?;

    let snaps = BulletinSnapshots {
        relay: extract_dir.join("relay.tgz"),
        bulletin_full: extract_dir.join("bulletin-full.tgz"),
        bulletin_partial: extract_dir.join("bulletin-partial.tgz"),
    };
    for p in [&snaps.relay, &snaps.bulletin_full, &snaps.bulletin_partial] {
        if !p.is_file() {
            bail!("bundle is missing expected archive {}", p.display());
        }
    }
    Ok(snaps)
}

fn bundle_cache_path(sha256: &str) -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
    let dir = base.join("smoldot-e2e").join("bulletin");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("bundle-{sha256}.tar.gz")))
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

/// Builds the bulletin network config (westend relay + bulletin parachain,
/// para id 2487).
///
/// - `snaps == None`: fresh from genesis, to *generate* the snapshots
///   (`bulletin_generate_snapshot`).
/// - `snaps == Some`: restore those snapshots to *run the tests* — relay on
///   both validators, `bulletin-full` on collator-1, `bulletin-partial` on
///   collator-2.
///
/// `extra_para_args` are appended to the parachain's default args.
pub fn bulletin_network_config(
    base_dir: &Path,
    chain_spec: &Path,
    snaps: Option<&BulletinSnapshots>,
    extra_para_args: &[&str],
) -> Result<NetworkConfig> {
    let chain_spec_str = chain_spec
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 chain spec path"))?
        .to_string();
    let base_dir_str = base_dir
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 base dir"))?
        .to_string();
    let relay = snaps.map(|s| s.relay.clone());
    let bulletin_full = snaps.map(|s| s.bulletin_full.clone());
    let bulletin_partial = snaps.map(|s| s.bulletin_partial.clone());
    let extra_para_args: Vec<String> = extra_para_args.iter().map(|s| s.to_string()).collect();

    NetworkConfigBuilder::new()
        .with_relaychain(move |rc| {
            rc.with_chain(bulletin::RELAY_CHAIN)
                .with_default_command(bulletin::RELAY_BINARY)
                .with_validator(|n| {
                    n.with_name("alice")
                        .bootnode(true)
                        .with_args(crate::listener_args("alice"))
                        .with_optional_db_snapshot(relay.clone())
                })
                .with_validator(|n| {
                    n.with_name("bob")
                        .bootnode(true)
                        .with_args(crate::listener_args("bob"))
                        .with_optional_db_snapshot(relay.clone())
                })
        })
        .with_parachain(move |p| {
            let mut args = vec!["--ipfs-server".into()];
            for arg in &extra_para_args {
                args.push(arg.as_str().into());
            }
            args.push(("--relay-chain-rpc-urls", "{{ZOMBIE:alice:ws_uri}}").into());

            p.with_id(bulletin::PARA_ID)
                .with_chain_spec_path(chain_spec_str.as_str())
                .cumulus_based(true)
                .with_default_args(args.clone())
                .with_collator(|c| {
                    // `with_args` overrides the parachain `with_default_args`,
                    // so the defaults must be repeated per collator.
                    let mut collator_args = args.clone();
                    collator_args.extend(crate::listener_args("collator-1"));
                    c.with_name("collator-1")
                        .validator(true)
                        .bootnode(true)
                        .with_command(bulletin::PARA_BINARY)
                        .with_args(collator_args)
                        .with_optional_db_snapshot(bulletin_full.clone())
                })
                .with_collator(|c| {
                    let mut collator_args = args.clone();
                    collator_args.extend(crate::listener_args("collator-2"));
                    c.with_name("collator-2")
                        .validator(true)
                        .bootnode(true)
                        .with_command(bulletin::PARA_BINARY)
                        .with_args(collator_args)
                        .with_optional_db_snapshot(bulletin_partial.clone())
                })
        })
        .with_global_settings(move |g| g.with_base_dir(base_dir_str.as_str()))
        .build()
        .map_err(|e| anyhow!("network config errors: {e:?}"))
}

/// Spawns the bulletin network restoring the supplied DB snapshots, detaches
/// it, and waits until it is up. Thin wrapper over [`bulletin_network_config`]
/// with `Some(snaps)`.
pub async fn spawn_with_snapshots(
    base_dir: &Path,
    chain_spec: &Path,
    snaps: &BulletinSnapshots,
    extra_para_args: &[&str],
) -> Result<Network<LocalFileSystem>> {
    let cfg = bulletin_network_config(base_dir, chain_spec, Some(snaps), extra_para_args)?;
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

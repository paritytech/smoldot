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

//! Resolves the artifact set consumed by `smoke_cold` / `smoke_warm`.
//!
//! Everything ships as a single bundle on GCS:
//! `gs://zombienet-db-snaps/zombienet/smoldot_smoke_db/{ARTIFACTS_VERSION}/bundle.tar.gz`.
//! On first use the bundle is downloaded into
//! `~/.cache/smoldot-e2e/{ARTIFACTS_VERSION}/`, SHA256-verified, and
//! extracted in place. A marker file (`.extracted-sha`) records which
//! version is currently extracted; mismatch triggers re-download.
//!
//! For local iteration set `ARTIFACTS_DIR_OVERRIDE` to a directory laid out
//! exactly like the generator output (`relaychain-db.tgz`, `relay-spec.json`,
//! `smoldot-db/relay.json`, …). All resolvers point inside it; no download
//! or verification.
//!
//! See `e2e-tests/docs/smoke-scenarios.md` for the full layout and the
//! regeneration procedure.

use std::path::PathBuf;

use anyhow::anyhow;

pub const ARTIFACTS_VERSION: &str = "v1";

const GCS_BASE: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/zombienet/smoldot_smoke_db";

const BUNDLE_FILE: &str = "bundle.tar.gz";
const ARTIFACTS_DIR_OVERRIDE_ENV: &str = "ARTIFACTS_DIR_OVERRIDE";

/// SHA256 of the published bundle for `ARTIFACTS_VERSION`. Empty means not
/// yet pinned — in that case the resolver requires `ARTIFACTS_DIR_OVERRIDE`.
const BUNDLE_SHA256: &str = "abea526d527c13aac54b4e1874602c04963046f7d3c3bc3e0adc217573bdc6da";

pub fn relay_db() -> Result<PathBuf, anyhow::Error> {
    resolve("relaychain-db.tgz")
}

pub fn para_db() -> Result<PathBuf, anyhow::Error> {
    resolve("parachain-db.tgz")
}

pub fn relay_spec() -> Result<PathBuf, anyhow::Error> {
    resolve("relay-spec.json")
}

pub fn para_spec() -> Result<PathBuf, anyhow::Error> {
    resolve("para-spec.json")
}

pub fn relay_spec_light_sync_state() -> Result<PathBuf, anyhow::Error> {
    resolve("relay-spec-lightSyncState.json")
}

pub fn para_spec_light_sync_state() -> Result<PathBuf, anyhow::Error> {
    resolve("para-spec-lightSyncState.json")
}

pub fn smoldot_db_relay() -> Result<PathBuf, anyhow::Error> {
    resolve("smoldot-db/relay.json")
}

pub fn smoldot_db_para() -> Result<PathBuf, anyhow::Error> {
    resolve("smoldot-db/para.json")
}

fn resolve(rel: &str) -> Result<PathBuf, anyhow::Error> {
    let dir = ensure_bundle_extracted()?;
    let p = dir.join(rel);
    if !p.is_file() {
        return Err(anyhow!(
            "expected {} in artifact bundle, missing",
            p.display()
        ));
    }
    Ok(p)
}

fn ensure_bundle_extracted() -> Result<PathBuf, anyhow::Error> {
    if let Ok(dir) = std::env::var(ARTIFACTS_DIR_OVERRIDE_ENV) {
        let p = PathBuf::from(dir);
        if !p.is_dir() {
            return Err(anyhow!(
                "{ARTIFACTS_DIR_OVERRIDE_ENV}: {} is not a directory",
                p.display()
            ));
        }
        log::info!("snapshot: using local override {}", p.display());
        return Ok(p);
    }

    let cache = cache_dir()?;
    let marker = cache.join(".extracted-sha");
    let extracted_ok = std::fs::read_to_string(&marker)
        .map(|s| s.trim() == BUNDLE_SHA256)
        .unwrap_or(false);
    if extracted_ok {
        log::info!("snapshot: cache hit ({})", cache.display());
        return Ok(cache);
    }

    if BUNDLE_SHA256.is_empty() {
        return Err(anyhow!(
            "BUNDLE_SHA256 not pinned for {ARTIFACTS_VERSION} (placeholder); \
             set {ARTIFACTS_DIR_OVERRIDE_ENV} to a local artifact directory"
        ));
    }

    let bundle_path = cache.join(BUNDLE_FILE);
    let url = format!("{GCS_BASE}/{ARTIFACTS_VERSION}/{BUNDLE_FILE}");
    log::info!("snapshot: downloading {url}");
    download(&url, &bundle_path)?;
    verify_sha256(&bundle_path, BUNDLE_SHA256)?;
    log::info!(
        "snapshot: extracting {} into {}",
        bundle_path.display(),
        cache.display()
    );
    extract_tarball(&bundle_path, &cache)?;
    std::fs::write(&marker, BUNDLE_SHA256)?;
    let _ = std::fs::remove_file(&bundle_path);
    Ok(cache)
}

fn cache_dir() -> Result<PathBuf, anyhow::Error> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
    let dir = base.join("smoldot-e2e").join(ARTIFACTS_VERSION);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn download(url: &str, dst: &std::path::Path) -> Result<(), anyhow::Error> {
    let tmp = dst.with_extension("partial");
    let status = std::process::Command::new("curl")
        .arg("-fL")
        .arg("--retry")
        .arg("3")
        .arg("-o")
        .arg(&tmp)
        .arg(url)
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("curl failed for {url} (exit {status})"));
    }
    std::fs::rename(&tmp, dst)?;
    Ok(())
}

fn extract_tarball(tarball: &std::path::Path, dst: &std::path::Path) -> Result<(), anyhow::Error> {
    let status = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(tarball)
        .arg("-C")
        .arg(dst)
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "tar -xzf failed for {} (exit {status})",
            tarball.display()
        ));
    }
    Ok(())
}

fn verify_sha256(path: &std::path::Path, expected: &str) -> Result<(), anyhow::Error> {
    let output = std::process::Command::new("sha256sum").arg(path).output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "sha256sum failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)?;
    let actual = stdout
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("empty sha256sum output for {}", path.display()))?;
    if actual != expected {
        return Err(anyhow!(
            "{}: SHA256 mismatch (expected {expected}, got {actual})",
            path.display()
        ));
    }
    Ok(())
}

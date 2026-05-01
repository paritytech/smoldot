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
//! All files (DB tarballs, chain specs with `lightSyncState`, smoldot
//! `databaseContent` JSONs) are hosted on GCS under
//! `gs://zombienet-db-snaps/zombienet/smoldot_smoke_db/{ARTIFACTS_VERSION}/`.
//! Resolvers cache them under `~/.cache/smoldot-e2e/{ARTIFACTS_VERSION}/`,
//! SHA256-verified against the pinned constants below.
//!
//! For local iteration (e.g. running the generator and validating cold/warm
//! before publishing to GCS), set `ARTIFACTS_DIR_OVERRIDE` to a directory
//! laid out exactly like the generator output (`relaychain-db.tgz`,
//! `relay-spec.json`, `smoldot-db/relay.json`, …). All resolvers point
//! inside it; SHA verification is skipped.
//!
//! See `e2e-tests/docs/smoke-scenarios.md` for the production / regeneration
//! procedure.

use std::path::PathBuf;

use anyhow::anyhow;

pub const ARTIFACTS_VERSION: &str = "v1";

const GCS_BASE: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/zombienet/smoldot_smoke_db";

const ARTIFACTS_DIR_OVERRIDE_ENV: &str = "ARTIFACTS_DIR_OVERRIDE";

// SHA256 constants are filled in when the corresponding `vN` artifact set is
// published. Empty means not yet pinned — in that case the resolver requires
// `ARTIFACTS_DIR_OVERRIDE` and refuses to download from GCS.
const RELAY_DB_SHA256: &str = "eb05f3a037b54ae83e03a1531f4d94034aa9e2b4d4ff64537f5d64811dcc6623";
const PARA_DB_SHA256: &str = "9314f2da74200ae2e1c6ec297a3ef4767c63611aa12873b4098eaf71a9bd8089";
const RELAY_SPEC_SHA256: &str = "f8db9c83f097000121c115e5e6041bb1628490b0bd6ac2bc86ddeed0e023d318";
const PARA_SPEC_SHA256: &str = "0e7b59f081c5e17e94d4a8d64a601f37955c2a23d95a94a462a29f53458d2a74";
const SMOLDOT_DB_RELAY_SHA256: &str =
    "871a06ff924d1f6ed603dbbf27788625a21b8e9324710fb5d7a286cf349daabd";
const SMOLDOT_DB_PARA_SHA256: &str =
    "6d202ea61aa192e911c4c3e5c91c9da2a4fa6adbe288f32ca40a247f5a50020e";

pub fn relay_db() -> Result<PathBuf, anyhow::Error> {
    resolve("relaychain-db.tgz", RELAY_DB_SHA256)
}

pub fn para_db() -> Result<PathBuf, anyhow::Error> {
    resolve("parachain-db.tgz", PARA_DB_SHA256)
}

pub fn relay_spec() -> Result<PathBuf, anyhow::Error> {
    resolve("relay-spec.json", RELAY_SPEC_SHA256)
}

pub fn para_spec() -> Result<PathBuf, anyhow::Error> {
    resolve("para-spec.json", PARA_SPEC_SHA256)
}

pub fn smoldot_db_relay() -> Result<PathBuf, anyhow::Error> {
    resolve("smoldot-db/relay.json", SMOLDOT_DB_RELAY_SHA256)
}

pub fn smoldot_db_para() -> Result<PathBuf, anyhow::Error> {
    resolve("smoldot-db/para.json", SMOLDOT_DB_PARA_SHA256)
}

fn resolve(rel: &str, sha256: &str) -> Result<PathBuf, anyhow::Error> {
    if let Ok(dir) = std::env::var(ARTIFACTS_DIR_OVERRIDE_ENV) {
        let p = PathBuf::from(dir).join(rel);
        if !p.is_file() {
            return Err(anyhow!(
                "{ARTIFACTS_DIR_OVERRIDE_ENV}: {} does not exist",
                p.display()
            ));
        }
        log::info!("snapshot {rel}: using local override {}", p.display());
        return Ok(p);
    }

    if sha256.is_empty() {
        return Err(anyhow!(
            "{rel} SHA256 not pinned for {ARTIFACTS_VERSION} (placeholder); \
             set {ARTIFACTS_DIR_OVERRIDE_ENV} to a local artifact directory"
        ));
    }

    let cached = cache_path(rel)?;
    if cached.is_file() {
        match verify_sha256(&cached, sha256) {
            Ok(()) => {
                log::info!("snapshot {rel}: cache hit ({})", cached.display());
                return Ok(cached);
            }
            Err(e) => {
                log::warn!("snapshot {rel}: cached SHA mismatch ({e}); re-downloading");
                let _ = std::fs::remove_file(&cached);
            }
        }
    }

    let url = format!("{GCS_BASE}/{ARTIFACTS_VERSION}/{rel}");
    log::info!("snapshot {rel}: downloading {url}");
    download(&url, &cached)?;
    verify_sha256(&cached, sha256)?;
    Ok(cached)
}

fn cache_path(rel: &str) -> Result<PathBuf, anyhow::Error> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
    let path = base.join("smoldot-e2e").join(ARTIFACTS_VERSION).join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(path)
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

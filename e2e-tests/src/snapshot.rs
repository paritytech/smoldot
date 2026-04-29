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
//! Two artifact classes:
//!
//! - **GCS-hosted** (network DB tarballs, ~few-MB each): downloaded into
//!   `~/.cache/smoldot-e2e/{ARTIFACTS_VERSION}/`, SHA256-verified against
//!   pinned constants. Bypassed by `DB_SNAPSHOT_*_OVERRIDE` env vars for
//!   local generator iteration.
//! - **Committed** (chain specs with `lightSyncState`, smoldot
//!   `databaseContent` JSONs): live under
//!   `e2e-tests/artifacts/{ARTIFACTS_VERSION}/` and are referenced by path.
//!
//! See `e2e-tests/docs/smoke-scenarios.md` for the production / regeneration
//! procedure and the full layout.

use std::path::PathBuf;

use anyhow::anyhow;

pub const ARTIFACTS_VERSION: &str = "v1";

const GCS_BASE: &str =
    "https://storage.googleapis.com/zombienet-db-snaps/zombienet/smoldot_smoke_db";

// SHA256 constants are filled in when the corresponding `vN` artifact set
// is published. An empty string means the artifact set hasn't been pinned
// yet — in that case the resolver requires `DB_SNAPSHOT_*_OVERRIDE` env
// vars and refuses to download from GCS.
const RELAY_DB_SHA256: &str = "";
const PARA_DB_SHA256: &str = "";

const RELAY_DB_FILE: &str = "relaychain-db.tgz";
const PARA_DB_FILE: &str = "parachain-db.tgz";

const RELAY_DB_OVERRIDE_ENV: &str = "DB_SNAPSHOT_RELAY_OVERRIDE";
const PARA_DB_OVERRIDE_ENV: &str = "DB_SNAPSHOT_PARA_OVERRIDE";

/// Cached DB tarballs (env override → cache → download + SHA-verify).
pub fn relay_db() -> Result<PathBuf, anyhow::Error> {
    resolve_db(RELAY_DB_FILE, RELAY_DB_SHA256, RELAY_DB_OVERRIDE_ENV)
}

pub fn para_db() -> Result<PathBuf, anyhow::Error> {
    resolve_db(PARA_DB_FILE, PARA_DB_SHA256, PARA_DB_OVERRIDE_ENV)
}

/// Committed chain spec files. Paths are absolute via `CARGO_MANIFEST_DIR`.
pub fn relay_spec() -> PathBuf {
    artifacts_dir().join("relay-spec.json")
}

pub fn para_spec() -> PathBuf {
    artifacts_dir().join("para-spec.json")
}

/// Committed smoldot `databaseContent` dumps used by the warm scenario.
pub fn smoldot_db_relay() -> PathBuf {
    artifacts_dir().join("smoldot-db/relay.json")
}

pub fn smoldot_db_para() -> PathBuf {
    artifacts_dir().join("smoldot-db/para.json")
}

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts")
        .join(ARTIFACTS_VERSION)
}

fn resolve_db(file: &str, sha256: &str, override_env: &str) -> Result<PathBuf, anyhow::Error> {
    if let Ok(path) = std::env::var(override_env) {
        let p = PathBuf::from(path);
        if !p.is_file() {
            return Err(anyhow!(
                "{override_env} points at non-existent file: {}",
                p.display()
            ));
        }
        log::info!("snapshot {file}: using local override {}", p.display());
        return Ok(p);
    }

    if sha256.is_empty() {
        return Err(anyhow!(
            "{file} SHA256 not pinned for {ARTIFACTS_VERSION} (placeholder); \
             set {override_env} to a local file"
        ));
    }

    let cached = cache_dir()?.join(file);
    if cached.is_file() {
        match verify_sha256(&cached, sha256) {
            Ok(()) => {
                log::info!("snapshot {file}: cache hit ({})", cached.display());
                return Ok(cached);
            }
            Err(e) => {
                log::warn!("snapshot {file}: cached SHA mismatch ({e}); re-downloading");
                let _ = std::fs::remove_file(&cached);
            }
        }
    }

    let url = format!("{GCS_BASE}/{ARTIFACTS_VERSION}/{file}");
    log::info!("snapshot {file}: downloading {url}");
    download(&url, &cached)?;
    verify_sha256(&cached, sha256)?;
    Ok(cached)
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
    let tmp = dst.with_extension("tgz.partial");
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

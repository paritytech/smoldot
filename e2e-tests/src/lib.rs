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

pub mod bulletin;
pub mod network;
pub mod snapshot;
pub mod statement;

pub use network::{
    run_smoke_js, spawn_scenario, spawned_chain_spec_paths, LiveNetwork, Scenario, SmoldotDbPaths,
    SnapshotPaths, BEST_METRIC, FINALIZED_METRIC, PARA_ID,
};

/// A file-backed Rust → JS message channel. Rust appends newline-terminated
/// messages with [`SyncFile::send`]; JS polls the file and waits for a given
/// line via the `waitForMessage` helper in `e2e-tests/js/helpers.js`. The
/// tempfile lives as long as this struct, so keep it alive for the full test.
pub struct SyncFile {
    file: tempfile::NamedTempFile,
}

impl SyncFile {
    pub fn new() -> Result<Self, anyhow::Error> {
        let file = tempfile::Builder::new().suffix(".sync").tempfile()?;
        Ok(Self { file })
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }

    pub fn send(&self, message: &str) -> Result<(), anyhow::Error> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.file.path())?;
        writeln!(f, "{message}")?;
        Ok(())
    }
}

/// Resolves the base directory tests share with zombienet.
///
/// Honour `ZOMBIENET_SDK_BASE_DIR` if set, otherwise fall back to a per-pid temp dir.
/// Zombienet is configured (via `with_global_settings`) to use the same path,
/// so the chain-specs it emits land where the tests can read them back.
pub fn resolve_base_dir() -> Result<PathBuf, anyhow::Error> {
    let path = std::env::var("ZOMBIENET_SDK_BASE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("zombienet-{}", std::process::id())));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Ensures the smoldot JS bundle is built.
pub fn ensure_smoldot_built() {
    let js_dir = project_root().join("wasm-node/javascript");
    let status = std::process::Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(&js_dir)
        .status()
        .expect("failed to run npm build");
    assert!(status.success(), "smoldot npm build failed");
}

/// Ensures JS test dependencies are installed.
pub fn ensure_js_deps_installed() {
    let js_dir = project_root().join("e2e-tests/js");
    let node_modules = js_dir.join("node_modules");
    if node_modules.exists() {
        return;
    }
    let status = std::process::Command::new("npm")
        .arg("install")
        .current_dir(&js_dir)
        .status()
        .expect("failed to run npm install");
    assert!(status.success(), "npm install in e2e-tests/js failed");
}

/// Ensures browser test dependencies (Playwright + smoldot) are installed and
/// that Playwright's bundled Chromium is downloaded.
pub fn ensure_browser_deps_installed() {
    let browser_dir = project_root().join("e2e-tests/browser");
    let node_modules = browser_dir.join("node_modules");
    if !node_modules.exists() {
        let status = std::process::Command::new("npm")
            .arg("install")
            .current_dir(&browser_dir)
            .status()
            .expect("failed to run npm install for browser tests");
        assert!(
            status.success(),
            "npm install in e2e-tests/browser failed"
        );
    }
    // `playwright install chromium` is idempotent and a no-op if the browser
    // is already cached locally.
    let status = std::process::Command::new("npx")
        .args(["playwright", "install", "chromium"])
        .current_dir(&browser_dir)
        .status()
        .expect("failed to run playwright install");
    assert!(status.success(), "playwright install chromium failed");
}

/// Runs a Node.js script under `e2e-tests/browser` with the given environment.
/// Mirrors [`run_js_test`] but the working directory is the browser dir so
/// that `import { chromium } from 'playwright'` resolves.
pub async fn run_browser_test(
    script: &str,
    env_vars: &[(&str, &str)],
) -> Result<(), String> {
    let browser_dir = project_root().join("e2e-tests/browser");
    let script_path = browser_dir.join(script);

    let mut cmd = tokio::process::Command::new("node");
    cmd.arg(&script_path);
    cmd.current_dir(&browser_dir);
    for (key, val) in env_vars {
        cmd.env(key, val);
    }

    let output = cmd.output().await.expect("failed to run node");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("--- browser stdout ---\n{stdout}");
    eprintln!("--- browser stderr ---\n{stderr}");

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "browser test exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        ))
    }
}

/// Pre-fetch a snapshot from `source` to a stable local path and return
/// that path. Pass-through if `source` already points at a local file.
///
/// Workaround for a class of CI flakes caused by zombienet-provider
/// 0.4.11's [`initialize_db_snapshot`]: it calls `reqwest::get(...)
/// .bytes().await.unwrap()` without checking the HTTP status or
/// `Content-Length`, so a 5xx-with-HTML-body or a mid-stream connection
/// close becomes a panic on tar extraction. `curl -fL --retry` handles
/// both cases (`-f` rejects non-2xx, retry covers transient drops),
/// `tar -tzf` validates the archive integrity, and we hand zombienet a
/// local file path that's already known-good.
///
/// Cached under `e2e-tests/target/snapshot-cache/<basename>` so repeated
/// runs reuse the file. Only validated files reach the cache: a failed
/// download or a corrupt archive is never renamed in.
pub fn prefetch_snapshot(source: &str) -> Result<PathBuf, anyhow::Error> {
    if !source.starts_with("http://") && !source.starts_with("https://") {
        return Ok(PathBuf::from(source));
    }
    let cache_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("snapshot-cache");
    std::fs::create_dir_all(&cache_dir)?;
    let filename = source
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no filename in URL: {source}"))?;
    let path = cache_dir.join(filename);
    if path.exists() {
        return Ok(path);
    }
    let tmp = cache_dir.join(format!("{filename}.partial"));
    let _ = std::fs::remove_file(&tmp);

    let status = std::process::Command::new("curl")
        .args([
            "-fL",
            "--retry",
            "5",
            "--retry-delay",
            "2",
            "--retry-max-time",
            "120",
            "--max-time",
            "300",
            "-o",
        ])
        .arg(&tmp)
        .arg(source)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn curl: {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("curl failed for {source}: {status}");
    }

    let test_status = std::process::Command::new("tar")
        .arg("-tzf")
        .arg(&tmp)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn tar: {e}"))?;
    if !test_status.success() {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("tar -tzf failed for {source}: archive is not a valid gzipped tar");
    }

    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Runs a JS test script with the given environment variables.
///
/// Uses `tokio::process::Command` for async compatibility.
pub async fn run_js_test(script: &str, env_vars: &[(&str, &str)]) -> Result<(), String> {
    let e2e_dir = project_root().join("e2e-tests");
    let script_path = e2e_dir.join(script);

    let mut cmd = tokio::process::Command::new("node");
    cmd.arg(&script_path);
    cmd.current_dir(&e2e_dir);
    for (key, val) in env_vars {
        cmd.env(key, val);
    }

    let output = cmd.output().await.expect("failed to run node");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("--- JS stdout ---\n{stdout}");
    eprintln!("--- JS stderr ---\n{stderr}");

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "JS test exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        ))
    }
}

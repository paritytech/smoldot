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
pub mod harness;
pub mod network;
pub mod snapshot;
pub mod statement;

pub use network::{
    elastic_scaling_genesis_overrides, listener_args, prepare_runtime_spec, prepare_runtime_specs,
    run_chainhead_v1_follow, run_smoke, spawn_scenario, spawned_chain_spec_paths, FollowChain,
    LiveNetwork, Scenario, SmoldotDbPaths, SnapshotPaths, BEST_METRIC,
    ELASTIC_MAX_VALIDATORS_PER_CORE, ELASTIC_SCALING_CORES, ELASTIC_VALIDATOR_COUNT,
    FINALIZED_METRIC, PARA_ID,
};

/// Which host runs a shared test body: the Node build over TCP,
/// or the browser over WebRTC.
#[derive(Clone, Copy, Debug)]
pub enum Host {
    Node,
    Browser,
}

/// Runs the shared test module `test_name` (under `e2e-tests/shared/`) on
/// both node and headless browser hosts.
pub async fn run_test(test_name: &str, env_vars: &[(&str, &str)]) -> Result<(), String> {
    log::info!("Running {} test on Node Host", test_name);
    crate::ensure_js_deps_installed();
    run_shared_test(Host::Node, test_name, env_vars).await?;

    log::info!("Running {} test on Browser Host", test_name);
    crate::ensure_browser_deps_installed();
    run_shared_test(Host::Browser, test_name, env_vars).await?;

    Ok(())
}

/// Runs the shared test module `test_name` (under `e2e-tests/shared/`) on the
/// chosen host. Both hosts execute the *same* JS body, the transport and
/// the generic runner differ. `env_vars` carries the test's inputs.
pub async fn run_shared_test(
    host: Host,
    test_name: &str,
    env_vars: &[(&str, &str)],
) -> Result<(), String> {
    let mut env: Vec<(&str, &str)> = env_vars.to_vec();
    env.push(("TEST_NAME", test_name));
    // Both runners are launched via `run_js_test`.
    let script = match host {
        Host::Node => "hosts/node/run.js",
        // NOTE: temporarily disable test execution within the browser.
        // The reason is a blocking fix needed upstream.
        // Waiting until it is fixed.
        // When re-enabling, also uncomment the browser-only
        // `zombienet-smoldot-0014-webrtc_double_open` and
        // `zombienet-smoldot-0015-webrtc_send_after_close` entries in
        // `.github/workflows/zombienet.yml`.
        // Host::Browser => "hosts/browser/run.js",
        _ => return Ok(()),
    };
    run_js_test(script, &env).await
}

/// A file-backed Rust → JS message channel. Rust appends newline-terminated
/// messages with [`SyncFile::send`]; JS polls the file and waits for a given
/// line via the `waitForSyncMessage` helper in `e2e-tests/hosts/sync-file.js`. The
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

/// Ensures the smoldot JS bundle is built, to make cargo test self-sufficient.
pub fn ensure_smoldot_built() {
    let js_dir = project_root().join("wasm-node/javascript");
    if !js_dir.join("node_modules").exists() {
        let status = std::process::Command::new("npm")
            .arg("ci")
            .current_dir(&js_dir)
            .status()
            .expect("failed to run npm ci");
        assert!(status.success(), "npm ci in wasm-node/javascript failed");
    }
    let status = std::process::Command::new("npm")
        .arg("run")
        .arg("build")
        .current_dir(&js_dir)
        .status()
        .expect("failed to run npm build");
    assert!(status.success(), "smoldot npm build failed");
}

/// Installs the unified JS dependencies (smoldot + Playwright) into the single
/// `e2e-tests/node_modules`. no-op once `node_modules` exists.
/// Every JS script under `e2e-tests/` resolves its bare imports from here.
fn ensure_deps_installed() {
    let e2e_dir = project_root().join("e2e-tests");
    if e2e_dir.join("node_modules").exists() {
        return;
    }
    let status = std::process::Command::new("npm")
        .arg("install")
        .current_dir(&e2e_dir)
        .status()
        .expect("failed to run npm install");
    assert!(status.success(), "npm install in e2e-tests failed");
}

/// Ensures Node-host test dependencies are installed.
pub fn ensure_js_deps_installed() {
    ensure_deps_installed();
}

/// Ensures browser-host dependencies are installed and that Playwright's bundled
/// Chromium is downloaded.
pub fn ensure_browser_deps_installed() {
    ensure_deps_installed();
    // `playwright install chromium` is idempotent and a no-op if the browser
    // is already cached locally.
    let status = std::process::Command::new("npx")
        .args(["playwright", "install", "chromium"])
        .current_dir(project_root().join("e2e-tests"))
        .status()
        .expect("failed to run playwright install");
    assert!(status.success(), "playwright install chromium failed");
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

    eprintln!("--- JS stderr ---\n{stderr}");
    eprintln!("--- JS stdout ---\n{stdout}");

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "JS test exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        ))
    }
}

# Browser / WebRTC e2e tests — architecture & blueprint

## Why this exists

The e2e suite runs smoldot inside **Node.js over TCP**. The WebRTC transport can
only be exercised in a real browser (Node has no browser WebRTC), so we need a
second "host" that runs smoldot inside headless Chrome via Playwright.

Rather than duplicate every test, each test's **logic is written once** as a
transport-agnostic module and executed by **two thin runners**:

- **Node host** → smoldot Node build, TCP (today's behaviour).
- **Browser host** → smoldot browser build inside headless Chrome, `forbidTcp: true` → WebRTC.

"Two hosts execute the same test": the modularity is enforced by there being a
single body file per test. The smoke test is the first one migrated and serves
as the reference.

---

## Architecture

```
                       shared/<name>.js              ← test body, written ONCE
            export default async (ctx) => {…}   (imports only sibling shared/*)
                    │ host-specific via ctx │ JSON-RPC via import "./rpc.js"
              ┌───────────────┴────────────────┐
        hosts/node/ctx.js                hosts/browser/ctx.js
        (Node build, TCP)                (browser build, forbidTcp→WebRTC)
              │                                  │
        hosts/node/run.js                hosts/browser/run.js
        (generic runner)                 (generic Playwright runner)
              │                                  │
        run_shared_test(Host::Node)      run_shared_test(Host::Browser)
                              │
                       Rust test (tests/*.rs)
```

### The `ctx` primitives (the host-specific seam)

`ctx` carries only what genuinely differs by host. A body gets the rest —
JSON-RPC — from `shared/rpc.js`, which it imports directly and builds with
`createRpc(ctx.client)` (see below).

| field | meaning |
|---|---|
| `host` | `"node"` or `"browser"` — lets a `prepareCtx` branch on the rare occasion it must |
| `client` | started smoldot client (Node build / browser build with `forbidTcp`) |
| `env` | raw env values (strings): `REQUIRED_BLOCKS`, … |
| `files` | contents of the `fileInputs` env vars (string, or `null`) |
| `report(name, passed, detail)` | PASS/FAIL accounting |
| `log(msg)` | diagnostic line |
| `waitSync(label, timeoutMs)` | block until Rust signals `label` via the SyncFile |
| `dumpDb(files)` | write `{name: content}` to `SMOLDOT_DB_DUMP_DIR` (Node only; no-op in browser) |

The host-specific pieces, all hidden behind `ctx`:
- **start options** — browser sets `forbidTcp: true`; Node does not.
- **`waitSync`** — Node polls the SyncFile on disk; browser calls a Playwright
  `page.exposeFunction("__waitSync", …)` that polls the file in Node and resolves
  back into the page (a browser sandbox can't read disk).
- **`dumpDb`** — Node writes files; browser is a no-op (the browser host never sets
  `SMOLDOT_DB_DUMP_DIR`, so the body's dump branch is skipped anyway).

### JSON-RPC is host-agnostic (not in `ctx`)

`shared/rpc.js` is a plain library: `createRpc(client)` returns `addChain`,
`sendRpc`, `readJsonRpcUntil`, `sendRpcAndWait`, `waitForJsonRpcMatch`. It works
on both hosts because the smoldot `Chain` API (`addChain`, `sendJsonRpc`,
`jsonRpcResponses`) is identical across builds — the per-chain FIFO is fed by
draining `chain.jsonRpcResponses` (an async iterator both builds expose), so
there is no host-specific reader. A body imports it with a **relative sibling**
import (`import { createRpc } from "./rpc.js"`), which resolves on both hosts:
Node loads it from disk; the browser host serves it at `/shared/rpc.js` via
`page.route`.

### Browser execution model

The whole body runs inside a **single** `page.evaluate`. The page imports the
served modules (`/shared/<name>.js`, `/browser/ctx.js`,
`/shared/rpc.js`), builds the ctx, runs the body, and returns a pass/fail flag.
Mid-test Rust handshakes work via `__waitSync`, so there is no multi-evaluate
state stashing (simpler than the older `statement_store_browser.js` pattern).

Those module/wasm assets are not served by an HTTP server — `run.js` fulfills
them from disk via **Playwright request interception** (`page.route("**/*", …)`)
against a `http://localhost/` origin, mapping the `/smoldot/`, `/shared/` and
`/browser/` prefixes to their directories. No port is bound and no server
lifecycle is managed; `route.fulfill({ path })` infers the content-type from the
file extension.

---

## Layout

JS is split into **`hosts/`** (what varies per transport) and **`shared/`** (the
test bodies), with one dependency root:

```
e2e-tests/
  package.json          unified deps (smoldot + playwright); single node_modules/
  hosts/
    node/    { ctx.js, run.js }
    browser/ { ctx.js, run.js, helpers.js, page/index.html }
  shared/    { rpc.js, ctx-primitives.js, smoke.js, … }
  js/        LEGACY not-yet-migrated Node tests + helpers.js  (transitional)
  browser/   LEGACY statement_store_browser.js + helpers.js + page/  (transitional)
```

Node resolves bare imports by the script's location, so the single
`e2e-tests/node_modules` serves `hosts/*`, `shared/*`, and the legacy dirs alike;
one runner (`run_js_test`, cwd `e2e-tests/`) drives both hosts. End state (after
all tests migrate): delete the legacy dirs and wrap `hosts/` + `shared/` +
`package.json` under a single `js/`.

## Files

### New
| File | Role |
|---|---|
| `package.json` | unified deps (smoldot + playwright) at the e2e-tests root |
| `shared/rpc.js` | host-agnostic JSON-RPC library — `createRpc(client)` → `addChain` + send/read helpers; imported directly by bodies |
| `shared/ctx-primitives.js` | the `ctx` contract — `CTX_KEYS` + `assertCtx` (host-specific seam only) |
| `shared/smoke.js` | smoke test body (the one source of truth for smoke logic) |
| `hosts/node/ctx.js` | Node-host ctx builder (smoldot Node build, TCP) |
| `hosts/node/run.js` | generic Node runner (selects body by `TEST_NAME`) |
| `hosts/browser/ctx.js` | browser-host ctx builder (served to the page) |
| `hosts/browser/run.js` | generic Playwright runner (selects body by `TEST_NAME`) |
| `hosts/browser/helpers.js` | the SyncFile poller (`waitForSyncMessage`) backing `ctx.waitSync`; page/asset serving is done by `page.route` in `run.js`, not a static server |
| `hosts/browser/page/index.html` | loads the smoldot browser bundle onto `window.__smoldot` (copy) |
| `tests/smoke_webrtc.rs` | `smoke_fresh_webrtc` — browser twin of `smoke_fresh` |

### Modified
| File | Change |
|---|---|
| `browser/helpers.js` | (legacy `browser/` dir) `startStaticServer` gained an optional `mounts` arg; existing 2-arg calls unchanged. The new `hosts/browser/` host does **not** use a static server — it serves assets via `page.route` — so `hosts/browser/helpers.js` keeps only `waitForSyncMessage` |
| `src/lib.rs` | added `Host { Node, Browser }` + `run_shared_test` (both hosts via `run_js_test`); unified `ensure_deps_installed` (collapses the old js/browser installers); exported `run_smoke_browser`, `prepare_webrtc_spec` |
| `src/network.rs` | `run_smoke_js` routes through `run_shared_test(Host::Node, "smoke", …)`; added `run_smoke_browser`; added `prepare_webrtc_spec` (the WebRTC seam) |
| `tests/smoke_generate_snapshots.rs` | direct `js/smoke.js` call → `run_shared_test(Host::Node, "smoke", …)` |
| `.gitignore` | per-dir `node_modules` rules collapsed to `/e2e-tests/node_modules` |

### Removed
| File | Reason |
|---|---|
| `js/smoke.js` | superseded by `shared/smoke.js` (Node host now runs the shared body) |
| `js/package.json`, `browser/package.json` (+ lockfiles) | superseded by the unified root `package.json` |

`js/helpers.js` and `browser/helpers.js` are **kept** — still used by the
not-yet-migrated tests. `hosts/node/ctx.js` is self-contained: it inlines its own
`report` + SyncFile poll rather than importing legacy `js/helpers.js`.

---

## The WebRTC seam (separate work item)

`src/network.rs::prepare_webrtc_spec(live) -> (relay_spec, para_spec)` is the
**single** place WebRTC connectivity needs to be wired. It currently returns the
TCP specs unchanged (stub + warning). The real implementation rewrites the chain
spec's `bootNodes` to `/webrtc-direct` multiaddrs (with certhash) so a
`forbidTcp` smoldot client can connect; substrate nodes must also listen on
`/webrtc-direct` (via `.with_args` on the zombienet node, as in
`reserved_peer_discovery.rs`).

Until that lands, `smoke_fresh_webrtc` spins up the full browser harness and
times out at the connect step — which still exercises everything except the
transport.

---

## How to add the next test (blueprint)

1. **Write the body** — `shared/<name>.js`:
   ```js
   import { createRpc } from "./rpc.js";
   export const fileInputs = ["RELAY_CHAIN_SPEC", "PARA_CHAIN_SPEC", /* … */];
   export default async function (ctx) {
     const { report, env, files } = ctx;
     const { addChain, sendRpc, readJsonRpcUntil } = createRpc(ctx.client);
     // …logic; specs arrive as files.RELAY_CHAIN_SPEC (contents)…
   }
   ```
   Import only sibling `shared/*` modules (they resolve on both hosts). Never
   import `smoldot`/`fs`/host APIs, never `process.env`. Keep it browser-safe (no
   `Buffer`, no Node globals).

2. **Wire Rust** — add to `src/network.rs` (or a fixture module) a pair that
   builds env and dispatches:
   ```rust
   run_shared_test(Host::Node,    "<name>", &env).await      // TCP
   run_shared_test(Host::Browser, "<name>", &env).await      // WebRTC (browser specs)
   ```
   Specs are passed as **file paths**; the runner reads the `fileInputs` into
   `ctx.files` (Node reads on disk; browser reads in Node and ships the contents
   into the page).

3. **Add the test pair** — `tests/<name>.rs` with `<name>` (Node) and
   `<name>_webrtc` (Browser), sharing the network setup. The browser test must
   call `ensure_browser_deps_installed()` (Playwright + Chromium).

4. **Mid-run Rust signal?** Call `await ctx.waitSync("LABEL")` in the body and
   `sync.send("LABEL")` from Rust (`SyncFile`). Works on both hosts.

5. **Run** — `cargo test -p smoldot-e2e-tests <name>` (both variants).

---

## Verification performed

- `cargo test --no-run` compiles `smoke_fresh`, `smoke_generate_snapshots`,
  `smoke_webrtc`, and the legacy `statement_store_browser`.
- `node --check` passes on every moved/edited JS module (and the legacy files).
- Unified deps: `npm install` in `e2e-tests/` populates one `node_modules` with
  both `smoldot` and `playwright`.
- **Node host, end-to-end minus network**: `TEST_NAME=smoke node hosts/node/run.js`
  imports `shared/smoke.js`, builds the ctx, **starts smoldot** (logs
  `Smoldot v3.x`), runs the body, and fails only at input validation — proving
  the relocated Node import/start path (`hosts/node/run → ctx → ../../shared/rpc.js + smoldot`).
- **Browser host, end-to-end minus network**: `TEST_NAME=smoke node hosts/browser/run.js`
  launches headless Chromium, fulfills `/` and the `/smoldot/*`, `/shared/*`,
  `/browser/*` assets from disk via `page.route` (no HTTP server), reaches
  `window.__ready` (smoldot browser bundle loaded), imports the served modules,
  passes `assertCtx`, runs the body, and fails only at input validation — the
  body's stack frames resolve to `http://localhost/shared/smoke.js`, confirming
  module serving via interception.

**Not yet run** (needs zombienet + Docker images + Chromium, and the WebRTC seam):
the full `cargo test smoke_fresh_webrtc` against a live network.

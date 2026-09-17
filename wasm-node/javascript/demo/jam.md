# C1 JAM browser / WASM demo

This uses `start` / `addChain` from the integrated browser client, not the raw
WebTransport probe, a WebSocket server, or the node's JSON-RPC endpoint.
**Trusted anchor only; no live finality.** The spec supplies a trusted genesis
or checkpoint header and its post-state. B3's `LightState::from_anchor` restores
pending winning tickets from the checkpoint's raw ticket accumulator; callers
must not reorder that accumulator themselves. Shape validation does not establish
trust or prove checkpoint ancestry. `initialized`'s
finalized hashes describe that anchor, not newly proven finality. The demo
always calls `chainHead_v1_follow` with `[false]` (`withRuntime: false`).

## Build and serve

With the integrated C1 Rust changes available and the repository's Rust/WASM
build prerequisites installed, run:

```sh
cd /home/sebastian/work/tries/smoldot-jam/C1-M10-integration/wasm-node/javascript
npm ci --ignore-scripts
node prepare.mjs --debug
npm run buildModules
```

Do **not** use `npm start`: that launches the separate Node WebSocket demo.
The build generates `dist/mjs/index-browser.js` and its WASM bytecode module.
Rebuild after integration changes; a stale build may lack JAM support.

From that same directory, run this temporary, loopback-only HTTP server. It
serves the JavaScript tree plus exactly one external fixture endpoint, directly
from its original file. It creates no symlink, source copy, or fixture copy:

```sh
python3 - <<'PY'
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

root = Path.cwd()
assert (root / 'demo/jam.html').is_file(), 'Run from wasm-node/javascript'
fixture = Path('/home/sebastian/work/repos/jam-light-client-planning/fixtures/chain-spec.polkajam.json')
assert fixture.is_file(), fixture

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(root), **kwargs)

    def do_GET(self):
        if urlsplit(self.path).path == '/fixtures/chain-spec.polkajam.json':
            data = fixture.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)
        else:
            super().do_GET()

print('Open http://localhost:8080/demo/jam.html; Ctrl-C stops this server.')
ThreadingHTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
PY
```

Open **http://localhost:8080/demo/jam.html** in a browser supporting WebTransport
and `serverCertificateHashes`. Localhost is a secure context; do not open the
HTML as `file://` or disable certificate checks. Other spec URLs need same-origin
access or appropriate CORS headers. Alternatively select a local JSON file
(takes precedence over the URL). Specs are limited to 16 MiB.

Start the external A5 network using
`/home/sebastian/work/repos/jam-light-client-planning/fixtures/local-network.md`.
Only for that network, check **Add public dev node0 P-256 bootnode**. The option
is off by default and appends, without replacing existing bootnodes:

```text
p256:oqov2a57d7etnpzb6aerv64y5j622ejkkvqjencdrwln4qhnoqvqb@127.0.0.1:40000
```

This changes only the in-memory spec. These are public development keys, not
production credentials. Certificate pins are derived by the integrated client;
the demo does not reuse historical, potentially expired certificate fixtures.

## Controls and browser QA

1. **Start** loads the spec, starts WASM, adds the chain and follows without a
   runtime. Check `initialized`, then `newBlock` and `bestBlockChanged` events.
2. Each latest `newBlock` automatically triggers `chainHead_v1_header`.
   **Header** requests it again. The dedicated panel prints the requested block
   hash and the exact returned canonical header hex (up to 1 MiB of bytes).
   There is no JS hash verification or claim of canonical-chain membership.
3. **Unpin** releases the latest new block. Its Header/Unpin buttons become
   unavailable until another new block arrives. The last displayed header is
   retained with its hash as historical output, not as a currently pinned block.
4. **Unfollow** releases the subscription/pins while leaving the chain running.
   **Stop** removes the chain and terminates the client, including during startup.
   Stop, then Start to subscribe again. RPC failures/timeouts stop the session.
5. Kill/restart the local node without stopping the demo and observe client
   reconnection/catch-up. Record browser/version and results; syntax validation
   alone is not evidence of a working live browser session or compatibility.

The demo retains 100 entries per event/log panel, 4,096 characters per entry,
one header, at most 16 locally tracked pins, and at most 32 pending RPC calls
with 15-second timeouts. Older pins are automatically unpinned; in-flight
unpins can briefly retain more server-side pins. Header requests are coalesced
while outstanding. These are demo-side bounds, **not a measurement or guarantee
of the integrated WASM sync tree's memory usage**. A server `stop` event stops
the demo; an unexpected live `finalized` event is reported as an error.

Named DOM elements: `spec-url`, `spec-file`, `dev-bootnode`, `start`, `stop`,
`header`, `unpin`, `unfollow`, `status`, `header-output`, `events`, `logs`.
Browser QA can use `window.jamDemo.start()`, `.stop()`, `.header()`, `.unfollow()`
and `.snapshot()` (a bounded copy of current state); use the named Unpin button
to exercise its control. Rendered RPC/log content uses `textContent`, not HTML.

Syntax check (does not execute WASM or connect to the network):

```sh
node --check demo/jam.mjs
```

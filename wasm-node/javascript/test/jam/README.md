# JAM test assets

The live JAM tests are scenarios of the `e2e-tests` crate: zombienet-sdk
spawns the PolkaJam network, Rust injects the faults through zombienet's node
handles, and a JavaScript body runs the smoldot browser build in headless
Chrome. See
[`e2e-tests/docs/jam-scenarios.md`](../../../../e2e-tests/docs/jam-scenarios.md)
for the five scenarios, the aged snapshot and the `DEV_MODE` route to the
manual demo.

```sh
cargo test --manifest-path e2e-tests/Cargo.toml --features jam --test jam_follow -- --nocapture
```

What stays here:

| File | Purpose |
|---|---|
| `demo.mjs` | Browser regression of the manual demo page. `node --test test/jam/demo.mjs` runs the controlled-stream cases (no network); `--live` is the JavaScript step of the `jam_demo` scenario and needs `JAM_SPEC_PATH` and `JAM_RPC_PORT` of a running GRANDPA network |
| `zombienet/tiny-grandpa.toml` | The six-validator GRANDPA network `just zombie-jam` spawns with `zombie-cli` for the manual demo (`demo/jam.md`) |
| `FINALITY.md` | How to regenerate the committed CE 130 finality fixture |

The `ava` configuration in `package.json` excludes `test/jam/**`, so
`npm test` never starts a browser for these files.

## Notes

- **Headless Chromium and local network access**: Chromium blocks requests from
  a page to loopback/LAN addresses unless the origin is allowed, which surfaces
  as `net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`. The `e2e-tests` browser
  host launches Chromium with `--disable-features=LocalNetworkAccessChecks`;
  without it, WebTransport never reaches the node.
- **Stopping a node uses SIGINT, not SIGTERM or SIGKILL**: PolkaJam only
  installs a SIGINT handler (`tokio::signal::ctrl_c`) and flushes its database
  in it. The scenarios stop a node through zombienet's `kill` with a grace
  period, which sends SIGINT first; a restarted node then resumes its chain
  instead of writing a new genesis block, and the scenarios check that.

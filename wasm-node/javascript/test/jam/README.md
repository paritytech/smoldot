# JAM test assets

The live JAM tests are scenarios of the `e2e-tests` crate: zombienet-sdk
spawns the PolkaJam network, Rust injects the faults through zombienet's node
handles, and a JavaScript body runs the smoldot browser build in headless
Chrome. See
[`e2e-tests/docs/jam-scenarios.md`](../../../../e2e-tests/docs/jam-scenarios.md)
for the four scenarios, the aged snapshot and `DEV_MODE`.

```sh
cargo test --manifest-path e2e-tests/Cargo.toml --features jam --test jam_follow -- --nocapture
```

What stays here:

| File | Purpose |
|---|---|
| `FINALITY.md` | How to regenerate the committed CE 130 finality fixture |

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

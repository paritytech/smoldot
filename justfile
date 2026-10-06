# Developer convenience shortcuts. Not part of the build system:
# everything here just forwards to the underlying npm script.

# List the available recipes.
default:
    @just --list

# The demo harness starts no network any more (D19, e2e scenarios on zombienet):
# `demo-jam` and `demo-jam-fast` are the attach recipe under their old names.
alias demo-jam := demo-jam-attach
alias demo-jam-fast := demo-jam-attach

# `zombie-jam` needs `zombie-cli` and `polkajam` from the
# `skunert/polkajam-light-client` branches of zombienet-sdk and PolkaJam:
# `ZOMBIE_CLI` (else `zombie-cli` from PATH) and `POLKAJAM_BIN_DIR` (prepended
# to PATH, else `polkajam` from PATH). The spec lands at
# /tmp/jam-zombie/jam_spec.json, which `demo-jam-attach` serves by default.

# Spawn the six-validator GRANDPA PolkaJam network with zombienet; Ctrl-C stops it.
zombie-jam:
    rm -rf /tmp/jam-zombie
    PATH="${POLKAJAM_BIN_DIR:+$POLKAJAM_BIN_DIR:}$PATH" exec "${ZOMBIE_CLI:-zombie-cli}" spawn --provider native --dir /tmp/jam-zombie --node-verifier none wasm-node/javascript/test/jam/zombienet/tiny-grandpa.toml

# Serve the demo page for a running network (default: zombie-jam's); Ctrl-C stops only the server.
demo-jam-attach spec=env_var_or_default("JAM_SPEC_PATH", "/tmp/jam-zombie/jam_spec.json") rpc_port=env_var_or_default("JAM_RPC_PORT", "19800"):
    cd wasm-node/javascript && JAM_SPEC_PATH="{{spec}}" JAM_RPC_PORT="{{rpc_port}}" npm run demo:jam

# `demo-jam-dev` spawns the network of an `e2e-tests` JAM scenario (default
# `jam_demo`, GRANDPA) through zombienet-sdk in DEV_MODE and prints the
# `just demo-jam-attach` line for it. Needs `polkajam` (`POLKAJAM_BIN_DIR`,
# prepended to PATH, else PATH).

# Keep a scenario's JAM network up for the demo page (DEV_MODE); Ctrl-C stops it.
demo-jam-dev scenario="jam_demo":
    PATH="${POLKAJAM_BIN_DIR:+$POLKAJAM_BIN_DIR:}$PATH" ZOMBIE_PROVIDER=native DEV_MODE=1 cargo test --manifest-path e2e-tests/Cargo.toml --test {{scenario}} -- --nocapture

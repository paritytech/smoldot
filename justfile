# Developer convenience shortcuts. Not part of the build system:
# everything here just forwards to the underlying npm script.

# List the available recipes.
default:
    @just --list

# Rebuild the JS package and start the local JAM demo (needs PolkaJam binaries).
demo-jam:
    cd wasm-node/javascript && npm run demo:jam:rebuild

# Start the local JAM demo without rebuilding the JS package.
demo-jam-fast:
    cd wasm-node/javascript && npm run demo:jam

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

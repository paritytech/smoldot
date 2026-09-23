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

# Statement Chat

A simple chat application demonstrating the statement distribution protocol via smoldot light client.

## Prerequisites

1. A running local relay chain with at least one parachain
2. Chain specs for both the relay chain and parachain

## Quick Start

If you have a running local network with polkadot-omni-node or polkadot-parachain:

```bash
./dev.sh
```

The script automatically extracts chain specs, builds smoldot, and starts the dev server at http://localhost:5173.

## Manual Setup

1. Start a local network
2. Extract chain specs from running nodes
   - `public/chain-specs/relay.json`
   - `public/chain-specs/parachain.json`
3. Run the dev server `npm run dev`


## Usage

1. Open http://localhost:5173 in your browser
2. Wait for smoldot to connect to both chains
3. Enter a topic (32-byte hex) or use the default
4. Click "Subscribe"
5. Send messages - they'll be distributed to all peers on the same topic

## How It Works

The app uses smoldot's statement store protocol:
- `statement_subscribeStatement` - Subscribe to topics on a chain
- `statement_submit` - Broadcast signed statements to the network
- `statement_subscribeStatement` (notification) - Receive statements from other peers

Messages are signed with Ed25519 keys (stored in localStorage) and distributed peer-to-peer without central servers.

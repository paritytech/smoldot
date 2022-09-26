# Light client for Polkadot and Substrate-based chains

This JavaScript library provides a light client for
[the Polkadot blockchain](https://polkadot.network/) and for chains built
using [the Substrate blockchain framework](https://substrate.io/).

It is an "actual" light client, in the sense that it is byzantine-resilient.
It does not rely on the presence of an RPC server, but directly connects to
the full nodes of the network.

## Example

```
import * as smoldot from '@substrate/smoldot-light';

// Load a string chain specification.
const chainSpec = fs.readFileSync('./westend.json', 'utf8');

// A single client can be used to initialize multiple chains.
const client = smoldot.start();

const chain = await client.addChain({
  chainSpec,
  jsonRpcCallback: (jsonRpcResponse) => {
      // Called whenever the client emits a response to a JSON-RPC request,
      // or an incoming JSON-RPC notification.
      console.log(jsonRpcResponse)
  }
});

chain.sendJsonRpc('{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}');

// Later:
// chain.remove();
```

## Usage

The first thing to do is to initialize the client with the `start` function.

Once initialized, the client can be used to connect to one or more chains. Use `addChain` to add
a new chain that the client must be connected to. `addChain` must be passed the specification of
the chain (commonly known as "chain spec").

The `addChain` function returns a `Promise` that yields a chain once the chain specification has
been successfully parsed and basic initialization is finished, but before Internet connections
are opened towards the chains.

In order to de-initialize a chain, call `chain.remove()`. Any function called afterwards on this
chain will throw an exception.
In order to de-initialize a client, call `client.terminate()`. Any function called afterwards on
any of the chains of the client will throw an exception.

After having obtained a chain, use `sendJsonRpc` to send a JSON-RPC request towards the node.
The function accepts as parameter a string request. See
[the specification of the JSON-RPC protocol](https://www.jsonrpc.org/specification),
and [the list of requests that smoldot is capable of serving](https://polkadot.js.org/docs/substrate/rpc/).
Smoldot also has experimental support for an extra (still experimental at the time of writing of
this comment) set of JSON-RPC functions [found here](https://github.com/paritytech/json-rpc-interface-spec/).

If the request is well formatted, the client will send a response using the `jsonRpcCallback`
callback that was passed to `addChain`. This callback takes as parameter the string JSON-RPC
response.

If the request is a subscription, the notifications will also be sent back using the same
`jsonRpcCallback`.

If no `jsonRpcCallback` was passed to `addChain`, then this chain won't be capable of serving
any JSON-RPC request at all. This can be used to save resources.

If the chain specification passed to `addChain` is a parachain, then the list of potential relay
chains must be passed as parameter to `addChain` as well. In situations where the chain
specifications passed to `addChain` are not trusted, it is important for security reasons to not
establish a parachain-relay-chain link between two chains that aren't part of the same "trust
sandbox".

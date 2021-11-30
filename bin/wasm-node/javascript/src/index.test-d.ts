import { start, Client } from 'smoldot';

// Test when supplying all options and all params to logCallback

// $ExpectType Client
let sm = start({
  maxLogLevel: 3,
  logCallback: (level, target, message) => { },
  forbidTcp: false,
  forbidWs: false,
  forbidWss: false,
});

// Test when not supplying optional options and optional params

(async () => {
  // $ExpectType Client
  sm = start();
  // $ExpectType Promise<Chain>
  const chain1 = sm.addChain({ chainSpec: '' });
  // $ExpectType Promise<Chain>
  const chain2Promise = sm.addChain({ chainSpec: '', potentialRelayChains: [await chain1], jsonRpcCallback: (resp) => { } });
  // $ExpectType Chain
  const chain2 = await chain2Promise;
  // $ExpectType void
  chain2.sendJsonRpc('{"id":8,"jsonrpc":"2.0","method":"system_health","params":[]}');
  // $ExpectType void
  chain2.remove();
  // $ExpectType Promise<void>
  sm.terminate();
})();

import smoldot from 'smoldot'; // smoldot is Smoldot

// $ExpectType Promise<SmoldotClient>
const sp = smoldot.start({
  max_log_level: 3,
  chain_spec: '',
  database_content: '',
  parachain_spec: '',
  json_rpc_callback: (resp) => {},
  database_save_callback: (content) => {},
  log_callback: (level, target, message) => {},
});

sp.then(sm => {
  // $ExpectType void
  sm.terminate();
});

/**
 * Interface that the Wasm module exports. Contains the functions that are exported by the Rust
 * code.
 *
 * Must match the bindings found in the Rust code.
 */
export interface SmoldotWasmExports extends WebAssembly.Exports {
    memory: WebAssembly.Memory;
    init: (maxLogLevel: number, enableCurrentTask: number, cpuRateLimit: number) => void;
    start_shutdown: () => void;
    alloc: (len: number) => number;
    add_chain: (chainSpecPointer: number, chainSpecLen: number, databaseContentPointer: number, databaseContentLen: number, jsonRpcRunning: number, potentialRelayChainsPtr: number, potentialRelayChainsLen: number) => number;
    remove_chain: (chainId: number) => void;
    chain_is_ok: (chainId: number) => number;
    chain_error_len: (chainId: number) => number;
    chain_error_ptr: (chainId: number) => number;
    json_rpc_send: (textPtr: number, textLen: number, chainId: number) => void;
    database_content: (chainId: number, maxSize: number) => void;
    timer_finished: (timerId: number) => void;
    connection_open_single_stream: (connectionId: number) => void;
    connection_open_multi_stream: (connectionId: number, peerIdPtr: number, peerIdLen: number) => void;
    stream_message: (connectionId: number, streamId: number, ptr: number, len: number) => void;
    connection_stream_opened: (connectionId: number, streamId: number, outbound: number) => void;
    connection_closed: (connectionId: number, ptr: number, len: number) => void;
    stream_closed: (connectionId: number, streamId: number) => void;
}
export interface SmoldotWasmInstance extends WebAssembly.Instance {
    readonly exports: SmoldotWasmExports;
}

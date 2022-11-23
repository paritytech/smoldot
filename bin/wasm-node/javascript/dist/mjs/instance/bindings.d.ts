/**
 * Interface that the Wasm module exports. Contains the functions that are exported by the Rust
 * code.
 *
 * Must match the bindings found in the Rust code.
 */
export interface SmoldotWasmExports extends WebAssembly.Exports {
    memory: WebAssembly.Memory;
    init: (maxLogLevel: number, enableCurrentTask: number, cpuRateLimit: number, periodicallyYield: number) => void;
    set_periodically_yield: (periodicallyYield: number) => void;
    start_shutdown: () => void;
    alloc: (len: number) => number;
    add_chain: (chainSpecPointer: number, chainSpecLen: number, databaseContentPointer: number, databaseContentLen: number, jsonRpcRunning: number, potentialRelayChainsPtr: number, potentialRelayChainsLen: number) => number;
    remove_chain: (chainId: number) => void;
    chain_is_ok: (chainId: number) => number;
    chain_error_len: (chainId: number) => number;
    chain_error_ptr: (chainId: number) => number;
    json_rpc_send: (textPtr: number, textLen: number, chainId: number) => number;
    json_rpc_responses_peek: (chainId: number) => number;
    json_rpc_responses_pop: (chainId: number) => void;
    timer_finished: (timerId: number) => void;
    connection_open_single_stream: (connectionId: number, handshakeTy: number) => void;
    connection_open_multi_stream: (connectionId: number, handshakeTyPtr: number, handshakeTyLen: number) => void;
    stream_message: (connectionId: number, streamId: number, ptr: number, len: number) => void;
    connection_stream_opened: (connectionId: number, streamId: number, outbound: number) => void;
    connection_reset: (connectionId: number, ptr: number, len: number) => void;
    stream_reset: (connectionId: number, streamId: number) => void;
}
export interface SmoldotWasmInstance extends WebAssembly.Instance {
    readonly exports: SmoldotWasmExports;
}

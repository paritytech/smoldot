export interface SmoldotWasmInstance extends WebAssembly.Instance {
    readonly exports: SmoldotWasmExports;
}
/**
 * Must match the bindings found in the Rust code.
 */
export interface SmoldotWasmExports extends WebAssembly.Exports {
    memory: WebAssembly.Memory;
    init: (maxLogLevel: number) => void;
    alloc: (len: number) => number;
    add_chain: (chainSpecPointer: number, chainSpecLen: number, databaseContentPointer: number, databaseContentLen: number, jsonRpcRunning: number, potentialRelayChainsPtr: number, potentialRelayChainsLen: number) => number;
    remove_chain: (chainId: number) => void;
    chain_is_ok: (chainId: number) => number;
    chain_error_len: (chainId: number) => number;
    chain_error_ptr: (chainId: number) => number;
    json_rpc_send: (textPtr: number, textLen: number, chainId: number) => void;
    database_content: (chainId: number, maxSize: number) => void;
    timer_finished: (timerId: number) => void;
    connection_open: (id: number) => void;
    connection_message: (id: number, ptr: number, len: number) => void;
    connection_closed: (id: number, ptr: number, len: number) => void;
}

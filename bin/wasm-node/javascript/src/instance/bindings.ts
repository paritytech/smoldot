// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Interface that the Wasm module exports. Contains the functions that are exported by the Rust
 * code.
 *
 * Must match the bindings found in the Rust code.
 */
export interface SmoldotWasmExports extends WebAssembly.Exports {
    memory: WebAssembly.Memory,
    init: (maxLogLevel: number, enableCurrentTask: number, cpuRateLimit: number) => void,
    start_shutdown: () => void,
    alloc: (len: number) => number,
    add_chain: (chainSpecPointer: number, chainSpecLen: number, databaseContentPointer: number, databaseContentLen: number, jsonRpcRunning: number, potentialRelayChainsPtr: number, potentialRelayChainsLen: number) => number;
    remove_chain: (chainId: number) => void,
    chain_is_ok: (chainId: number) => number,
    chain_error_len: (chainId: number) => number,
    chain_error_ptr: (chainId: number) => number,
    json_rpc_send: (textPtr: number, textLen: number, chainId: number) => number,
    json_rpc_responses_peek: (chainId: number) => number,
    json_rpc_responses_pop: (chainId: number) => void,
    database_content: (chainId: number, maxSize: number) => void,
    timer_finished: (timerId: number) => void,
    connection_open_single_stream: (connectionId: number, handshakeTy: number) => void,
    connection_open_multi_stream: (connectionId: number, handshakeTyPtr: number, handshakeTyLen: number) => void,
    stream_message: (connectionId: number, streamId: number, ptr: number, len: number) => void,
    connection_stream_opened: (connectionId: number, streamId: number, outbound: number) => void,
    connection_closed: (connectionId: number, ptr: number, len: number) => void,
    stream_closed: (connectionId: number, streamId: number) => void,
}

export interface SmoldotWasmInstance extends WebAssembly.Instance {
    readonly exports: SmoldotWasmExports;
}

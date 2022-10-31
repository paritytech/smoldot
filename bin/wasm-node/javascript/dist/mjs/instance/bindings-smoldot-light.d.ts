import type { SmoldotWasmInstance } from './bindings.js';
export interface Config {
    instance?: SmoldotWasmInstance;
    /**
     * Returns the number of milliseconds since an arbitrary epoch.
     */
    performanceNow: () => number;
    /**
     * Tries to open a new connection using the given configuration.
     *
     * @see Connection
     * @throws {@link ConnectionError} If the multiaddress couldn't be parsed or contains an invalid protocol.
     */
    connect(config: ConnectionConfig): Connection;
    /**
     * Closure to call when the Wasm instance calls `panic`.
     *
     * This callback will always be invoked from within a binding called the Wasm instance.
     */
    onPanic: (message: string) => never;
    logCallback: (level: number, target: string, message: string) => void;
    jsonRpcResponsesNonEmptyCallback: (chainId: number) => void;
    currentTaskCallback?: (taskName: string | null) => void;
}
/**
 * Connection to a remote node.
 *
 * At any time, a connection can be in one of the three following states:
 *
 * - `Opening` (initial state)
 * - `Open`
 * - `Reset`
 *
 * When in the `Opening` or `Open` state, the connection can transition to the `Reset` state
 * if the remote closes the connection or refuses the connection altogether. When that
 * happens, `config.onReset` is called. Once in the `Reset` state, the connection cannot
 * transition back to another state.
 *
 * Initially in the `Opening` state, the connection can transition to the `Open` state if the
 * remote accepts the connection. When that happens, `config.onOpen` is called.
 *
 * When in the `Open` state, the connection can receive messages. When a message is received,
 * `config.onMessage` is called.
 *
 * @see connect
 */
export interface Connection {
    /**
     * Transitions the connection or one of its substreams to the `Reset` state.
     *
     * If the connection is of type "single-stream", the whole connection must be shut down.
     * If the connection is of type "multi-stream", a `streamId` can be provided, in which case
     * only the given substream is shut down.
     *
     * The `config.onReset` or `config.onStreamReset` callbacks are **not** called.
     *
     * The transition is performed in the background.
     * If the whole connection is to be shut down, none of the callbacks passed to the `Config`
     * must be called again. If only a substream is shut down, the `onStreamReset` and `onMessage`
     * callbacks must not be called again with that substream.
     */
    reset(streamId?: number): void;
    /**
     * Queues data to be sent on the given connection.
     *
     * The connection must currently be in the `Open` state.
     *
     * The `streamId` must be provided if and only if the connection is of type "multi-stream".
     * It indicates which substream to send the data on.
     */
    send(data: Uint8Array, streamId?: number): void;
    /**
     * Start opening an additional outbound substream on the given connection.
     *
     * The state of the connection must be `Open`. This function must only be called for
     * connections of type "multi-stream".
     *
     * The `onStreamOpened` callback must later be called with an outbound direction.
     *
     * Note that no mechanism exists in this API to handle the situation where a substream fails
     * to open, as this is not supposed to happen. If you need to handle such a situation, either
     * try again opening a substream again or reset the entire connection.
     */
    openOutSubstream(): void;
}
/**
 * Configuration for a connection.
 *
 * @see connect
 */
export interface ConnectionConfig {
    /**
     * Multiaddress in string format that describes which node to try to connect to.
     *
     * Note that this address shouldn't be trusted. The value in this field might have been chosen
     * by a potentially malicious peer.
     */
    address: string;
    /**
     * Callback called when the connection transitions from the `Opening` to the `Open` state.
     *
     * Must only be called once per connection.
     */
    onOpen: (info: {
        type: 'single-stream';
        handshake: 'multistream-select-noise-yamux';
    } | {
        type: 'multi-stream';
        handshake: 'webrtc';
        localTlsCertificateMultihash: Uint8Array;
        remoteTlsCertificateMultihash: Uint8Array;
    }) => void;
    /**
     * Callback called when the connection transitions to the `Reset` state.
     *
     * It it **not** called if `Connection.reset` is manually called by the API user.
     */
    onConnectionReset: (message: string) => void;
    /**
     * Callback called when a new substream has been opened.
     *
     * This function must only be called for connections of type "multi-stream".
     */
    onStreamOpened: (streamId: number, direction: 'inbound' | 'outbound') => void;
    /**
     * Callback called when a stream transitions to the `Reset` state.
     *
     * It it **not** called if `Connection.resetStream` is manually called by the API user.
     *
     * This function must only be called for connections of type "multi-stream".
     */
    onStreamReset: (streamId: number) => void;
    /**
     * Callback called when a message sent by the remote has been received.
     *
     * Can only happen while the connection is in the `Open` state.
     *
     * The `streamId` parameter must be provided if and only if the connection is of type
     * "multi-stream".
     */
    onMessage: (message: Uint8Array, streamId?: number) => void;
}
/**
 * Emitted by `connect` if the multiaddress couldn't be parsed or contains an invalid protocol.
 *
 * @see connect
 */
export declare class ConnectionError extends Error {
    constructor(message: string);
}
export default function (config: Config): {
    imports: WebAssembly.ModuleImports;
    killAll: () => void;
};

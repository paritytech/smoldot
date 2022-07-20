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
     * @throws ConnectionError If the multiaddress couldn't be parsed or contains an invalid protocol.
     */
    connect(config: ConnectionConfig): Connection;
    /**
     * Closure to call when the Wasm instance calls `panic`.
     *
     * This callback will always be invoked from within a binding called the Wasm instance.
     */
    onPanic: (message: string) => never;
    logCallback: (level: number, target: string, message: string) => void;
    jsonRpcCallback: (response: string, chainId: number) => void;
    databaseContentCallback: (data: string, chainId: number) => void;
    currentTaskCallback?: (taskName: string | null) => void;
}
/**
 * Connection to a remote node.
 *
 * At any time, a connection can be in one of the three following states:
 *
 * - `Opening` (initial state)
 * - `Open`
 * - `Closed`
 *
 * When in the `Opening` or `Open` state, the connection can transition to the `Closed` state
 * if the remote closes the connection or refuses the connection altogether. When that
 * happens, `config.onClosed` is called. Once in the `Closed` state, the connection cannot
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
     * Transitions the connection to the `Closed` state.
     *
     * The `config.onClose` callback is **not** called.
     *
     * The transition is performed in the background.
     * None of the callbacks passed to the `Config` will be called again.
     */
    close(): void;
    /**
     * Queues data to be sent on the given connection.
     *
     * The connection must currently be in the `Open` state.
     */
    send(data: Uint8Array): void;
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
     */
    onOpen: () => void;
    /**
     * Callback called when the connection transitions to the `Closed` state.
     *
     * It it **not** called if `Connection.close` is manually called by the API user.
     */
    onClose: (message: string) => void;
    /**
     * Callback called when a message sent by the remote has been received.
     *
     * Can only happen while the connection is in the `Open` state.
     */
    onMessage: (message: Uint8Array) => void;
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

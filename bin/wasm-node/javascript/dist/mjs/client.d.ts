import { PlatformBindings } from './instance/instance.js';
export { MalformedJsonRpcError, QueueFullError, CrashError } from './instance/instance.js';
/**
 * Thrown in case of a problem when initializing the chain.
 */
export declare class AddChainError extends Error {
    constructor(message: string);
}
/**
 * Thrown in case the API user tries to use a chain or client that has already been destroyed.
 */
export declare class AlreadyDestroyedError extends Error {
    constructor();
}
/**
 * Thrown when trying to send a JSON-RPC message to a chain whose JSON-RPC system hasn't been
 * enabled.
 */
export declare class JsonRpcDisabledError extends Error {
    constructor();
}
/**
 * Client with zero or more active connections to blockchains.
 */
export interface Client {
    /**
     * Connects to a chain.
     *
     * Throws an exception if the chain specification isn't valid, or if the chain specification
     * concerns a parachain but no corresponding relay chain can be found.
     *
     * Smoldot will automatically de-duplicate chains if multiple identical chains are added, in
     * order to save resources. In other words, it is not a problem to call `addChain` multiple
     * times with the same chain specifications and obtain multiple `Chain`.
     * When the same client is used for multiple different purposes, you are in fact strongly
     * encouraged to trust smoldot and not attempt to de-duplicate chains yourself, as determining
     * whether two chains are identical is complicated and might have security implications.
     *
     * Smoldot tries to distribute CPU resources equally between all active `Chain` objects.
     *
     * @param options Configuration of the chain to add.
     *
     * @throws {@link AddChainError} If the chain can't be added.
     * @throws {@link AlreadyDestroyedError} If the client has been terminated earlier.
     * @throws {@link CrashError} If the background client has crashed.
     */
    addChain(options: AddChainOptions): Promise<Chain>;
    /**
     * Terminates the client.
     *
     * Afterwards, trying to use the client or any of its chains again will lead to an exception
     * being thrown.
     *
     * @throws {@link AlreadyDestroyedError} If the client has already been terminated earlier.
     * @throws {@link CrashError} If the background client has crashed.
     */
    terminate(): Promise<void>;
}
/**
 * Active connection to a blockchain.
 */
export interface Chain {
    /**
     * Enqueues a JSON-RPC request that the client will process as soon as possible.
     *
     * The response will be sent back using the callback passed when adding the chain.
     *
     * See <https://www.jsonrpc.org/specification> for a specification of the JSON-RPC format. Only
     * version 2 is supported.
     * Be aware that some requests will cause notifications to be sent back using the same callback
     * as the responses.
     *
     * A {@link MalformedJsonRpcError} is thrown if the request isn't a valid JSON-RPC request or
     * if the request is unreasonably large (64 MiB at the time of writing of this comment).
     * If, however, the request is a valid JSON-RPC request but that concerns an unknown method, a
     * error response is properly generated.
     *
     * Two JSON-RPC APIs are supported by smoldot:
     *
     * - The "legacy" one, documented here: <https://polkadot.js.org/docs/substrate/rpc>
     * - The more recent one: <https://github.com/paritytech/json-rpc-interface-spec>
     *
     * @param rpc JSON-encoded RPC request.
     *
     * @throws {@link MalformedJsonRpcError} If the payload isn't valid JSON-RPC.
     * @throws {@link QueueFullError} If the queue of JSON-RPC requests of the chain is full.
     * @throws {@link AlreadyDestroyedError} If the chain has been removed or the client has been terminated.
     * @throws {@link JsonRpcDisabledError} If the JSON-RPC system was disabled in the options of the chain.
     * @throws {@link CrashError} If the background client has crashed.
     */
    sendJsonRpc(rpc: string): void;
    /**
     * Waits for a JSON-RPC response or notification to be generated.
     *
     * If this function is called multiple times "simultaneously" (generating multiple different
     * `Promise`s), each `Promise` will return a different JSON-RPC response or notification.
     *
     * Each chain contains a buffer of the responses waiting to be sent out. Calling this function
     * pulls one element from the buffer. If this function is called at a slower rate than responses
     * are generated, then buffer will eventually become full, at which point calling
     * {@link Chain.sendJsonRpc} will throw an exception.
     *
     * @throws {@link AlreadyDestroyedError} If the chain has been removed or the client has been terminated.
     * @throws {@link JsonRpcDisabledError} If the JSON-RPC system was disabled in the options of the chain.
     * @throws {@link CrashError} If the background client has crashed.
     */
    nextJsonRpcResponse(): Promise<string>;
    /**
     * Disconnects from the blockchain.
     *
     * The JSON-RPC callback will no longer be called.
     *
     * Trying to use the chain again will lead to an exception being thrown.
     *
     * If this chain is a relay chain, then all parachains that use it will continue to work. Smoldot
     * automatically keeps alive all relay chains that have an active parachains. There is no need
     * to track parachains and relaychains, or to destroy them in the correct order, as this is
     * handled automatically.
     *
     * @throws {@link AlreadyDestroyedError} If the chain has already been removed or the client has been terminated.
     * @throws {@link CrashError} If the background client has crashed.
     */
    remove(): void;
}
/**
 * @param level How important this message is. 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Trace
 * @param target Name of the sub-system that the message concerns.
 * @param message Human-readable message that developers can use to figure out what is happening.
 */
export type LogCallback = (level: number, target: string, message: string) => void;
/**
 * Configuration of a client.
 */
export interface ClientOptions {
    /**
     * Callback that the client will invoke in order to report a log event.
     *
     * By default, prints the log on the `console`. If you want to disable logging altogether,
     * please pass an empty callback function.
     */
    logCallback?: LogCallback;
    /**
     * The client will never call the callback with a value of `level` superior to this value.
     * Defaults to 3.
     *
     * While this filtering could be done directly by the `logCallback`, passing a maximum log level
     * leads to better performances as the client doesn't even need to generate a `message` when it
     * knows that this message isn't interesting.
     */
    maxLogLevel?: number;
    /**
     * Maximum amount of CPU that the client should consume on average.
     *
     * This must be a number between `0.0` and `1.0`. For example, passing `0.25` bounds the client
     * to 25% of CPU power.
     * Defaults to `1.0` if no value is provided.
     *
     * Note that this is implemented by sleeping for certain amounts of time in order for the average
     * CPU consumption to not go beyond the given limit. It is therefore still possible for the
     * client to use high amounts of CPU for short amounts of time.
     */
    cpuRateLimit?: number;
    /**
     * If `true`, then the client will never open any TCP connection.
     * Defaults to `false`.
     *
     * This option can be used in order to mimic an environment where the TCP protocol isn't
     * supported (e.g. browsers) from an environment where TCP is supported (e.g. NodeJS).
     *
     * This option has no effect in environments where the TCP protocol isn't supported anyway.
     */
    forbidTcp?: boolean;
    /**
     * If `true`, then the client will never open any non-secure WebSocket connection.
     * Defaults to `false`.
     *
     * This option can be used in order to mimic an environment where non-secure WebSocket
     * connections aren't supported (e.g. web pages) from an environment where they are supported
     * (e.g. NodeJS).
     *
     * This option has no effect in environments where non-secure WebSocket connections aren't
     * supported anyway.
     */
    forbidWs?: boolean;
    /**
     * If `true`, then the client will never open any non-secure WebSocket connection to addresses
     * other than `localhost` or `127.0.0.1`.
     * Defaults to `false`.
     *
     * This option is similar to `forbidWs`, except that connections to `localhost` and `127.0.0.1`
     * do not take the value of this option into account.
     *
     * This option can be used in order to mimic an environment where non-secure WebSocket
     * connections aren't supported (e.g. web pages) from an environment where they are supported
     * (e.g. NodeJS).
     *
     * This option has no effect in environments where non-secure WebSocket connections aren't
     * supported anyway.
     */
    forbidNonLocalWs?: boolean;
    /**
     * If `true`, then the client will never open any secure WebSocket connection.
     * Defaults to `false`.
     *
     * This option exists of the sake of completeness. All environments support secure WebSocket
     * connections.
     */
    forbidWss?: boolean;
    /**
     * If `true`, then the client will never open any WebRTC connection.
     * Defaults to `false`.
     *
     * This option has no effect in environments where non-secure WebSocket connections aren't
     * supported anyway.
     */
    forbidWebRtc?: boolean;
}
/**
 * Configuration of a blockchain.
 */
export interface AddChainOptions {
    /**
     * JSON-encoded specification of the chain.
     *
     * The specification of the chain can be generated from a Substrate node by calling
     * `<client> build-spec --raw > spec.json`. Only "raw" chain specifications are supported by
     * smoldot at the moment.
     *
     * If the chain specification contains a `relay_chain` field, then smoldot will try to match
     * the value in `relay_chain` with the value in `id` of the chains in `potentialRelayChains`.
     */
    chainSpec: string;
    /**
     * Content of the database of this chain. Can be obtained by using the
     * `chainHead_unstable_finalizedDatabase` JSON-RPC function.
     *
     * Smoldot reserves the right to change its database format, making previous databases
     * incompatible. For this reason, no error is generated if the content of the database is invalid
     * and/or can't be decoded.
     *
     * Important: please note that using a malicious database content can lead to a security
     * vulnerability. This database content is considered by smoldot as trusted input. It is the
     * responsibility of the API user to make sure that the value passed in this field comes from
     * the same source of trust as the chain specification that was used when retrieving this
     * database content.
     */
    databaseContent?: string;
    /**
     * If `chainSpec` concerns a parachain, contains the list of chains whose `id` smoldot will try
     * to match with the parachain's `relay_chain`.
     * Defaults to `[]`.
     *
     * Must contain exactly the objects that were returned by previous calls to `addChain`. The
     * library uses a `WeakMap` in its implementation in order to identify chains.
     *
     * The primary way smoldot determines which relay chain is associated to a parachain is by
     * inspecting the chain specification of that parachain (i.e. the `chainSpec` field).
     *
     * This poses a problem in situations where the same client is shared between multiple different
     * applications: multiple applications could add mutiple different chains with the same `id`,
     * creating an ambiguity, or an application could register malicious chains with small variations
     * of a popular chain's `id` and try to benefit from a typo in a legitimate application's
     * `relay_chain`.
     *
     * These problems can be solved by using this parameter to segregate multiple different uses of
     * the same client. To use it, pass the list of all chains that the same application has
     * previously added to the client. By doing so, you are guaranteed that the chains of multiple
     * different applications can't interact in any way (good or bad), while still benefiting from
     * the de-duplication of resources that smoldot performs in `addChain`.
     *
     * When multiple different parachains use the same relay chain, it is important to be sure that
     * they are indeed using the same relay chain, and not accidentally using different ones. For
     * this reason, this parameter is a list of potential relay chains in which only one chain
     * should match, rather than a single `Chain` corresponding to the relay chain.
     */
    potentialRelayChains?: Chain[];
    /**
     * Disables the JSON-RPC system of the chain.
     *
     * This option can be used in order to save up some resources.
     *
     * It will be illegal to call {@link Chain.sendJsonRpc} and {@link Chain.nextJsonRpcResponse} on
     * this chain.
     */
    disableJsonRpc?: boolean;
}
export declare function start(options: ClientOptions, platformBindings: PlatformBindings): Client;

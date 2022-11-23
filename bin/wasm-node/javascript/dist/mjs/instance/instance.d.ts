import * as instance from './raw-instance.js';
export { PlatformBindings, ConnectionError, ConnectionConfig, Connection } from './raw-instance.js';
/**
 * Thrown in case the underlying client encounters an unexpected crash.
 *
 * This is always an internal bug in smoldot and is never supposed to happen.
 */
export declare class CrashError extends Error {
    constructor(message: string);
}
/**
 * Thrown in case a malformed JSON-RPC request is sent.
 */
export declare class MalformedJsonRpcError extends Error {
    constructor();
}
/**
 * Thrown in case the buffer of JSON-RPC requests is full and cannot accept any more request.
 */
export declare class QueueFullError extends Error {
    constructor();
}
/**
 * Contains the configuration of the instance.
 */
export interface Config {
    logCallback: (level: number, target: string, message: string) => void;
    maxLogLevel: number;
    enableCurrentTask: boolean;
    cpuRateLimit: number;
}
export interface Instance {
    request: (request: string, chainId: number) => void;
    nextJsonRpcResponse: (chainId: number) => Promise<string>;
    addChain: (chainSpec: string, databaseContent: string, potentialRelayChains: number[], disableJsonRpc: boolean) => Promise<{
        success: true;
        chainId: number;
    } | {
        success: false;
        error: string;
    }>;
    removeChain: (chainId: number) => void;
    startShutdown: () => void;
}
export declare function start(configMessage: Config, platformBindings: instance.PlatformBindings): Instance;

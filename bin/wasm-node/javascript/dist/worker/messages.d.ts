/**
 * Message to the worker.
 *
 * The first ever message sent to the worker must be a `ToWorkerConfig`, then all subsequent
 * messages must be `ToWorkerNonConfig`s.
 */
export declare type ToWorker = ToWorkerConfig | ToWorkerNonConfig;
export declare type ToWorkerNonConfig = ToWorkerRpcRequest | ToWorkerAddChain | ToWorkerRemoveChain | ToWorkerDatabaseContent;
/**
 * Message that the worker can send to the outside.
 */
export declare type FromWorker = FromWorkerChainAddedOk | FromWorkerChainAddedError | FromWorkerLog | FromWorkerJsonRpc | FromWorkerDatabaseContent | FromWorkerLivenessPing | FromWorkerCurrentTask;
/**
 * Contains the initial configuration of the worker.
 *
 * This message is only ever sent once, and it is always the first ever message sent to the
 * worker.
 */
export interface ToWorkerConfig {
    maxLogLevel: number;
    enableCurrentTask: boolean;
    cpuRateLimit: number;
    forbidTcp: boolean;
    forbidWs: boolean;
    forbidNonLocalWs: boolean;
    forbidWss: boolean;
}
/**
 * Start a JSON-RPC request.
 */
export interface ToWorkerRpcRequest {
    ty: 'request';
    request: string;
    chainId: number;
}
/**
 * Add a new chain.
 *
 * The worker must reply with either a `FromWorkerChainAddedOk` or a `FromWorkerChainAddedError`.
 */
export interface ToWorkerAddChain {
    ty: 'addChain';
    chainSpec: string;
    databaseContent: string;
    potentialRelayChains: number[];
    jsonRpcRunning: boolean;
}
/**
 * Remove a chain.
 *
 * The worker must reply with a `FromWorkerChainRemoved`.
 */
export interface ToWorkerRemoveChain {
    ty: 'removeChain';
    chainId: number;
}
/**
 * Get the database content of a chain.
 *
 * The worker must reply with a `FromWorkerDatabaseContent`.
 */
export interface ToWorkerDatabaseContent {
    ty: 'databaseContent';
    chainId: number;
    maxUtf8BytesSize: number;
}
export interface FromWorkerChainAddedOk {
    kind: 'chainAddedOk';
    chainId: number;
}
export interface FromWorkerChainAddedError {
    kind: 'chainAddedErr';
    error: string;
}
export interface FromWorkerLog {
    kind: 'log';
    level: number;
    target: string;
    message: string;
}
export interface FromWorkerJsonRpc {
    kind: 'jsonrpc';
    data: string;
    chainId: number;
}
export interface FromWorkerDatabaseContent {
    kind: 'databaseContent';
    data: string;
    chainId: number;
}
export interface FromWorkerLivenessPing {
    kind: 'livenessPing';
}
export interface FromWorkerCurrentTask {
    kind: 'currentTask';
    taskName: string | null;
}

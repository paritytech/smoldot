/**
 * Message to the worker.
 *
 * The first ever message sent to the worker must be a `ToWorkerConfig`, then all subsequent
 * messages must be `ToWorkerNonConfig`s.
 */
export declare type ToWorker = ToWorkerConfig | ToWorkerNonConfig;
export declare type ToWorkerNonConfig = ToWorkerRpcRequest | ToWorkerAddChain | ToWorkerRemoveChain | ToWorkerDatabaseContent;
export declare type FromWorker = FromWorkerChainAddedOk | FromWorkerChainAddedError | FromWorkerChainRemoved | FromWorkerLog | FromWorkerJsonRpc | FromWorkerDatabaseContent | FromWorkerLivenessPing;
export interface ToWorkerConfig {
    maxLogLevel: number;
    forbidTcp: boolean;
    forbidWs: boolean;
    forbidNonLocalWs: boolean;
    forbidWss: boolean;
}
export interface ToWorkerRpcRequest {
    ty: 'request';
    request: string;
    chainId: number;
}
export interface ToWorkerAddChain {
    ty: 'addChain';
    chainSpec: string;
    databaseContent: string;
    potentialRelayChains: number[];
    jsonRpcRunning: boolean;
}
export interface ToWorkerRemoveChain {
    ty: 'removeChain';
    chainId: number;
}
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
    error: Error;
}
export interface FromWorkerChainRemoved {
    kind: 'chainRemoved';
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

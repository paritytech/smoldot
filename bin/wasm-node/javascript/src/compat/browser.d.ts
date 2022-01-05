/// <reference lib="dom" />
import { Timeout, CompatWorker } from './index';
export declare function compatSetTimeout(callback: () => void, timeout: number): Timeout;
export declare function compatClearTimeout(timeout: Timeout): void;
export declare function workerOnMessage(worker: CompatWorker, callback: (message: any) => void): void;
export declare function workerOnError(worker: CompatWorker, callback: (error: any) => void): void;
export declare function workerTerminate(worker: CompatWorker): Promise<void>;
export declare function isTcpAvailable(): boolean;
export declare function postMessage(msg: any): void;
export declare function setOnMessage(callback: (message: any) => void): void;

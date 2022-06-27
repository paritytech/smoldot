export function workerOnMessage(worker: any, callback: any): void;
export function workerOnError(worker: any, callback: any): void;
export function workerTerminate(worker: any): Promise<void>;
export function postMessage(msg: any): void;
export function setOnMessage(callback: any): void;
export function performanceNow(): number;
export function isTcpAvailable(): boolean;
export function createConnection(_opts: any, _connectionListener: any): void;
export function getRandomValues(buffer: any): void;
